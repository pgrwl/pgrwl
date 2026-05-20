#!/usr/bin/env bash
set -euo pipefail
. /var/lib/postgresql/scripts/pg/pg.sh

TEST_NAME=$(basename "$0" .sh)
TEST_STATE_PATH="/var/lib/postgresql/test-state/${TEST_NAME}"

# Cleanup on exit (even on error)
cleanup() {
  set +e
  # save content for debug
  mkdir -p "${TEST_STATE_PATH}"
  cp -a /tmp/* "${TEST_STATE_PATH}/"
  cp /var/log/postgresql/pg.log "${TEST_STATE_PATH}/pg.log" 2>/dev/null || true
  # cleanup state
  rm -rf /tmp/*
}
trap cleanup EXIT

export BASEBACKUP_PATH="/tmp/basebackup"
export WAL_PATH="/tmp/wal-archive"
export LOG_FILE="/tmp/pgrwl.log"
export LOG_LEVEL_DEFAULT=debug
export LOG_FORMAT_DEFAULT=text
export PG_RECEIVEWAL_WAL_PATH="/tmp/wal-archive-pg_receivewal"
export PG_RECEIVEWAL_LOG_FILE="/tmp/pg_receivewal.log"
export BACKGROUND_INSERTS_SCRIPT_PATH="/var/lib/postgresql/scripts/gendata/inserts.sh"
export BACKGROUND_INSERTS_SCRIPT_LOG_FILE="/tmp/ts-inserts.log"
export RECEIVER_PID=''
export PGRECEIVEWAL_PID=''
export SERVE_PID=''

# Default environment

export PGHOST="localhost"
export PGPORT="5432"
export PGUSER="postgres"
export PGPASSWORD="postgres"
export PGDATABASE="postgres"

# cleanup possible state

x_remake_buckets() {
  minio-mc alias set local https://minio:9000 minioadmin minioadmin123 --insecure
  minio-mc rb --force "local/${TEST_NAME}" --insecure || true

  # Wait until bucket is really gone
  for i in {1..10}; do
    if minio-mc ls "local/${TEST_NAME}" --insecure >/dev/null 2>&1; then
      log_info "Waiting for bucket to be deleted..."
      sleep 1
    else
      log_info "Bucket is deleted."
      break
    fi
  done

  minio-mc mb "local/${TEST_NAME}" --insecure || true
  minio-mc version enable "local/${TEST_NAME}" --insecure
}

x_kill_proc_rmrf_tmp() {
  # stop all processes, clean ALL state
  sudo pkill -9 postgres || true
  sudo pkill -9 pgrwl || true
  sudo rm -rf /tmp/*
}

x_remake_dirs() {
  x_kill_proc_rmrf_tmp

  # recreate localFS
  rm -rf "${BASEBACKUP_PATH}" && mkdir -p "${BASEBACKUP_PATH}"
  rm -rf "${WAL_PATH}" && mkdir -p "${WAL_PATH}"
  rm -rf "${PG_RECEIVEWAL_WAL_PATH}" && mkdir -p "${PG_RECEIVEWAL_WAL_PATH}"
  chown -R postgres:postgres "${PG_RECEIVEWAL_WAL_PATH}"

  # recreate bucket
  x_remake_buckets
}

# start the receiver in background and store its PID
x_start_receiver() {
  local cfg=$1
  log_info "starting receiver with $cfg"

  # Run the receiver in background.
  #   * stdout  -> tee -> log file (append) -> /dev/null (discard)
  #   * stderr  -> tee -> log file (append) -> original stderr (so it appears on console)
  /usr/local/bin/pgrwl daemon -c "${cfg}" -m receive \
    > >(tee -a "$LOG_FILE") \
    2> >(tee -a "$LOG_FILE" >&2) &

  RECEIVER_PID=$!
}

x_stop_receiver() {
  if [[ -n "${RECEIVER_PID:-}" ]]; then
    log_info "stopping receiver (PID $RECEIVER_PID)"
    kill -TERM "$RECEIVER_PID" 2>/dev/null || true
    wait "$RECEIVER_PID" 2>/dev/null || true
  fi
}

# start pg_receivewal in background and store its PID
x_start_pg_receivewal() {
  log_info "starting pg_receivewal"
  pg_receivewal \
    -D "${PG_RECEIVEWAL_WAL_PATH}" \
    -S pg_receivewal \
    --no-loop \
    --verbose \
    --no-password \
    --synchronous \
    --dbname "dbname=replication options=-cdatestyle=iso replication=true application_name=pg_receivewal" \
    >>"${PG_RECEIVEWAL_LOG_FILE}" 2>&1 &
  PGRECEIVEWAL_PID=$!
}

x_stop_pg_receivewal() {
  if [[ -n "${PGRECEIVEWAL_PID:-}" ]]; then
    log_info "stopping pg_receivewal (PID $PGRECEIVEWAL_PID)"
    kill -TERM "$PGRECEIVEWAL_PID" 2>/dev/null || true
    wait "$PGRECEIVEWAL_PID" 2>/dev/null || true
  fi
}

x_generate_wal() {
  local count=${1:-5}
  log_info "generating $count WAL switches"
  for ((i = 0; i < count; i++)); do
    psql -U postgres -c 'DROP TABLE IF EXISTS xxx; SELECT pg_switch_wal(); CREATE TABLE IF NOT EXISTS xxx(id serial);' \
      >/dev/null 2>&1
  done
}

x_start_serving() {
  local cfg=$1
  log_info "starting wal-serving with $cfg"

  # Run the 'serve' mode in background.
  #   * stdout  -> tee -> log file (append) -> /dev/null (discard)
  #   * stderr  -> tee -> log file (append) -> original stderr (so it appears on console)
  /usr/local/bin/pgrwl daemon -c "${cfg}" -m serve \
    > >(tee -a "$LOG_FILE") \
    2> >(tee -a "$LOG_FILE" >&2) &

  SERVE_PID=$!

  # Wait for the HTTP server to be ready before returning.
  # PostgreSQL's restore_command connects to this port immediately on startup;
  # without this wait there is a race where the command fails and recovery aborts.
  x_wait_http_ok "http://127.0.0.1:7070/healthz" 30
}

x_search_errors_in_logs() {
  log_info "searching for errors in pgrwl logs"
  if [[ -f "${LOG_FILE}" ]]; then
    grep -i "error" "${LOG_FILE}" || log_info "no errors found in pgrwl logs"
  fi

  log_info "searching for errors in pg logs"
  if [[ -f "/var/log/postgresql/pg.log" ]]; then
    grep -i "err" "/var/log/postgresql/pg.log" || log_info "no errors found in pg logs"
  fi
}

# toxiproxy utils

export TOXIPROXY_API="http://toxiproxy:8474"
export TOXIPROXY_MINIO_PROXY="minio_s3"
export TOXIPROXY_MINIO_LISTEN="0.0.0.0:9005"
export TOXIPROXY_MINIO_UPSTREAM="minio:9000"

x_wait_http_ok() {
  local url="${1:?url required}"
  local timeout="${2:-30}"
  local i

  for ((i = 0; i < timeout; i++)); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  return 1
}

x_wait_toxiproxy_up() {
  log_info "waiting toxiproxy api"
  x_wait_http_ok "${TOXIPROXY_API}/version" 30
}

x_toxiproxy_reset() {
  log_info "resetting toxiproxy"
  curl -fsS -X POST "${TOXIPROXY_API}/reset" >/dev/null
}

x_toxiproxy_create_minio_proxy() {
  log_info "creating toxiproxy minio proxy"
  curl -fsS -X POST "${TOXIPROXY_API}/proxies" \
    -H 'Content-Type: application/json' \
    -d "{
      \"name\": \"${TOXIPROXY_MINIO_PROXY}\",
      \"listen\": \"${TOXIPROXY_MINIO_LISTEN}\",
      \"upstream\": \"${TOXIPROXY_MINIO_UPSTREAM}\"
    }" >/dev/null || true
}

x_toxiproxy_delete_minio_proxy() {
  curl -fsS -X DELETE "${TOXIPROXY_API}/proxies/${TOXIPROXY_MINIO_PROXY}" >/dev/null 2>&1 || true
}

x_toxiproxy_enable_minio() {
  log_info "enabling minio proxy"
  curl -fsS -X POST "${TOXIPROXY_API}/proxies/${TOXIPROXY_MINIO_PROXY}" \
    -H 'Content-Type: application/json' \
    -d '{"enabled":true}' >/dev/null
}

x_toxiproxy_disable_minio() {
  log_info "disabling minio proxy"
  curl -fsS -X POST "${TOXIPROXY_API}/proxies/${TOXIPROXY_MINIO_PROXY}" \
    -H 'Content-Type: application/json' \
    -d '{"enabled":false}' >/dev/null
}

x_toxiproxy_setup_minio() {
  x_wait_toxiproxy_up
  x_toxiproxy_reset
  x_toxiproxy_delete_minio_proxy
  x_toxiproxy_create_minio_proxy
  x_toxiproxy_enable_minio
}

x_toxiproxy_cut_minio_after_delay() {
  local delay="${1:-2}"
  local downtime="${2:-5}"

  (
    sleep "${delay}"
    log_info "cutting minio through toxiproxy for ${downtime}s"
    x_toxiproxy_disable_minio
    sleep "${downtime}"
    x_toxiproxy_enable_minio
    log_info "restored minio through toxiproxy"
  ) &
}

x_toxiproxy_flap_minio() {
  local delay_before_first="${1:-2}"
  local cycles="${2:-2}"
  local downtime="${3:-4}"
  local pause_between="${4:-3}"

  (
    sleep "${delay_before_first}"
    local i
    for ((i = 1; i <= cycles; i++)); do
      log_info "toxiproxy minio flap cycle ${i}/${cycles}: down ${downtime}s"
      x_toxiproxy_disable_minio
      sleep "${downtime}"
      x_toxiproxy_enable_minio

      if (( i < cycles )); then
        sleep "${pause_between}"
      fi
    done
  ) &
}

# ---------------------------------------------------------------------------
# Standard backup/restore lifecycle with hook points.
# Tests override only the hooks they need; everything else is a no-op.
# ---------------------------------------------------------------------------

x_hook_post_setup()            { :; }
x_hook_after_cluster_start()   { :; }
x_hook_start_extra_receivers() { :; }
x_hook_after_start_receiver()  { :; }
x_hook_before_create_backup()  { :; }
x_hook_after_wal_generated()   { :; }
x_hook_after_snapshot()        { :; }
x_hook_stop_extra_receivers()  { :; }
x_hook_rename_extra_partials() { :; }
x_hook_after_diff()            { :; }

x_hook_create_backup() {
  echo_delim "creating basebackup"
  pg_basebackup \
    --pgdata="${BASEBACKUP_PATH}/data" \
    --wal-method=none \
    --checkpoint=fast \
    --progress \
    --no-password \
    --verbose
}

x_hook_generate_wal() {
  x_generate_wal 100
}

x_hook_restore_data() {
  mv "${BASEBACKUP_PATH}/data" "${PGDATA}"
  chmod 0750 "${PGDATA}"
  chown -R postgres:postgres "${PGDATA}"
  touch "${PGDATA}/recovery.signal"
}

x_run_backup_restore() {
  echo_delim "cleanup state"
  x_remake_dirs
  x_remake_config
  x_hook_post_setup

  echo_delim "init and run a cluster"
  xpg_rebuild
  xpg_start
  x_hook_after_cluster_start

  echo_delim "running wal-receivers"
  x_start_receiver "/tmp/config.json"
  x_hook_after_start_receiver
  x_hook_start_extra_receivers

  x_hook_before_create_backup
  x_hook_create_backup

  x_hook_generate_wal
  x_hook_after_wal_generated

  pg_dumpall -f "/tmp/pgdumpall-before" --restrict-key=0
  x_hook_after_snapshot

  echo_delim "teardown"
  x_stop_receiver
  x_hook_stop_extra_receivers
  xpg_teardown

  echo_delim "restoring backup"
  x_hook_restore_data

  find "${WAL_PATH}" -type f -name "*.partial" -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +
  x_hook_rename_extra_partials

  xpg_config
  cat <<EOF >>"${PG_CFG}"
restore_command = 'pgrwl restore-command --serve-addr=127.0.0.1:7070 %f %p'
EOF

  echo_delim "running wal fetcher"
  x_start_serving "/tmp/config.json"

  >/var/log/postgresql/pg.log

  echo_delim "running cluster"
  xpg_start

  xpg_wait_is_in_recovery
  cat /var/log/postgresql/pg.log

  echo_delim "running diff on pg_dumpall dumps (before vs after)"
  pg_dumpall -f "/tmp/pgdumpall-after" --restrict-key=0
  diff "/tmp/pgdumpall-before" "/tmp/pgdumpall-after"

  x_hook_after_diff

  echo_delim "run post_restore_check.sql"
  psql -f /var/lib/postgresql/scripts/pg/post_restore_check.sql -v "ON_ERROR_STOP=1" postgres

  x_search_errors_in_logs
}
