#!/usr/bin/env bash
set -Eeuo pipefail
. /var/lib/postgresql/scripts/tests/utils.sh

: "${POLL_INTERVAL_SEC:=0.10}"
: "${STREAMING_TIMEOUT_SEC:=30}"
: "${TARGET_TIMEOUT_SEC:=60}"
: "${TIMING_DELTA_FAIL_SEC:=3.0}"

PGRWL_SLOT="pgrwl_v5"
PGRWL_APPNAME="pgrwl_v5"
PGRECEIVEWAL_SLOT="pg_receivewal"
PGRECEIVEWAL_APPNAME="pg_receivewal"

x_remake_config() {
  cat <<EOF > "/tmp/config.json"
{
  "main": {
    "listen_port": 7070,
    "directory": "/tmp/wal-archive"
  },
  "receiver": {
    "slot": "${PGRWL_SLOT}",
    "no_loop": true
  },
  "log": {
    "level": "${LOG_LEVEL_DEFAULT}",
    "format": "${LOG_FORMAT_DEFAULT}",
    "add_source": true
  },
  "backup": {
    "cron": "*/50 * * * *"
  }
}
EOF
}

measure_reach_time_pair() {
  local label="$1"
  local target_lsn="$2"
  local timeout="${3:-$TARGET_TIMEOUT_SEC}"

  local row
  row="$(
    psql -X -A -F '|' -t -q <<SQL
SELECT
  milestone,
  target_lsn,
  extract(epoch FROM pgrwl_at),
  extract(epoch FROM pg_receivewal_at),
  delta_sec,
  ok
FROM measure_reach_time_pair(
  '${label}',
  '${target_lsn}',
  '${PGRWL_APPNAME}',
  '${PGRECEIVEWAL_APPNAME}',
  ${timeout},
  ${POLL_INTERVAL_SEC},
  ${TIMING_DELTA_FAIL_SEC}
);
SQL
  )" || {
    echo "pg_stat_replication:"
    xpg_dump_pg_stat_replication
    return 1
  }

  [[ -n "${row}" ]] || {
    echo "measure_reach_time_pair returned no rows"
    return 1
  }

  IFS='|' read -r milestone out_target t_pgrwl t_pgrcv delta ok <<<"${row}"

  printf 'milestone=%-7s target_lsn=%s pgrwl_at=%s pg_receivewal_at=%s delta=%s\n' \
    "${milestone}" "${out_target}" "${t_pgrwl}" "${t_pgrcv}" "${delta}"

  [[ "${ok}" == "t" ]]
}

x_backup_restore() {
  local target_lsn

  echo_delim "cleanup state"
  x_remake_dirs
  x_remake_config

  echo_delim "init and run a cluster"
  xpg_rebuild
  xpg_start
  xpg_init_fns
  xpg_recreate_slots

  echo_delim "running wal-receivers"
  x_start_receiver "/tmp/config.json"
  x_start_pg_receivewal

  echo_delim "wait both receivers streaming"
  xpg_wait_until_streaming "${PGRWL_APPNAME}"
  xpg_wait_until_streaming "${PGRECEIVEWAL_APPNAME}"

  echo_delim "creating basebackup"
  pg_basebackup \
    --pgdata="${BASEBACKUP_PATH}/data" \
    --wal-method=none \
    --checkpoint=fast \
    --progress \
    --no-password \
    --verbose

  echo_delim "generate WAL"
  x_generate_wal 100

  echo_delim "force WAL switch"
  xpg_sql "select pg_switch_wal();" >/dev/null

  echo_delim "capture target LSN"
  target_lsn="$(xpg_current_insert_lsn)"
  echo "target_lsn=${target_lsn}"

  echo_delim "wait both receivers reached target"
  measure_reach_time_pair "final" "${target_lsn}"

  echo_delim "remember the state"
  pg_dumpall -f "/tmp/pgdumpall-before" --restrict-key=0

  echo_delim "teardown"
  x_stop_receiver
  x_stop_pg_receivewal
  xpg_teardown

  echo_delim "restoring backup"
  mv "${BASEBACKUP_PATH}/data" "${PGDATA}"
  chmod 0750 "${PGDATA}"
  chown -R postgres:postgres "${PGDATA}"
  touch "${PGDATA}/recovery.signal"

  echo_delim "prepare archive"
  find "${WAL_PATH}" -type f -name "*.partial" -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +
  find "${PG_RECEIVEWAL_WAL_PATH}" -type f -name "*.partial" -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +

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

  echo_delim "running diff on pg_dumpall dumps (before vs after)"
  pg_dumpall -f "/tmp/pgdumpall-after" --restrict-key=0
  diff "/tmp/pgdumpall-before" "/tmp/pgdumpall-after"

  echo_delim "compare wal-archive with pg_receivewal"
  find "${WAL_PATH}" -type f -name "*.json" -delete
  bash "/var/lib/postgresql/scripts/utils/dircmp.sh" "${WAL_PATH}" "${PG_RECEIVEWAL_WAL_PATH}"
}

x_backup_restore "${@}"
