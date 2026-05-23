#!/usr/bin/env bash
set -euo pipefail
. /var/lib/postgresql/scripts/tests/utils.sh

###############################################################################
#   1. Start a fresh PG cluster and the pgrwl receiver (localfs).
#   2. Take a base backup, start a background insert load.
#   3. Stop PG hard (-m immediate) while the receiver is streaming, then
#      restart it. Do this several times to exercise the reconnect loop.
#   4. Stop the load, flush a final WAL switch, let the receiver catch up.
#   5. Tear down the original cluster, restore from the base backup +
#      archived WAL, and diff pg_dumpall before vs after.
###############################################################################

# NOTE: no_loop is set to 'false' (default), so - it allows to reconnect happens
x_remake_config() {
  cat <<EOF > "/tmp/config.json"
{
  "main": {
    "listen_port": 7070,
    "directory": "${WAL_PATH}"
  },
  "receiver": {
    "slot": "pgrwl_v5"
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

# Wait until the receiver log shows it has streamed past a restart.
# We look for either the explicit "reconnected" line emitted by the
# refactored connection code, or a fresh "reconnect" attempt followed
# by streaming activity. Times out after ~60s.
x_wait_for_reconnect_log() {
  local needle="${1:-reconnected}"
  local timeout="${2:-60}"
  local i
  for ((i = 0; i < timeout; i++)); do
    if grep -q "${needle}" "${LOG_FILE}" 2>/dev/null; then
      log_info "found '${needle}' in receiver log"
      return 0
    fi
    sleep 1
  done
  log_info "timed out waiting for '${needle}' in receiver log"
  return 1
}

x_reset_log_marker() {
  # append a marker line so subsequent greps can scope to the new window.
  echo "----- MARKER $(date '+%F %T.%N') $* -----" >> "${LOG_FILE}"
}

x_reconnect_flow() {
  echo_delim "cleanup state"
  x_remake_dirs
  x_remake_config

  echo_delim "init and run a cluster"
  xpg_rebuild
  xpg_start
  xpg_recreate_slots

  echo_delim "start wal receiver"
  x_start_receiver "/tmp/config.json"
  sleep 3

  echo_delim "create basebackup"
  /usr/local/bin/pgrwl backup -c "/tmp/config.json"

  echo_delim "start background inserts"
  chmod +x "${BACKGROUND_INSERTS_SCRIPT_PATH}"
  nohup "${BACKGROUND_INSERTS_SCRIPT_PATH}" >>"${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}" 2>&1 &

  pgbench -i -s 5 postgres

  ###############################################################################
  # Reconnect cycles: stop PG hard, restart, generate more WAL.
  # Each cycle should be visible in the receiver log as a reconnect attempt
  # followed by a successful "reconnected" line.
  ###############################################################################

  local cycles=3
  local i
  for ((i = 1; i <= cycles; i++)); do
    echo_delim "reconnect cycle ${i}/${cycles}: generating wal before stop"
    x_generate_wal 10

    x_reset_log_marker "before stop cycle ${i}"

    echo_delim "reconnect cycle ${i}/${cycles}: stopping postgres (immediate)"
    xpg_stop

    # Receiver should be alive but unable to talk to PG. Give it time to
    # notice the broken connection and enter its reconnect loop.
    sleep 3

    # Receiver must NOT have died.
    if ! kill -0 "${RECEIVER_PID}" 2>/dev/null; then
      log_fatal "receiver process ${RECEIVER_PID} died after pg stop in cycle ${i}"
    fi

    echo_delim "reconnect cycle ${i}/${cycles}: restarting postgres"
    xpg_start

    # Wait for the receiver to log that it reconnected.
    if ! x_wait_for_reconnect_log "reconnected" 60; then
      tail -100 "${LOG_FILE}" || true
      log_fatal "receiver did not log 'reconnected' after cycle ${i}"
    fi

    # Truncate the log so the next cycle's grep only sees fresh output.
    : > "${LOG_FILE}"

    # Generate some WAL after the reconnect; if the connection is really
    # alive the slot should advance.
    x_generate_wal 10
  done

  echo_delim "stop background inserts"
  pkill -f inserts.sh || true
  sleep 1

  echo_delim "force final wal flush and wait for slot to catch up"
  xpg_checkpoint_switch_wal
  xpg_wait_for_slot "pgrwl_v5"

  echo_delim "save expected state"
  pg_dumpall -f "/tmp/pgdumpall-before" --restrict-key=0

  ###############################################################################
  # standard restore + replay path
  ###############################################################################

  echo_delim "teardown original cluster"
  x_stop_receiver
  xpg_teardown

  echo_delim "restore basebackup"
  /usr/local/bin/pgrwl restore --dest="${PGDATA}" -c "/tmp/config.json"

  chmod 0750 "${PGDATA}"
  chown -R postgres:postgres "${PGDATA}"
  touch "${PGDATA}/recovery.signal"

  # Promote any .partial segments so the restored cluster can replay them.
  find "${WAL_PATH}" -type f -name "*.partial" \
    -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +

  xpg_config
  cat <<EOF >>"${PG_CFG}"
restore_command = 'pgrwl restore-command --serve-addr=127.0.0.1:7070 %f %p'
EOF

  echo_delim "start wal serving"
  x_start_serving "/tmp/config.json"

  >/var/log/postgresql/pg.log

  echo_delim "start restored cluster"
  xpg_start

  xpg_wait_is_in_recovery
  cat /var/log/postgresql/pg.log

  echo_delim "diff pg_dumpall before vs after"
  pg_dumpall -f "/tmp/pgdumpall-after" --restrict-key=0
  diff "/tmp/pgdumpall-before" "/tmp/pgdumpall-after"

  echo_delim "show latest applied records"
  psql --pset pager=off -c "select count(*), min(ts), max(ts) from public.tslog;" || true
  tail -10 "${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}" || true

  echo_delim "run post_restore_check.sql"
  x_run_post_restore_check

  # connection-reset errors during reconnect cycles are expected
  x_search_errors_in_logs
  x_print_ok
}

x_reconnect_flow "$@"
