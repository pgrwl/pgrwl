#!/usr/bin/env bash
set -euo pipefail
. /var/lib/postgresql/scripts/tests/utils.sh

###############################################################################
# Verify pgrwl receiver survives PostgreSQL restarts.
#
#   1. Start PG and the pgrwl receiver.
#   2. Take a base backup.
#   3. Stop PG hard, restart it. Three times.
#   4. Restore from backup + WAL, diff pg_dumpall before vs after.
###############################################################################

# NOTE: nreceiver.no_loop should be set to false (or absent as here)
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
    "format": "pretty",
    "add_source": true
  },
  "backup": {
    "cron": "*/50 * * * *"
  }
}
EOF
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
  # Reconnect cycle 1
  ###############################################################################
  echo_delim "cycle 1: generate wal"
  x_generate_wal 10

  echo_delim "cycle 1: stop pg"
  xpg_stop
  sleep 5

  echo_delim "cycle 1: start pg"
  xpg_start
  sleep 10

  echo_delim "cycle 1: generate wal after restart"
  x_generate_wal 10

  ###############################################################################
  # Reconnect cycle 2
  ###############################################################################
  echo_delim "cycle 2: stop pg"
  xpg_stop
  sleep 5

  echo_delim "cycle 2: start pg"
  xpg_start
  sleep 10

  echo_delim "cycle 2: generate wal after restart"
  x_generate_wal 10

  ###############################################################################
  # Reconnect cycle 3
  ###############################################################################
  echo_delim "cycle 3: stop pg"
  xpg_stop
  sleep 5

  echo_delim "cycle 3: start pg"
  xpg_start
  sleep 10

  echo_delim "cycle 3: generate wal after restart"
  x_generate_wal 10

  ###############################################################################
  # Wrap up: receiver must still be alive after all the restarts.
  ###############################################################################
  echo_delim "verify receiver is still alive"
  if ! kill -0 "${RECEIVER_PID}" 2>/dev/null; then
    log_fatal "receiver died during reconnect cycles"
  fi

  echo_delim "stop background inserts"
  pkill -f inserts.sh || true
  sleep 1

  echo_delim "force final wal flush and wait for slot to catch up"
  xpg_checkpoint_switch_wal
  xpg_wait_for_slot "pgrwl_v5"

  echo_delim "save expected state"
  pg_dumpall -f "/tmp/pgdumpall-before" --restrict-key=0

  ###############################################################################
  # Standard restore + replay path
  ###############################################################################
  echo_delim "teardown original cluster"
  x_stop_receiver
  xpg_teardown

  echo_delim "restore basebackup"
  /usr/local/bin/pgrwl restore --dest="${PGDATA}" -c "/tmp/config.json"

  chmod 0750 "${PGDATA}"
  chown -R postgres:postgres "${PGDATA}"
  touch "${PGDATA}/recovery.signal"

  xpg_config
  cat <<EOF >>"${PG_CFG}"
restore_command = 'pgrwl restore-command --serve-addr=127.0.0.1:7070 %f %p'
EOF

  echo_delim "start wal serving"
  x_start_serving "/tmp/config.json"

  echo_delim "start restored cluster"
  xpg_start
  xpg_wait_is_in_recovery
  cat /var/log/postgresql/pg.log

  echo_delim "diff pg_dumpall before vs after"
  pg_dumpall -f "/tmp/pgdumpall-after" --restrict-key=0
  diff "/tmp/pgdumpall-before" "/tmp/pgdumpall-after"

  echo_delim "run post_restore_check.sql"
  x_run_post_restore_check

  # connection-reset errors during reconnect cycles are expected
  x_search_errors_in_logs_no_fatal
  x_print_ok
}

x_reconnect_flow "$@"
