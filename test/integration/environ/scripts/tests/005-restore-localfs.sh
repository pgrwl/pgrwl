#!/usr/bin/env bash
set -euo pipefail
. /var/lib/postgresql/scripts/tests/utils.sh

x_remake_config() {
  cat <<EOF > "/tmp/config.json"
{
  "main": {
    "listen_port": 7070,
    "directory": "/tmp/wal-archive"
  },
  "receiver": {
    "slot": "pgrwl_v5",
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

x_backup_restore() {
  echo_delim "cleanup state"
  x_kill_proc_rmrf_tmp
  x_remake_dirs
  x_remake_config

  # rerun the cluster
  echo_delim "init and run a cluster"
  xpg_rebuild
  xpg_start
  xpg_recreate_slots

  # run wal-receivers
  echo_delim "running wal-receivers"
  x_run_receiver_daemon "/tmp/config.json"
  x_start_pg_receivewal

  # make a backup before doing anything
  echo_delim "creating backup"
  /usr/local/bin/pgrwl backup -c "/tmp/config.json"

  # run inserts in a background
  chmod +x "${BACKGROUND_INSERTS_SCRIPT_PATH}"
  nohup "${BACKGROUND_INSERTS_SCRIPT_PATH}" >>"${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}" 2>&1 &

  # fill with 1M rows
  echo_delim "running pgbench"
  pgbench -i -s 10 postgres

  # wait a little
  sleep 5

  # stop inserts
  pkill -f inserts.sh

  # remember the state
  pg_dumpall -f "/tmp/pgdumpall-before" --restrict-key=0

  # stop cluster, cleanup data
  echo_delim "teardown"
  x_stop_receiver_rest_api
  x_stop_pg_receivewal
  xpg_teardown

  # restore from backup
  echo_delim "restoring backup"
  #BACKUP_ID=$(find /tmp/wal-archive/backups -mindepth 1 -maxdepth 1 -type d -printf "%T@ %f\n" | sort -n | tail -1 | cut -d' ' -f2)
  /usr/local/bin/pgrwl restore --dest="${PGDATA}" -c "/tmp/config.json"
  chmod 0750 "${PGDATA}"
  chown -R postgres:postgres "${PGDATA}"
  touch "${PGDATA}/recovery.signal"

  # prepare archive (all partial files contain valid wal-segments)
  find "${WAL_PATH}" -type f -name "*.partial" -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +
  find "${PG_RECEIVEWAL_WAL_PATH}" -type f -name "*.partial" -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +

  # fix configs
  xpg_config
  cat <<EOF >>"${PG_CFG}"
restore_command = 'pgrwl restore-command --addr=127.0.0.1:7070 %f %p'
EOF

  echo_delim "running wal fetcher"
  x_stop_receiver_rest_api

  # run restored cluster
  echo_delim "running cluster"
  xpg_start

  # wait until is in recovery, check logs, etc...
  xpg_wait_is_in_recovery
  cat /var/log/postgresql/pg.log

  # check diffs
  echo_delim "running diff on pg_dumpall dumps (before vs after)"
  pg_dumpall -f "/tmp/pgdumpall-after" --restrict-key=0
  diff "/tmp/pgdumpall-before" "/tmp/pgdumpall-after"

  # read the latest rec
  echo_delim "read latest applied records"
  echo "table content:"
  psql --pset pager=off -c "select * from public.tslog;"
  echo "insert log content:"
  tail -10 "${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}"

  # compare with pg_receivewal
  echo_delim "compare wal-archive with pg_receivewal"
  find "${WAL_PATH}" -type f -name "*.json" -delete
  rm -rf "${WAL_PATH}/backups"
  bash "/var/lib/postgresql/scripts/utils/dircmp.sh" "${WAL_PATH}" "${PG_RECEIVEWAL_WAL_PATH}"

  echo_delim "run post_restore_check.sql"
  x_run_post_restore_check

  x_search_errors_in_logs_or_fatal
  x_print_ok
}

x_backup_restore "${@}"
