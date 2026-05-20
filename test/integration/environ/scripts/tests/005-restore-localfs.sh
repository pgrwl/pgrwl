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

x_hook_after_cluster_start() {
  xpg_recreate_slots
}

x_hook_start_extra_receivers() {
  x_start_pg_receivewal
}

x_hook_create_backup() {
  echo_delim "creating backup"
  /usr/local/bin/pgrwl backup -c "/tmp/config.json"
}

x_hook_generate_wal() {
  chmod +x "${BACKGROUND_INSERTS_SCRIPT_PATH}"
  nohup "${BACKGROUND_INSERTS_SCRIPT_PATH}" >>"${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}" 2>&1 &
  echo_delim "running pgbench"
  pgbench -i -s 10 postgres
  sleep 5
  pkill -f inserts.sh
}

x_hook_stop_extra_receivers() {
  x_stop_pg_receivewal
}

x_hook_restore_data() {
  /usr/local/bin/pgrwl restore --dest="${PGDATA}" -c "/tmp/config.json"
  chmod 0750 "${PGDATA}"
  chown -R postgres:postgres "${PGDATA}"
  touch "${PGDATA}/recovery.signal"
}

x_hook_rename_extra_partials() {
  find "${PG_RECEIVEWAL_WAL_PATH}" -type f -name "*.partial" -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +
}

x_hook_after_diff() {
  echo_delim "read latest applied records"
  echo "table content:"
  psql --pset pager=off -c "select * from public.tslog;"
  echo "insert log content:"
  tail -10 "${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}"

  echo_delim "compare wal-archive with pg_receivewal"
  find "${WAL_PATH}" -type f -name "*.json" -delete
  rm -rf "${WAL_PATH}/backups"
  bash "/var/lib/postgresql/scripts/utils/dircmp.sh" "${WAL_PATH}" "${PG_RECEIVEWAL_WAL_PATH}"
}

x_run_backup_restore "${@}"
