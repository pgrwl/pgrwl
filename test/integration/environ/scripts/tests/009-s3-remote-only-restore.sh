#!/usr/bin/env bash
set -euo pipefail
. /var/lib/postgresql/scripts/tests/utils.sh

MARKER="2099-01-01 00:00:00"

x_remake_config() {
  cat <<EOF > "/tmp/config.json"
{
  "main": {
     "listen_port": 7070,
     "directory": "${WAL_PATH}"
  },
  "receiver": {
     "slot": "pgrwl_v5",
     "no_loop": true,
     "uploader": {
       "sync_interval": "3s",
       "max_concurrency": 4
     }
  },
  "log": {
    "level": "${LOG_LEVEL_DEFAULT}",
    "format": "${LOG_FORMAT_DEFAULT}",
    "add_source": true
  },
  "backup": {
    "cron": "*/50 * * * *"
  },
  "storage": {
    "name": "s3",
    "compression": { "algo": "gzip" },
    "encryption": {
      "algo": "aes-256-gcm",
      "pass": "qwerty123"
    },
    "s3": {
      "url": "https://minio:9000",
      "access_key_id": "minioadmin",
      "secret_access_key": "minioadmin123",
      "bucket": "${TEST_NAME}",
      "region": "main",
      "use_path_style": true,
      "disable_ssl": true
    }
  }
}
EOF
}

x_sql() {
  psql -v ON_ERROR_STOP=1 --pset pager=off -d postgres -Atqc "$1"
}

x_backup_restore() {
  echo_delim "cleanup"
  x_kill_proc_rmrf_tmp
  x_remake_dirs
  x_remake_config

  echo_delim "start cluster"
  xpg_rebuild
  xpg_start

  echo_delim "start receiver"
  x_start_receiver "/tmp/config.json"

  echo_delim "create base backup"
  pgrwl backup -c "/tmp/config.json"

  echo_delim "start background inserts"
  chmod +x "${BACKGROUND_INSERTS_SCRIPT_PATH}"
  nohup "${BACKGROUND_INSERTS_SCRIPT_PATH}" >>"${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}" 2>&1 &

  sleep 5

  echo_delim "stop inserts"
  pkill -f inserts.sh || true
  sleep 2

  echo_delim "insert marker row"
  x_sql "insert into public.tslog values ('${MARKER}');"

  echo_delim "force WAL switch"
  x_sql "select pg_switch_wal();"
  sleep 5   # simple and readable > perfect

  echo_delim "teardown source"
  x_stop_receiver
  xpg_teardown

  echo_delim "wipe local WAL (important!)"
  rm -rf "${WAL_PATH}"
  mkdir -p "${WAL_PATH}"

  echo_delim "restore base backup"
  pgrwl restore --dest="${PGDATA}" -c "/tmp/config.json"
  chmod 0750 "${PGDATA}"
  chown -R postgres:postgres "${PGDATA}"
  touch "${PGDATA}/recovery.signal"

  xpg_config
  cat <<EOF >>"${PG_CFG}"
restore_command = 'pgrwl restore-command --addr=127.0.0.1:7070 %f %p'
EOF

  echo_delim "serving files"
  x_stop_receiver_rest_api

  echo_delim "start restored cluster"
  xpg_start
  xpg_wait_is_in_recovery

  echo_delim "wait a bit for replay"
  sleep 5

  echo_delim "check marker exists"
  x_sql "select count(*) from public.tslog where ts = '${MARKER}';" | grep -qx "1"

  echo_delim "run post_restore_check.sql"
  x_run_post_restore_check

  x_search_errors_in_logs_or_fatal
  x_print_ok
}

x_backup_restore "$@"
