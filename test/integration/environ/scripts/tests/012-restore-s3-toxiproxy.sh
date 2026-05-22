#!/usr/bin/env bash
set -euo pipefail
. /var/lib/postgresql/scripts/tests/utils.sh

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
       "sync_interval": "2s",
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
    "compression": {
      "algo": "gzip"
    },
    "encryption": {
      "algo": "aes-256-gcm",
      "pass": "qwerty123"
    },
    "s3": {
      "url": "https://toxiproxy:9005",
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

x_backup_restore_with_toxiproxy() {
  echo_delim "cleanup state"
  x_kill_proc_rmrf_tmp
  x_remake_dirs
  x_toxiproxy_setup_minio
  x_remake_config

  echo_delim "init and run a cluster"
  xpg_rebuild
  xpg_start

  echo_delim "running wal receiver"
  x_run_receiver_daemon "/tmp/config.json"

  echo_delim "creating backup"
  /usr/local/bin/pgrwl backup -c "/tmp/config.json"

  chmod +x "${BACKGROUND_INSERTS_SCRIPT_PATH}"
  nohup "${BACKGROUND_INSERTS_SCRIPT_PATH}" >>"${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}" 2>&1 &

  echo_delim "generate load while minio is flapping through toxiproxy"
  x_toxiproxy_flap_minio 1 2 5 3
  pgbench -i -s 10 postgres
  x_generate_wal 50
  sleep 10

  pkill -f inserts.sh || true

  echo_delim "save expected state"
  pg_dumpall -f "/tmp/pgdumpall-before" --restrict-key=0

  echo_delim "teardown original cluster"
  x_stop_receiver_rest_api
  xpg_teardown

  echo_delim "restore backup while minio is cut through toxiproxy"
  x_toxiproxy_cut_minio_after_delay 1 5
  /usr/local/bin/pgrwl restore --dest="${PGDATA}" -c "/tmp/config.json"

  chmod 0750 "${PGDATA}"
  chown -R postgres:postgres "${PGDATA}"
  touch "${PGDATA}/recovery.signal"

  find "${WAL_PATH}" -type f -name "*.partial" -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +

  xpg_config
  cat <<EOF >>"${PG_CFG}"
restore_command = 'pgrwl restore-command --addr=127.0.0.1:7070 %f %p'
EOF

  echo_delim "start wal serving"
  x_stop_receiver_rest_api

  >/var/log/postgresql/pg.log

  echo_delim "start restored cluster"
  xpg_start

  xpg_wait_is_in_recovery
  cat /var/log/postgresql/pg.log

  echo_delim "diff pg_dumpall before vs after"
  pg_dumpall -f "/tmp/pgdumpall-after" --restrict-key=0
  diff "/tmp/pgdumpall-before" "/tmp/pgdumpall-after"

  echo_delim "show latest applied records"
  psql --pset pager=off -c "select * from public.tslog;"
  tail -10 "${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}" || true

  echo_delim "run post_restore_check.sql"
  x_run_post_restore_check

  x_search_errors_in_logs
  x_print_ok
}

x_backup_restore_with_toxiproxy "$@"
