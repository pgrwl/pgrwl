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

x_hook_post_setup() {
  x_toxiproxy_setup_minio
}

x_hook_create_backup() {
  echo_delim "creating backup"
  /usr/local/bin/pgrwl backup -c "/tmp/config.json"
}

x_hook_generate_wal() {
  chmod +x "${BACKGROUND_INSERTS_SCRIPT_PATH}"
  nohup "${BACKGROUND_INSERTS_SCRIPT_PATH}" >>"${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}" 2>&1 &
  echo_delim "generate load while minio is flapping through toxiproxy"
  x_toxiproxy_flap_minio 1 2 5 3
  pgbench -i -s 10 postgres
  x_generate_wal 50
  sleep 10
  pkill -f inserts.sh || true
}

x_hook_restore_data() {
  x_toxiproxy_cut_minio_after_delay 1 5
  /usr/local/bin/pgrwl restore --dest="${PGDATA}" -c "/tmp/config.json"
  chmod 0750 "${PGDATA}"
  chown -R postgres:postgres "${PGDATA}"
  touch "${PGDATA}/recovery.signal"
}

x_hook_after_diff() {
  echo_delim "show latest applied records"
  psql --pset pager=off -c "select * from public.tslog;"
  tail -10 "${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}" || true
}

x_run_backup_restore "${@}"
