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
       "sync_interval": "5s",
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

x_hook_after_snapshot() {
  echo_delim "waiting upload"
  sleep 10
}

x_run_backup_restore "${@}"
