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
       "sync_interval": "1s",
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
    "name": "sftp",
    "compression": {
      "algo": "gzip"
    },
    "encryption": {
      "algo": "aes-256-gcm",
      "pass": "qwerty123"
    },
    "sftp": {
      "host": "sshd",
      "port": 22,
      "base_dir": "/home/testuser",
      "user": "testuser",
      "pkey_path": "/var/lib/postgresql/.ssh/id_ed25519"
    }
  }
}
EOF
}

x_hook_post_setup() {
  chmod 0600 /var/lib/postgresql/.ssh/id_ed25519
}

x_hook_after_start_receiver() {
  sleep 10
}

x_hook_after_snapshot() {
  echo_delim "waiting upload"
  sleep 10
}

x_run_backup_restore "${@}"
