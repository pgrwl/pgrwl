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

x_backup_restore() {
  log_info "cleanup state"
  chmod 0600 /var/lib/postgresql/.ssh/id_ed25519
  x_remake_dirs
  x_remake_config

  # rerun the cluster
  log_info "init and run a cluster"
  xpg_rebuild
  xpg_start

  # run wal-receivers
  log_info "running wal-receivers"
  x_start_receiver "/tmp/config.json"
  sleep 10

  # make a basebackup before doing anything
  log_info "creating basebackup"
  pg_basebackup \
    --pgdata="${BASEBACKUP_PATH}/data" \
    --wal-method=none \
    --checkpoint=fast \
    --progress \
    --no-password \
    --verbose

  # trying to write ~100 of WAL files as quick as possible
  x_generate_wal 100

  # remember the state
  pg_dumpall -f "/tmp/pgdumpall-before" --restrict-key=0

  log_info "waiting upload"
  sleep 10

  # stop cluster, cleanup data
  log_info "teardown"
  x_stop_receiver
  xpg_teardown

  # restore from backup
  log_info "restoring backup"
  mv "${BASEBACKUP_PATH}/data" "${PGDATA}"
  chmod 0750 "${PGDATA}"
  chown -R postgres:postgres "${PGDATA}"
  touch "${PGDATA}/recovery.signal"

  # fix configs
  xpg_config
  cat <<EOF >>"${PG_CFG}"
restore_command = 'pgrwl restore-command --serve-addr=127.0.0.1:7070 %f %p'
EOF

  # run serve-mode
  log_info "running wal fetcher"
  x_start_serving "/tmp/config.json"

  # run restored cluster
  echo_delim "running cluster"
  xpg_start

  # wait until is in recovery, check logs, etc...
  xpg_wait_is_in_recovery

  # check diffs
  echo_delim "running diff on pg_dumpall dumps (before vs after)"
  pg_dumpall -f "/tmp/pgdumpall-after" --restrict-key=0
  diff "/tmp/pgdumpall-before" "/tmp/pgdumpall-after"

  echo_delim "run post_restore_check.sql"
  x_run_post_restore_check

  x_search_errors_in_logs
}

x_backup_restore "${@}"
