#!/usr/bin/env bash
set -euo pipefail
. /var/lib/postgresql/scripts/tests/utils.sh

# clean up on exit or interrupt
cleanup() {
  log_info "Cleaning up"
  x_stop_receiver
}
trap cleanup EXIT INT TERM

x_remake_config() {
  cat <<EOF > "/tmp/config-zstd.yaml"
main:
  listen_port: 7070
  directory: /tmp/wal-archive
receiver:
  slot: pgrwl_v5
  uploader:
    sync_interval: 3s
    max_concurrency: 4
log:
  level: ${LOG_LEVEL_DEFAULT}
  format: ${LOG_FORMAT_DEFAULT}
  add_source: true
backup:
  cron: "*/50 * * * *"
storage:
  name: "local"
  compression:
    algo: zstd
EOF

  cat <<EOF > "/tmp/config-gzip-aes.yaml"
main:
  listen_port: 7070
  directory: /tmp/wal-archive
receiver:
  slot: pgrwl_v5
  uploader:
    sync_interval: 3s
    max_concurrency: 4
log:
  level: ${LOG_LEVEL_DEFAULT}
  format: ${LOG_FORMAT_DEFAULT}
  add_source: true
backup:
  cron: "*/50 * * * *"
storage:
  name: "local"
  compression:
    algo: gzip
  encryption:
    algo: aes-256-gcm
    pass: qwerty123
EOF

  cat <<EOF > "/tmp/config-aes.yaml"
main:
  listen_port: 7070
  directory: /tmp/wal-archive
receiver:
  slot: pgrwl_v5
  uploader:
    sync_interval: 3s
    max_concurrency: 4
log:
  level: ${LOG_LEVEL_DEFAULT}
  format: ${LOG_FORMAT_DEFAULT}
  add_source: true
backup:
  cron: "*/50 * * * *"
storage:
  name: "local"
  encryption:
    algo: aes-256-gcm
    pass: qwerty123
EOF

  cat <<EOF > "/tmp/config-plain.yaml"
main:
  listen_port: 7070
  directory: /tmp/wal-archive
receiver:
  slot: pgrwl_v5
  uploader:
    sync_interval: 3s
    max_concurrency: 4
log:
  level: ${LOG_LEVEL_DEFAULT}
  format: ${LOG_FORMAT_DEFAULT}
  add_source: true
backup:
  cron: "*/50 * * * *"
EOF

}

x_backup_restore() {
  echo_delim "cleanup state"
  x_remake_dirs
  x_remake_config

  # rerun the cluster
  echo_delim "init and run a cluster"
  xpg_rebuild
  xpg_start

  # run wal-receivers (zstd compression, no encryption)
  echo_delim "running wal-receiver with zstd compression, no encryption"
  x_start_receiver "/tmp/config-zstd.yaml"

  # make a basebackup before doing anything
  echo_delim "creating basebackup"
  pg_basebackup \
    --pgdata="${BASEBACKUP_PATH}/data" \
    --wal-method=none \
    --checkpoint=fast \
    --progress \
    --no-password \
    --verbose

  # switch config files with different compression/encryption settings
  echo_delim "configs switching loop"
  declare -a config_files=(
    "/tmp/config-gzip-aes.yaml"
    "/tmp/config-aes.yaml"
    "/tmp/config-plain.yaml"
  )
  for config_file in "${config_files[@]}"; do
    # rerun receiver with a new config
    echo_delim "running wal-receiver with config: ${config_file}"
    x_stop_receiver
    x_start_receiver "${config_file}"

    # generate some wals
    x_generate_wal 25

    # wait compressor/encryptor/uploader
    sleep 10
  done

  # remember the state
  pg_dumpall -f "/tmp/pgdumpall-before" --restrict-key=0

  # stop cluster, cleanup data
  echo_delim "teardown"
  x_stop_receiver
  xpg_teardown

  # restore from backup
  echo_delim "restoring backup"
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
  echo_delim "running wal fetcher"
  nohup /usr/local/bin/pgrwl daemon -c "/tmp/config-gzip-aes.yaml" -m serve >>"$LOG_FILE" 2>&1 &

  # run restored cluster
  echo_delim "running cluster"
  xpg_start

  # wait until is in recovery, check logs, etc...
  xpg_wait_is_in_recovery
  cat /var/log/postgresql/pg.log

  # check diffs
  echo_delim "running diff on pg_dumpall dumps (before vs after)"
  pg_dumpall -f "/tmp/pgdumpall-after" --restrict-key=0
  diff -u "/tmp/pgdumpall-before" "/tmp/pgdumpall-after"

  echo_delim "run post_restore_check.sql"
  x_run_post_restore_check

  x_search_errors_in_logs
}

x_backup_restore "${@}"
