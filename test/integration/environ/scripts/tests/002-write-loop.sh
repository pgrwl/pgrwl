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

x_wait_for_slots_lsn() {
    local target_lsn="$1"
    shift

    echo_delim "waiting for slots to reach ${target_lsn}: $*"

    for i in {1..120}; do
        local all_ok="true"

        for slot in "$@"; do
            local confirmed
            confirmed=$(
                psql -At -U postgres -c \
                    "SELECT COALESCE(restart_lsn::text, '0/0')
                     FROM pg_replication_slots
                     WHERE slot_name = '${slot}'"
            )

            if [[ -z "$confirmed" ]]; then
                confirmed="0/0"
            fi

            local ok
            ok=$(
                psql -At -U postgres -c \
                    "SELECT '${confirmed}'::pg_lsn >= '${target_lsn}'::pg_lsn"
            )

            if [[ "$ok" != "t" ]]; then
                all_ok="false"
                echo "slot ${slot}: ${confirmed} < ${target_lsn}"
                break
            fi
        done

        if [[ "$all_ok" = "true" ]]; then
            echo "all slots caught up to ${target_lsn}"
            return 0
        fi

        sleep 0.25
    done

    echo "slots failed to catch up to ${target_lsn} in time"
    return 1
}

x_backup_restore() {
  echo_delim "cleanup state"
  x_remake_dirs
  x_remake_config

  # rerun the cluster
  echo_delim "init and run a cluster"
  xpg_rebuild
  xpg_start
  xpg_recreate_slots

  # run wal-receivers
  echo_delim "running wal-receivers"
  x_start_receiver "/tmp/config.json"
  x_start_pg_receivewal

  # make a basebackup before doing anything
  echo_delim "creating basebackup"
  pg_basebackup \
    --pgdata="${BASEBACKUP_PATH}/data" \
    --wal-method=none \
    --checkpoint=fast \
    --progress \
    --no-password \
    --verbose

  # trying to write ~100 of WAL files as quick as possible
  x_generate_wal 350

  # (to prevent test-races just wait while slots are in sync)
  #
  # those are races, when one receiver is ahead of another (may vary, it's impossible to fully keep in sync two receivers)
  #
  # renamed '/tmp/wal-archive/000000010000000000000067.partial' -> '/tmp/wal-archive/000000010000000000000067'
  # renamed '/tmp/wal-archive-pg_receivewal/000000010000000000000066.partial' -> '/tmp/wal-archive-pg_receivewal/000000010000000000000066'
  #
  target_lsn="$(xpg_current_lsn)"
  x_wait_for_slots_lsn "$target_lsn" "pgrwl_v5" "pg_receivewal"

  x_stop_receiver
  x_stop_pg_receivewal

  # remember the state
  pg_dumpall -f "/tmp/pgdumpall-before" --restrict-key=0

  # stop cluster, cleanup data
  echo_delim "teardown"
  xpg_teardown

  # restore from backup
  echo_delim "restoring backup"
  mv "${BASEBACKUP_PATH}/data" "${PGDATA}"
  chmod 0750 "${PGDATA}"
  chown -R postgres:postgres "${PGDATA}"
  touch "${PGDATA}/recovery.signal"

  # prepare archive (all partial files contain valid wal-segments)
  find "${WAL_PATH}" -type f -name "*.partial" -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +
  find "${PG_RECEIVEWAL_WAL_PATH}" -type f -name "*.partial" -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +

  # fix configs
  xpg_config
  cat <<EOF >>"${PG_CFG}"
#restore_command = 'cp ${WAL_PATH}/%f %p'
restore_command = 'pgrwl restore-command --serve-addr=127.0.0.1:7070 %f %p'
EOF

  # run serve-mode
  echo_delim "running wal fetcher"
  x_start_serving "/tmp/config.json"

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

  # compare with pg_receivewal
  echo_delim "compare wal-archive with pg_receivewal"
  find "${WAL_PATH}" -type f -name "*.json" -delete
  bash "/var/lib/postgresql/scripts/utils/dircmp.sh" "${WAL_PATH}" "${PG_RECEIVEWAL_WAL_PATH}"

  echo_delim "run post_restore_check.sql"
  x_run_post_restore_check

  x_search_errors_in_logs_or_fatal
  x_print_ok
}

x_backup_restore "${@}"
