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

x_hook_after_wal_generated() {
  # wait while both slots are in sync before taking the snapshot
  xpg_wait_for_slot "pgrwl_v5"
  xpg_wait_for_slot "pg_receivewal"
}

x_hook_stop_extra_receivers() {
  x_stop_pg_receivewal
}

x_hook_rename_extra_partials() {
  find "${PG_RECEIVEWAL_WAL_PATH}" -type f -name "*.partial" -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +
}

x_hook_after_diff() {
  echo_delim "compare wal-archive with pg_receivewal"
  find "${WAL_PATH}" -type f -name "*.json" -delete
  bash "/var/lib/postgresql/scripts/utils/dircmp.sh" "${WAL_PATH}" "${PG_RECEIVEWAL_WAL_PATH}"
}

x_run_backup_restore "${@}"
