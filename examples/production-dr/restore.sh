#!/bin/bash
# Runs once inside the pg-restore container (see docker-compose.yml). PGDATA must be empty.
#
#   RESTORE_ID            base backup id (UTC, YYYYMMDDHHMMSS); empty = latest
#   RECOVERY_TARGET_TIME  PostgreSQL timestamp, e.g. 2026-09-09 10:15:30.123456+00; empty = end of WAL
set -euo pipefail
PGDATA=/var/lib/postgresql/data
CONFIG=/etc/pgrwl-config.yaml

if [ -n "$(ls -A "$PGDATA")" ]; then
  echo "refusing to restore: $PGDATA is not empty" >&2
  exit 1
fi

echo ">> pulling base backup ${RESTORE_ID:-latest} into $PGDATA"
pgrwl restore -c "$CONFIG" --dest="$PGDATA" ${RESTORE_ID:+--id="$RESTORE_ID"}

echo ">> writing recovery settings"
touch "$PGDATA/recovery.signal"
{
  echo "restore_command = 'pgrwl restore-command --serve-addr=pgrwl-serve:7070 %f %p'"
  if [ -n "${RECOVERY_TARGET_TIME:-}" ]; then
    echo "recovery_target_time = '${RECOVERY_TARGET_TIME}'"
    echo "recovery_target_action = 'promote'"
  fi
} > "$PGDATA/postgresql.auto.conf"
cat "$PGDATA/postgresql.auto.conf"

chown -R postgres:postgres "$PGDATA"
chmod 0700 "$PGDATA"
echo ">> done; start pg-primary to begin recovery"
