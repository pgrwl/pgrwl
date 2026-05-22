#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# Simple 'Point In Time Recovery' tutorial with pgrwl
#
# What this script demonstrates:
#
#   1. Start a fresh PostgreSQL cluster
#   2. Start pgrwl in WAL receiver mode
#   3. Take a base backup
#   4. Generate more data AFTER the base backup
#   5. Save a logical dump of the final database state
#   6. Destroy PGDATA (simulate disaster)
#   7. Restore from the base backup
#   8. Replay archived WAL files
#   9. Compare the restored database with the original state
#
# Main idea:
#
#   A base backup is only a snapshot at one point in time.
#   All changes made after that snapshot live in WAL.
#   To recover to the latest committed transaction, we need BOTH:
#
#     - the base backup
#     - the WAL generated after the backup
#
###############################################################################

###############################################################################
# Configuration
###############################################################################

PGDATA="/tmp/pgrwl-basic/pgdata"
WAL_ARCHIVE_DIR="/tmp/pgrwl-basic/wal-archive"
PGRWL_CONFIG="/tmp/pgrwl-basic/pgrwl-config.json"

DBNAME="bench"
REPL_SLOT="pgrwl_v5"

export PGHOST="localhost"
export PGPORT="5432"
export PGUSER="postgres"
export PGPASSWORD="postgres"

PGRWL_RECEIVE_PID=""

###############################################################################
# Small helper functions
###############################################################################

log() {
  printf '\n[%s] %s\n' "$(date '+%F %T')" "$*"
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

wait_for_postgres() {
  log "Waiting for PostgreSQL to accept connections..."
  for _ in $(seq 1 120); do
    if pg_isready -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  die "PostgreSQL did not become ready in time"
}

wait_until_out_of_recovery() {
  log "Waiting for PostgreSQL to finish recovery..."
  for _ in $(seq 1 120); do
    if psql -d postgres -Atqc "select pg_is_in_recovery()" 2>/dev/null | grep -q '^f$'; then
      return 0
    fi
    sleep 1
  done
  die "PostgreSQL did not finish recovery in time"
}

stop_postgres() {
  if [[ -d "$PGDATA" ]]; then
    log "Stopping PostgreSQL..."
    pg_ctl -D "$PGDATA" -m immediate stop >/dev/null 2>&1 || true
  fi
}

###############################################################################
# Phase 0. Start from a clean state
###############################################################################

log "Cleaning up old processes and files..."
sudo pkill -9 postgres || true
sudo pkill -9 pgrwl || true
sudo rm -rf "/tmp/pgrwl-basic"

log "Preparing work directory: /tmp/pgrwl-basic"
mkdir -p "/tmp/pgrwl-basic" "$WAL_ARCHIVE_DIR"

###############################################################################
# Phase 1. Create and start a fresh PostgreSQL cluster
###############################################################################

log "Initializing PostgreSQL cluster..."
initdb -D "$PGDATA" -A trust --auth-local=trust --auth-host=trust >/dev/null

cat >>"$PGDATA/postgresql.conf" <<EOF
listen_addresses      = '*'

# Settings required for WAL streaming / archiving style workflows
wal_level                = replica
max_wal_senders          = 10
max_replication_slots    = 10
wal_keep_size            = 64MB

# Durability settings
fsync                    = on
synchronous_commit       = on
full_page_writes         = on

# Basic logging settings
log_directory            = '/tmp/pgrwl-basic'
log_filename             = 'pg.log'
log_lock_waits           = on
log_temp_files           = 0
log_checkpoints          = on
log_connections          = off
log_destination          = 'stderr'
log_error_verbosity      = 'DEFAULT' # TERSE, DEFAULT, VERBOSE
log_hostname             = off
log_min_messages         = 'WARNING' # DEBUG5, DEBUG4, DEBUG3, DEBUG2, DEBUG1, INFO, NOTICE, WARNING, ERROR, LOG, FATAL, PANIC
log_timezone             = 'Asia/Aqtau'
log_line_prefix          = '%t [%p-%l] %r %q%u@%d '
EOF

log "Starting PostgreSQL..."
pg_ctl -D "$PGDATA" -l "/tmp/pgrwl-basic/pg.log" start >/dev/null
wait_for_postgres

log "Creating physical replication slot: $REPL_SLOT"
psql -d postgres -v ON_ERROR_STOP=1 \
  -c "select pg_create_physical_replication_slot('$REPL_SLOT');" >/dev/null

log "Creating test database: $DBNAME"
createdb "$DBNAME"

###############################################################################
# Phase 2. Configure and start pgrwl in receive mode
###############################################################################

log "Writing pgrwl configuration..."
cat >"$PGRWL_CONFIG" <<EOF
{
  "main": {
    "listen_port": 7070,
    "directory": "$WAL_ARCHIVE_DIR"
  },
  "receiver": {
    "slot": "$REPL_SLOT",
    "no_loop": true
  },
  "log": {
    "level": "debug",
    "format": "text",
    "add_source": false
  },
  "backup": {
    "cron": "*/50 * * * *"
  }
}
EOF

log "Starting pgrwl receiver..."
pgrwl daemon -c "$PGRWL_CONFIG" >"/tmp/pgrwl-basic/pgrwl-receive.log" 2>&1 &
PGRWL_RECEIVE_PID=$!

# Give the receiver a moment to connect and begin streaming.
sleep 3

###############################################################################
# Phase 3. Take a base backup
###############################################################################

log "Creating base backup..."
pgrwl backup -c "$PGRWL_CONFIG"

###############################################################################
# Phase 4. Generate data AFTER the base backup
#
# This is the important part.
# If we recover only from the base backup, these changes would be lost.
# They survive only because the WAL receiver captures the WAL stream.
###############################################################################

log "Initializing pgbench data (scale=10 ~ about 1 million rows in pgbench_accounts)..."
pgbench -i -s 10 "$DBNAME"

log "Running pgbench workload..."
pgbench -c 4 -j 2 -t 200 "$DBNAME"

###############################################################################
# Phase 5. Save the final logical state before disaster
#
# This dump becomes our ground truth.
# After restore + WAL replay, we expect the cluster to match this state.
###############################################################################

log "Dumping cluster state before destruction..."
pg_dumpall --quote-all-identifiers --restrict-key=0 >"/tmp/pgrwl-basic/before.sql"

###############################################################################
# Phase 6. Force PostgreSQL to emit final WAL and let receiver catch up
###############################################################################

log "Forcing checkpoint and WAL switch..."
psql -d postgres -v ON_ERROR_STOP=1 -c "checkpoint;" >/dev/null
psql -d postgres -v ON_ERROR_STOP=1 -c "select pg_switch_wal();" >/dev/null

# Give pgrwl time to receive the last WAL segment(s).
sleep 3

###############################################################################
# Phase 7. Simulate disaster
###############################################################################

log "Stopping PostgreSQL and pgrwl receiver..."
stop_postgres
curl -X POST http://127.0.0.1:7070/api/v1/receiver/stop

log "Removing original PGDATA to simulate data loss..."
rm -rf "$PGDATA"

###############################################################################
# Phase 8. Restore the base backup
###############################################################################

log "Restoring PGDATA from base backup..."
pgrwl restore --dest="$PGDATA" -c "$PGRWL_CONFIG"

chmod 0750 "$PGDATA"
chown -R postgres:postgres "$PGDATA"

# recovery.signal tells PostgreSQL to start in archive recovery mode.
touch "$PGDATA/recovery.signal"

cat >>"$PGDATA/postgresql.conf" <<EOF
restore_command = 'pgrwl restore-command --addr=127.0.0.1:7070 %f %p'
EOF

###############################################################################
# Phase 10. Start restored PostgreSQL and let it replay WAL
###############################################################################

log "Starting restored PostgreSQL cluster..."
pg_ctl -D "$PGDATA" -l "/tmp/pgrwl-basic/postgres-restored.log" start >/dev/null

wait_for_postgres
wait_until_out_of_recovery

###############################################################################
# Phase 11. Dump restored state and compare
###############################################################################

log "Dumping cluster state after recovery..."
pg_dumpall --quote-all-identifiers --restrict-key=0 >"/tmp/pgrwl-basic/after.sql"

log "Comparing dumps..."
if diff -u "/tmp/pgrwl-basic/before.sql" "/tmp/pgrwl-basic/after.sql" >"/tmp/pgrwl-basic/dump.diff"; then
  log "SUCCESS: restored cluster matches original state"
  echo "before: /tmp/pgrwl-basic/before.sql"
  echo "after : /tmp/pgrwl-basic/after.sql"
  echo "diff  : /tmp/pgrwl-basic/dump.diff (empty)"
else
  echo
  echo "FAIL: restored cluster differs from original state"
  echo "See diff: /tmp/pgrwl-basic/dump.diff"
  exit 1
fi
