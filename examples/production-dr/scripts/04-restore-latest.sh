#!/usr/bin/env bash
# Scenario A: PGDATA is lost. Restore the latest base backup and replay all WAL.
#
#   1. stop PostgreSQL and the receiver, delete the data volume (the disaster)
#   2. start pgrwl in serve mode (WAL source for restore_command)
#   3. pg-restore: pull the base backup into an empty PGDATA, write recovery settings
#   4. start PostgreSQL; it replays WAL until the archive ends, then promotes
#   5. start the receiver again; it follows the new timeline
source "$(dirname "$0")/lib.sh"
export RESTORE_ID="${RESTORE_ID:-}" RECOVERY_TARGET_TIME=""

log "1/5 stopping pg-primary and pgrwl-receive, deleting volume ${PG_VOLUME}"
$COMPOSE stop pgrwl-receive pg-primary
$COMPOSE rm -f pg-primary
docker volume rm "$PG_VOLUME"
T0=$(date +%s)

log "2/5 starting pgrwl-serve"
$COMPOSE --profile restore up -d pgrwl-serve

log "3/5 restoring base backup ${RESTORE_ID:-latest} into a fresh PGDATA"
$COMPOSE --profile restore run --rm pg-restore

log "4/5 starting pg-primary (archive recovery)"
$COMPOSE up -d pg-primary
wait_out_of_recovery
T1=$(date +%s)

log "5/5 starting pgrwl-receive again, stopping pgrwl-serve"
$COMPOSE up -d --no-deps pgrwl-receive
$COMPOSE --profile restore stop pgrwl-serve

log "recovered to timeline $(psql_primary -c 'select timeline_id from pg_control_checkpoint()') in $((T1 - T0))s"
log "dr_events: $(psql_primary -c "select count(*) || ' rows, last ts ' || max(ts) from dr_events")"
echo
echo "Next: take a fresh base backup on the new timeline: scripts/01-backup.sh"
