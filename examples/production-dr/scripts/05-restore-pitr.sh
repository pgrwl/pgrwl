#!/usr/bin/env bash
# Scenario B: point-in-time recovery to a moment before the accident.
#
#   usage: scripts/05-restore-pitr.sh <T> [backup-id]
#     T           target time as printed by 03-accident.sh: 'YYYY-MM-DD HH:MM:SS.US+00' (UTC)
#     backup-id   base backup to start from; default: newest backup that finished before T
#
# Steps are the same as 04-restore-latest.sh, plus recovery_target_time.
source "$(dirname "$0")/lib.sh"
T="${1:?target time required, e.g. '2026-09-09 10:15:30.123456+00'}"
ID="${2:-}"

if [ -z "$ID" ]; then
  # newest completed backup whose "finished" precedes T
  # (API gives RFC-3339 UTC "2026-09-09T10:15:30.1Z"; rewrite it as "2026-09-09 10:15:30.1+00" so a string compare with T works)
  ID="$(list_backups | tr '{' '\n' | grep '"status":"completed"' \
        | sed -n 's/.*"label":"pgrwl_\([0-9]*\)".*"finished":"\([^"]*\)".*/\2 \1/p' \
        | sed 's/T/ /; s/Z /+00 /' \
        | awk -F'  *' -v t="$T" '$1" "$2 < t {print $3}' | sort -r | head -1)"
  case "$T" in *+00) ;; *) echo "note: automatic backup selection assumes T is UTC (+00); pass the backup id explicitly otherwise" >&2 ;; esac
  [ -n "$ID" ] || { echo "no completed base backup finished before $T" >&2; exit 1; }
fi
export RESTORE_ID="$ID" RECOVERY_TARGET_TIME="$T"

log "1/5 stopping pg-primary and pgrwl-receive, deleting volume ${PG_VOLUME}"
$COMPOSE stop pgrwl-receive pg-primary
$COMPOSE rm -f pg-primary
docker volume rm "$PG_VOLUME"
T0=$(date +%s)

log "2/5 starting pgrwl-serve"
$COMPOSE --profile restore up -d pgrwl-serve

log "3/5 restoring base backup ${ID}, target time ${T}"
$COMPOSE --profile restore run --rm pg-restore

log "4/5 starting pg-primary (archive recovery up to T, then promote)"
$COMPOSE up -d pg-primary
wait_out_of_recovery
T1=$(date +%s)

log "5/5 starting pgrwl-receive again, stopping pgrwl-serve"
$COMPOSE up -d --no-deps pgrwl-receive
$COMPOSE --profile restore stop pgrwl-serve

log "recovered to timeline $(psql_primary -c 'select timeline_id from pg_control_checkpoint()') in $((T1 - T0))s"
log "dr_events: $(psql_primary -c "select count(*) || ' rows, last ts ' || max(ts) from dr_events")"
log "rows after T (must be 0): $(psql_primary -c "select count(*) from dr_events where ts > '${T}'")"
echo
echo "Next: take a fresh base backup on the new timeline: scripts/01-backup.sh"
