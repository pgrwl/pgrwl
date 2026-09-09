#!/usr/bin/env bash
# The "oops" moment: record the time T just before the damage, then DROP TABLE.
# T is printed in UTC with microseconds in PostgreSQL's own format; 05-restore-pitr.sh takes it as-is.
source "$(dirname "$0")/lib.sh"

T="$(psql_primary -c "select to_char(now() at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS.US+00')")"
ROWS="$(psql_primary -c 'select count(*) from dr_events')"
sleep 1
psql_primary -c "drop table dr_events;"

log "T = ${T}  (dr_events had ${ROWS} rows at T; the table is gone now)"
echo "$T" > .last-accident-time
echo
echo "Next: scripts/05-restore-pitr.sh \"${T}\""
