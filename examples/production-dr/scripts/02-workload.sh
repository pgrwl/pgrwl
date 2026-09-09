#!/usr/bin/env bash
# Write one timestamped row per second so that every restore can be checked
# against a known last row. Default: 30 seconds.
source "$(dirname "$0")/lib.sh"
SECONDS_TO_RUN="${1:-30}"

psql_primary -c "create table if not exists dr_events (id bigserial primary key, ts timestamptz not null default now(), note text);"
log "inserting one row per second for ${SECONDS_TO_RUN}s"
for _ in $(seq 1 "$SECONDS_TO_RUN"); do
  psql_primary -c "insert into dr_events(note) values ('tick');"
  sleep 1
done
log "dr_events now: $(psql_primary -c "select count(*) || ' rows, last ts ' || max(ts) from dr_events")"
