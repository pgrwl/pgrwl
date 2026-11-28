#!/usr/bin/env bash
# Synchronous-replication commit latency benchmark: pgrwl vs pg_receivewal.
#
# Starts a throwaway PostgreSQL and measures single-row INSERT commit latency
# (pgbench) with synchronous_standby_names pointing at:
#   (a) nothing                         - async baseline
#   (b) pgrwl receive                   - application_name = slot name (pgrwl_v5)
#   (c) pg_receivewal --synchronous     - reference implementation
#
# Runs inside the integration-test image (has postgres, pgbench, pg_receivewal
# and the pgrwl binary). From the repo root:
#
#   make build-linux && rm -rf test/integration/environ/bin && mv bin test/integration/environ/
#   (cd test/integration/environ && PG_MAJOR=17 docker compose build pg-primary)
#   docker run --rm --user postgres \
#     -v "$PWD/hack/sync-bench.sh:/sync-bench.sh:ro" \
#     --entrypoint bash pgrwl/pg-primary-17 /sync-bench.sh
#
# Env: BENCH_SECONDS (pgbench duration per run, default 8)
#
# Reference numbers (2026-11, PG17, local disk):
#   async                              1 client    ~2 ms
#   pgrwl (1s drain-timeout bug)       1 client ~1125 ms   8 clients ~1018 ms
#   pgrwl (fixed)                      1 client   ~10 ms   8 clients   ~13 ms
#   pg_receivewal --synchronous        1 client  ~8.6 ms   8 clients   ~13 ms
set -euo pipefail

PG_MAJOR="${PG_MAJOR:-17}"
BENCH_SECONDS="${BENCH_SECONDS:-8}"

export PATH="/usr/lib/postgresql/${PG_MAJOR}/bin:$PATH"
# trust auth; pgrwl just requires PGPASSWORD to be set
export PGHOST=127.0.0.1 PGPORT=5432 PGUSER=postgres PGDATABASE=postgres PGPASSWORD=postgres

D=/tmp/sync-bench
rm -rf "$D" && mkdir -p "$D"

initdb -D "$D/pg" -A trust -U postgres >/dev/null
cat >>"$D/pg/postgresql.conf" <<EOF
listen_addresses = '127.0.0.1'
wal_level = replica
max_wal_senders = 10
max_replication_slots = 10
synchronous_commit = on
EOF
echo "host replication all 127.0.0.1/32 trust" >>"$D/pg/pg_hba.conf"
pg_ctl -D "$D/pg" -l "$D/pg.log" -w start >/dev/null
trap 'pg_ctl -D "$D/pg" -m immediate stop >/dev/null 2>&1 || true' EXIT

psql -qc "create table t(id bigserial, v int)"
echo "insert into t(v) values (1);" >"$D/ins.sql"

set_sync() {
  psql -qc "alter system set synchronous_standby_names = '$1'" -c "select pg_reload_conf()" >/dev/null
}

wait_sync() {
  local i s
  for i in $(seq 1 60); do
    s=$(psql -Atc "select sync_state from pg_stat_replication where application_name = '$1'")
    [[ "$s" == "sync" ]] && return 0
    sleep 0.5
  done
  echo "standby '$1' never became sync"
  tail -20 "$D/pgrwl.log" "$D/prw.log" 2>/dev/null || true
  psql -c "select application_name, state, sync_state from pg_stat_replication"
  return 1
}

bench() {
  local label=$1 clients=$2
  pgbench -n -f "$D/ins.sql" -c "$clients" -j "$clients" -T "$BENCH_SECONDS" 2>/dev/null |
    awk -v l="$label" -v c="$clients" '
      /latency average/ {lat=$4}
      /^tps/            {tps=$3}
      END {printf "%-34s clients=%-2s latency_avg=%9s ms  tps=%s\n", l, c, lat, tps}'
}

# (a) async baseline
set_sync ""
bench "async (no sync standby)" 1

# (b) pgrwl
cat >"$D/pgrwl.json" <<EOF
{ "main": { "listen_port": 7070, "directory": "$D/pgrwl-wal" },
  "receiver": { "slot": "pgrwl_v5", "no_loop": true },
  "backup": { "cron": "*/50 * * * *" },
  "log": { "level": "warn", "format": "text" } }
EOF
mkdir -p "$D/pgrwl-wal"
pgrwl daemon -c "$D/pgrwl.json" -m receive >"$D/pgrwl.log" 2>&1 &
RECEIVER_PID=$!
set_sync "pgrwl_v5"
wait_sync "pgrwl_v5"
bench "sync: pgrwl" 1
bench "sync: pgrwl" 8
set_sync ""
kill "$RECEIVER_PID"
wait "$RECEIVER_PID" 2>/dev/null || true

# (c) pg_receivewal --synchronous (reference)
mkdir -p "$D/prw-wal"
pg_receivewal -D "$D/prw-wal" --slot=prw --create-slot >/dev/null 2>&1
pg_receivewal -D "$D/prw-wal" --slot=prw --synchronous >"$D/prw.log" 2>&1 &
PRW_PID=$!
set_sync "pg_receivewal"
wait_sync "pg_receivewal"
bench "sync: pg_receivewal --synchronous" 1
bench "sync: pg_receivewal --synchronous" 8
set_sync ""
kill "$PRW_PID"
wait "$PRW_PID" 2>/dev/null || true
