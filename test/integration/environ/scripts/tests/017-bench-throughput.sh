#!/usr/bin/env bash
set -euo pipefail
. /var/lib/postgresql/scripts/tests/utils.sh

WAL_SWITCHES="${1:-50}"

BENCH_PGRWL_SLOT="pgrwl_bench"
BENCH_PGRWL_CFG="/tmp/bench-config.json"

make_pgrwl_cfg() {
  cat >"$BENCH_PGRWL_CFG" <<EOF
{
  "main": {
    "listen_port": 7070,
    "directory": "${WAL_PATH}"
  },
  "receiver": {
    "slot": "${BENCH_PGRWL_SLOT}",
    "no_loop": true
  },
  "backup": {
    "cron": "*/50 * * * *"
  },
  "log": {
    "level": "warn",
    "format": "text",
    "add_source": false
  }
}
EOF
}

x_wait_flush_lsn() {
  local app="$1"
  local target_lsn="$2"

  for i in {1..120}; do
    local ok
    ok=$(psql -At -U postgres -c "
      SELECT coalesce(
        (SELECT flush_lsn >= '${target_lsn}'::pg_lsn
         FROM pg_stat_replication
         WHERE application_name = '${app}'
         LIMIT 1),
        false
      )")
    if [[ "$ok" == "t" ]]; then
      return 0
    fi
    sleep 0.1
  done

  echo "receiver ${app} failed to reach ${target_lsn}" >&2
  return 1
}

# Wait until the receiver shows up as a streaming replica.
x_wait_receiver_connected() {
  local app="$1"
  for i in {1..60}; do
    local count
    count=$(psql -At -U postgres -c "
      SELECT count(*) FROM pg_stat_replication
      WHERE application_name = '${app}'")
    if [[ "${count}" -ge 1 ]]; then
      return 0
    fi
    sleep 0.1
  done
  echo "receiver ${app} did not appear in pg_stat_replication" >&2
  return 1
}

# Drop OS page cache so both phases start with the same cold-cache state.
# Requires root; silently skipped otherwise.
x_drop_caches() {
  sync
  echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
}

dir_bytes() {
  du -sb "$1" | awk '{print $1}'
}

setup_pg_with_slot() {
  local slot="$1"
  xpg_teardown
  xpg_rebuild
  xpg_start
  psql -v ON_ERROR_STOP=1 <<EOSQL
    SELECT pg_create_physical_replication_slot('${slot}', true, false);
    CHECKPOINT;
    SELECT pg_switch_wal();
EOSQL
}

between_phases() {
  x_stop_receiver      2>/dev/null || true
  x_stop_pg_receivewal 2>/dev/null || true
  xpg_teardown

  rm -rf "$WAL_PATH" "$PG_RECEIVEWAL_WAL_PATH"
  mkdir -p "$WAL_PATH" "$PG_RECEIVEWAL_WAL_PATH"
  chown -R postgres:postgres "$PG_RECEIVEWAL_WAL_PATH"
}

######################################################################
# phase 1: pg_receivewal
######################################################################

between_phases
echo_delim "phase 1: pg_receivewal  (${WAL_SWITCHES} WAL switches)"

setup_pg_with_slot "pg_receivewal"

# Pre-generate all WAL before the receiver starts so the measurement covers
# only streaming time, not WAL generation time.
x_generate_wal "$WAL_SWITCHES"
pgrw_target_lsn=$(psql -At -U postgres -c "SELECT pg_current_wal_lsn()")
psql -U postgres -c "CHECKPOINT" >/dev/null

# Drop page cache: WAL sender re-reads from disk, receiver writes to cold pages.
x_drop_caches

x_start_pg_receivewal
x_wait_receiver_connected "pg_receivewal"

t0=$(x_now_epoch_ms)
x_wait_flush_lsn "pg_receivewal" "$pgrw_target_lsn"
t1=$(x_now_epoch_ms)

pgrw_bytes=$(dir_bytes "$PG_RECEIVEWAL_WAL_PATH")
pgrw_elapsed=$(x_float_sub "$t1" "$t0")
pgrw_tput=$(awk -v b="$pgrw_bytes" -v t="$pgrw_elapsed" 'BEGIN { printf "%.2f", b / t / 1048576 }')

######################################################################
# phase 2: pgrwl
######################################################################

between_phases
echo_delim "phase 2: pgrwl  (${WAL_SWITCHES} WAL switches)"

make_pgrwl_cfg
setup_pg_with_slot "$BENCH_PGRWL_SLOT"

x_generate_wal "$WAL_SWITCHES"
pgrwl_target_lsn=$(psql -At -U postgres -c "SELECT pg_current_wal_lsn()")
psql -U postgres -c "CHECKPOINT" >/dev/null

x_drop_caches

x_start_receiver "$BENCH_PGRWL_CFG"
x_wait_receiver_connected "$BENCH_PGRWL_SLOT"

t0=$(x_now_epoch_ms)
x_wait_flush_lsn "$BENCH_PGRWL_SLOT" "$pgrwl_target_lsn"
t1=$(x_now_epoch_ms)

pgrwl_bytes=$(dir_bytes "$WAL_PATH")
pgrwl_elapsed=$(x_float_sub "$t1" "$t0")
pgrwl_tput=$(awk -v b="$pgrwl_bytes" -v t="$pgrwl_elapsed" 'BEGIN { printf "%.2f", b / t / 1048576 }')

######################################################################
# results
######################################################################

between_phases
echo_delim "results  (${WAL_SWITCHES} WAL switches)"
printf "%-20s %15s %14s %18s\n" "receiver" "bytes written" "elapsed (s)" "throughput (MB/s)"
printf "%-20s %15s %14s %18s\n" "pg_receivewal" "$pgrw_bytes"  "$pgrw_elapsed"  "$pgrw_tput"
printf "%-20s %15s %14s %18s\n" "pgrwl"         "$pgrwl_bytes" "$pgrwl_elapsed" "$pgrwl_tput"
