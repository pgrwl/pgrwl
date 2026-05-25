#!/usr/bin/env bash
set -euo pipefail
. /var/lib/postgresql/scripts/tests/utils.sh

# Compare pg_receivewal and pgrwl under strace.
#
# Usage:
#   bash /var/lib/postgresql/scripts/tests/018-bench-strace.sh [wal-switches]
#
# Example:
#   bash /var/lib/postgresql/scripts/tests/018-bench-strace.sh 250
#
# Output:
#   - normal throughput table
#   - one aggregated strace summary per receiver
#   - compact syscall comparison table
#
# Notes:
#   strace -c writes the summary only after the traced process exits, so each
#   receiver is stopped before the strace report is parsed.
#   Use -f, not -ff: -ff and -c are mutually exclusive in strace.

WAL_SWITCHES="${1:-50}"

BENCH_PGRWL_SLOT="pgrwl_bench"
BENCH_PGRWL_CFG="/tmp/bench-config.json"

STRACE_DIR="/tmp/strace-bench"
STRACE_TRACE="${STRACE_TRACE:-write,pwrite64,fsync,fdatasync,openat,close,rename,renameat,renameat2,ftruncate,fallocate}"

PG_RECEIVEWAL_STRACE_PREFIX="${STRACE_DIR}/pg_receivewal.strace"
PGRWL_STRACE_PREFIX="${STRACE_DIR}/pgrwl.strace"

PG_RECEIVEWAL_STRACE_PID=""
PGRWL_STRACE_PID=""

require_strace() {
  if ! command -v strace >/dev/null 2>&1; then
    echo "strace is required for this test" >&2
    return 1
  fi
}

make_pgrwl_cfg() {
  cat >"$BENCH_PGRWL_CFG" <<EOF_CFG
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
EOF_CFG
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
  stop_pg_receivewal_strace 2>/dev/null || true
  stop_pgrwl_strace 2>/dev/null || true
  x_stop_receiver 2>/dev/null || true
  x_stop_pg_receivewal 2>/dev/null || true
  xpg_teardown

  rm -rf "$WAL_PATH" "$PG_RECEIVEWAL_WAL_PATH"
  mkdir -p "$WAL_PATH" "$PG_RECEIVEWAL_WAL_PATH" "$STRACE_DIR"
  chown -R postgres:postgres "$PG_RECEIVEWAL_WAL_PATH"
}

wait_for_child_process() {
  local parent_pid="$1"
  local pattern="$2"

  for i in {1..100}; do
    local child
    child=$(pgrep -P "$parent_pid" -f "$pattern" | head -n 1 || true)
    if [[ -n "$child" ]]; then
      echo "$child"
      return 0
    fi
    sleep 0.05
  done

  return 1
}

stop_traced_process() {
  local strace_pid="$1"
  local pattern="$2"

  if [[ -z "$strace_pid" ]]; then
    return 0
  fi

  local child
  child=$(pgrep -P "$strace_pid" -f "$pattern" | head -n 1 || true)

  if [[ -n "$child" ]]; then
    kill -TERM "$child" 2>/dev/null || true
  else
    # Fallback. Usually not needed, but keeps cleanup reliable if strace exited.
    kill -TERM "$strace_pid" 2>/dev/null || true
  fi

  wait "$strace_pid" 2>/dev/null || true
}

start_pg_receivewal_strace() {
  log_info "starting pg_receivewal under strace"

  rm -f "${PG_RECEIVEWAL_STRACE_PREFIX}"*

  strace \
    -f \
    -qq \
    -c \
    -e "trace=${STRACE_TRACE}" \
    -o "$PG_RECEIVEWAL_STRACE_PREFIX" \
    pg_receivewal \
      -D "${PG_RECEIVEWAL_WAL_PATH}" \
      -S pg_receivewal \
      --no-loop \
      --verbose \
      --no-password \
      --synchronous \
      --dbname "dbname=replication options=-cdatestyle=iso replication=true application_name=pg_receivewal" \
      >>"${PG_RECEIVEWAL_LOG_FILE}" 2>&1 &

  PG_RECEIVEWAL_STRACE_PID=$!
  wait_for_child_process "$PG_RECEIVEWAL_STRACE_PID" "pg_receivewal" >/dev/null
}

stop_pg_receivewal_strace() {
  if [[ -n "${PG_RECEIVEWAL_STRACE_PID:-}" ]]; then
    log_info "stopping traced pg_receivewal (strace PID ${PG_RECEIVEWAL_STRACE_PID})"
    stop_traced_process "$PG_RECEIVEWAL_STRACE_PID" "pg_receivewal"
    PG_RECEIVEWAL_STRACE_PID=""
  fi
}

start_pgrwl_strace() {
  local cfg="$1"
  log_info "starting pgrwl receiver under strace with $cfg"

  rm -f "${PGRWL_STRACE_PREFIX}"*

  strace \
    -f \
    -qq \
    -c \
    -e "trace=${STRACE_TRACE}" \
    -o "$PGRWL_STRACE_PREFIX" \
    /usr/local/bin/pgrwl daemon -c "${cfg}" -m receive \
      >>"$LOG_FILE" 2>&1 &

  PGRWL_STRACE_PID=$!
  wait_for_child_process "$PGRWL_STRACE_PID" "pgrwl" >/dev/null
}

stop_pgrwl_strace() {
  if [[ -n "${PGRWL_STRACE_PID:-}" ]]; then
    log_info "stopping traced pgrwl (strace PID ${PGRWL_STRACE_PID})"
    stop_traced_process "$PGRWL_STRACE_PID" "pgrwl"
    PGRWL_STRACE_PID=""
  fi
}

print_raw_strace() {
  local title="$1"
  local prefix="$2"

  echo_delim "raw strace summary: ${title}"

  if ! compgen -G "${prefix}*" >/dev/null; then
    echo "no strace files found for ${title}: ${prefix}*"
    return 0
  fi

  for f in "${prefix}"*; do
    echo "--- ${f} ---"
    cat "$f"
  done
}

# strace -c output format differs depending on whether an syscall row has
# an error column. This parser sums seconds and calls for rows whose last
# column is the syscall name.
strace_metric() {
  local prefix="$1"
  local syscall="$2"
  local metric="$3" # calls|seconds

  awk -v syscall="$syscall" -v metric="$metric" '
    $NF == syscall {
      seconds += $2
      if (NF == 6) {
        calls += $(NF - 2)
      } else if (NF == 5) {
        calls += $(NF - 1)
      }
    }
    END {
      if (metric == "seconds") {
        printf "%.6f", seconds
      } else {
        printf "%d", calls
      }
    }
  ' "${prefix}"* 2>/dev/null || printf "0"
}

print_syscall_compare() {
  echo_delim "syscall comparison"
  printf "%-14s %15s %15s %15s %15s\n" "syscall" "pgwal calls" "pgrwl calls" "pgwal sec" "pgrwl sec"

  local syscalls=(write pwrite64 fsync fdatasync openat close rename renameat renameat2 ftruncate fallocate)

  for s in "${syscalls[@]}"; do
    local pg_calls pg_sec pgrwl_calls pgrwl_sec
    pg_calls=$(strace_metric "$PG_RECEIVEWAL_STRACE_PREFIX" "$s" calls)
    pgrwl_calls=$(strace_metric "$PGRWL_STRACE_PREFIX" "$s" calls)
    pg_sec=$(strace_metric "$PG_RECEIVEWAL_STRACE_PREFIX" "$s" seconds)
    pgrwl_sec=$(strace_metric "$PGRWL_STRACE_PREFIX" "$s" seconds)

    if [[ "$pg_calls" != "0" || "$pgrwl_calls" != "0" || "$pg_sec" != "0.000000" || "$pgrwl_sec" != "0.000000" ]]; then
      printf "%-14s %15s %15s %15s %15s\n" "$s" "$pg_calls" "$pgrwl_calls" "$pg_sec" "$pgrwl_sec"
    fi
  done
}

require_strace
mkdir -p "$STRACE_DIR"

# phase 1: pg_receivewal

between_phases
echo_delim "phase 1: pg_receivewal under strace (${WAL_SWITCHES} WAL switches)"

setup_pg_with_slot "pg_receivewal"
start_pg_receivewal_strace

t0=$(x_now_epoch_ms)
x_generate_wal "$WAL_SWITCHES"
target_lsn=$(psql -At -U postgres -c "SELECT pg_current_wal_lsn()")
x_wait_flush_lsn "pg_receivewal" "$target_lsn"
t1=$(x_now_epoch_ms)

pgrw_bytes=$(dir_bytes "$PG_RECEIVEWAL_WAL_PATH")
pgrw_elapsed=$(x_float_sub "$t1" "$t0")
pgrw_tput=$(awk -v b="$pgrw_bytes" -v t="$pgrw_elapsed" 'BEGIN { printf "%.2f", b / t / 1048576 }')

stop_pg_receivewal_strace

# phase 2: pgrwl

between_phases
echo_delim "phase 2: pgrwl under strace (${WAL_SWITCHES} WAL switches)"

make_pgrwl_cfg
setup_pg_with_slot "$BENCH_PGRWL_SLOT"
start_pgrwl_strace "$BENCH_PGRWL_CFG"

t0=$(x_now_epoch_ms)
x_generate_wal "$WAL_SWITCHES"
target_lsn=$(psql -At -U postgres -c "SELECT pg_current_wal_lsn()")
x_wait_flush_lsn "$BENCH_PGRWL_SLOT" "$target_lsn"
t1=$(x_now_epoch_ms)

pgrwl_bytes=$(dir_bytes "$WAL_PATH")
pgrwl_elapsed=$(x_float_sub "$t1" "$t0")
pgrwl_tput=$(awk -v b="$pgrwl_bytes" -v t="$pgrwl_elapsed" 'BEGIN { printf "%.2f", b / t / 1048576 }')

stop_pgrwl_strace

# results

echo_delim "results (${WAL_SWITCHES} WAL switches)"
printf "%-20s %15s %14s %18s\n" "receiver" "bytes written" "elapsed (s)" "throughput (MB/s)"
printf "%-20s %15s %14s %18s\n" "pg_receivewal" "$pgrw_bytes"  "$pgrw_elapsed"  "$pgrw_tput"
printf "%-20s %15s %14s %18s\n" "pgrwl"         "$pgrwl_bytes" "$pgrwl_elapsed" "$pgrwl_tput"

print_syscall_compare
print_raw_strace "pg_receivewal" "$PG_RECEIVEWAL_STRACE_PREFIX"
print_raw_strace "pgrwl" "$PGRWL_STRACE_PREFIX"

between_phases
x_print_ok
