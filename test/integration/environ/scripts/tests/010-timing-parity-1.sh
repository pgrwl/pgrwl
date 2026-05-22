#!/usr/bin/env bash
set -Eeuo pipefail
. /var/lib/postgresql/scripts/tests/utils.sh

# Timing thresholds
: "${POLL_INTERVAL_SEC:=0.10}"      # 100ms polling for replication stats
: "${STREAMING_TIMEOUT_SEC:=30}"
: "${TARGET_TIMEOUT_SEC:=60}"
: "${TIMING_DELTA_FAIL_SEC:=1.0}"

# Workload sizing
: "${PHASE1_BATCHES:=20}"
: "${PHASE1_ROWS_PER_BATCH:=1000}"
: "${PHASE2_BATCHES:=20}"
: "${PHASE2_ROWS_PER_BATCH:=1000}"

###############################################################################
# INTERNAL STATE
###############################################################################

export TEST_ID="receivers_cmp"
export TEST_BASE=/tmp/pgrwl-parity-tests
export TEST_ROOT="${TEST_BASE}/parity-${TEST_ID}"
export RUN_DIR="${TEST_ROOT}/run"
export LOGS_DIR="${TEST_ROOT}/logs"
export ARTIFACTS_DIR="${TEST_ROOT}/artifacts"
export PGDATA="${RUN_DIR}/pgdata"
export POSTGRES_LOG="${LOGS_DIR}/pg.log"
export PGRWL_CONFIG="${RUN_DIR}/pgrwl-config.json"
export PGRWL_DIR="${ARTIFACTS_DIR}/pgrwl"
export PGRWL_LOG="${LOGS_DIR}/pgrwl.log"
export PGRWL_SLOT="pgrwl_v5"
export PGRWL_APPNAME=pgrwl_v5
export PGRECEIVEWAL_DIR="${ARTIFACTS_DIR}/pg_receivewal"
export PGRECEIVEWAL_LOG="${LOGS_DIR}/pg_receivewal.log"
export PGRECEIVEWAL_SLOT="pg_receivewal"
export PGRECEIVEWAL_APPNAME=pg_receivewal
export STATE_FILE="${RUN_DIR}/state.env"
export RESULTS_FILE="${RUN_DIR}/results.txt"

PGRWL_PID=""
PGRECEIVEWAL_PID=""

MID_LSN=""
FINAL_LSN=""

###############################################################################
# LOGGING / UTILS
###############################################################################

ts() {
  date '+%Y-%m-%d %H:%M:%S'
}

log() {
  printf '[%s] %s\n' "$(ts)" "$*"
}

fail() {
  printf '[%s] ERROR: %s\n' "$(ts)" "$*" >&2
  exit 1
}

section() {
  echo ""
  echo "######################################################################"
  printf '### [%s] %s \n' "$(ts)" "$*"
  echo "######################################################################"
  echo ""  
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

float_abs() {
  awk -v x="$1" 'BEGIN { if (x < 0) x = -x; printf "%.3f", x }'
}

float_gt() {
  awk -v a="$1" -v b="$2" 'BEGIN { exit !(a > b) }'
}

float_sub() {
  awk -v a="$1" -v b="$2" 'BEGIN { printf "%.3f", a - b }'
}

now_epoch_ms() {
  date +%s.%3N
}

sanitize_id() {
  tr -cd 'a-zA-Z0-9_-'
}

###############################################################################
# CLEANUP
###############################################################################

stop_pid_if_running() {
  local pid="${1:-}"
  local name="${2:-process}"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    log "stopping ${name} pid=${pid}"
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  fi
}

drop_slot_if_exists() {
  local slot="$1"
  local exists
  exists="$(sql_scalar "select count(*) from pg_replication_slots where slot_name='${slot}'")" || return 0
  if [[ "${exists}" == "1" ]]; then
    log "dropping slot ${slot}"
    sql "select pg_drop_replication_slot('${slot}')" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  local rc=$?
  set +e

  section "cleanup"
  stop_pid_if_running "${PGRWL_PID}" "pgrwl"
  stop_pid_if_running "${PGRECEIVEWAL_PID}" "pg_receivewal"

  if [[ -n "${PGRWL_SLOT}" ]]; then
    drop_slot_if_exists "${PGRWL_SLOT}"
  fi
  if [[ -n "${PGRECEIVEWAL_SLOT}" ]]; then
    drop_slot_if_exists "${PGRECEIVEWAL_SLOT}"
  fi

  if [[ -n "${PGDATA}" && -d "${PGDATA}" ]]; then
    pg_ctl -D "${PGDATA}" -m fast stop >/dev/null 2>&1 || true
  fi

  if [[ -n "${TEST_ROOT}" && -d "${TEST_ROOT}" ]]; then
    mkdir -p "${ARTIFACTS_DIR}/final-state" 2>/dev/null || true
    cp -a "${LOGS_DIR}" "${ARTIFACTS_DIR}/final-state/" 2>/dev/null || true
  fi

  if [[ "${rc}" -eq 0 ]]; then
    log "PASS"
  else
    log "FAIL"
    [[ -f "${POSTGRES_LOG}" ]] && { echo; echo "--- postgres log tail ---"; tail -n 120 "${POSTGRES_LOG}" || true; }
    [[ -f "${PGRWL_LOG}" ]] && { echo; echo "--- pgrwl log tail ---"; tail -n 120 "${PGRWL_LOG}" || true; }
    [[ -f "${PGRECEIVEWAL_LOG}" ]] && { echo; echo "--- pg_receivewal log tail ---"; tail -n 120 "${PGRECEIVEWAL_LOG}" || true; }
  fi

  exit "${rc}"
}

trap cleanup EXIT

###############################################################################
# SANDBOX
###############################################################################

init_sandbox() {
  mkdir -p "${RUN_DIR}" "${LOGS_DIR}" "${ARTIFACTS_DIR}" "${PGRWL_DIR}" "${PGRECEIVEWAL_DIR}"

  cat > "${STATE_FILE}" <<EOF
TEST_ID=${TEST_ID}
TEST_ROOT=${TEST_ROOT}
PGRWL_SLOT=${PGRWL_SLOT}
PGRECEIVEWAL_SLOT=${PGRECEIVEWAL_SLOT}
EOF

  log "sandbox: ${TEST_ROOT}"
}

###############################################################################
# POSTGRES HELPERS
###############################################################################

psql_base_args=()
setup_psql_args() {
  psql_base_args=(
    -h "${PGHOST}"
    -p "${PGPORT}"
    -U "${PGUSER}"
    -d "${PGDATABASE}"
    -v ON_ERROR_STOP=1
    --pset pager=off
  )
}

sql() {
  psql "${psql_base_args[@]}" -Atqc "$*"
}

sql_scalar() {
  local out
  out="$(sql "$*")"
  printf '%s' "${out}" | tr -d '\n'
}

sql_file() {
  local file="$1"
  psql "${psql_base_args[@]}" -f "${file}"
}

init_cluster() {
  section "init cluster"

  initdb --auth=trust -U postgres -D "${PGDATA}" > "${LOGS_DIR}/initdb.log" 2>&1

  cat >> "${PGDATA}/postgresql.conf" <<EOF
listen_addresses         = '*'
logging_collector        = on
log_directory            = '${LOGS_DIR}'
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
wal_level                = replica
max_wal_senders          = 10
wal_keep_size            = 64MB
log_replication_commands = on
EOF

  cat >> "${PGDATA}/pg_hba.conf" <<EOF
local all         all     trust
local replication all     trust
host  all         all all trust
host  replication all all trust
EOF

  pg_ctl -D "${PGDATA}" -l "${POSTGRES_LOG}" start >/dev/null

  wait_for_postgres

  setup_psql_args

  sql "alter user postgres password '${PGPASSWORD}'" >/dev/null
  sql "select 1" >/dev/null
}

wait_for_postgres() {
  section "wait for postgres"
  local start now
  start="$(now_epoch_ms)"
  while true; do
    if pg_isready -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" >/dev/null 2>&1; then
      break
    fi
    now="$(now_epoch_ms)"
    if float_gt "$(float_sub "${now}" "${start}")" "30.0"; then
      fail "postgres did not become ready in time"
    fi
    sleep 0.2
  done
}

current_insert_lsn() {
  sql_scalar "select pg_current_wal_insert_lsn()"
}

walfile_name_for_lsn() {
  local lsn="$1"
  sql_scalar "select pg_walfile_name('${lsn}')"
}

lsn_ge() {
  local left="$1"
  local right="$2"
  local res
  res="$(sql_scalar "select case when '${left}'::pg_lsn >= '${right}'::pg_lsn then 1 else 0 end")"
  [[ "${res}" == "1" ]]
}

wait_slot_active() {
  local slot="$1"
  local timeout="${2:-30}"
  local start now active
  start="$(now_epoch_ms)"
  while true; do
    active="$(sql_scalar "select case when active then 1 else 0 end from pg_replication_slots where slot_name='${slot}'")"
    if [[ "${active}" == "1" ]]; then
      return 0
    fi
    now="$(now_epoch_ms)"
    if float_gt "$(float_sub "${now}" "${start}")" "${timeout}"; then
      fail "slot did not become active in time: ${slot}"
    fi
    sleep "${POLL_INTERVAL_SEC}"
  done
}

dump_pg_stat_replication() {
  sql "
    select
      application_name,
      state,
      sent_lsn,
      write_lsn,
      flush_lsn,
      sync_state
    from pg_stat_replication
    order by application_name
  " || true
}

dump_replication_slots() {
  sql "
    select
      slot_name,
      active,
      restart_lsn
    from pg_replication_slots
    order by slot_name
  " || true
}

###############################################################################
# RECEIVER STARTUP
###############################################################################

write_pgrwl_config() {
  section "write pgrwl config"

  cat > "${PGRWL_CONFIG}" <<EOF
{
  "main": {
    "listen_port": 7070,
    "directory": "${PGRWL_DIR}"
  },
  "receiver": {
    "slot": "${PGRWL_SLOT}",
    "no_loop": true
  },
  "log": {
    "level": "trace",
    "format": "text",
    "add_source": true
  },
  "backup": {
    "cron": "*/50 * * * *"
  }
}
EOF
}

start_pg_receivewal() {
  section "start pg_receivewal"

  pg_receivewal \
    --directory="${PGRECEIVEWAL_DIR}" \
    --slot="${PGRECEIVEWAL_SLOT}" \
    --no-loop \
    --verbose \
    --no-password \
    --synchronous \
    --dbname="dbname=replication options=-cdatestyle=iso replication=true application_name=${PGRECEIVEWAL_APPNAME}" \
    >"${PGRECEIVEWAL_LOG}" 2>&1 &

  PGRECEIVEWAL_PID=$!
  log "pg_receivewal pid=${PGRECEIVEWAL_PID}"
}

start_pgrwl() {
  section "start pgrwl"

  write_pgrwl_config

  /usr/local/bin/pgrwl daemon -c "${PGRWL_CONFIG}" >"${PGRWL_LOG}" 2>&1 &

  PGRWL_PID=$!
  log "pgrwl pid=${PGRWL_PID}"
}

wait_until_streaming() {
  local app="$1"
  local timeout="${2:-30}"
  local start now state
  start="$(now_epoch_ms)"

  while true; do
    state="$(sql_scalar "
      select coalesce(
        (select state
         from pg_stat_replication
         where application_name='${app}'
         limit 1),
        ''
      )
    ")"

    echo " => app = ${app}"
    echo " => state = ${state}"
    sql "select slot_name from pg_replication_slots;"
    sql "select application_name, state from pg_stat_replication;"

    if [[ "${state}" == "streaming" ]]; then
      log "application ${app} is streaming"
      return 0
    fi

    now="$(now_epoch_ms)"
    if float_gt "$(float_sub "${now}" "${start}")" "${timeout}"; then
      echo "pg_stat_replication:"
      dump_pg_stat_replication
      fail "application did not enter streaming in time: ${app}"
    fi

    sleep "${POLL_INTERVAL_SEC}"
  done
}

wait_both_streaming() {
  section "wait both streaming"
  wait_until_streaming "${PGRWL_APPNAME}" "${STREAMING_TIMEOUT_SEC}"
  wait_until_streaming "${PGRECEIVEWAL_APPNAME}" "${STREAMING_TIMEOUT_SEC}"
  wait_slot_active "${PGRWL_SLOT}" "${STREAMING_TIMEOUT_SEC}"
  wait_slot_active "${PGRECEIVEWAL_SLOT}" "${STREAMING_TIMEOUT_SEC}"
}

stop_receivers() {
  section "stop receivers"
  stop_pid_if_running "${PGRWL_PID}" "pgrwl"
  stop_pid_if_running "${PGRECEIVEWAL_PID}" "pg_receivewal"
}

###############################################################################
# REPLICATION STATS / TIMING
###############################################################################

get_flush_lsn_for_app() {
  local app="$1"
  sql_scalar "
    select coalesce(
      (select flush_lsn::text
       from pg_stat_replication
       where application_name='${app}'
       limit 1),
      ''
    )
  "
}

measure_reach_time_for_app() {
  local app="$1"
  local target_lsn="$2"
  local timeout="${3:-60}"

  local start now reached_at flush_lsn
  start="$(now_epoch_ms)"

  while true; do
    flush_lsn="$(get_flush_lsn_for_app "${app}")"

    if [[ -n "${flush_lsn}" ]] && lsn_ge "${flush_lsn}" "${target_lsn}"; then
      reached_at="$(now_epoch_ms)"
      printf '%s' "${reached_at}"
      return 0
    fi

    now="$(now_epoch_ms)"
    if float_gt "$(float_sub "${now}" "${start}")" "${timeout}"; then
      echo "pg_stat_replication:"
      dump_pg_stat_replication
      fail "application ${app} did not reach target LSN in time: ${target_lsn}"
    fi

    sleep "${POLL_INTERVAL_SEC}"
  done
}

measure_reach_time_pair() {
  local label="$1"
  local target_lsn="$2"

  section "measure timing parity: ${label} target=${target_lsn}"

  local t1 t2 delta
  local start
  start="$(now_epoch_ms)"

  t1="$(measure_reach_time_for_app "${PGRWL_APPNAME}" "${target_lsn}" "${TARGET_TIMEOUT_SEC}")"
  t2="$(measure_reach_time_for_app "${PGRECEIVEWAL_APPNAME}" "${target_lsn}" "${TARGET_TIMEOUT_SEC}")"

  delta="$(float_abs "$(float_sub "${t1}" "${t2}")")"

  {
    printf 'milestone=%-7s target_lsn=%s pgrwl_at=%s pg_receivewal_at=%s delta=%s\n' \
      "${label}" "${target_lsn}" "${t1}" "${t2}" "${delta}"
  } | tee -a "${RESULTS_FILE}"

  if float_gt "${delta}" "${TIMING_DELTA_FAIL_SEC}"; then
    echo
    echo "TIMING PARITY FAILED"
    echo "milestone: ${label}"
    echo "target_lsn: ${target_lsn}"
    echo "pgrwl reached at: ${t1}"
    echo "pg_receivewal reached at: ${t2}"
    echo "delta: ${delta}"
    echo "threshold: ${TIMING_DELTA_FAIL_SEC}"
    echo
    echo "pg_stat_replication snapshot:"
    dump_pg_stat_replication
    fail "timing parity exceeded threshold"
  fi
}

###############################################################################
# WORKLOAD
###############################################################################

create_test_schema() {
  section "create test schema"
  sql "
    create table if not exists public.parity_test (
      id bigserial primary key,
      phase text not null,
      payload text not null,
      created_at timestamptz default now()
    );
  " >/dev/null
}

generate_phase_workload() {
  local phase="$1"
  local batches="$2"
  local rows_per_batch="$3"

  section "generate workload ${phase}"
  local i
  for i in $(seq 1 "${batches}"); do
    sql "
      insert into public.parity_test(phase, payload)
      select '${phase}', repeat(md5(random()::text), 20)
      from generate_series(1, ${rows_per_batch});
    " >/dev/null
  done
}

force_wal_switch() {
  section "force wal switch"
  sql "select pg_switch_wal()" >/dev/null
}

insert_marker() {
  local phase="$1"
  section "insert marker ${phase}"
  sql "
    insert into public.parity_test(phase, payload)
    values ('${phase}', 'MARKER:${phase}');
  " >/dev/null
}

###############################################################################
# WAL ARTIFACT DISCOVERY / COMPARISON
###############################################################################

# Accept:
#   24 hex chars
#   24 hex chars + .partial
is_wal_artifact_name() {
  local name="$1"
  [[ "${name}" =~ ^[0-9A-F]{24}(\.partial)?$ ]]
}

artifact_base_segment() {
  local name="$1"
  printf '%s' "${name%.partial}"
}

list_wal_artifacts_up_to_segment() {
  local dir="$1"
  local target_seg="$2"

  find "${dir}" -maxdepth 1 -type f -printf '%f\n' \
    | while IFS= read -r name; do
        is_wal_artifact_name "${name}" || continue
        local base
        base="$(artifact_base_segment "${name}")"
        if [[ "${base}" < "${target_seg}" || "${base}" == "${target_seg}" ]]; then
          printf '%s\n' "${name}"
        fi
      done \
    | sort
}

compare_artifact_sets_up_to_lsn() {
  local target_lsn="$1"
  local target_seg
  target_seg="$(walfile_name_for_lsn "${target_lsn}")"

  section "compare artifact sets up to ${target_lsn} (segment ${target_seg})"

  local left_list right_list
  left_list="${RUN_DIR}/pgrwl-artifacts.txt"
  right_list="${RUN_DIR}/pgreceivewal-artifacts.txt"

  list_wal_artifacts_up_to_segment "${PGRWL_DIR}" "${target_seg}" > "${left_list}"
  list_wal_artifacts_up_to_segment "${PGRECEIVEWAL_DIR}" "${target_seg}" > "${right_list}"

  echo "--- pgrwl artifacts ---"
  cat "${left_list}" || true
  echo "--- pg_receivewal artifacts ---"
  cat "${right_list}" || true

  if ! diff -u "${left_list}" "${right_list}"; then
    fail "artifact set mismatch"
  fi
}

compare_artifact_bytes_up_to_lsn() {
  local target_lsn="$1"
  local target_seg
  target_seg="$(walfile_name_for_lsn "${target_lsn}")"

  section "compare artifact bytes up to ${target_lsn} (segment ${target_seg})"

  local name left right left_sha right_sha
  while IFS= read -r name; do
    [[ -n "${name}" ]] || continue

    left="${PGRWL_DIR}/${name}"
    right="${PGRECEIVEWAL_DIR}/${name}"

    [[ -f "${left}" ]] || fail "missing pgrwl artifact: ${name}"
    [[ -f "${right}" ]] || fail "missing pg_receivewal artifact: ${name}"

    if ! cmp -s "${left}" "${right}"; then
      left_sha="$(sha256sum "${left}" | awk '{print $1}')"
      right_sha="$(sha256sum "${right}" | awk '{print $1}')"
      echo
      echo "BYTE PARITY FAILED"
      echo "artifact: ${name}"
      echo "pgrwl sha256: ${left_sha}"
      echo "pg_receivewal sha256: ${right_sha}"
      fail "artifact bytes differ: ${name}"
    fi
  done < <(list_wal_artifacts_up_to_segment "${PGRWL_DIR}" "${target_seg}")
}

###############################################################################
# MAIN TEST FLOW
###############################################################################

print_summary() {
  section "summary"
  [[ -f "${RESULTS_FILE}" ]] && cat "${RESULTS_FILE}" || true
  echo "WAL artifact parity: OK"
}

main() {
  echo_delim "cleanup state"
  x_kill_proc_rmrf_tmp

  init_sandbox
  init_cluster

  create_test_schema
  xpg_recreate_slots

  start_pg_receivewal
  start_pgrwl
  wait_both_streaming

  generate_phase_workload "phase1" "${PHASE1_BATCHES}" "${PHASE1_ROWS_PER_BATCH}"
  insert_marker "mid"
  MID_LSN="$(current_insert_lsn)"
  echo "MID_LSN=${MID_LSN}" | tee -a "${STATE_FILE}"
  measure_reach_time_pair "mid" "${MID_LSN}"

  generate_phase_workload "phase2" "${PHASE2_BATCHES}" "${PHASE2_ROWS_PER_BATCH}"
  insert_marker "final-before-switch"
  force_wal_switch
  insert_marker "final"
  FINAL_LSN="$(current_insert_lsn)"
  echo "FINAL_LSN=${FINAL_LSN}" | tee -a "${STATE_FILE}"
  measure_reach_time_pair "final" "${FINAL_LSN}"

  stop_receivers

  compare_artifact_sets_up_to_lsn "${FINAL_LSN}"
  compare_artifact_bytes_up_to_lsn "${FINAL_LSN}"

  print_summary
}

main "$@"
