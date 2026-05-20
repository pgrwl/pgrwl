#!/usr/bin/env bash
set -euo pipefail
. /var/lib/postgresql/scripts/tests/utils.sh

###############################################################################
# Test: stream-mode manual basebackup API
#
# What this verifies:
#
#   1. pgrwl receiver/stream daemon starts with the new HTTP API.
#   2. POST /api/v1/basebackup triggers a manual basebackup.
#   3. GET /api/v1/basebackup/status reports the backup state.
#   4. A second POST while the first backup is running returns 409.
#   5. The backup eventually succeeds.
#   6. A backup manifest appears in local backup storage.
#   7. WAL receiver remains alive while the backup is running.
#
# This test uses existing environ helpers:
#
#   x_remake_dirs
#   xpg_rebuild
#   xpg_start
#   xpg_recreate_slots
#   x_start_receiver
#   x_stop_receiver
#   x_search_errors_in_logs
#
###############################################################################

API_ADDR="${API_ADDR:-http://127.0.0.1:7070}"
BASEBACKUP_STATUS_URL="${API_ADDR}/api/v1/basebackup/status"
BASEBACKUP_START_URL="${API_ADDR}/api/v1/basebackup"

# Keep this moderate. Large enough so the duplicate trigger can usually observe
# the first backup while it is still running, but not too slow for CI.
API_TEST_PGBENCH_SCALE="${API_TEST_PGBENCH_SCALE:-10}"

x_remake_config() {
  cat <<EOF > "/tmp/config.json"
{
  "main": {
     "listen_port": 7070,
     "directory": "${WAL_PATH}"
  },
  "receiver": {
     "slot": "pgrwl_v5",
     "no_loop": true,
     "uploader": {
       "sync_interval": "3s",
       "max_concurrency": 4
     }
  },
  "log": {
    "level": "${LOG_LEVEL_DEFAULT}",
    "format": "${LOG_FORMAT_DEFAULT}",
    "add_source": true
  },
  "backup": {
    "cron": "59 23 31 12 *"
  },
  "retention": {
    "enable": false,
    "type": "recovery_window",
    "value": "72h",
    "keep_last": 1
  }
}
EOF
}

x_json_field() {
  local file="$1"
  local field="$2"

  python3 - "$file" "$field" <<'PY'
import json
import sys

path = sys.argv[1]
field = sys.argv[2].lstrip(".")

with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

value = data.get(field, "")
if value is None:
    print("")
elif isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

x_http_json() {
  local method="$1"
  local url="$2"
  local body_file="$3"

  curl -sS \
    -X "${method}" \
    -H "Content-Type: application/json" \
    -o "${body_file}" \
    -w "%{http_code}" \
    "${url}"
}

x_wait_api_ready() {
  log_info "wait for stream API"

  if ! x_wait_http_ok "${API_ADDR}/healthz" 60; then
    echo "pgrwl log:"
    cat "${LOG_FILE}" || true
    log_fatal "stream API did not become ready"
  fi
}

x_wait_basebackup_finished() {
  local timeout="${1:-180}"
  local i
  local code
  local status
  local running
  local last_error

  log_info "wait for basebackup to finish"

  for ((i = 1; i <= timeout; i++)); do
    code="$(x_http_json GET "${BASEBACKUP_STATUS_URL}" "/tmp/basebackup-status.json")"

    if [[ "${code}" != "200" ]]; then
      log_warn "GET /api/v1/basebackup/status returned HTTP ${code}"
      cat "/tmp/basebackup-status.json" || true
      sleep 1
      continue
    fi

    status="$(x_json_field "/tmp/basebackup-status.json" ".status")"
    running="$(x_json_field "/tmp/basebackup-status.json" ".running")"
    last_error="$(x_json_field "/tmp/basebackup-status.json" ".last_error")"

    log_info "basebackup status=${status}, running=${running}"

    case "${status}" in
      succeeded)
        return 0
        ;;
      failed)
        cat "/tmp/basebackup-status.json" || true
        log_fatal "basebackup failed: ${last_error}"
        ;;
      running|idle|"")
        sleep 1
        ;;
      *)
        cat "/tmp/basebackup-status.json" || true
        log_fatal "unexpected basebackup status: ${status}"
        ;;
    esac
  done

  cat "/tmp/basebackup-status.json" || true
  log_fatal "basebackup did not finish in ${timeout}s"
}

x_count_backup_manifests() {
  if [[ ! -d "${WAL_PATH}/backups" ]]; then
    echo 0
    return
  fi

  find "${WAL_PATH}/backups" \
    -type f \
    \( -name "manifest.json" -o -name "*.json" \) \
    2>/dev/null | wc -l | tr -d " "
}

x_count_wal_files() {
  if [[ ! -d "${WAL_PATH}" ]]; then
    echo 0
    return
  fi

  find "${WAL_PATH}" \
    -maxdepth 1 \
    -type f \
    2>/dev/null | wc -l | tr -d " "
}

x_trigger_basebackup() {
  local code

  log_info "trigger manual basebackup"

  code="$(x_http_json POST "${BASEBACKUP_START_URL}" "/tmp/basebackup-start.json")"
  cat "/tmp/basebackup-start.json" || true

  if [[ "${code}" != "200" ]]; then
    cat "${LOG_FILE}" || true
    log_fatal "expected POST /api/v1/basebackup to return 200, got ${code}"
  fi

  local status
  status="$(x_json_field "/tmp/basebackup-start.json" ".status")"

  if [[ "${status}" != "running" && "${status}" != "succeeded" ]]; then
    log_fatal "expected basebackup start status to be running or succeeded, got ${status}"
  fi
}

x_expect_duplicate_basebackup_conflict_if_running() {
  local status
  local code

  status="$(x_json_field "/tmp/basebackup-start.json" ".status")"

  if [[ "${status}" != "running" ]]; then
    log_warn "first backup completed too quickly; skipping duplicate 409 assertion"
    return 0
  fi

  log_info "trigger duplicate manual basebackup"

  code="$(x_http_json POST "${BASEBACKUP_START_URL}" "/tmp/basebackup-duplicate.json")"
  cat "/tmp/basebackup-duplicate.json" || true

  if [[ "${code}" != "409" ]]; then
    cat "${LOG_FILE}" || true
    log_fatal "expected duplicate POST /api/v1/basebackup to return 409, got ${code}"
  fi
}

x_test_stream_api_basebackup() {
  log_info "cleanup"
  x_remake_dirs
  x_remake_config

  log_info "start cluster"
  xpg_rebuild
  xpg_start
  xpg_recreate_slots

  log_info "prepare data before basebackup"
  pgbench -i -s "${API_TEST_PGBENCH_SCALE}" postgres

  echo_delim "start receiver / stream daemon"
  x_start_receiver "/tmp/config.json"
  x_wait_api_ready

  echo_delim "start background inserts"
  chmod +x "${BACKGROUND_INSERTS_SCRIPT_PATH}"
  nohup "${BACKGROUND_INSERTS_SCRIPT_PATH}" >>"${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}" 2>&1 &

  sleep 3

  local manifests_before
  local wal_files_before
  manifests_before="$(x_count_backup_manifests)"
  wal_files_before="$(x_count_wal_files)"

  log_info "before: backup_manifests=${manifests_before}, wal_files=${wal_files_before}"

  x_trigger_basebackup
  x_expect_duplicate_basebackup_conflict_if_running
  x_wait_basebackup_finished 240

  echo_delim "stop background inserts"
  pkill -f inserts.sh || true
  sleep 2

  echo_delim "force WAL switch"
  psql -v ON_ERROR_STOP=1 -d postgres -Atqc "select pg_switch_wal();" >/dev/null
  sleep 5

  local manifests_after
  local wal_files_after
  manifests_after="$(x_count_backup_manifests)"
  wal_files_after="$(x_count_wal_files)"

  log_info "after: backup_manifests=${manifests_after}, wal_files=${wal_files_after}"

  if (( manifests_after <= manifests_before )); then
    find "${WAL_PATH}/backups" -maxdepth 3 -type f -print 2>/dev/null || true
    cat "${LOG_FILE}" || true
    log_fatal "expected backup manifest count to increase"
  fi

  echo_delim "verify receiver process is still alive"
  if [[ -z "${RECEIVER_PID:-}" ]] || ! kill -0 "${RECEIVER_PID}" 2>/dev/null; then
    cat "${LOG_FILE}" || true
    log_fatal "receiver process is not running after basebackup"
  fi

  echo_delim "fetch final basebackup status"
  curl -fsS "${BASEBACKUP_STATUS_URL}" | tee "/tmp/basebackup-status-final.json"

  echo_delim "check logs"
  x_search_errors_in_logs

  echo_delim "OK"
}

x_test_stream_api_basebackup "$@"
