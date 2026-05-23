#!/usr/bin/env bash
# Parallel integration test runner for local development.
#
# minio / sshd / toxiproxy start once and are shared by all parallel tests.
# Tests run as 'docker compose run' containers in the same compose project,
# so they reach infra services by their Docker service names (minio:9000, etc.).
#
# Usage:
#   PG_MAJOR=17 bash run-tests-par.sh                   # all tests in parallel
#   PG_MAJOR=17 bash run-tests-par.sh pg_003_s3         # single test
#   BUILD=1 PG_MAJOR=17 bash run-tests-par.sh           # force rebuild first

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PG_MAJOR="${PG_MAJOR:-17}"
BUILD="${BUILD:-}"

COMPOSE_FILE="${SCRIPT_DIR}/docker-compose-par.yml"
PROJECT="pgrwl_par_${PG_MAJOR}"

ALL_TESTS=(
  pg_001_fundamental
  pg_002_write_loop
  pg_003_s3
  pg_004_sftp
  pg_005_restore_localfs
  pg_006_restore_s3
  pg_007_tablespaces_localfs
  pg_008_dynstor
  pg_009_s3_remote_only_restore
  pg_009_sftp_remote_only_restore
  pg_010_timing_parity_1
  pg_010_timing_parity_2
  pg_011_basic_flow
  pg_012_restore_s3_toxiproxy
  pg_014_stream_api_bb
  pg_016_reconnect
)

if [[ $# -gt 0 ]]; then
  TESTS=("$@")
else
  TESTS=("${ALL_TESTS[@]}")
fi

_dc() {
  COMPOSE_PROJECT_NAME="$PROJECT" PG_MAJOR="$PG_MAJOR" \
    docker compose -f "$COMPOSE_FILE" "$@"
}

# Build binary if missing or BUILD=1
if [[ -n "$BUILD" || ! -f "${SCRIPT_DIR}/bin/pgrwl" ]]; then
  echo "==> building binary..."
  rm -rf "${SCRIPT_DIR:?}/bin"
  (cd "$REPO_ROOT" && make build-linux)
  mv "${REPO_ROOT}/bin" "${SCRIPT_DIR}/"
fi

# Build Docker images if missing or BUILD=1
if [[ -n "$BUILD" ]] || ! docker image inspect "pgrwl/pg-primary-${PG_MAJOR}" &>/dev/null; then
  echo "==> building docker images (PG_MAJOR=${PG_MAJOR})..."
  _dc build
fi

# Start shared infra once; minio healthcheck ensures it is ready before returning
echo "==> starting infra (minio, sshd, toxiproxy)..."
_dc up -d minio sshd toxiproxy

LOG_DIR="${SCRIPT_DIR}/test_logs"
rm -rf "$LOG_DIR" && mkdir -p "$LOG_DIR"
trap '_dc down -v --remove-orphans >/dev/null 2>&1 || true' EXIT

run_test() {
  local test="$1"
  local logfile="${LOG_DIR}/${test}.log"
  local start=$SECONDS
  local rc=0

  # --no-deps: infra already running; --rm: remove container after exit
  _dc run --no-deps --rm "$test" >>"$logfile" 2>&1 || rc=$?

  local elapsed=$((SECONDS - start))
  if [[ $rc -eq 0 ]]; then
    printf "  \033[32mPASS\033[0m  %-45s %ds\n" "$test" "$elapsed"
  else
    printf "  \033[31mFAIL\033[0m  %-45s %ds\n" "$test" "$elapsed"
  fi

  return $rc
}

echo "==> running ${#TESTS[@]} tests in parallel (PG_MAJOR=${PG_MAJOR})"
echo ""

declare -A pids
for test in "${TESTS[@]}"; do
  (run_test "$test") &
  pids["$test"]=$!
done

declare -A exit_codes
failed=0
for test in "${TESTS[@]}"; do
  if wait "${pids[$test]}"; then
    exit_codes["$test"]=0
  else
    exit_codes["$test"]=1
    failed=$((failed + 1))
  fi
done

echo ""

if [[ $failed -gt 0 ]]; then
  # for test in "${TESTS[@]}"; do
  #   if [[ "${exit_codes[$test]}" -ne 0 ]]; then
  #     printf "\033[31m--- logs: %s ---\033[0m\n" "$test"
  #     tail -60 "${LOG_DIR}/${test}.log"
  #     echo ""
  #   fi
  # done
  echo "${failed}/${#TESTS[@]} tests FAILED"
  exit 1
fi

echo "all ${#TESTS[@]} tests passed"
