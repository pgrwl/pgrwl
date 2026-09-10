#!/usr/bin/env bash
# Shared helpers for the production-dr scripts. Sourced, not executed.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

COMPOSE="docker compose"
PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$PWD")}"   # compose project name defaults to the directory name
# shellcheck disable=SC2034  # used by the restore scripts
PG_VOLUME="${PROJECT}_pg-data"
PGRWL_API="http://localhost:7070"

psql_primary() { $COMPOSE exec -T pg-primary psql -U postgres -v ON_ERROR_STOP=1 -Atq "$@"; }
log()          { printf '\n[%s] %s\n' "$(date -u '+%H:%M:%S')" "$*"; }

# Waits until PostgreSQL is up and out of recovery. Connection errors while it is
# still starting or replaying are expected; a restarting container is not.
wait_out_of_recovery() {
  for _ in $(seq 1 600); do
    if [ "$(psql_primary -c 'select pg_is_in_recovery()' 2>/dev/null || true)" = "f" ]; then return 0; fi
    # a container that keeps restarting means PostgreSQL refused its configuration
    if [ "$(docker inspect -f '{{.RestartCount}}' pg-primary 2>/dev/null || echo 0)" -gt 0 ]; then
      echo "PostgreSQL failed to start:" >&2; docker logs --tail 8 pg-primary >&2; return 1
    fi
    sleep 1
  done
  echo "PostgreSQL did not finish recovery in 600s; check: $COMPOSE logs pg-primary pgrwl-serve" >&2
  return 1
}

list_backups() { curl -sf "$PGRWL_API/api/v1/backups"; }
