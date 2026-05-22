#!/usr/bin/env bash
set -euo pipefail

export PGHOST=localhost
export PGPORT=5432
export PGUSER=postgres
export PGPASSWORD=postgres

go run ../cmd/pgrwl/main.go daemon -c configs/s3/receive.yml
