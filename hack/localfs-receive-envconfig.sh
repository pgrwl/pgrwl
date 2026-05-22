#!/usr/bin/env bash
set -euo pipefail

######################################################################
## pgconn envs
######################################################################
export PGHOST=localhost
export PGPORT=5432
export PGUSER=postgres
export PGPASSWORD=postgres

######################################################################
## pgrwl envs
######################################################################
export PGRWL_MAIN_LISTEN_PORT=7070
export PGRWL_MAIN_DIRECTORY=wals
export PGRWL_RECEIVER_SLOT=pgrwl_v5
export PGRWL_LOG_LEVEL="trace"
export PGRWL_LOG_FORMAT="text"
export PGRWL_LOG_ADD_SOURCE="true"

go run ../cmd/pgrwl/main.go daemon
