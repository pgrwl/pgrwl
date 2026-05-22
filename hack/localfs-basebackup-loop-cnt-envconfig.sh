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

# main
export PGRWL_MAIN_LISTEN_PORT=7070
export PGRWL_MAIN_DIRECTORY=wals
export PGRWL_LOG_LEVEL="trace"
export PGRWL_LOG_FORMAT="text"
export PGRWL_LOG_ADD_SOURCE="true"
# backup
export PGRWL_BACKUP_CRON="* * * * *"
export PGRWL_BACKUP_RETENTION_ENABLE='true'
export PGRWL_BACKUP_RETENTION_TYPE='count'
export PGRWL_BACKUP_RETENTION_VALUE='2'
export PGRWL_BACKUP_RETENTION_KEEP_LAST='1'

go run ../cmd/pgrwl/main.go daemon
