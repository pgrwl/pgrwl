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
# receiver
export PGRWL_RECEIVER_SLOT=pgrwl_v5
export PGRWL_RECEIVER_UPLOADER_SYNC_INTERVAL=10s
export PGRWL_RECEIVER_UPLOADER_MAX_CONCURRENCY=4
# logs
export PGRWL_LOG_LEVEL=trace
export PGRWL_LOG_FORMAT=text
export PGRWL_LOG_ADD_SOURCE=true
export PGRWL_METRICS_ENABLE=true
# storage
export PGRWL_STORAGE_NAME=s3
export PGRWL_STORAGE_COMPRESSION_ALGO=gzip
export PGRWL_STORAGE_ENCRYPTION_ALGO=aes-256-gcm
export PGRWL_STORAGE_ENCRYPTION_PASS=qwerty123
export PGRWL_STORAGE_S3_URL="https://localhost:9000"
export PGRWL_STORAGE_S3_ACCESS_KEY_ID=minioadmin
export PGRWL_STORAGE_S3_SECRET_ACCESS_KEY=minioadmin123
export PGRWL_STORAGE_S3_BUCKET=backups
export PGRWL_STORAGE_S3_REGION=main
export PGRWL_STORAGE_S3_USE_PATH_STYLE=true
export PGRWL_STORAGE_S3_DISABLE_SSL=true

go run ../cmd/pgrwl/main.go daemon
