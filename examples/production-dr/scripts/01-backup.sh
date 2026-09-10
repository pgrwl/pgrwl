#!/usr/bin/env bash
# Take a base backup with pgrwl (streaming replication protocol, no pg_basebackup).
# The receiver keeps streaming WAL while the backup runs; the replication slot
# guarantees that every WAL record after the backup's start LSN is retained.
source "$(dirname "$0")/lib.sh"

log "taking base backup"
$COMPOSE exec -T pgrwl-receive pgrwl backup -c /etc/pgrwl-config.yaml

log "backups known to the receiver"
list_backups; echo
