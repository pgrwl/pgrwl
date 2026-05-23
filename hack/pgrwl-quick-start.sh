#!/usr/bin/env bash
set -euo pipefail

# Clone repo
git clone https://github.com/pgrwl/pgrwl.git
cd pgrwl

# Prepare docker-compose files
cat <<EOF >pg_hba.conf
local all         all     trust
local replication all     trust
host  all         all all trust
host  replication all all trust
EOF

cat <<EOF >docker-compose.yml
services:
  pg-primary:
    image: postgres:17
    container_name: pg-primary
    restart: unless-stopped
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "15432:5432"
    volumes:
      - pg-primary-data:/var/lib/postgresql/17/main
      - ./pg_hba.conf:/etc/postgresql/pg_hba.conf:ro
    command: -c wal_level=replica
      -c max_wal_senders=10
      -c wal_keep_size=64MB
      -c listen_addresses=*
      -c log_replication_commands=on
      -c hba_file=/etc/postgresql/pg_hba.conf
volumes:
  pg-primary-data:
EOF

# Run containers, wait while pg is ready
docker compose up -d
until docker exec pg-primary pg_isready -U postgres >/dev/null 2>&1; do
  echo "Waiting for PostgreSQL to be ready..."
  sleep 1
done

# Run WAL receiver with local storage
cat <<EOF >config.yml
main:
  listen_port: 7070
  directory: wals
receiver:
  slot: pgrwl_v5
log:
  level: trace
  format: text
  add_source: true
EOF

export PGHOST=localhost
export PGPORT=15432
export PGUSER=postgres
export PGPASSWORD=postgres
export PGRWL_DAEMON_MODE=receive
go run cmd/pgrwl/main.go daemon -c config.yml
