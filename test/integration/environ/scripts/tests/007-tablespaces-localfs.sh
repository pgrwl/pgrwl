#!/usr/bin/env bash
set -euo pipefail
. /var/lib/postgresql/scripts/tests/utils.sh

x_remake_config() {
  cat <<EOF > "/tmp/config.json"
{
  "main": {
    "listen_port": 7070,
    "directory": "/tmp/wal-archive"
  },
  "receiver": {
    "slot": "pgrwl_v5",
    "no_loop": true
  },
  "log": {
    "level": "${LOG_LEVEL_DEFAULT}",
    "format": "${LOG_FORMAT_DEFAULT}",
    "add_source": true
  },
  "backup": {
    "cron": "*/50 * * * *"
  }
}
EOF
}

x_hook_after_cluster_start() {
  xpg_recreate_slots
}

x_hook_start_extra_receivers() {
  x_start_pg_receivewal
}

x_hook_before_create_backup() {
  mkdir -p "/tmp/spaces/alpha"
  mkdir -p "/tmp/spaces/beta"
  chown -R postgres:postgres "/tmp/spaces"

  "${PG_BINDIR}/psql" -v ON_ERROR_STOP=1 <<EOSQL
CREATE TABLESPACE ts_alpha LOCATION '/tmp/spaces/alpha';
CREATE TABLESPACE ts_beta  LOCATION '/tmp/spaces/beta';
EOSQL

  "${PG_BINDIR}/psql" -v ON_ERROR_STOP=1 <<'EOSQL'
CREATE TABLE products (
    product_id   integer,
    product_name text,
    country      text
) TABLESPACE ts_alpha;

INSERT INTO products (product_id, product_name, country) VALUES
    (1, 'Orion Lamp',    'Germany'),
    (2, 'Silver Pen',    'United Kingdom'),
    (3, 'Blue Notebook', 'Sweden');

CREATE TABLE orders (
    order_id    integer,
    description text
) TABLESPACE ts_beta;

INSERT INTO orders (order_id, description) VALUES
    (1, 'First customer order'),
    (2, 'Bulk shipment'),
    (3, 'Online marketplace order');

CREATE TABLE customers (
    customer_id integer,
    full_name   text,
    secret_hash text
);

INSERT INTO customers (customer_id, full_name, secret_hash) VALUES
    (1, 'alice01',      'hash_a1b2c3'),
    (2, 'bob_dev',      'hash_x9y8z7'),
    (3, 'charlie_k',    'hash_q2w3e4'),
    (4, 'dora_admin',   'hash_l0p9m8');
EOSQL
}

x_hook_create_backup() {
  echo_delim "creating backup"
  /usr/local/bin/pgrwl backup -c "/tmp/config.json"
}

x_hook_generate_wal() {
  chmod +x "${BACKGROUND_INSERTS_SCRIPT_PATH}"
  nohup "${BACKGROUND_INSERTS_SCRIPT_PATH}" >>"${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}" 2>&1 &
  echo_delim "running pgbench"
  pgbench -i -s 10 postgres
  sleep 5
  pkill -f inserts.sh
}

x_hook_stop_extra_receivers() {
  x_stop_pg_receivewal
}

x_hook_restore_data() {
  cp -r "/tmp/spaces" "/tmp/spaces_backup"
  rm -rf /tmp/spaces/*
  /usr/local/bin/pgrwl restore --dest="${PGDATA}" -c "/tmp/config.json"
  chmod 0750 "${PGDATA}"
  chown -R postgres:postgres "${PGDATA}"
  touch "${PGDATA}/recovery.signal"
}

x_hook_rename_extra_partials() {
  find "${PG_RECEIVEWAL_WAL_PATH}" -type f -name "*.partial" -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +
}

x_hook_after_diff() {
  echo_delim "running diff on tablespaces (before vs after)"
  diff -r "/tmp/spaces_backup" "/tmp/spaces"

  echo_delim "read latest applied records"
  echo "table content:"
  psql --pset pager=off -c "select * from public.tslog;"
  echo "insert log content:"
  tail -10 "${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}"

  echo_delim "compare wal-archive with pg_receivewal"
  find "${WAL_PATH}" -type f -name "*.json" -delete
  rm -rf "${WAL_PATH}/backups"
  bash "/var/lib/postgresql/scripts/utils/dircmp.sh" "${WAL_PATH}" "${PG_RECEIVEWAL_WAL_PATH}"
}

x_run_backup_restore "${@}"
