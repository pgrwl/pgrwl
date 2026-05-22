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

x_backup_restore() {
  echo_delim "cleanup state"
  x_kill_proc_rmrf_tmp
  x_remake_dirs
  x_remake_config

  # rerun the cluster
  echo_delim "init and run a cluster"
  xpg_rebuild
  xpg_start
  xpg_recreate_slots

  # run wal-receivers
  echo_delim "running wal-receivers"
  x_start_receiver "/tmp/config.json"
  x_start_pg_receivewal

  # create tablespaces
  mkdir -p "/tmp/spaces/alpha"
  mkdir -p "/tmp/spaces/beta"
  chown -R postgres:postgres "/tmp/spaces"

"${PG_BINDIR}/psql" -v ON_ERROR_STOP=1 <<EOSQL
-- tablespaces
CREATE TABLESPACE ts_alpha LOCATION '/tmp/spaces/alpha';
CREATE TABLESPACE ts_beta  LOCATION '/tmp/spaces/beta';
EOSQL

"${PG_BINDIR}/psql" -v ON_ERROR_STOP=1 <<'EOSQL'
-- products
CREATE TABLE products (
    product_id   integer,
    product_name text,
    country      text
) TABLESPACE ts_alpha;

INSERT INTO products (product_id, product_name, country) VALUES
    (1, 'Orion Lamp',    'Germany'),
    (2, 'Silver Pen',    'United Kingdom'),
    (3, 'Blue Notebook', 'Sweden');

-- orders
CREATE TABLE orders (
    order_id    integer,
    description text
) TABLESPACE ts_beta;

INSERT INTO orders (order_id, description) VALUES
    (1, 'First customer order'),
    (2, 'Bulk shipment'),
    (3, 'Online marketplace order');

-- customers
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

  # make a backup before doing anything
  echo_delim "creating backup"
  /usr/local/bin/pgrwl backup -c "/tmp/config.json"

  # run inserts in a background
  chmod +x "${BACKGROUND_INSERTS_SCRIPT_PATH}"
  nohup "${BACKGROUND_INSERTS_SCRIPT_PATH}" >>"${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}" 2>&1 &

  # fill with 1M rows
  echo_delim "running pgbench"
  pgbench -i -s 10 postgres

  # wait a little
  sleep 5

  # stop inserts
  pkill -f inserts.sh

  # remember the state
  pg_dumpall -f "/tmp/pgdumpall-before" --restrict-key=0

  # stop cluster, cleanup data
  echo_delim "teardown"
  x_stop_receiver
  x_stop_pg_receivewal
  xpg_teardown

  # save and cleanup tablespaces
  cp -r "/tmp/spaces" "/tmp/spaces_backup"
  rm -rf /tmp/spaces/*

  # restore from backup
  echo_delim "restoring backup"
  #BACKUP_ID=$(find /tmp/wal-archive/backups -mindepth 1 -maxdepth 1 -type d -printf "%T@ %f\n" | sort -n | tail -1 | cut -d' ' -f2)
  /usr/local/bin/pgrwl restore --dest="${PGDATA}" -c "/tmp/config.json"
  chmod 0750 "${PGDATA}"
  chown -R postgres:postgres "${PGDATA}"
  touch "${PGDATA}/recovery.signal"

  # prepare archive (all partial files contain valid wal-segments)
  find "${WAL_PATH}" -type f -name "*.partial" -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +
  find "${PG_RECEIVEWAL_WAL_PATH}" -type f -name "*.partial" -exec bash -c 'for f; do mv -v "$f" "${f%.partial}"; done' _ {} +

  # fix configs
  xpg_config
  cat <<EOF >>"${PG_CFG}"
restore_command = 'pgrwl restore-command --serve-addr=127.0.0.1:7070 %f %p'
EOF

  # run serve-mode
  echo_delim "running wal fetcher"
  x_start_serving "/tmp/config.json"

  # run restored cluster
  echo_delim "running cluster"
  xpg_start

  # wait until is in recovery, check logs, etc...
  xpg_wait_is_in_recovery
  cat /var/log/postgresql/pg.log

  # check diffs
  echo_delim "running diff on pg_dumpall dumps (before vs after)"
  pg_dumpall -f "/tmp/pgdumpall-after" --restrict-key=0
  diff "/tmp/pgdumpall-before" "/tmp/pgdumpall-after"
  echo_delim "running diff on tablespaces (before vs after)"
  diff -r "/tmp/spaces_backup" "/tmp/spaces"

  # read the latest rec
  echo_delim "read latest applied records"
  echo "table content:"
  psql --pset pager=off -c "select * from public.tslog;"
  echo "insert log content:"
  tail -10 "${BACKGROUND_INSERTS_SCRIPT_LOG_FILE}"

  # compare with pg_receivewal
  echo_delim "compare wal-archive with pg_receivewal"
  find "${WAL_PATH}" -type f -name "*.json" -delete
  rm -rf "${WAL_PATH}/backups"
  bash "/var/lib/postgresql/scripts/utils/dircmp.sh" "${WAL_PATH}" "${PG_RECEIVEWAL_WAL_PATH}"

  echo_delim "run post_restore_check.sql"
  x_run_post_restore_check

  x_search_errors_in_logs_or_fatal
  x_print_ok
}

x_backup_restore "${@}"
