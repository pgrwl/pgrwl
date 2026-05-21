# pgrwl

> Cloud-native continuous backup for PostgreSQL in a single binary.

[![License](https://img.shields.io/github/license/pgrwl/pgrwl)](https://github.com/pgrwl/pgrwl/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/pgrwl/pgrwl)](https://goreportcard.com/report/github.com/pgrwl/pgrwl)
[![Go Reference](https://pkg.go.dev/badge/github.com/pgrwl/pgrwl.svg)](https://pkg.go.dev/github.com/pgrwl/pgrwl)
[![Workflow Status](https://img.shields.io/github/actions/workflow/status/pgrwl/pgrwl/ci.yml?branch=master)](https://github.com/pgrwl/pgrwl/actions/workflows/ci.yml?query=branch:master)
[![GitHub Issues](https://img.shields.io/github/issues/pgrwl/pgrwl)](https://github.com/pgrwl/pgrwl/issues)
[![Go Version](https://img.shields.io/github/go-mod/go-version/pgrwl/pgrwl)](https://github.com/pgrwl/pgrwl/blob/master/go.mod#L3)
[![Latest Release](https://img.shields.io/github/v/release/pgrwl/pgrwl)](https://github.com/pgrwl/pgrwl/releases/latest)
[![Start contributing](https://img.shields.io/github/issues/pgrwl/pgrwl/good%20first%20issue?color=7057ff&label=Contribute)](https://github.com/pgrwl/pgrwl/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc+label%3A%22good+first+issue%22)

**pgrwl** is a Go-based PostgreSQL backup tool for continuous WAL archiving and scheduled base backups. It streams
PostgreSQL WALs and base backups into local or remote storage, with optional compression, encryption, retention, and
monitoring built in.

It is designed for disaster recovery and PITR (Point-in-Time Recovery), with a focus on low operational complexity:
no extra backup tools, no external schedulers, and no dependency chain to operate - just one binary, PostgreSQL, and
your chosen storage backend.

For WAL streaming, `pgrwl` behaves as a container-friendly alternative to `pg_receivewal`, supporting streaming
replication, automatic reconnects, partial WAL files, archive upload, retention, and restore integration.

---

## Table of Contents

- [About](#about)
- [Quick Start](#quick-start)
- [Configuration Reference](docs/pgrwl/configuration.md)
- [Installation](docs/pgrwl/installation.md)
- [Disaster Recovery Use Cases](#disaster-recovery-use-cases)
- [Architecture](#architecture)
    - [Design Notes](#design-notes)
    - [Durability \& `fsync`](#durability--fsync)
    - [Why Not `archive_command`?](#why-not-archive_command)
- [Contributing](#contributing)
- [Links](docs/pgrwl/links.md)
- [License](#license)

---

## About

Reliable PostgreSQL backups come with moving parts: WAL handling, scheduled jobs, compression, remote storage, 
and retention - each one more thing to configure, monitor, and debug.

`pgrwl` replaces that entire stack with a single process: WAL streaming, scheduled base backups,
compression, encryption, S3/SFTP upload, retention management, and a restore helper - all driven
by one config file. No external schedulers, no backup tool chains, no extra services to operate.

It implements the streaming replication protocol directly (not `archive_command`), which means
it supports replication slots, `*.partial` WAL files, and synchronous replication acknowledgment -
enabling **RPO=0** in high-durability setups.

**Basic dashboard**

![UI](https://raw.githubusercontent.com/hashmap-kz/assets/main/pgrwl/pgrwl-ui-v5.png)

**Architecture**

![Receive Mode](docs/assets/svg/stream-mode.svg)

---

## Quick Start 

```sh
# Install
curl -fsSL https://raw.githubusercontent.com/pgrwl/pgrwl/master/scripts/install.sh | sh

# Start PostgreSQL with replication enabled
cat >docker-compose.yml <<'EOF'
services:
  pg:
    image: postgres:17.9-bookworm
    environment:
      POSTGRES_PASSWORD: postgres
    ports: ["15432:5432"]
    command: >
      postgres
      -c wal_level=replica
      -c max_wal_senders=10
      -c max_replication_slots=10
      -c listen_addresses=*
      -c hba_file=/etc/postgresql/pg_hba.conf
    configs:
      - source: pg_hba.conf
        target: /etc/postgresql/pg_hba.conf
        mode: "0755"
configs:
  pg_hba.conf:
    content: |
      local all         all     trust
      local replication all     trust
      host  all         all all trust
      host  replication all all trust
EOF
docker compose up -d

# Configure and run pgrwl
cat >config.yml <<'EOF'
main:
  listen_port: 7070
  directory: wals
receiver:
  slot: pgrwl_v5
  uploader:
    sync_interval: 15s
    max_concurrency: 2
backup:
  cron: "* * * * *"
EOF

PGHOST=localhost PGPORT=15432 PGUSER=postgres PGPASSWORD=postgres \
    pgrwl daemon -c config.yml -m receive
```

**Kubernetes examples**

See [examples](https://github.com/pgrwl/pgrwl/tree/master/examples/k8s-quick-start)

**Docker-Compose examples (s3, ui)**

See [examples](docs/pgrwl/docker-compose-quick-start.md)

**Restore command**

See [restore_command](docs/pgrwl/restore-command.md)

---

## Disaster Recovery Use Cases

_The full process may look like this (a typical, rough, and simplified example):_

- A typical production setup runs `pgrwl` in **stream mode** as the main backup/archiving daemon.
  In this mode, one process is responsible for **continuous WAL streaming**, **WAL archiving**, scheduled
  **base backups**, optional manual basebackup triggers, metrics, and the HTTP API.

- In stream mode, `pgrwl` continuously **streams WAL files** from PostgreSQL, writes them locally as
  `*.partial` files while they are still being received, and renames them to final WAL segment names once
  the segment is complete.

- The archive supervisor periodically scans completed WAL files, applies optional **compression** and
  **encryption**, uploads them to the configured storage backend, such as **S3**, **SFTP**, or local storage,
  and removes the local copy after a successful upload.

- The basebackup supervisor performs full base backups on a configured schedule, for example **once every
  three days**, using streaming basebackup. A basebackup can also be triggered manually through the HTTP API.
  Basebackup failures are reported and logged, but they do not stop the WAL receiver, because WAL streaming
  is the critical part of the system.

- WAL files and basebackups are stored in the same configured storage backend, but under different logical
  paths or prefixes. For example, WAL files may be stored under a WAL archive path, while basebackup files
  and manifests are stored under a backups path.

- Retention is handled by a single **recovery-window retention manager**. Instead of deleting WALs and
  backups independently, it chooses an **anchor backup**: the newest successful basebackup that started
  before the beginning of the configured recovery window. It then keeps that backup, all newer successful
  backups, and all WAL files required to restore forward from the anchor backup.

- For example, with a recovery window of **72 hours**, `pgrwl` keeps enough backup and WAL history to recover
  to any point within the last three days. WAL files older than the anchor backup’s start WAL can be removed,
  while WAL files from the anchor backup onward are kept.

- During recovery, `pgrwl` can run in **restore mode** as a restore daemon. PostgreSQL’s `restore_command`
  invokes the lightweight `pgrwl restore-command` helper, which asks the restore daemon for the requested WAL
  file and writes it to the path expected by PostgreSQL.

- With this setup, you're able to restore your cluster after a crash to **any point covered by the configured
  recovery window**, using the retained basebackup and the WAL files kept from that backup onward.

---

## Architecture

### Design Notes

`pgrwl` is designed to **always stream WAL data to the local filesystem first**. This design ensures durability and
correctness, especially in synchronous replication setups where PostgreSQL waits for the replica to confirm the commit.

- Incoming WAL data is written directly to `*.partial` files in a local directory.
- These `*.partial` files are synced (`fsync`) after each write to ensure that WAL segments are fully durable on disk.
- Once a WAL segment is fully received, the `*.partial` suffix is removed, and the file is considered complete.

**Compression and encryption** are applied only after a WAL segment is completed:

- Completed files are passed to the uploader worker, which may compress and/or encrypt them before uploading to a remote
  backend (e.g., S3, SFTP).
- The uploader worker **ignores partial files** and operates only on finalized, closed segments.

This model avoids the complexity and risk of streaming incomplete WAL data directly to remote storage, which can lead to
inconsistencies or partial restores. By ensuring that all WAL files are locally durable and only completed files are
uploaded, `pgrwl` guarantees restore safety and clean segment handoff for disaster recovery.

In short: **PostgreSQL requires acknowledgments for commits in synchronous setups**, and relying on external systems for
critical paths (like WAL streaming) could introduce unacceptable delays or failures. This architecture mitigates that
risk.

### Durability & `fsync`

- After each WAL segment is written, an `fsync` is performed on the currently open WAL file to ensure durability.
- An `fsync` is triggered when a WAL segment is completed and the `*.partial` file is renamed to its final form.
- An `fsync` is triggered when a keepalive message is received from the server with the `reply_requested` option set.
- Additionally, `fsync` is called whenever an error occurs during the receive-copy loop.

### Why Not `archive_command`?

There’s a significant difference between using `archive_command` and archiving WAL files via the streaming replication
protocol.

The `archive_command` is triggered only after a WAL file is fully completed-typically when it reaches 16 MiB (the
default segment size). This means that in a crash scenario, you could lose up to 16 MiB of data.

You can mitigate this by setting a lower `archive_timeout` (e.g., 1 minute), but even then, in a worst-case scenario,
you risk losing up to 1 minute of data.
Also, it’s important to note that PostgreSQL preallocates WAL files to the configured `wal_segment_size`, so they are
created with full size regardless of how much data has been written. (Quote from documentation:
_It is therefore unwise to set a very short `archive_timeout` - it will bloat your archive storage._).

In contrast, streaming WAL archiving-when used with replication slots and the `synchronous_standby_names`
parameter-ensures that the system can be restored to the latest committed transaction.
This approach provides true zero data loss (**RPO=0**), making it ideal for high-durability requirements.

## Contributing

Contributions are welcomed and greatly appreciated. See [CONTRIBUTING.md](./CONTRIBUTING.md)
for details on submitting patches and the contribution workflow.

Check also the [Developer Notes](docs/pgrwl/developer-notes.md) for additional information and guidelines.

Debug with your favorite editor and a local PostgreSQL container ([local-dev-infra](test/integration/environ/)).

---

## License

MIT. See [LICENSE](./LICENSE) for details.
