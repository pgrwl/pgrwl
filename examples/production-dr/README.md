# Production-style disaster recovery with pgrwl

A small, complete backup-and-restore setup you can run on a laptop and repeat on a server:
PostgreSQL 17, `pgrwl` streaming WAL and base backups to S3 (SeaweedFS here), and two
rehearsed recoveries: **restore to the latest transaction** after losing the data directory,
and **point-in-time recovery** to just before an accidental `DROP TABLE`.

Everything happens with `pgrwl` commands only: no `pg_basebackup`, no renaming of `.partial`
files, no hand-written `restore_command` wrappers.

```
pg-primary       PostgreSQL 17 + the pgrwl binary (Dockerfile)      normal operation
pgrwl-receive    streams WAL, uploads segments and base backups      normal operation
seaweedfs        S3-compatible storage, one container                normal operation
pgrwl-serve      serves WAL to the recovering PostgreSQL             restore only
pg-restore       one-shot: base backup -> PGDATA, recovery settings  restore only
```

Requirements: Docker Compose v2, `curl`. On an arm64 host uncomment the `platform:` lines in
`docker-compose.yml` (the `quay.io/pgrwl/pgrwl` image is published for amd64 only).

## 1. Start and take the first base backup

```bash
docker compose up -d --build
scripts/01-backup.sh          # pgrwl backup, then lists backups from http://localhost:7070/api/v1/backups
scripts/02-workload.sh 30     # one timestamped row per second into dr_events, so restores are checkable
```

Order matters: the receiver starts first (compose does that), the base backup comes second. The
receiver creates the replication slot, and the slot is what makes PostgreSQL keep every WAL record
from the backup's start LSN (`wal_start_lsn` in the API output) until the receiver has it. A base
backup taken before the slot exists can lose the WAL it needs. The receiver keeps streaming while
the backup runs.

## 2. Scenario A: the data directory is gone

```bash
scripts/04-restore-latest.sh
```

What the script does, in order:

1. stops `pg-primary` and `pgrwl-receive`, deletes the `pg-data` volume (this is the disaster)
2. starts `pgrwl-serve`: PostgreSQL will pull WAL from it during recovery
3. runs `pg-restore`: `pgrwl restore` writes the newest base backup into the empty PGDATA,
   creates `recovery.signal` and a `postgresql.auto.conf` with
   `restore_command = 'pgrwl restore-command --serve-addr=pgrwl-serve:7070 %f %p'`
4. starts `pg-primary`: archive recovery replays every WAL file the archive has, then promotes
5. starts `pgrwl-receive` again and stops `pgrwl-serve`

Expected output: `recovered to timeline 2 in Ns` and the same row count `dr_events` had before.

## 3. Scenario B: someone dropped a table

```bash
scripts/01-backup.sh                 # optional; any earlier backup works too
scripts/02-workload.sh 15
scripts/03-accident.sh               # prints T, then DROP TABLE dr_events
scripts/05-restore-pitr.sh "<T>"     # T exactly as printed, e.g. "2026-09-09 10:15:30.123456+00"
```

Same five steps as scenario A, with two differences:

- the base backup is chosen for you: the newest one whose `finished` time precedes T
  (from `/api/v1/backups`; pass an id as the second argument to choose yourself)
- `pg-restore` adds `recovery_target_time = '<T>'` and `recovery_target_action = 'promote'`

Expected output: the table is back, `rows after T (must be 0): 0`, and PostgreSQL's log shows
`recovery stopping before commit of transaction N` for the transaction that dropped the table.

The scripts restore in place for brevity. On a real system, run scenario B on a separate instance
(or a copy of the data directory), take what you need from it, and leave the production cluster
alone: everything committed after T is gone on the restored copy.

## 4. After any restore

- The cluster is on a **new timeline**. The receiver notices, follows the timeline switch and
  recreates its replication slot; check `docker compose logs pgrwl-receive` for
  `end of timeline, continue`.
- Take a **new base backup** (`scripts/01-backup.sh`). Backups taken before the restore remain
  usable for the old timeline only.
- Retention is disabled in this example so you can rehearse freely. In production set
  `receiver.retention` to the recovery window you need.

## 5. What you can lose

`pgrwl` uploads a WAL segment when it is complete; the segment being written lives on the
receiver's volume (`pgrwl-data`) until then. `pgrwl-serve` reads that volume first, so as long as
the receiver's disk survives, recovery reaches the last committed transaction. If the receiver
host is lost together with the database, recovery uses S3 alone and stops at the last **completed**
segment. Measured here: after `SELECT pg_switch_wal()` and the 10 s upload interval, every row written
afterwards was lost; everything before it was recovered. To rehearse it:

```bash
docker compose --profile restore rm -sf pgrwl-receive pgrwl-serve
docker volume rm production-dr_pgrwl-data
scripts/04-restore-latest.sh
```

Keep the receiver's volume on durable storage, and bound the exposure with `archive_timeout`
(for example `archive_timeout = 60s`): PostgreSQL then switches to a new segment at least that
often, even with `archive_mode = off`, so the receiver can upload it. Each switch costs one 16 MiB
segment in the archive (compressed by `pgrwl`).

## 6. The same steps on a VM

| Step | Container | VM |
|---|---|---|
| WAL source for recovery | `pgrwl-serve` service | `pgrwl daemon -m serve -c pgrwl.yaml` on the host that has the archive |
| Base backup into PGDATA | `pg-restore` service | `pgrwl restore -c pgrwl.yaml --dest=$PGDATA [--id=ID]` |
| Recovery settings | written by `restore.sh` | `touch $PGDATA/recovery.signal`, `restore_command`, optional `recovery_target_*` in `postgresql.auto.conf` |
| Start and wait | `docker compose up -d pg-primary` | `pg_ctl start`, wait for `pg_is_in_recovery() = false` |

`restore.sh` is intentionally short; read it once and the container-specific part is over.

## Troubleshooting

- `recovery ended before configured recovery target was reached`: either the chosen base backup
  finished after T (pick an older id from `curl localhost:7070/api/v1/backups` and pass it as the
  second argument), or T is later than the last WAL in the archive (use `04-restore-latest.sh`).
- `invalid value for parameter "recovery_target_time"`: use PostgreSQL's own format,
  `YYYY-MM-DD HH:MM:SS.US+00`; `T`/`Z` ISO variants are rejected.
- `refusing to restore: PGDATA is not empty`: the `pg-data` volume still exists; the scripts delete
  it first, on a VM move the old directory aside.
- `no manifest file (*<id>.json*) found for backup <id>`: the newest backup was still running when
  the disaster happened. Pass the previous id with `--id` (`RESTORE_ID=<id> scripts/04-restore-latest.sh`).
- Backup ids are UTC start times (`YYYYMMDDHHMMSS`). If the receiver is down and the API is not
  available, `pgrwl restore` without `--id` takes the newest backup.
