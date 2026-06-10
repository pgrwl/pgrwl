# Glossary

This page explains the PostgreSQL concepts that `pgrwl` is built on. It is written for people who
are new to PostgreSQL and want to understand why a backup tool needs all of these moving parts.
Each term has a short definition and a link to the official PostgreSQL documentation if you want to
go deeper.

---

## The big picture

PostgreSQL writes down every change before it touches the real data files. That running record is
the [WAL](#wal-write-ahead-log), and every position inside it has an address called an
[LSN](#lsn-log-sequence-number). `pgrwl` connects to PostgreSQL much like a replica would and copies
this stream to local disk as it is produced. The segment it is currently receiving is stored as a
[`.partial` file](#partial-file) and flushed to disk on every write, so a sudden crash cannot lose
work that was already committed. So that PostgreSQL never deletes WAL before `pgrwl` has copied it,
the server keeps a [replication slot](#replication-slot) that remembers how far `pgrwl` has read.

WAL on its own only describes changes; it needs something to apply those changes to. That starting
point is a [base backup](#base-backup), a full copy of the database taken at a known position in the
log. Put the two together and you get [PITR](#pitr-point-in-time-recovery): restore the base backup,
then replay WAL forward until you reach the exact moment you want. When a restore creates a new
branch of history, PostgreSQL records it as a fresh [timeline](#timeline) so the old and new
histories never get mixed up.

The reason for all of this is to control your [RPO](#rpo-recovery-point-objective), which is how much
data you could lose if the server failed right now. Because `pgrwl` captures WAL continuously instead
of waiting for each 16 MB segment to fill, it can shrink that window all the way to zero in a
synchronous setup. This means no committed transaction is ever lost.

---

## WAL (Write-Ahead Log)

PostgreSQL never changes a data file without first writing down what it is about to do. That note
goes into the Write-Ahead Log, usually shortened to WAL. The WAL is a single, append-only stream
that records every change in the order it happened.

This ordering is what makes recovery possible. If the server crashes, PostgreSQL reads the log back
and redoes any work that had not yet reached the data files. The same property powers backups: if
you have an older copy of the database plus every WAL record written since, you can replay those
records to rebuild the database up to any later point. Capturing this stream safely is the main job
of `pgrwl`.

- Docs: <https://www.postgresql.org/docs/current/wal-intro.html>

## LSN (Log Sequence Number)

As WAL is written, every byte in it gets an address called a Log Sequence Number, or LSN. It is
shown as two hexadecimal numbers joined by a slash, for example `16/B374D848`. The simplest way to
think about it is as a position marker in the log: a larger LSN just means "further along".

LSNs matter because every component measures progress with the same numbers. PostgreSQL, its
replicas, and `pgrwl` all describe how much WAL has been written, sent, saved to disk, or replayed
in terms of an LSN. Most replication and recovery decisions come down to comparing two of them.

- Docs: <https://www.postgresql.org/docs/current/datatype-pg-lsn.html>

## Timeline

A timeline is a numbered branch of WAL history. Most of the time a database runs on a single
timeline and the log simply grows. The idea becomes important during recovery.

When you restore from a backup and recover to a point in the past, the events that originally came
after that point still exist in the old WAL. To avoid writing a conflicting history on top of them,
PostgreSQL starts a new timeline at the moment of recovery and increases the timeline number. The
timeline ID is part of every WAL file name, which is how PostgreSQL and `pgrwl` tell the branches
apart and follow the correct one when restoring.

- Docs: <https://www.postgresql.org/docs/current/continuous-archiving.html#BACKUP-TIMELINES>

## Replication slot

A replication slot is a bookmark that PostgreSQL keeps on the server for one specific consumer, such
as `pgrwl`. The slot records the last WAL position that consumer has safely received. As long as the
slot exists, PostgreSQL will not delete or recycle any WAL beyond that position, even if the consumer
disconnects for a while.

This is what guarantees `pgrwl` never misses a segment. It comes with a real trade-off: if the
consumer stays offline, WAL keeps building up on the server and can eventually fill the disk. For
that reason a slot that is no longer in use should be removed.

- Docs: <https://www.postgresql.org/docs/current/warm-standby.html#STREAMING-REPLICATION-SLOTS>

## `.partial` file

WAL is divided into fixed-size chunks called segments, 16 MB each by default. While a segment is
still being received it is not yet a complete file, so `pgrwl` stores it under a name ending in
`.partial`.

As more data arrives, `pgrwl` appends it to this file and calls `fsync`, which forces the operating
system to flush the bytes to physical disk instead of leaving them in memory. Once the full segment
has been received, `pgrwl` renames the file and drops the `.partial` suffix. Keeping the in-progress
segment on local disk is what lets a restore use the most recent committed changes, even though that
segment is not finished and has not been uploaded to remote storage yet.

- Docs: <https://www.postgresql.org/docs/current/app-pgreceivewal.html>

## Base backup

WAL alone cannot rebuild a database, because it only describes changes. You also need something to
apply those changes to. A base backup is that something: a complete physical copy of the PostgreSQL
data directory, taken at a known position in the WAL stream.

Every restore follows the same two steps. First lay down the base backup, then replay WAL forward
from the position where the backup began. `pgrwl` takes base backups on a schedule and can also
create one on demand through its HTTP API.

- Docs: <https://www.postgresql.org/docs/current/continuous-archiving.html#BACKUP-BASE-BACKUP>

## PITR (Point-in-Time Recovery)

Point-in-Time Recovery, or PITR, is the ability to restore the database to a chosen moment in the
past rather than only to its latest state. It works by combining the two pieces above: restore a
base backup, then replay archived WAL forward until you reach the target you asked for. That target
can be a timestamp, a specific LSN, or a named restore point.

PITR is the main reason `pgrwl` exists. Continuously capturing WAL and base backups is exactly what
makes this kind of recovery possible.

- Docs: <https://www.postgresql.org/docs/current/continuous-archiving.html#BACKUP-PITR-RECOVERY>

## RPO (Recovery Point Objective)

Recovery Point Objective, or RPO, describes how much data you can afford to lose, measured as a span
of time. An RPO of five minutes means a disaster may cost you up to the last five minutes of changes.
An RPO of zero means no committed transaction is ever lost.

The older `archive_command` approach copies WAL only after a full 16 MB segment fills up, so a crash
can lose everything written since the last completed segment. `pgrwl` streams WAL as it is produced,
and in a synchronous setup it can wait for the standby to confirm each commit. Together these let it
reach **RPO = 0**.

- Docs: <https://www.postgresql.org/docs/current/continuous-archiving.html>

---

## See also

- [Links](links.md) — curated PostgreSQL references used throughout these docs.
