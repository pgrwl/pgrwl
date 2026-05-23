package backupsv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/pgrwl/pgrwl/config"
	"github.com/pgrwl/pgrwl/internal/opt/basebackup/backupdto"
	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const retentionScenarioWalSegSize = 16 * 1024 * 1024

func TestRecoveryWindowRetentionBackupBeginWALConvertsLSNToSegmentNumber(t *testing.T) {
	retention := &recoveryWindowRetention{
		opts: &BackupSupervisorOpts{WalSegSz: retentionScenarioWalSegSize},
	}

	lsn, err := pglogrepl.ParseLSN("3C/D9000000")
	require.NoError(t, err)

	info := &backupdto.Result{
		TimelineID: 1,
		StartLSN:   lsn,
	}

	got := retention.backupBeginWAL(info)

	assert.Equal(t, "000000010000003C000000D9", got)
}

func TestRecoveryWindowRetentionBackupBeginWALUsesManifestWALRange(t *testing.T) {
	retention := &recoveryWindowRetention{
		opts: &BackupSupervisorOpts{WalSegSz: retentionScenarioWalSegSize},
	}

	topLevelLSN, err := pglogrepl.ParseLSN("3C/DB000000")
	require.NoError(t, err)

	info := &backupdto.Result{
		TimelineID: 1,
		StartLSN:   topLevelLSN,
		Manifest: &backupdto.BackupManifest{
			WALRanges: []backupdto.ManifestWALRange{
				{
					Timeline: 1,
					StartLSN: "3C/D9000000",
					EndLSN:   "3C/DA000000",
				},
			},
		},
	}

	got := retention.backupBeginWAL(info)

	assert.Equal(t, "000000010000003C000000D9", got)
}

func TestRetentionScenarioDeletesOnlyBackupsOlderThanAnchorAndWALBeforeAnchor(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	backupStorage := st.NewInMemoryStorage()
	walBackend := st.NewInMemoryStorage()

	// Recovery window: 72h. Window start is now-3d.
	// The newest backup before the window start is 20260428065500, so it becomes
	// the anchor. Retention may delete only backups older than that anchor and WAL
	// files older than that anchor's begin WAL.
	putScenarioBackup(t, backupStorage, "20260422065500", now.Add(-10*24*time.Hour), "000000010000003C000000D8")
	putScenarioBackup(t, backupStorage, "20260428065500", now.Add(-5*24*time.Hour), "000000010000003C000000D9")
	putScenarioBackup(t, backupStorage, "20260501065500", now.Add(-2*24*time.Hour), "000000010000003C000000DA")
	putScenarioBackup(t, backupStorage, "20260502065500", now.Add(-1*time.Hour), "000000010000003C000000DB")

	for _, wal := range []string{
		"000000010000003C000000D8",
		"000000010000003C000000D9",
		"000000010000003C000000DA",
		"000000010000003C000000DB",
		"000000010000003C000000DC.partial",
		"00000002.history",
		"README.txt",
	} {
		putScenarioRaw(t, walBackend, wal)
	}

	retention := newRecoveryWindowRetention(
		&BackupSupervisorOpts{
			WalSegSz:       retentionScenarioWalSegSize,
			Cfg:            retentionScenarioConfig(72*time.Hour, 1),
			BasebackupStor: backupStorage,
			WalStor:        retentionScenarioVariadicStorage(t, walBackend),
		},
	)

	err := retention.RunBeforeBackup(ctx)
	require.NoError(t, err)

	assertScenarioMissing(t, backupStorage, "20260422065500/20260422065500.json")
	assertScenarioMissing(t, backupStorage, "20260422065500/base.tar")
	assertScenarioExists(t, backupStorage, "20260428065500/20260428065500.json")
	assertScenarioExists(t, backupStorage, "20260501065500/20260501065500.json")
	assertScenarioExists(t, backupStorage, "20260502065500/20260502065500.json")

	assertScenarioMissing(t, walBackend, "000000010000003C000000D8")
	assertScenarioExists(t, walBackend, "000000010000003C000000D9")
	assertScenarioExists(t, walBackend, "000000010000003C000000DA")
	assertScenarioExists(t, walBackend, "000000010000003C000000DB")
	assertScenarioExists(t, walBackend, "000000010000003C000000DC.partial")
	assertScenarioExists(t, walBackend, "00000002.history")
	assertScenarioExists(t, walBackend, "README.txt")
}

func TestRetentionScenarioKeepLastCanMoveAnchorEarlierForDurability(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	backupStorage := st.NewInMemoryStorage()
	walBackend := st.NewInMemoryStorage()

	putScenarioBackup(t, backupStorage, "20260422065500", now.Add(-10*24*time.Hour), "000000010000003C000000D8")
	putScenarioBackup(t, backupStorage, "20260424065500", now.Add(-8*24*time.Hour), "000000010000003C000000D9")
	putScenarioBackup(t, backupStorage, "20260425065500", now.Add(-7*24*time.Hour), "000000010000003C000000DA")
	putScenarioBackup(t, backupStorage, "20260501065500", now.Add(-1*24*time.Hour), "000000010000003C000000DB")

	for _, wal := range []string{
		"000000010000003C000000D8",
		"000000010000003C000000D9",
		"000000010000003C000000DA",
		"000000010000003C000000DB",
	} {
		putScenarioRaw(t, walBackend, wal)
	}

	// Without KeepLast=3, the anchor would be 20260425065500. KeepLast=3 moves
	// it earlier to 20260424065500 so the newest 3 backups remain recoverable.
	retention := newRecoveryWindowRetention(
		&BackupSupervisorOpts{
			WalSegSz:       retentionScenarioWalSegSize,
			Cfg:            retentionScenarioConfig(72*time.Hour, 3),
			BasebackupStor: backupStorage,
			WalStor:        retentionScenarioVariadicStorage(t, walBackend),
		},
	)

	err := retention.RunBeforeBackup(ctx)
	require.NoError(t, err)

	assertScenarioMissing(t, backupStorage, "20260422065500/20260422065500.json")
	assertScenarioExists(t, backupStorage, "20260424065500/20260424065500.json")
	assertScenarioExists(t, backupStorage, "20260425065500/20260425065500.json")
	assertScenarioExists(t, backupStorage, "20260501065500/20260501065500.json")

	assertScenarioMissing(t, walBackend, "000000010000003C000000D8")
	assertScenarioExists(t, walBackend, "000000010000003C000000D9")
	assertScenarioExists(t, walBackend, "000000010000003C000000DA")
	assertScenarioExists(t, walBackend, "000000010000003C000000DB")
}

func TestRetentionScenarioAllBackupsNewerThanWindowKeepsAllBackupsButPurgesPreAnchorWAL(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	backupStorage := st.NewInMemoryStorage()
	walBackend := st.NewInMemoryStorage()

	putScenarioBackup(t, backupStorage, "20260501065500", now.Add(-48*time.Hour), "000000010000003C000000D9")
	putScenarioBackup(t, backupStorage, "20260502065500", now.Add(-24*time.Hour), "000000010000003C000000DA")

	putScenarioRaw(t, walBackend, "000000010000003C000000D8")
	putScenarioRaw(t, walBackend, "000000010000003C000000D9")
	putScenarioRaw(t, walBackend, "000000010000003C000000DA")

	retention := newRecoveryWindowRetention(
		&BackupSupervisorOpts{
			WalSegSz:       retentionScenarioWalSegSize,
			Cfg:            retentionScenarioConfig(7*24*time.Hour, 1),
			BasebackupStor: backupStorage,
			WalStor:        retentionScenarioVariadicStorage(t, walBackend),
		},
	)

	err := retention.RunBeforeBackup(ctx)
	require.NoError(t, err)

	// All backups are newer than the recovery window start. The oldest successful
	// backup becomes the safest available anchor, so no backup directory is deleted.
	assertScenarioExists(t, backupStorage, "20260501065500/20260501065500.json")
	assertScenarioExists(t, backupStorage, "20260502065500/20260502065500.json")

	// WAL older than the oldest available backup is still not useful for PITR from
	// retained backups, so it is purged.
	assertScenarioMissing(t, walBackend, "000000010000003C000000D8")
	assertScenarioExists(t, walBackend, "000000010000003C000000D9")
	assertScenarioExists(t, walBackend, "000000010000003C000000DA")
}

func TestRetentionScenarioSkipsBrokenBackupsWithoutDeletingThem(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	backupStorage := st.NewInMemoryStorage()
	walBackend := st.NewInMemoryStorage()

	// Broken backup directory: it has files, but the same-name manifest is not
	// valid JSON. Retention must not count it as a successful backup and must not
	// delete it merely because it is old.
	require.NoError(t, backupStorage.Put(ctx, "20260401065500/20260401065500.json", strings.NewReader("not-json")))
	require.NoError(t, backupStorage.Put(ctx, "20260401065500/base.tar", strings.NewReader("base")))

	putScenarioBackup(t, backupStorage, "20260428065500", now.Add(-5*24*time.Hour), "000000010000003C000000D9")
	putScenarioBackup(t, backupStorage, "20260501065500", now.Add(-1*24*time.Hour), "000000010000003C000000DA")

	putScenarioRaw(t, walBackend, "000000010000003C000000D8")
	putScenarioRaw(t, walBackend, "000000010000003C000000D9")
	putScenarioRaw(t, walBackend, "000000010000003C000000DA")

	retention := newRecoveryWindowRetention(
		&BackupSupervisorOpts{
			WalSegSz:       retentionScenarioWalSegSize,
			Cfg:            retentionScenarioConfig(72*time.Hour, 1),
			BasebackupStor: backupStorage,
			WalStor:        retentionScenarioVariadicStorage(t, walBackend),
		},
	)

	err := retention.RunBeforeBackup(ctx)
	require.NoError(t, err)

	assertScenarioExists(t, backupStorage, "20260401065500/20260401065500.json")
	assertScenarioExists(t, backupStorage, "20260401065500/base.tar")
	assertScenarioExists(t, backupStorage, "20260428065500/20260428065500.json")
	assertScenarioExists(t, backupStorage, "20260501065500/20260501065500.json")

	assertScenarioMissing(t, walBackend, "000000010000003C000000D8")
	assertScenarioExists(t, walBackend, "000000010000003C000000D9")
	assertScenarioExists(t, walBackend, "000000010000003C000000DA")
}

func TestRetentionScenarioBackupDeleteFailureStopsBeforeWALCleanup(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	backupStorage := &retentionScenarioDeleteDirFailStorage{InMemoryStorage: st.NewInMemoryStorage()}
	walBackend := st.NewInMemoryStorage()

	putScenarioBackup(t, backupStorage, "20260422065500", now.Add(-10*24*time.Hour), "000000010000003C000000D8")
	putScenarioBackup(t, backupStorage, "20260428065500", now.Add(-5*24*time.Hour), "000000010000003C000000D9")

	putScenarioRaw(t, walBackend, "000000010000003C000000D8")
	putScenarioRaw(t, walBackend, "000000010000003C000000D9")

	retention := newRecoveryWindowRetention(
		&BackupSupervisorOpts{
			WalSegSz:       retentionScenarioWalSegSize,
			Cfg:            retentionScenarioConfig(72*time.Hour, 1),
			BasebackupStor: backupStorage,
			WalStor:        retentionScenarioVariadicStorage(t, walBackend),
		},
	)

	err := retention.RunBeforeBackup(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "purge old backups")

	// Durability guard: if backup deletion fails, WAL cleanup must not run yet.
	assertScenarioExists(t, backupStorage, "20260422065500/20260422065500.json")
	assertScenarioExists(t, walBackend, "000000010000003C000000D8")
	assertScenarioExists(t, walBackend, "000000010000003C000000D9")
}

func TestRetentionScenarioWALDeleteFailureReturnsErrorAfterBackupDelete(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	backupStorage := st.NewInMemoryStorage()
	walBackend := &retentionScenarioDeleteFailStorage{InMemoryStorage: st.NewInMemoryStorage()}

	putScenarioBackup(t, backupStorage, "20260422065500", now.Add(-10*24*time.Hour), "000000010000003C000000D8")
	putScenarioBackup(t, backupStorage, "20260428065500", now.Add(-5*24*time.Hour), "000000010000003C000000D9")

	putScenarioRaw(t, walBackend, "000000010000003C000000D8")
	putScenarioRaw(t, walBackend, "000000010000003C000000D9")

	retention := newRecoveryWindowRetention(
		&BackupSupervisorOpts{
			WalSegSz:       retentionScenarioWalSegSize,
			Cfg:            retentionScenarioConfig(72*time.Hour, 1),
			BasebackupStor: backupStorage,
			WalStor:        retentionScenarioVariadicStorage(t, walBackend),
		},
	)

	err := retention.RunBeforeBackup(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "purge old WALs")

	// Current order is: delete old backup dirs first, then delete old WALs.
	// This assertion documents that an old backup can already be gone when WAL
	// cleanup fails, while anchor/newer backups remain intact.
	assertScenarioMissing(t, backupStorage, "20260422065500/20260422065500.json")
	assertScenarioExists(t, backupStorage, "20260428065500/20260428065500.json")
	assertScenarioExists(t, walBackend, "000000010000003C000000D8")
	assertScenarioExists(t, walBackend, "000000010000003C000000D9")
}

func retentionScenarioConfig(window time.Duration, keepLast int) *config.Config {
	return &config.Config{
		Retention: config.RetentionConfig{
			Enable:             true,
			Type:               config.RetentionTypeRecoveryWindow,
			KeepDurationParsed: window,
			KeepLast:           &keepLast,
		},
	}
}

func retentionScenarioVariadicStorage(t *testing.T, backend st.Storage) *st.VariadicStorage {
	t.Helper()

	vs, err := st.NewVariadicStorage(backend, st.Algorithms{}, "")
	require.NoError(t, err)
	return vs
}

func putScenarioBackup(t *testing.T, storage st.Storage, id string, startedAt time.Time, beginWAL string) {
	t.Helper()

	ctx := context.Background()
	lsnText := retentionScenarioStartLSNForWAL(t, beginWAL)
	lsn, err := pglogrepl.ParseLSN(lsnText)
	require.NoError(t, err)

	info := backupdto.Result{
		StartedAt:  startedAt.UTC(),
		FinishedAt: startedAt.UTC().Add(time.Minute),
		TimelineID: 1,
		StartLSN:   lsn,
		BytesTotal: 128,
		Manifest: &backupdto.BackupManifest{
			WALRanges: []backupdto.ManifestWALRange{
				{
					Timeline: 1,
					StartLSN: lsnText,
					EndLSN:   lsnText,
				},
			},
		},
	}

	payload, err := json.Marshal(info)
	require.NoError(t, err)

	require.NoError(t, storage.Put(ctx, fmt.Sprintf("%s/%s.json", id, id), strings.NewReader(string(payload))))
	require.NoError(t, storage.Put(ctx, fmt.Sprintf("%s/base.tar", id), strings.NewReader("base")))
	require.NoError(t, storage.Put(ctx, fmt.Sprintf("%s/25222.tar", id), strings.NewReader("tablespace")))
}

func putScenarioRaw(t *testing.T, storage st.Storage, path string) {
	t.Helper()
	require.NoError(t, storage.Put(context.Background(), path, strings.NewReader("x")))
}

func retentionScenarioStartLSNForWAL(t *testing.T, walName string) string {
	t.Helper()
	require.Len(t, walName, 24)

	logID, err := strconv.ParseUint(walName[8:16], 16, 64)
	require.NoError(t, err)
	segID, err := strconv.ParseUint(walName[16:24], 16, 64)
	require.NoError(t, err)

	segNo := logID*256 + segID
	lsn := segNo * retentionScenarioWalSegSize

	//nolint:gosec
	return fmt.Sprintf("%X/%08X", uint32(lsn>>32), uint32(lsn))
}

func assertScenarioExists(t *testing.T, storage st.Storage, path string) {
	t.Helper()

	exists, err := storage.Exists(context.Background(), path)
	require.NoError(t, err)
	assert.True(t, exists, "expected %s to exist", path)
}

func assertScenarioMissing(t *testing.T, storage st.Storage, path string) {
	t.Helper()

	exists, err := storage.Exists(context.Background(), path)
	require.NoError(t, err)
	assert.False(t, exists, "expected %s to be missing", path)
}

type retentionScenarioDeleteDirFailStorage struct {
	*st.InMemoryStorage
}

func (s *retentionScenarioDeleteDirFailStorage) DeleteDir(context.Context, string) error {
	return errors.New("delete dir failed")
}

type retentionScenarioDeleteFailStorage struct {
	*st.InMemoryStorage
}

func (s *retentionScenarioDeleteFailStorage) Delete(_ context.Context, path string) error {
	if strings.Contains(path, "000000010000003C000000D8") {
		return errors.New("delete WAL failed")
	}
	return s.InMemoryStorage.Delete(context.Background(), path)
}

var (
	_ st.Storage = (*retentionScenarioDeleteDirFailStorage)(nil)
	_ st.Storage = (*retentionScenarioDeleteFailStorage)(nil)
)
