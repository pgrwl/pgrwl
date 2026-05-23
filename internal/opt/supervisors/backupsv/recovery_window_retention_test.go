package backupsv

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/pgrwl/pgrwl/config"
	"github.com/pgrwl/pgrwl/internal/core/xlog"
	"github.com/pgrwl/pgrwl/internal/opt/basebackup/backupdto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testWalSegSz = 16 * 1024 * 1024

type fakeBackupStore struct {
	dirs      map[string]bool
	manifests map[string]*backupdto.Result

	listErr   error
	readErrs  map[string]error
	deleteErr error
	deleted   []string
}

var _ BackupStore = (*fakeBackupStore)(nil)

func newFakeBackupStore() *fakeBackupStore {
	return &fakeBackupStore{
		dirs:      make(map[string]bool),
		manifests: make(map[string]*backupdto.Result),
		readErrs:  make(map[string]error),
	}
}

func (s *fakeBackupStore) ListBackupDirs(context.Context) (map[string]bool, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := make(map[string]bool, len(s.dirs))
	for k, v := range s.dirs {
		out[k] = v
	}
	return out, nil
}

func (s *fakeBackupStore) ReadManifest(_ context.Context, backupID string) (*backupdto.Result, error) {
	if err := s.readErrs[backupID]; err != nil {
		return nil, err
	}
	info, ok := s.manifests[backupID]
	if !ok {
		return nil, errors.New("manifest not found")
	}
	return info, nil
}

func (s *fakeBackupStore) DeleteBackups(_ context.Context, backupsToDelete []string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, backupsToDelete...)
	return nil
}

type fakeWALCleaner struct {
	calls       int
	keepFromWAL string
	err         error
}

var _ WALCleaner = (*fakeWALCleaner)(nil)

func (c *fakeWALCleaner) DeleteBefore(_ context.Context, keepFromWAL string) error {
	c.calls++
	c.keepFromWAL = keepFromWAL
	return c.err
}

func newRetentionForTest(cfg *config.Config, store BackupStore, cleaner WALCleaner) *recoveryWindowRetention {
	return &recoveryWindowRetention{
		l: testLogger(),
		opts: &BackupSupervisorOpts{
			Cfg:      cfg,
			WalSegSz: testWalSegSz,
		},
		backupStore: store,
		walCleaner:  cleaner,
	}
}

func retentionConfigForTest() *config.Config {
	keepLast := 1
	return &config.Config{
		Retention: config.RetentionConfig{
			Enable:             true,
			Type:               config.RetentionTypeRecoveryWindow,
			KeepDurationParsed: 72 * time.Hour,
			KeepLast:           &keepLast,
		},
	}
}

func manifestResult(t *testing.T, startedAt string, timeline int32, startLSN string) *backupdto.Result {
	t.Helper()

	started := mustTime(t, startedAt)
	lsn, err := pglogrepl.ParseLSN(startLSN)
	require.NoError(t, err)
	return &backupdto.Result{
		StartedAt:  started,
		FinishedAt: started.Add(time.Minute),
		TimelineID: timeline,
		StartLSN:   lsn,
	}
}

//nolint:unparam
func manifestResultAt(t *testing.T, started time.Time, timeline int32, startLSN string) *backupdto.Result {
	t.Helper()

	lsn, err := pglogrepl.ParseLSN(startLSN)
	require.NoError(t, err)

	return &backupdto.Result{
		StartedAt:  started.UTC(),
		FinishedAt: started.UTC().Add(time.Minute),
		TimelineID: timeline,
		StartLSN:   lsn,
	}
}

func manifestResultWithWALRange(t *testing.T, startedAt string, topTimeline int32, topStartLSN, rangeStartLSN string, rangeTimeline int32) *backupdto.Result {
	t.Helper()

	info := manifestResult(t, startedAt, topTimeline, topStartLSN)
	info.Manifest = &backupdto.BackupManifest{
		WALRanges: []backupdto.ManifestWALRange{
			{Timeline: rangeTimeline, StartLSN: rangeStartLSN},
		},
	}
	return info
}

func TestRecoveryWindowRetentionBackupBeginWALDoesNotMixManifestTimelineWithInvalidManifestLSN(t *testing.T) {
	retention := &recoveryWindowRetention{
		opts: &BackupSupervisorOpts{
			WalSegSz: testWalSegSz,
		},
	}

	topLevelLSN, err := pglogrepl.ParseLSN("0/1000000")
	require.NoError(t, err)

	info := &backupdto.Result{
		TimelineID: 1,
		StartLSN:   topLevelLSN,
		Manifest: &backupdto.BackupManifest{
			WALRanges: []backupdto.ManifestWALRange{
				{
					Timeline: 2,
					StartLSN: "not-a-lsn",
				},
			},
		},
	}

	got := retention.backupBeginWAL(info)

	assert.Equal(t, "000000010000000000000001", got)
}

func TestRecoveryWindowRetentionBackupBeginWALUsesFirstValidManifestWALRange(t *testing.T) {
	retention := &recoveryWindowRetention{
		opts: &BackupSupervisorOpts{
			WalSegSz: testWalSegSz,
		},
	}

	topLevelLSN, err := pglogrepl.ParseLSN("0/1000000")
	require.NoError(t, err)

	info := &backupdto.Result{
		TimelineID: 1,
		StartLSN:   topLevelLSN,
		Manifest: &backupdto.BackupManifest{
			WALRanges: []backupdto.ManifestWALRange{
				{
					Timeline: 2,
					StartLSN: "invalid",
				},
				{
					Timeline: 3,
					StartLSN: "0/3000000",
				},
			},
		},
	}

	got := retention.backupBeginWAL(info)

	assert.Equal(t, "000000030000000000000003", got)
}

func TestRecoveryWindowRetentionBackupBeginWALReturnsEmptyWhenWalSegmentSizeIsZero(t *testing.T) {
	retention := &recoveryWindowRetention{
		opts: &BackupSupervisorOpts{WalSegSz: 0},
	}

	lsn, err := pglogrepl.ParseLSN("0/1000000")
	require.NoError(t, err)

	info := &backupdto.Result{
		TimelineID: 1,
		StartLSN:   lsn,
	}

	got := retention.backupBeginWAL(info)

	assert.Empty(t, got)
}

func TestRecoveryWindowRetentionLoadSuccessfulBackupsSkipsUnreadableAndInvalidBackups(t *testing.T) {
	store := newFakeBackupStore()
	store.dirs = map[string]bool{
		"20260502065500": true,
		"20260502070500": true,
		"20260502071500": true,
		"20260502072500": true,
		"20260502073500": true,
	}
	store.manifests["20260502065500"] = manifestResult(t, "2026-04-29T12:00:00Z", 1, "0/1000000")
	store.manifests["20260502071500"] = &backupdto.Result{TimelineID: 1, StartLSN: pglogrepl.LSN(0x1000000)}
	store.manifests["20260502072500"] = manifestResult(t, "2026-04-29T13:00:00Z", 0, "0/1000000")
	store.manifests["20260502073500"] = &backupdto.Result{StartedAt: mustTime(t, "2026-04-29T14:00:00Z"), TimelineID: 1}
	store.readErrs["20260502070500"] = errors.New("read failed")

	retention := newRetentionForTest(retentionConfigForTest(), store, &fakeWALCleaner{})

	got, err := retention.loadSuccessfulBackups(context.Background())

	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "20260502065500", got[0].name)
	assert.NotEmpty(t, got[0].beginWAL)
}

func TestRecoveryWindowRetentionBackupBeginWALUsesManifestWALRangeWhenPresent(t *testing.T) {
	retention := newRetentionForTest(retentionConfigForTest(), newFakeBackupStore(), &fakeWALCleaner{})

	info := manifestResultWithWALRange(
		t,
		"2026-04-29T12:00:00Z",
		1,
		"0/1000000",
		"0/3000000",
		2,
	)

	got := retention.backupBeginWAL(info)

	segNo := xlog.XLByteToSeg(uint64(pglogrepl.LSN(0x3000000)), testWalSegSz)
	expected := xlog.XLogFileName(2, segNo, testWalSegSz)

	assert.Equal(t, expected, got)
}

func TestRecoveryWindowRetentionRunBeforeBackupDeletesOldBackupsThenCleansWAL(t *testing.T) {
	store := newFakeBackupStore()
	store.dirs = map[string]bool{
		"20260422065500": true,
		"20260428065500": true,
		"20260501065500": true,
	}
	now := time.Now().UTC()
	store.manifests["20260422065500"] = manifestResultAt(t, now.Add(-10*24*time.Hour), 1, "0/1000000")
	store.manifests["20260428065500"] = manifestResultAt(t, now.Add(-4*24*time.Hour), 1, "0/2000000")
	store.manifests["20260501065500"] = manifestResultAt(t, now.Add(-24*time.Hour), 1, "0/3000000")

	cleaner := &fakeWALCleaner{}
	cfg := retentionConfigForTest()
	cfg.Retention.KeepDurationParsed = 72 * time.Hour
	retention := newRetentionForTest(cfg, store, cleaner)

	err := retention.RunBeforeBackup(context.Background())

	require.NoError(t, err)
	assert.Equal(t, []string{"20260422065500"}, store.deleted)
	assert.Equal(t, 1, cleaner.calls)
	assert.NotEmpty(t, cleaner.keepFromWAL)
}

func TestRecoveryWindowRetentionRunBeforeBackupDoesNotCleanWALIfBackupDeleteFails(t *testing.T) {
	store := newFakeBackupStore()
	store.deleteErr = errors.New("delete backups failed")
	store.dirs = map[string]bool{
		"20260422065500": true,
		"20260428065500": true,
	}
	now := time.Now().UTC()
	store.manifests["20260422065500"] = manifestResultAt(t, now.Add(-10*24*time.Hour), 1, "0/1000000")
	store.manifests["20260428065500"] = manifestResultAt(t, now.Add(-4*24*time.Hour), 1, "0/2000000")

	cleaner := &fakeWALCleaner{}
	retention := newRetentionForTest(retentionConfigForTest(), store, cleaner)

	err := retention.RunBeforeBackup(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "purge old backups")
	assert.Equal(t, 0, cleaner.calls)
}

func TestRecoveryWindowRetentionRunBeforeBackupReturnsWALCleanerError(t *testing.T) {
	store := newFakeBackupStore()
	store.dirs = map[string]bool{"20260502065500": true}
	store.manifests["20260502065500"] = manifestResultAt(t, time.Now().UTC().Add(-24*time.Hour), 1, "0/3000000")

	cleaner := &fakeWALCleaner{err: errors.New("wal cleanup failed")}
	retention := newRetentionForTest(retentionConfigForTest(), store, cleaner)

	err := retention.RunBeforeBackup(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "purge old WALs")
	assert.Equal(t, 1, cleaner.calls)
}

func TestRecoveryWindowRetentionRunBeforeBackupReturnsContextError(t *testing.T) {
	retention := newRetentionForTest(retentionConfigForTest(), newFakeBackupStore(), &fakeWALCleaner{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := retention.RunBeforeBackup(ctx)

	assert.ErrorIs(t, err, context.Canceled)
}

func TestRecoveryWindowRetentionRunBeforeBackupSkipsWhenNoSuccessfulBackups(t *testing.T) {
	store := newFakeBackupStore()
	cleaner := &fakeWALCleaner{}
	retention := newRetentionForTest(retentionConfigForTest(), store, cleaner)

	err := retention.RunBeforeBackup(context.Background())

	require.NoError(t, err)
	assert.Empty(t, store.deleted)
	assert.Equal(t, 0, cleaner.calls)
}
