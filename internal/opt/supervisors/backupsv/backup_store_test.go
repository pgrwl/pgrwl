package backupsv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/pgrwl/pgrwl/internal/opt/basebackup/backupdto"
	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingStorage struct {
	st.Storage

	listTopLevelDirsErr error
	deleteDirErr        error
	getErr              error

	deletedDirs []string
}

func newRecordingMemoryStorage() (*recordingStorage, *st.InMemoryStorage) {
	base := st.NewInMemoryStorage()

	return &recordingStorage{
		Storage: base,
	}, base
}

func (s *recordingStorage) Get(ctx context.Context, path string) (io.ReadCloser, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.Storage.Get(ctx, path)
}

func (s *recordingStorage) DeleteDir(ctx context.Context, path string) error {
	if s.deleteDirErr != nil {
		return s.deleteDirErr
	}

	s.deletedDirs = append(s.deletedDirs, path)
	return s.Storage.DeleteDir(ctx, path)
}

func (s *recordingStorage) ListTopLevelDirs(ctx context.Context, prefix string) (map[string]bool, error) {
	if s.listTopLevelDirsErr != nil {
		return nil, s.listTopLevelDirsErr
	}
	return s.Storage.ListTopLevelDirs(ctx, prefix)
}

func newTestBackupStore(storage st.Storage) BackupStore {
	return NewBackupStore(&BackupSupervisorOpts{
		BasebackupStor: storage,
	})
}

//nolint:gocritic
func putManifest(t *testing.T, storage st.Storage, backupID string, result backupdto.Result) {
	t.Helper()

	data, err := json.Marshal(result)
	require.NoError(t, err)

	path := backupID + "/" + backupID + ".json"
	require.NoError(t, storage.Put(context.Background(), path, bytes.NewReader(data)))
}

func testBackupResult(startedAt string) backupdto.Result {
	started, err := time.Parse(time.RFC3339, startedAt)
	if err != nil {
		panic(err)
	}
	return backupdto.Result{
		StartedAt:  started,
		FinishedAt: started.Add(time.Minute),
		StartLSN:   pglogrepl.LSN(0x1000000),
		TimelineID: 1,
		BytesTotal: 1234,
	}
}

func TestBackupStoreListBackupDirs(t *testing.T) {
	ctx := context.Background()
	storage := st.NewInMemoryStorage()
	store := newTestBackupStore(storage)

	putManifest(t, storage, "20260502065500", testBackupResult("2026-05-02T06:55:00Z"))
	putManifest(t, storage, "20260502070500", testBackupResult("2026-05-02T07:05:00Z"))
	require.NoError(t, storage.Put(ctx, "loose-file.txt", strings.NewReader("ignored")))

	dirs, err := store.ListBackupDirs(ctx)

	require.NoError(t, err)
	assert.Equal(t, map[string]bool{
		"20260502065500": true,
		"20260502070500": true,
	}, dirs)
}

func TestBackupStoreReadManifest(t *testing.T) {
	ctx := context.Background()
	storage := st.NewInMemoryStorage()
	store := newTestBackupStore(storage)

	putManifest(t, storage, "20260502065500", testBackupResult("2026-05-02T06:55:00Z"))

	got, err := store.ReadManifest(ctx, "20260502065500")

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, int32(1), got.TimelineID)
	assert.Equal(t, int64(1234), got.BytesTotal)
}

func TestBackupStoreDeleteBackupsDeletesOnlyRequestedTopLevelDirs(t *testing.T) {
	ctx := context.Background()
	storage, base := newRecordingMemoryStorage()
	store := newTestBackupStore(storage)

	putManifest(t, storage, "20260502065500", testBackupResult("2026-05-02T06:55:00Z"))
	putManifest(t, storage, "20260502070500", testBackupResult("2026-05-02T07:05:00Z"))
	putManifest(t, storage, "20260502071500", testBackupResult("2026-05-02T07:15:00Z"))

	err := store.DeleteBackups(ctx, []string{
		"20260502065500",
		"20260502070500",
	})

	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		"20260502065500",
		"20260502070500",
	}, storage.deletedDirs)

	exists, err := base.Exists(ctx, "20260502071500/20260502071500.json")
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = base.Exists(ctx, "20260502065500/20260502065500.json")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestBackupStoreDeleteBackupsPropagatesDeleteError(t *testing.T) {
	ctx := context.Background()
	storage, _ := newRecordingMemoryStorage()
	storage.deleteDirErr = errors.New("delete failed")

	store := newTestBackupStore(storage)

	putManifest(t, storage, "20260502065500", testBackupResult("2026-05-02T06:55:00Z"))

	err := store.DeleteBackups(ctx, []string{"20260502065500"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete backup")
}

func TestBackupStoreDeleteBackupsAllowsUnreadableManifest(t *testing.T) {
	ctx := context.Background()
	storage, _ := newRecordingMemoryStorage()
	store := newTestBackupStore(storage)

	require.NoError(t, storage.Put(ctx,
		"20260502065500/20260502065500.json",
		strings.NewReader("not-json"),
	))

	err := store.DeleteBackups(ctx, []string{"20260502065500"})

	require.NoError(t, err)
	assert.Equal(t, []string{"20260502065500"}, storage.deletedDirs)
}

func TestBackupStoreListBackupDirsPropagatesStorageError(t *testing.T) {
	storage, _ := newRecordingMemoryStorage()
	storage.listTopLevelDirsErr = errors.New("list failed")
	store := newTestBackupStore(storage)

	dirs, err := store.ListBackupDirs(context.Background())

	require.Error(t, err)
	assert.Nil(t, dirs)
}

func TestBackupStoreDeleteBackupsEmptyInputDoesNothing(t *testing.T) {
	ctx := context.Background()
	storage, _ := newRecordingMemoryStorage()
	store := newTestBackupStore(storage)

	err := store.DeleteBackups(ctx, nil)

	require.NoError(t, err)
	assert.Empty(t, storage.deletedDirs)
}
