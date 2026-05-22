package receivesv

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	stormock "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"

	"github.com/pgrwl/pgrwl/config"
	"github.com/pgrwl/pgrwl/internal/core/xlog"
	"github.com/stretchr/testify/assert"
)

type MockPgReceiveWal struct {
	CurrentWAL string
	RunFunc    func(ctx context.Context) error
	StatusFunc func() *xlog.StreamStatus
	ConnFunc   func() *pgconn.PgConn
}

var _ xlog.PgReceiveWal = &MockPgReceiveWal{}

func (m *MockPgReceiveWal) CurrentOpenWALFileName() string {
	return m.CurrentWAL
}

func (m *MockPgReceiveWal) Run(ctx context.Context) error {
	if m.RunFunc != nil {
		return m.RunFunc(ctx)
	}
	return nil
}

func (m *MockPgReceiveWal) Status() *xlog.StreamStatus {
	if m.StatusFunc != nil {
		return m.StatusFunc()
	}
	return nil
}

func (m *MockPgReceiveWal) WalSegSz() uint64 {
	return 16 * 1024 * 1024
}

func (m *MockPgReceiveWal) Conn() *pgconn.PgConn {
	if m.ConnFunc != nil {
		return m.ConnFunc()
	}
	return nil
}

func TestArchiveSupervisor_PerformUploads(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Create mock WAL files
	file1 := filepath.Join(dir, "000000010000000000000001")
	file2 := filepath.Join(dir, "000000010000000000000002") // mock current WAL

	err := os.WriteFile(file1, []byte("wal1"), 0o600)
	assert.NoError(t, err)
	err = os.WriteFile(file2, []byte("wal2"), 0o600)
	assert.NoError(t, err)

	mockPGRW := &MockPgReceiveWal{
		CurrentWAL: "000000010000000000000002",
		StatusFunc: func() *xlog.StreamStatus {
			return &xlog.StreamStatus{
				Slot:         "my_slot",
				Timeline:     1,
				LastFlushLSN: "0/16B6C50",
				Uptime:       "12m34s",
				Running:      true,
			}
		},
	}

	cfg := &config.Config{
		Receiver: config.ReceiveConfig{
			Uploader: config.UploadConfig{
				MaxConcurrency:     2,
				SyncIntervalParsed: 1 * time.Second,
			},
		},
		Storage: config.StorageConfig{},
	}

	stor := stormock.NewInMemoryStorage()
	sup := NewArchiveSupervisor(cfg, stor, &Opts{
		ReceiveDirectory: dir,
		PGRW:             mockPGRW,
	})

	// Only file1 should be uploaded and deleted
	err = sup.performUploads(ctx)
	assert.NoError(t, err)

	// file1 should be in memory storage
	assert.Contains(t, stor.Files, "000000010000000000000001")

	// file1 should be removed from disk
	_, err = os.Stat(file1)
	assert.True(t, os.IsNotExist(err))

	// file2 should still exist
	_, err = os.Stat(file2)
	assert.NoError(t, err)
}

func TestArchiveSupervisor_UploadOneFile(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	walFile := filepath.Join(tmpDir, "000000010000000000000003")

	assert.NoError(t, os.WriteFile(walFile, []byte("testwal"), 0o600))

	stor := stormock.NewInMemoryStorage()
	cfg := &config.Config{}
	sup := NewArchiveSupervisor(cfg, stor, &Opts{})

	err := sup.uploadOneFile(ctx, uploadBundle{walFilePath: walFile})
	assert.NoError(t, err)

	assert.Contains(t, stor.Files, "000000010000000000000003")

	_, err = os.Stat(walFile)
	assert.True(t, os.IsNotExist(err))
}
