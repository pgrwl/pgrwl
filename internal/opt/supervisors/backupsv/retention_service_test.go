package backupsv

import (
	"context"
	"testing"
	"time"

	"github.com/pgrwl/pgrwl/config"
	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoopRetentionReturnsContextErrorOnly(t *testing.T) {
	ctx := context.Background()
	assert.NoError(t, NoopRetention{}.RunBeforeBackup(ctx))

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, NoopRetention{}.RunBeforeBackup(canceled), context.Canceled)
}

func TestNewRetentionServiceReturnsNoopWhenConfigNilOrDisabled(t *testing.T) {
	svc, err := NewRetentionService(&BackupSupervisorOpts{})
	require.NoError(t, err)
	assert.IsType(t, NoopRetention{}, svc)

	svc, err = NewRetentionService(&BackupSupervisorOpts{
		Cfg: &config.Config{Retention: config.RetentionConfig{Enable: false}},
	})
	require.NoError(t, err)
	assert.IsType(t, NoopRetention{}, svc)
}

func TestNewRetentionServiceReturnsErrorForUnsupportedType(t *testing.T) {
	_, err := NewRetentionService(&BackupSupervisorOpts{
		Cfg: &config.Config{Retention: config.RetentionConfig{
			Enable: true,
			Type:   "unknown",
		}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported backup retention type")
}

func TestNewRetentionServiceRecoveryWindowReturnsService(t *testing.T) {
	backend := st.NewInMemoryStorage()
	walStor := newPlainVariadicStorage(t, backend)
	keepLast := 1

	svc, err := NewRetentionService(&BackupSupervisorOpts{
		WalSegSz:       16 * 1024 * 1024,
		BasebackupStor: backend,
		WalStor:        walStor,
		Cfg: &config.Config{Retention: config.RetentionConfig{
			Enable:             true,
			Type:               config.RetentionTypeRecoveryWindow,
			KeepDurationParsed: 72 * time.Hour,
			KeepLast:           &keepLast,
		}},
	})

	require.NoError(t, err)
	assert.NotNil(t, svc)

	err = svc.RunBeforeBackup(context.Background())
	require.NoError(t, err)
}
