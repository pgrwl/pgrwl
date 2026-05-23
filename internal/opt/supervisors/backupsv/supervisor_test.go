package backupsv

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/pgrwl/pgrwl/config"
	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"

	"github.com/robfig/cron/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeBackupRunner struct {
	runCalls        int
	startAsyncCalls int
	lastSource      string
	runErr          error
	startAsyncErr   error
	state           BackupRunState
}

var _ BackupRunner = (*fakeBackupRunner)(nil)

func (r *fakeBackupRunner) RunBackupSync(_ context.Context, source string) error {
	r.runCalls++
	r.lastSource = source
	return r.runErr
}

func (r *fakeBackupRunner) RunBackupAsync(_ context.Context, source string) (*BackupRunState, error) {
	r.startAsyncCalls++
	r.lastSource = source
	if r.startAsyncErr != nil {
		return nil, r.startAsyncErr
	}
	state := r.state
	if state.Status == "" {
		state = BackupRunState{Running: true, Status: BackupRunRunning, Source: source}
	}
	return &state, nil
}

func newSupervisorForTest(state BackupState, runner BackupRunner) *baseBackupSupervisor {
	return &baseBackupSupervisor{
		l: slog.New(slog.NewTextHandler(io.Discard, nil)),
		opts: &BackupSupervisorOpts{
			Cfg: &config.Config{Backup: config.BackupConfig{Cron: "* * * * *"}},
		},
		state:  state,
		runner: runner,
		cron:   cron.New(),
	}
}

func TestBaseBackupSupervisorTriggerDefaultsSourceToManual(t *testing.T) {
	state := NewBackupState()
	runner := &fakeBackupRunner{}
	s := newSupervisorForTest(state, runner)

	err := s.TriggerBackupSync(context.Background(), "")

	require.NoError(t, err)
	assert.Equal(t, 1, runner.runCalls)
	assert.Equal(t, "manual", runner.lastSource)
}

func TestBaseBackupSupervisorTriggerPassesExplicitSource(t *testing.T) {
	runner := &fakeBackupRunner{}
	s := newSupervisorForTest(NewBackupState(), runner)

	err := s.TriggerBackupSync(context.Background(), "cron")

	require.NoError(t, err)
	assert.Equal(t, "cron", runner.lastSource)
}

func TestBaseBackupSupervisorTriggerPropagatesRunnerError(t *testing.T) {
	runner := &fakeBackupRunner{runErr: errors.New("run failed")}
	s := newSupervisorForTest(NewBackupState(), runner)

	err := s.TriggerBackupSync(context.Background(), "manual")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "run failed")
}

func TestBaseBackupSupervisorTriggerAsyncDefaultsSourceToManual(t *testing.T) {
	runner := &fakeBackupRunner{}
	s := newSupervisorForTest(NewBackupState(), runner)

	state, err := s.TriggerBackupAsync(context.Background(), "")

	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, 1, runner.startAsyncCalls)
	assert.Equal(t, "manual", runner.lastSource)
	assert.True(t, state.Running)
}

func TestBaseBackupSupervisorTriggerAsyncPropagatesRunnerError(t *testing.T) {
	runner := &fakeBackupRunner{startAsyncErr: ErrBackupAlreadyRunning}
	s := newSupervisorForTest(NewBackupState(), runner)

	state, err := s.TriggerBackupAsync(context.Background(), "manual")

	assert.Nil(t, state)
	assert.ErrorIs(t, err, ErrBackupAlreadyRunning)
}

func TestBaseBackupSupervisorBackupStatusReturnsStateSnapshot(t *testing.T) {
	state := NewBackupState()
	require.True(t, state.Begin("manual"))
	s := newSupervisorForTest(state, &fakeBackupRunner{})

	snap := s.BackupStatus()

	assert.True(t, snap.Running)
	assert.Equal(t, BackupRunRunning, snap.Status)
	assert.Equal(t, "manual", snap.Source)
}

func TestBaseBackupSupervisorHandleRunErrorDoesNotPanic(t *testing.T) {
	s := newSupervisorForTest(NewBackupState(), &fakeBackupRunner{})

	assert.NotPanics(t, func() {
		s.handleRunError("scheduled", context.Canceled)
		s.handleRunError("scheduled", context.DeadlineExceeded)
		s.handleRunError("scheduled", ErrBackupAlreadyRunning)
		s.handleRunError("scheduled", errors.New("boom"))
	})
}

func TestNewBaseBackupSupervisorNilOptsReturnsError(t *testing.T) {
	_, err := NewBaseBackupSupervisor(nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "opts cannot be nil")
}

func TestNewBaseBackupSupervisorValidationErrors(t *testing.T) {
	backend := st.NewInMemoryStorage()
	walStor := newPlainVariadicStorage(t, backend)

	validOpts := func() *BackupSupervisorOpts {
		return &BackupSupervisorOpts{
			Directory:      "/tmp/backup",
			WalSegSz:       16 * 1024 * 1024,
			BasebackupStor: backend,
			WalStor:        walStor,
			Cfg:            &config.Config{},
		}
	}

	tests := []struct {
		name    string
		mutate  func(*BackupSupervisorOpts)
		wantErr string
	}{
		{"empty directory", func(o *BackupSupervisorOpts) { o.Directory = "" }, "opts.Directory cannot be empty"},
		{"zero wal segment size", func(o *BackupSupervisorOpts) { o.WalSegSz = 0 }, "opts.WalSegSz cannot be 0"},
		{"nil basebackup storage", func(o *BackupSupervisorOpts) { o.BasebackupStor = nil }, "opts.BasebackupStor cannot be nil"},
		{"nil wal storage", func(o *BackupSupervisorOpts) { o.WalStor = nil }, "opts.WalStor cannot be nil"},
		{"nil config", func(o *BackupSupervisorOpts) { o.Cfg = nil }, "opts.Cfg cannot be nil"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := validOpts()
			tt.mutate(opts)
			_, err := NewBaseBackupSupervisor(opts)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestNewBaseBackupSupervisorValidOptsSucceeds(t *testing.T) {
	backend := st.NewInMemoryStorage()
	walStor := newPlainVariadicStorage(t, backend)

	sv, err := NewBaseBackupSupervisor(&BackupSupervisorOpts{
		Directory:      "/tmp/backup",
		WalSegSz:       16 * 1024 * 1024,
		BasebackupStor: backend,
		WalStor:        walStor,
		Cfg:            &config.Config{},
	})

	require.NoError(t, err)
	assert.NotNil(t, sv)
}

func TestNewBaseBackupSupervisorUnsupportedRetentionTypeReturnsError(t *testing.T) {
	backend := st.NewInMemoryStorage()
	walStor := newPlainVariadicStorage(t, backend)

	_, err := NewBaseBackupSupervisor(&BackupSupervisorOpts{
		Directory:      "/tmp/backup",
		WalSegSz:       16 * 1024 * 1024,
		BasebackupStor: backend,
		WalStor:        walStor,
		Cfg: &config.Config{Retention: config.RetentionConfig{
			Enable: true,
			Type:   "unknown",
		}},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported backup retention type")
}

func TestBaseBackupSupervisorRunCronDaemonInvalidCronReturnsError(t *testing.T) {
	s := &baseBackupSupervisor{
		l:      testLogger(),
		opts:   &BackupSupervisorOpts{Cfg: &config.Config{Backup: config.BackupConfig{Cron: "not-a-cron"}}},
		state:  NewBackupState(),
		runner: &fakeBackupRunner{},
		cron:   newBackupCron(),
	}

	err := s.RunCronDaemon(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "add basebackup cron job")
}

func TestBaseBackupSupervisorRunCronDaemonStopsWhenContextCanceled(t *testing.T) {
	s := &baseBackupSupervisor{
		l:      testLogger(),
		opts:   &BackupSupervisorOpts{Cfg: &config.Config{Backup: config.BackupConfig{Cron: "* * * * *"}}},
		state:  NewBackupState(),
		runner: &fakeBackupRunner{},
		cron:   newBackupCron(),
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- s.RunCronDaemon(ctx)
	}()

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("backup scheduler did not stop after context cancellation")
	}
}
