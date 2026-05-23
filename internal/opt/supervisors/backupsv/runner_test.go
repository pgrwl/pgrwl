package backupsv

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRetentionService struct {
	calls int
	err   error
	panic any
}

func (f *fakeRetentionService) RunBeforeBackup(ctx context.Context) error {
	f.calls++

	if f.panic != nil {
		panic(f.panic)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.err
}

type fakeBaseBackupCreator struct {
	calls int
	err   error
	panic any
}

func (f *fakeBaseBackupCreator) Create(ctx context.Context) error {
	f.calls++
	if f.panic != nil {
		panic(f.panic)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.err
}

type blockingBaseBackupCreator struct {
	started chan struct{}
	release chan struct{}
	err     error

	once sync.Once
}

func newBlockingBaseBackupCreator() *blockingBaseBackupCreator {
	return &blockingBaseBackupCreator{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (c *blockingBaseBackupCreator) Create(ctx context.Context) error {
	c.once.Do(func() { close(c.started) })

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.release:
		return c.err
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestRunner(state BackupState, retention RetentionService, creator BaseBackupCreator) BackupRunner {
	return NewBackupRunner(&BackupRunnerOpts{
		State:      state,
		Retention:  retention,
		Basebackup: creator,
	})
}

func TestBackupRunnerRunFailsWhenContextAlreadyCanceled(t *testing.T) {
	state := NewBackupState()
	runner := newTestRunner(state, &fakeRetentionService{}, &fakeBaseBackupCreator{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runner.RunBackupSync(ctx, "manual")

	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, BackupRunIdle, state.Snapshot().Status)
}

func TestBackupRunnerRunSucceedsAndMarksStateSucceeded(t *testing.T) {
	state := NewBackupState()
	retention := &fakeRetentionService{}
	creator := &fakeBaseBackupCreator{}
	runner := newTestRunner(state, retention, creator)

	err := runner.RunBackupSync(context.Background(), "manual")

	require.NoError(t, err)
	assert.Equal(t, 1, retention.calls)
	assert.Equal(t, 1, creator.calls)
	snap := state.Snapshot()
	assert.False(t, snap.Running)
	assert.Equal(t, BackupRunSucceeded, snap.Status)
	assert.Equal(t, "manual", snap.Source)
	assert.Empty(t, snap.LastError)
	assert.NotNil(t, snap.StartedAt)
	assert.NotNil(t, snap.FinishedAt)
}

func TestBackupRunnerRunRetentionFailureSkipsBasebackupAndMarksFailed(t *testing.T) {
	state := NewBackupState()
	retention := &fakeRetentionService{err: errors.New("retention failed")}
	creator := &fakeBaseBackupCreator{}
	runner := newTestRunner(state, retention, creator)

	err := runner.RunBackupSync(context.Background(), "cron")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "retention before basebackup")
	assert.Equal(t, 1, retention.calls)
	assert.Equal(t, 0, creator.calls)

	snap := state.Snapshot()
	assert.False(t, snap.Running)
	assert.Equal(t, BackupRunFailed, snap.Status)
	assert.Contains(t, snap.LastError, "retention before basebackup")
}

func TestBackupRunnerRunBasebackupFailureMarksFailed(t *testing.T) {
	state := NewBackupState()
	retention := &fakeRetentionService{}
	creator := &fakeBaseBackupCreator{err: errors.New("basebackup failed")}
	runner := newTestRunner(state, retention, creator)

	err := runner.RunBackupSync(context.Background(), "cron")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "create basebackup")
	assert.Equal(t, 1, retention.calls)
	assert.Equal(t, 1, creator.calls)

	snap := state.Snapshot()
	assert.False(t, snap.Running)
	assert.Equal(t, BackupRunFailed, snap.Status)
	assert.Contains(t, snap.LastError, "create basebackup")
}

func TestBackupRunnerRunRecoversRetentionPanicAndMarksFailed(t *testing.T) {
	state := NewBackupState()
	retention := &fakeRetentionService{panic: "retention boom"}
	creator := &fakeBaseBackupCreator{}
	runner := newTestRunner(state, retention, creator)

	err := runner.RunBackupSync(context.Background(), "cron")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "basebackup panicked")
	assert.Equal(t, 1, retention.calls)
	assert.Equal(t, 0, creator.calls)

	snap := state.Snapshot()
	assert.False(t, snap.Running)
	assert.Equal(t, BackupRunFailed, snap.Status)
	assert.Contains(t, snap.LastError, "basebackup panicked")
}

func TestBackupRunnerRunRecoversBasebackupPanicAndMarksFailed(t *testing.T) {
	state := NewBackupState()
	retention := &fakeRetentionService{}
	creator := &fakeBaseBackupCreator{panic: "creator boom"}
	runner := newTestRunner(state, retention, creator)

	err := runner.RunBackupSync(context.Background(), "cron")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "basebackup panicked")
	assert.Equal(t, 1, retention.calls)
	assert.Equal(t, 1, creator.calls)

	snap := state.Snapshot()
	assert.False(t, snap.Running)
	assert.Equal(t, BackupRunFailed, snap.Status)
	assert.Contains(t, snap.LastError, "basebackup panicked")
}

func TestBackupRunnerRunReturnsAlreadyRunning(t *testing.T) {
	state := NewBackupState()
	require.True(t, state.Begin("existing"))

	runner := newTestRunner(state, &fakeRetentionService{}, &fakeBaseBackupCreator{})

	err := runner.RunBackupSync(context.Background(), "manual")

	assert.ErrorIs(t, err, ErrBackupAlreadyRunning)
	assert.Equal(t, "existing", state.Snapshot().Source)
}

func TestBackupRunnerStartAsyncReservesImmediatelyAndEventuallySucceeds(t *testing.T) {
	state := NewBackupState()
	creator := newBlockingBaseBackupCreator()
	runner := newTestRunner(state, &fakeRetentionService{}, creator)

	running, err := runner.RunBackupAsync(context.Background(), "manual")
	require.NoError(t, err)
	require.NotNil(t, running)
	assert.True(t, running.Running)
	assert.Equal(t, BackupRunRunning, running.Status)

	assert.Eventually(t, func() bool {
		select {
		case <-creator.started:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	_, err = runner.RunBackupAsync(context.Background(), "manual")
	assert.ErrorIs(t, err, ErrBackupAlreadyRunning)

	close(creator.release)

	assert.Eventually(t, func() bool {
		return state.Snapshot().Status == BackupRunSucceeded
	}, time.Second, 10*time.Millisecond)
}

func TestBackupRunnerStartAsyncEventuallyMarksFailure(t *testing.T) {
	state := NewBackupState()
	creator := newBlockingBaseBackupCreator()
	creator.err = errors.New("async failed")
	runner := newTestRunner(state, &fakeRetentionService{}, creator)

	_, err := runner.RunBackupAsync(context.Background(), "manual")
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		select {
		case <-creator.started:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)

	close(creator.release)

	assert.Eventually(t, func() bool {
		snap := state.Snapshot()
		return snap.Status == BackupRunFailed && snap.LastError != ""
	}, time.Second, 10*time.Millisecond)
}

func TestBackupRunnerStartAsyncRecoversPanicAndMarksFailure(t *testing.T) {
	state := NewBackupState()
	creator := &fakeBaseBackupCreator{panic: "async panic"}
	runner := newTestRunner(state, &fakeRetentionService{}, creator)

	_, err := runner.RunBackupAsync(context.Background(), "manual")
	require.NoError(t, err)

	assert.Eventually(t, func() bool {
		snap := state.Snapshot()
		return snap.Status == BackupRunFailed && snap.LastError != ""
	}, time.Second, 10*time.Millisecond)
}
