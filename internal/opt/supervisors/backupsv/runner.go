package backupsv

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
)

type BackupRunnerOpts struct {
	State      BackupState
	Retention  RetentionService
	Basebackup BaseBackupCreator
}

type BackupRunner interface {
	RunBackupSync(ctx context.Context, source string) error
	RunBackupAsync(ctx context.Context, source string) (*BackupRunState, error)
}

type backupRunner struct {
	l          *slog.Logger
	state      BackupState
	retention  RetentionService
	basebackup BaseBackupCreator
}

var _ BackupRunner = &backupRunner{}

func NewBackupRunner(opts *BackupRunnerOpts) BackupRunner {
	return &backupRunner{
		l:          slog.With(slog.String("component", "basebackup-runner")),
		state:      opts.State,
		retention:  opts.Retention,
		basebackup: opts.Basebackup,
	}
}

func (r *backupRunner) RunBackupSync(ctx context.Context, source string) error {
	if _, err := r.reserve(ctx, source); err != nil {
		return err
	}

	return r.runReserved(ctx, source)
}

func (r *backupRunner) RunBackupAsync(ctx context.Context, source string) (*BackupRunState, error) {
	state, err := r.reserve(ctx, source)
	if err != nil {
		return nil, err
	}

	go func() {
		if err := r.runReserved(ctx, source); err != nil {
			r.l.Error("async basebackup run failed",
				slog.String("source", source),
				slog.Any("err", err),
			)
		}
	}()

	return state, nil
}

func (r *backupRunner) reserve(ctx context.Context, source string) (*BackupRunState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if !r.state.Begin(source) {
		return nil, ErrBackupAlreadyRunning
	}

	state := r.state.Snapshot()
	return &state, nil
}

func (r *backupRunner) runReserved(ctx context.Context, source string) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("basebackup panicked: %v", rec)

			r.l.Error("basebackup run panicked",
				slog.String("source", source),
				slog.Any("panic", rec),
				slog.String("stack", string(debug.Stack())),
			)
		}

		if err != nil {
			r.state.Finish(BackupRunFailed, err.Error())
			return
		}

		r.state.Finish(BackupRunSucceeded, "")
	}()

	r.l.Info("starting basebackup",
		slog.String("source", source),
	)

	if err := r.retention.RunBeforeBackup(ctx); err != nil {
		return fmt.Errorf("retention before basebackup: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := r.basebackup.Create(ctx); err != nil {
		return fmt.Errorf("create basebackup: %w", err)
	}

	r.l.Info("basebackup completed",
		slog.String("source", source),
	)

	return nil
}
