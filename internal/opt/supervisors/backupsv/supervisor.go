package backupsv

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/robfig/cron/v3"

	"github.com/pgrwl/pgrwl/config"
	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
)

var ErrBackupAlreadyRunning = errors.New("basebackup is already running")

type BackupSupervisorOpts struct {
	Directory      string
	WalSegSz       uint64
	BasebackupStor st.Storage
	WalStor        *st.VariadicStorage
	Cfg            *config.Config
}

type BaseBackupSupervisor interface {
	RunCron(ctx context.Context) error
	Trigger(ctx context.Context, source string) error
	TriggerAsync(ctx context.Context, source string) (*BackupRunState, error)
	BackupStatus() BackupRunState
}

type baseBackupSupervisor struct {
	l      *slog.Logger
	opts   *BackupSupervisorOpts
	state  BackupState
	runner BackupRunner
	cron   *cron.Cron
}

var _ BaseBackupSupervisor = &baseBackupSupervisor{}

func NewBaseBackupSupervisor(opts *BackupSupervisorOpts) (BaseBackupSupervisor, error) {
	err := checkOpts(opts)
	if err != nil {
		return nil, err
	}

	state := NewBackupState()

	runner := NewBackupRunner(&BackupRunnerOpts{
		State:     state,
		Retention: NewRetentionService(opts),
		Basebackup: &basebackupCreator{
			Directory: opts.Directory,
		},
	})

	return &baseBackupSupervisor{
		l:      slog.With(slog.String("component", "basebackup-supervisor")),
		opts:   opts,
		state:  state,
		runner: runner,
		cron:   newBackupCron(),
	}, nil
}

func checkOpts(opts *BackupSupervisorOpts) error {
	if opts == nil {
		return fmt.Errorf("backup-supervisor, opts cannot be nil")
	}
	if opts.Directory == "" {
		return fmt.Errorf("backup-supervisor, opts.Directory cannot be empty")
	}
	if opts.WalSegSz == 0 {
		return fmt.Errorf("backup-supervisor, opts.WalSegSz cannot be 0")
	}
	if opts.BasebackupStor == nil {
		return fmt.Errorf("backup-supervisor, opts.BasebackupStor cannot be nil")
	}
	if opts.WalStor == nil {
		return fmt.Errorf("backup-supervisor, opts.WalStor cannot be nil")
	}
	if opts.Cfg == nil {
		return fmt.Errorf("backup-supervisor, opts.Cfg cannot be nil")
	}
	return nil
}

func (s *baseBackupSupervisor) log() *slog.Logger {
	if s.l != nil {
		return s.l
	}
	return slog.With(slog.String("component", "basebackup-supervisor"))
}

// RunCron starts the basebackup scheduler and blocks until ctx is canceled.
//
// Fatal/setup errors are returned:
//   - cron expression is invalid
//
// Per-backup errors are logged and do not stop the scheduler:
//   - backup already running
//   - retention failed
//   - basebackup failed
//   - WAL cleanup failed
//   - panic inside a scheduled backup run
func (s *baseBackupSupervisor) RunCron(ctx context.Context) error {
	cfg := s.opts.Cfg

	_, err := s.cron.AddFunc(cfg.Backup.Cron, func() {
		if err := s.runner.Run(ctx, "cron"); err != nil {
			s.handleRunError("scheduled", err)
		}
	})
	if err != nil {
		return fmt.Errorf("add basebackup cron job: %w", err)
	}

	s.cron.Start()

	s.log().Info("basebackup scheduler started",
		slog.String("cron", cfg.Backup.Cron),
	)

	<-ctx.Done()

	s.log().Info("stopping basebackup scheduler")

	stopCtx := s.cron.Stop()
	<-stopCtx.Done()

	s.log().Info("basebackup scheduler stopped")

	return nil
}

// Trigger starts a basebackup run synchronously.
func (s *baseBackupSupervisor) Trigger(ctx context.Context, source string) error {
	if source == "" {
		source = "manual"
	}

	return s.runner.Run(ctx, source)
}

// TriggerAsync starts a basebackup run in the background and returns the
// running state after the backup slot has been reserved.
//
// Pass the application context here, not the HTTP request context, otherwise
// the backup may be canceled as soon as the HTTP response is written.
func (s *baseBackupSupervisor) TriggerAsync(ctx context.Context, source string) (*BackupRunState, error) {
	if source == "" {
		source = "manual"
	}

	return s.runner.StartAsync(ctx, source)
}

func (s *baseBackupSupervisor) BackupStatus() BackupRunState {
	return s.state.Snapshot()
}

//nolint:unparam
func (s *baseBackupSupervisor) handleRunError(kind string, err error) {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		s.log().Info(kind+" basebackup stopped", slog.Any("reason", err))

	case errors.Is(err, ErrBackupAlreadyRunning):
		s.log().Warn("skipping basebackup run",
			slog.String("cause", "previous basebackup still running"),
		)

	default:
		s.log().Error(kind+" basebackup run failed", slog.Any("err", err))
	}
}

func newBackupCron() *cron.Cron {
	// POSIX-compatible cron syntax: "* * * * *".
	// No seconds field.
	return cron.New(cron.WithParser(cron.NewParser(
		cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow,
	)))
}
