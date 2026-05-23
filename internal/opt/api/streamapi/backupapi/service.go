package backupapi

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/pgrwl/pgrwl/internal/opt/supervisors/backupsv"
)

type Service interface {
	Start() (*backupsv.BackupRunState, error)
	Status() backupsv.BackupRunState
}

var _ Service = &svc{}

type svc struct {
	l          *slog.Logger
	supervisor backupsv.BaseBackupSupervisor
	appCtx     context.Context
}

func NewService(opts *Opts) Service {
	return &svc{
		l:          slog.With("component", "manual-basebackup"),
		supervisor: opts.Supervisor,
		appCtx:     opts.AppCtx,
	}
}

func (s *svc) Start() (*backupsv.BackupRunState, error) {
	if s.supervisor == nil {
		return nil, fmt.Errorf("backup supervisor is nil")
	}

	if err := s.appCtx.Err(); err != nil {
		return nil, err
	}

	state, err := s.supervisor.TriggerBackupAsync(s.appCtx, "manual")
	if err != nil {
		return nil, err
	}

	s.l.Info("manual basebackup accepted")
	return state, nil
}

func (s *svc) Status() backupsv.BackupRunState {
	if s.supervisor == nil {
		return backupsv.BackupRunState{
			Running:   false,
			Status:    backupsv.BackupRunIdle,
			LastError: "backup supervisor is nil",
		}
	}

	return s.supervisor.BackupStatus()
}
