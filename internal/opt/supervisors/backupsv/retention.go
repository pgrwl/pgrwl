package backupsv

import (
	"context"
	"fmt"

	"github.com/pgrwl/pgrwl/config"
)

type RetentionService interface {
	RunBeforeBackup(ctx context.Context) error
}

type NoopRetention struct{}

func (NoopRetention) RunBeforeBackup(ctx context.Context) error {
	return ctx.Err()
}

func NewRetentionService(opts *BackupSupervisorOpts) (RetentionService, error) {
	if opts.Cfg == nil || !opts.Cfg.Retention.Enable {
		return NoopRetention{}, nil
	}

	switch opts.Cfg.Retention.Type {
	case config.RetentionTypeRecoveryWindow:
		return newRecoveryWindowRetention(opts), nil

	default:
		return nil, fmt.Errorf(
			"unsupported backup retention type %q: only %q is supported",
			opts.Cfg.Retention.Type,
			config.RetentionTypeRecoveryWindow,
		)
	}
}
