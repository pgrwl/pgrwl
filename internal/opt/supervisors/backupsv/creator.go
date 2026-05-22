package backupsv

import (
	"context"

	"github.com/pgrwl/pgrwl/internal/opt/basebackup/backup"
)

type BaseBackupCreator interface {
	Create(ctx context.Context) error
}

type basebackupCreator struct {
	Directory string
}

var _ BaseBackupCreator = &basebackupCreator{}

func (c *basebackupCreator) Create(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	_, err := backup.CreateBaseBackup(ctx,
		&backup.CreateBaseBackupOpts{
			Directory: c.Directory,
		},
	)
	return err
}
