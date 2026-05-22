package backup

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pgrwl/pgrwl/config"
	"github.com/pgrwl/pgrwl/internal/opt/api"
	"github.com/pgrwl/pgrwl/internal/opt/basebackup/backupdto"
)

type CreateBaseBackupOpts struct {
	Directory string
}

func CreateBaseBackup(ctx context.Context, opts *CreateBaseBackupOpts) (*backupdto.Result, error) {
	var err error

	// timestamp
	ts := time.Now().UTC().Format("20060102150405")
	loggr := slog.With(slog.String("component", "basebackup"), slog.String("id", ts))

	// setup storage
	stor, err := api.SetupStorage(&api.SetupStorageOpts{
		BaseDir: opts.Directory,
		SubPath: filepath.ToSlash(filepath.Join(config.BaseBackupSubpath, ts)),
	})
	if err != nil {
		loggr.Error("cannot init storage", slog.Any("err", err))
		return nil, err
	}

	// create connection
	conn, err := pgconn.Connect(ctx, "application_name=pgrwl_basebackup replication=yes")
	if err != nil {
		loggr.Error("cannot establish connection", slog.Any("err", err))
		return nil, err
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()

	// init module
	baseBackup, err := NewBaseBackup(conn, stor, ts)
	if err != nil {
		loggr.Error("cannot init basebackup module", slog.Any("err", err))
		return nil, err
	}

	// stream basebackup to defined storage
	bbResult, err := baseBackup.StreamBackup(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			loggr.Warn("backup was not created: context canceled")
			return nil, err
		}
		loggr.Error("cannot create basebackup", slog.Any("err", err))
		return nil, err
	}

	loggr.Info("basebackup successfully created")
	return bbResult, nil
}
