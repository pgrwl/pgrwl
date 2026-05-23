package backup

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/pgrwl/pgrwl/config"
	"github.com/pgrwl/pgrwl/internal/core/xlog"
	"github.com/pgrwl/pgrwl/internal/opt/api"
	"github.com/pgrwl/pgrwl/internal/opt/basebackup/backupdto"
)

const applicationName = "pgrwl_basebackup"

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
	streamingConn, err := xlog.OpenReplicationConn(ctx, loggr, applicationName)
	if err != nil {
		loggr.Error("cannot establish connection", slog.Any("err", err))
		return nil, err
	}
	defer func() {
		loggr.Info("closing basebackup connection")
		xlog.CloseReplicationConn(streamingConn.Conn, loggr)
	}()

	// init module
	baseBackup, err := NewBaseBackup(streamingConn.Conn, stor, ts)
	if err != nil {
		loggr.Error("cannot init basebackup module", slog.Any("err", err))
		return nil, err
	}

	// stream basebackup to defined storage
	bbResult, err := baseBackup.StreamBackup(ctx)
	if err != nil {
		loggr.Error("cannot create basebackup", slog.Any("err", err))
		return nil, err
	}

	loggr.Info("basebackup successfully created")
	return bbResult, nil
}
