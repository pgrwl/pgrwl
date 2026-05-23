package receivesv

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/pgrwl/pgrwl/config"
	"github.com/pgrwl/pgrwl/internal/core/xlog"
	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
)

const defaultUploadInterval = 5 * time.Minute

type Opts struct {
	ReceiveDirectory string
	PGRW             xlog.PgReceiveWal
}

type uploadBundle struct {
	walFilePath string
}

type ArchiveSupervisor struct {
	l    *slog.Logger
	cfg  *config.Config
	stor st.Storage
	opts *Opts
}

func NewArchiveSupervisor(cfg *config.Config, stor st.Storage, opts *Opts) *ArchiveSupervisor {
	return &ArchiveSupervisor{
		l:    slog.With(slog.String("component", "archive-supervisor")),
		cfg:  cfg,
		stor: stor,
		opts: opts,
	}
}

func (u *ArchiveSupervisor) log() *slog.Logger {
	if u.l != nil {
		return u.l
	}

	return slog.With(slog.String("component", "archive-supervisor"))
}

func (u *ArchiveSupervisor) Run(ctx context.Context) error {
	uploadInterval := u.cfg.Receiver.Uploader.SyncIntervalParsed
	if uploadInterval <= 0 {
		uploadInterval = defaultUploadInterval
		u.log().Info("upload interval set to default", slog.Duration("duration", defaultUploadInterval))
	}

	uploadTicker := time.NewTicker(uploadInterval)
	defer uploadTicker.Stop()

	u.log().Info("archive supervisor started",
		slog.Duration("upload_interval", uploadInterval),
	)

	for {
		select {
		case <-ctx.Done():
			u.log().Info("exiting archive supervisor", slog.String("cause", "context is done"))
			return ctx.Err()

		case <-uploadTicker.C:
			u.runUploadJob(ctx)
		}
	}
}

func (u *ArchiveSupervisor) runUploadJob(ctx context.Context) {
	u.log().Debug("upload worker is running")
	defer u.log().Debug("upload worker is done")

	if err := u.performUploads(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			u.log().Info("upload worker stopped", slog.Any("reason", err))
			return
		}

		u.log().Error("error uploading files", slog.Any("err", err))
	}
}
