package backupsv

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/pgrwl/pgrwl/internal/opt/metrics/receivemetrics"
)

type WALCleaner interface {
	DeleteBefore(ctx context.Context, keepFromWAL string) error
}

type walCleaner struct {
	l    *slog.Logger
	opts *BackupSupervisorOpts
}

var _ WALCleaner = &walCleaner{}

func NewWALCleaner(opts *BackupSupervisorOpts) WALCleaner {
	return &walCleaner{
		l:    slog.With(slog.String("component", "wal-cleaner")),
		opts: opts,
	}
}

func (c *walCleaner) DeleteBefore(ctx context.Context, keepFromWAL string) error {
	if keepFromWAL == "" {
		return fmt.Errorf("keepFromWAL is empty")
	}

	stor := c.opts.WalStor

	wals, err := stor.ListInfoRaw(ctx, "")
	if err != nil {
		return fmt.Errorf("list WAL archive: %w", err)
	}

	deleted := 0
	kept := 0

	for _, wal := range wals {
		if !isRootStoragePath(wal.Path) {
			kept++
			continue
		}

		name, history, ok := normalizeWALFilename(wal.Path)
		if !ok {
			kept++
			continue
		}

		// Timeline history files are tiny and important for timeline switching.
		// Keep them for now.
		if history {
			kept++
			continue
		}

		if !walBefore(name, keepFromWAL) {
			kept++
			continue
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		c.l.Info("deleting old WAL",
			slog.String("wal", name),
			slog.String("path", wal.Path),
			slog.String("keep_from", keepFromWAL),
		)

		if err := stor.Delete(ctx, wal.Path); err != nil {
			return fmt.Errorf("delete WAL %s: %w", wal.Path, err)
		}

		receivemetrics.M.IncWALFilesDeleted()
		deleted++
	}

	c.l.Info("WAL retention completed",
		slog.String("keep_from", keepFromWAL),
		slog.Int("deleted_wals", deleted),
		slog.Int("kept_wals", kept),
	)

	return nil
}

func isRootStoragePath(path string) bool {
	clean := filepath.ToSlash(strings.TrimSpace(path))
	clean = strings.TrimPrefix(clean, "./")

	return clean != "" && !strings.Contains(clean, "/")
}
