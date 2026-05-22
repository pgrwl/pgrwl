package serveapi

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/pgrwl/pgrwl/internal/opt/shared/x/fsx"

	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"

	"github.com/pgrwl/pgrwl/internal/core/xlog"
)

type Service interface {
	GetWalFile(ctx context.Context, filename string) (io.ReadCloser, error)
}

type svc struct {
	l       *slog.Logger
	baseDir string
	storage *st.VariadicStorage
}

var _ Service = &svc{}

func NewService(opts *Opts) Service {
	return &svc{
		l:       slog.With("component", "serve-service"),
		baseDir: opts.BaseDir,
		storage: opts.Storage,
	}
}

func (s *svc) log() *slog.Logger {
	if s.l != nil {
		return s.l
	}
	return slog.With("component", "serve-service")
}

func (s *svc) GetWalFile(ctx context.Context, filename string) (io.ReadCloser, error) {
	if err := validateWALDownloadName(filename); err != nil {
		return nil, err
	}

	// 1) Fast-path: check that file exists locally
	// 2) Check *.partial file locally
	// 3) Fetch from storage (if it's not nil)

	// TODO: send checksum in headers

	s.log().Debug("fetching WAL file", slog.String("filename", filename))

	// 1) trying to find local completed segment
	// 2) trying to find partial segment
	filePath := filepath.Join(s.baseDir, filename)
	partialFilePath := filePath + xlog.PartialSuffix

	s.log().Debug("wal-restore, fetching local file", slog.String("path", filePath))
	if fsx.FileExists(filePath) {
		s.log().Debug("wal-restore, found local file", slog.String("path", filePath))
		//nolint:gosec
		return os.Open(filePath)
	}
	if fsx.FileExists(partialFilePath) {
		s.log().Debug("wal-restore, found local partial file", slog.String("path", partialFilePath))
		//nolint:gosec
		return os.Open(partialFilePath)
	}

	// 3) trying remote
	if s.storage != nil {
		s.log().Debug("wal-restore, fetching remote file", slog.String("filename", filename))
		return s.storage.Get(ctx, filename)
	}

	return nil, fmt.Errorf("cannot fetch file: %s", filename)
}

func validateWALDownloadName(name string) error {
	if name != filepath.Base(name) {
		return fmt.Errorf("invalid wal filename")
	}
	// TODO: check is wal-file-name, or history-file-name
	return nil
}
