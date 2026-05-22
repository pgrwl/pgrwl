package receiveapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pgrwl/pgrwl/config"

	"github.com/pgrwl/pgrwl/internal/opt/api"
	"github.com/pgrwl/pgrwl/internal/opt/basebackup/backupdto"
	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
	"github.com/pgrwl/pgrwl/internal/opt/shared/x/fsx"

	"github.com/pgrwl/pgrwl/internal/core/xlog"
)

type Service interface {
	Status() *PgrwlStatus
	BriefConfig(ctx context.Context) (*BriefConfig, error)
	FullRedactedConfig(ctx context.Context) *config.Config
	ListWALFiles(ctx context.Context) ([]WALFile, error)
	ListBackups(ctx context.Context) ([]Backup, error)
	GetWalFile(ctx context.Context, filename string) (io.ReadCloser, error)
	StopReceiver()
}

type svc struct {
	l            *slog.Logger
	pgrw         xlog.PgReceiveWal // direct access to running state
	baseDir      string
	storage      *st.VariadicStorage
	stopReceiver func()
}

var _ Service = &svc{}

func NewService(opts *Opts) Service {
	return &svc{
		l:            slog.With("component", "receive-service"),
		pgrw:         opts.PGRW,
		baseDir:      opts.BaseDir,
		storage:      opts.Storage,
		stopReceiver: opts.StopReceiver,
	}
}

func (s *svc) log() *slog.Logger {
	if s.l != nil {
		return s.l
	}
	return slog.With("component", "receive-service")
}

func (s *svc) Status() *PgrwlStatus {
	s.log().Debug("querying status")

	var streamStatusResp *StreamStatus
	if s.pgrw != nil {
		streamStatus := s.pgrw.Status()
		streamStatusResp = &StreamStatus{
			Slot:         streamStatus.Slot,
			Timeline:     streamStatus.Timeline,
			LastFlushLSN: streamStatus.LastFlushLSN,
			Uptime:       streamStatus.Uptime,
			Running:      streamStatus.Running,
		}
	}
	return &PgrwlStatus{
		StreamStatus: streamStatusResp,
	}
}

func (s *svc) BriefConfig(_ context.Context) (*BriefConfig, error) {
	cfg, err := config.Cfg()
	if err != nil {
		return nil, err
	}
	return &BriefConfig{RetentionEnable: cfg.Retention.Enable}, nil
}

func (s *svc) FullRedactedConfig(_ context.Context) *config.Config {
	c := config.RedactedCopy()
	return &c
}

// ListWALFiles returns metadata for every WAL file currently held in storage.
func (s *svc) ListWALFiles(ctx context.Context) ([]WALFile, error) {
	cfg, err := config.Cfg()
	if err != nil {
		return nil, err
	}

	encrypted := cfg.Storage.Encryption.Algo != ""

	infos, err := s.storage.ListInfoRaw(ctx, "")
	if err != nil {
		return nil, err
	}

	files := make([]WALFile, 0, len(infos))
	for _, fi := range infos {
		base := filepath.Base(fi.Path)

		// logical name (sans transform ext) is fi.Path after VariadicStorage.decodePath
		// base name without compression/encryption suffix
		logicalBase := base
		ext := ""
		for _, suffix := range []string{".gz.aes", ".zst.aes", ".aes", ".gz", ".zst"} {
			if strings.HasSuffix(base, suffix) {
				logicalBase = strings.TrimSuffix(base, suffix)
				ext = suffix
				break
			}
		}

		sizeMB := float64(fi.Size) / (1024 * 1024)
		files = append(files, WALFile{
			Name:       logicalBase,
			Ext:        ext,
			Filename:   base,
			SizeMB:     sizeMB,
			UploadedAt: fi.ModTime,
			Encrypted:  encrypted,
		})
	}
	return files, nil
}

// ListBackups returns metadata for every base backup stored in the backup subpath.
// It reads the per-backup manifest JSON to populate size and LSN fields.
func (s *svc) ListBackups(ctx context.Context) ([]Backup, error) {
	backupStor, err := api.SetupStorage(&api.SetupStorageOpts{
		BaseDir: filepath.ToSlash(s.baseDir),
		SubPath: config.BaseBackupSubpath,
	})
	if err != nil {
		return nil, err
	}

	// Each backup lives in a top-level directory named after its timestamp label.
	dirs, err := backupStor.ListTopLevelDirs(ctx, "")
	if err != nil {
		return nil, err
	}

	backups := make([]Backup, 0, len(dirs))
	for dir := range dirs {
		label := filepath.Base(dir)

		b := Backup{
			Label:  "pgrwl_" + label,
			Status: "unknown",
		}

		// Try to read the manifest to enrich the entry.
		manifestPath := filepath.ToSlash(filepath.Join(label, label+".json"))
		rc, readErr := backupStor.Get(ctx, manifestPath)
		if readErr == nil {
			var result backupdto.Result
			if decErr := json.NewDecoder(rc).Decode(&result); decErr == nil {
				b.SizeGB = float64(result.BytesTotal) / (1024 * 1024 * 1024)
				b.WALStartLSN = result.StartLSN.String()
				b.WALStopLSN = result.StopLSN.String()
				b.Status = "completed"
				b.Started = result.StartedAt
				b.Finished = result.FinishedAt
			}
			_ = rc.Close()
		} else {
			// Manifest absent -> backup in progress or failed.
			b.Status = "in_progress"
		}

		backups = append(backups, b)
	}

	// Sort newest first by label (labels are timestamp strings, so lexicographic = chronological).
	slices.SortFunc(backups, func(a, b Backup) int {
		if a.Label > b.Label {
			return -1
		}
		if a.Label < b.Label {
			return 1
		}
		return 0
	})

	return backups, nil
}

func (s *svc) GetWalFile(ctx context.Context, filename string) (io.ReadCloser, error) {
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

	if s.storage != nil {
		s.log().Debug("wal-restore, fetching remote file", slog.String("filename", filename))
		return s.storage.Get(ctx, filename)
	}

	return nil, fmt.Errorf("cannot fetch file: %s", filename)
}

func (s *svc) StopReceiver() {
	s.stopReceiver()
}
