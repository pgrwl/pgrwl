package backup

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/pgrwl/pgrwl/internal/opt/basebackup/backupdto"
	"github.com/pgrwl/pgrwl/internal/opt/metrics/backupmetrics"
	"github.com/pgrwl/pgrwl/internal/opt/shared/x/fsx"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
)

// https://www.postgresql.org/docs/current/protocol-replication.html#PROTOCOL-REPLICATION-BASE-BACKUP

// BaseBackup is an API for streaming basebackup
type BaseBackup interface {
	StreamBackup(ctx context.Context) (*backupdto.Result, error)
}

type baseBackup struct {
	l         *slog.Logger
	conn      *pgconn.PgConn
	storage   st.Storage
	timestamp string
}

func NewBaseBackup(conn *pgconn.PgConn, storage st.Storage, timestamp string) (BaseBackup, error) {
	if conn == nil {
		return nil, fmt.Errorf("basebackup: connection is required")
	}
	if storage == nil {
		return nil, fmt.Errorf("basebackup: storage is required")
	}
	if timestamp == "" {
		return nil, fmt.Errorf("basebackup: timestamp is required")
	}
	return &baseBackup{
		l:         slog.With(slog.String("component", "basebackup"), slog.String("id", timestamp)),
		conn:      conn,
		storage:   storage,
		timestamp: timestamp,
	}, nil
}

func (bb *baseBackup) log() *slog.Logger {
	if bb.l != nil {
		return bb.l
	}
	return slog.With(slog.String("component", "basebackup"), slog.String("id", bb.timestamp))
}

func (bb *baseBackup) StreamBackup(ctx context.Context) (*backupdto.Result, error) {
	result, err := bb.streamBaseBackup(ctx)
	if err != nil {
		return nil, err
	}

	// upload marker
	markerFileName := bb.timestamp + ".json"
	bb.log().Debug("uploading marker file", slog.String("name", markerFileName))
	markerFileData, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	err = bb.storage.Put(ctx, markerFileName, io.NopCloser(bytes.NewReader(markerFileData)))
	if err != nil {
		return nil, err
	}

	// metrics
	bb.log().Debug("bytes received", slog.Int64("total", result.BytesTotal))
	backupmetrics.M.AddBasebackupBytesReceived(float64(result.BytesTotal))
	return result, nil
}

func (bb *baseBackup) streamBaseBackup(ctx context.Context) (*backupdto.Result, error) {
	startResp, err := pglogrepl.StartBaseBackup(ctx, bb.conn, pglogrepl.BaseBackupOptions{
		Label:         fmt.Sprintf("pgrwl_%s", bb.timestamp),
		Progress:      false, // or true if you want to use 'p'
		Fast:          true,
		WAL:           false,
		NoWait:        true,
		MaxRate:       0,
		TablespaceMap: true,
		Manifest:      true,
	})
	if err != nil {
		return nil, fmt.Errorf("start base backup: %w", err)
	}

	result := &backupdto.Result{
		StartLSN:    startResp.LSN,
		TimelineID:  startResp.TimelineID,
		Tablespaces: getTblspcInfo(startResp.Tablespaces),
	}

	log := bb.log()
	log.Info("started backup",
		slog.String("StartLSN", startResp.LSN.String()),
		slog.Int("tablespaces", len(startResp.Tablespaces)),
	)

	startTime := time.Now()
	var curFile *StreamingFile
	var totalBytes int64
	var remotePath string

	manifestBuf := bytes.Buffer{}
	inManifest := false

	closeCurrent := func() error {
		if curFile == nil {
			return nil
		}
		if err := curFile.Close(); err != nil {
			return err
		}
		curFile = nil
		return nil
	}

	for {
		msg, err := bb.conn.ReceiveMessage(ctx)
		if err != nil {
			//nolint:errcheck
			_ = closeCurrent()
			return nil, fmt.Errorf("receive message: %w", err)
		}

		switch m := msg.(type) {
		case *pgproto3.CopyOutResponse:
			// nothing interesting here
			log.Debug("copy-out response received")
			continue

		case *pgproto3.CopyData:
			switch m.Data[0] {
			// Identifies the message as indicating the start of a new archive.
			// There will be one archive for the main data directory and one for each additional tablespace;
			// each will use tar format (following the "ustar interchange format" specified in the POSIX 1003.1-2008 standard).
			case 'n':
				inManifest = false

				if err := closeCurrent(); err != nil {
					return nil, err
				}

				filename, rest, err := readCString(m.Data[1:])
				if err != nil {
					return nil, err
				}

				tsPath, _, err := readCString(rest)
				if err != nil {
					return nil, err
				}

				remotePath = strings.TrimPrefix(filename, "./")
				curFile = NewStreamingFile(ctx, log, bb.storage, remotePath)

				log.Info("streaming backup file",
					slog.String("path", remotePath),
					slog.String("tablespace-path", tsPath),
				)

				// Identifies the message as containing archive or manifest data.
			case 'd':

				// manifest

				if inManifest {
					mData := m.Data[1:]
					log.Debug("writing manifest data", slog.Int("len", len(mData)))
					if _, err := manifestBuf.Write(mData); err != nil {
						return nil, fmt.Errorf("write manifest buffer: %w", err)
					}
					continue
				}

				// archive

				if curFile == nil {
					//nolint:errcheck
					_ = closeCurrent()
					return nil, fmt.Errorf("received data but no active file")
				}
				n, err := curFile.Write(m.Data[1:])
				if err != nil {
					//nolint:errcheck
					_ = closeCurrent()
					return nil, fmt.Errorf("write to storage pipe: %w", err)
				}
				totalBytes += int64(n)

				// Identifies the message as indicating the start of the backup manifest.
			case 'm':
				log.Debug("received manifest start")

				if err := closeCurrent(); err != nil {
					return nil, err
				}

				inManifest = true
				manifestBuf.Reset() // only once, at manifest start

				// Identifies the message as a progress report.
			case 'p':
				// only if Progress: true
				if len(m.Data) >= 9 {
					//nolint:gosec
					bytesDone := int64(binary.BigEndian.Uint64(m.Data[1:9]))
					elapsed := time.Since(startTime)
					log.Info("basebackup progress",
						slog.String("file", remotePath),
						slog.Int64("bytes_done", bytesDone),
						slog.String("bytes_done_iec", fsx.ByteCountIEC(bytesDone)),
						slog.String("elapsed", elapsed.Round(time.Millisecond).String()),
					)
				}

			default:
				log.Warn("unknown CopyData type", slog.String("rune", string(m.Data[0])))
			}

		case *pgproto3.CopyDone:
			if err := closeCurrent(); err != nil {
				return nil, err
			}
			log.Info("backup stream complete")

			stopRes, err := pglogrepl.FinishBaseBackup(ctx, bb.conn)
			if err != nil {
				return nil, fmt.Errorf("finish base backup: %w", err)
			}

			elapsed := time.Since(startTime)
			log.Info("finished backup",
				slog.String("StopLSN", stopRes.LSN.String()),
				slog.Int64("total_bytes", totalBytes),
				slog.String("total_size_iec", fsx.ByteCountIEC(totalBytes)),
				slog.String("elapsed", elapsed.Round(time.Millisecond).String()),
			)

			result.StopLSN = stopRes.LSN
			result.BytesTotal = totalBytes
			result.StartedAt = startTime.UTC()
			result.FinishedAt = time.Now().UTC()

			if manifestBuf.Len() > 0 {
				manifest := backupdto.BackupManifest{}
				if err := json.Unmarshal(manifestBuf.Bytes(), &manifest); err != nil {
					return nil, fmt.Errorf("parse manifest: %w", err)
				}
				result.Manifest = &manifest
			}

			return result, nil

		default:
			return nil, fmt.Errorf("unexpected message type: %T", msg)
		}
	}
}

//nolint:gocritic
func readCString(buf []byte) (string, []byte, error) {
	idx := bytes.IndexByte(buf, 0)
	if idx < 0 {
		return "", nil, fmt.Errorf("invalid CString: %q", string(buf))
	}
	return string(buf[:idx]), buf[idx+1:], nil
}

func getTblspcInfo(t []pglogrepl.BaseBackupTablespace) []backupdto.Tablespace {
	//nolint:prealloc
	r := []backupdto.Tablespace{}
	for _, elem := range t {
		r = append(r, backupdto.Tablespace{
			OID:      elem.OID,
			Location: elem.Location,
		})
	}
	return r
}
