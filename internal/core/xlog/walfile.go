package xlog

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/pgrwl/pgrwl/internal/opt/metrics/receivemetrics"

	"github.com/jackc/pglogrepl"
	"github.com/pgrwl/pgrwl/internal/core/conv"
	"github.com/pgrwl/pgrwl/internal/core/fsync"
)

type walfileT struct {
	currpos  uint64
	pathname string
	fd       *os.File
	sysfd    int // raw fd cached at open time; valid while fd is open
}

func (stream *StreamCtl) SyncWalFile() error {
	if stream.walfile == nil {
		return fmt.Errorf("stream.walfile is nil (SyncWalFile)")
	}
	return fsync.FsyncFd(stream.walfile.sysfd)
}

func (stream *StreamCtl) WriteAtWalFile(data []byte, xlogoff uint64) (int, error) {
	xlogOffToInt64, err := conv.Uint64ToInt64(xlogoff)
	if err != nil {
		return -1, err
	}

	if stream.walfile == nil {
		return -1, fmt.Errorf("stream.walfile is nil (WriteAtWalFile)")
	}
	if stream.walfile.fd == nil {
		return -1, fmt.Errorf("stream.walfile.fd is nil (WriteAtWalFile)")
	}
	n, err := stream.walfile.fd.WriteAt(data, xlogOffToInt64)
	if err != nil {
		return -1, err
	}
	if n > 0 {
		stream.walfile.currpos += uint64(n)
	}
	return n, nil
}

// OpenWalFile open a new WAL file in the specified directory.
// The file will be padded to 16Mb with zeroes.
func (stream *StreamCtl) OpenWalFile(startpoint pglogrepl.LSN) error {
	var err error

	segno := XLByteToSeg(uint64(startpoint), stream.walSegSz)
	filename := XLogFileName(stream.timeline, segno, stream.walSegSz) + stream.partialSuffix
	fullPath := filepath.Join(stream.receiveDir, filename)

	l := stream.log().With(
		slog.String("job", "open_wal_file"),
		slog.String("startpoint", startpoint.String()),
		slog.String("segno", fmt.Sprintf("%08X", segno)),
		slog.String("path", filepath.ToSlash(fullPath)),
	)

	l.Debug("opening WAL file for write")

	/*
	 * When streaming to files, if an existing file exists we verify that it's
	 * either empty (just created), or a complete WalSegSz segment (in which
	 * case it has been created and padded). Anything else indicates a corrupt
	 * file.
	 */

	// Check if file already exists
	stat, err := os.Stat(fullPath)
	if err == nil && stat.Mode().IsRegular() {
		l.Debug("file exists, check size")

		// File exists
		if conv.ToUint64(stat.Size()) == stream.walSegSz {
			l.Debug("file exists and correctly sized", slog.String("note", "open and fsync"))

			// File already correctly sized, open it
			fd, err := stream.openFileAndFsync(fullPath)
			if err != nil {
				stream.log().Error("cannot open and fsync existing file, exiting", slog.Any("err", err))
				// MARK:exit
				os.Exit(1)
			}

			l.Info("streaming resumes")
			stream.walfile = &walfileT{
				currpos:  0,
				pathname: fullPath,
				fd:       fd,
				sysfd:    int(fd.Fd()),
			}
			return nil
		}
		if stat.Size() != 0 {
			return fmt.Errorf("corrupt WAL file %s: expected size 0 or %d bytes, found %d",
				fullPath,
				stream.walSegSz,
				stat.Size(),
			)
		}
		// If size 0, proceed to initialize it
	}

	l.Debug("file does not exists, creating",
		slog.Uint64("size", stream.walSegSz),
	)

	// Otherwise create new file and preallocate
	fd, err := stream.createFileAndTruncate(fullPath, stream.walSegSz)
	if err != nil {
		return fmt.Errorf("could not create WAL file %s: %w", fullPath, err)
	}

	stream.walfile = &walfileT{
		currpos:  0,
		pathname: fullPath,
		fd:       fd,
		sysfd:    int(fd.Fd()),
	}

	l.Info("starting new WAL segment")
	return nil
}

func (stream *StreamCtl) createFileAndTruncate(fullPath string, initSize uint64) (*os.File, error) {
	// Create new file
	fd, err := os.OpenFile(fullPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o660)
	if err != nil {
		return nil, fmt.Errorf("could not create file %s: %w", fullPath, err)
	}

	// Preallocate file with zeros up to initSize
	truncateSize, err := conv.Uint64ToInt64(initSize)
	if err != nil {
		_ = fd.Close()
		return nil, err
	}
	if err := fd.Truncate(truncateSize); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("could not preallocate file %s: %w", fullPath, err)
	}
	return fd, nil
}

func (stream *StreamCtl) openFileAndFsync(fullPath string) (*os.File, error) {
	fd, err := os.OpenFile(fullPath, os.O_RDWR, 0o660)
	if err != nil {
		stream.log().Warn("could not open file",
			slog.String("path", filepath.ToSlash(fullPath)),
			slog.Any("err", err),
		)
		return nil, err
	}

	// fsync file in case of a previous crash
	if errFsync := fsync.Fsync(fd); errFsync != nil {
		if errClose := fd.Close(); errClose != nil {
			stream.log().Warn("cannot close file",
				slog.String("path", filepath.ToSlash(fullPath)),
				slog.Any("err", errClose),
			)
		}
		if errUnlink := os.Remove(fullPath); errUnlink != nil {
			stream.log().Warn("cannot unlink file",
				slog.String("path", filepath.ToSlash(fullPath)),
				slog.Any("err", errUnlink),
			)
		}
		return nil, errFsync
	}
	return fd, nil
}

// CloseWalFile close the current WAL file (if open), and rename it to the correct
// filename if it's complete.
func (stream *StreamCtl) CloseWalFile() error {
	var err error
	pos := stream.blockPos

	if stream.walfile == nil {
		return nil
	}

	l := stream.log().With(
		slog.String("job", "close_wal_file"),
		slog.String("pos", pos.String()),
		slog.String("path", filepath.ToSlash(stream.walfile.pathname)),
	)
	l.Debug("close WAL file")

	if strings.HasSuffix(stream.walfile.pathname, stream.partialSuffix) {
		if stream.walfile.currpos == stream.walSegSz {
			err = stream.closeAndRename()
		} else {
			err = stream.closeNoRename()
		}
	} else {
		err = stream.closeAndRename()
	}

	if err != nil {
		stream.log().Error("could not close file, (CloseWalfile)", slog.Any("err", err))
		return fmt.Errorf("could not close file: %w", err)
	}

	stream.updateLastFlushPosition(context.TODO(), pos, "CloseWalfile")
	return nil
}

// CloseWalFileIfPresentNoRename if any error occurs during streaming, safely close and fsync partial segment
func (stream *StreamCtl) CloseWalFileIfPresentNoRename(notice string) {
	stream.log().Warn("closing WAL file without renaming", slog.String("cause", notice))
	if stream.walfile != nil {
		err := stream.closeNoRename()
		if err != nil {
			stream.log().Error("could not close WAL file", slog.Any("err", err))
		}
	}
}

func (stream *StreamCtl) closeNoRename() error {
	if stream.walfile.fd == nil {
		return fmt.Errorf("stream.walfile.fd is nil (closeNoRename)")
	}

	pathname := stream.walfile.pathname
	l := stream.log().With(
		slog.String("job", "close_wal_file_no_rename"),
		slog.String("path", filepath.ToSlash(pathname)),
	)

	l.Warn("close without renaming", slog.String("note", "segment is not complete"))
	err := stream.walfile.fd.Close()
	if err != nil {
		return err
	}
	stream.walfile = nil

	l.Debug("fsync filename and parent-dir")
	err = fsync.FsyncFnameAndDir(pathname)
	if err != nil {
		return err
	}
	return nil
}

func (stream *StreamCtl) closeAndRename() error {
	if stream.walfile.fd == nil {
		return fmt.Errorf("stream.walfile.fd is nil (closeAndRename)")
	}

	pathname := stream.walfile.pathname
	finalName := strings.TrimSuffix(pathname, stream.partialSuffix)
	l := stream.log().With(
		slog.String("job", "close_wal_file_with_rename"),
	)

	l.Debug("closing fd (*.partial file)", slog.String("path", filepath.ToSlash(pathname)))
	if err := stream.walfile.fd.Close(); err != nil {
		return err
	}

	l.Debug("fsync path (*.partial file)", slog.String("path", filepath.ToSlash(pathname)))
	if err := fsync.FsyncFname(pathname); err != nil {
		return err
	}

	l.Debug("renaming to complete segment",
		slog.String("src", filepath.ToSlash(pathname)),
		slog.String("dst", filepath.ToSlash(finalName)),
	)
	if err := os.Rename(pathname, finalName); err != nil {
		return err
	}
	stream.walfile = nil

	l.Debug("fsync filename and parent-dir", slog.String("path", filepath.ToSlash(finalName)))
	if err := fsync.FsyncFnameAndDir(finalName); err != nil {
		return err
	}

	// NOTE:metrics
	receivemetrics.M.IncWALFilesReceived()

	l.Info("segment is complete")
	return nil
}
