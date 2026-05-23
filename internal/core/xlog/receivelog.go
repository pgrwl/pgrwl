package xlog

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pgrwl/pgrwl/config"

	"github.com/pgrwl/pgrwl/internal/opt/metrics/receivemetrics"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/pgrwl/pgrwl/internal/core/conv"
	"github.com/pgrwl/pgrwl/internal/core/fsync"
	"github.com/pgrwl/pgrwl/internal/core/logger"
)

// https://github.com/postgres/postgres/blob/master/src/bin/pg_basebackup/receivelog.c

type StreamOpts struct {
	StartPos         pglogrepl.LSN
	Timeline         uint32
	ReplicationSlot  string
	WalSegSz         uint64
	ReceiveDirectory string
	Conn             *pgconn.PgConn
}

type StreamCtl struct {
	l                     *slog.Logger
	startPos              pglogrepl.LSN
	timeline              uint32
	standbyMessageTimeout time.Duration
	synchronous           bool
	partialSuffix         string
	replicationSlot       string
	walSegSz              uint64
	receiveDir            string
	reportFlushPosition   bool
	lastStatus            time.Time
	lastFlushPosition     pglogrepl.LSN
	blockPos              pglogrepl.LSN
	stopPos               pglogrepl.LSN
	conn                  *pgconn.PgConn
	walfile               *walfileT
	startedAt             time.Time
	mu                    sync.RWMutex
}

func NewStream(o *StreamOpts) *StreamCtl {
	return &StreamCtl{
		l:                     slog.With("component", "receivelog"),
		standbyMessageTimeout: 10 * time.Second,
		synchronous:           true,
		partialSuffix:         PartialSuffix,
		reportFlushPosition:   true,
		startPos:              o.StartPos,
		timeline:              o.Timeline,
		replicationSlot:       o.ReplicationSlot,
		walSegSz:              o.WalSegSz,
		receiveDir:            o.ReceiveDirectory,
		conn:                  o.Conn,
		startedAt:             time.Now(),
	}
}

func (stream *StreamCtl) log() *slog.Logger {
	if stream.l != nil {
		return stream.l
	}
	return slog.With("component", "receivelog")
}

// ReceiveXlogStream
//
// Receive a log stream starting at the specified position.
//
// Individual parameters are passed through the StreamCtl structure.
//
// All received segments will be written to the directory
// specified by basedir.
// This will also fetch any missing timeline history files.
//
// Files are initially created with the *.partial suffix,
// and the suffix is removed once the file is finished.
// That allows you to tell the difference between partial and completed files,
// so that you can continue later where you left.
//
// The received WAL is flushes as soon as written.
//
// Note: The WAL location *must* be at a log segment start!
func (stream *StreamCtl) ReceiveXlogStream(ctx context.Context) error {
	/*
	 * initialize flush position to starting point, it's the caller's
	 * responsibility that that's sane.
	 */
	stream.updateLastFlushPosition(ctx, stream.startPos, "ReceiveXlogStream: init")
	stream.lastStatus = time.Time{}

	for {
		// --- Before streaming starts ---

		timelineToI32, err := conv.Uint32ToInt32(stream.timeline)
		if err != nil {
			return err
		}

		/*
		 * Fetch the timeline history file for this timeline, if we don't have
		 * it already. When streaming log to tar, this will always return
		 * false, as we are never streaming into an existing file and
		 * therefore there can be no pre-existing timeline history file.
		 */
		if !stream.existsTimeLineHistoryFile() {
			tlh, err := pglogrepl.TimelineHistory(ctx, stream.conn, timelineToI32)
			if err != nil {
				return fmt.Errorf("failed to fetch timeline history: %w", err)
			}
			if err := stream.writeTimeLineHistoryFile(tlh.FileName, string(tlh.Content)); err != nil {
				return fmt.Errorf("failed to write timeline history file: %w", err)
			}
		}

		/* Initiate the replication stream at specified location */
		opts := pglogrepl.StartReplicationOptions{
			Timeline: timelineToI32,
			Mode:     pglogrepl.PhysicalReplication,
		}
		if err := pglogrepl.StartReplication(ctx, stream.conn, stream.replicationSlot, stream.startPos, opts); err != nil {
			return fmt.Errorf("failed to start replication: %w", err)
		}

		/* Stream the WAL */
		cdr, err := stream.handleCopyStream(ctx)
		if err != nil {
			errMsg := "func handleCopyStream() exits with an error"
			if errors.Is(err, context.Canceled) {
				errMsg = "context canceled"
			}
			stream.CloseWalFileIfPresentNoRename(errMsg)
			return fmt.Errorf("error during streaming: %w", err)
		}

		/*
		 * Streaming finished.
		 *
		 * There are two possible reasons for that: a controlled shutdown, or
		 * we reached the end of the current timeline. In case of
		 * end-of-timeline, the server sends a result set after Copy has
		 * finished, containing information about the next timeline. Read
		 * that, and restart streaming from the next timeline. In case of
		 * controlled shutdown, stop here.
		 */

		if cdr != nil {
			/*
			 * End-of-timeline. Read the next timeline's ID and starting
			 * position. Usually, the starting position will match the end of
			 * the previous timeline, but there are corner cases like if the
			 * server had sent us half of a WAL record, when it was promoted.
			 * The new timeline will begin at the end of the last complete
			 * record in that case, overlapping the partial WAL record on the
			 * old timeline.
			 */

			newTimeline := conv.ToUint32(cdr.Timeline)
			newStartPos := cdr.LSN

			if newTimeline <= stream.timeline {
				stream.CloseWalFileIfPresentNoRename("(end-of-timeline) newTimeline <= stream.Timeline")
				return fmt.Errorf("server reported unexpected next timeline %d <= %d", newTimeline, stream.timeline)
			}
			if newStartPos > stream.stopPos {
				stream.CloseWalFileIfPresentNoRename("(end-of-timeline) newStartPos > stopPos")
				return fmt.Errorf("server reported next timeline startpos %s > stoppos %s", newStartPos, stream.stopPos)
			}

			/*
			* Loop back to start streaming from the new timeline. Always
			* start streaming at the beginning of a segment.
			 */
			stream.timeline = newTimeline
			stream.startPos = newStartPos - (newStartPos % pglogrepl.LSN(stream.walSegSz))

			stream.log().Info("end of timeline, continue",
				slog.Uint64("new-tli", uint64(stream.timeline)),
				slog.String("new-pos", stream.startPos.String()),
			)

			continue // restart streaming
		}

		/*
		 * End of replication (i.e. controlled shut down of the server).
		 */

		if config.Verbose {
			stream.log().LogAttrs(ctx, logger.LevelTrace, "stream termination",
				slog.String("job", "receive_xlog_stream"),
				slog.String("reason", "controlled shutdown"),
				slog.Uint64("tli", uint64(stream.timeline)),
				slog.String("flush_pos", stream.lastFlushPosition.String()),
			)
		}

		stream.log().Warn("replication stream was terminated")
		stream.CloseWalFileIfPresentNoRename("controlled shutdown")
		return nil
	}
}

func (stream *StreamCtl) handleCopyStream(ctx context.Context) (*pglogrepl.CopyDoneResult, error) {
	stream.lastStatus = time.Time{}
	stream.blockPos = stream.startPos

	for {
		now := time.Now()

		// If synchronous, flush WAL file and update server immediately
		if stream.synchronous && stream.lastFlushPosition < stream.blockPos && stream.walfile != nil {
			if config.Verbose {
				stream.log().LogAttrs(ctx, logger.LevelTrace, "SYNC-1",
					slog.String("job", "handle_copy_stream"),
					slog.String("flush_pos", stream.lastFlushPosition.String()),
					slog.String("block_pos", stream.blockPos.String()),
					slog.Uint64("diff", uint64(stream.blockPos)-uint64(stream.lastFlushPosition)),
				)
			}

			if err := stream.SyncWalFile(); err != nil {
				return nil, fmt.Errorf("could not fsync WAL file: %w", err)
			}
			stream.updateLastFlushPosition(ctx, stream.blockPos, "handleCopyStream: (stream.LastFlushPosition < blockPos)")
			/*
			 * Send feedback so that the server sees the latest WAL locations
			 * immediately.
			 */
			if err := stream.sendFeedback(ctx, now, false); err != nil {
				return nil, fmt.Errorf("could not send feedback after sync: %w", err)
			}
			stream.lastStatus = now
		}

		/*
		 * Potentially send a status message to the primary
		 */
		if stream.standbyMessageTimeout > 0 &&
			time.Since(stream.lastStatus) > stream.standbyMessageTimeout {
			/* Time to send feedback! */
			if err := stream.sendFeedback(ctx, now, false); err != nil {
				return nil, fmt.Errorf("could not send periodic feedback: %w", err)
			}
			stream.lastStatus = now
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			/*
			 * Calculate how long send/receive loops should sleep
			 */
			sleeptime := stream.calculateCopyStreamSleepTime(now)

			ctxTimeout, cancel := context.WithTimeout(ctx, sleeptime)
			msg, err := stream.conn.ReceiveMessage(ctxTimeout)
			cancel()
			if pgconn.Timeout(err) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("receive message failed: %w", err)
			}

			for {
				cdr, err := stream.processOneMsg(ctx, msg)
				if err != nil || cdr != nil {
					return cdr, err
				}

				/*
				 * Process the received data, and any subsequent data we can read
				 * without blocking.
				 */
				ctxTimeout, cancel = context.WithTimeout(ctx, 1*time.Second)
				msg, err = stream.conn.ReceiveMessage(ctxTimeout)
				cancel()
				if pgconn.Timeout(err) {
					break // done draining
				}
				if err != nil {
					return nil, err
				}
			}
		}
	}
}

func (stream *StreamCtl) processOneMsg(ctx context.Context, msg pgproto3.BackendMessage) (*pglogrepl.CopyDoneResult, error) {
	switch m := msg.(type) {
	case *pgproto3.CopyData:
		switch m.Data[0] {
		case pglogrepl.PrimaryKeepaliveMessageByteID:
			pkm, err := pglogrepl.ParsePrimaryKeepaliveMessage(m.Data[1:])
			if err != nil {
				return nil, fmt.Errorf("parse keepalive failed: %w", err)
			}
			if err := stream.processKeepaliveMsg(ctx, pkm); err != nil {
				return nil, fmt.Errorf("process keepalive failed: %w", err)
			}

		case pglogrepl.XLogDataByteID:
			xld, err := pglogrepl.ParseXLogData(m.Data[1:])
			if err != nil {
				return nil, fmt.Errorf("parse xlogdata failed: %w", err)
			}

			if config.Verbose {
				stream.log().LogAttrs(ctx, logger.LevelTrace, "begin to process xlog data msg",
					slog.String("job", "handle_copy_stream"),
					slog.String("flush_pos", stream.lastFlushPosition.String()),
					slog.String("block_pos", stream.blockPos.String()),
					slog.Uint64("diff", uint64(stream.blockPos)-uint64(stream.lastFlushPosition)),
					slog.Int("len", len(xld.WALData)),
				)
			}

			if err := stream.processXLogDataMsg(ctx, xld); err != nil {
				return nil, fmt.Errorf("processing xlogdata failed: %w", err)
			}

			if config.Verbose {
				stream.log().LogAttrs(ctx, logger.LevelTrace, "log data msg processed",
					slog.String("job", "handle_copy_stream"),
					slog.String("flush_pos", stream.lastFlushPosition.String()),
					slog.String("block_pos", stream.blockPos.String()),
					slog.Uint64("diff", uint64(stream.blockPos)-uint64(stream.lastFlushPosition)),
				)
			}
		default:
			return nil, fmt.Errorf("unexpected CopyData message type: %c", m.Data[0])
		}

	case *pgproto3.CopyDone:
		return stream.handleEndOfCopyStream(ctx)

		// Handle other commands
	case *pgproto3.CommandComplete:
		stream.log().Warn("received CommandComplete", slog.String("note", "treating as disconnection"))
		return nil, nil // safe exit
	case *pgproto3.ErrorResponse:
		return nil, fmt.Errorf("error response from server: %s", m.Message)
	case *pgproto3.ReadyForQuery:
		stream.log().Warn("received ReadyForQuery", slog.String("note", "treating as disconnection"))
		return nil, nil // safe exit
	default:
		stream.log().Warn("received unexpected message", slog.String("type", fmt.Sprintf("%T", msg)))
		return nil, fmt.Errorf("received unexpected message: %T", msg)
	}
	return nil, nil
}

func (stream *StreamCtl) processKeepaliveMsg(ctx context.Context, keepalive pglogrepl.PrimaryKeepaliveMessage) error {
	if keepalive.ReplyRequested {
		// If a valid flush location needs to be reported, and WAL file exists
		if stream.reportFlushPosition &&
			stream.lastFlushPosition < stream.blockPos &&
			stream.walfile != nil {
			/*
			 * If a valid flush location needs to be reported, flush the
			 * current WAL file so that the latest flush location is sent back
			 * to the server. This is necessary to see whether the last WAL
			 * data has been successfully replicated or not, at the normal
			 * shutdown of the server.
			 */

			if config.Verbose {
				stream.log().LogAttrs(ctx, logger.LevelTrace, "SYNC-K",
					slog.String("job", "process_keepalive_msg"),
					slog.String("flush_pos", stream.lastFlushPosition.String()),
					slog.String("block_pos", stream.blockPos.String()),
					slog.Uint64("diff", uint64(stream.blockPos)-uint64(stream.lastFlushPosition)),
				)
			}

			if err := stream.SyncWalFile(); err != nil {
				return fmt.Errorf("could not fsync WAL file: %w", err)
			}
			stream.updateLastFlushPosition(ctx, stream.blockPos, "processKeepaliveMsg: (stream.LastFlushPosition < blockPos)")
		}

		now := time.Now()
		if err := stream.sendFeedback(ctx, now, false); err != nil {
			return fmt.Errorf("failed to send feedback in keepalive: %w", err)
		}
		stream.lastStatus = now
	}

	return nil
}

func (stream *StreamCtl) processXLogDataMsg(ctx context.Context, xld pglogrepl.XLogData) error {
	var err error
	stream.blockPos = xld.WALStart

	/* Extract WAL location for this block */
	xlogoff := XLogSegmentOffset(stream.blockPos, stream.walSegSz)

	/*
	 * Verify that the initial location in the stream matches where we think
	 * we are.
	 */
	if stream.walfile == nil {
		if xlogoff != 0 {
			return fmt.Errorf("received WAL at offset %d but no file open", xlogoff)
		}
	} else {
		/* More data in existing segment */
		if stream.walfile.currpos != xlogoff {
			return fmt.Errorf("got WAL data offset %08x, expected %08x", xlogoff, stream.walfile.currpos)
		}
	}

	data := xld.WALData

	bytesLeft := uint64(len(data))
	bytesWritten := uint64(0)

	if config.Verbose {
		stream.log().LogAttrs(ctx, logger.LevelTrace, "begin to write xlog data msg",
			slog.String("job", "process_xlog_data_msg"),
			slog.String("flush_pos", stream.lastFlushPosition.String()),
			slog.String("block_pos", stream.blockPos.String()),
			slog.Uint64("diff", uint64(stream.blockPos-stream.lastFlushPosition)),
			slog.Uint64("len", bytesLeft),
		)
	}

	for bytesLeft != 0 {
		var bytesToWrite uint64

		/*
		 * If crossing a WAL boundary, only write up until we reach wal
		 * segment size.
		 */
		if xlogoff+bytesLeft > stream.walSegSz {
			bytesToWrite = stream.walSegSz - xlogoff
		} else {
			bytesToWrite = bytesLeft
		}

		if stream.walfile == nil {
			err = stream.OpenWalFile(stream.blockPos)
			if err != nil {
				return err
			}
		}

		// if(stream->walmethod->ops->write(walfile,
		// 	copybuf + hdr_len + bytes_written,
		// 	bytes_to_write) != bytes_to_write) {}

		n, err := stream.WriteAtWalFile(data[bytesWritten:bytesWritten+bytesToWrite], xlogoff)
		if err != nil {
			return fmt.Errorf("could not write %d bytes to WAL file: %w", bytesToWrite, err)
		}
		if conv.ToUint64(int64(n)) != bytesToWrite {
			return fmt.Errorf("could not write %d bytes to WAL file: %w", bytesToWrite, err)
		}

		/* Write was successful, advance our position */
		bytesWritten += bytesToWrite
		bytesLeft -= bytesToWrite
		stream.blockPos += pglogrepl.LSN(bytesToWrite)
		xlogoff += bytesToWrite

		// NOTE:metrics
		receivemetrics.M.AddWALBytesReceived(float64(bytesToWrite))

		/* Did we reach the end of a WAL segment? */
		xlSegOff := XLogSegmentOffset(stream.blockPos, stream.walSegSz)
		if xlSegOff == 0 {
			err := stream.CloseWalFile()
			if err != nil {
				return err
			}
			xlogoff = 0
		}
	}

	/* No more data left to write, receive next copy packet */
	return nil
}

func (stream *StreamCtl) sendFeedback(ctx context.Context, now time.Time, replyRequested bool) error {
	if config.Verbose {
		stream.log().LogAttrs(ctx, logger.LevelTrace, "sending feedback",
			slog.String("flush_pos", stream.lastFlushPosition.String()),
			slog.String("block_pos", stream.blockPos.String()),
			slog.Uint64("diff", uint64(stream.blockPos)-uint64(stream.lastFlushPosition)),
			slog.Time("now", now),
		)
	}

	var standbyStatus pglogrepl.StandbyStatusUpdate

	standbyStatus.WALWritePosition = stream.blockPos

	if stream.reportFlushPosition {
		standbyStatus.WALFlushPosition = stream.lastFlushPosition
	} else {
		standbyStatus.WALFlushPosition = pglogrepl.LSN(0)
	}

	standbyStatus.WALApplyPosition = pglogrepl.LSN(0)
	standbyStatus.ClientTime = now
	standbyStatus.ReplyRequested = replyRequested

	err := pglogrepl.SendStandbyStatusUpdate(ctx, stream.conn, standbyStatus)
	if err != nil {
		stream.log().Error("could not send feedback packet", slog.Any("err", err))
		return err
	}

	return nil
}

func (stream *StreamCtl) handleEndOfCopyStream(ctx context.Context) (*pglogrepl.CopyDoneResult, error) {
	stream.log().Debug("received CopyDone")
	var err error
	var cdr *pglogrepl.CopyDoneResult

	if err := stream.CloseWalFile(); err != nil {
		return nil, fmt.Errorf("failed to close WAL file: %w", err)
	}

	cdr, err = SendStandbyCopyDone(ctx, stream.conn)
	if err != nil {
		return nil, fmt.Errorf("failed to send client CopyDone: %w", err)
	}
	stream.log().Debug("CopyDoneResult", slog.Any("cdr", cdr))

	stream.stopPos = stream.blockPos
	return cdr, nil
}

func (stream *StreamCtl) updateLastFlushPosition(ctx context.Context, p pglogrepl.LSN, reason string) {
	if config.Verbose {
		stream.log().LogAttrs(ctx, logger.LevelTrace, "updating last-flush position",
			slog.String("prev", stream.lastFlushPosition.String()),
			slog.String("next", p.String()),
			slog.Uint64("diff", uint64(p-stream.lastFlushPosition)),
			slog.String("reason", reason),
		)
	}

	stream.lastFlushPosition = p
}

// timeline history file

func (stream *StreamCtl) existsTimeLineHistoryFile() bool {
	// Timeline 1 never has a history file
	if stream.timeline == 1 {
		return true
	}

	histfname := fmt.Sprintf("%08X.history", stream.timeline)
	return fileExists(filepath.Join(stream.receiveDir, histfname))
}

func (stream *StreamCtl) writeTimeLineHistoryFile(filename, content string) error {
	expectedName := fmt.Sprintf("%08X.history", stream.timeline)

	if expectedName != filename {
		return fmt.Errorf("server reported unexpected history file name for timeline %d: %s", stream.timeline, filename)
	}

	histPath := filepath.Join(stream.receiveDir, filename+".tmp")

	// Create temporary file first
	f, err := os.OpenFile(histPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("could not create timeline history file %s: %w", histPath, err)
	}
	defer func() {
		_ = f.Close() // ensure close even on error
	}()

	// Write content
	n, err := f.WriteString(content)
	if err != nil || n != len(content) {
		_ = os.Remove(histPath) // delete temp file
		return fmt.Errorf("could not write timeline history file %s: %w", histPath, err)
	}

	// Sync to disk
	if err := fsync.Fsync(f); err != nil {
		return fmt.Errorf("could not fsync timeline history file %s: %w", histPath, err)
	}

	// Close file
	if err := f.Close(); err != nil {
		return fmt.Errorf("could not close timeline history file %s: %w", histPath, err)
	}

	// Rename from .tmp to final
	finalPath := filepath.Join(stream.receiveDir, filename)
	if err := os.Rename(histPath, finalPath); err != nil {
		return fmt.Errorf("could not rename temp timeline history file to final: %w", err)
	}

	return nil
}

func (stream *StreamCtl) calculateCopyStreamSleepTime(now time.Time) time.Duration {
	var statusTargetTime time.Time
	var sleepTime time.Duration

	if stream.standbyMessageTimeout > 0 {
		statusTargetTime = stream.lastStatus.Add(stream.standbyMessageTimeout)
	}

	if !statusTargetTime.IsZero() {
		diff := statusTargetTime.Sub(now)

		if diff <= 0 {
			// Always sleep at least 1 second if overdue
			sleepTime = 1 * time.Second
		} else {
			sleepTime = diff
		}
	} else {
		sleepTime = -1
	}

	return sleepTime
}
