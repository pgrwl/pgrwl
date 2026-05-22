package xlog

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/pgrwl/pgrwl/internal/core/conv"
	"github.com/pgrwl/pgrwl/internal/core/fsync"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/jackc/pglogrepl"
)

type PgReceiveWal interface {
	Run(ctx context.Context) error
	Status() *StreamStatus
	CurrentOpenWALFileName() string
	WalSegSz() uint64
	Conn() *pgconn.PgConn
}

type pgReceiveWal struct {
	l                *slog.Logger
	receiveDirectory string
	walSegSz         uint64
	conn             *pgconn.PgConn
	connStrRepl      string
	slotName         string
	noLoop           bool
	streamMu         sync.RWMutex
	stream           *StreamCtl // current active stream (or nil)
}

var _ PgReceiveWal = &pgReceiveWal{}

type PgReceiveWalOpts struct {
	ReceiveDirectory string
	Slot             string
	NoLoop           bool
}

var ErrNoWalEntries = fmt.Errorf("no valid WAL segments found")

func NewPgReceiver(_ context.Context, streamingConn *StreamingConn, opts *PgReceiveWalOpts) PgReceiveWal {
	return &pgReceiveWal{
		l:                slog.With(slog.String("component", "pgreceivewal")),
		receiveDirectory: opts.ReceiveDirectory,
		walSegSz:         streamingConn.StartupInfo.WalSegSz,
		conn:             streamingConn.Conn,
		connStrRepl:      streamingConn.ConnStrRepl,
		slotName:         opts.Slot,
		noLoop:           opts.NoLoop,
	}
}

func (pgrw *pgReceiveWal) Run(ctx context.Context) error {
	// enter main streaming loop
	for {
		err := pgrw.streamLog(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				pgrw.log().Warn("context canceled in pgrw.Run(), exiting", slog.Any("err", err))
				return nil
			}
			pgrw.log().Error("an error occurred in StreamLog(), exiting", slog.Any("err", err))
			return err
		}

		select {
		case <-ctx.Done():
			pgrw.log().Info("context is done, exiting...")
			return nil
		default:
		}

		if pgrw.noLoop {
			pgrw.log().Error("disconnected")
			return fmt.Errorf("disconnected")
		}

		pgrw.log().Info("disconnected; waiting 5 seconds to try again")
		time.Sleep(5 * time.Second)
	}
}

func (pgrw *pgReceiveWal) CurrentOpenWALFileName() string {
	pgrw.streamMu.Lock()
	defer pgrw.streamMu.Unlock()
	if pgrw.stream == nil || pgrw.stream.walfile == nil || pgrw.stream.walfile.fd == nil {
		return ""
	}
	return pgrw.stream.walfile.pathname
}

func (pgrw *pgReceiveWal) log() *slog.Logger {
	if pgrw.l != nil {
		return pgrw.l
	}
	return slog.With(slog.String("component", "pgreceivewal"))
}

// StreamLog the main loop of WAL receiving, any error FATAL
func (pgrw *pgReceiveWal) streamLog(ctx context.Context) error {
	var err error

	// 1
	if pgrw.conn == nil {
		pgrw.conn, err = pgconn.Connect(context.Background(), pgrw.connStrRepl)
		if err != nil {
			pgrw.log().Error("cannot establish connection", slog.Any("err", err))
			// not a fatal error, a reconnect loop will handle it
			return nil
		}
	}

	walSegSz := pgrw.walSegSz

	// 3
	var slotRestartInfo *ReadReplicationSlotResultResult
	_, err = GetSlotInformation(pgrw.conn, pgrw.slotName)
	if err != nil {
		if errors.Is(err, ErrSlotDoesNotExist) {
			pgrw.log().Info("creating replication slot", slog.String("name", pgrw.slotName))
			replicationSlotOptions := pglogrepl.CreateReplicationSlotOptions{Mode: pglogrepl.PhysicalReplication}
			_, err = pglogrepl.CreateReplicationSlot(ctx, pgrw.conn, pgrw.slotName, "", replicationSlotOptions)
			if err != nil {
				return fmt.Errorf("cannot create replication slot: %w", err)
			}
		} else {
			return fmt.Errorf("cannot get slot information when checking existence: %w", err)
		}
	}

	slotRestartInfo, err = GetSlotInformation(pgrw.conn, pgrw.slotName)
	if err != nil {
		return fmt.Errorf("cannot get slot information: %w", err)
	}

	// 3
	sysident, err := pglogrepl.IdentifySystem(ctx, pgrw.conn)
	if err != nil {
		return fmt.Errorf("cannot identify system: %w", err)
	}

	// 4
	streamStartLSN, streamStartTimeline, err := pgrw.findStreamingStart()
	if err != nil {
		if !errors.Is(err, ErrNoWalEntries) {
			// just log an error and continue, stream-start-lsn and timeline
			// are required, and we will proceed with slot-info or sysident
			pgrw.log().Error("cannot find streaming start", slog.Any("err", err))
		}
	}

	if streamStartLSN == 0 {
		if slotRestartInfo.RestartLSN != 0 {
			streamStartLSN = slotRestartInfo.RestartLSN
			streamStartTimeline = slotRestartInfo.RestartTLI
		}
	}

	if streamStartLSN == 0 {
		streamStartLSN = sysident.XLogPos
		streamStartTimeline = conv.ToUint32(sysident.Timeline)
	}

	// final check
	if streamStartLSN == 0 || streamStartTimeline == 0 {
		return fmt.Errorf("cannot find start LSN for streaming")
	}

	// 5

	// Always start streaming at the beginning of a segment
	curPos := uint64(streamStartLSN) - XLogSegmentOffset(streamStartLSN, walSegSz)
	streamStartLSN = pglogrepl.LSN(curPos)

	pgrw.log().Info("starting log streaming",
		slog.String("lsn", streamStartLSN.String()),
		slog.Uint64("tli", uint64(streamStartTimeline)),
	)

	stream := NewStream(&StreamOpts{
		StartPos:         streamStartLSN,
		Timeline:         streamStartTimeline,
		ReplicationSlot:  pgrw.slotName,
		WalSegSz:         pgrw.walSegSz,
		ReceiveDirectory: pgrw.receiveDirectory,
		Conn:             pgrw.conn,
	})
	pgrw.SetStream(stream)

	err = stream.ReceiveXlogStream(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			pgrw.log().Warn("log streaming terminated: context canceled")
		} else {
			pgrw.log().Error("log streaming terminated", slog.Any("err", err))
		}
	}

	// fsync dir
	err = fsync.FsyncDir(pgrw.receiveDirectory)
	if err != nil {
		pgrw.log().Info("could not finish writing WAL files", slog.Any("err", err))
		// not a fatal error, just log it
		return nil
	}

	if pgrw.conn != nil {
		err := pgrw.conn.Close(ctx)
		if err != nil {
			// not a fatal error, just log it
			pgrw.log().Info("could not close connection", slog.Any("err", err))
		}
		pgrw.conn = nil
	}

	return nil
}

func (pgrw *pgReceiveWal) SetStream(s *StreamCtl) {
	pgrw.streamMu.Lock()
	defer pgrw.streamMu.Unlock()
	pgrw.stream = s
}

// findStreamingStart scans baseDir for WAL files and returns (startLSN, timeline)
func (pgrw *pgReceiveWal) findStreamingStart() (pglogrepl.LSN, uint32, error) {
	type walEntry struct {
		tli       uint32
		segNo     uint64
		isPartial bool
		basename  string
	}

	var entries []walEntry

	err := filepath.WalkDir(pgrw.receiveDirectory, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		base := filepath.Base(path)

		isPartial := IsPartialXLogFileName(base)
		if !IsXLogFileName(base) && !isPartial {
			return nil
		}

		tli, segNo, err := XLogFromFileName(base, pgrw.walSegSz)
		if err != nil {
			return err
		}

		if !isPartial {
			info, err := os.Stat(path)
			if err != nil {
				return fmt.Errorf("could not stat file %q: %w", path, err)
			}
			if conv.ToUint64(info.Size()) != pgrw.walSegSz {
				pgrw.log().Warn("WAL segment has incorrect size, skipping",
					slog.String("base", base),
					slog.Int64("size", info.Size()),
				)
				return nil
			}
		}

		entries = append(entries, walEntry{
			tli:       tli,
			segNo:     segNo,
			isPartial: isPartial,
			basename:  base,
		})

		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("could not read directory %q: %w", pgrw.receiveDirectory, err)
	}

	if len(entries) == 0 {
		return 0, 0, ErrNoWalEntries
	}

	// Sort by segNo, tli, isPartial (completed > partial)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].segNo != entries[j].segNo {
			return entries[i].segNo > entries[j].segNo
		}
		if entries[i].tli != entries[j].tli {
			return entries[i].tli > entries[j].tli
		}
		return !entries[i].isPartial && entries[j].isPartial
	})

	best := entries[0]

	var startLSN pglogrepl.LSN
	if best.isPartial {
		startLSN = XLogSegNoToRecPtr(best.segNo, pgrw.walSegSz)
	} else {
		startLSN = XLogSegNoToRecPtr(best.segNo+1, pgrw.walSegSz)
	}

	pgrw.log().Debug("found streaming start (based on WAL dir)",
		slog.String("lsn", startLSN.String()),
		slog.Uint64("tli", uint64(best.tli)),
		slog.String("wal", best.basename),
	)
	return startLSN, best.tli, nil
}

func (pgrw *pgReceiveWal) WalSegSz() uint64 {
	return pgrw.walSegSz
}

func (pgrw *pgReceiveWal) Conn() *pgconn.PgConn {
	return pgrw.conn
}
