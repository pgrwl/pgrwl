package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/pgrwl/pgrwl/internal/opt/api/streamapi/backupapi"
	"github.com/pgrwl/pgrwl/internal/opt/api/streamapi/receiveapi"

	"github.com/pgrwl/pgrwl/internal/opt/api/streamapi"

	"github.com/pgrwl/pgrwl/config"
	"github.com/pgrwl/pgrwl/internal/core/conv"
	"github.com/pgrwl/pgrwl/internal/core/xlog"
	"github.com/pgrwl/pgrwl/internal/opt/api"
	"github.com/pgrwl/pgrwl/internal/opt/metrics/backupmetrics"
	"github.com/pgrwl/pgrwl/internal/opt/metrics/receivemetrics"
	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
	"github.com/pgrwl/pgrwl/internal/opt/supervisors/backupsv"
	"github.com/pgrwl/pgrwl/internal/opt/supervisors/receivesv"
)

const shutdownTimeout = 30 * time.Second

type ReceiveModeOpts struct {
	ReceiveDirectory string
	Slot             string
	NoLoop           bool
	ListenPort       int
}

//nolint:gocyclo
func RunReceiveMode(opts *ReceiveModeOpts) error {
	cfg, err := config.Cfg()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	loggr := slog.With("component", "receive-mode-runner")

	// setup context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, signalCancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer signalCancel()

	// fatalErrCh is used only by critical components.
	//
	// Critical:
	//   - WAL receiver
	//   - WAL archive supervisor, when enabled
	//
	// Non-critical:
	//   - HTTP API
	//   - basebackup supervisor
	//   - manual basebackup service
	//   - metrics
	fatalErrCh := make(chan error, 1)

	sendFatalErr := func(err error) {
		if err == nil {
			return
		}

		select {
		case fatalErrCh <- err:
			cancel()
		default:
			// Another fatal error was already reported.
			cancel()
		}
	}

	// print options
	loggr.LogAttrs(ctx, slog.LevelInfo, "opts", slog.Any("opts", opts))

	//////////////////////////////////////////////////////////////////////
	// Init WAL-receiver first.
	//
	// This remains the core component. If it cannot be initialized, receive
	// mode must not start.

	// init replication connection (NOTE: pgrw responsible for closing it, even during reconnects)
	streamingConn, err := xlog.OpenReplicationConn(ctx, opts.Slot)
	if err != nil {
		return fmt.Errorf("init streaming conn: %w", err)
	}
	if err := checkStreamingConn(streamingConn); err != nil {
		return err
	}

	// init pgrw
	pgrw, err := initPgrw(ctx, streamingConn, opts)
	if err != nil {
		return fmt.Errorf("init wal receiver: %w", err)
	}

	//////////////////////////////////////////////////////////////////////
	// Init receive/archive dependencies before starting goroutines.

	walSegSz := streamingConn.StartupInfo.WalSegSz

	walStor, err := initWalStorage(loggr, opts, walSegSz)
	if err != nil {
		return fmt.Errorf("init wal storage: %w", err)
	}

	basebackupStor, err := initBasebackupStorage(cfg.Main.Directory)
	if err != nil {
		return fmt.Errorf("init basebackup storage: %w", err)
	}

	basebackupSupervisor, err := backupsv.NewBaseBackupSupervisor(&backupsv.BackupSupervisorOpts{
		Directory:      opts.ReceiveDirectory,
		WalSegSz:       walSegSz,
		BasebackupStor: basebackupStor,
		WalStor:        walStor,
		Cfg:            cfg,
	})
	if err != nil {
		return fmt.Errorf("init basebackup supervisor: %w", err)
	}

	// setup metrics
	initMetrics(ctx, cfg, loggr)

	var wg sync.WaitGroup

	//////////////////////////////////////////////////////////////////////
	// Main WAL receiver loop.
	//
	// Critical component. Any error or panic is fatal.

	wg.Add(1)
	go func() {
		defer wg.Done()

		defer func() {
			if r := recover(); r != nil {
				sendFatalErr(fmt.Errorf("wal receiver panicked: %v", r))
			}
		}()

		loggr.Info("wal-receiver started")

		if err := pgrw.Run(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				loggr.Info("wal-receiver stopped", slog.String("reason", "context canceled"))
				return
			}

			sendFatalErr(fmt.Errorf("streaming failed: %w", err))
			return
		}

		loggr.Info("wal-receiver stopped")
	}()

	//////////////////////////////////////////////////////////////////////
	// Basebackup supervisor.
	//
	// Optional/non-critical component in merged receive mode.
	//
	// If it fails, WAL receiving must continue. Errors are logged only.
	// This starts the cron-based backup daemon only when backup.cron is set.

	wg.Add(1)
	go func() {
		defer wg.Done()

		defer func() {
			if r := recover(); r != nil {
				loggr.Error("basebackup supervisor panicked",
					slog.Any("panic", r),
					slog.String("goroutine", "basebackup-supervisor"),
				)
			}
		}()

		if err := basebackupSupervisor.RunCron(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}

			loggr.Error("basebackup supervisor failed", slog.Any("err", err))
			return
		}
	}()

	//////////////////////////////////////////////////////////////////////
	// HTTP server.
	//
	// Non-critical. It should not cancel the main WAL receiver loop.
	//
	// This single server exposes both:
	//   - receive API
	//   - basebackup API

	wg.Add(1)
	go func() {
		defer wg.Done()

		defer func() {
			if r := recover(); r != nil {
				loggr.Error("http server panicked",
					slog.Any("panic", r),
					slog.String("goroutine", "http-server"),
				)
			}
		}()

		handlers := streamapi.Init(&streamapi.Opts{
			Receive: &receiveapi.Opts{
				PGRW:    pgrw,
				BaseDir: opts.ReceiveDirectory,
				Storage: walStor,
				Cfg:     cfg,
			},
			Backup: &backupapi.Opts{
				Supervisor: basebackupSupervisor,
				AppCtx:     ctx,
			},
			Cfg: cfg,
		})

		srv := api.NewHTTPServer(opts.ListenPort, handlers)

		if err := srv.Run(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}

			loggr.Error("http server failed", slog.Any("err", err))
		}
	}()

	//////////////////////////////////////////////////////////////////////
	// ArchiveSupervisor.

	wg.Add(1)
	go func() {
		defer wg.Done()

		defer func() {
			if r := recover(); r != nil {
				sendFatalErr(fmt.Errorf("wal archive supervisor panicked: %v", r))
			}
		}()

		u := receivesv.NewArchiveSupervisor(cfg, walStor, &receivesv.Opts{
			ReceiveDirectory: opts.ReceiveDirectory,
			PGRW:             pgrw,
		})

		if err := u.Run(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}

			sendFatalErr(fmt.Errorf("run wal archive supervisor: %w", err))
			return
		}
	}()

	//////////////////////////////////////////////////////////////////////
	// Wait for shutdown reason:
	//   - signal/context cancellation
	//   - fatal error from critical component

	var runErr error

	select {
	case <-ctx.Done():
		// Could be SIGINT/SIGTERM or cancellation caused by sendFatalErr().
		// Try to prefer real fatal error if one was sent.
		select {
		case runErr = <-fatalErrCh:
		default:
			runErr = ctx.Err()
		}

	case runErr = <-fatalErrCh:
		cancel()
	}

	loggr.Info("shutting down", slog.String("note", "waiting for goroutines..."))

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownTimeout):
		return fmt.Errorf("shutdown timeout: some goroutines did not stop")
	}

	// A fatal error may have appeared while goroutines were shutting down.
	select {
	case err := <-fatalErrCh:
		if err != nil {
			runErr = err
		}
	default:
	}

	if runErr == nil {
		loggr.Info("all components shut down cleanly")
		return nil
	}

	if errors.Is(runErr, context.Canceled) {
		loggr.Info("all components shut down cleanly", slog.String("reason", "shutdown requested"))
		return nil
	}

	loggr.Error("receive mode stopped with error", slog.Any("err", runErr))
	return runErr
}

func initMetrics(ctx context.Context, cfg *config.Config, loggr *slog.Logger) {
	if cfg.Metrics.Enable {
		loggr.Debug("init prom metrics")
		receivemetrics.InitPromMetrics(ctx)
		backupmetrics.InitPromMetrics(ctx)
	}
}

func checkStreamingConn(streamingConn *xlog.StreamingConn) error {
	// ensure required props
	if streamingConn.StartupInfo == nil {
		return fmt.Errorf("pgrw initialization: streamingConn.StartupInfo cannot be nil")
	}
	if streamingConn.StartupInfo.WalSegSz == 0 {
		return fmt.Errorf("pgrw initialization: streamingConn.WalSegSz cannot be 0")
	}
	return nil
}

func initPgrw(ctx context.Context, streamingConn *xlog.StreamingConn, opts *ReceiveModeOpts) (xlog.PgReceiveWal, error) {
	// ensure dirs
	if err := os.MkdirAll(opts.ReceiveDirectory, 0o750); err != nil {
		return nil, err
	}

	// construct pgrw
	return xlog.NewPgReceiver(ctx, streamingConn, &xlog.PgReceiveWalOpts{
		ReceiveDirectory: opts.ReceiveDirectory,
		Slot:             opts.Slot,
		NoLoop:           opts.NoLoop,
	}), nil
}

func initWalStorage(
	loggr *slog.Logger,
	opts *ReceiveModeOpts,
	walSegSzUint64 uint64,
) (*st.VariadicStorage, error) {
	loggr.Info("init storage")

	walSegSz, err := conv.Uint64ToInt64(walSegSzUint64)
	if err != nil {
		return nil, fmt.Errorf("convert wal segment size: %w", err)
	}

	loggr.Info("multipart chunk part (walSegSz)", slog.Int64("sz", walSegSz))

	stor, err := api.SetupStorage(&api.SetupStorageOpts{
		BaseDir:         opts.ReceiveDirectory,
		SubPath:         config.LocalFSStorageSubpath,
		S3PartSizeBytes: walSegSz,
	})
	if err != nil {
		return nil, err
	}

	return stor, nil
}

func initBasebackupStorage(baseDir string) (st.Storage, error) {
	return api.SetupStorage(&api.SetupStorageOpts{
		BaseDir: filepath.ToSlash(baseDir),
		SubPath: config.BaseBackupSubpath,
	})
}
