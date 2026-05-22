package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// receiverController manages the lifecycle of the WAL receiver, archive
// supervisor, and basebackup supervisor as a restartable unit. The HTTP server
// and storage are not part of this unit and remain running across stop/start.
type receiverController struct {
	mu      sync.Mutex
	startMu sync.Mutex
	pgrw    xlog.PgReceiveWal
	rctx    context.Context
	cancel  context.CancelFunc

	outerCtx     context.Context
	opts         *ReceiveModeOpts
	cfg          *config.Config
	walStor      *st.VariadicStorage
	bbSupervisor backupsv.BaseBackupSupervisor
	wg           *sync.WaitGroup
	loggr        *slog.Logger
	sendFatalErr func(error)
}

func (r *receiverController) GetPgrw() xlog.PgReceiveWal {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pgrw
}

func (r *receiverController) Stop() {
	r.mu.Lock()
	cancel := r.cancel
	r.mu.Unlock()
	cancel()
}

func (r *receiverController) Start() error {
	if !r.startMu.TryLock() {
		return fmt.Errorf("receiver start already in progress")
	}
	defer r.startMu.Unlock()

	r.mu.Lock()
	rctx := r.rctx
	r.mu.Unlock()
	if rctx.Err() == nil {
		return fmt.Errorf("receiver is already running")
	}

	newPgrw, err := initPgrw(r.outerCtx, r.opts)
	if err != nil {
		return fmt.Errorf("init wal receiver: %w", err)
	}

	newRctx, newCancel := context.WithCancel(r.outerCtx)

	r.mu.Lock()
	r.pgrw = newPgrw
	r.rctx = newRctx
	r.cancel = newCancel
	r.mu.Unlock()

	r.launch(newRctx, newPgrw)
	return nil
}

func (r *receiverController) launch(rctx context.Context, pgrw xlog.PgReceiveWal) {
	//////////////////////////////////////////////////////////////////////
	// Main WAL receiver loop.
	//
	// Critical component. Any error or panic is fatal.

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		defer func() {
			if rec := recover(); rec != nil {
				r.sendFatalErr(fmt.Errorf("wal receiver panicked: %v", rec))
			}
		}()

		r.loggr.Info("wal-receiver started")

		if err := pgrw.Run(rctx); err != nil {
			if errors.Is(err, context.Canceled) {
				r.loggr.Info("wal-receiver stopped", slog.String("reason", "context canceled"))
				return
			}

			r.sendFatalErr(fmt.Errorf("streaming failed: %w", err))
			return
		}

		r.loggr.Info("wal-receiver stopped")
	}()

	//////////////////////////////////////////////////////////////////////
	// Basebackup supervisor.
	//
	// Optional/non-critical component in merged receive mode.
	//
	// If it fails, WAL receiving must continue. Errors are logged only.
	// This starts the cron-based backup daemon only when backup.cron is set.

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		defer func() {
			if rec := recover(); rec != nil {
				r.loggr.Error("basebackup supervisor panicked",
					slog.Any("panic", rec),
					slog.String("goroutine", "basebackup-supervisor"),
				)
			}
		}()

		if err := r.bbSupervisor.RunCron(rctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}

			r.loggr.Error("basebackup supervisor failed", slog.Any("err", err))
		}
	}()

	//////////////////////////////////////////////////////////////////////
	// ArchiveSupervisor.

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		defer func() {
			if rec := recover(); rec != nil {
				r.sendFatalErr(fmt.Errorf("wal archive supervisor panicked: %v", rec))
			}
		}()

		u := receivesv.NewArchiveSupervisor(r.cfg, r.walStor, &receivesv.Opts{
			ReceiveDirectory: r.opts.ReceiveDirectory,
			PGRW:             pgrw,
		})

		if err := u.Run(rctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}

			r.sendFatalErr(fmt.Errorf("run wal archive supervisor: %w", err))
		}
	}()
}

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

	receiverCtx, cancelReceiver := context.WithCancel(ctx)
	defer cancelReceiver()

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

	pgrw, err := initPgrw(ctx, opts)
	if err != nil {
		return fmt.Errorf("init wal receiver: %w", err)
	}

	//////////////////////////////////////////////////////////////////////
	// Init receive/archive dependencies before starting goroutines.

	walStor, err := initWalStorage(loggr, opts, pgrw)
	if err != nil {
		return fmt.Errorf("init wal storage: %w", err)
	}

	basebackupStor, err := initBasebackupStorage(cfg.Main.Directory)
	if err != nil {
		return fmt.Errorf("init basebackup storage: %w", err)
	}

	basebackupSupervisor, err := backupsv.NewBaseBackupSupervisor(&backupsv.BackupSupervisorOpts{
		Directory:      opts.ReceiveDirectory,
		WalSegSz:       pgrw.WalSegSz(),
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

	rc := &receiverController{
		pgrw:         pgrw,
		rctx:         receiverCtx,
		cancel:       cancelReceiver,
		outerCtx:     ctx,
		opts:         opts,
		cfg:          cfg,
		walStor:      walStor,
		bbSupervisor: basebackupSupervisor,
		wg:           &wg,
		loggr:        loggr,
		sendFatalErr: sendFatalErr,
	}

	rc.launch(receiverCtx, pgrw)

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
			if rec := recover(); rec != nil {
				loggr.Error("http server panicked",
					slog.Any("panic", rec),
					slog.String("goroutine", "http-server"),
				)
			}
		}()

		handlers := streamapi.Init(&streamapi.Opts{
			Receive: &receiveapi.Opts{
				GetPgrw:       rc.GetPgrw,
				BaseDir:       opts.ReceiveDirectory,
				Storage:       walStor,
				Cfg:           cfg,
				StopReceiver:  rc.Stop,
				StartReceiver: rc.Start,
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

	loggr.Info("shutting down, waiting for goroutines...")

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

func initPgrw(ctx context.Context, opts *ReceiveModeOpts) (xlog.PgReceiveWal, error) {
	pgrw, err := xlog.NewPgReceiver(ctx, &xlog.PgReceiveWalOpts{
		ReceiveDirectory: opts.ReceiveDirectory,
		Slot:             opts.Slot,
		NoLoop:           opts.NoLoop,
	})
	if err != nil {
		return nil, err
	}

	return pgrw, nil
}

func initWalStorage(
	loggr *slog.Logger,
	opts *ReceiveModeOpts,
	pgrw xlog.PgReceiveWal,
) (*st.VariadicStorage, error) {
	loggr.Info("init storage")

	walSegSz, err := conv.Uint64ToInt64(pgrw.WalSegSz())
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
