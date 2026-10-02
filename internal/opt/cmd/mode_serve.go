package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/signal"
	"sync"
	"syscall"

	"github.com/pgrwl/pgrwl/config"
	"github.com/pgrwl/pgrwl/internal/opt/api"
	"github.com/pgrwl/pgrwl/internal/opt/api/serveapi"
	st "github.com/pgrwl/pgrwl/internal/opt/shared/storecrypt"
)

type ServeModeOpts struct {
	Directory  string
	ListenPort int
}

func RunServeMode(opts *ServeModeOpts) error {
	loggr := slog.With("component", "serve-mode-runner")

	// setup context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, signalCancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer signalCancel()

	varicStor, err := api.SetupStorage(&api.SetupStorageOpts{
		BaseDir: opts.Directory,
		SubPath: config.LocalFSStorageSubpath,
	})
	if err != nil {
		return fmt.Errorf("setup storage: %w", err)
	}
	stor := st.NewChecksumStorage(varicStor)

	var wg sync.WaitGroup

	errCh := make(chan error, 1)

	sendErr := func(err error) {
		if err == nil {
			return
		}

		select {
		case errCh <- err:
			cancel()
		default:
			// Another error was already reported.
			cancel()
		}
	}

	// HTTP server
	wg.Add(1)
	go func() {
		defer wg.Done()

		defer func() {
			if r := recover(); r != nil {
				sendErr(fmt.Errorf("http server panicked: %v", r))
			}
		}()

		handlers := serveapi.Init(&serveapi.Opts{
			BaseDir: opts.Directory,
			Storage: stor,
		})

		srv := api.NewHTTPServer(opts.ListenPort, handlers)

		if err := srv.Run(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}

			sendErr(fmt.Errorf("run http server: %w", err))
			return
		}
	}()

	var runErr error

	select {
	case <-ctx.Done():
		// Could be SIGINT/SIGTERM or cancellation caused by sendErr().
		select {
		case runErr = <-errCh:
		default:
			runErr = ctx.Err()
		}

	case runErr = <-errCh:
		cancel()
	}

	loggr.Info("shutting down, waiting for goroutines...")

	wg.Wait()

	// A real server error may have been reported during shutdown.
	select {
	case err := <-errCh:
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

	loggr.Error("serve mode stopped with error", slog.Any("err", runErr))
	return runErr
}
