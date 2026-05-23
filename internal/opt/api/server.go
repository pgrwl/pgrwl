package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type HTTPServer struct {
	l      *slog.Logger
	port   int
	router http.Handler
}

func NewHTTPServer(port int, router http.Handler) *HTTPServer {
	return &HTTPServer{
		l:      slog.With("component", "http-server"),
		port:   port,
		router: router,
	}
}

func (s *HTTPServer) log() *slog.Logger {
	if s.l != nil {
		return s.l
	}
	return slog.With("component", "http-server")
}

func (s *HTTPServer) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           s.router,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	//nolint:gosec
	go func() {
		<-ctx.Done()
		// Context was cancelled, shut down the HTTP server gracefully
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			s.log().Error("http server shutdown error", slog.Any("err", err))
		} else {
			s.log().Info("http server shut down")
		}
	}()

	s.log().Info("starting http server", slog.String("addr", srv.Addr))

	// Start the server (blocking)
	err := srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err // real error
	}
	return nil
}
