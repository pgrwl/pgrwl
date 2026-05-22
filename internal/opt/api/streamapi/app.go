package streamapi

import (
	"log/slog"
	"net/http"
	"net/http/pprof"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/pgrwl/pgrwl/internal/opt/api/streamapi/backupapi"
	"github.com/pgrwl/pgrwl/internal/opt/api/streamapi/receiveapi"

	"github.com/pgrwl/pgrwl/config"
	"github.com/pgrwl/pgrwl/internal/opt/api/middleware"
	"golang.org/x/time/rate"
)

type Opts struct {
	Receive *receiveapi.Opts
	Backup  *backupapi.Opts
	Cfg     *config.Config
}

func Init(o *Opts) http.Handler {
	l := slog.With("component", "stream-api")

	// init services/handlers
	backupHandler := backupapi.NewHandler(backupapi.NewService(o.Backup))
	receiveHandler := receiveapi.NewHandler(receiveapi.NewService(o.Receive))

	// init middlewares
	loggingMiddleware := middleware.LoggingMiddleware{
		Logger: l,
	}
	rateLimitMiddleware := middleware.RateLimiterMiddleware{Limiter: rate.NewLimiter(5, 10)}

	// Build middleware chain
	secureChain := middleware.Chain(
		middleware.SafeHandlerMiddleware,
		middleware.Cors,
		loggingMiddleware.Middleware,
		rateLimitMiddleware.Middleware,
	)

	// Init handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// mount routes
	mux.Handle("POST /api/v1/basebackup", secureChain(http.HandlerFunc(backupHandler.Start)))
	mux.Handle("GET /api/v1/basebackup/status", secureChain(http.HandlerFunc(backupHandler.Status)))
	mux.Handle("GET /api/v1/status", secureChain(http.HandlerFunc(receiveHandler.StatusHandler)))
	mux.Handle("GET /api/v1/brief-config", secureChain(http.HandlerFunc(receiveHandler.BriefConfig)))
	mux.Handle("GET /api/v1/redacted-config", secureChain(http.HandlerFunc(receiveHandler.FullRedactedConfig)))
	mux.Handle("GET /api/v1/wals", secureChain(http.HandlerFunc(receiveHandler.WalsHandler)))
	mux.Handle("GET /api/v1/backups", secureChain(http.HandlerFunc(receiveHandler.BackupsHandler)))
	mux.Handle("GET /api/v1/wal/{filename}", secureChain(http.HandlerFunc(receiveHandler.WalFileDownloadHandler)))
	mux.Handle("POST /api/v1/receiver/stop", secureChain(http.HandlerFunc(receiveHandler.StopReceiverHandler)))
	mux.Handle("POST /api/v1/receiver/start", secureChain(http.HandlerFunc(receiveHandler.StartReceiverHandler)))

	initOptionalHandlers(o.Cfg, mux, l)
	return mux
}

func initOptionalHandlers(cfg *config.Config, mux *http.ServeMux, l *slog.Logger) {
	if cfg.Metrics.Enable {
		l.Debug("enable metric endpoints")
		mux.Handle("/metrics", promhttp.Handler())
	}

	if cfg.DevConfig.Pprof.Enable {
		l.Debug("enable pprof endpoints")
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
}
