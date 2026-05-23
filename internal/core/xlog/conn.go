package xlog

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

type StreamingConn struct {
	ConnStrRepl string
	// NOTE: connection should be closed by CloseReplicationConn()
	Conn        *pgconn.PgConn
	StartupInfo *StartupInfo
}

func OpenReplicationConn(ctx context.Context, loggr *slog.Logger, applicationName string) (*StreamingConn, error) {
	l := loggr.With(slog.String("fn", "OpenReplicationConn"))
	l.Info("open connection")

	connStrRepl := fmt.Sprintf("application_name=%s replication=yes", applicationName)
	conn, err := pgconn.Connect(ctx, connStrRepl)
	if err != nil {
		return nil, err
	}

	startupInfo, err := GetStartupInfo(conn)
	if err != nil {
		l.Error("cannot get startup info",
			slog.Any("err", err),
		)
		return nil, err
	}

	return &StreamingConn{
		ConnStrRepl: connStrRepl,
		Conn:        conn,
		StartupInfo: startupInfo,
	}, nil
}

// CloseReplicationConn - utility function that closes connection (if this conn isn't nil and wasn't already closed),
// with logging and shutdown timeout.
func CloseReplicationConn(conn *pgconn.PgConn, loggr *slog.Logger) {
	if conn == nil {
		loggr.Info("connection is nil")
		return
	}
	if conn.IsClosed() {
		loggr.Info("connection is already closed")
		return
	}

	const shutdownTimeout = 30 * time.Second

	closeCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	err := conn.Close(closeCtx)

	if err != nil {
		loggr.Warn("closing connection", slog.Any("err", err))
	} else {
		loggr.Info("connection successfully closed")
	}
}
