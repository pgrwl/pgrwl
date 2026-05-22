package connx

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const shutdownTimeout = 30 * time.Second

func CloseConn(conn *pgconn.PgConn, loggr *slog.Logger) {
	if conn == nil {
		loggr.Info("connection is nil")
		return
	}
	if conn.IsClosed() {
		loggr.Info("connection is already closed")
		return
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	err := conn.Close(closeCtx)

	if err != nil {
		loggr.Warn("closing connection", slog.Any("err", err))
	} else {
		loggr.Info("connection successfully closed")
	}
}
