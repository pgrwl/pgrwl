package xlog

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgconn"
)

type StreamingConn struct {
	ConnStrRepl string
	// NOTE: connection will be closed by general utility func
	Conn        *pgconn.PgConn
	StartupInfo *StartupInfo
}

func InitStreamingConn(ctx context.Context, slot string) (*StreamingConn, error) {
	loggr := slog.With(slog.String("component", "startup-info"))
	loggr.Info("open connection")

	connStrRepl := fmt.Sprintf("application_name=%s replication=yes", slot)
	conn, err := pgconn.Connect(ctx, connStrRepl)
	if err != nil {
		loggr.Error("cannot establish connection",
			slog.Any("err", err),
		)
		return nil, err
	}
	startupInfo, err := GetStartupInfo(conn)
	if err != nil {
		loggr.Error("cannot get startup info",
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
