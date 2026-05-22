package xlog

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgconn"
)

type StreamingConn struct {
	ConnStrRepl string
	Conn        *pgconn.PgConn
	StartupInfo *StartupInfo
}

func InitStreamingConn(ctx context.Context, slot string) (*StreamingConn, error) {
	connStrRepl := fmt.Sprintf("application_name=%s replication=yes", slot)
	conn, err := pgconn.Connect(ctx, connStrRepl)
	if err != nil {
		slog.Error("cannot establish connection",
			slog.String("component", "pgreceivewal"),
			slog.Any("err", err),
		)
		return nil, err
	}
	startupInfo, err := GetStartupInfo(conn)
	if err != nil {
		return nil, err
	}

	return &StreamingConn{
		ConnStrRepl: connStrRepl,
		Conn:        conn,
		StartupInfo: startupInfo,
	}, nil
}

func (c *StreamingConn) Close(ctx context.Context) error {
	if c.Conn == nil {
		return nil
	}
	err := c.Conn.Close(ctx)
	c.Conn = nil
	return err
}
