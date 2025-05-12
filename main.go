package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib" // Blank import to register SQL driver
	"github.com/martbul/server"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const cookieFliemane = ".cookie"

var (
	version  string = "1.0.0"
	commitID string = "dev"
)

func main() {
	defer os.Exit(0)

	semver := fmt.Sprintf("%s+%s", version, commitID)

	http.DefaultClient.Timeout = 1500 * time.Millisecond

	tmpLogger := server.NewJSONLogger(os.Stdout, zapcore.InfoLevel, server.JSONFormat)

	ctx, ctxCancelFn := context.WithCancel(context.Background())

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println(semver)
			return

		case "migrate":
			config := server.ParseArgs(tmpLogger, os.Args[2:])
			server.ValideateConfigDatabase(tmpLogger, config)
			db := server.DbConnect(ctx, tmpLogger, config, true)
			defer db.Close()

			conn, err := db.Conn(ctx)
			if err != nil {
				tmpLogger.Fatal("Failed to acquire db conn for migration", zap.Error(err))
			}

			if err = conn.Raw(func(driverConn any) error {
				pgxConn := driverConn.(*stdlib.Conn).Conn()
				migrate.RunCmd(ctx, tmpLogger, pgxConn, os.Args[2], config.GetLimit(), config.GetLogger().Format)

				return nil
			}); err != nil {
				conn.Close()
				tmpLogger.Fatal("Failed to acquire pgx conn for migration", zap.Error(err))
			}
			conn.Close()
			return
		}
	}
}
