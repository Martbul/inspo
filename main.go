package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/martbul/server"
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
		}
	}
}
