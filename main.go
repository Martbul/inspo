package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib" // Blank import to register SQL driver
	"github.com/martbul/migrate"
	"github.com/martbul/server"
	"github.com/martbul/social"
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

		//case "check":
		// Parse any command line args to look up runtime path.
		//	config := server.NewConfig(tmpLogger)
		//	var runtimePath string
		//	flags := flag.NewFlagSet("check", flag.ExitOnError)
		//	flags.StringVar(&runtimePath, "runtime.path", filepath.Join(config.GetDataDir(), "modules"), "Path for the server to scan for lua and Go library files")
		//	if err := flags.Parse(os.Args[2:]); err != nil {

		//		tmpLogger.Fatal("Could not parse check flags.")
		//	}

		//	config.GetRuntime().Path = runtimePath
		//
		//			if err := server.CheckRuntime(tmpLogger, config, version); err != nil {
		//				// Errors are already logged in the function above.
		//				os.Exit(1)
		//			}
		//			return

		case "healthcheck":
			port := "7350"
			if len(os.Args) > 2 {
				port = os.Args[2]
			}

			resp, err := http.Get("http://localhost:" + port)
			if err != nil || resp.StatusCode != http.StatusOK {
				tmpLogger.Fatal("healthcheck failed")
			}

			tmpLogger.Info("healthcheck")
			return
		}

	}

	config := server.ParseArgs(tmpLogger, os.Args)
	logger, startupLogger := server.SetupLogging(tmpLogger, config)
	configWarnings := server.ValidateConfig(logger, config)

	startupLogger.Info("Inspo starting")
	startupLogger.Info("Node", zap.String("name", config.GetName()), zap.String("version", semver), zap.String("runtime", runtime.Version()), zap.Int("cpu", runtime.NumCPU()), zap.Int("proc", runtime.GOMAXPROCS(0)))
	startupLogger.Info("Data directory", zap.String("path", config.GetDataDir()))

	redactedAddresses := make([]string, 0, 1)
	for _, address := range config.GetDatabase().Addresses {
		rawURL := fmt.Sprintf("postgres://%s", address)
		parsedURL, err := url.Parse(rawURL)
		if err != nil {

			logger.Fatal("Bad connection URL", zap.Error(err))
		}
		redactedAddresses = append(redactedAddresses, strings.TrimPrefix(parsedURL.Redacted(), "postgres://"))
	}
	startupLogger.Info("Database connections", zap.Strings("dsns", redactedAddresses))

	db := server.DbConnect(ctx, startupLogger, config, false)

	// Check migration status and fail fast if the schema has diverged.
	conn, err := db.Conn(context.Background())
	if err != nil {

		logger.Fatal("Failed to acquire db conn for migration check", zap.Error(err))
	}

	if err = conn.Raw(func(driverConn any) error {
		pgxConn := driverConn.(*stdlib.Conn).Conn()
		migrate.Check(ctx, startupLogger, pgxConn)
		return nil
	}); err != nil {
		conn.Close()

		logger.Fatal("Failed to acquire pgx conn for migration check", zap.Error(err))
	}
	conn.Close()

	// Access to social provider integrations.
	socialClient := social.NewClient(logger, 5*time.Second, config.GetGoogleAuth().OAuthConfig)

	// Start up server components
	metrics := server.NewLocalMetrics(logger, startupLogger, db, config)
	sessionRegistry := server.NewLocalSessionRegistry(metrics)
	sessionCache := server.NewLocalSessionCache(config.GetSession().TokenExpirySec, config.GetSession().RefreshTokenExpirySec)
	consoleSessionCache := server.NewLocalSessionCache(config.GetConsole().TokenExpirySec, 0)
	loginAttemptCache := server.NewLocalLoginAttemptCache()
}
