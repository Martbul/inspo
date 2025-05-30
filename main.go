package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib" // Blank import to register SQL driver
	"github.com/martbul/inspo/console"
	"github.com/martbul/inspo/migrate"
	"github.com/martbul/inspo/se"
	"github.com/martbul/inspo/server"
	"github.com/martbul/inspo/social"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/encoding/protojson"
)

const cookieFilename = ".cookie"

var (
	version  string = "1.0.0"
	commitID string = "dev"

	// Shared utility components.
	jsonpbMarshaler = &protojson.MarshalOptions{
		UseEnumNumbers:  true,
		EmitUnpopulated: false,
		Indent:          "",
		UseProtoNames:   true,
	}
	jsonpbUnmarshaler = &protojson.UnmarshalOptions{
		DiscardUnknown: false,
	}
)

func main() {
	defer os.Exit(0)

	fmt.Println("starting the project!!!!")
	semver := fmt.Sprintf("%s+%s", version, commitID)

	//INFO: Setting maximum time for a request of a 1.5 sec(the client will "give up after 1.5sec")
	http.DefaultClient.Timeout = 1500 * time.Millisecond

	tmpLogger := server.NewJSONLogger(os.Stdout, zapcore.InfoLevel, server.JSONFormat)

	ctx, ctxCancelFn := context.WithCancel(context.Background())

	fmt.Println("osArgs", os.Args[0])
	fmt.Println("osArgsLen", len(os.Args))
	//INFO: os.Args[0] is always the name or path of the running executable.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println("case version")
			fmt.Println(semver)
			return

		case "migrate":
			fmt.Println("case migrate")
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

		case "check":
			// Parse any command line args to look up runtime path.
			// Use full config structure even if not all of its options are available in this command.
			config := server.NewConfig(tmpLogger)
			var runtimePath string
			flags := flag.NewFlagSet("check", flag.ExitOnError)
			flags.StringVar(&runtimePath, "runtime.path", filepath.Join(config.GetDataDir(), "modules"), "Path for the server to scan for Lua and Go library files.")
			if err := flags.Parse(os.Args[2:]); err != nil {
				tmpLogger.Fatal("Could not parse check flags.")
			}
			config.GetRuntime().Path = runtimePath

			if err := server.CheckRuntime(tmpLogger, config, version); err != nil {
				// Errors are already logged in the function above.
				os.Exit(1)
			}
			return
		case "healthcheck":
			fmt.Println("case healtcheck")
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
	fmt.Println(config.GetConsole().Username)
	logger, startupLogger := server.SetupLogging(tmpLogger, config)
	configWarnings := server.ValidateConfig(logger, config)

	startupLogger.Info("Inspo starting")
	startupLogger.Info("Node", zap.String("name", config.GetName()), zap.String("version", semver), zap.String("runtime", runtime.Version()), zap.Int("cpu", runtime.NumCPU()), zap.Int("proc", runtime.GOMAXPROCS(0)))
	startupLogger.Info("Data directory", zap.String("path", config.GetDataDir()))

	redactedAddresses := make([]string, 0, 1)
	for _, address := range config.GetDatabase().Addresses {
		fmt.Println(address)
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

		fmt.Println(err)
		logger.Fatal("Failed to acquire db conn for migration check", zap.Error(err))
	}

	if err = conn.Raw(func(driverConn any) error {

		fmt.Println("err2")
		pgxConn := driverConn.(*stdlib.Conn).Conn()
		fmt.Println("pgxConn", pgxConn)
		migrate.Check(ctx, startupLogger, pgxConn)
		return nil
	}); err != nil {
		conn.Close()

		logger.Fatal("Failed to acquire pgx conn for migration check", zap.Error(err))
	}
	conn.Close()

	fmt.Println("here3")
	// Access to social provider integrations.
	socialClient := social.NewClient(logger, 5*time.Second, config.GetGoogleAuth().OAuthConfig)

	// Start up server components
	metrics := server.NewLocalMetrics(logger, startupLogger, db, config)
	sessionRegistry := server.NewLocalSessionRegistry(metrics)
	sessionCache := server.NewLocalSessionCache(config.GetSession().TokenExpirySec, config.GetSession().RefreshTokenExpirySec)
	consoleSessionCache := server.NewLocalSessionCache(config.GetConsole().TokenExpirySec, 0)
	loginAttemptCache := server.NewLocalLoginAttemptCache()
	statusRegistry := server.NewLocalStatusRegistry(logger, config, sessionRegistry, jsonpbMarshaler)
	tracker := server.StartLocalTracker(logger, config, sessionRegistry, statusRegistry, metrics, jsonpbMarshaler)
	router := server.NewLocalMessageRouter(sessionRegistry, tracker, jsonpbMarshaler)
	leaderboardCache := server.NewLocalLeaderboardCache(ctx, logger, startupLogger, db)
	leaderboardRankCache := server.NewLocalLeaderboardRankCache(ctx, startupLogger, db, config.GetLeaderboard(), leaderboardCache)
	leaderboardScheduler := server.NewLocalLeaderboardScheduler(logger, db, config, leaderboardCache, leaderboardRankCache)
	googleRefundScheduler := server.NewGoogleRefundScheduler(logger, db, config)
	matchRegistry := server.NewLocalMatchRegistry(logger, startupLogger, config, sessionRegistry, tracker, router, metrics, config.GetName())
	tracker.SetMatchJoinListener(matchRegistry.Join)
	tracker.SetMatchLeaveListener(matchRegistry.Leave)
	streamManager := server.NewLocalStreamManager(config, sessionRegistry, tracker)
	fmCallbackHandler := server.NewLocalFmCallbackHandler(config)

	storageIndex, err := server.NewLocalStorageIndex(logger, db, config.GetStorage(), metrics)

	if err != nil {
		logger.Fatal("Failed to initialize storage index", zap.Error(err))
	}
	runtime, runtimeInfo, err := server.NewRuntime(ctx, logger, startupLogger, db, jsonpbMarshaler, jsonpbUnmarshaler, config, version, socialClient, leaderboardCache, leaderboardRankCache, leaderboardScheduler, sessionRegistry, sessionCache, statusRegistry, matchRegistry, tracker, metrics, streamManager, router, storageIndex, fmCallbackHandler)
	if err != nil {
		startupLogger.Fatal("Failed initializing runtime modules", zap.Error(err))
	}
	matchmaker := server.NewLocalMatchmaker(logger, startupLogger, config, router, metrics, runtime)
	partyRegistry := server.NewLocalPartyRegistry(logger, config, matchmaker, tracker, streamManager, router, config.GetName())
	tracker.SetPartyJoinListener(partyRegistry.Join)
	tracker.SetPartyLeaveListener(partyRegistry.Leave)

	storageIndex.RegisterFilters(runtime)
	go func() {
		if err = storageIndex.Load(ctx); err != nil {
			logger.Error("Failed to load storage index entries from database", zap.Error(err))
		}
	}()

	leaderboardScheduler.Start(runtime)
	googleRefundScheduler.Start(runtime)

	pipeline := server.NewPipeline(logger, config, db, jsonpbMarshaler, jsonpbUnmarshaler, sessionRegistry, statusRegistry, matchRegistry, partyRegistry, matchmaker, tracker, router, runtime)
	statusHandler := server.NewLocalStatusHandler(logger, sessionRegistry, matchRegistry, tracker, metrics, config.GetName())

	telemetryEnabled := len(os.Getenv("NAKAMA_TELEMETRY")) < 1
	console.UIFS.Nt = !telemetryEnabled
	cookie := newOrLoadCookie(telemetryEnabled, config)

	apiServer := server.StartApiServer(logger, startupLogger, db, jsonpbMarshaler, jsonpbUnmarshaler, config, version, socialClient, storageIndex, leaderboardCache, leaderboardRankCache, sessionRegistry, sessionCache, statusRegistry, matchRegistry, matchmaker, tracker, router, streamManager, metrics, pipeline, runtime)
	consoleServer := server.StartConsoleServer(logger, startupLogger, db, config, tracker, router, streamManager, metrics, sessionRegistry, sessionCache, consoleSessionCache, loginAttemptCache, statusRegistry, statusHandler, runtimeInfo, matchRegistry, configWarnings, semver, leaderboardCache, leaderboardRankCache, leaderboardScheduler, storageIndex, apiServer, runtime, cookie)

	if telemetryEnabled {
		const telemetryKey = "YU1bIKUhjQA9WC0O6ouIRIWTaPlJ5kFs"
		_ = se.Start(telemetryKey, cookie, semver, "nakama")
		defer func() {
			_ = se.End(telemetryKey, cookie)
		}()
	}

	// Respect OS stop signals.
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	startupLogger.Info("Startup done")

	// Wait for a termination signal.
	<-c

	server.HandleShutdown(ctx, logger, matchRegistry, config.GetShutdownGraceSec(), runtime.Shutdown(), c)

	// Signal cancellation to the global runtime context.
	ctxCancelFn()

	// Gracefully stop remaining server components.
	apiServer.Stop()
	consoleServer.Stop()
	matchmaker.Stop()
	leaderboardScheduler.Stop()
	googleRefundScheduler.Stop()
	tracker.Stop()
	statusRegistry.Stop()
	sessionCache.Stop()
	sessionRegistry.Stop()
	metrics.Stop(logger)
	loginAttemptCache.Stop()

	startupLogger.Info("Shutdown complete")
}

func newOrLoadCookie(enabled bool, config server.Config) string {
	if !enabled {
		return ""
	}
	filePath := filepath.FromSlash(config.GetDataDir() + "/" + cookieFilename)
	b, err := os.ReadFile(filePath)
	cookie := uuid.FromBytesOrNil(b)
	if err != nil || cookie == uuid.Nil {
		cookie = uuid.Must(uuid.NewV4())
		_ = os.WriteFile(filePath, cookie.Bytes(), 0o644)
	}
	return cookie.String()

}
