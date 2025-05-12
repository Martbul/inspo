package server

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/martbul/flags"
	"github.com/martbul/inspo-common/runtime"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"
)

type config struct {
	Name             string             `yaml:"name" json:"name" usage:"Inspo server’s node name - must be unique."`
	Config           []string           `yaml:"config" json:"config" usage:"The absolute file path to configuration YAML file."`
	ShutdownGraceSec int                `yaml:"shutdown_grace_sec" json:"shutdown_grace_sec" usage:"Maximum number of seconds to wait for the server to complete work before shutting down. Default is 0 seconds. If 0 the server will shut down immediately when it receives a termination signal."`
	DataDir          string             `yaml:"data_dir" json:"data_dir" usage:"An absolute path to a writeable folder where Inspo will store its data."`
	Logger           *LoggerConfig      `yaml:"logger" json:"logger" usage:"Logger levels and output."`
	Metrics          *MetricsConfig     `yaml:"metrics" json:"metrics" usage:"Metrics settings."`
	Session          *SessionConfig     `yaml:"session" json:"session" usage:"Session authentication settings."`
	Socket           *SocketConfig      `yaml:"socket" json:"socket" usage:"Socket configuration."`
	Database         *DatabaseConfig    `yaml:"database" json:"database" usage:"Database connection settings."`
	Social           *SocialConfig      `yaml:"social" json:"social" usage:"Properties for social provider integrations."`
	Runtime          *RuntimeConfig     `yaml:"runtime" json:"runtime" usage:"Script Runtime properties."`
	Match            *MatchConfig       `yaml:"match" json:"match" usage:"Authoritative realtime match properties."`
	Tracker          *TrackerConfig     `yaml:"tracker" json:"tracker" usage:"Presence tracker properties."`
	Console          *ConsoleConfig     `yaml:"console" json:"console" usage:"Console settings."`
	Leaderboard      *LeaderboardConfig `yaml:"leaderboard" json:"leaderboard" usage:"Leaderboard settings."`
	Matchmaker       *MatchmakerConfig  `yaml:"matchmaker" json:"matchmaker" usage:"Matchmaker settings."`
	IAP              *IAPConfig         `yaml:"iap" json:"iap" usage:"In-App Purchase settings."`
	GoogleAuth       *GoogleAuthConfig  `yaml:"google_auth" json:"google_auth" usage:"Google's auth settings."`
	Satori           *SatoriConfig      `yaml:"satori" json:"satori" usage:"Satori integration settings."`
	Storage          *StorageConfig     `yaml:"storage" json:"storage" usage:"Storage settings."`
	MFA              *MFAConfig         `yaml:"mfa" json:"mfa" usage:"MFA settings."`
	Limit            int                `json:"-"` // Only used for migrate command.
}

// Config interface is the inspo core configuration.
type Config interface {
	GetName() string
	GetDataDir() string
	GetShutdownGraceSec() int
	GetLogger() *LoggerConfig
	GetMetrics() *MetricsConfig
	GetSession() *SessionConfig
	GetSocket() *SocketConfig
	GetDatabase() *DatabaseConfig
	GetSocial() *SocialConfig
	GetRuntime() *RuntimeConfig
	GetMatch() *MatchConfig
	GetTracker() *TrackerConfig
	GetConsole() *ConsoleConfig
	GetLeaderboard() *LeaderboardConfig
	GetMatchmaker() *MatchmakerConfig
	GetIAP() *IAPConfig
	GetGoogleAuth() *GoogleAuthConfig
	GetSatori() *SatoriConfig
	GetStorage() *StorageConfig
	GetMFA() *MFAConfig
	GetLimit() int

	Clone() (Config, error)
	GetRuntimeConfig() (runtime.Config, error)
}

func ParseArgs(logger *zap.Logger, args []string) Config {
	configFilePath := NewConfig(logger)
	configFileFlagSet := flag.NewFlagSet("inspo", flag.ExitOnError)

	//INFO: used ti bind config values from yaml with flags
	configFileFlagMarker := flags.NewFlagMakerFlagSet(&flags.FlagMakingOptions{
		UseLowerCase: true,
		Flatten:      false,
		TagName:      "yaml",
		TagUsage:     "usage",
	}, configFileFlagSet)

	if _, err := configFileFlagMarker.ParseArgs(configFilePath, args[1:]); err != nil {

		logger.Fatal("Could not parse command line arguments", zap.Error(err))
	}

	// Parse config file if path is set.
	mainConfig := NewConfig(logger)
	runtimeEnvironment := mainConfig.GetRuntime().Environment

	for _, cfg := range configFilePath.Config {
		data, err := os.ReadFile(cfg)

		if err != nil {
			logger.Fatal("Could not read config file", zap.String("path", cfg), zap.Error(err))
		}

		err = yaml.Unmarshal(data, mainConfig)
		if err != nil {
			logger.Fatal("Could not parse config file", zap.String("path", cfg), zap.Error(err))
		}

		// Convert and preserve the runtime environment key-value pairs.
		runtimeEnvironment = convertRuntimeEnv(logger, runtimeEnvironment, mainConfig.GetRuntime().Env)
		logger.Info("Successfully loaded config file", zap.String("path", cfg))
	}
	// Preserve the config file path arguments.
	mainConfig.Config = configFilePath.Config

	// Override config with those passed from command-line.
	mainFlagSet := flag.NewFlagSet("nakama", flag.ExitOnError)
	mainFlagMaker := flags.NewFlagMakerFlagSet(&flags.FlagMakingOptions{
		UseLowerCase: true,
		Flatten:      false,
		TagName:      "yaml",
		TagUsage:     "usage",
	}, mainFlagSet)

	if _, err := mainFlagMaker.ParseArgs(mainConfig, args[1:]); err != nil {
		logger.Fatal("Could not parse command line arguments", zap.Error(err))
	}

	mainConfig.GetRuntime().Environment = convertRuntimeEnv(logger, runtimeEnvironment, mainConfig.GetRuntime().Env)
	mainConfig.GetRuntime().Env = make([]string, 0, len(mainConfig.GetRuntime().Environment))

	for k, v := range mainConfig.GetRuntime().Environment {

		mainConfig.GetRuntime().Env = append(mainConfig.GetRuntime().Env, fmt.Sprintf("%v=%v", k, v))
	}

	sort.Strings(mainConfig.GetRuntime().Env)

	if mainConfig.GetGoogleAuth() != nil && mainConfig.GetGoogleAuth().CredentialsJSON != "" {

		cnf, err := google.ConfigFromJSON([]byte(mainConfig.GetGoogleAuth().CredentialsJSON))
		if err != nil {
			logger.Fatal("Failed to parse Google's credentials JSON", zap.Error(err))
		}

		mainConfig.GetGoogleAuth().OAuthConfig = cnf
	}
	return mainConfig
}

func convertRuntimeEnv(logger *zap.Logger, existingEnv map[string]string, mergeEnv []string) map[string]string {
	envMap := make(map[string]string, len(existingEnv))
	for k, v := range existingEnv {
		envMap[k] = v
	}

	for _, e := range mergeEnv {
		if !strings.Contains(e, "=") {
			logger.Fatal("Invalid runtime environment value.", zap.String("value", e))
		}

		kv := strings.SplitN(e, "=", 2) // the value can contain the character "=" many times over.
		if len(kv) == 1 {
			envMap[kv[0]] = ""
		} else if len(kv) == 2 {
			envMap[kv[0]] = kv[1]
		}
	}
	return envMap
}

func ValideateConfigDatabase(logger *zap.Logger, c Config) {
	if len(c.GetDatabase().Addresses) < 1 {

		logger.Fatal("At least one database address must be specified", zap.Strings("database.address", c.GetDatabase().Addresses))
	}

	for _, address := range c.GetDatabase().Addresses {

		rawURL := fmt.Sprintf("postgresql://%s", address)

		if _, err := url.Parse(rawURL); err != nil {

			logger.Fatal("Bad database connection URL", zap.String("database.address", address), zap.Error(err))

		}
	}

	if c.GetDatabase().DnsScanIntervalSec < 1 {

		logger.Fatal("Database DNS scan interval seconds must be > 0", zap.Int("database.dns_scan_interval_sec", c.GetDatabase().DnsScanIntervalSec))
	}
}

func NewConfig(logger *zap.Logger) *config {
	currentDir, err := os.Getwd()
	logger.Debug("current working directory: " + currentDir)
	if err != nil {

		logger.Fatal("Error getting current working directory.", zap.Error(err))
	}

	return &config{
		Name:             "inspo",
		DataDir:          filepath.Join(currentDir, "data"),
		ShutdownGraceSec: 0,
		Logger:           NewLoggerConfig(),
		Metrics:          NewMetricsConfig(),
		Session:          NewSessionConfig(),
		Socket:           NewSocketConfig(),
		Database:         NewDatabaseConfig(),
		Social:           NewSocialConfig(),
		Runtime:          NewRuntimeConfig(),
		Match:            NewMatchConfig(),
		Tracker:          NewTrackerConfig(),
		Console:          NewConsoleConfig(),
		Leaderboard:      NewLeaderboardConfig(),
		Matchmaker:       NewMatchmakerConfig(),
		IAP:              NewIAPConfig(),
		GoogleAuth:       NewGoogleAuthConfig(),
		Satori:           NewSatoriConfig(),
		Storage:          NewStorageConfig(),
		MFA:              NewMFAConfig(),
		Limit:            -1,
	}
}

func (c *config) Clone() (Config, error) {
	configSocket, err := c.Socket.Clone()
	if err != nil {
		return nil, err
	}

	nc := &config{
		Name:             c.Name,
		DataDir:          c.DataDir,
		ShutdownGraceSec: c.ShutdownGraceSec,
		Logger:           c.Logger.Clone(),
		Metrics:          c.Metrics.Clone(),
		Session:          c.Session.Clone(),
		Socket:           configSocket,
		Database:         c.Database.Clone(),
		Social:           c.Social.Clone(),
		Runtime:          c.Runtime.Clone(),
		Match:            c.Match.Clone(),
		Tracker:          c.Tracker.Clone(),
		Console:          c.Console.Clone(),
		Leaderboard:      c.Leaderboard.Clone(),
		Matchmaker:       c.Matchmaker.Clone(),
		IAP:              c.IAP.Clone(),
		Satori:           c.Satori.Clone(),
		GoogleAuth:       c.GoogleAuth.Clone(),
		Storage:          c.Storage.Clone(),
		MFA:              c.MFA.Clone(),
		Limit:            c.Limit,
	}

	return nc, nil
}

func (c *config) GetName() string {
	return c.Name
}

func (c *config) GetDataDir() string {
	return c.DataDir
}

func (c *config) GetShutdownGraceSec() int {
	return c.ShutdownGraceSec
}

func (c *config) GetLogger() *LoggerConfig {
	return c.Logger
}

func (c *config) GetMetrics() *MetricsConfig {
	return c.Metrics
}

func (c *config) GetSession() *SessionConfig {
	return c.Session
}

func (c *config) GetSocket() *SocketConfig {
	return c.Socket
}

func (c *config) GetDatabase() *DatabaseConfig {
	return c.Database
}

func (c *config) GetSocial() *SocialConfig {
	return c.Social
}

func (c *config) GetRuntime() *RuntimeConfig {
	return c.Runtime
}

func (c *config) GetMatch() *MatchConfig {
	return c.Match
}

func (c *config) GetTracker() *TrackerConfig {
	return c.Tracker
}

func (c *config) GetConsole() *ConsoleConfig {
	return c.Console
}

func (c *config) GetLeaderboard() *LeaderboardConfig {
	return c.Leaderboard
}

func (c *config) GetMatchmaker() *MatchmakerConfig {
	return c.Matchmaker
}

func (c *config) GetIAP() *IAPConfig {
	return c.IAP
}

func (c *config) GetGoogleAuth() *GoogleAuthConfig {
	return c.GoogleAuth
}

func (c *config) GetSatori() *SatoriConfig {
	return c.Satori
}

func (c *config) GetStorage() *StorageConfig {
	return c.Storage
}

func (c *config) GetMFA() *MFAConfig {
	return c.MFA
}

func (c *config) GetRuntimeConfig() (runtime.Config, error) {
	clone, err := c.Clone()
	if err != nil {
		return nil, err
	}

	var lc runtime.LoggerConfig = clone.GetLogger()
	var sc runtime.SessionConfig = clone.GetSession()
	var soc runtime.SocketConfig = clone.GetSocket()
	var socialConf runtime.SocialConfig = clone.GetSocial()
	var rc runtime.RuntimeConfig = clone.GetRuntime()
	var iap runtime.IAPConfig = clone.GetIAP()
	var gauth runtime.GoogleAuthConfig = clone.GetGoogleAuth()
	var satori runtime.SatoriConfig = clone.GetSatori()

	cn := &RuntimeConfigClone{
		Name:          clone.GetName(),
		ShutdownGrace: clone.GetShutdownGraceSec(),
		Logger:        lc,
		Session:       sc,
		Socket:        soc,
		Social:        socialConf,
		Runtime:       rc,
		Iap:           iap,
		GoogleAuth:    gauth,
		Satori:        satori,
	}

	return cn, nil
}

func (c *config) GetLimit() int {
	return c.Limit
}

var _ runtime.LoggerConfig = &LoggerConfig{}

type LoggerConfig struct {
	Level    string `yaml:"level" json:"level" usage:"Log level to set. Valid values are 'debug', 'info', 'warn', 'error'. Default 'info'."`
	Stdout   bool   `yaml:"stdout" json:"stdout" usage:"Log to standard console output (as well as to a file if set). Default true."`
	File     string `yaml:"file" json:"file" usage:"Log output to a file (as well as stdout if set). Make sure that the directory and the file is writable."`
	Rotation bool   `yaml:"rotation" json:"rotation" usage:"Rotate log files. Default is false."`
	// Reference: https://godoc.org/gopkg.in/natefinch/lumberjack.v2
	MaxSize    int    `yaml:"max_size" json:"max_size" usage:"The maximum size in megabytes of the log file before it gets rotated. It defaults to 100 megabytes."`
	MaxAge     int    `yaml:"max_age" json:"max_age" usage:"The maximum number of days to retain old log files based on the timestamp encoded in their filename. The default is not to remove old log files based on age."`
	MaxBackups int    `yaml:"max_backups" json:"max_backups" usage:"The maximum number of old log files to retain. The default is to retain all old log files (though MaxAge may still cause them to get deleted.)"`
	LocalTime  bool   `yaml:"local_time" json:"local_time" usage:"This determines if the time used for formatting the timestamps in backup files is the computer's local time. The default is to use UTC time."`
	Compress   bool   `yaml:"compress" json:"compress" usage:"This determines if the rotated log files should be compressed using gzip."`
	Format     string `yaml:"format" json:"format" usage:"Set logging output format. Can either be 'JSON' or 'Stackdriver'. Default is 'JSON'."`
}

func (cfg *LoggerConfig) GetLevel() string {
	return cfg.Level
}

func (cfg *LoggerConfig) Clone() *LoggerConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg
	return &cfgCopy
}

func NewLoggerConfig() *LoggerConfig {
	return &LoggerConfig{
		Level:      "info",
		Stdout:     true,
		File:       "",
		Rotation:   false,
		MaxSize:    100,
		MaxAge:     0,
		MaxBackups: 0,
		LocalTime:  false,
		Compress:   false,
		Format:     "json",
	}
}

func NewMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		ReportingFreqSec: 60,
		Namespace:        "",
		PrometheusPort:   0,
		Prefix:           "inspo",
		CustomPrefix:     "custom",
	}
}

func (cfg *MetricsConfig) Clone() *MetricsConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg
	return &cfgCopy
}

type MetricsConfig struct {
	ReportingFreqSec int    `yaml:"reporting_freq_sec" json:"reporting_freq_sec" usage:"Frequency of metrics exports. Default is 60 seconds."`
	Namespace        string `yaml:"namespace" json:"namespace" usage:"Namespace for Prometheus metrics. It will always prepend node name."`
	PrometheusPort   int    `yaml:"prometheus_port" json:"prometheus_port" usage:"Port to expose Prometheus. If '0' Prometheus exports are disabled."`
	Prefix           string `yaml:"prefix" json:"prefix" usage:"Prefix for metric names. Default is 'inspo', empty string '' disables the prefix."`
	CustomPrefix     string `yaml:"custom_prefix" json:"custom_prefix" usage:"Prefix for custom runtime metric names. Default is 'custom', empty string '' disables the prefix."`
}

var _ runtime.SessionConfig = &SessionConfig{}

func (cfg *SessionConfig) GetEncryptionKey() string {
	return cfg.EncryptionKey
}

func (cfg *SessionConfig) GetTokenExpirySec() int64 {
	return cfg.TokenExpirySec
}

func (cfg *SessionConfig) GetRefreshEncryptionKey() string {
	return cfg.RefreshEncryptionKey
}

func (cfg *SessionConfig) GetRefreshTokenExpirySec() int64 {
	return cfg.RefreshTokenExpirySec
}

func (cfg *SessionConfig) GetSingleSocket() bool {
	return cfg.SingleSocket
}

func (cfg *SessionConfig) GetSingleMatch() bool {
	return cfg.SingleMatch
}

func (cfg *SessionConfig) GetSingleParty() bool {
	return cfg.SingleParty
}

func (cfg *SessionConfig) GetSingleSession() bool {
	return cfg.SingleSession
}

func (cfg *SessionConfig) Clone() *SessionConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg
	return &cfgCopy
}

func NewSessionConfig() *SessionConfig {
	return &SessionConfig{
		EncryptionKey:         "defaultencryptionkey",
		TokenExpirySec:        60,
		RefreshEncryptionKey:  "defaultrefreshencryptionkey",
		RefreshTokenExpirySec: 3600,
	}
}

// SessionConfig is configuration relevant to the session.
type SessionConfig struct {
	EncryptionKey         string `yaml:"encryption_key" json:"encryption_key" usage:"The encryption key used to produce the client token."`
	TokenExpirySec        int64  `yaml:"token_expiry_sec" json:"token_expiry_sec" usage:"Token expiry in seconds."`
	RefreshEncryptionKey  string `yaml:"refresh_encryption_key" json:"refresh_encryption_key" usage:"The encryption key used to produce the client refresh token."`
	RefreshTokenExpirySec int64  `yaml:"refresh_token_expiry_sec" json:"refresh_token_expiry_sec" usage:"Refresh token expiry in seconds."`
	SingleSocket          bool   `yaml:"single_socket" json:"single_socket" usage:"Only allow one socket per user. Older sessions are disconnected. Default false."`
	SingleMatch           bool   `yaml:"single_match" json:"single_match" usage:"Only allow one match per user. Older matches receive a leave. Requires single socket to enable. Default false."`
	SingleParty           bool   `yaml:"single_party" json:"single_party" usage:"Only allow one party per user. Older parties receive a leave. Requires single socket to enable. Default false."`
	SingleSession         bool   `yaml:"single_session" json:"single_session" usage:"Only allow one session token per user. Older session tokens are invalidated in the session cache. Default false."`
}

var _ runtime.SocketConfig = &SocketConfig{}

func NewSocketConfig() *SocketConfig {
	return &SocketConfig{
		ServerKey:            "defaultkey",
		Port:                 7350,
		Address:              "",
		Protocol:             "tcp",
		MaxMessageSizeBytes:  4096,
		MaxRequestSizeBytes:  262_144, // 256 KB.
		ReadBufferSizeBytes:  4096,
		WriteBufferSizeBytes: 4096,
		ReadTimeoutMs:        10 * 1000,
		WriteTimeoutMs:       10 * 1000,
		IdleTimeoutMs:        60 * 1000,
		WriteWaitMs:          5000,
		PongWaitMs:           25000,
		PingPeriodMs:         15000,
		PingBackoffThreshold: 20,
		OutgoingQueueSize:    64,
		SSLCertificate:       "",
		SSLPrivateKey:        "",
	}
}

func (cfg *SocketConfig) GetServerKey() string {
	return cfg.ServerKey
}

func (cfg *SocketConfig) GetPort() int {
	return cfg.Port
}

func (cfg *SocketConfig) GetAddress() string {
	return cfg.Address
}

func (cfg *SocketConfig) GetProtocol() string {
	return cfg.Protocol
}

func (cfg *SocketConfig) Clone() (*SocketConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	cfgCopy := *cfg

	if cfg.ResponseHeaders != nil {
		cfgCopy.ResponseHeaders = make([]string, len(cfg.ResponseHeaders))
		copy(cfgCopy.ResponseHeaders, cfg.ResponseHeaders)
	}
	if cfg.Headers != nil {
		cfgCopy.Headers = make(map[string]string, len(cfg.Headers))
		for k, v := range cfg.Headers {
			cfgCopy.Headers[k] = v
		}
	}
	if cfg.CertPEMBlock != nil {
		cfgCopy.CertPEMBlock = make([]byte, len(cfg.CertPEMBlock))
		copy(cfgCopy.CertPEMBlock, cfg.CertPEMBlock)
	}
	if cfg.KeyPEMBlock != nil {
		cfgCopy.KeyPEMBlock = make([]byte, len(cfg.KeyPEMBlock))
		copy(cfgCopy.KeyPEMBlock, cfg.KeyPEMBlock)
	}
	if len(cfg.TLSCert) != 0 {
		cert, err := tls.X509KeyPair(cfg.CertPEMBlock, cfg.KeyPEMBlock)
		if err != nil {
			return nil, err
		}
		cfgCopy.TLSCert = []tls.Certificate{cert}
	}

	return &cfgCopy, nil
}

// SocketConfig is configuration relevant to the transport socket and protocol.
type SocketConfig struct {
	ServerKey            string            `yaml:"server_key" json:"server_key" usage:"Server key to use to establish a connection to the server."`
	Port                 int               `yaml:"port" json:"port" usage:"The port for accepting connections from the client for the given interface(s), address(es), and protocol(s). Default 7350."`
	Address              string            `yaml:"address" json:"address" usage:"The IP address of the interface to listen for client traffic on. Default listen on all available addresses/interfaces."`
	Protocol             string            `yaml:"protocol" json:"protocol" usage:"The network protocol to listen for traffic on. Possible values are 'tcp' for both IPv4 and IPv6, 'tcp4' for IPv4 only, or 'tcp6' for IPv6 only. Default 'tcp'."`
	MaxMessageSizeBytes  int64             `yaml:"max_message_size_bytes" json:"max_message_size_bytes" usage:"Maximum amount of data in bytes allowed to be read from the client socket per message. Used for real-time connections."`
	MaxRequestSizeBytes  int64             `yaml:"max_request_size_bytes" json:"max_request_size_bytes" usage:"Maximum amount of data in bytes allowed to be read from clients per request. Used for gRPC and HTTP connections."`
	ReadBufferSizeBytes  int               `yaml:"read_buffer_size_bytes" json:"read_buffer_size_bytes" usage:"Size in bytes of the pre-allocated socket read buffer. Default 4096."`
	WriteBufferSizeBytes int               `yaml:"write_buffer_size_bytes" json:"write_buffer_size_bytes" usage:"Size in bytes of the pre-allocated socket write buffer. Default 4096."`
	ReadTimeoutMs        int               `yaml:"read_timeout_ms" json:"read_timeout_ms" usage:"Maximum duration in milliseconds for reading the entire request. Used for HTTP connections."`
	WriteTimeoutMs       int               `yaml:"write_timeout_ms" json:"write_timeout_ms" usage:"Maximum duration in milliseconds before timing out writes of the response. Used for HTTP connections."`
	IdleTimeoutMs        int               `yaml:"idle_timeout_ms" json:"idle_timeout_ms" usage:"Maximum amount of time in milliseconds to wait for the next request when keep-alives are enabled. Used for HTTP connections."`
	WriteWaitMs          int               `yaml:"write_wait_ms" json:"write_wait_ms" usage:"Time in milliseconds to wait for an ack from the client when writing data. Used for real-time connections."`
	PongWaitMs           int               `yaml:"pong_wait_ms" json:"pong_wait_ms" usage:"Time in milliseconds to wait between pong messages received from the client. Used for real-time connections."`
	PingPeriodMs         int               `yaml:"ping_period_ms" json:"ping_period_ms" usage:"Time in milliseconds to wait between sending ping messages to the client. This value must be less than the pong_wait_ms. Used for real-time connections."`
	PingBackoffThreshold int               `yaml:"ping_backoff_threshold" json:"ping_backoff_threshold" usage:"Minimum number of messages received from the client during a single ping period that will delay the sending of a ping until the next ping period, to avoid sending unnecessary pings on regularly active connections. Default 20."`
	OutgoingQueueSize    int               `yaml:"outgoing_queue_size" json:"outgoing_queue_size" usage:"The maximum number of messages waiting to be sent to the client. If this is exceeded the client is considered too slow and will disconnect. Used when processing real-time connections."`
	SSLCertificate       string            `yaml:"ssl_certificate" json:"ssl_certificate" usage:"Path to certificate file if you want the server to use SSL directly. Must also supply ssl_private_key. NOT recommended for production use."`
	SSLPrivateKey        string            `yaml:"ssl_private_key" json:"ssl_private_key" usage:"Path to private key file if you want the server to use SSL directly. Must also supply ssl_certificate. NOT recommended for production use."`
	ResponseHeaders      []string          `yaml:"response_headers" json:"response_headers" usage:"Additional headers to send to clients with every response. Values here are only used if the response would not otherwise contain a value for the specified headers."`
	Headers              map[string]string `yaml:"-" json:"-"` // Created by parsing ResponseHeaders above, not set from input args directly.
	CertPEMBlock         []byte            `yaml:"-" json:"-"` // Created by fully reading the file contents of SSLCertificate, not set from input args directly.
	KeyPEMBlock          []byte            `yaml:"-" json:"-"` // Created by fully reading the file contents of SSLPrivateKey, not set from input args directly.
	TLSCert              []tls.Certificate `yaml:"-" json:"-"` // Created by processing CertPEMBlock and KeyPEMBlock, not set from input args directly.
}

type DatabaseConfig struct {
	Addresses          []string `yaml:"address" json:"address" usage:"List of database servers (username:password@address:port/dbname). Default 'root@localhost:26257'."`
	ConnMaxLifetimeMs  int      `yaml:"conn_max_lifetime_ms" json:"conn_max_lifetime_ms" usage:"Time in milliseconds to reuse a database connection before the connection is killed and a new one is created. Default 3600000 (1 hour)."`
	MaxOpenConns       int      `yaml:"max_open_conns" json:"max_open_conns" usage:"Maximum number of allowed open connections to the database. Default 100."`
	MaxIdleConns       int      `yaml:"max_idle_conns" json:"max_idle_conns" usage:"Maximum number of allowed open but unused connections to the database. Default 100."`
	DnsScanIntervalSec int      `yaml:"dns_scan_interval_sec" json:"dns_scan_interval_sec" usage:"Number of seconds between scans looking for DNS resolution changes for the database hostname. Default 60."`
}

func (cfg *DatabaseConfig) Clone() *DatabaseConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg

	if cfg.Addresses != nil {
		cfgCopy.Addresses = make([]string, len(cfg.Addresses))
		copy(cfgCopy.Addresses, cfg.Addresses)
	}

	return &cfgCopy
}

func NewDatabaseConfig() *DatabaseConfig {
	return &DatabaseConfig{
		Addresses:          []string{"root@localhost:26257"},
		ConnMaxLifetimeMs:  3600000,
		MaxOpenConns:       100,
		MaxIdleConns:       100,
		DnsScanIntervalSec: 60,
	}
}

func NewSocialConfig() *SocialConfig {
	return &SocialConfig{
		Steam: &SocialConfigSteam{
			PublisherKey: "",
			AppID:        0,
		},
		FacebookInstantGame: &SocialConfigFacebookInstantGame{
			AppSecret: "",
		},
		FacebookLimitedLogin: &SocialConfigFacebookLimitedLogin{
			AppId: "",
		},
		Apple: &SocialConfigApple{
			BundleId: "",
		},
	}
}

var _ runtime.SocialConfig = &SocialConfig{}

func (cfg *SocialConfig) GetSteam() runtime.SocialConfigSteam {
	return cfg.Steam
}

func (cfg *SocialConfig) GetFacebookInstantGame() runtime.SocialConfigFacebookInstantGame {
	return cfg.FacebookInstantGame
}

func (cfg *SocialConfig) GetFacebookLimitedLogin() runtime.SocialConfigFacebookLimitedLogin {
	return cfg.FacebookLimitedLogin
}

func (cfg *SocialConfig) GetApple() runtime.SocialConfigApple {
	return cfg.Apple
}

func (cfg *SocialConfig) Clone() *SocialConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg

	if cfg.Steam != nil {
		c := *(cfg.Steam)
		cfgCopy.Steam = &c
	}
	if cfg.FacebookInstantGame != nil {
		c := *(cfg.FacebookInstantGame)
		cfgCopy.FacebookInstantGame = &c
	}
	if cfg.FacebookLimitedLogin != nil {
		c := *(cfg.FacebookLimitedLogin)
		cfgCopy.FacebookLimitedLogin = &c
	}
	if cfg.Apple != nil {
		c := *(cfg.Apple)
		cfgCopy.Apple = &c
	}

	return &cfgCopy
}

// SocialConfig is configuration relevant to the social authentication providers.
type SocialConfig struct {
	Steam                *SocialConfigSteam                `yaml:"steam" json:"steam" usage:"Steam configuration."`
	FacebookInstantGame  *SocialConfigFacebookInstantGame  `yaml:"facebook_instant_game" json:"facebook_instant_game" usage:"Facebook Instant Game configuration."`
	FacebookLimitedLogin *SocialConfigFacebookLimitedLogin `yaml:"facebook_limited_login" json:"facebook_limited_login" usage:"Facebook Limited Login configuration."`
	Apple                *SocialConfigApple                `yaml:"apple" json:"apple" usage:"Apple Sign In configuration."`
}

var _ runtime.SocialConfigSteam = &SocialConfigSteam{}

// SocialConfigSteam is configuration relevant to Steam.
type SocialConfigSteam struct {
	PublisherKey string `yaml:"publisher_key" json:"publisher_key" usage:"Steam Publisher Key value."`
	AppID        int    `yaml:"app_id" json:"app_id" usage:"Steam App ID."`
}

func (s SocialConfigSteam) GetPublisherKey() string {
	return s.PublisherKey
}

func (s SocialConfigSteam) GetAppID() int {
	return s.AppID
}

var _ runtime.SocialConfigFacebookInstantGame = &SocialConfigFacebookInstantGame{}

// SocialConfigFacebookInstantGame is configuration relevant to Facebook Instant Games.
type SocialConfigFacebookInstantGame struct {
	AppSecret string `yaml:"app_secret" json:"app_secret" usage:"Facebook Instant App secret."`
}

func (s SocialConfigFacebookInstantGame) GetAppSecret() string {
	return s.AppSecret
}

var _ runtime.SocialConfigFacebookLimitedLogin = &SocialConfigFacebookLimitedLogin{}

// SocialConfigFacebookLimitedLogin is configuration relevant to Facebook Limited Login.
type SocialConfigFacebookLimitedLogin struct {
	AppId string `yaml:"app_id" json:"app_id" usage:"Facebook Limited Login App ID."`
}

func (s SocialConfigFacebookLimitedLogin) GetAppId() string {
	return s.AppId
}

var _ runtime.SocialConfigApple = &SocialConfigApple{}

// SocialConfigApple is configuration relevant to Apple Sign In.
type SocialConfigApple struct {
	BundleId string `yaml:"bundle_id" json:"bundle_id" usage:"Apple Sign In bundle ID."`
}

func (s SocialConfigApple) GetBundleId() string {
	return s.BundleId
}
func NewMatchConfig() *MatchConfig {
	return &MatchConfig{
		InputQueueSize:        128,
		CallQueueSize:         128,
		SignalQueueSize:       10,
		JoinAttemptQueueSize:  128,
		DeferredQueueSize:     128,
		JoinMarkerDeadlineMs:  15000,
		MaxEmptySec:           0,
		LabelUpdateIntervalMs: 1000,
	}
}

// MatchConfig is configuration relevant to authoritative realtime multiplayer matches.
type MatchConfig struct {
	InputQueueSize        int `yaml:"input_queue_size" json:"input_queue_size" usage:"Size of the authoritative match buffer that stores client messages until they can be processed by the next tick. Default 128."`
	CallQueueSize         int `yaml:"call_queue_size" json:"call_queue_size" usage:"Size of the authoritative match buffer that sequences calls to match handler callbacks to ensure no overlaps. Default 128."`
	SignalQueueSize       int `yaml:"signal_queue_size" json:"signal_queue_size" usage:"Size of the authoritative match buffer that sequences signal operations to match handler callbacks to ensure no overlaps. Default 10."`
	JoinAttemptQueueSize  int `yaml:"join_attempt_queue_size" json:"join_attempt_queue_size" usage:"Size of the authoritative match buffer that limits the number of in-progress join attempts. Default 128."`
	DeferredQueueSize     int `yaml:"deferred_queue_size" json:"deferred_queue_size" usage:"Size of the authoritative match buffer that holds deferred message broadcasts until the end of each loop execution. Default 128."`
	JoinMarkerDeadlineMs  int `yaml:"join_marker_deadline_ms" json:"join_marker_deadline_ms" usage:"Deadline in milliseconds that client authoritative match joins will wait for match handlers to acknowledge joins. Default 15000."`
	MaxEmptySec           int `yaml:"max_empty_sec" json:"max_empty_sec" usage:"Maximum number of consecutive seconds that authoritative matches are allowed to be empty before they are stopped. 0 indicates no maximum. Default 0."`
	LabelUpdateIntervalMs int `yaml:"label_update_interval_ms" json:"label_update_interval_ms" usage:"Time in milliseconds between match label update batch processes. Default 1000."`
}

func (cfg *MatchConfig) Clone() *MatchConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg
	return &cfgCopy
}

// TrackerConfig is configuration relevant to the presence tracker.
type TrackerConfig struct {
	EventQueueSize int `yaml:"event_queue_size" json:"event_queue_size" usage:"Size of the tracker presence event buffer. Increase if the server is expected to generate a large number of presence events in a short time. Default 1024."`
}

func (cfg *TrackerConfig) Clone() *TrackerConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg
	return &cfgCopy
}

func NewTrackerConfig() *TrackerConfig {
	return &TrackerConfig{
		EventQueueSize: 1024,
	}
}

var _ runtime.RuntimeConfig = &RuntimeConfig{}

// RuntimeConfig is configuration relevant to the Runtimes.
type RuntimeConfig struct {
	Environment        map[string]string `yaml:"-" json:"-"`
	Env                []string          `yaml:"env" json:"env" usage:"Values to pass into Runtime as environment variables."`
	Path               string            `yaml:"path" json:"path" usage:"Path for the server to scan for Lua and Go library files."`
	HTTPKey            string            `yaml:"http_key" json:"http_key" usage:"Runtime HTTP Invocation key."`
	MinCount           int               `yaml:"min_count" json:"min_count" usage:"Minimum number of Lua runtime instances to allocate. Default 0."` // Kept for backwards compatibility
	LuaMinCount        int               `yaml:"lua_min_count" json:"lua_min_count" usage:"Minimum number of Lua runtime instances to allocate. Default 16."`
	MaxCount           int               `yaml:"max_count" json:"max_count" usage:"Maximum number of Lua runtime instances to allocate. Default 0."` // Kept for backwards compatibility
	LuaMaxCount        int               `yaml:"lua_max_count" json:"lua_max_count" usage:"Maximum number of Lua runtime instances to allocate. Default 48."`
	JsMinCount         int               `yaml:"js_min_count" json:"js_min_count" usage:"Maximum number of Javascript runtime instances to allocate. Default 16."`
	JsMaxCount         int               `yaml:"js_max_count" json:"js_max_count" usage:"Maximum number of Javascript runtime instances to allocate. Default 32."`
	CallStackSize      int               `yaml:"call_stack_size" json:"call_stack_size" usage:"Size of each runtime instance's call stack. Default 0."` // Kept for backwards compatibility
	LuaCallStackSize   int               `yaml:"lua_call_stack_size" json:"lua_call_stack_size" usage:"Size of each runtime instance's call stack. Default 128."`
	RegistrySize       int               `yaml:"registry_size" json:"registry_size" usage:"Size of each Lua runtime instance's registry. Default 0."` // Kept for backwards compatibility
	LuaRegistrySize    int               `yaml:"lua_registry_size" json:"lua_registry_size" usage:"Size of each Lua runtime instance's registry. Default 512."`
	EventQueueSize     int               `yaml:"event_queue_size" json:"event_queue_size" usage:"Size of the event queue buffer. Default 65536."`
	EventQueueWorkers  int               `yaml:"event_queue_workers" json:"event_queue_workers" usage:"Number of workers to use for concurrent processing of events. Default 8."`
	ReadOnlyGlobals    bool              `yaml:"read_only_globals" json:"read_only_globals" usage:"When enabled marks all Lua runtime global tables as read-only to reduce memory footprint. Default true."` // Kept for backwards compatibility
	LuaReadOnlyGlobals bool              `yaml:"lua_read_only_globals" json:"lua_read_only_globals" usage:"When enabled marks all Lua runtime global tables as read-only to reduce memory footprint. Default true."`
	JsReadOnlyGlobals  bool              `yaml:"js_read_only_globals" json:"js_read_only_globals" usage:"When enabled marks all Javascript runtime globals as read-only to reduce memory footprint. Default true."`
	LuaApiStacktrace   bool              `yaml:"lua_api_stacktrace" json:"lua_api_stacktrace" usage:"Include the Lua stacktrace in error responses returned to the client. Default false."`
	JsEntrypoint       string            `yaml:"js_entrypoint" json:"js_entrypoint" usage:"Specifies the location of the bundled JavaScript runtime source code."`
}

func (r *RuntimeConfig) GetEnv() []string {
	return r.Env
}

func (r *RuntimeConfig) GetHTTPKey() string {
	return r.HTTPKey
}

func (r *RuntimeConfig) Clone() *RuntimeConfig {
	if r == nil {
		return nil
	}

	cfgCopy := *r

	if r.Env != nil {
		cfgCopy.Env = make([]string, len(r.Env))
		copy(cfgCopy.Env, r.Env)
	}
	if r.Environment != nil {
		cfgCopy.Environment = make(map[string]string, len(r.Environment))
		for k, v := range r.Environment {
			cfgCopy.Environment[k] = v
		}
	}

	return &cfgCopy
}

// Function to allow backwards compatibility for MinCount config
func (r *RuntimeConfig) GetLuaMinCount() int {
	if r.MinCount != 0 {
		return r.MinCount
	}
	return r.LuaMinCount
}

// Function to allow backwards compatibility for MaxCount config
func (r *RuntimeConfig) GetLuaMaxCount() int {
	if r.MaxCount != 0 {
		return r.MaxCount
	}
	return r.LuaMaxCount
}

// Function to allow backwards compatibility for CallStackSize config
func (r *RuntimeConfig) GetLuaCallStackSize() int {
	if r.CallStackSize != 0 {
		return r.CallStackSize
	}
	return r.LuaCallStackSize
}

// Function to allow backwards compatibility for RegistrySize config
func (r *RuntimeConfig) GetLuaRegistrySize() int {
	if r.RegistrySize != 0 {
		return r.RegistrySize
	}
	return r.LuaRegistrySize
}

// Function to allow backwards compatibility for LuaReadOnlyGlobals config
func (r *RuntimeConfig) GetLuaReadOnlyGlobals() bool {
	if !r.ReadOnlyGlobals {
		return r.ReadOnlyGlobals
	}
	return r.LuaReadOnlyGlobals
}

func NewRuntimeConfig() *RuntimeConfig {
	return &RuntimeConfig{
		Environment:        make(map[string]string),
		Env:                make([]string, 0),
		Path:               "",
		HTTPKey:            "defaulthttpkey",
		LuaMinCount:        16,
		LuaMaxCount:        48,
		LuaCallStackSize:   128,
		LuaRegistrySize:    512,
		JsMinCount:         16,
		JsMaxCount:         32,
		EventQueueSize:     65536,
		EventQueueWorkers:  8,
		ReadOnlyGlobals:    true,
		LuaReadOnlyGlobals: true,
		JsReadOnlyGlobals:  true,
		LuaApiStacktrace:   false,
	}
}

// ConsoleConfig is configuration relevant to the embedded console.
type ConsoleConfig struct {
	Port                int        `yaml:"port" json:"port" usage:"The port for accepting connections for the embedded console, listening on all interfaces."`
	Address             string     `yaml:"address" json:"address" usage:"The IP address of the interface to listen for console traffic on. Default listen on all available addresses/interfaces."`
	MaxMessageSizeBytes int64      `yaml:"max_message_size_bytes" json:"max_message_size_bytes" usage:"Maximum amount of data in bytes allowed to be read from the client socket per message."`
	ReadTimeoutMs       int        `yaml:"read_timeout_ms" json:"read_timeout_ms" usage:"Maximum duration in milliseconds for reading the entire request."`
	WriteTimeoutMs      int        `yaml:"write_timeout_ms" json:"write_timeout_ms" usage:"Maximum duration in milliseconds before timing out writes of the response."`
	IdleTimeoutMs       int        `yaml:"idle_timeout_ms" json:"idle_timeout_ms" usage:"Maximum amount of time in milliseconds to wait for the next request when keep-alives are enabled."`
	Username            string     `yaml:"username" json:"username" usage:"Username for the embedded console. Default username is 'admin'."`
	Password            string     `yaml:"password" json:"password" usage:"Password for the embedded console. Default password is 'password'."`
	TokenExpirySec      int64      `yaml:"token_expiry_sec" json:"token_expiry_sec" usage:"Token expiry in seconds. Default 86400."`
	SigningKey          string     `yaml:"signing_key" json:"signing_key" usage:"Key used to sign console session tokens."`
	MFA                 *MFAConfig `yaml:"mfa" json:"mfa" usage:"MFA settings."`
}

func (cfg *ConsoleConfig) Clone() *ConsoleConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg

	if cfg.MFA != nil {
		c := *(cfg.MFA)
		cfgCopy.MFA = &c
	}

	return &cfgCopy
}

func NewConsoleConfig() *ConsoleConfig {
	return &ConsoleConfig{
		Port:                7351,
		MaxMessageSizeBytes: 4_194_304, // 4 MB.
		ReadTimeoutMs:       10 * 1000,
		WriteTimeoutMs:      60 * 1000,
		IdleTimeoutMs:       300 * 1000,
		Username:            "admin",
		Password:            "password",
		TokenExpirySec:      86400,
		SigningKey:          "defaultsigningkey",
		MFA:                 NewMFAConfig(),
	}
}

// LeaderboardConfig is configuration relevant to the leaderboard system.
type LeaderboardConfig struct {
	BlacklistRankCache   []string `yaml:"blacklist_rank_cache" json:"blacklist_rank_cache" usage:"Disable rank cache for leaderboards with matching identifiers. To disable rank cache entirely, use '*', otherwise leave blank to enable rank cache."`
	CallbackQueueSize    int      `yaml:"callback_queue_size" json:"callback_queue_size" usage:"Size of the leaderboard and tournament callback queue that sequences expiry/reset/end invocations. Default 65536."`
	CallbackQueueWorkers int      `yaml:"callback_queue_workers" json:"callback_queue_workers" usage:"Number of workers to use for concurrent processing of leaderboard and tournament callbacks. Default 8."`
	RankCacheWorkers     int      `yaml:"rank_cache_workers" json:"rank_cache_workers" usage:"The number of parallel workers to use while populating leaderboard rank cache from the database. Higher number of workers usually makes the process faster but at the cost of increased database load. Default 1."`
}

func (cfg *LeaderboardConfig) Clone() *LeaderboardConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg

	if cfg.BlacklistRankCache != nil {
		cfgCopy.BlacklistRankCache = make([]string, len(cfg.BlacklistRankCache))
		copy(cfgCopy.BlacklistRankCache, cfg.BlacklistRankCache)
	}

	return &cfgCopy
}

func NewLeaderboardConfig() *LeaderboardConfig {
	return &LeaderboardConfig{
		BlacklistRankCache:   []string{},
		CallbackQueueSize:    65536,
		CallbackQueueWorkers: 8,
		RankCacheWorkers:     1,
	}
}

type MatchmakerConfig struct {
	MaxTickets   int  `yaml:"max_tickets" json:"max_tickets" usage:"Maximum number of concurrent matchmaking tickets allowed per session or party. Default 3."`
	IntervalSec  int  `yaml:"interval_sec" json:"interval_sec" usage:"How quickly the matchmaker attempts to form matches, in seconds. Default 15."`
	MaxIntervals int  `yaml:"max_intervals" json:"max_intervals" usage:"How many intervals the matchmaker attempts to find matches at the max player count, before allowing min count. Default 2."`
	RevPrecision bool `yaml:"rev_precision" json:"rev_precision" usage:"Reverse matching precision. Default false."`
	RevThreshold int  `yaml:"rev_threshold" json:"rev_threshold" usage:"Reverse matching threshold. Default 1."`
}

func (cfg *MatchmakerConfig) Clone() *MatchmakerConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg
	return &cfgCopy
}

func NewMatchmakerConfig() *MatchmakerConfig {
	return &MatchmakerConfig{
		MaxTickets:   3,
		IntervalSec:  15,
		MaxIntervals: 2,
		RevPrecision: false,
		RevThreshold: 1,
	}
}

var _ runtime.IAPConfig = &IAPConfig{}

type IAPConfig struct {
	Apple           *IAPAppleConfig           `yaml:"apple" json:"apple" usage:"Apple App Store purchase validation configuration."`
	Google          *IAPGoogleConfig          `yaml:"google" json:"google" usage:"Google Play Store purchase validation configuration."`
	Huawei          *IAPHuaweiConfig          `yaml:"huawei" json:"huawei" usage:"Huawei purchase validation configuration."`
	FacebookInstant *IAPFacebookInstantConfig `yaml:"facebook_instant" json:"facebook_instant" usage:"Facebook Instant purchase validation configuration."`
}

func (cfg *IAPConfig) GetApple() runtime.IAPAppleConfig {
	return cfg.Apple
}

func (cfg *IAPConfig) GetGoogle() runtime.IAPGoogleConfig {
	return cfg.Google
}

func (cfg *IAPConfig) GetHuawei() runtime.IAPHuaweiConfig {
	return cfg.Huawei
}

func (cfg *IAPConfig) GetFacebookInstant() runtime.IAPFacebookInstantConfig {
	return cfg.FacebookInstant
}

func (cfg *IAPConfig) Clone() *IAPConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg

	if cfg.Google != nil {
		c := *(cfg.Google)
		cfgCopy.Google = &c
	}
	if cfg.Apple != nil {
		c := *(cfg.Apple)
		cfgCopy.Apple = &c
	}
	if cfg.FacebookInstant != nil {
		c := *(cfg.FacebookInstant)
		cfgCopy.FacebookInstant = &c
	}
	if cfg.Huawei != nil {
		c := *(cfg.Huawei)
		cfgCopy.Huawei = &c
	}

	return &cfgCopy
}

func NewIAPConfig() *IAPConfig {
	return &IAPConfig{
		Apple:           &IAPAppleConfig{},
		Google:          &IAPGoogleConfig{},
		Huawei:          &IAPHuaweiConfig{},
		FacebookInstant: &IAPFacebookInstantConfig{},
	}
}

var _ runtime.IAPAppleConfig = &IAPAppleConfig{}

var _ runtime.IAPAppleConfig = &IAPAppleConfig{}

type IAPAppleConfig struct {
	SharedPassword          string `yaml:"shared_password" json:"shared_password" usage:"Your Apple Store App IAP shared password. Only necessary for validation of auto-renewable subscriptions."`
	NotificationsEndpointId string `yaml:"notifications_endpoint_id" json:"notifications_endpoint_id" usage:"The callback endpoint identifier for Apple Store subscription notifications."`
}

func (iap IAPAppleConfig) GetSharedPassword() string {
	return iap.SharedPassword
}

func (iap IAPAppleConfig) GetNotificationsEndpointId() string {
	return iap.NotificationsEndpointId
}

var _ runtime.IAPGoogleConfig = &IAPGoogleConfig{}

type IAPGoogleConfig struct {
	ClientEmail             string `yaml:"client_email" json:"client_email" usage:"Google Service Account client email."`
	PrivateKey              string `yaml:"private_key" json:"private_key" usage:"Google Service Account private key."`
	NotificationsEndpointId string `yaml:"notifications_endpoint_id" json:"notifications_endpoint_id" usage:"The callback endpoint identifier for Android subscription notifications."`
	RefundCheckPeriodMin    int    `yaml:"refund_check_period_min" json:"refund_check_period_min" usage:"Defines the polling interval in minutes of the Google IAP refund API."`
	PackageName             string `yaml:"package_name" json:"package_name" usage:"Google Play Store App Package Name."`
}

func (iapg *IAPGoogleConfig) GetClientEmail() string {
	return iapg.ClientEmail
}

func (iapg *IAPGoogleConfig) GetPrivateKey() string {
	return iapg.PrivateKey
}

func (iapg *IAPGoogleConfig) GetNotificationsEndpointId() string {
	return iapg.NotificationsEndpointId
}

func (iapg *IAPGoogleConfig) GetRefundCheckPeriodMin() int {
	return iapg.RefundCheckPeriodMin
}

func (iapg *IAPGoogleConfig) GetPackageName() string {
	return iapg.PackageName
}

func (iapg *IAPGoogleConfig) Enabled() bool {
	if iapg.PrivateKey != "" && iapg.PackageName != "" {
		return true
	}
	return false
}

var _ runtime.SatoriConfig = &SatoriConfig{}

type SatoriConfig struct {
	Url          string `yaml:"url" json:"url" usage:"Satori URL."`
	ApiKeyName   string `yaml:"api_key_name" json:"api_key_name" usage:"Satori Api key name."`
	ApiKey       string `yaml:"api_key" json:"api_key" usage:"Satori Api key."`
	SigningKey   string `yaml:"signing_key" json:"signing_key" usage:"Key used to sign Satori session tokens."`
	CacheEnabled bool   `yaml:"cache_enabled" json:"cache_enabled" usage:"Enable caching of responses throughout the lifetime of a request."`
}

func (sc *SatoriConfig) GetUrl() string {
	return sc.Url
}

func (sc *SatoriConfig) GetApiKeyName() string {
	return sc.ApiKeyName
}

func (sc *SatoriConfig) GetApiKey() string {
	return sc.ApiKey
}

func (sc *SatoriConfig) GetSigningKey() string {
	return sc.SigningKey
}

func (sc *SatoriConfig) Clone() *SatoriConfig {
	if sc == nil {
		return nil
	}

	cfgCopy := *sc
	return &cfgCopy
}

func NewSatoriConfig() *SatoriConfig {
	return &SatoriConfig{}
}

func (sc *SatoriConfig) Validate(logger *zap.Logger) {
	satoriUrl, err := url.Parse(sc.Url) // Empty string is a valid URL
	if err != nil {
		logger.Fatal("Satori URL is invalid", zap.String("satori_url", sc.Url), zap.Error(err))
	}

	if satoriUrl.String() != "" {
		if sc.ApiKeyName == "" {
			logger.Fatal("Satori configuration incomplete: api_key_name not set")
		}
		if sc.ApiKey == "" {
			logger.Fatal("Satori configuration incomplete: api_key not set")
		}
		if sc.SigningKey == "" {
			logger.Fatal("Satori configuration incomplete: signing_key not set")
		}
	} else if sc.ApiKeyName != "" || sc.ApiKey != "" || sc.SigningKey != "" {
		logger.Fatal("Satori configuration incomplete: url not set")
	}
}

var _ runtime.IAPHuaweiConfig = &IAPHuaweiConfig{}

type IAPHuaweiConfig struct {
	PublicKey    string `yaml:"public_key" json:"public_key" usage:"Huawei IAP store Base64 encoded Public Key."`
	ClientID     string `yaml:"client_id" json:"client_id" usage:"Huawei OAuth client secret."`
	ClientSecret string `yaml:"client_secret" json:"client_secret" usage:"Huawei OAuth app client secret."`
}

func (i IAPHuaweiConfig) GetPublicKey() string {
	return i.PublicKey
}

func (i IAPHuaweiConfig) GetClientID() string {
	return i.ClientID
}

func (i IAPHuaweiConfig) GetClientSecret() string {
	return i.ClientSecret
}

var _ runtime.IAPFacebookInstantConfig = &IAPFacebookInstantConfig{}

type IAPFacebookInstantConfig struct {
	AppSecret string `yaml:"app_secret" json:"app_secret" usage:"Facebook Instant OAuth app client secret."`
}

func (i IAPFacebookInstantConfig) GetAppSecret() string {
	return i.AppSecret
}

var _ runtime.GoogleAuthConfig = &GoogleAuthConfig{}

type GoogleAuthConfig struct {
	CredentialsJSON string         `yaml:"credentials_json" json:"credentials_json" usage:"Google's Access Credentials."`
	OAuthConfig     *oauth2.Config `yaml:"-" json:"-"`
}

func (cfg *GoogleAuthConfig) GetCredentialsJSON() string {
	return cfg.CredentialsJSON
}

func (cfg *GoogleAuthConfig) Clone() *GoogleAuthConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg

	if cfg.OAuthConfig != nil {
		c := *cfg.OAuthConfig
		if cfg.OAuthConfig.Scopes != nil {
			c.Scopes = make([]string, len(cfg.OAuthConfig.Scopes))
			copy(c.Scopes, cfg.OAuthConfig.Scopes)
		}
		cfgCopy.OAuthConfig = &c
	}

	return &cfgCopy
}

func NewGoogleAuthConfig() *GoogleAuthConfig {
	return &GoogleAuthConfig{
		CredentialsJSON: "",
		OAuthConfig:     nil,
	}
}

var _ runtime.SatoriConfig = &SatoriConfig{}

type StorageConfig struct {
	DisableIndexOnly bool `yaml:"disable_index_only" json:"disable_index_only" usage:"Override and disable 'index_only' storage indices config and fallback to reading from the database."`
}

func (cfg *StorageConfig) Clone() *StorageConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg
	return &cfgCopy
}

func NewStorageConfig() *StorageConfig {
	return &StorageConfig{}
}

type MFAConfig struct {
	StorageEncryptionKey string `yaml:"storage_encryption_key" json:"storage_encryption_key" usage:"The encryption key to be used when persisting MFA related data. Has to be 32 bytes long."`
	AdminAccountOn       bool   `yaml:"admin_account_enabled" json:"admin_account_enabled" usage:"Require MFA for the Console Admin account."`
}

func (cfg *MFAConfig) Clone() *MFAConfig {
	if cfg == nil {
		return nil
	}

	cfgCopy := *cfg
	return &cfgCopy
}

func NewMFAConfig() *MFAConfig {
	return &MFAConfig{
		StorageEncryptionKey: "the-key-has-to-be-32-bytes-long!", // Has to be 32 bit long.
		AdminAccountOn:       false,
	}
}
