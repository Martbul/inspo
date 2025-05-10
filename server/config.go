package server

import (
	"crypto/tls"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

type config struct {
	Name             string          `yaml:"name" json:"name" usage:"Inspo server’s node name - must be unique."`
	Config           []string        `yaml:"config" json:"config" usage:"The absolute file path to configuration YAML file."`
	ShutdownGraceSec int             `yaml:"shutdown_grace_sec" json:"shutdown_grace_sec" usage:"Maximum number of seconds to wait for the server to complete work before shutting down. Default is 0 seconds. If 0 the server will shut down immediately when it receives a termination signal."`
	DataDir          string          `yaml:"data_dir" json:"data_dir" usage:"An absolute path to a writeable folder where Inspo will store its data."`
	Logger           *LoggerConfig   `yaml:"logger" json:"logger" usage:"Logger levels and output."`
	Metrics          *MetricsConfig  `yaml:"metrics" json:"metrics" usage:"Metrics settings."`
	Session          *SessionConfig  `yaml:"session" json:"session" usage:"Session authentication settings."`
	Socket           *SocketConfig   `yaml:"socket" json:"socket" usage:"Socket configuration."`
	Database         *DatabaseConfig `yaml:"database" json:"database" usage:"Database connection settings."`
	//	Social           *SocialConfig      `yaml:"social" json:"social" usage:"Properties for social provider integrations."`
	//	Runtime          *RuntimeConfig     `yaml:"runtime" json:"runtime" usage:"Script Runtime properties."`
	//	Match            *MatchConfig       `yaml:"match" json:"match" usage:"Authoritative realtime match properties."`
	//	Tracker          *TrackerConfig     `yaml:"tracker" json:"tracker" usage:"Presence tracker properties."`
	//	Console          *ConsoleConfig     `yaml:"console" json:"console" usage:"Console settings."`
	//	Leaderboard      *LeaderboardConfig `yaml:"leaderboard" json:"leaderboard" usage:"Leaderboard settings."`
	//	Matchmaker       *MatchmakerConfig  `yaml:"matchmaker" json:"matchmaker" usage:"Matchmaker settings."`
	//	IAP              *IAPConfig         `yaml:"iap" json:"iap" usage:"In-App Purchase settings."`
	//	GoogleAuth       *GoogleAuthConfig  `yaml:"google_auth" json:"google_auth" usage:"Google's auth settings."`
	//	Satori           *SatoriConfig      `yaml:"satori" json:"satori" usage:"Satori integration settings."`
	//	Storage          *StorageConfig     `yaml:"storage" json:"storage" usage:"Storage settings."`
	//	MFA              *MFAConfig         `yaml:"mfa" json:"mfa" usage:"MFA settings."`
	Limit int `json:"-"` // Only used for migrate command.
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
	}
}

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

type MetricsConfig struct {
	ReportingFreqSec int    `yaml:"reporting_freq_sec" json:"reporting_freq_sec" usage:"Frequency of metrics exports. Default is 60 seconds."`
	Namespace        string `yaml:"namespace" json:"namespace" usage:"Namespace for Prometheus metrics. It will always prepend node name."`
	PrometheusPort   int    `yaml:"prometheus_port" json:"prometheus_port" usage:"Port to expose Prometheus. If '0' Prometheus exports are disabled."`
	Prefix           string `yaml:"prefix" json:"prefix" usage:"Prefix for metric names. Default is 'inspo', empty string '' disables the prefix."`
	CustomPrefix     string `yaml:"custom_prefix" json:"custom_prefix" usage:"Prefix for custom runtime metric names. Default is 'custom', empty string '' disables the prefix."`
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
