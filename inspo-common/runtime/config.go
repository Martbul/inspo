package runtime

// Config interface is the Nakama core configuration.
type Config interface {
	GetName() string
	GetShutdownGraceSec() int
	GetLogger() LoggerConfig
	GetSession() SessionConfig
	GetSocket() SocketConfig
	GetSocial() SocialConfig
	GetRuntime() RuntimeConfig
	GetIAP() IAPConfig
	GetGoogleAuth() GoogleAuthConfig
	GetSatori() SatoriConfig
}

// LoggerConfig is configuration relevant to logging levels and output.
type LoggerConfig interface {
	GetLevel() string
}

// SessionConfig is configuration relevant to the session.
type SessionConfig interface {
	GetEncryptionKey() string
	GetTokenExpirySec() int64
	GetRefreshEncryptionKey() string
	GetRefreshTokenExpirySec() int64
	GetSingleSocket() bool
	GetSingleMatch() bool
	GetSingleParty() bool
	GetSingleSession() bool
}

// SocketConfig is configuration relevant to the transport socket and protocol.
type SocketConfig interface {
	GetServerKey() string
	GetPort() int
	GetAddress() string
	GetProtocol() string
}

// SocialConfig is configuration relevant to the social authentication providers.
type SocialConfig interface {
	GetSteam() SocialConfigSteam
	GetFacebookInstantGame() SocialConfigFacebookInstantGame
	GetFacebookLimitedLogin() SocialConfigFacebookLimitedLogin
	GetApple() SocialConfigApple
}

// SocialConfigSteam is configuration relevant to Steam.
type SocialConfigSteam interface {
	GetPublisherKey() string
	GetAppID() int
}

// SocialConfigFacebookInstantGame is configuration relevant to Facebook Instant Games.
type SocialConfigFacebookInstantGame interface {
	GetAppSecret() string
}

// SocialConfigFacebookLimitedLogin is configuration relevant to Facebook Limited Login.
type SocialConfigFacebookLimitedLogin interface {
	GetAppId() string
}

// SocialConfigApple is configuration relevant to Apple Sign In.
type SocialConfigApple interface {
	GetBundleId() string
}

// RuntimeConfig is configuration relevant to the Runtimes.
type RuntimeConfig interface {
	GetEnv() []string
	GetHTTPKey() string
}

type IAPConfig interface {
	GetApple() IAPAppleConfig
	GetGoogle() IAPGoogleConfig
	GetHuawei() IAPHuaweiConfig
	GetFacebookInstant() IAPFacebookInstantConfig
}

type IAPAppleConfig interface {
	GetSharedPassword() string
	GetNotificationsEndpointId() string
}

type IAPGoogleConfig interface {
	GetClientEmail() string
	GetPrivateKey() string
	GetNotificationsEndpointId() string
	GetRefundCheckPeriodMin() int
	GetPackageName() string
}

type SatoriConfig interface {
	GetUrl() string
	GetApiKeyName() string
	GetApiKey() string
	GetSigningKey() string
}

type IAPHuaweiConfig interface {
	GetPublicKey() string
	GetClientID() string
	GetClientSecret() string
}

type IAPFacebookInstantConfig interface {
	GetAppSecret() string
}

type GoogleAuthConfig interface {
	GetCredentialsJSON() string
}
