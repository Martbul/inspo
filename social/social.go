package social

import (
	"crypto/rsa"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// Client is responsible for making calls to different providers
type Client struct {
	logger *zap.Logger

	client *http.Client

	googleMutex          sync.RWMutex
	googleCerts          []*rsa.PublicKey
	googleCertsRefreshAt int

	facebookMutex          sync.Mutex
	facebookCerts          map[string]*JwksCert
	facebookCertsRefreshAt int64

	appleMutex          sync.RWMutex
	appleCerts          map[string]*JwksCert
	appleCertsRefreshAt int64

	config *oauth2.Config
}

type JwksCerts struct {
	Keys []*JwksCert `json:"keys"`
}

// JWK certificate data for an Apple Sign In verification key.
type JwksCert struct {
	key *rsa.PublicKey

	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// AppleProfile is an abbreviated version of a user authenticated through Apple Sign In.
type AppleProfile struct {
	ID            string
	Email         string
	EmailVerified bool
}

// FacebookProfile is an abbreviated version of a Facebook profile.
type FacebookProfile struct {
	ID      string              `json:"id"`
	Name    string              `json:"name"`
	Email   string              `json:"email"`
	Picture FacebookPictureData `json:"picture"`
}

type FacebookPictureData struct {
	Data FacebookPicture `json:"data"`
}

type FacebookPicture struct {
	Height       int    `json:"height"`
	Width        int    `json:"width"`
	IsSilhouette bool   `json:"is_silhouette"`
	Url          string `json:"url"`
}

type facebookPagingCursors struct {
	After  string `json:"after"`
	Before string `json:"before"`
}

type facebookPaging struct {
	Cursors  facebookPagingCursors `json:"cursors"`
	Previous string                `json:"previous"`
	Next     string                `json:"next"`
}

type facebookFriends struct {
	Paging facebookPaging    `json:"paging"`
	Data   []FacebookProfile `json:"data"`
}

// GoogleProfile is an abbreviated version of a Google profile extracted from a token.
type GoogleProfile interface {
	GetDisplayName() string
	GetEmail() string
	GetAvatarImageUrl() string
	GetGoogleId() string
	GetOriginalGoogleId() string
}

// JWTGoogleProfile is an abbreviated version of a Google profile extracted from a verified JWT token.
type JWTGoogleProfile struct {
	// Fields available in all tokens.
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Azp string `json:"azp"`
	Aud string `json:"aud"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	// Fields available only if the user granted the "profile" and "email" OAuth scopes.
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Locale        string `json:"locale"`
}

func (p *JWTGoogleProfile) GetDisplayName() string {
	return p.Name
}

func (p *JWTGoogleProfile) GetEmail() string {
	return p.Email
}
func (p *JWTGoogleProfile) GetAvatarImageUrl() string {
	return p.Picture
}
func (p *JWTGoogleProfile) GetGoogleId() string {
	return p.Sub
}

func (p *JWTGoogleProfile) GetOriginalGoogleId() string {
	// Dummy implementation
	return ""
}

// GooglePlayServiceProfile is an abbreviated version of a Google profile using an access token.
type GooglePlayServiceProfile struct {
	PlayerId         string `json:"playerId"`
	DisplayName      string `json:"displayName"`
	AvatarImageUrl   string `json:"avatarImageUrl"`
	OriginalPlayerId string `json:"originalPlayerId"`
}

func (p *GooglePlayServiceProfile) GetDisplayName() string {
	return p.DisplayName
}

func (p *GooglePlayServiceProfile) GetEmail() string {
	return "" // The API doesn't expose the email.
}
func (p *GooglePlayServiceProfile) GetAvatarImageUrl() string {
	return p.AvatarImageUrl
}
func (p *GooglePlayServiceProfile) GetGoogleId() string {
	return p.PlayerId
}
func (p *GooglePlayServiceProfile) GetOriginalGoogleId() string {
	return p.OriginalPlayerId
}

// SteamProfile is an abbreviated version of a Steam profile.
type SteamProfile struct {
	SteamID uint64 `json:"steamid,string"`
}

type steamFriends struct {
	Friends []SteamProfile `json:"friends"`
}

type steamFriendsWrapper struct {
	FriendsList steamFriends `json:"friendsList"`
}

// SteamError contains a possible error response from the Steam Web API.
type SteamError struct {
	ErrorDesc string `json:"errordesc"`
	ErrorCode int    `json:"errorcode"`
}

// Unwrapping the SteamProfile
type SteamProfileWrapper struct {
	Response struct {
		Params *SteamProfile `json:"params"`
		Error  *SteamError   `json:"error"`
	} `json:"response"`
}

// NewClient creates a new Social Client
func NewClient(logger *zap.Logger, timeout time.Duration, googleCnf *oauth2.Config) *Client {
	return &Client{
		logger: logger,

		client: &http.Client{
			Timeout: timeout,
		},

		config: googleCnf,
	}
}
