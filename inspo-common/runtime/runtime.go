// Copyright 2019 The Nakama Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package runtime is an API to interact with the embedded Runtime environment in Nakama.

The game server includes support to develop native code in Go with the plugin package from the Go stdlib.
It's used to enable compiled shared objects to be loaded by the game server at startup.

The Go runtime support can be used to develop authoritative multiplayer match handlers,
RPC functions, hook into messages processed by the server, and extend the server with any other custom logic.
It offers the same capabilities as the Lua runtime support but has the advantage that any package from the Go ecosystem can be used.

Here's the smallest example of a Go module written with the server runtime.

	package main

	import (
		"context"
		"database/sql"
		"log"

		"github.com/heroiclabs/nakama-common/runtime"
	)

	func InitModule(ctx context.Context, logger Logger, db *sql.DB, nk runtime.NakamaModule, initializer runtime.Initializer) error {
		if err := initializer.RegisterRpc("get_time", getServerTime); err != nil {
			return err
		}
		logger.Println("module loaded")
		return nil
	}

	func getServerTime(ctx context.Context, logger Logger, db *sql.DB, nk runtime.NakamaModule, payload string) (string, error) {
		serverTime := map[string]int64 {
			"time": time.Now().UTC().Unix(),
		}

		response, err := json.Marshal(serverTime)
		if err != nil {
			logger.Printf("failed to marshal response: %v", response)
			return "", errors.New("internal error; see logs")
		}
		return string(response), nil
	}

On server start, Nakama scans the module directory folder (https://heroiclabs.com/docs/runtime-code-basics/#load-modules).
If it finds a shared object file (*.so), it attempts to open the file as a plugin and initialize it by running the InitModule function.
This function is guaranteed to ever be invoked once during the uptime of the server.

To setup your own project to build modules for the game server you can follow these steps.

 1. Build Nakama from source:
    go get -d github.com/heroiclabs/nakama-common
    cd $GOPATH/src/github.com/heroiclabs/nakama-common
    env CGO_ENABLED=1 go build

 2. Setup a folder for your own server code:
    mkdir -p $GOPATH/src/some_project
    cd $GOPATH/src/some_project

 3. Build your plugin as a shared object:
    go build --buildmode=plugin -o ./modules/some_project.so

NOTE: It is not possible to build plugins on Windows with the native compiler toolchain but they can be cross-compiled and run with Docker.

 4. Start Nakama with your module:
    $GOPATH/src/github.com/heroiclabs/nakama-common/nakama --runtime.path $GOPATH/src/plugin_project/modules

TIP: You don't have to install Nakama from source but you still need to have the `api`, `rtapi` and `runtime` packages from Nakama on your `GOPATH`. Heroic Labs also offers a docker plugin-builder image that streamlines the plugin workflow.

For more information about the Go runtime have a look at the docs:
https://heroiclabs.com/docs/runtime-code-basics
*/
package runtime

import (
	"context"
	"errors"
)

const (
	// All available environmental variables made available to the runtime environment.
	// This is useful to store API keys and other secrets which may be different between servers run in production and in development.
	//   envs := ctx.Value(runtime.RUNTIME_CTX_ENV).(map[string]string)
	// This can always be safely cast into a `map[string]string`.
	RUNTIME_CTX_ENV = "env"

	// The mode associated with the execution context. It's one of these values:
	//  "event", "run_once", "rpc", "before", "after", "match", "matchmaker", "leaderboard_reset", "tournament_reset", "tournament_end".
	RUNTIME_CTX_MODE = "execution_mode"

	// The node ID where the current runtime context is executing.
	RUNTIME_CTX_NODE = "node"

	// Server version.
	RUNTIME_CTX_VERSION = "version"

	// Http headers. Only applicable to HTTP RPC requests.
	RUNTIME_CTX_HEADERS = "headers"

	// Query params that was passed through from HTTP request.
	RUNTIME_CTX_QUERY_PARAMS = "query_params"

	// The user ID associated with the execution context.
	RUNTIME_CTX_USER_ID = "user_id"

	// The username associated with the execution context.
	RUNTIME_CTX_USERNAME = "username"

	// Variables stored in the user's session token.
	RUNTIME_CTX_VARS = "vars"

	// The user session expiry in seconds associated with the execution context.
	RUNTIME_CTX_USER_SESSION_EXP = "user_session_exp"

	// The user session associated with the execution context.
	RUNTIME_CTX_SESSION_ID = "session_id"

	// The user session's lang value, if one is set.
	RUNTIME_CTX_LANG = "lang"

	// The IP address of the client making the request.
	RUNTIME_CTX_CLIENT_IP = "client_ip"

	// The port number of the client making the request.
	RUNTIME_CTX_CLIENT_PORT = "client_port"

	// The match ID that is currently being executed. Only applicable to server authoritative multiplayer.
	RUNTIME_CTX_MATCH_ID = "match_id"

	// The node ID that the match is being executed on. Only applicable to server authoritative multiplayer.
	RUNTIME_CTX_MATCH_NODE = "match_node"

	// Labels associated with the match. Only applicable to server authoritative multiplayer.
	RUNTIME_CTX_MATCH_LABEL = "match_label"

	// Tick rate defined for this match. Only applicable to server authoritative multiplayer.
	RUNTIME_CTX_MATCH_TICK_RATE = "match_tick_rate"
)

var (
	ErrStorageRejectedVersion    = errors.New("Storage write rejected - version check failed.")
	ErrStorageRejectedPermission = errors.New("Storage write rejected - permission denied.")

	ErrChannelIDInvalid     = errors.New("invalid channel id")
	ErrChannelCursorInvalid = errors.New("invalid channel cursor")
	ErrChannelGroupNotFound = errors.New("group not found")

	ErrInvalidChannelTarget = errors.New("Invalid channel target")
	ErrInvalidChannelType   = errors.New("Invalid channel type")

	ErrFriendInvalidCursor = errors.New("friend cursor invalid")

	ErrLeaderboardNotFound = errors.New("leaderboard not found")

	ErrTournamentNotFound                = errors.New("tournament not found")
	ErrTournamentAuthoritative           = errors.New("tournament only allows authoritative submissions")
	ErrTournamentMaxSizeReached          = errors.New("tournament max size reached")
	ErrTournamentOutsideDuration         = errors.New("tournament outside of duration")
	ErrTournamentWriteMaxNumScoreReached = errors.New("max number score count reached")
	ErrTournamentWriteJoinRequired       = errors.New("required to join before writing tournament record")

	ErrMatchmakerQueryInvalid     = errors.New("matchmaker query invalid")
	ErrMatchmakerDuplicateSession = errors.New("matchmaker duplicate session")
	ErrMatchmakerIndex            = errors.New("matchmaker index error")
	ErrMatchmakerDelete           = errors.New("matchmaker delete error")
	ErrMatchmakerNotAvailable     = errors.New("matchmaker not available")
	ErrMatchmakerTooManyTickets   = errors.New("matchmaker too many tickets")
	ErrMatchmakerTicketNotFound   = errors.New("matchmaker ticket not found")

	ErrPartyClosed                   = errors.New("party closed")
	ErrPartyFull                     = errors.New("party full")
	ErrPartyJoinRequestDuplicate     = errors.New("party join request duplicate")
	ErrPartyJoinRequestAlreadyMember = errors.New("party join request already member")
	ErrPartyJoinRequestsFull         = errors.New("party join requests full")
	ErrPartyNotLeader                = errors.New("party leader only")
	ErrPartyNotMember                = errors.New("party member not found")
	ErrPartyNotRequest               = errors.New("party join request not found")
	ErrPartyAcceptRequest            = errors.New("party could not accept request")
	ErrPartyRemove                   = errors.New("party could not remove")
	ErrPartyRemoveSelf               = errors.New("party cannot remove self")

	ErrGracePeriodExpired = errors.New("grace period expired")

	ErrGroupNameInUse         = errors.New("group name in use")
	ErrGroupPermissionDenied  = errors.New("group permission denied")
	ErrGroupNoUpdateOps       = errors.New("no group updates")
	ErrGroupNotUpdated        = errors.New("group not updated")
	ErrGroupNotFound          = errors.New("group not found")
	ErrGroupFull              = errors.New("group is full")
	ErrGroupUserNotFound      = errors.New("user not found")
	ErrGroupLastSuperadmin    = errors.New("user is last group superadmin")
	ErrGroupUserInvalidCursor = errors.New("group user cursor invalid")
	ErrUserGroupInvalidCursor = errors.New("user group cursor invalid")
	ErrGroupCreatorInvalid    = errors.New("group creator user ID not valid")

	ErrWalletLedgerInvalidCursor = errors.New("wallet ledger cursor invalid")

	ErrCannotEncodeParams    = errors.New("error creating match: cannot encode params")
	ErrCannotDecodeParams    = errors.New("error creating match: cannot decode params")
	ErrMatchIdInvalid        = errors.New("match id invalid")
	ErrMatchNotFound         = errors.New("match not found")
	ErrMatchBusy             = errors.New("match busy")
	ErrMatchStateFailed      = errors.New("match did not return state")
	ErrMatchLabelTooLong     = errors.New("match label too long, must be 0-2048 bytes")
	ErrDeferredBroadcastFull = errors.New("too many deferred message broadcasts per tick")

	ErrSatoriConfigurationInvalid = errors.New("satori configuration is invalid")
)

const (
	// Storage permission for public read, any user can read the object.
	STORAGE_PERMISSION_PUBLIC_READ = 2

	// Storage permission for owner read, only the user who owns it may access.
	STORAGE_PERMISSION_OWNER_READ = 1

	// Storage permission for no read. The object is only readable by server runtime.
	STORAGE_PERMISSION_NO_READ = 0

	// Storage permission for owner write, only the user who owns it may write.
	STORAGE_PERMISSION_OWNER_WRITE = 1

	// Storage permission for no write. The object is only writable by server runtime.
	STORAGE_PERMISSION_NO_WRITE = 0
)

/*
Error is used to indicate a failure in code. The message and code are returned to the client.
If an Error is used as response for a HTTP/gRPC request, then the server tries to use the error value as the gRPC error code. This will in turn translate to HTTP status codes.

For more information, please have a look at the following:

	https://github.com/grpc/grpc-go/blob/master/codes/codes.go
	https://github.com/grpc-ecosystem/grpc-gateway/blob/master/runtime/errors.go
	https://golang.org/pkg/net/http/
*/
type Error struct {
	Message string
	Code    int
}

// Error returns the encapsulated error message.
func (e *Error) Error() string {
	return e.Message
}

/*
NewError returns a new error. The message and code are sent directly to the client. The code field is also optionally translated to gRPC/HTTP code.

	runtime.NewError("Server unavailable", 14) // 14 = Unavailable = 503 HTTP status code
*/
func NewError(message string, code int) *Error {
	return &Error{Message: message, Code: code}
}

/*
Logger exposes a logging framework to use in modules. It exposes level-specific logging functions and a set of common functions for compatibility.
*/
type Logger interface {
	/*
		Log a message with optional arguments at DEBUG level. Arguments are handled in the manner of fmt.Printf.
	*/
	Debug(format string, v ...interface{})
	/*
		Log a message with optional arguments at INFO level. Arguments are handled in the manner of fmt.Printf.
	*/
	Info(format string, v ...interface{})
	/*
		Log a message with optional arguments at WARN level. Arguments are handled in the manner of fmt.Printf.
	*/
	Warn(format string, v ...interface{})
	/*
		Log a message with optional arguments at ERROR level. Arguments are handled in the manner of fmt.Printf.
	*/
	Error(format string, v ...interface{})
	/*
		Return a logger with the specified field set so that they are included in subsequent logging calls.
	*/
	WithField(key string, v interface{}) Logger
	/*
		Return a logger with the specified fields set so that they are included in subsequent logging calls.
	*/
	WithFields(fields map[string]interface{}) Logger
	/*
		Returns the fields set in this logger.
	*/
	Fields() map[string]interface{}
}

type NakamaModule interface {
	AuthenticateApple(ctx context.Context, token, username string, create bool) (string, string, bool, error)
	AuthenticateCustom(ctx context.Context, id, username string, create bool) (string, string, bool, error)
	AuthenticateDevice(ctx context.Context, id, username string, create bool) (string, string, bool, error)
	AuthenticateEmail(ctx context.Context, email, password, username string, create bool) (string, string, bool, error)
	AuthenticateFacebook(ctx context.Context, token string, importFriends bool, username string, create bool) (string, string, bool, error)
	AuthenticateFacebookInstantGame(ctx context.Context, signedPlayerInfo string, username string, create bool) (string, string, bool, error)
	AuthenticateGameCenter(ctx context.Context, playerID, bundleID string, timestamp int64, salt, signature, publicKeyUrl, username string, create bool) (string, string, bool, error)
	AuthenticateGoogle(ctx context.Context, token, username string, create bool) (string, string, bool, error)
	AuthenticateSteam(ctx context.Context, token, username string, create bool) (string, string, bool, error)

	AuthenticateTokenGenerate(userID, username string, exp int64, vars map[string]string) (string, int64, error)

	AccountGetId(ctx context.Context, userID string) (*api.Account, error)
	AccountsGetId(ctx context.Context, userIDs []string) ([]*api.Account, error)
	AccountUpdateId(ctx context.Context, userID, username string, metadata map[string]interface{}, displayName, timezone, location, langTag, avatarUrl string) error

	AccountDeleteId(ctx context.Context, userID string, recorded bool) error
	AccountExportId(ctx context.Context, userID string) (string, error)

	UsersGetId(ctx context.Context, userIDs []string, facebookIDs []string) ([]*api.User, error)
	UsersGetUsername(ctx context.Context, usernames []string) ([]*api.User, error)
	UsersGetFriendStatus(ctx context.Context, userID string, userIDs []string) ([]*api.Friend, error)
	UsersGetRandom(ctx context.Context, count int) ([]*api.User, error)
	UsersBanId(ctx context.Context, userIDs []string) error
	UsersUnbanId(ctx context.Context, userIDs []string) error

	LinkApple(ctx context.Context, userID, token string) error
	LinkCustom(ctx context.Context, userID, customID string) error
	LinkDevice(ctx context.Context, userID, deviceID string) error
	LinkEmail(ctx context.Context, userID, email, password string) error
	LinkFacebook(ctx context.Context, userID, username, token string, importFriends bool) error
	LinkFacebookInstantGame(ctx context.Context, userID, signedPlayerInfo string) error
	LinkGameCenter(ctx context.Context, userID, playerID, bundleID string, timestamp int64, salt, signature, publicKeyUrl string) error
	LinkGoogle(ctx context.Context, userID, token string) error
	LinkSteam(ctx context.Context, userID, username, token string, importFriends bool) error

	CronPrev(expression string, timestamp int64) (int64, error)
	CronNext(expression string, timestamp int64) (int64, error)
	ReadFile(path string) (*os.File, error)

	UnlinkApple(ctx context.Context, userID, token string) error
	UnlinkCustom(ctx context.Context, userID, customID string) error
	UnlinkDevice(ctx context.Context, userID, deviceID string) error
	UnlinkEmail(ctx context.Context, userID, email string) error
	UnlinkFacebook(ctx context.Context, userID, token string) error
	UnlinkFacebookInstantGame(ctx context.Context, userID, signedPlayerInfo string) error
	UnlinkGameCenter(ctx context.Context, userID, playerID, bundleID string, timestamp int64, salt, signature, publicKeyUrl string) error
	UnlinkGoogle(ctx context.Context, userID, token string) error
	UnlinkSteam(ctx context.Context, userID, token string) error

	StreamUserList(mode uint8, subject, subcontext, label string, includeHidden, includeNotHidden bool) ([]Presence, error)
	StreamUserGet(mode uint8, subject, subcontext, label, userID, sessionID string) (PresenceMeta, error)
	StreamUserJoin(mode uint8, subject, subcontext, label, userID, sessionID string, hidden, persistence bool, status string) (bool, error)
	StreamUserUpdate(mode uint8, subject, subcontext, label, userID, sessionID string, hidden, persistence bool, status string) error
	StreamUserLeave(mode uint8, subject, subcontext, label, userID, sessionID string) error
	StreamUserKick(mode uint8, subject, subcontext, label string, presence Presence) error
	StreamCount(mode uint8, subject, subcontext, label string) (int, error)
	StreamClose(mode uint8, subject, subcontext, label string) error
	StreamSend(mode uint8, subject, subcontext, label, data string, presences []Presence, reliable bool) error
	StreamSendRaw(mode uint8, subject, subcontext, label string, msg *rtapi.Envelope, presences []Presence, reliable bool) error

	SessionDisconnect(ctx context.Context, sessionID string, reason ...PresenceReason) error
	SessionLogout(userID, token, refreshToken string) error

	MatchCreate(ctx context.Context, module string, params map[string]interface{}) (string, error)
	MatchGet(ctx context.Context, id string) (*api.Match, error)
	MatchList(ctx context.Context, limit int, authoritative bool, label string, minSize, maxSize *int, query string) ([]*api.Match, error)
	MatchSignal(ctx context.Context, id string, data string) (string, error)

	NotificationSend(ctx context.Context, userID, subject string, content map[string]interface{}, code int, sender string, persistent bool) error
	NotificationsList(ctx context.Context, userID string, limit int, cursor string) ([]*api.Notification, string, error)
	NotificationsSend(ctx context.Context, notifications []*NotificationSend) error
	NotificationSendAll(ctx context.Context, subject string, content map[string]interface{}, code int, persistent bool) error
	NotificationsUpdate(ctx context.Context, updates ...NotificationUpdate) error
	NotificationsDelete(ctx context.Context, notifications []*NotificationDelete) error
	NotificationsGetId(ctx context.Context, userID string, ids []string) ([]*Notification, error)
	NotificationsDeleteId(ctx context.Context, userID string, ids []string) error

	WalletUpdate(ctx context.Context, userID string, changeset map[string]int64, metadata map[string]interface{}, updateLedger bool) (updated map[string]int64, previous map[string]int64, err error)
	WalletsUpdate(ctx context.Context, updates []*WalletUpdate, updateLedger bool) ([]*WalletUpdateResult, error)
	WalletLedgerUpdate(ctx context.Context, itemID string, metadata map[string]interface{}) (WalletLedgerItem, error)
	WalletLedgerList(ctx context.Context, userID string, limit int, cursor string) ([]WalletLedgerItem, string, error)

	StorageList(ctx context.Context, callerID, userID, collection string, limit int, cursor string) ([]*api.StorageObject, string, error)
	StorageRead(ctx context.Context, reads []*StorageRead) ([]*api.StorageObject, error)
	StorageWrite(ctx context.Context, writes []*StorageWrite) ([]*api.StorageObjectAck, error)
	StorageDelete(ctx context.Context, deletes []*StorageDelete) error
	StorageIndexList(ctx context.Context, callerID, indexName, query string, limit int, order []string, cursor string) (*api.StorageObjects, string, error)

	MultiUpdate(ctx context.Context, accountUpdates []*AccountUpdate, storageWrites []*StorageWrite, storageDeletes []*StorageDelete, walletUpdates []*WalletUpdate, updateLedger bool) ([]*api.StorageObjectAck, []*WalletUpdateResult, error)

	LeaderboardCreate(ctx context.Context, id string, authoritative bool, sortOrder, operator, resetSchedule string, metadata map[string]interface{}, enableRanks bool) error
	LeaderboardDelete(ctx context.Context, id string) error
	LeaderboardList(limit int, cursor string) (*api.LeaderboardList, error)
	LeaderboardRanksDisable(ctx context.Context, id string) error
	LeaderboardRecordsList(ctx context.Context, id string, ownerIDs []string, limit int, cursor string, expiry int64) (records []*api.LeaderboardRecord, ownerRecords []*api.LeaderboardRecord, nextCursor string, prevCursor string, err error)
	LeaderboardRecordsListCursorFromRank(id string, rank, overrideExpiry int64) (string, error)
	LeaderboardRecordWrite(ctx context.Context, id, ownerID, username string, score, subscore int64, metadata map[string]interface{}, overrideOperator *int) (*api.LeaderboardRecord, error)
	LeaderboardRecordDelete(ctx context.Context, id, ownerID string) error
	LeaderboardsGetId(ctx context.Context, ids []string) ([]*api.Leaderboard, error)
	LeaderboardRecordsHaystack(ctx context.Context, id, ownerID string, limit int, cursor string, expiry int64) (*api.LeaderboardRecordList, error)

	PurchaseValidateApple(ctx context.Context, userID, receipt string, persist bool, passwordOverride ...string) (*api.ValidatePurchaseResponse, error)
	PurchaseValidateGoogle(ctx context.Context, userID, receipt string, persist bool, overrides ...struct {
		ClientEmail string
		PrivateKey  string
	}) (*api.ValidatePurchaseResponse, error)
	PurchaseValidateHuawei(ctx context.Context, userID, signature, inAppPurchaseData string, persist bool) (*api.ValidatePurchaseResponse, error)
	PurchaseValidateFacebookInstant(ctx context.Context, userID, signedRequest string, persist bool) (*api.ValidatePurchaseResponse, error)
	PurchasesList(ctx context.Context, userID string, limit int, cursor string) (*api.PurchaseList, error)
	PurchaseGetByTransactionId(ctx context.Context, transactionID string) (*api.ValidatedPurchase, error)

	SubscriptionValidateApple(ctx context.Context, userID, receipt string, persist bool, passwordOverride ...string) (*api.ValidateSubscriptionResponse, error)
	SubscriptionValidateGoogle(ctx context.Context, userID, receipt string, persist bool, overrides ...struct {
		ClientEmail string
		PrivateKey  string
	}) (*api.ValidateSubscriptionResponse, error)
	SubscriptionsList(ctx context.Context, userID string, limit int, cursor string) (*api.SubscriptionList, error)
	SubscriptionGetByProductId(ctx context.Context, userID, productID string) (*api.ValidatedSubscription, error)

	TournamentCreate(ctx context.Context, id string, authoritative bool, sortOrder, operator, resetSchedule string, metadata map[string]interface{}, title, description string, category, startTime, endTime, duration, maxSize, maxNumScore int, joinRequired, enableRanks bool) error
	TournamentDelete(ctx context.Context, id string) error
	TournamentAddAttempt(ctx context.Context, id, ownerID string, count int) error
	TournamentJoin(ctx context.Context, id, ownerID, username string) error
	TournamentsGetId(ctx context.Context, tournamentIDs []string) ([]*api.Tournament, error)
	TournamentList(ctx context.Context, categoryStart, categoryEnd, startTime, endTime, limit int, cursor string) (*api.TournamentList, error)
	TournamentRanksDisable(ctx context.Context, id string) error
	TournamentRecordsList(ctx context.Context, tournamentId string, ownerIDs []string, limit int, cursor string, overrideExpiry int64) (records []*api.LeaderboardRecord, ownerRecords []*api.LeaderboardRecord, prevCursor string, nextCursor string, err error)
	TournamentRecordWrite(ctx context.Context, id, ownerID, username string, score, subscore int64, metadata map[string]interface{}, operatorOverride *int) (*api.LeaderboardRecord, error)
	TournamentRecordDelete(ctx context.Context, id, ownerID string) error
	TournamentRecordsHaystack(ctx context.Context, id, ownerID string, limit int, cursor string, expiry int64) (*api.TournamentRecordList, error)

	GroupsGetId(ctx context.Context, groupIDs []string) ([]*api.Group, error)
	GroupCreate(ctx context.Context, userID, name, creatorID, langTag, description, avatarUrl string, open bool, metadata map[string]interface{}, maxCount int) (*api.Group, error)
	GroupUpdate(ctx context.Context, id, userID, name, creatorID, langTag, description, avatarUrl string, open bool, metadata map[string]interface{}, maxCount int) error
	GroupDelete(ctx context.Context, id string) error
	GroupUserJoin(ctx context.Context, groupID, userID, username string) error
	GroupUserLeave(ctx context.Context, groupID, userID, username string) error
	GroupUsersAdd(ctx context.Context, callerID, groupID string, userIDs []string) error
	GroupUsersBan(ctx context.Context, callerID, groupID string, userIDs []string) error
	GroupUsersKick(ctx context.Context, callerID, groupID string, userIDs []string) error
	GroupUsersPromote(ctx context.Context, callerID, groupID string, userIDs []string) error
	GroupUsersDemote(ctx context.Context, callerID, groupID string, userIDs []string) error
	GroupUsersList(ctx context.Context, id string, limit int, state *int, cursor string) ([]*api.GroupUserList_GroupUser, string, error)
	GroupsList(ctx context.Context, name, langTag string, members *int, open *bool, limit int, cursor string) ([]*api.Group, string, error)
	GroupsGetRandom(ctx context.Context, count int) ([]*api.Group, error)
	UserGroupsList(ctx context.Context, userID string, limit int, state *int, cursor string) ([]*api.UserGroupList_UserGroup, string, error)

	FriendMetadataUpdate(ctx context.Context, userID string, friendUserId string, metadata map[string]any) error
	FriendsList(ctx context.Context, userID string, limit int, state *int, cursor string) ([]*api.Friend, string, error)
	FriendsOfFriendsList(ctx context.Context, userID string, limit int, cursor string) ([]*api.FriendsOfFriendsList_FriendOfFriend, string, error)
	FriendsAdd(ctx context.Context, userID string, username string, ids []string, usernames []string, metadata map[string]any) error
	FriendsDelete(ctx context.Context, userID string, username string, ids []string, usernames []string) error
	FriendsBlock(ctx context.Context, userID string, username string, ids []string, usernames []string) error

	Event(ctx context.Context, evt *api.Event) error

	MetricsCounterAdd(name string, tags map[string]string, delta int64)
	MetricsGaugeSet(name string, tags map[string]string, value float64)
	MetricsTimerRecord(name string, tags map[string]string, value time.Duration)

	ChannelIdBuild(ctx context.Context, sender string, target string, chanType ChannelType) (string, error)
	ChannelMessageSend(ctx context.Context, channelID string, content map[string]interface{}, senderId, senderUsername string, persist bool) (*rtapi.ChannelMessageAck, error)
	ChannelMessageUpdate(ctx context.Context, channelID, messageID string, content map[string]interface{}, senderId, senderUsername string, persist bool) (*rtapi.ChannelMessageAck, error)
	ChannelMessageRemove(ctx context.Context, channelId, messageId string, senderId, senderUsername string, persist bool) (*rtapi.ChannelMessageAck, error)
	ChannelMessagesList(ctx context.Context, channelId string, limit int, forward bool, cursor string) (messages []*api.ChannelMessage, nextCursor string, prevCursor string, err error)

	StatusFollow(sessionID string, userIDs []string) error
	StatusUnfollow(sessionID string, userIDs []string) error

	GetSatori() Satori
	GetFleetManager() FleetManager
}
