package server

import (
	"context"
	"database/sql"
	"errors"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrSessionTokenInvalid = errors.New("session token invalid")
	ErrRefreshTokenInvalid = errors.New("refresh token invalid")
)

func SessionRefresh(ctx context.Context, logger *zap.Logger, db *sql.DB, config Config, sessionCache SessionCache, token string) (uuid.UUID, string, map[string]string, string, int64, error) {
	userID, _, vars, exp, tokenId, tokenIssuedAt, ok := parseToken([]byte(config.GetSession().RefreshEncryptionKey), token)
	if !ok {
		return uuid.Nil, "", nil, "", 0, status.Error(codes.Unauthenticated, "Refresh token invalid or expired.")
	}
	if !sessionCache.IsValidRefresh(userID, exp, tokenId) {
		return uuid.Nil, "", nil, "", 0, status.Error(codes.Unauthenticated, "Refresh token invalid or expired.")
	}

	// Look for an existing account.
	query := "SELECT username, disable_time FROM users WHERE id = $1 LIMIT 1"
	var dbUsername string
	var dbDisableTime pgtype.Timestamptz
	err := db.QueryRowContext(ctx, query, userID).Scan(&dbUsername, &dbDisableTime)
	if err != nil {
		if err == sql.ErrNoRows {
			// Account not found and creation is never allowed for this type.
			return uuid.Nil, "", nil, "", 0, status.Error(codes.NotFound, "User account not found.")
		}
		logger.Error("Error looking up user by ID.", zap.Error(err), zap.String("id", userID.String()))
		return uuid.Nil, "", nil, "", 0, status.Error(codes.Internal, "Error finding user account.")
	}

	// Check if it's disabled.
	if dbDisableTime.Valid && dbDisableTime.Time.Unix() != 0 {
		logger.Info("User account is disabled.", zap.String("id", userID.String()))
		return uuid.Nil, "", nil, "", 0, status.Error(codes.PermissionDenied, "User account banned.")
	}

	return userID, dbUsername, vars, tokenId, tokenIssuedAt, nil
}

func SessionLogout(config Config, sessionCache SessionCache, userID uuid.UUID, token, refreshToken string) error {
	var maybeSessionExp int64
	var maybeSessionTokenId string
	if token != "" {
		var sessionUserID uuid.UUID
		var ok bool
		sessionUserID, _, _, maybeSessionExp, maybeSessionTokenId, _, ok = parseToken([]byte(config.GetSession().EncryptionKey), token)
		if !ok || sessionUserID != userID {
			return ErrSessionTokenInvalid
		}
	}

	var maybeRefreshExp int64
	var maybeRefreshTokenId string
	if refreshToken != "" {
		var refreshUserID uuid.UUID
		var ok bool
		refreshUserID, _, _, maybeRefreshExp, maybeRefreshTokenId, _, ok = parseToken([]byte(config.GetSession().RefreshEncryptionKey), refreshToken)
		if !ok || refreshUserID != userID {
			return ErrRefreshTokenInvalid
		}
	}

	if maybeSessionTokenId == "" && maybeRefreshTokenId == "" {
		sessionCache.RemoveAll(userID)
		return nil
	}

	sessionCache.Remove(userID, maybeSessionExp, maybeSessionTokenId, maybeRefreshExp, maybeRefreshTokenId)
	return nil
}
