package migrate

import (
	"context"
	"embed"
	"time"

	"github.com/martbul/server"
	"go.uber.org/zap"
)

const (
	migrationTable = "migration_info"
	defaultLimit   = -1
)

//go:embed sql/*
var sqlMigrateFS embed.FS

type statusRow struct {
	ID        string
	Migrated  bool
	Unknown   bool
	AppliedAt time.Time
}

type migrationService struct {
	limit        int
	loggerFormat server.LoggingFormat
	migrations   *sqlmigrate.EmbedFileSystemMigrationSource
	execFn       func(ctx context.Context, logger *zap.Logger, db *pgx.Conn)
}

