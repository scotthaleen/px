package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/pressly/goose/v3"
	"github.com/scotthaleen/go-toolbelt/sqlite"
)

type Kind string

const (
	KindAgent  Kind = "agent"
	KindServer Kind = "server"
)

//go:embed migrations/agent/*.sql migrations/server/*.sql
var migrationFiles embed.FS

func Config(kind Kind, path string) (sqlite.Config, error) {
	migrate, err := Migrator(kind)
	if err != nil {
		return sqlite.Config{}, err
	}
	return sqlite.Config{
		DSN:          DSN(path),
		Migrate:      migrate,
		MaxOpenConns: 1,
		MaxIdleConns: 1,
	}, nil
}

func Migrator(kind Kind) (sqlite.Migrator, error) {
	sub, err := fs.Sub(migrationFiles, filepath.ToSlash(filepath.Join("migrations", string(kind))))
	if err != nil {
		return nil, fmt.Errorf("load %s migrations: %w", kind, err)
	}
	return func(ctx context.Context, db *sql.DB) error {
		provider, err := goose.NewProvider(
			goose.DialectSQLite3,
			db,
			sub,
			goose.WithDisableGlobalRegistry(true),
		)
		if err != nil {
			return fmt.Errorf("create %s migration provider: %w", kind, err)
		}
		if _, err := provider.Up(ctx); err != nil {
			return fmt.Errorf("apply %s migrations: %w", kind, err)
		}
		return nil
	}, nil
}

func DSN(path string) string {
	databasePath := filepath.ToSlash(path)
	if len(path) >= 3 && isASCIILetter(path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
		// A leading slash keeps the drive letter in the URI path instead of
		// making it an authority, which modernc SQLite rejects.
		databasePath = "/" + strings.ReplaceAll(path, `\`, "/")
	}
	u := url.URL{Scheme: "file", Path: databasePath}
	query := u.Query()
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "journal_mode(WAL)")
	u.RawQuery = query.Encode()
	return u.String()
}

func isASCIILetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
