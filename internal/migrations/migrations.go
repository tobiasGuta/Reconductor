package migrations

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

//go:embed sql/*.sql
var files embed.FS

type DB interface {
	Begin(context.Context) (pgx.Tx, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

type SchemaDB interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

var ErrSchemaNotCurrent = errors.New("database schema is not current")

func Up(ctx context.Context, db DB) error {
	if _, err := db.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	entries, err := fs.ReadDir(files, "sql")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			return fmt.Errorf("migration %s has no numeric prefix", entry.Name())
		}
		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			return fmt.Errorf("migration %s: %w", entry.Name(), err)
		}
		tx, err := db.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7212026)`); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("acquire migration lock: %w", err)
		}
		var applied bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&applied); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if applied {
			tx.Rollback(ctx)
			continue
		}
		body, err := files.ReadFile("sql/" + entry.Name())
		if err != nil {
			tx.Rollback(ctx)
			return err
		}
		if _, err = tx.Exec(ctx, string(body)); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version,name) VALUES($1,$2)`, version, entry.Name()); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err = tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// RequireCurrent verifies the newest embedded migration without changing the
// database. Runtime commands use this fail-closed check; only the explicit
// administrative migration command may call Up.
func RequireCurrent(ctx context.Context, db SchemaDB) error {
	version, name, err := requiredMigration()
	if err != nil {
		return err
	}
	var appliedVersion int64
	var appliedName string
	if err := db.QueryRow(ctx, `SELECT version,name FROM schema_migrations ORDER BY version DESC LIMIT 1`).Scan(&appliedVersion, &appliedName); err != nil {
		return fmt.Errorf("%w: required migration %d (%s) is not the current schema frontier: %v; run platform migrate as a coordinated administrative action", ErrSchemaNotCurrent, version, name, err)
	}
	if appliedVersion != version || appliedName != name {
		return fmt.Errorf("%w: schema frontier is %d (%s), want %d (%s)", ErrSchemaNotCurrent, appliedVersion, appliedName, version, name)
	}
	return nil
}

func requiredMigration() (int64, string, error) {
	versions, err := Versions()
	if err != nil {
		return 0, "", err
	}
	if len(versions) == 0 {
		return 0, "", fmt.Errorf("no embedded migrations")
	}
	name := versions[len(versions)-1]
	prefix, _, ok := strings.Cut(name, "_")
	if !ok {
		return 0, "", fmt.Errorf("migration %s has no numeric prefix", name)
	}
	version, err := strconv.ParseInt(prefix, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("migration %s: %w", name, err)
	}
	return version, name, nil
}

func Versions() ([]string, error) {
	entries, err := fs.ReadDir(files, "sql")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}
