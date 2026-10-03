package migrations

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type schemaDBStub struct {
	version int64
	name    string
	err     error
	query   string
	args    []any
	queries int
}

func (s *schemaDBStub) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	s.query = query
	s.args = append([]any(nil), args...)
	s.queries++
	return schemaRowStub{version: s.version, name: s.name, err: s.err}
}

type schemaRowStub struct {
	version int64
	name    string
	err     error
}

func (r schemaRowStub) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 2 {
		return errors.New("unexpected schema row destination count")
	}
	version, ok := dest[0].(*int64)
	if !ok {
		return errors.New("unexpected schema version destination type")
	}
	name, ok := dest[1].(*string)
	if !ok {
		return errors.New("unexpected schema name destination type")
	}
	*version = r.version
	*name = r.name
	return nil
}

func TestRequireCurrentAcceptsOnlyNewestExactMigration(t *testing.T) {
	db := &schemaDBStub{version: 23, name: "0023_exact_action_contract.sql"}
	if err := RequireCurrent(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if db.queries != 1 || !strings.Contains(db.query, "SELECT version,name FROM schema_migrations ORDER BY version DESC LIMIT 1") || len(db.args) != 0 {
		t.Fatalf("schema query count=%d query=%q args=%v", db.queries, db.query, db.args)
	}
}

func TestRequireCurrentFailsClosedWithoutMutatingSchema(t *testing.T) {
	for _, test := range []struct {
		name       string
		version    int64
		applied    string
		queryError error
	}{
		{name: "missing ledger row", queryError: pgx.ErrNoRows},
		{name: "behind embedded schema", version: 18, applied: "0018_large_result_publication_journal.sql"},
		{name: "ahead of embedded schema", version: 24, applied: "0024_future.sql"},
		{name: "wrong migration name", version: 22, applied: "0022_wrong.sql"},
		{name: "query failure", queryError: errors.New("schema ledger unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := &schemaDBStub{version: test.version, name: test.applied, err: test.queryError}
			err := RequireCurrent(context.Background(), db)
			if !errors.Is(err, ErrSchemaNotCurrent) {
				t.Fatalf("RequireCurrent error=%v", err)
			}
			if db.queries != 1 {
				t.Fatalf("schema queries=%d want=1", db.queries)
			}
		})
	}
}

func TestArtifactStoreMigrationUsesDefaultsWithoutHistoricalRewrite(t *testing.T) {
	body, err := files.ReadFile("sql/0016_artifact_store_ownership.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.ToUpper(string(body))
	if strings.Contains(sql, "UPDATE ARTIFACTS") {
		t.Fatal("migration 0016 rewrites historical Artifact rows")
	}
	legacyDefault := strings.Index(sql, "ADD COLUMN ADDRESSING_VERSION SMALLINT NOT NULL DEFAULT 0")
	modernDefault := strings.Index(sql, "ALTER COLUMN ADDRESSING_VERSION SET DEFAULT 1")
	if legacyDefault < 0 || modernDefault < 0 || legacyDefault >= modernDefault {
		t.Fatalf("addressing defaults are missing or out of order: legacy=%d modern=%d", legacyDefault, modernDefault)
	}
	if strings.Contains(sql, "UPDATE ARTIFACTS SET STORAGE_LOCATION") {
		t.Fatal("migration 0016 rewrites historical storage locations")
	}
}
