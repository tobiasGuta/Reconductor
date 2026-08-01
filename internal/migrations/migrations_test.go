package migrations

import (
	"context"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEmbeddedMigrationsAreOrderedAndNonDestructive(t *testing.T) {
	versions, err := Versions()
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 9 {
		t.Fatalf("migrations=%v", versions)
	}
	for _, name := range versions {
		body, err := files.ReadFile("sql/" + name)
		if err != nil {
			t.Fatal(err)
		}
		sql := strings.ToUpper(string(body))
		for _, forbidden := range []string{"DROP TABLE", "TRUNCATE ", "DELETE FROM FINDINGS", "DELETE FROM ENDPOINTS"} {
			if strings.Contains(sql, forbidden) {
				t.Fatalf("migration %s contains destructive statement %q", name, forbidden)
			}
		}
	}
}

func TestSchedulerRecoveryProtocolBackfillsExistingExecutions(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "migration_backfill_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop migration test schema: %v", err)
		}
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	pool, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	applyEmbeddedMigrationsThrough(t, ctx, pool, 8)

	const (
		programID   = "00000000-0000-4000-8000-000000000901"
		scheduleID  = "00000000-0000-4000-8000-000000000902"
		executionID = "00000000-0000-4000-8000-000000000903"
	)
	if _, err := pool.Exec(ctx, `INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,'migration-backfill','integration','synthetic://local','integration')`, programID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO schedules(id,program_id,name,workflow_name,objective,cron_expression,timezone,created_by,next_run_at) VALUES($1,$2,'migration-backfill','continuous-web-recon','migration backfill','0 9 * * *','UTC','integration',clock_timestamp()+interval '1 hour')`, scheduleID, programID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scheduled_executions(id,schedule_id,planned_at,trigger_source,status) VALUES($1,$2,clock_timestamp(),'run_now','pending')`, executionID, scheduleID); err != nil {
		t.Fatal(err)
	}
	var columnExists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='scheduled_executions' AND column_name='recovery_protocol_version')`).Scan(&columnExists); err != nil {
		t.Fatal(err)
	}
	if columnExists {
		t.Fatal("recovery protocol column existed before migration 0009")
	}
	if err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var protocol int
	if err := pool.QueryRow(ctx, `SELECT recovery_protocol_version FROM scheduled_executions WHERE id=$1`, executionID).Scan(&protocol); err != nil {
		t.Fatal(err)
	}
	if protocol != 0 {
		t.Fatalf("backfilled recovery protocol=%d want=0", protocol)
	}
}

func applyEmbeddedMigrationsThrough(t *testing.T, ctx context.Context, pool *pgxpool.Pool, maximum int64) {
	t.Helper()
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	versions, err := Versions()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range versions {
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			t.Fatalf("migration %s has no numeric prefix", name)
		}
		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if version > maximum {
			continue
		}
		body, err := files.ReadFile("sql/" + name)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("apply migration %s: %v", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version,name) VALUES($1,$2)`, version, name); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}
