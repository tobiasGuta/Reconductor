package migrations

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestArtifactCleanupMigration(t *testing.T) {
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
	schema := "migration_artifact_cleanup_" + strconv.FormatInt(time.Now().UnixNano(), 10)
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

	// Step 1: Start at schema 15
	applyEmbeddedMigrationsThrough(t, ctx, pool, 15)

	const (
		programID      = "00000000-0000-4000-8000-000000001700"
		scopeVersionID = "00000000-0000-4000-8000-000000001713"
		definitionID   = "00000000-0000-4000-8000-000000001701"
		taskID         = "00000000-0000-4000-8000-000000001702"
		runID          = "00000000-0000-4000-8000-000000001703"
		stepID         = "00000000-0000-4000-8000-000000001704"
		toolID         = "00000000-0000-4000-8000-000000001705"
		storeID        = "00000000-0000-4000-8000-000000001706"
		storeNonce     = "00000000-0000-4000-8000-000000001707"
		legacyID       = "00000000-0000-4000-8000-000000001708"
		modernID       = "00000000-0000-4000-8000-000000001709"
	)
	digest := strings.Repeat("a", 64)

	// Step 2: Insert valid lineage and pre-0016 historical artifact at schema 15
	for _, statement := range []string{
		`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES('` + programID + `','artifact-cleanup-migration','integration','synthetic://local','integration')`,
		`INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,target_plan_digest,target_plan) VALUES('` + scopeVersionID + `','` + programID + `','synthetic://local','` + digest + `','` + digest + `','{}')`,
		`INSERT INTO workflow_definitions(id,name,version,definition) VALUES('` + definitionID + `','artifact-cleanup-migration','1','{}')`,
		`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES('` + taskID + `','` + programID + `','cleanup migration','` + definitionID + `','running','integration')`,
		`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source,materialized_definition,materialization_digest,original_scope_version_id) VALUES('` + runID + `','` + taskID + `','` + definitionID + `','1','running','integration','{}','` + digest + `','` + scopeVersionID + `')`,
		`INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,idempotency_key) VALUES('` + stepID + `','` + runID + `','step','test.capability','running','artifact-cleanup-migration')`,
		`INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at) VALUES('` + toolID + `','` + stepID + `','test.capability','test-provider',clock_timestamp())`,
		`INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,storage_location,redaction_state) VALUES('` + legacyID + `','` + taskID + `','` + runID + `','` + stepID + `','` + toolID + `','raw-provider-output','text/plain',1,'sha','legacy://locator','redacted')`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	// Step 3: Apply migration 0016
	applyMigration(t, ctx, pool, 16, "0016_artifact_store_ownership.sql")

	// Step 4: Register artifact store and modern v1 artifact under schema 16
	for _, statement := range []string{
		`INSERT INTO artifact_stores(id,incarnation_nonce,backend_kind,marker_format,marker_version) VALUES('` + storeID + `','` + storeNonce + `','local-v1','reconductor-artifact-store',1)`,
		`INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state,expires_at) VALUES('` + modernID + `','` + taskID + `','` + runID + `','` + stepID + `','` + toolID + `','raw-provider-output','text/plain',1,'sha',1,'` + storeID + `','v1/00/` + modernID + `','redacted',clock_timestamp()+interval '1 hour')`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	// Step 5: Apply migration 0017 without pulling later independent schema slices into this test.
	applyMigration(t, ctx, pool, 17, "0017_artifact_store_tombstone_cleanup.sql")

	// Frontier and ordering verification
	var maxVersion int
	var latestName string
	var totalMigrations int
	if err := pool.QueryRow(ctx, `SELECT max(version), count(*) FROM schema_migrations`).Scan(&maxVersion, &totalMigrations); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if maxVersion != 17 || totalMigrations != 17 {
		t.Fatalf("migrations frontier version=%d total=%d want version=17 total=17", maxVersion, totalMigrations)
	}
	if err := pool.QueryRow(ctx, `SELECT name FROM schema_migrations WHERE version=17`).Scan(&latestName); err != nil || latestName != "0017_artifact_store_tombstone_cleanup.sql" {
		t.Fatalf("migration 17 name=%q err=%v", latestName, err)
	}

	assertRejected := func(name string, query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err == nil {
			t.Fatalf("%s unexpectedly succeeded", name)
		}
	}

	assertAccepted := func(name string, query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%s failed: %v", name, err)
		}
	}

	// Verify all 8 CHECK constraints exist in schema
	for _, conname := range []string{
		"artifacts_cleanup_legacy_v0_null_ck",
		"artifacts_cleanup_claim_pair_ck",
		"artifacts_cleanup_error_code_ck",
		"artifacts_cleanup_lifecycle_address_ck",
		"artifacts_cleanup_state_shape_ck",
		"artifacts_cleanup_tombstone_time_ck",
		"artifacts_cleanup_retry_error_ck",
		"artifacts_cleanup_quarantine_error_ck",
	} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='artifacts'::regclass AND contype='c' AND conname=$1)`, conname).Scan(&exists); err != nil || !exists {
			t.Fatalf("constraint %s missing from schema", conname)
		}
	}
	var constraintCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid='artifacts'::regclass AND contype='c' AND conname LIKE 'artifacts_cleanup_%'`).Scan(&constraintCount); err != nil || constraintCount != 8 {
		t.Fatalf("cleanup CHECK count=%d want=8 err=%v", constraintCount, err)
	}
	assertCleanupConstraintSemantics(t, ctx, pool)

	// Partial index verification: structural candidate index with NO current-time predicate
	var indexDef string
	if err := pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='artifacts_cleanup_eligible_idx'`).Scan(&indexDef); err != nil {
		t.Fatalf("query artifacts_cleanup_eligible_idx indexdef: %v", err)
	}
	for _, required := range []string{
		"WHERE",
		"addressing_version = 1",
		"expires_at IS NOT NULL",
		"content_deleted_at IS NULL",
		"cleanup_quarantined_at IS NULL",
	} {
		if !strings.Contains(indexDef, required) {
			t.Fatalf("indexdef %q missing required predicate %q", indexDef, required)
		}
	}
	for _, forbidden := range []string{
		"current_timestamp",
		"now()",
		"clock_timestamp()",
		"statement_timestamp()",
		"cleanup_retry_after",
	} {
		if strings.Contains(strings.ToLower(indexDef), forbidden) {
			t.Fatalf("indexdef %q contains forbidden temporal predicate %q", indexDef, forbidden)
		}
	}
	indexParts := strings.SplitN(indexDef, " WHERE ", 2)
	if len(indexParts) != 2 || strings.NewReplacer("(", "", ")", "").Replace(indexParts[1]) != "addressing_version = 1 AND expires_at IS NOT NULL AND content_deleted_at IS NULL AND cleanup_quarantined_at IS NULL" || !strings.Contains(indexParts[0], "(artifact_store_id, expires_at, id)") {
		t.Fatalf("index differs from frozen structure: %s", indexDef)
	}

	// 1. Legacy v0 / storage_location NOT NULL cannot participate in cleanup lifecycle
	assertRejected("legacy v0 with claim", `UPDATE artifacts SET cleanup_claim_token=gen_random_uuid(),cleanup_claimed_at=now() WHERE id=$1`, legacyID)
	assertRejected("legacy v0 with tombstone", `UPDATE artifacts SET content_deleted_at=now() WHERE id=$1`, legacyID)
	assertRejected("legacy v0 with retry", `UPDATE artifacts SET cleanup_retry_after=now(),cleanup_last_error_code='filesystem_io' WHERE id=$1`, legacyID)
	assertRejected("legacy v0 with quarantine", `UPDATE artifacts SET cleanup_quarantined_at=now(),cleanup_last_error_code='unexpected_entry_type' WHERE id=$1`, legacyID)

	// 2. Lifecycle state requires expires_at non-null
	const nullExpiryID = "00000000-0000-4000-8000-000000001710"
	if _, err := pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state,expires_at) VALUES($1,$2,$3,$4,$5,'raw-provider-output','text/plain',1,'sha',1,$6,$7,'redacted',NULL)`, nullExpiryID, taskID, runID, stepID, toolID, storeID, "v1/00/"+nullExpiryID); err != nil {
		t.Fatal(err)
	}
	assertRejected("null expiry claim", `UPDATE artifacts SET cleanup_claim_token=gen_random_uuid(),cleanup_claimed_at=now() WHERE id=$1`, nullExpiryID)
	assertRejected("null expiry retry", `UPDATE artifacts SET cleanup_retry_after=now()+interval '5 minutes',cleanup_last_error_code='filesystem_io' WHERE id=$1`, nullExpiryID)
	assertRejected("null expiry tombstone", `UPDATE artifacts SET content_deleted_at=now() WHERE id=$1`, nullExpiryID)
	assertRejected("null expiry quarantine", `UPDATE artifacts SET cleanup_quarantined_at=now(),cleanup_last_error_code='unexpected_entry_type' WHERE id=$1`, nullExpiryID)

	// 3. Claim pair atomicity
	const testID = "00000000-0000-4000-8000-000000001711"
	if _, err := pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state,expires_at) VALUES($1,$2,$3,$4,$5,'raw-provider-output','text/plain',1,'sha',1,$6,$7,'redacted',clock_timestamp()-interval '1 hour')`, testID, taskID, runID, stepID, toolID, storeID, "v1/00/"+testID); err != nil {
		t.Fatal(err)
	}
	assertRejected("token without claimed_at", `UPDATE artifacts SET cleanup_claim_token=gen_random_uuid(),cleanup_claimed_at=NULL WHERE id=$1`, testID)
	assertRejected("claimed_at without token", `UPDATE artifacts SET cleanup_claim_token=NULL,cleanup_claimed_at=now() WHERE id=$1`, testID)

	// 4. Error taxonomy & state shape restrictions
	assertRejected("unknown error code", `UPDATE artifacts SET cleanup_retry_after=now(),cleanup_last_error_code='unknown_error' WHERE id=$1`, testID)
	assertRejected("invalid_storage_key error code", `UPDATE artifacts SET cleanup_retry_after=now(),cleanup_last_error_code='invalid_storage_key' WHERE id=$1`, testID)
	assertRejected("retry with unexpected_entry_type", `UPDATE artifacts SET cleanup_retry_after=now(),cleanup_last_error_code='unexpected_entry_type' WHERE id=$1`, testID)
	assertRejected("CLAIMED with last_error_code", `UPDATE artifacts SET cleanup_claim_token=gen_random_uuid(),cleanup_claimed_at=now(),cleanup_last_error_code='filesystem_io' WHERE id=$1`, testID)
	assertRejected("quarantine with filesystem_io", `UPDATE artifacts SET cleanup_quarantined_at=now(),cleanup_last_error_code='filesystem_io' WHERE id=$1`, testID)
	assertRejected("quarantine with durability_sync", `UPDATE artifacts SET cleanup_quarantined_at=now(),cleanup_last_error_code='durability_sync' WHERE id=$1`, testID)
	assertRejected("quarantine with null code", `UPDATE artifacts SET cleanup_quarantined_at=now(),cleanup_last_error_code=NULL WHERE id=$1`, testID)

	// 5. Pre-lifecycle expiry mutation is permitted on UNCLAIMED
	assertAccepted("pre-lifecycle expiry update", `UPDATE artifacts SET expires_at=clock_timestamp()-interval '2 hours' WHERE id=$1`, testID)

	// 6. Same UPDATE: change expires_at + create first claim rejected
	assertRejected("change expires_at and claim in same update", `UPDATE artifacts SET expires_at=clock_timestamp()-interval '3 hours',cleanup_claim_token=gen_random_uuid(),cleanup_claimed_at=now() WHERE id=$1`, testID)

	// 7. Transition graph: direct illegal transitions from UNCLAIMED
	assertRejected("unclaimed to retry_wait", `UPDATE artifacts SET cleanup_retry_after=now(),cleanup_last_error_code='filesystem_io' WHERE id=$1`, testID)
	assertRejected("unclaimed to content_deleted", `UPDATE artifacts SET content_deleted_at=now() WHERE id=$1`, testID)
	assertRejected("unclaimed to quarantined", `UPDATE artifacts SET cleanup_quarantined_at=now(),cleanup_last_error_code='unexpected_entry_type' WHERE id=$1`, testID)

	// Step to CLAIMED
	token1 := "00000000-0000-4000-8000-0000000017a1"
	assertAccepted("unclaimed to claimed", `UPDATE artifacts SET cleanup_claim_token=$2,cleanup_claimed_at=now() WHERE id=$1`, testID, token1)

	// Expiry freeze while CLAIMED
	assertRejected("mutate expires_at while claimed", `UPDATE artifacts SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1`, testID)

	// CLAIMED to CLAIMED (stale takeover)
	token2 := "00000000-0000-4000-8000-0000000017a2"
	assertAccepted("claimed to claimed", `UPDATE artifacts SET cleanup_claim_token=$2,cleanup_claimed_at=now() WHERE id=$1`, testID, token2)

	// CLAIMED cannot transition to UNCLAIMED
	assertRejected("claimed to unclaimed", `UPDATE artifacts SET cleanup_claim_token=NULL,cleanup_claimed_at=NULL WHERE id=$1`, testID)

	// CLAIMED to RETRY_WAIT
	assertRejected("claimed to retry with null code", `UPDATE artifacts SET cleanup_claim_token=NULL,cleanup_claimed_at=NULL,cleanup_retry_after=now(),cleanup_last_error_code=NULL WHERE id=$1`, testID)
	assertRejected("claimed to quarantine with null code", `UPDATE artifacts SET cleanup_claim_token=NULL,cleanup_claimed_at=NULL,cleanup_quarantined_at=now(),cleanup_last_error_code=NULL WHERE id=$1`, testID)
	assertAccepted("claimed to retry_wait", `UPDATE artifacts SET cleanup_claim_token=NULL,cleanup_claimed_at=NULL,cleanup_retry_after=now()+interval '5 minutes',cleanup_last_error_code='filesystem_io' WHERE id=$1`, testID)

	// Expiry freeze while RETRY_WAIT
	assertRejected("mutate expires_at during retry_wait", `UPDATE artifacts SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1`, testID)

	// RETRY_WAIT to CLAIMED
	token3 := "00000000-0000-4000-8000-0000000017a3"
	assertAccepted("retry_wait to claimed", `UPDATE artifacts SET cleanup_retry_after=NULL,cleanup_last_error_code=NULL,cleanup_claim_token=$2,cleanup_claimed_at=now() WHERE id=$1`, testID, token3)

	// Move back to RETRY_WAIT with durability_sync
	assertAccepted("claimed to retry_wait durability_sync", `UPDATE artifacts SET cleanup_claim_token=NULL,cleanup_claimed_at=NULL,cleanup_retry_after=now()+interval '5 minutes',cleanup_last_error_code='durability_sync' WHERE id=$1`, testID)

	// RETRY_WAIT cannot jump directly to content_deleted or quarantined
	assertRejected("retry_wait to content_deleted", `UPDATE artifacts SET cleanup_retry_after=NULL,cleanup_last_error_code=NULL,content_deleted_at=now() WHERE id=$1`, testID)
	assertRejected("retry_wait to quarantined", `UPDATE artifacts SET cleanup_retry_after=NULL,cleanup_last_error_code='unexpected_entry_type',cleanup_quarantined_at=now() WHERE id=$1`, testID)

	// Move back to claimed, then to CONTENT_DELETED
	token4 := "00000000-0000-4000-8000-0000000017a4"
	assertAccepted("retry_wait to claimed 2", `UPDATE artifacts SET cleanup_retry_after=NULL,cleanup_last_error_code=NULL,cleanup_claim_token=$2,cleanup_claimed_at=now() WHERE id=$1`, testID, token4)

	// Tombstone before expires_at rejected (artifacts_cleanup_tombstone_time_ck)
	assertRejected("tombstone before expires_at", `UPDATE artifacts SET cleanup_claim_token=NULL,cleanup_claimed_at=NULL,content_deleted_at=clock_timestamp()-interval '3 hours' WHERE id=$1`, testID)

	// CLAIMED to CONTENT_DELETED
	assertAccepted("claimed to content_deleted", `UPDATE artifacts SET cleanup_claim_token=NULL,cleanup_claimed_at=NULL,content_deleted_at=now() WHERE id=$1`, testID)

	// Expiry freeze while CONTENT_DELETED
	assertRejected("mutate expires_at during content_deleted", `UPDATE artifacts SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1`, testID)

	// CONTENT_DELETED is terminal and immutable
	assertRejected("mutate content_deleted artifact", `UPDATE artifacts SET content_deleted_at=now()+interval '1 hour' WHERE id=$1`, testID)
	assertRejected("un-delete content_deleted artifact", `UPDATE artifacts SET content_deleted_at=NULL WHERE id=$1`, testID)
	assertRejected("claim content_deleted artifact", `UPDATE artifacts SET cleanup_claim_token=gen_random_uuid(),cleanup_claimed_at=now() WHERE id=$1`, testID)

	// Test Quarantine lifecycle and terminality
	const qID = "00000000-0000-4000-8000-000000001712"
	if _, err := pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state,expires_at) VALUES($1,$2,$3,$4,$5,'raw-provider-output','text/plain',1,'sha',1,$6,$7,'redacted',clock_timestamp()-interval '1 hour')`, qID, taskID, runID, stepID, toolID, storeID, "v1/00/"+qID); err != nil {
		t.Fatal(err)
	}
	tokenQ := "00000000-0000-4000-8000-0000000017b1"
	assertAccepted("claim for quarantine", `UPDATE artifacts SET cleanup_claim_token=$2,cleanup_claimed_at=now() WHERE id=$1`, qID, tokenQ)
	assertAccepted("claimed to quarantined", `UPDATE artifacts SET cleanup_claim_token=NULL,cleanup_claimed_at=NULL,cleanup_quarantined_at=now(),cleanup_last_error_code='unexpected_entry_type' WHERE id=$1`, qID)

	// Expiry freeze while QUARANTINED
	assertRejected("mutate expires_at during quarantined", `UPDATE artifacts SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1`, qID)

	// QUARANTINED is terminal and immutable
	assertRejected("mutate quarantined artifact", `UPDATE artifacts SET cleanup_quarantined_at=now()+interval '1 hour' WHERE id=$1`, qID)
	assertRejected("unquarantine quarantined artifact", `UPDATE artifacts SET cleanup_quarantined_at=NULL,cleanup_last_error_code=NULL WHERE id=$1`, qID)
	assertRejected("claim quarantined artifact", `UPDATE artifacts SET cleanup_claim_token=gen_random_uuid(),cleanup_claimed_at=now() WHERE id=$1`, qID)
}

// Evaluate the actual CHECK expressions independently of triggers and other
// constraints, including PostgreSQL's acceptance of UNKNOWN CHECK results.
func assertCleanupConstraintSemantics(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	definitions := make(map[string]string)
	rows, err := pool.Query(ctx, `SELECT conname, pg_get_expr(conbin, conrelid) FROM pg_constraint WHERE conrelid='artifacts'::regclass AND contype='c' AND conname LIKE 'artifacts_cleanup_%'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name, expr string
		if err := rows.Scan(&name, &expr); err != nil {
			t.Fatal(err)
		}
		definitions[name] = expr
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	check := func(name string, fields map[string]string, want bool) {
		t.Helper()
		columns := []string{"addressing_version", "artifact_store_id", "storage_key", "storage_location", "expires_at", "content_deleted_at", "cleanup_claim_token", "cleanup_claimed_at", "cleanup_retry_after", "cleanup_last_error_code", "cleanup_quarantined_at"}
		defaults := []string{"1::smallint", "'00000000-0000-4000-8000-000000000001'::uuid", "'v1/00/example'::text", "NULL::text", "'2026-01-01'::timestamptz", "NULL::timestamptz", "NULL::uuid", "NULL::timestamptz", "NULL::timestamptz", "NULL::text", "NULL::timestamptz"}
		var selectFields []string
		for i, column := range columns {
			value := defaults[i]
			if override, ok := fields[column]; ok {
				value = override
			}
			selectFields = append(selectFields, value+" AS "+column)
		}
		expr, ok := definitions["artifacts_cleanup_"+name+"_ck"]
		if !ok {
			t.Fatalf("missing constraint %s", name)
		}
		var accepted bool
		if err := pool.QueryRow(ctx, "SELECT ("+expr+") IS NOT FALSE FROM (SELECT "+strings.Join(selectFields, ",")+") a").Scan(&accepted); err != nil {
			t.Fatal(err)
		}
		if accepted != want {
			t.Fatalf("constraint %s fields=%v accepted=%v want=%v", name, fields, accepted, want)
		}
	}
	lifecycle := []string{"content_deleted_at", "cleanup_claim_token", "cleanup_claimed_at", "cleanup_retry_after", "cleanup_last_error_code", "cleanup_quarantined_at"}
	values := []string{"'2026-01-02'::timestamptz", "'00000000-0000-4000-8000-000000000002'::uuid", "'2026-01-02'::timestamptz", "'2026-01-02'::timestamptz", "'filesystem_io'::text", "'2026-01-02'::timestamptz"}
	for mask := 0; mask < 64; mask++ {
		for _, code := range []string{"filesystem_io", "durability_sync", "unexpected_entry_type", "unknown"} {
			fields := map[string]string{}
			for bit, column := range lifecycle {
				if mask&(1<<bit) != 0 {
					fields[column] = values[bit]
				}
			}
			if mask&16 != 0 {
				fields["cleanup_last_error_code"] = fmt.Sprintf("'%s'::text", code)
			}
			want := mask == 0 || mask == 6 || mask == 1 || (mask == 24 && (code == "filesystem_io" || code == "durability_sync")) || (mask == 48 && code == "unexpected_entry_type")
			check("state_shape", fields, want)
			check("claim_pair", fields, (mask&2 != 0) == (mask&4 != 0))
			check("error_code", fields, mask&16 == 0 || code != "unknown")
			check("retry_error", fields, mask&8 == 0 || (mask&16 != 0 && (code == "filesystem_io" || code == "durability_sync")))
			check("quarantine_error", fields, mask&32 == 0 || (mask&16 != 0 && code == "unexpected_entry_type"))
			fields["addressing_version"] = "0::smallint"
			check("legacy_v0_null", fields, mask == 0)
		}
	}
	check("tombstone_time", map[string]string{"content_deleted_at": "'2026-01-02'::timestamptz", "expires_at": "NULL::timestamptz"}, false)
	for _, deleted := range []string{"2025-12-31", "2026-01-01", "2026-01-02"} {
		check("tombstone_time", map[string]string{"content_deleted_at": fmt.Sprintf("'%s'::timestamptz", deleted)}, deleted >= "2026-01-01")
	}
	for _, column := range lifecycle {
		check("lifecycle_address", map[string]string{}, true)
		for _, invalid := range []struct{ column, value string }{{"addressing_version", "0::smallint"}, {"artifact_store_id", "NULL::uuid"}, {"storage_key", "NULL::text"}, {"storage_location", "'legacy'::text"}, {"expires_at", "NULL::timestamptz"}} {
			fields := map[string]string{}
			for i, field := range lifecycle {
				if field == column {
					fields[field] = values[i]
				}
			}
			check("lifecycle_address", fields, true)
			fields[invalid.column] = invalid.value
			check("lifecycle_address", fields, false)
		}
	}
}

func applyMigration(t *testing.T, ctx context.Context, pool *pgxpool.Pool, version int64, name string) {
	t.Helper()
	body, err := files.ReadFile("sql/" + name)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7212026)`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("acquire migration lock: %v", err)
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
