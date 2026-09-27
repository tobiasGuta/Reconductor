package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/migrations"
)

func TestPreparedLimitsRemediation0021EndToEnd(t *testing.T) {
	ctx := context.Background()
	pool, databaseURL := newPlatformMigrationFixture(t, 20)
	const (
		storeID    = "00000000-0000-4000-8000-000000521001"
		storeNonce = "00000000-0000-4000-8000-000000521002"
	)
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_stores(id,incarnation_nonce,backend_kind,marker_format,marker_version)
		VALUES($1,$2,'local-v1','reconductor-artifact-store',1)`, storeID, storeNonce); err != nil {
		t.Fatal(err)
	}
	const aggregateLimit = int64(256 << 20)
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_store_prepared_limits(artifact_store_id,max_open_sets,max_set_bytes,max_unresolved_bytes)
		VALUES($1,64,$2,$3)`, storeID, domain.PreparedSetOutputAuthorityMaxBytes+1, aggregateLimit); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Database: config.Database{URL: databaseURL}, ArtifactStorage: config.ArtifactStorage{StoreID: storeID}}

	if err := migrations.Up(ctx, pool); err == nil || !strings.Contains(err.Error(), "contains max_set_bytes above 8388608 bytes") {
		t.Fatalf("initial migration error=%v", err)
	}
	assertMigration0021AbsentAndLimit(t, ctx, pool, storeID, domain.PreparedSetOutputAuthorityMaxBytes+1, aggregateLimit)

	store, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RequireCurrentSchema(ctx); !errors.Is(err, migrations.ErrSchemaNotCurrent) {
		store.Close()
		t.Fatalf("outdated schema readiness error=%v", err)
	}
	store.Close()

	if err := artifactStoreCommand(ctx, cfg, []string{"prepared-limits-remediate-0021", "--max-set-bytes", "8388608"}); err == nil || !strings.Contains(err.Error(), "requires --confirm-artifact-runtimes-stopped") {
		t.Fatalf("incomplete remediation error=%v", err)
	}
	if err := artifactStoreCommand(ctx, cfg, []string{"prepared-limits-remediate-0021", "--max-set-bytes", "8388609", "--confirm-artifact-runtimes-stopped"}); err == nil || !strings.Contains(err.Error(), "must be between") {
		t.Fatalf("plus-one remediation error=%v", err)
	}
	missingCfg := cfg
	missingCfg.ArtifactStorage.StoreID = "00000000-0000-4000-8000-000000521099"
	if err := artifactStoreCommand(ctx, missingCfg, []string{"prepared-limits-remediate-0021", "--max-set-bytes", "8388608", "--confirm-artifact-runtimes-stopped"}); err == nil || !strings.Contains(err.Error(), "existing prepared-limit configuration") {
		t.Fatalf("missing-store remediation error=%v", err)
	}
	assertMigration0021AbsentAndLimit(t, ctx, pool, storeID, domain.PreparedSetOutputAuthorityMaxBytes+1, aggregateLimit)

	lineage := insertRemediationLineage(t, ctx, pool, "521")
	if err := artifactStoreCommand(ctx, cfg, []string{"prepared-limits-remediate-0021", "--max-set-bytes", "8388608", "--confirm-artifact-runtimes-stopped"}); err == nil || !strings.Contains(err.Error(), "running_steps=1") {
		t.Fatalf("active-execution remediation error=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE step_runs SET status='succeeded',completed_at=clock_timestamp() WHERE id=$1`, lineage.stepID); err != nil {
		t.Fatal(err)
	}
	publicationID := "00000000-0000-4000-8000-000000521020"
	artifactID := "00000000-0000-4000-8000-000000521021"
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_publications(
		id,provider_attempt_id,publication_ordinal,result_occurrence_id,artifact_id,artifact_store_id,storage_key,
		content_type,content_size_bytes,content_sha256,publication_state,origin_owner_instance_id,owner_kind,
		owner_instance_id,publication_token,fence_generation,lease_duration_ms,lease_expires_at)
		VALUES($1,$2,0,gen_random_uuid(),$3,$4,$5,'text/plain',1,$6,'reserved',
		gen_random_uuid(),'recovery',gen_random_uuid(),gen_random_uuid(),1,120000,clock_timestamp()+interval '2 minutes')`,
		publicationID, lineage.providerAttemptID, artifactID, storeID, "v1/00/"+artifactID, strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := artifactStoreCommand(ctx, cfg, []string{"prepared-limits-remediate-0021", "--max-set-bytes", "8388608", "--confirm-artifact-runtimes-stopped"}); err == nil || !strings.Contains(err.Error(), "unresolved_publications=1") {
		t.Fatalf("active-publication remediation error=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE artifact_publications SET publication_state='abandoned',
		owner_kind=NULL,owner_instance_id=NULL,publication_token=NULL,lease_expires_at=NULL,
		abandoned_at=clock_timestamp() WHERE id=$1`, publicationID); err != nil {
		t.Fatal(err)
	}

	out, err := captureStdout(func() error {
		return artifactStoreCommand(ctx, cfg, []string{"prepared-limits-remediate-0021", "--max-set-bytes", "8388608", "--confirm-artifact-runtimes-stopped"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		StoreID               string `json:"store_id"`
		PreviousMaxSetBytes   int64  `json:"previous_max_set_bytes"`
		MaxSetBytes           int64  `json:"max_set_bytes"`
		MaxOpenSets           int    `json:"max_open_sets"`
		MaxUnresolvedBytes    int64  `json:"max_unresolved_bytes"`
		SchemaFrontierVersion int64  `json:"schema_frontier_version"`
		Status                string `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result.StoreID != storeID || result.PreviousMaxSetBytes != domain.PreparedSetOutputAuthorityMaxBytes+1 ||
		result.MaxSetBytes != domain.PreparedSetOutputAuthorityMaxBytes || result.MaxOpenSets != 64 ||
		result.MaxUnresolvedBytes != aggregateLimit || result.SchemaFrontierVersion != 20 ||
		result.Status != "migration_0021_remediated" {
		t.Fatalf("remediation output=%s", out)
	}
	assertMigration0021AbsentAndLimit(t, ctx, pool, storeID, domain.PreparedSetOutputAuthorityMaxBytes, aggregateLimit)

	store, err = database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.RequireCurrentSchema(ctx); !errors.Is(err, migrations.ErrSchemaNotCurrent) {
		t.Fatalf("remediation prematurely enabled execution: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.RequireCurrentSchema(ctx); err != nil {
		t.Fatalf("current-schema readiness after retry: %v", err)
	}
	status, err := store.RequirePreparedEvidenceReady(ctx, domain.ID(storeID))
	if err != nil {
		t.Fatalf("prepared readiness after retry: %v", err)
	}
	if status.MaxSetBytes != domain.PreparedSetOutputAuthorityMaxBytes || status.MaxUnresolvedBytes != aggregateLimit {
		t.Fatalf("prepared readiness status=%+v", status)
	}
	if err := artifactStoreCommand(ctx, cfg, []string{"prepared-limits-remediate-0021", "--max-set-bytes", "8388608", "--confirm-artifact-runtimes-stopped"}); err == nil || !strings.Contains(err.Error(), "requires exact schema frontier 20") {
		t.Fatalf("current-schema remediation error=%v", err)
	}
	if err := artifactStoreCommand(ctx, cfg, []string{"prepared-limits", "--max-open-sets", "65", "--max-set-bytes", "4194304", "--max-unresolved-bytes", strconv.FormatInt(aggregateLimit, 10)}); err != nil {
		t.Fatalf("ordinary current-schema administration: %v", err)
	}
}

func TestPreparedLimitsRemediation0021RejectsUnsupportedFrontier(t *testing.T) {
	ctx := context.Background()
	_, databaseURL := newPlatformMigrationFixture(t, 19)
	cfg := config.Config{Database: config.Database{URL: databaseURL}, ArtifactStorage: config.ArtifactStorage{StoreID: "00000000-0000-4000-8000-000000519001"}}
	err := artifactStoreCommand(ctx, cfg, []string{"prepared-limits-remediate-0021", "--max-set-bytes", "8388608", "--confirm-artifact-runtimes-stopped"})
	if err == nil || !strings.Contains(err.Error(), "requires exact schema frontier 20") || !strings.Contains(err.Error(), "found 19") {
		t.Fatalf("unsupported-frontier remediation error=%v", err)
	}
}

func TestProviderOutputAuthorityMigrationRejectsLegacyOversizedPreparedEvidence(t *testing.T) {
	ctx := context.Background()
	pool, databaseURL := newPlatformMigrationFixture(t, 20)
	const (
		storeID    = "00000000-0000-4000-8000-000000522001"
		storeNonce = "00000000-0000-4000-8000-000000522002"
	)
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_stores(id,incarnation_nonce,backend_kind,marker_format,marker_version)
		VALUES($1,$2,'local-v1','reconductor-artifact-store',1)`, storeID, storeNonce); err != nil {
		t.Fatal(err)
	}
	const aggregateLimit = int64(256 << 20)
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_store_prepared_limits(artifact_store_id,max_open_sets,max_set_bytes,max_unresolved_bytes)
		VALUES($1,64,$2,$3)`, storeID, domain.PreparedSetOutputAuthorityMaxBytes+1, aggregateLimit); err != nil {
		t.Fatal(err)
	}
	lineage := insertRemediationLineage(t, ctx, pool, "522")
	if _, err := pool.Exec(ctx, `UPDATE step_runs SET status='succeeded',completed_at=clock_timestamp() WHERE id=$1`, lineage.stepID); err != nil {
		t.Fatal(err)
	}
	preparedID := "00000000-0000-4000-8000-000000522020"
	if _, err := pool.Exec(ctx, `INSERT INTO prepared_evidence_sets(
		id,manifest_id,owner_kind,provider_attempt_id,program_id,task_id,workflow_run_id,step_run_id,
		action_request_id,step_attempt,artifact_store_id,store_incarnation_nonce,lifecycle_state,
		reserved_capacity_bytes,quarantined_at,quarantine_reason_code)
		VALUES($1,gen_random_uuid(),'provider_attempt',$2,$3,$4,$5,$6,$7,1,$8,$9,'QUARANTINED',$10,clock_timestamp(),'legacy_review')`,
		preparedID, lineage.providerAttemptID, lineage.programID, lineage.taskID, lineage.runID, lineage.stepID,
		lineage.actionID, storeID, storeNonce, domain.PreparedSetOutputAuthorityMaxBytes+1); err != nil {
		t.Fatal(err)
	}
	if err := migrations.Up(ctx, pool); err == nil || !strings.Contains(err.Error(), "oversized legacy prepared evidence remains") {
		t.Fatalf("legacy migration error=%v", err)
	}
	var state string
	var reserved int64
	if err := pool.QueryRow(ctx, `SELECT lifecycle_state,reserved_capacity_bytes FROM prepared_evidence_sets WHERE id=$1`, preparedID).Scan(&state, &reserved); err != nil {
		t.Fatal(err)
	}
	if state != "QUARANTINED" || reserved != domain.PreparedSetOutputAuthorityMaxBytes+1 {
		t.Fatalf("legacy prepared evidence was mutated: state=%s reserved=%d", state, reserved)
	}
	cfg := config.Config{Database: config.Database{URL: databaseURL}, ArtifactStorage: config.ArtifactStorage{StoreID: storeID}}
	if err := artifactStoreCommand(ctx, cfg, []string{"prepared-limits-remediate-0021", "--max-set-bytes", "8388608", "--confirm-artifact-runtimes-stopped"}); err == nil || !strings.Contains(err.Error(), "would strand oversized prepared evidence") || !strings.Contains(err.Error(), "quarantined evidence has no automatic disposition") {
		t.Fatalf("legacy remediation error=%v", err)
	}
	assertMigration0021AbsentAndLimit(t, ctx, pool, storeID, domain.PreparedSetOutputAuthorityMaxBytes+1, aggregateLimit)
}

type remediationLineage struct {
	programID         string
	taskID            string
	runID             string
	stepID            string
	actionID          string
	providerAttemptID string
}

func insertRemediationLineage(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) remediationLineage {
	t.Helper()
	prefix := "00000000-0000-4000-8000-000000" + suffix
	lineage := remediationLineage{
		programID: prefix + "003", taskID: prefix + "006", runID: prefix + "007",
		stepID: prefix + "008", actionID: prefix + "011", providerAttemptID: prefix + "010",
	}
	scopeID := prefix + "004"
	definitionID := prefix + "005"
	authorizationID := prefix + "009"
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,$2,'integration','synthetic://local','integration')`, []any{lineage.programID, "migration-remediation-" + suffix}},
		{`INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,target_plan_digest,target_plan) VALUES($1,$2,'synthetic://local','scope','plan','{}')`, []any{scopeID, lineage.programID}},
		{`INSERT INTO workflow_definitions(id,name,version,definition) VALUES($1,$2,'1','{}')`, []any{definitionID, "migration-remediation-" + suffix}},
		{`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES($1,$2,'migration remediation',$3,'running','integration')`, []any{lineage.taskID, lineage.programID, definitionID}},
		{`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source,materialized_definition,materialization_digest,original_scope_version_id) VALUES($1,$2,$3,'1','running','integration','{}',$4,$5)`, []any{lineage.runID, lineage.taskID, definitionID, strings.Repeat("a", 64), scopeID}},
		{`INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,idempotency_key) VALUES($1,$2,'one','test.capability','running',$3)`, []any{lineage.stepID, lineage.runID, "migration-remediation-" + suffix}},
		{`INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,step_run_id,safe_message,details) VALUES($1,'policy_allowed','policy','integration',$2,$3,$4,$5,'allowed','{"phase":"execution"}')`, []any{authorizationID, lineage.programID, lineage.taskID, lineage.runID, lineage.stepID}},
		{`INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,step_run_id,action_request_id,step_attempt,execution_authorization_event_id,capability,provider,safe_message,details) VALUES($1,'provider_invocation_started','provider','integration',$2,$3,$4,$5,$6,1,$7,'test.capability','test-provider','started','{}')`, []any{lineage.providerAttemptID, lineage.programID, lineage.taskID, lineage.runID, lineage.stepID, lineage.actionID, authorizationID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return lineage
}

func assertMigration0021AbsentAndLimit(t *testing.T, ctx context.Context, pool *pgxpool.Pool, storeID string, maxSetBytes, maxUnresolvedBytes int64) {
	t.Helper()
	var migrationCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=21`).Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	var storedSet, storedAggregate int64
	if err := pool.QueryRow(ctx, `SELECT max_set_bytes,max_unresolved_bytes FROM artifact_store_prepared_limits WHERE artifact_store_id=$1`, storeID).Scan(&storedSet, &storedAggregate); err != nil {
		t.Fatal(err)
	}
	if migrationCount != 0 || storedSet != maxSetBytes || storedAggregate != maxUnresolvedBytes {
		t.Fatalf("migration count=%d max_set_bytes=%d max_unresolved_bytes=%d", migrationCount, storedSet, storedAggregate)
	}
}

func newPlatformMigrationFixture(t *testing.T, maximum int64) (*pgxpool.Pool, string) {
	t.Helper()
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
	schema := "platform_remediation_" + strconv.FormatInt(time.Now().UnixNano(), 10)
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
	scopedURL := parsed.String()
	pool, err := pgxpool.New(ctx, scopedURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	sqlDirectory := filepath.Join("..", "..", "internal", "migrations", "sql")
	entries, err := os.ReadDir(sqlDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			t.Fatalf("migration %s has no numeric prefix", entry.Name())
		}
		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if version > maximum {
			continue
		}
		body, err := os.ReadFile(filepath.Join(sqlDirectory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7212026)`); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("apply migration %s: %v", entry.Name(), err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version,name) VALUES($1,$2)`, version, entry.Name()); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	return pool, scopedURL
}
