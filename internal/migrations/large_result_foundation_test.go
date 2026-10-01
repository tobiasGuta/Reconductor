package migrations

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestLargeResultFoundationMigrationsAreOrderedAndClosed(t *testing.T) {
	versions, err := Versions()
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) < 6 || versions[len(versions)-6] != "0018_large_result_publication_journal.sql" || versions[len(versions)-5] != "0019_large_result_recovery_foundation.sql" || versions[len(versions)-4] != "0020_prepared_evidence_ownership.sql" || versions[len(versions)-3] != "0021_provider_output_authority_ceiling.sql" || versions[len(versions)-2] != "0022_exact_launch_authority_foundation.sql" || versions[len(versions)-1] != "0023_exact_action_contract.sql" {
		t.Fatalf("large-result migration order=%v", versions)
	}

	publicationBody, err := files.ReadFile("sql/0018_large_result_publication_journal.sql")
	if err != nil {
		t.Fatal(err)
	}
	publication := strings.ToLower(string(publicationBody))
	for _, required := range []string{
		"create table artifact_publications",
		"publication_state in ('reserved','publishing','sealed','adopted','abandoned','quarantined')",
		"unique (provider_attempt_id, publication_ordinal)",
		"unique (artifact_id)",
		"unique (artifact_store_id, storage_key)",
		"artifact publication identity is immutable",
		"deferrable initially deferred",
		"artifact_publications_cleanup_state_shape_ck",
		"publication_state <> 'abandoned'",
		"enforce_artifact_publication_state_transition",
		"terminal artifact publication state is immutable",
		"enforce_artifact_publication_cleanup_transition",
		"content-deleted publication cleanup is terminal and immutable",
		"cleanup-quarantined publication cleanup is terminal and immutable",
	} {
		if !strings.Contains(publication, required) {
			t.Fatalf("0018 missing %q", required)
		}
	}
	for _, forbidden := range []string{"publication_set_id", "'cleanup_quarantined'"} {
		if strings.Contains(publication, forbidden) {
			t.Fatalf("0018 contains prohibited publication concept %q", forbidden)
		}
	}

	recoveryBody, err := files.ReadFile("sql/0019_large_result_recovery_foundation.sql")
	if err != nil {
		t.Fatal(err)
	}
	recovery := strings.ToLower(string(recoveryBody))
	for _, required := range []string{
		"create table failure_finalization_records",
		"create table step_attempt_claims",
		"create table workflow_attempt_waves",
		"create table workflow_wave_members",
		"unique (workflow_run_id, wave_sequence)",
		"unique (wave_id, step_run_id)",
		"unique (result_occurrence_id)",
		"unique (provider_attempt_id)",
		"automatic_attempt_count between 0 and 2",
		"'resolved_retryable'",
		"'retry_pending'",
		"'provider_invocation_timed_out'",
		"add column failure_finalization_record_id uuid",
		"add column result_occurrence_id uuid",
		"add column wave_id uuid",
		"add column claim_fence_generation bigint",
		"add column finalization_attempt_number smallint",
		"workflow wave member count does not match its immutable declaration",
		"large_result_uuid_values_distinct",
		"workflow_attempt_waves_propagation_renewal_shape_ck",
		"workflow_attempt_waves_dispatch_renewal_shape_ck",
	} {
		if !strings.Contains(recovery, required) {
			t.Fatalf("0019 missing %q", required)
		}
	}
	if strings.Contains(recovery, "unique (action_request_id)") {
		t.Fatal("action_request_id was made unique")
	}
	for _, futureID := range []string{"provider_terminal_event_id uuid references", "provider_result_accepted_event_id uuid references", "tool_run_id uuid references"} {
		if strings.Contains(recovery, futureID) {
			t.Fatalf("preallocated future identity received a premature foreign key: %q", futureID)
		}
	}
	preparedBody, err := files.ReadFile("sql/0020_prepared_evidence_ownership.sql")
	if err != nil {
		t.Fatal(err)
	}
	prepared := strings.ToLower(string(preparedBody))
	for _, required := range []string{
		"create table artifact_store_prepared_limits",
		"create table prepared_evidence_sets",
		"'allocated','sealed','resolved_adopted','resolved_abandoned','quarantined','cleaned'",
		"prepared_evidence_sets_owner_shape_ck",
		"prepared_evidence_sets_state_shape_ck",
		"prepared_evidence_sets_manifest_key_ck",
		"enforce_prepared_evidence_set_transition",
		"old.lifecycle_state in ('resolved_adopted','resolved_abandoned') and new.lifecycle_state='cleaned'",
	} {
		if !strings.Contains(prepared, required) {
			t.Fatalf("0020 missing %q", required)
		}
	}
	for _, forbidden := range []string{"create table prepared_evidence_members", "insert into prepared_evidence_sets", "update artifact_publications"} {
		if strings.Contains(prepared, forbidden) {
			t.Fatalf("0020 contains prohibited historical/member mutation %q", forbidden)
		}
	}

	ceilingBody, err := files.ReadFile("sql/0021_provider_output_authority_ceiling.sql")
	if err != nil {
		t.Fatal(err)
	}
	ceiling := strings.ToLower(string(ceilingBody))
	limit := strconv.FormatInt(domain.PreparedSetOutputAuthorityMaxBytes, 10)
	for _, required := range []string{
		"lock table artifact_store_prepared_limits in access exclusive mode",
		"where max_set_bytes > " + limit,
		"check (max_set_bytes between 1 and " + limit + ")",
		"platform artifact-store prepared-limits-remediate-0021 --max-set-bytes 8388608 --confirm-artifact-runtimes-stopped",
		"oversized legacy prepared evidence remains",
		"execution or publication state is active",
	} {
		if !strings.Contains(ceiling, required) {
			t.Fatalf("0021 missing %q", required)
		}
	}
	for _, forbidden := range []string{"update artifact_store_prepared_limits", "delete from artifact_store_prepared_limits", "max_unresolved_bytes between 1 and " + limit} {
		if strings.Contains(ceiling, forbidden) {
			t.Fatalf("0021 contains prohibited configuration rewrite/aggregate ceiling %q", forbidden)
		}
	}
}

func TestProviderOutputAuthorityCeilingMigration(t *testing.T) {
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
	schema := "migration_output_ceiling_" + strconv.FormatInt(time.Now().UnixNano(), 10)
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
	applyEmbeddedMigrationsThrough(t, ctx, pool, 20)

	const (
		compatibleStore = "00000000-0000-4000-8000-000000021001"
		compatibleNonce = "00000000-0000-4000-8000-000000021002"
		oversizedStore  = "00000000-0000-4000-8000-000000021003"
		oversizedNonce  = "00000000-0000-4000-8000-000000021004"
	)
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_stores(id,incarnation_nonce,backend_kind,marker_format,marker_version) VALUES
		($1,$2,'local-v1','reconductor-artifact-store',1),($3,$4,'local-v1','reconductor-artifact-store',1)`, compatibleStore, compatibleNonce, oversizedStore, oversizedNonce); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_store_prepared_limits(artifact_store_id,max_open_sets,max_set_bytes,max_unresolved_bytes) VALUES
		($1,128,$2,$3),($4,128,$5,$6)`,
		compatibleStore, int64(1<<20), int64(128<<20),
		oversizedStore, domain.PreparedSetOutputAuthorityMaxBytes+1, int64(128<<20)); err != nil {
		t.Fatal(err)
	}

	err = Up(ctx, pool)
	if err == nil || !strings.Contains(err.Error(), "contains max_set_bytes above 8388608 bytes") {
		t.Fatalf("oversized migration error=%v", err)
	}
	var appliedCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=21`).Scan(&appliedCount); err != nil || appliedCount != 0 {
		t.Fatalf("rolled-back migration count=%d error=%v", appliedCount, err)
	}
	var storedOversized int64
	if err := pool.QueryRow(ctx, `SELECT max_set_bytes FROM artifact_store_prepared_limits WHERE artifact_store_id=$1`, oversizedStore).Scan(&storedOversized); err != nil || storedOversized != domain.PreparedSetOutputAuthorityMaxBytes+1 {
		t.Fatalf("oversized configuration changed to %d error=%v", storedOversized, err)
	}
	var oldConstraint string
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='artifact_store_prepared_limits_set_ck' AND conrelid='artifact_store_prepared_limits'::regclass`).Scan(&oldConstraint); err != nil || !strings.Contains(oldConstraint, "1099511627776") {
		t.Fatalf("old constraint=%q error=%v", oldConstraint, err)
	}

	if _, err := RemediateProviderOutputAuthority0021(ctx, pool, domain.ID(oversizedStore), domain.PreparedSetOutputAuthorityMaxBytes+1); err == nil || !strings.Contains(err.Error(), "must be between") {
		t.Fatalf("plus-one remediation error=%v", err)
	}
	if _, err := RemediateProviderOutputAuthority0021(ctx, pool, "00000000-0000-4000-8000-000000021099", domain.PreparedSetOutputAuthorityMaxBytes); err == nil || !strings.Contains(err.Error(), "existing prepared-limit configuration") {
		t.Fatalf("missing-store remediation error=%v", err)
	}
	result, err := RemediateProviderOutputAuthority0021(ctx, pool, domain.ID(oversizedStore), domain.PreparedSetOutputAuthorityMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if result.PreviousMaxSetBytes != domain.PreparedSetOutputAuthorityMaxBytes+1 || result.MaxSetBytes != domain.PreparedSetOutputAuthorityMaxBytes || result.MaxOpenSets != 128 || result.MaxUnresolvedBytes != 128<<20 || result.SchemaFrontierVersion != 20 {
		t.Fatalf("remediation result=%+v", result)
	}
	if err := RequireCurrent(ctx, pool); err == nil || !errors.Is(err, ErrSchemaNotCurrent) {
		t.Fatalf("execution became ready before migration retry: %v", err)
	}
	if err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := RequireCurrent(ctx, pool); err != nil {
		t.Fatalf("current-schema readiness after retry: %v", err)
	}
	if _, err := RemediateProviderOutputAuthority0021(ctx, pool, domain.ID(oversizedStore), domain.PreparedSetOutputAuthorityMaxBytes); err == nil || !strings.Contains(err.Error(), "requires exact schema frontier 20") {
		t.Fatalf("current-schema remediation error=%v", err)
	}
	var compatibleValue int64
	if err := pool.QueryRow(ctx, `SELECT max_set_bytes FROM artifact_store_prepared_limits WHERE artifact_store_id=$1`, compatibleStore).Scan(&compatibleValue); err != nil || compatibleValue != 1<<20 {
		t.Fatalf("compatible configuration=%d error=%v", compatibleValue, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE artifact_store_prepared_limits SET max_set_bytes=$2 WHERE artifact_store_id=$1`, oversizedStore, domain.PreparedSetOutputAuthorityMaxBytes+1); err == nil || !strings.Contains(err.Error(), "artifact_store_prepared_limits_set_ck") {
		t.Fatalf("ceiling constraint error=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE artifact_store_prepared_limits SET max_unresolved_bytes=$2 WHERE artifact_store_id=$1`, oversizedStore, int64(1<<50)); err != nil {
		t.Fatalf("aggregate unresolved capacity was reduced: %v", err)
	}
}

func TestLargeResultFoundationMigrationCatalog(t *testing.T) {
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
	schema := "migration_large_result_" + strconv.FormatInt(time.Now().UnixNano(), 10)
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
	if err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}

	for _, relation := range []string{"artifact_publications", "failure_finalization_records", "step_attempt_claims", "workflow_attempt_waves", "workflow_wave_members"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, relation).Scan(&exists); err != nil || !exists {
			t.Fatalf("relation %s exists=%v error=%v", relation, exists, err)
		}
	}
	for _, constraint := range []string{
		"artifact_publications_state_ck",
		"failure_finalization_records_attempt_count_ck",
		"failure_finalization_records_attempt_shape_ck",
		"step_attempt_claims_state_shape_ck",
		"workflow_attempt_waves_dispatch_state_ck",
		"workflow_attempt_waves_propagation_state_ck",
		"workflow_attempt_waves_propagation_renewal_shape_ck",
		"workflow_attempt_waves_dispatch_renewal_shape_ck",
		"workflow_wave_members_state_ck",
		"audit_events_finalization_attempt_ck",
	} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conname=$1)`, constraint).Scan(&exists); err != nil || !exists {
			t.Fatalf("constraint %s exists=%v error=%v", constraint, exists, err)
		}
	}
	var terminalIndex string
	if err := pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='audit_events_provider_terminal_unique_idx'`).Scan(&terminalIndex); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{"provider_invocation_succeeded", "provider_invocation_failed", "provider_invocation_cancelled", "provider_invocation_timed_out"} {
		if !strings.Contains(terminalIndex, event) {
			t.Fatalf("terminal uniqueness index %q missing %q", terminalIndex, event)
		}
	}

	assertLargeResultFoundationBehavior(t, ctx, pool)
}

func assertLargeResultFoundationBehavior(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	const (
		programID       = "00000000-0000-4000-8000-000000019001"
		scopeVersionID  = "00000000-0000-4000-8000-000000019002"
		definitionID    = "00000000-0000-4000-8000-000000019003"
		taskID          = "00000000-0000-4000-8000-000000019004"
		runID           = "00000000-0000-4000-8000-000000019005"
		stepOneID       = "00000000-0000-4000-8000-000000019006"
		stepTwoID       = "00000000-0000-4000-8000-000000019007"
		authorizationID = "00000000-0000-4000-8000-000000019008"
		providerOneID   = "00000000-0000-4000-8000-000000019009"
		providerTwoID   = "00000000-0000-4000-8000-000000019010"
		storeID         = "00000000-0000-4000-8000-000000019011"
		storeNonce      = "00000000-0000-4000-8000-000000019012"
		waveID          = "00000000-0000-4000-8000-000000019013"
		actionID        = "00000000-0000-4000-8000-000000019014"
		resultOneID     = "00000000-0000-4000-8000-000000019015"
		resultTwoID     = "00000000-0000-4000-8000-000000019016"
		recordOneID     = "00000000-0000-4000-8000-000000019017"
		recordTwoID     = "00000000-0000-4000-8000-000000019018"
		recordThreeID   = "00000000-0000-4000-8000-000000019019"
	)
	digest := strings.Repeat("a", 64)
	for _, statement := range []string{
		`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES('` + programID + `','large-result-foundation','integration','synthetic://local','integration')`,
		`INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,target_plan_digest,target_plan) VALUES('` + scopeVersionID + `','` + programID + `','synthetic://local','scope','plan','{}')`,
		`INSERT INTO workflow_definitions(id,name,version,definition) VALUES('` + definitionID + `','large-result-foundation','1','{}')`,
		`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES('` + taskID + `','` + programID + `','large result foundation','` + definitionID + `','running','integration')`,
		`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source,materialized_definition,materialization_digest,original_scope_version_id) VALUES('` + runID + `','` + taskID + `','` + definitionID + `','1','running','integration','{}','` + digest + `','` + scopeVersionID + `')`,
		`INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,idempotency_key) VALUES('` + stepOneID + `','` + runID + `','one','test.capability','running','large-result-one')`,
		`INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,idempotency_key) VALUES('` + stepTwoID + `','` + runID + `','two','test.capability','running','large-result-two')`,
		`INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,step_run_id,safe_message,details) VALUES('` + authorizationID + `','policy_allowed','policy','integration','` + programID + `','` + taskID + `','` + runID + `','` + stepOneID + `','allowed','{"phase":"execution"}')`,
		`INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,step_run_id,action_request_id,step_attempt,execution_authorization_event_id,capability,provider,safe_message,details) VALUES('` + providerOneID + `','provider_invocation_started','provider','integration','` + programID + `','` + taskID + `','` + runID + `','` + stepTwoID + `','` + actionID + `',1,'` + authorizationID + `','test.capability','test-provider','started','{}')`,
		`INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,step_run_id,action_request_id,step_attempt,execution_authorization_event_id,capability,provider,safe_message,details) VALUES('` + providerTwoID + `','provider_invocation_started','provider','integration','` + programID + `','` + taskID + `','` + runID + `','` + stepTwoID + `','` + actionID + `',2,'` + authorizationID + `','test.capability','test-provider','started','{}')`,
		`INSERT INTO artifact_stores(id,incarnation_nonce,backend_kind,marker_format,marker_version) VALUES('` + storeID + `','` + storeNonce + `','local-v1','reconductor-artifact-store',1)`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO workflow_attempt_waves(wave_id,workflow_run_id,wave_sequence,materialization_digest,member_count,propagation_state,dispatch_state) VALUES($1,$2,1,$3,2,'not_required','pending')`, waveID, runID, digest); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO workflow_wave_members(wave_id,member_ordinal,step_run_id,step_definition_id,member_state) VALUES($1,0,$2,'one','planned'),($1,1,$3,'two','planned')`, waveID, stepOneID, stepTwoID); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	artifactID := "00000000-0000-4000-8000-000000019020"
	storageKey := "v1/00/" + artifactID
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_publications(
		id,provider_attempt_id,publication_ordinal,result_occurrence_id,artifact_id,artifact_store_id,storage_key,
		content_type,content_size_bytes,content_sha256,publication_state,origin_owner_instance_id,owner_kind,
		owner_instance_id,publication_token,fence_generation,lease_duration_ms,lease_expires_at)
		VALUES(gen_random_uuid(),$1,0,$2,$3,$4,$5,'text/plain',1,$6,'reserved',gen_random_uuid(),'recovery',gen_random_uuid(),gen_random_uuid(),1,120000,clock_timestamp()+interval '2 minutes')`, providerOneID, resultOneID, artifactID, storeID, storageKey, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_publications(
		id,provider_attempt_id,publication_ordinal,result_occurrence_id,artifact_id,artifact_store_id,storage_key,
		content_type,content_size_bytes,content_sha256,publication_state,origin_owner_instance_id,owner_kind,
		owner_instance_id,publication_token,fence_generation,lease_duration_ms,lease_expires_at)
		VALUES(gen_random_uuid(),$1,0,gen_random_uuid(),'00000000-0000-4000-8000-000000019099',$2,'v1/00/00000000-0000-4000-8000-000000019099','text/plain',1,$3,'reserved',gen_random_uuid(),'recovery',gen_random_uuid(),gen_random_uuid(),1,120000,clock_timestamp()+interval '2 minutes')`, providerOneID, storeID, digest); err == nil {
		t.Fatal("duplicate provider publication ordinal was accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_publications(
		id,provider_attempt_id,publication_ordinal,result_occurrence_id,artifact_id,artifact_store_id,storage_key,
		content_type,content_size_bytes,content_sha256,publication_state,origin_owner_instance_id,owner_kind,
		owner_instance_id,publication_token,fence_generation,lease_duration_ms,lease_expires_at)
		VALUES(gen_random_uuid(),$1,1,gen_random_uuid(),'00000000-0000-4000-8000-000000019098',$2,'v1/00/00000000-0000-4000-8000-000000019098','text/plain',1,$3,'cleanup_quarantined',gen_random_uuid(),'recovery',gen_random_uuid(),gen_random_uuid(),1,120000,clock_timestamp()+interval '2 minutes')`, providerOneID, storeID, digest); err == nil {
		t.Fatal("unknown publication state was accepted")
	}
	assertArtifactPublicationTransitions(t, ctx, pool, taskID, runID, stepTwoID, providerTwoID, storeID, digest)

	if err := insertFoundationFFR(ctx, pool, recordOneID, programID, taskID, runID, stepOneID, 1, actionID, resultOneID, waveID, 0, authorizationID, nil); err != nil {
		t.Fatal(err)
	}
	if err := insertFoundationFFR(ctx, pool, recordTwoID, programID, taskID, runID, stepOneID, 2, actionID, resultTwoID, waveID, 0, authorizationID, nil); err != nil {
		t.Fatalf("action_request_id did not repeat across attempts: %v", err)
	}
	var repeated int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM failure_finalization_records WHERE action_request_id=$1`, actionID).Scan(&repeated); err != nil || repeated != 2 {
		t.Fatalf("repeated action lineage count=%d error=%v", repeated, err)
	}
	if err := insertFoundationFFR(ctx, pool, "00000000-0000-4000-8000-000000019021", programID, taskID, runID, stepOneID, 3, actionID, resultTwoID, waveID, 0, authorizationID, nil); err == nil {
		t.Fatal("duplicate result_occurrence_id was accepted")
	}
	providerID := providerOneID
	if err := insertFoundationFFR(ctx, pool, recordThreeID, programID, taskID, runID, stepTwoID, 1, actionID, "00000000-0000-4000-8000-000000019022", waveID, 1, authorizationID, &providerID); err != nil {
		t.Fatal(err)
	}
	if err := insertFoundationFFR(ctx, pool, "00000000-0000-4000-8000-000000019023", programID, taskID, runID, stepTwoID, 2, actionID, "00000000-0000-4000-8000-000000019024", waveID, 1, authorizationID, &providerID); err == nil {
		t.Fatal("duplicate provider_attempt_id was accepted")
	}

	if _, err := pool.Exec(ctx, `INSERT INTO step_attempt_claims(
		step_run_id,step_attempt,action_request_id,record_id,wave_id,wave_member_ordinal,claim_state,
		owner_kind,owner_instance_id,origin_owner_instance_id,claim_token,fence_generation,lease_duration_ms,lease_expires_at)
		VALUES($1,1,$2,$3,$4,0,'active','recovery',gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1,120000,clock_timestamp()+interval '2 minutes')`, stepOneID, actionID, recordOneID, waveID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO step_attempt_claims(
		step_run_id,step_attempt,action_request_id,record_id,wave_id,wave_member_ordinal,claim_state,
		owner_kind,owner_instance_id,origin_owner_instance_id,claim_token,fence_generation,lease_duration_ms,
		lease_expires_at,last_release_id,closed_at,close_reason)
		VALUES($1,2,$2,$3,$4,0,'released','recovery',gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1,120000,
		clock_timestamp()+interval '2 minutes',gen_random_uuid(),clock_timestamp(),'handoff')`, stepOneID, actionID, recordTwoID, waveID); err == nil {
		t.Fatal("released claim with current ownership was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE step_attempt_claims SET renewal_sequence=1,last_renewal_id=gen_random_uuid() WHERE step_run_id=$1 AND step_attempt=1`, stepOneID); err == nil {
		t.Fatal("claim renewal ID without renewal timestamp was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE step_attempt_claims SET renewal_sequence=1,last_renewal_id=gen_random_uuid(),last_renewed_at=clock_timestamp() WHERE step_run_id=$1 AND step_attempt=1`, stepOneID); err != nil {
		t.Fatalf("valid claim renewal tuple was rejected: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE step_attempt_claims SET renewal_sequence=0 WHERE step_run_id=$1 AND step_attempt=1`, stepOneID); err == nil {
		t.Fatal("zero claim renewal sequence with renewal identity was accepted")
	}

	if _, err := pool.Exec(ctx, `INSERT INTO workflow_wave_members(wave_id,member_ordinal,step_run_id,step_definition_id,member_state) VALUES($1,2,$2,'duplicate','planned')`, waveID, stepOneID); err == nil {
		t.Fatal("duplicate wave member step was accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO workflow_attempt_waves(wave_id,workflow_run_id,wave_sequence,materialization_digest,member_count,propagation_state,dispatch_state) VALUES(gen_random_uuid(),$1,1,$2,1,'not_required','pending')`, runID, digest); err == nil {
		t.Fatal("duplicate workflow wave sequence was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE workflow_attempt_waves SET propagation_renewal_sequence=1 WHERE wave_id=$1`, waveID); err == nil {
		t.Fatal("positive propagation renewal sequence without identity was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE workflow_attempt_waves SET propagation_last_renewal_id=gen_random_uuid() WHERE wave_id=$1`, waveID); err == nil {
		t.Fatal("zero propagation renewal sequence with identity was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE workflow_attempt_waves SET propagation_renewal_sequence=1,propagation_last_renewal_id=gen_random_uuid() WHERE wave_id=$1`, waveID); err != nil {
		t.Fatalf("valid propagation renewal tuple was rejected: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE workflow_attempt_waves SET dispatch_renewal_sequence=1 WHERE wave_id=$1`, waveID); err == nil {
		t.Fatal("positive dispatch renewal sequence without identity was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE workflow_attempt_waves SET dispatch_last_renewal_id=gen_random_uuid() WHERE wave_id=$1`, waveID); err == nil {
		t.Fatal("zero dispatch renewal sequence with identity was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE workflow_attempt_waves SET dispatch_renewal_sequence=1,dispatch_last_renewal_id=gen_random_uuid() WHERE wave_id=$1`, waveID); err != nil {
		t.Fatalf("valid dispatch renewal tuple was rejected: %v", err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,provider_attempt_id,safe_message,details) VALUES(gen_random_uuid(),'provider_invocation_succeeded','provider','integration',$1,'succeeded','{}')`, providerOneID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,provider_attempt_id,safe_message,details) VALUES(gen_random_uuid(),'provider_invocation_timed_out','provider','integration',$1,'timed out','{}')`, providerOneID); err == nil {
		t.Fatal("timeout did not share provider terminal uniqueness")
	}
}

func assertArtifactPublicationTransitions(t *testing.T, ctx context.Context, pool *pgxpool.Pool, taskID, runID, stepID, providerAttemptID, storeID, digest string) {
	t.Helper()
	const toolRunID = "00000000-0000-4000-8000-000000019025"
	if _, err := pool.Exec(ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at,provider_attempt_id) VALUES($1,$2,'test.capability','test-provider',clock_timestamp(),$3)`, toolRunID, stepID, providerAttemptID); err != nil {
		t.Fatal(err)
	}

	type route struct {
		name   string
		states []string
	}
	legalRoutes := []route{
		{"reserved_to_publishing", []string{"publishing"}},
		{"publishing_to_sealed", []string{"publishing", "sealed"}},
		{"sealed_to_adopted", []string{"publishing", "sealed", "adopted"}},
		{"reserved_to_abandoned", []string{"abandoned"}},
		{"reserved_to_quarantined", []string{"quarantined"}},
		{"publishing_to_abandoned", []string{"publishing", "abandoned"}},
		{"publishing_to_quarantined", []string{"publishing", "quarantined"}},
		{"sealed_to_abandoned", []string{"publishing", "sealed", "abandoned"}},
		{"sealed_to_quarantined", []string{"publishing", "sealed", "quarantined"}},
	}
	ordinal := 100
	for _, route := range legalRoutes {
		ordinal++
		publicationID, artifactID, storageKey := insertReservedTransitionPublication(t, ctx, pool, providerAttemptID, storeID, digest, ordinal)
		for _, state := range route.states {
			if state == "adopted" {
				insertTransitionArtifact(t, ctx, pool, artifactID, taskID, runID, stepID, toolRunID, storeID, storageKey, digest)
			}
			if _, err := transitionArtifactPublication(ctx, pool, publicationID, state); err != nil {
				t.Fatalf("legal publication transition %s to %s was rejected: %v", route.name, state, err)
			}
		}
	}

	illegalRoutes := []struct {
		from string
		to   string
	}{
		{"adopted", "abandoned"},
		{"adopted", "quarantined"},
		{"adopted", "sealed"},
		{"abandoned", "adopted"},
		{"abandoned", "quarantined"},
		{"abandoned", "publishing"},
		{"quarantined", "adopted"},
		{"quarantined", "abandoned"},
		{"quarantined", "publishing"},
	}
	for _, route := range illegalRoutes {
		ordinal++
		publicationID, artifactID, storageKey := insertReservedTransitionPublication(t, ctx, pool, providerAttemptID, storeID, digest, ordinal)
		for _, state := range publicationRouteTo(route.from) {
			if state == "adopted" {
				insertTransitionArtifact(t, ctx, pool, artifactID, taskID, runID, stepID, toolRunID, storeID, storageKey, digest)
			}
			if _, err := transitionArtifactPublication(ctx, pool, publicationID, state); err != nil {
				t.Fatalf("prepare terminal publication state %s: %v", route.from, err)
			}
		}
		_, err := transitionArtifactPublication(ctx, pool, publicationID, route.to)
		assertSQLRejectedContaining(t, err, "terminal artifact publication state is immutable")
	}

	ordinal++
	deletedID, _, _ := insertReservedTransitionPublication(t, ctx, pool, providerAttemptID, storeID, digest, ordinal)
	if _, err := transitionArtifactPublication(ctx, pool, deletedID, "abandoned"); err != nil {
		t.Fatal(err)
	}
	claimArtifactPublicationCleanup(t, ctx, pool, deletedID)
	if _, err := pool.Exec(ctx, `UPDATE artifact_publications SET cleanup_claim_token=NULL,cleanup_claimed_at=NULL,cleanup_retry_after=clock_timestamp()+interval '1 minute',cleanup_last_error_code='filesystem_io' WHERE id=$1`, deletedID); err != nil {
		t.Fatalf("claimed-to-retry cleanup transition was rejected: %v", err)
	}
	claimArtifactPublicationCleanup(t, ctx, pool, deletedID)
	if _, err := pool.Exec(ctx, `UPDATE artifact_publications SET cleanup_claim_token=NULL,cleanup_claimed_at=NULL,content_deleted_at=clock_timestamp() WHERE id=$1`, deletedID); err != nil {
		t.Fatalf("claimed-to-content-deleted cleanup transition was rejected: %v", err)
	}
	_, err := pool.Exec(ctx, `UPDATE artifact_publications SET content_deleted_at=NULL WHERE id=$1`, deletedID)
	assertSQLRejectedContaining(t, err, "content-deleted publication cleanup is terminal and immutable")
	_, err = pool.Exec(ctx, `UPDATE artifact_publications SET content_deleted_at=NULL,cleanup_last_error_code='unexpected_entry_type',cleanup_quarantined_at=clock_timestamp() WHERE id=$1`, deletedID)
	assertSQLRejectedContaining(t, err, "content-deleted publication cleanup is terminal and immutable")

	ordinal++
	quarantinedID, _, _ := insertReservedTransitionPublication(t, ctx, pool, providerAttemptID, storeID, digest, ordinal)
	if _, err := transitionArtifactPublication(ctx, pool, quarantinedID, "abandoned"); err != nil {
		t.Fatal(err)
	}
	claimArtifactPublicationCleanup(t, ctx, pool, quarantinedID)
	if _, err := pool.Exec(ctx, `UPDATE artifact_publications SET cleanup_claim_token=NULL,cleanup_claimed_at=NULL,cleanup_last_error_code='unexpected_entry_type',cleanup_quarantined_at=clock_timestamp() WHERE id=$1`, quarantinedID); err != nil {
		t.Fatalf("claimed-to-cleanup-quarantined transition was rejected: %v", err)
	}
	_, err = pool.Exec(ctx, `UPDATE artifact_publications SET cleanup_last_error_code=NULL,cleanup_quarantined_at=NULL WHERE id=$1`, quarantinedID)
	assertSQLRejectedContaining(t, err, "cleanup-quarantined publication cleanup is terminal and immutable")
	_, err = pool.Exec(ctx, `UPDATE artifact_publications SET cleanup_last_error_code=NULL,cleanup_quarantined_at=NULL,content_deleted_at=clock_timestamp() WHERE id=$1`, quarantinedID)
	assertSQLRejectedContaining(t, err, "cleanup-quarantined publication cleanup is terminal and immutable")
}

func insertReservedTransitionPublication(t *testing.T, ctx context.Context, pool *pgxpool.Pool, providerAttemptID, storeID, digest string, ordinal int) (string, string, string) {
	t.Helper()
	publicationID := foundationTransitionID(0x10000001, ordinal)
	resultID := foundationTransitionID(0x20000001, ordinal)
	artifactID := foundationTransitionID(0x30000001, ordinal)
	storageKey := "v1/" + strings.ReplaceAll(artifactID, "-", "")[:2] + "/" + artifactID
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_publications(
		id,provider_attempt_id,publication_ordinal,result_occurrence_id,artifact_id,artifact_store_id,storage_key,
		content_type,content_size_bytes,content_sha256,publication_state,origin_owner_instance_id,owner_kind,
		owner_instance_id,publication_token,fence_generation,lease_duration_ms,lease_expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,'text/plain',1,$8,'reserved',gen_random_uuid(),'recovery',gen_random_uuid(),gen_random_uuid(),1,120000,clock_timestamp()+interval '2 minutes')`, publicationID, providerAttemptID, ordinal, resultID, artifactID, storeID, storageKey, digest); err != nil {
		t.Fatal(err)
	}
	return publicationID, artifactID, storageKey
}

func insertTransitionArtifact(t *testing.T, ctx context.Context, pool *pgxpool.Pool, artifactID, taskID, runID, stepID, toolRunID, storeID, storageKey, digest string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `INSERT INTO artifacts(
		id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,redaction_state,
		addressing_version,artifact_store_id,storage_key)
		VALUES($1,$2,$3,$4,$5,'large-result','text/plain',1,$6,'not_required',1,$7,$8)`, artifactID, taskID, runID, stepID, toolRunID, digest, storeID, storageKey); err != nil {
		t.Fatal(err)
	}
}

func transitionArtifactPublication(ctx context.Context, pool *pgxpool.Pool, publicationID, state string) (pgconn.CommandTag, error) {
	return pool.Exec(ctx, `UPDATE artifact_publications SET
		publication_state=$2,
		publishing_at=CASE WHEN $2 IN ('publishing','sealed','adopted') THEN COALESCE(publishing_at,clock_timestamp()) ELSE publishing_at END,
		sealed_at=CASE WHEN $2 IN ('sealed','adopted') THEN COALESCE(sealed_at,clock_timestamp()) ELSE CASE WHEN $2='publishing' THEN NULL ELSE sealed_at END END,
		adopted_at=CASE WHEN $2='adopted' THEN COALESCE(adopted_at,clock_timestamp()) ELSE NULL END,
		abandoned_at=CASE WHEN $2='abandoned' THEN COALESCE(abandoned_at,clock_timestamp()) ELSE NULL END,
		quarantined_at=CASE WHEN $2='quarantined' THEN COALESCE(quarantined_at,clock_timestamp()) ELSE NULL END,
		quarantine_reason_code=CASE WHEN $2='quarantined' THEN 'transition_test' ELSE NULL END,
		owner_kind=CASE WHEN $2 IN ('reserved','publishing','sealed') THEN 'recovery' ELSE NULL END,
		owner_instance_id=CASE WHEN $2 IN ('reserved','publishing','sealed') THEN COALESCE(owner_instance_id,gen_random_uuid()) ELSE NULL END,
		publication_token=CASE WHEN $2 IN ('reserved','publishing','sealed') THEN COALESCE(publication_token,gen_random_uuid()) ELSE NULL END,
		lease_expires_at=CASE WHEN $2 IN ('reserved','publishing','sealed') THEN COALESCE(lease_expires_at,clock_timestamp()+interval '2 minutes') ELSE NULL END
		WHERE id=$1`, publicationID, state)
}

func publicationRouteTo(state string) []string {
	switch state {
	case "adopted":
		return []string{"publishing", "sealed", "adopted"}
	case "abandoned", "quarantined":
		return []string{state}
	default:
		panic("unsupported terminal publication state " + state)
	}
}

func claimArtifactPublicationCleanup(t *testing.T, ctx context.Context, pool *pgxpool.Pool, publicationID string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `UPDATE artifact_publications SET cleanup_claim_token=gen_random_uuid(),cleanup_claimed_at=clock_timestamp(),cleanup_retry_after=NULL,cleanup_last_error_code=NULL WHERE id=$1`, publicationID); err != nil {
		t.Fatalf("legal publication cleanup claim was rejected: %v", err)
	}
}

func assertSQLRejectedContaining(t *testing.T, err error, message string) {
	t.Helper()
	if err == nil {
		t.Fatalf("SQL operation unexpectedly succeeded; wanted %q", message)
	}
	if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(message)) {
		t.Fatalf("SQL rejection %q did not contain %q", err, message)
	}
}

func foundationTransitionID(prefix, ordinal int) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", prefix, ordinal)
}

func insertFoundationFFR(ctx context.Context, pool *pgxpool.Pool, recordID, programID, taskID, runID, stepID string, stepAttempt int, actionID, resultID, waveID string, ordinal int, authorizationID string, providerAttemptID *string) error {
	var provider any
	var state = "prepared"
	var outcome = "not_started"
	if providerAttemptID != nil {
		provider = "test-provider"
		state = "provider_started"
		outcome = "unknown"
	}
	_, err := pool.Exec(ctx, `INSERT INTO failure_finalization_records(
		record_id,program_id,task_id,workflow_run_id,step_run_id,step_attempt,action_request_id,result_occurrence_id,
		wave_id,wave_member_ordinal,execution_authorization_event_id,origin_owner_instance_id,claim_token,claim_fence_generation,
		provider_attempt_id,provider_terminal_event_id,provider_result_accepted_event_id,tool_run_id,capability,provider,
		provider_outcome,result_persistence_outcome,adoption_resolution,record_state,propagation_state,
		finalization_charge_1_id,finalization_charge_1_audit_event_id,finalization_begin_1_event_id,finalization_outcome_1_event_id,
		finalization_charge_2_id,finalization_charge_2_audit_event_id,finalization_begin_2_event_id,finalization_outcome_2_event_id,
		result_commit_unknown_event_id,result_commit_resolution_event_id,failure_finalization_failed_event_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,gen_random_uuid(),gen_random_uuid(),1,
		$12,CASE WHEN $12::uuid IS NULL THEN NULL ELSE gen_random_uuid() END,
		CASE WHEN $12::uuid IS NULL THEN NULL ELSE gen_random_uuid() END,
		CASE WHEN $12::uuid IS NULL THEN NULL ELSE gen_random_uuid() END,
		'test.capability',$13,$14,'not_attempted','not_applicable',$15,'not_applicable',
		gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),
		gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),
		gen_random_uuid(),gen_random_uuid(),gen_random_uuid())`,
		recordID, programID, taskID, runID, stepID, stepAttempt, actionID, resultID, waveID, ordinal, authorizationID,
		providerAttemptID, provider, outcome, state)
	return err
}
