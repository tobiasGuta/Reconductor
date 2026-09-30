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
	if len(versions) != 22 {
		t.Fatalf("migrations=%v", versions)
	}
	wantVersions := []string{
		"0001_platform_core.sql",
		"0002_findings_approvals_audit.sql",
		"0003_audit_immutability.sql",
		"0004_scope_target_plans.sql",
		"0005_policy_enforcement.sql",
		"0006_verification_verdicts.sql",
		"0007_scheduled_reconnaissance.sql",
		"0008_scheduler_hardening.sql",
		"0009_scheduler_recovery_protocol.sql",
		"0010_structured_execution_provenance.sql",
		"0011_provider_attempt_provenance.sql",
		"0012_asset_observation_emissions.sql",
		"0013_endpoint_origin_identity.sql",
		"0014_concrete_http_resource_lineage.sql",
		"0015_workflow_template_materialization_integrity.sql",
		"0016_artifact_store_ownership.sql",
		"0017_artifact_store_tombstone_cleanup.sql",
		"0018_large_result_publication_journal.sql",
		"0019_large_result_recovery_foundation.sql",
		"0020_prepared_evidence_ownership.sql",
		"0021_provider_output_authority_ceiling.sql",
		"0022_exact_launch_authority_foundation.sql",
	}
	for index := range wantVersions {
		if versions[index] != wantVersions[index] {
			t.Fatalf("migration[%d]=%q want=%q", index, versions[index], wantVersions[index])
		}
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

func TestStructuredExecutionProvenanceMigrationPreservesLegacyAuditRows(t *testing.T) {
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
	schema := "migration_provenance_" + strconv.FormatInt(time.Now().UnixNano(), 10)
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
	applyEmbeddedMigrationsThrough(t, ctx, pool, 9)

	const (
		programID      = "00000000-0000-4000-8000-000000001001"
		scopeVersionID = "00000000-0000-4000-8000-000000001002"
		scheduleID     = "00000000-0000-4000-8000-000000001003"
		executionID    = "00000000-0000-4000-8000-000000001004"
		legacyAuditID  = "00000000-0000-4000-8000-000000001005"
	)
	if _, err := pool.Exec(ctx, `INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,'migration-provenance','integration','synthetic://local','integration')`, programID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,target_plan_digest,target_plan) VALUES($1,$2,'synthetic://local','scope','plan','{}')`, scopeVersionID, programID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO schedules(id,program_id,name,workflow_name,objective,cron_expression,timezone,created_by,next_run_at) VALUES($1,$2,'migration-provenance','continuous-web-recon','migration provenance','0 9 * * *','UTC','integration',clock_timestamp()+interval '1 hour')`, scheduleID, programID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scheduled_executions(id,schedule_id,planned_at,trigger_source,status) VALUES($1,$2,clock_timestamp(),'run_now','pending')`, executionID, scheduleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,'legacy_scheduler_event','scheduler','integration',$2,'legacy row','{"scheduled_execution_id":"legacy-details-only"}')`, legacyAuditID, programID); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}

	var legacyCount int
	var scheduledExecution, schedulerAttempt, scopeVersion *string
	if err := pool.QueryRow(ctx, `SELECT count(*),max(scheduled_execution_id::text),max(scheduler_attempt::text),max(scope_version_id::text) FROM audit_events WHERE id=$1`, legacyAuditID).Scan(&legacyCount, &scheduledExecution, &schedulerAttempt, &scopeVersion); err != nil {
		t.Fatal(err)
	}
	if legacyCount != 1 || scheduledExecution != nil || schedulerAttempt != nil || scopeVersion != nil {
		t.Fatalf("legacy audit changed count=%d execution=%v attempt=%v scope=%v", legacyCount, scheduledExecution, schedulerAttempt, scopeVersion)
	}

	insertAudit := func(id string, execution any, attempt any, scope any) error {
		_, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,scheduled_execution_id,scheduler_attempt,scope_version_id,safe_message) VALUES($1,'migration_constraint_test','scheduler','integration',$2,$3,$4,$5,'constraint test')`, id, programID, execution, attempt, scope)
		return err
	}
	if err := insertAudit("00000000-0000-4000-8000-000000001006", executionID, 0, nil); err == nil {
		t.Fatal("scheduler_attempt=0 was accepted")
	}
	if err := insertAudit("00000000-0000-4000-8000-000000001007", executionID, -1, nil); err == nil {
		t.Fatal("negative scheduler_attempt was accepted")
	}
	if err := insertAudit("00000000-0000-4000-8000-000000001008", "00000000-0000-4000-8000-000000001099", 1, nil); err == nil {
		t.Fatal("missing scheduled execution foreign key was accepted")
	}
	if err := insertAudit("00000000-0000-4000-8000-000000001009", executionID, 1, "00000000-0000-4000-8000-000000001099"); err == nil {
		t.Fatal("missing scope version foreign key was accepted")
	}
	if err := insertAudit("00000000-0000-4000-8000-000000001010", executionID, 1, scopeVersionID); err != nil {
		t.Fatalf("valid structured audit row: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE audit_events SET scheduler_attempt=1 WHERE id=$1`, legacyAuditID); err == nil || !strings.Contains(err.Error(), "audit_events are append-only") {
		t.Fatalf("audit update error=%v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM audit_events WHERE id=$1`, legacyAuditID); err == nil || !strings.Contains(err.Error(), "audit_events are append-only") {
		t.Fatalf("audit delete error=%v", err)
	}
	var indexDefinition string
	if err := pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='audit_events_execution_trace_idx'`).Scan(&indexDefinition); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"scheduled_execution_id", "occurred_at", "id", "WHERE (scheduled_execution_id IS NOT NULL)"} {
		if !strings.Contains(indexDefinition, required) {
			t.Fatalf("index definition %q missing %q", indexDefinition, required)
		}
	}
}

func TestProviderAttemptProvenanceMigrationConstraints(t *testing.T) {
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
	schema := "migration_provider_attempt_" + strconv.FormatInt(time.Now().UnixNano(), 10)
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
	applyEmbeddedMigrationsThrough(t, ctx, pool, 10)

	const (
		programID     = "00000000-0000-4000-8000-000000002001"
		definitionID  = "00000000-0000-4000-8000-000000002002"
		taskID        = "00000000-0000-4000-8000-000000002003"
		runID         = "00000000-0000-4000-8000-000000002004"
		stepID        = "00000000-0000-4000-8000-000000002005"
		legacyAuditID = "00000000-0000-4000-8000-000000002006"
		legacyToolID  = "00000000-0000-4000-8000-000000002007"
		actionID      = "00000000-0000-4000-8000-000000002008"
		authorizeID   = "00000000-0000-4000-8000-000000002009"
		providerID    = "00000000-0000-4000-8000-000000002010"
		terminalID    = "00000000-0000-4000-8000-000000002011"
		linkedToolID  = "00000000-0000-4000-8000-000000002012"
	)
	for _, statement := range []string{
		`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES('` + programID + `','provider-attempt-migration','integration','synthetic://local','integration')`,
		`INSERT INTO workflow_definitions(id,name,version,definition) VALUES('` + definitionID + `','provider-attempt-migration','1','{}')`,
		`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES('` + taskID + `','` + programID + `','migration','` + definitionID + `','running','integration')`,
		`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source) VALUES('` + runID + `','` + taskID + `','` + definitionID + `','1','running','integration')`,
		`INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,idempotency_key) VALUES('` + stepID + `','` + runID + `','step','test.capability','running','provider-attempt-migration')`,
		`INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,safe_message) VALUES('` + legacyAuditID + `','legacy_provider_history','test','integration','` + taskID + `','` + programID + `','` + runID + `','` + stepID + `','legacy')`,
		`INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at) VALUES('` + legacyToolID + `','` + stepID + `','test.capability','legacy',clock_timestamp())`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE step_runs SET status='succeeded',completed_at=clock_timestamp() WHERE id=$1`, stepID); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}

	var legacyAction, legacyAttempt, legacyQueue, legacyAuthorization, legacyProvider, legacyToolProvider *string
	if err := pool.QueryRow(ctx, `SELECT action_request_id::text,step_attempt::text,queue_job_id::text,execution_authorization_event_id::text,provider_attempt_id::text FROM audit_events WHERE id=$1`, legacyAuditID).Scan(&legacyAction, &legacyAttempt, &legacyQueue, &legacyAuthorization, &legacyProvider); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT provider_attempt_id::text FROM tool_runs WHERE id=$1`, legacyToolID).Scan(&legacyToolProvider); err != nil {
		t.Fatal(err)
	}
	if legacyAction != nil || legacyAttempt != nil || legacyQueue != nil || legacyAuthorization != nil || legacyProvider != nil || legacyToolProvider != nil {
		t.Fatalf("legacy provenance was backfilled: action=%v attempt=%v queue=%v authorization=%v provider=%v tool=%v", legacyAction, legacyAttempt, legacyQueue, legacyAuthorization, legacyProvider, legacyToolProvider)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,action_request_id,step_attempt,capability,provider,safe_message,details) VALUES($1,'policy_allowed','policy','integration',$2,$3,$4,$5,$6,3,'test.capability','test-provider','allow','{"phase":"execution"}')`, authorizeID, taskID, programID, runID, stepID, actionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,action_request_id,step_attempt,execution_authorization_event_id,capability,provider,safe_message) VALUES($1,'provider_invocation_started','provider','integration',$2,$3,$4,$5,$6,3,$7,'test.capability','test-provider','start')`, providerID, taskID, programID, runID, stepID, actionID, authorizeID); err != nil {
		t.Fatal(err)
	}
	var startProvider *string
	if err := pool.QueryRow(ctx, `SELECT provider_attempt_id::text FROM audit_events WHERE id=$1`, providerID).Scan(&startProvider); err != nil || startProvider != nil {
		t.Fatalf("start provider_attempt_id=%v err=%v", startProvider, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,action_request_id,execution_authorization_event_id,safe_message) VALUES(gen_random_uuid(),'provider_invocation_started','provider','integration',$1,$2,'bad step')`, actionID, authorizeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,execution_authorization_event_id,safe_message) VALUES(gen_random_uuid(),'provider_invocation_started','provider','integration',$1,'missing action')`, authorizeID); err == nil {
		t.Fatal("provider start without action_request_id was accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,action_request_id,step_attempt,safe_message) VALUES(gen_random_uuid(),'test_step_attempt','test','integration',$1,0,'zero attempt')`, actionID); err == nil {
		t.Fatal("step_attempt=0 was accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,action_request_id,step_attempt,safe_message) VALUES(gen_random_uuid(),'test_step_attempt','test','integration',$1,-1,'negative attempt')`, actionID); err == nil {
		t.Fatal("negative step_attempt was accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,action_request_id,execution_authorization_event_id,safe_message) VALUES(gen_random_uuid(),'provider_invocation_started','provider','integration',$1,'00000000-0000-4000-8000-000000002099','missing authorization')`, actionID); err == nil {
		t.Fatal("missing execution authorization FK was accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,provider_attempt_id,safe_message) VALUES($1,'provider_invocation_succeeded','provider','integration',$2,'success')`, terminalID, providerID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,provider_attempt_id,safe_message) VALUES(gen_random_uuid(),'provider_invocation_failed','provider','integration',$1,'duplicate')`, providerID); err == nil {
		t.Fatal("duplicate terminal was accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,safe_message) VALUES(gen_random_uuid(),'provider_invocation_cancelled','provider','integration','missing provider')`); err == nil {
		t.Fatal("terminal without provider_attempt_id was accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at,provider_attempt_id) VALUES($1,$2,'test.capability','test-provider',clock_timestamp(),$3)`, linkedToolID, stepID, providerID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at,provider_attempt_id) VALUES(gen_random_uuid(),$1,'test.capability','test-provider',clock_timestamp(),$2)`, stepID, providerID); err == nil {
		t.Fatal("second ToolRun for one provider attempt was accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at,provider_attempt_id) VALUES(gen_random_uuid(),$1,'test.capability','test-provider',clock_timestamp(),'00000000-0000-4000-8000-000000002099')`, stepID); err == nil {
		t.Fatal("missing ToolRun provider attempt FK was accepted")
	}
	if _, err := pool.Exec(ctx, `UPDATE audit_events SET provider_attempt_id=$2 WHERE id=$1`, legacyAuditID, providerID); err == nil || !strings.Contains(err.Error(), "audit_events are append-only") {
		t.Fatalf("audit update error=%v", err)
	}
}

func TestAssetObservationEmissionMigrationDoesNotBackfill(t *testing.T) {
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
	schema := "migration_observation_emissions_" + strconv.FormatInt(time.Now().UnixNano(), 10)
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
	applyEmbeddedMigrationsThrough(t, ctx, pool, 11)

	const (
		programID     = "00000000-0000-4000-8000-000000003001"
		definitionID  = "00000000-0000-4000-8000-000000003002"
		taskID        = "00000000-0000-4000-8000-000000003003"
		runID         = "00000000-0000-4000-8000-000000003004"
		assetID       = "00000000-0000-4000-8000-000000003005"
		observationID = "00000000-0000-4000-8000-000000003006"
	)
	for _, statement := range []string{
		`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES('` + programID + `','observation-emission-migration','integration','synthetic://local','integration')`,
		`INSERT INTO workflow_definitions(id,name,version,definition) VALUES('` + definitionID + `','observation-emission-migration','1','{}')`,
		`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES('` + taskID + `','` + programID + `','migration','` + definitionID + `','running','integration')`,
		`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source) VALUES('` + runID + `','` + taskID + `','` + definitionID + `','1','completed','integration')`,
		`INSERT INTO assets(id,program_id,type,canonical_value) VALUES('` + assetID + `','` + programID + `','http_service','https://historical.test/')`,
		`INSERT INTO asset_observations(id,asset_id,workflow_run_id,source_capability,observed_value,first_seen_at,observed_at,confidence) VALUES('` + observationID + `','` + assetID + `','` + runID + `','probe.http','https://historical.test/',clock_timestamp(),clock_timestamp(),1)`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	if err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var observations, emissions int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM asset_observations WHERE id=$1),
		(SELECT count(*) FROM asset_observation_emissions)`, observationID).Scan(&observations, &emissions); err != nil {
		t.Fatal(err)
	}
	if observations != 1 || emissions != 0 {
		t.Fatalf("historical observations=%d emissions=%d", observations, emissions)
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

func TestEndpointOriginIdentityMigrationPreservesLegacyRowsAndGuardsCorrectedIdentity(t *testing.T) {
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
	schema := "migration_endpoint_origin_" + strconv.FormatInt(time.Now().UnixNano(), 10)
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
	applyEmbeddedMigrationsThrough(t, ctx, pool, 12)

	const (
		programID   = "00000000-0000-4000-8000-000000004001"
		legacyID    = "00000000-0000-4000-8000-000000004002"
		correctedID = "00000000-0000-4000-8000-000000004003"
	)
	if _, err := pool.Exec(ctx, `INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,'endpoint-origin-migration','integration','synthetic://local','integration')`, programID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO endpoints(id,program_id,exact_url,route_signature,method,content_type,parameter_schema,first_seen,last_seen) VALUES($1,$2,'https://legacy.example/api/users/123','/api/users/{id}','GET','','["id"]','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z')`, legacyID, programID); err != nil {
		t.Fatal(err)
	}
	var before string
	if err := pool.QueryRow(ctx, `SELECT to_jsonb(e)::text FROM endpoints e WHERE id=$1`, legacyID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := Up(ctx, pool); err != nil {
		t.Fatalf("second Up: %v", err)
	}

	var after string
	var scheme, host *string
	var port *int
	if err := pool.QueryRow(ctx, `SELECT (to_jsonb(e)-'origin_scheme'-'origin_host'-'origin_effective_port')::text,origin_scheme,origin_host,origin_effective_port FROM endpoints e WHERE id=$1`, legacyID).Scan(&after, &scheme, &host, &port); err != nil {
		t.Fatal(err)
	}
	if before != after || scheme != nil || host != nil || port != nil {
		t.Fatalf("legacy row changed before=%s after=%s origin=%v/%v/%v", before, after, scheme, host, port)
	}

	var validated bool
	if err := pool.QueryRow(ctx, `SELECT convalidated FROM pg_constraint WHERE conrelid='endpoints'::regclass AND conname='endpoints_corrected_row_ck'`).Scan(&validated); err != nil {
		t.Fatal(err)
	}
	if validated {
		t.Fatal("corrected endpoint constraint was unexpectedly validated")
	}
	var correctedIndex string
	if err := pool.QueryRow(ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() AND indexname='endpoints_corrected_identity_uq'`).Scan(&correctedIndex); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"program_id", "origin_scheme", "origin_host", "origin_effective_port", "route_signature", "method", "content_type", "parameter_schema", "WHERE", "origin_scheme IS NOT NULL", "origin_host IS NOT NULL", "origin_effective_port IS NOT NULL"} {
		if !strings.Contains(correctedIndex, required) {
			t.Fatalf("corrected index %q missing %q", correctedIndex, required)
		}
	}
	lastPosition := -1
	for _, column := range []string{"program_id", "origin_scheme", "origin_host", "origin_effective_port", "route_signature", "method", "content_type", "parameter_schema"} {
		position := strings.Index(correctedIndex, column)
		if position <= lastPosition {
			t.Fatalf("corrected index columns are out of order in %q at %q", correctedIndex, column)
		}
		lastPosition = position
	}
	var oldIndex, triggerCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes WHERE schemaname=current_schema() AND indexname='endpoints_identity_uq'`).Scan(&oldIndex); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_trigger WHERE tgrelid='endpoints'::regclass AND tgname='endpoints_identity_guard' AND NOT tgisinternal`).Scan(&triggerCount); err != nil {
		t.Fatal(err)
	}
	if oldIndex != 0 || triggerCount != 1 {
		t.Fatalf("old index=%d identity triggers=%d", oldIndex, triggerCount)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO endpoints(id,program_id,exact_url,route_signature,method,content_type,parameter_schema,first_seen,last_seen) VALUES(gen_random_uuid(),$1,'https://invalid.example/','/','GET','','[]',clock_timestamp(),clock_timestamp())`, programID); err == nil || !strings.Contains(err.Error(), "endpoints_corrected_row_ck") {
		t.Fatalf("direct legacy-shaped insert error=%v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO endpoints(id,program_id,exact_url,route_signature,method,content_type,parameter_schema,origin_scheme,origin_host,first_seen,last_seen) VALUES(gen_random_uuid(),$1,'https://partial.example/','/','GET','','[]','https','partial.example',clock_timestamp(),clock_timestamp())`, programID); err == nil {
		t.Fatal("partial origin row was accepted")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO endpoints(id,program_id,exact_url,route_signature,method,content_type,parameter_schema,origin_scheme,origin_host,origin_effective_port,first_seen,last_seen) VALUES($1,$2,'https://corrected.example/api/users/456','/api/users/{id}','GET','','["id"]','https','corrected.example',443,'2026-01-03T00:00:00Z','2026-01-03T00:00:00Z')`, correctedID, programID); err != nil {
		t.Fatalf("corrected same-route row: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE endpoints SET origin_scheme='https',origin_host='legacy.example',origin_effective_port=443 WHERE id=$1`, legacyID); err == nil || !strings.Contains(err.Error(), "endpoint identity fields are immutable") {
		t.Fatalf("legacy conversion error=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE endpoints SET origin_host='other.example' WHERE id=$1`, correctedID); err == nil || !strings.Contains(err.Error(), "endpoint identity fields are immutable") {
		t.Fatalf("corrected identity mutation error=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE endpoints SET exact_url='https://corrected.example/api/users/123',first_seen='2026-01-02T00:00:00Z',last_seen='2026-01-04T00:00:00Z' WHERE id=$1`, correctedID); err != nil {
		t.Fatalf("corrected aggregate update: %v", err)
	}
	var migrationCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=13 AND name='0013_endpoint_origin_identity.sql'`).Scan(&migrationCount); err != nil || migrationCount != 1 {
		t.Fatalf("migration ledger count=%d err=%v", migrationCount, err)
	}
}

func TestWorkflowTemplateMaterializationIntegrityMigration(t *testing.T) {
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
	schema := "migration_workflow_materialization_" + strconv.FormatInt(time.Now().UnixNano(), 10)
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
	applyEmbeddedMigrationsThrough(t, ctx, pool, 14)

	const (
		programID       = "00000000-0000-4000-8000-000000015001"
		scopeVersionID  = "00000000-0000-4000-8000-000000015002"
		baselineOldID   = "c9479711-b203-4fe1-8528-718888e5a5d2"
		continuousOldID = "d0e5e6a3-bd8a-4b4b-a76b-f6452c30179a"
		baselineTaskID  = "00000000-0000-4000-8000-000000015003"
		continuousTask  = "00000000-0000-4000-8000-000000015004"
		baselineRunID   = "00000000-0000-4000-8000-000000015005"
		continuousRunID = "00000000-0000-4000-8000-000000015006"
		currentDefID    = "3e62ed2c-ab49-421d-a4ce-5fdfead60f4a"
		currentTaskID   = "00000000-0000-4000-8000-000000015007"
		currentRunID    = "00000000-0000-4000-8000-000000015008"
	)
	for _, statement := range []string{
		`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES('` + programID + `','workflow-materialization-migration','integration','synthetic://local','integration')`,
		`INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,target_plan_digest,target_plan) VALUES('` + scopeVersionID + `','` + programID + `','synthetic://local','scope','plan','{}')`,
		`INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements) VALUES('` + baselineOldID + `','authorized-web-baseline','1.2.0','historical baseline','{}','{}')`,
		`INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements) VALUES('` + continuousOldID + `','continuous-web-recon','2.2.0','historical continuous','{}','{}')`,
		`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES('` + baselineTaskID + `','` + programID + `','legacy baseline','` + baselineOldID + `','completed','integration')`,
		`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES('` + continuousTask + `','` + programID + `','legacy continuous','` + continuousOldID + `','completed','integration')`,
		`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source) VALUES('` + baselineRunID + `','` + baselineTaskID + `','` + baselineOldID + `','1.2.0','completed','integration')`,
		`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source) VALUES('` + continuousRunID + `','` + continuousTask + `','` + continuousOldID + `','2.2.0','completed','integration')`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := Up(ctx, pool); err != nil {
		t.Fatal(err)
	}

	var legacyDefinitions, legacyRuns, legacyNullRuns int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM workflow_definitions WHERE id IN ($1,$2)),
		(SELECT count(*) FROM workflow_runs WHERE id IN ($3,$4)),
		(SELECT count(*) FROM workflow_runs WHERE id IN ($3,$4) AND materialized_definition IS NULL AND materialization_digest IS NULL AND original_scope_version_id IS NULL)`, baselineOldID, continuousOldID, baselineRunID, continuousRunID).Scan(&legacyDefinitions, &legacyRuns, &legacyNullRuns); err != nil {
		t.Fatal(err)
	}
	if legacyDefinitions != 2 || legacyRuns != 2 || legacyNullRuns != 2 {
		t.Fatalf("legacy definitions=%d runs=%d null_runs=%d", legacyDefinitions, legacyRuns, legacyNullRuns)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements) VALUES($1,'continuous-web-recon','2.4.0','current','{"schema_version":1,"kind":"built-in","materializer":"web-recon/v1"}','{}')`, currentDefID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES($1,$2,'current',$3,'running','integration')`, currentTaskID, programID, currentDefID); err != nil {
		t.Fatal(err)
	}
	materialized := `{"id":"` + currentDefID + `","name":"continuous-web-recon","version":"2.4.0","materializer":"web-recon/v1","description":"current","steps":[],"default_policy_requirements":{},"created_at":"2026-07-21T00:00:00Z"}`
	if _, err := pool.Exec(ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source,materialized_definition,materialization_digest,original_scope_version_id) VALUES($1,$2,$3,'2.4.0','running','integration',$4,$5,$6)`, currentRunID, currentTaskID, currentDefID, materialized, strings.Repeat("a", 64), scopeVersionID); err != nil {
		t.Fatal(err)
	}
	assertImmutable := func(name, statement string) {
		t.Helper()
		if _, err := pool.Exec(ctx, statement); err == nil || !strings.Contains(strings.ToLower(err.Error()), "immutable") {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	for _, id := range []string{baselineOldID, currentDefID} {
		for field, assignment := range map[string]string{
			"id":                          `id=gen_random_uuid()`,
			"name":                        `name=name||'-changed'`,
			"version":                     `version=version||'-changed'`,
			"description":                 `description=description||'-changed'`,
			"definition":                  `definition='{"changed":true}'::jsonb`,
			"default_policy_requirements": `default_policy_requirements='{"changed":true}'::jsonb`,
			"created_at":                  `created_at=created_at+interval '1 second'`,
		} {
			assertImmutable("workflow definition "+id+" "+field, `UPDATE workflow_definitions SET `+assignment+` WHERE id='`+id+`'`)
		}
	}
	assertImmutable("historical template delete", `DELETE FROM workflow_definitions WHERE id='`+baselineOldID+`'`)
	for _, id := range []string{baselineTaskID, currentTaskID} {
		for field, assignment := range map[string]string{
			"id":                     `id=gen_random_uuid()`,
			"program_id":             `program_id=gen_random_uuid()`,
			"workflow_definition_id": `workflow_definition_id=gen_random_uuid()`,
		} {
			assertImmutable("task "+id+" "+field, `UPDATE tasks SET `+assignment+` WHERE id='`+id+`'`)
		}
	}
	for _, id := range []string{baselineRunID, currentRunID} {
		for field, assignment := range map[string]string{
			"id":                        `id=gen_random_uuid()`,
			"task_id":                   `task_id=gen_random_uuid()`,
			"workflow_definition_id":    `workflow_definition_id=gen_random_uuid()`,
			"workflow_version":          `workflow_version=workflow_version||'-changed'`,
			"previous_run_id":           `previous_run_id=gen_random_uuid()`,
			"trigger_source":            `trigger_source=trigger_source||'-changed'`,
			"materialized_definition":   `materialized_definition=COALESCE(materialized_definition,'{}'::jsonb)||'{"changed":true}'::jsonb`,
			"materialization_digest":    `materialization_digest=repeat('b',64)`,
			"original_scope_version_id": `original_scope_version_id=gen_random_uuid()`,
		} {
			assertImmutable("workflow run "+id+" "+field, `UPDATE workflow_runs SET `+assignment+` WHERE id='`+id+`'`)
		}
	}
	for name, statement := range map[string]string{
		"definition semantic no-op": `UPDATE workflow_definitions SET id=id,name=name,version=version,description=description,definition=definition,default_policy_requirements=default_policy_requirements,created_at=created_at WHERE id='` + currentDefID + `'`,
		"task semantic no-op":       `UPDATE tasks SET id=id,program_id=program_id,workflow_definition_id=workflow_definition_id WHERE id='` + currentTaskID + `'`,
		"run semantic no-op":        `UPDATE workflow_runs SET id=id,task_id=task_id,workflow_definition_id=workflow_definition_id,workflow_version=workflow_version,previous_run_id=previous_run_id,trigger_source=trigger_source,materialized_definition=materialized_definition,materialization_digest=materialization_digest,original_scope_version_id=original_scope_version_id WHERE id='` + currentRunID + `'`,
		"task lifecycle":            `UPDATE tasks SET status='paused',updated_at=clock_timestamp() WHERE id='` + currentTaskID + `'`,
		"run lifecycle":             `UPDATE workflow_runs SET status='paused',completed_at=clock_timestamp(),summary='{"lifecycle":true}' WHERE id='` + currentRunID + `'`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source) VALUES($1,$2,$3,'1.2.0','running','integration')`, "00000000-0000-4000-8000-000000015009", baselineTaskID, baselineOldID); err == nil || !strings.Contains(err.Error(), "complete immutable materialization") {
		t.Fatalf("post-migration NULL run error=%v", err)
	}

	if _, err := pool.Exec(ctx, `UPDATE workflow_runs SET materialization_digest=$2 WHERE id=$1`, currentRunID, strings.Repeat("b", 64)); err == nil || !strings.Contains(strings.ToLower(err.Error()), "immutable") {
		t.Fatalf("snapshot mutation error=%v", err)
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
}
