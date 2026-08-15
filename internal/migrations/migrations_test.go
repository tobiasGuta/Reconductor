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
	if len(versions) != 11 {
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
