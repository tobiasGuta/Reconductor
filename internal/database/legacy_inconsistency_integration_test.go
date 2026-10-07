package database

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestLegacyInconsistenciesRemainDetectableAfterMaterializationMigration(t *testing.T) {
	t.Run("probe HTTP source WorkflowRun Task hierarchy", func(t *testing.T) {
		assertLegacyProbeHTTPSourceHierarchyRejected(t, "workflow_task")
	})
	t.Run("probe HTTP source Task Program hierarchy", func(t *testing.T) {
		assertLegacyProbeHTTPSourceHierarchyRejected(t, "task_program")
	})
	t.Run("scheduler recovery preserves contradictory lineage for manual review", func(t *testing.T) {
		store, ctx := pre0015IntegrationStore(t, "legacy_scheduler_inconsistent")
		programA, programB, definitionA, definitionB := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
		taskA, taskB, runID, stepID, scheduleID, executionID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
		now := time.Now().UTC().Truncate(time.Microsecond)
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,$2,'integration','scope','policy'),($3,$4,'integration','scope','policy')`, []any{programA, "legacy-a-" + string(programA), programB, "legacy-b-" + string(programB)}},
			{`INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements) VALUES($1,$2,'1','legacy','{}','{}'),($3,$4,'1','legacy','{}','{}')`, []any{definitionA, "legacy-a-" + string(definitionA), definitionB, "legacy-b-" + string(definitionB)}},
			{`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES($1,$2,'scheduled task',$3,'running','integration'),($4,$5,'other task',$6,'running','integration')`, []any{taskA, programA, definitionA, taskB, programB, definitionB}},
			{`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,trigger_source,summary) VALUES($1,$2,$3,'1','running',$4,'run_now','{}')`, []any{runID, taskB, definitionB, now}},
			{`INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,attempt_count,input,idempotency_key,approval_state,started_at) VALUES($1,$2,'running','test.running','running',1,'{}','legacy-running','not_required',$3)`, []any{stepID, runID, now}},
			{`INSERT INTO schedules(id,program_id,name,workflow_name,objective,cron_expression,timezone,created_by,next_run_at) VALUES($1,$2,'legacy recovery','continuous-web-recon','legacy','0 9 * * *','UTC','integration',$3)`, []any{scheduleID, programA, now.Add(time.Hour)}},
			{`INSERT INTO scheduled_executions(id,schedule_id,planned_at,trigger_source,status,task_id,workflow_run_id,attempt_count,lease_owner,lease_expires_at,recovery_protocol_version,started_at,created_at,updated_at) VALUES($1,$2,$3,'run_now','running',$4,$5,1,'legacy-owner',$6,1,$3,$3,$3)`, []any{executionID, scheduleID, now, taskA, runID, now.Add(-time.Minute)}},
		} {
			if _, err := store.Pool.Exec(ctx, statement.sql, statement.args...); err != nil {
				t.Fatal(err)
			}
		}
		assertProviderCeilingMigrationBlockedByActiveState(t, store, ctx)
		if err := store.reconcileStaleScheduledExecutions(ctx, staleReconciliationBatchLimit); err != nil {
			t.Fatal(err)
		}
		var status domain.ScheduledExecutionStatus
		var classification, summary string
		if err := store.Pool.QueryRow(ctx, `SELECT status,error_classification,error_summary FROM scheduled_executions WHERE id=$1`, executionID).Scan(&status, &classification, &summary); err != nil {
			t.Fatal(err)
		}
		var taskAStatus, taskBStatus domain.TaskStatus
		var runStatus domain.RunStatus
		var stepStatus domain.StepStatus
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM tasks WHERE id=$1`, taskA).Scan(&taskAStatus); err != nil {
			t.Fatal(err)
		}
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM tasks WHERE id=$1`, taskB).Scan(&taskBStatus); err != nil {
			t.Fatal(err)
		}
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM workflow_runs WHERE id=$1`, runID).Scan(&runStatus); err != nil {
			t.Fatal(err)
		}
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM step_runs WHERE id=$1`, stepID).Scan(&stepStatus); err != nil {
			t.Fatal(err)
		}
		var manualReview string
		if err := store.Pool.QueryRow(ctx, `SELECT details->>'manual_review_required' FROM audit_events WHERE event_type='scheduled_execution_lineage_inconsistent' AND scheduled_execution_id=$1 ORDER BY occurred_at DESC,id DESC LIMIT 1`, executionID).Scan(&manualReview); err != nil {
			t.Fatal(err)
		}
		if status != domain.ScheduledExecutionInterrupted || classification != "lineage_inconsistent" || !strings.Contains(summary, "manual review") || taskAStatus != domain.TaskRunning || taskBStatus != domain.TaskRunning || runStatus != domain.RunRunning || stepStatus != domain.StepRunning || manualReview != "true" {
			t.Fatalf("execution=%s/%s/%q tasks=%s/%s run=%s step=%s manual=%s", status, classification, summary, taskAStatus, taskBStatus, runStatus, stepStatus, manualReview)
		}
	})

	t.Run("execution projection reports legacy workflow version contradiction", func(t *testing.T) {
		store, ctx := pre0015IntegrationStore(t, "legacy_projection_inconsistent")
		programID, definitionID, taskID, runID, scheduleID, executionID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
		now := time.Now().UTC().Truncate(time.Microsecond)
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,$2,'integration','scope','policy')`, []any{programID, "legacy-projection-" + string(programID)}},
			{`INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements) VALUES($1,'legacy-projection','1','legacy','{}','{}')`, []any{definitionID}},
			{`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES($1,$2,'legacy projection',$3,'running','integration')`, []any{taskID, programID, definitionID}},
			{`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,trigger_source,summary) VALUES($1,$2,$3,'contradictory-version','running',$4,'run_now','{}')`, []any{runID, taskID, definitionID, now}},
			{`INSERT INTO schedules(id,program_id,name,workflow_name,objective,cron_expression,timezone,created_by,next_run_at) VALUES($1,$2,'legacy projection','legacy-projection','legacy','0 9 * * *','UTC','integration',$3)`, []any{scheduleID, programID, now.Add(time.Hour)}},
			{`INSERT INTO scheduled_executions(id,schedule_id,planned_at,trigger_source,status,task_id,workflow_run_id,attempt_count,lease_owner,lease_expires_at,recovery_protocol_version,started_at,created_at,updated_at) VALUES($1,$2,$3,'run_now','running',$4,$5,1,'legacy-owner',$6,1,$3,$3,$3)`, []any{executionID, scheduleID, now, taskID, runID, now.Add(time.Hour)}},
		} {
			if _, err := store.Pool.Exec(ctx, statement.sql, statement.args...); err != nil {
				t.Fatal(err)
			}
		}
		assertProviderCeilingMigrationBlockedByActiveState(t, store, ctx)
		projection, err := store.GetExecutionProjection(ctx, executionID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.Workflow == nil || projection.Workflow.WorkflowVersion != "contradictory-version" || countLineageIssue(projection.Lineage.Issues, ExecutionLineageWorkflowDefinitionVersionMismatch) != 1 {
			t.Fatalf("projection workflow=%#v issues=%v", projection.Workflow, projection.Lineage.Issues)
		}
	})
}

func assertProviderCeilingMigrationBlockedByActiveState(t *testing.T, store *Store, ctx context.Context) {
	t.Helper()
	err := store.Migrate(ctx)
	if err == nil || !strings.Contains(err.Error(), "execution or publication state is active") {
		t.Fatalf("migration 0021 active-state error=%v", err)
	}
	var version int64
	var name string
	if err := store.Pool.QueryRow(ctx, `SELECT version,name FROM schema_migrations ORDER BY version DESC LIMIT 1`).Scan(&version, &name); err != nil {
		t.Fatal(err)
	}
	if version != 20 || name != "0020_prepared_evidence_ownership.sql" {
		t.Fatalf("failed migration frontier=%d (%s)", version, name)
	}
}

func assertLegacyProbeHTTPSourceHierarchyRejected(t *testing.T, mismatch string) {
	t.Helper()
	store, ctx := pre0015IntegrationStore(t, "legacy_source_"+mismatch)
	programA, programB, definitionA, definitionB := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	eventTaskID, runTaskID, runID := domain.NewID(), domain.NewID(), domain.NewID()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,$2,'integration','scope','policy'),($3,$4,'integration','scope','policy')`, []any{programA, "source-a-" + string(programA), programB, "source-b-" + string(programB)}},
		{`INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements) VALUES($1,$2,'1','legacy','{}','{}'),($3,$4,'1','legacy','{}','{}')`, []any{definitionA, "source-a-" + string(definitionA), definitionB, "source-b-" + string(definitionB)}},
	} {
		if _, err := store.Pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if mismatch == "workflow_task" {
		if _, err := store.Pool.Exec(ctx, `INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES($1,$2,'event task',$3,'running','integration'),($4,$5,'run task',$6,'running','integration')`, eventTaskID, programA, definitionA, runTaskID, programB, definitionB); err != nil {
			t.Fatal(err)
		}
	} else {
		runTaskID = eventTaskID
		if _, err := store.Pool.Exec(ctx, `INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES($1,$2,'reparented task',$3,'running','integration')`, eventTaskID, programB, definitionB); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source,summary) VALUES($1,$2,$3,'1','running','integration','{}')`, runID, runTaskID, definitionB); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	stepID, authorizationID, providerAttemptID, toolID, acceptedID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	actionID, assetID, observationID, resourceID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	if _, err := store.Pool.Exec(ctx, `INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,attempt_count,input,idempotency_key,approval_state) VALUES($1,$2,'probe','probe.http','running',1,'{}','legacy-source','not_required')`, stepID, runID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,action_request_id,step_attempt,capability,provider,safe_message,details) VALUES($1,'policy_allowed','policy','integration',$2,$3,$4,$5,$6,1,'probe.http','fixture-provider','legacy authorization','{"phase":"execution"}')`, authorizationID, eventTaskID, programA, runID, stepID, actionID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,action_request_id,step_attempt,execution_authorization_event_id,capability,provider,safe_message,details) VALUES($1,'provider_invocation_started','provider','integration',$2,$3,$4,$5,$6,1,$7,'probe.http','fixture-provider','legacy provider start','{}')`, providerAttemptID, eventTaskID, programA, runID, stepID, actionID, authorizationID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at,provider_attempt_id) VALUES($1,$2,'probe.http','fixture-provider',clock_timestamp(),$3)`, toolID, stepID, providerAttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,tool_run_id,action_request_id,step_attempt,execution_authorization_event_id,provider_attempt_id,capability,provider,safe_message,details) VALUES($1,'provider_result_accepted','integration','integration',$2,$3,$4,$5,$6,$7,1,$8,$9,'probe.http','fixture-provider','legacy accepted','{}')`, acceptedID, eventTaskID, programA, runID, stepID, toolID, actionID, authorizationID, providerAttemptID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO assets(id,program_id,type,canonical_value) VALUES($1,$2,'http_service','https://legacy-source.example.test/')`, assetID, programA); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO asset_observations(id,asset_id,workflow_run_id,source_capability,observed_value,first_seen_at,observed_at,confidence) VALUES($1,$2,$3,'probe.http','https://legacy-source.example.test/',clock_timestamp(),clock_timestamp(),1)`, observationID, assetID, runID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO asset_observation_emissions(program_id,asset_observation_id,provider_result_accepted_event_id) VALUES($1,$2,$3)`, programA, observationID, acceptedID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO canonical_concrete_http_resources(id,program_id,identity_namespace,scheme,host,effective_port,concrete_escaped_path,canonical_query) VALUES($1,$2,'http-uri-resource-v1','https','legacy-source.example.test',443,'/','')`, resourceID, programA); err != nil {
		t.Fatal(err)
	}
	_, err := store.Pool.Exec(ctx, `INSERT INTO probe_http_source_records(source_locator,program_id,concrete_http_resource_id,asset_observation_id,provider_result_accepted_event_id,provider_attempt_id,authorized_record_index,record_digest,request_method_state,request_method_value,request_content_type_state,identity_namespace,derivation_version) VALUES($1,$2,$3,$4,$5,$6,0,$7,'defaulted','GET','unknown','http-uri-resource-v1','http-resource-derivation-v1')`, strings.ReplaceAll(string(domain.NewID()), "-", "")+strings.Repeat("0", 32), programA, resourceID, observationID, acceptedID, providerAttemptID, strings.Repeat("a", 64))
	if err == nil || !strings.Contains(err.Error(), "lineage is inconsistent") {
		t.Fatalf("legacy %s source lineage error=%v", mismatch, err)
	}
}
