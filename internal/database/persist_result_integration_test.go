package database

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

func TestPostgresPersistsFailedExecutionLineage(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	schema := "persist_result_" + strings.ReplaceAll(string(domain.NewID()), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop integration schema: %v", err)
		}
	}()

	u, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	store, err := Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	programID, definitionID, taskID := domain.NewID(), domain.NewID(), domain.NewID()
	program := domain.Program{
		ID: programID, Name: "persistence-" + string(programID), Platform: "integration", Description: "synthetic local integration data",
		ScopeReference: "synthetic://local", PolicyReference: "integration", ScopeDigest: "scope", IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{},
		TargetPlanDigest: "plan", ScopePlanWarnings: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now,
	}
	snapshot := domain.ScopeSnapshot{ScopeReference: program.ScopeReference, ScopeDigest: program.ScopeDigest, IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: program.TargetPlanDigest, PlanningWarnings: json.RawMessage(`[]`), TargetPlan: json.RawMessage(`{}`), CreatedAt: now}
	if err := store.CreateProgram(ctx, program, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateWorkflowDefinition(ctx, definitionID, "persistence-"+string(definitionID), "1", "synthetic", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	task := domain.Task{ID: taskID, ProgramID: programID, Objective: "verify failure persistence", WorkflowDefinitionID: definitionID, Status: domain.TaskRunning, RequestedBy: "integration-test", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateTask(ctx, task); err != nil {
		t.Fatal(err)
	}

	runID, stepID, toolID, artifactID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	state := &workflow.State{
		Run:   domain.WorkflowRun{ID: runID, TaskID: taskID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration-test", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{"dns": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "dns", Capability: "resolve.dns", Status: domain.StepRunning, Input: json.RawMessage(`{"targets":["https://local.example.test/"]}`), IdempotencyKey: string(domain.NewID()), ApprovalState: "not_required"}}},
	}
	if err := store.SaveWorkflowState(ctx, state); err != nil {
		t.Fatal(err)
	}

	exitCode := 1
	completed := now.Add(time.Second)
	tool := &domain.ToolRun{ID: toolID, StepRunID: stepID, Capability: "resolve.dns", Provider: "dnsx", ToolVersion: "test", SanitizedArguments: json.RawMessage(`{"stdin_bytes":19}`), ExecutionEnvironment: json.RawMessage(`{"kind":"local-process","shell":false}`), StartedAt: now, CompletedAt: &completed, ExitCode: &exitCode, StderrArtifactID: &artifactID}
	expires := now.Add(-time.Minute)
	artifact := domain.Artifact{ID: artifactID, TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, ToolRunID: toolID, Type: "raw-provider-output", ContentType: "text/plain", Size: 24, SHA256: strings.Repeat("a", 64), StorageLocation: "synthetic://stderr.txt", CreatedAt: completed, ExpiresAt: &expires, RedactionState: "redacted"}
	step := domain.StepRun{ID: stepID, WorkflowRunID: runID, Capability: "resolve.dns", Status: domain.StepFailed, Output: json.RawMessage(`{"lines":[],"authorized":[],"filtered":[]}`), ErrorClassification: "provider_error", ErrorDetails: "exit status 1: fake DNS failure", CompletedAt: &completed, IdempotencyKey: state.Steps["dns"].Run.IdempotencyKey}
	action := domain.ActionResult{RequestID: domain.NewID(), Status: "failed", Summary: "dnsx execution failed", Output: step.Output, Error: &domain.StructuredError{Classification: "provider_error", Message: step.ErrorDetails}}
	if err := store.PersistResult(ctx, programID, step, tool, []domain.Artifact{artifact}, action); err != nil {
		t.Fatal(err)
	}

	var status domain.StepStatus
	var classification, details string
	if err := store.Pool.QueryRow(ctx, `SELECT status,error_classification,error_details FROM step_runs WHERE id=$1`, stepID).Scan(&status, &classification, &details); err != nil {
		t.Fatal(err)
	}
	if status != domain.StepFailed || classification != step.ErrorClassification || details != step.ErrorDetails {
		t.Fatalf("failed step mismatch: status=%s classification=%q details=%q", status, classification, details)
	}
	var storedExit int
	var stderrID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT exit_code,stderr_artifact_id FROM tool_runs WHERE id=$1`, toolID).Scan(&storedExit, &stderrID); err != nil {
		t.Fatal(err)
	}
	if storedExit != exitCode || stderrID != artifactID {
		t.Fatalf("failed tool mismatch: exit=%d stderr=%s", storedExit, stderrID)
	}
	var storedTask, storedRun, storedStep, storedTool domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT task_id,workflow_run_id,step_run_id,tool_run_id FROM artifacts WHERE id=$1`, artifactID).Scan(&storedTask, &storedRun, &storedStep, &storedTool); err != nil {
		t.Fatal(err)
	}
	if storedTask != taskID || storedRun != runID || storedStep != stepID || storedTool != toolID {
		t.Fatalf("artifact lineage mismatch: task=%s run=%s step=%s tool=%s", storedTask, storedRun, storedStep, storedTool)
	}
	if err := store.RecordPolicyDecision(ctx, capability.PolicyDecisionRecord{ProgramID: programID, Action: domain.ActionRequest{TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, Capability: "resolve.dns", RequestedBy: "integration-test"}, Provider: "dnsx", PolicyID: "restricted", Phase: "execution", Evaluation: policy.Evaluation{Decision: policy.Deny, Reason: "synthetic denial"}}); err != nil {
		t.Fatal(err)
	}
	var policyEvents int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type='policy_denied'`, stepID).Scan(&policyEvents); err != nil || policyEvents != 1 {
		t.Fatalf("policy audit count=%d err=%v", policyEvents, err)
	}
	expired, err := store.ExpiredArtifacts(ctx, 10)
	if err != nil || len(expired) != 1 || expired[0].ID != artifactID {
		t.Fatalf("expired=%#v err=%v", expired, err)
	}
	if err := store.DeleteArtifact(ctx, artifactID); err != nil {
		t.Fatal(err)
	}
	var artifactRows, expiryEvents int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM artifacts WHERE id=$1`, artifactID).Scan(&artifactRows); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type='artifact_expired'`, stepID).Scan(&expiryEvents); err != nil {
		t.Fatal(err)
	}
	if artifactRows != 0 || expiryEvents != 1 {
		t.Fatalf("artifact rows=%d expiry audits=%d", artifactRows, expiryEvents)
	}

	state.Steps["dns"].Run.Status = domain.StepRunning
	state.Steps["dns"].Run.Output = nil
	state.Steps["dns"].Run.ErrorClassification = ""
	state.Steps["dns"].Run.ErrorDetails = ""
	state.Steps["dns"].Run.CompletedAt = nil
	if err := store.SaveWorkflowState(ctx, state); err != nil {
		t.Fatalf("resume existing failed step: %v", err)
	}
	var stepCount int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM step_runs WHERE workflow_run_id=$1 AND step_definition_id='dns' AND idempotency_key=$2`, runID, state.Steps["dns"].Run.IdempotencyKey).Scan(&stepCount); err != nil {
		t.Fatal(err)
	}
	if stepCount != 1 {
		t.Fatalf("resume created %d step rows, want 1", stepCount)
	}
}
