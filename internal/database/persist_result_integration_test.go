package database

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/execution"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

type postgresProvenanceCapability struct {
	calls          int
	store          *Store
	startID        *domain.ID
	cancel         context.CancelFunc
	startVisible   bool
	observationErr error
}

func (*postgresProvenanceCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "test.provenance", Version: "1", Risk: policy.Low}
}
func (*postgresProvenanceCapability) Validate(context.Context, capability.Request) error { return nil }
func (c *postgresProvenanceCapability) Execute(ctx context.Context, req capability.Request) (capability.Result, error) {
	c.calls++
	if c.store != nil && c.startID != nil {
		var count int
		c.observationErr = c.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE id=$1 AND event_type='provider_invocation_started'`, *c.startID).Scan(&count)
		c.startVisible = c.observationErr == nil && count == 1
	}
	if c.cancel != nil {
		c.cancel()
	}
	return capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Summary: "provider returned"}}, nil
}

type observingPostgresRecorder struct {
	store   *Store
	startID *domain.ID
}

func (r observingPostgresRecorder) RecordProviderInvocationStarted(ctx context.Context, record capability.ProviderInvocationStartRecord) (domain.ID, error) {
	id, err := r.store.RecordProviderInvocationStarted(ctx, record)
	if err == nil {
		*r.startID = id
	}
	return id, err
}
func (r observingPostgresRecorder) RecordProviderInvocationTerminal(ctx context.Context, record capability.ProviderInvocationTerminalRecord) error {
	return r.store.RecordProviderInvocationTerminal(ctx, record)
}

type invalidPostgresStartRecorder struct{ store *Store }

func (r invalidPostgresStartRecorder) RecordProviderInvocationStarted(ctx context.Context, record capability.ProviderInvocationStartRecord) (domain.ID, error) {
	record.ExecutionAuthorizationEventID = domain.NewID()
	return r.store.RecordProviderInvocationStarted(ctx, record)
}
func (r invalidPostgresStartRecorder) RecordProviderInvocationTerminal(ctx context.Context, record capability.ProviderInvocationTerminalRecord) error {
	return r.store.RecordProviderInvocationTerminal(ctx, record)
}

type failingPostgresTerminalRecorder struct {
	store *Store
	err   error
}

func (r failingPostgresTerminalRecorder) RecordProviderInvocationStarted(ctx context.Context, record capability.ProviderInvocationStartRecord) (domain.ID, error) {
	return r.store.RecordProviderInvocationStarted(ctx, record)
}
func (r failingPostgresTerminalRecorder) RecordProviderInvocationTerminal(context.Context, capability.ProviderInvocationTerminalRecord) error {
	return r.err
}

type integrationAllowScope struct{}

func (integrationAllowScope) Allows(string) bool { return true }

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
	altProgramID, altTaskID, altRunID, altStepID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	altProgram := program
	altProgram.ID = altProgramID
	altProgram.Name = "persistence-alt-" + string(altProgramID)
	if err := store.CreateProgram(ctx, altProgram, snapshot); err != nil {
		t.Fatal(err)
	}
	altTask := task
	altTask.ID = altTaskID
	altTask.Objective = "alternate valid terminal lineage"
	if err := store.CreateTask(ctx, altTask); err != nil {
		t.Fatal(err)
	}
	altState := &workflow.State{
		Run:   domain.WorkflowRun{ID: altRunID, TaskID: altTaskID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration-test", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{"alternate": {Run: domain.StepRun{ID: altStepID, WorkflowRunID: altRunID, StepDefinitionID: "alternate", Capability: "alternate.capability", Status: domain.StepRunning, Input: json.RawMessage(`{}`), IdempotencyKey: string(domain.NewID()), ApprovalState: "not_required"}}},
	}
	if err := store.SaveWorkflowState(ctx, altState); err != nil {
		t.Fatal(err)
	}
	actionRequest := domain.ActionRequest{ID: domain.NewID(), TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, RequestedBy: "integration-test", Capability: "resolve.dns", Reason: "must not persist in provider provenance", Input: json.RawMessage(`{"target":"must-not-persist.example.test","token":"secret"}`), IdempotencyKey: state.Steps["dns"].Run.IdempotencyKey, StepAttempt: 1}
	dispatchAuthorizationID, err := store.RecordPolicyDecision(ctx, capability.PolicyDecisionRecord{ProgramID: programID, Action: actionRequest, Provider: "dnsx", PolicyID: "restricted", Phase: "dispatch", Evaluation: policy.Evaluation{Decision: policy.Allow, Reason: "synthetic dispatch allow"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordProviderInvocationStarted(ctx, capability.ProviderInvocationStartRecord{ProgramID: programID, TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, ActionRequestID: actionRequest.ID, StepAttempt: actionRequest.StepAttempt, ExecutionAuthorizationEventID: dispatchAuthorizationID, Capability: actionRequest.Capability, Provider: "dnsx", Actor: actionRequest.RequestedBy}); err == nil {
		t.Fatal("dispatch-phase ALLOW authorized a provider start")
	}
	var dispatchStarts int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event_type='provider_invocation_started' AND execution_authorization_event_id=$1`, dispatchAuthorizationID).Scan(&dispatchStarts); err != nil || dispatchStarts != 0 {
		t.Fatalf("dispatch authorization provider starts=%d err=%v", dispatchStarts, err)
	}
	authorizationID, err := store.RecordPolicyDecision(ctx, capability.PolicyDecisionRecord{ProgramID: programID, Action: actionRequest, Provider: "dnsx", PolicyID: "restricted", Phase: "execution", Evaluation: policy.Evaluation{Decision: policy.Allow, Reason: "synthetic allow"}})
	if err != nil {
		t.Fatal(err)
	}
	validStart := capability.ProviderInvocationStartRecord{ProgramID: programID, TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, ActionRequestID: actionRequest.ID, StepAttempt: actionRequest.StepAttempt, ExecutionAuthorizationEventID: authorizationID, Capability: actionRequest.Capability, Provider: "dnsx", Actor: actionRequest.RequestedBy}
	altQueueID := domain.NewID()
	for _, test := range []struct {
		name   string
		mutate func(*capability.ProviderInvocationStartRecord)
	}{
		{name: "program", mutate: func(record *capability.ProviderInvocationStartRecord) { record.ProgramID = altProgramID }},
		{name: "task", mutate: func(record *capability.ProviderInvocationStartRecord) { record.TaskID = altTaskID }},
		{name: "workflow", mutate: func(record *capability.ProviderInvocationStartRecord) { record.WorkflowRunID = altRunID }},
		{name: "step", mutate: func(record *capability.ProviderInvocationStartRecord) { record.StepRunID = altStepID }},
		{name: "action", mutate: func(record *capability.ProviderInvocationStartRecord) { record.ActionRequestID = domain.NewID() }},
		{name: "step attempt", mutate: func(record *capability.ProviderInvocationStartRecord) { record.StepAttempt++ }},
		{name: "queue job", mutate: func(record *capability.ProviderInvocationStartRecord) { record.QueueJobID = &altQueueID }},
		{name: "authorization", mutate: func(record *capability.ProviderInvocationStartRecord) {
			record.ExecutionAuthorizationEventID = dispatchAuthorizationID
		}},
		{name: "capability", mutate: func(record *capability.ProviderInvocationStartRecord) { record.Capability = "alternate.capability" }},
		{name: "provider", mutate: func(record *capability.ProviderInvocationStartRecord) { record.Provider = "alternate-provider" }},
	} {
		t.Run("provider start rejects mismatched "+test.name, func(t *testing.T) {
			record := validStart
			test.mutate(&record)
			if _, err := store.RecordProviderInvocationStarted(ctx, record); err == nil {
				t.Fatalf("provider start accepted mismatched %s", test.name)
			}
		})
	}
	providerAttemptID, err := store.RecordProviderInvocationStarted(ctx, validStart)
	if err != nil {
		t.Fatal(err)
	}
	var committedStart int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE id=$1 AND event_type='provider_invocation_started'`, providerAttemptID).Scan(&committedStart); err != nil || committedStart != 1 {
		t.Fatalf("provider start was not committed before callback boundary: count=%d err=%v", committedStart, err)
	}
	validTerminal := capability.ProviderInvocationTerminalRecord{ProviderAttemptID: providerAttemptID, ProgramID: programID, TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, Capability: actionRequest.Capability, Provider: "dnsx", Actor: actionRequest.RequestedBy, Outcome: capability.ProviderInvocationFailed}
	for _, test := range []struct {
		name   string
		mutate func(*capability.ProviderInvocationTerminalRecord)
	}{
		{name: "program", mutate: func(record *capability.ProviderInvocationTerminalRecord) { record.ProgramID = altProgramID }},
		{name: "task", mutate: func(record *capability.ProviderInvocationTerminalRecord) { record.TaskID = altTaskID }},
		{name: "workflow", mutate: func(record *capability.ProviderInvocationTerminalRecord) { record.WorkflowRunID = altRunID }},
		{name: "step", mutate: func(record *capability.ProviderInvocationTerminalRecord) { record.StepRunID = altStepID }},
		{name: "capability", mutate: func(record *capability.ProviderInvocationTerminalRecord) { record.Capability = "alternate.capability" }},
		{name: "provider", mutate: func(record *capability.ProviderInvocationTerminalRecord) { record.Provider = "alternate-provider" }},
	} {
		t.Run("terminal rejects mismatched "+test.name, func(t *testing.T) {
			record := validTerminal
			test.mutate(&record)
			if err := store.RecordProviderInvocationTerminal(ctx, record); err == nil {
				t.Fatalf("terminal accepted mismatched %s", test.name)
			}
			var terminals int
			if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE provider_attempt_id=$1 AND event_type IN ('provider_invocation_succeeded','provider_invocation_failed','provider_invocation_cancelled')`, providerAttemptID).Scan(&terminals); err != nil || terminals != 0 {
				t.Fatalf("mismatched terminal rows=%d err=%v", terminals, err)
			}
		})
	}
	if err := store.RecordProviderInvocationTerminal(ctx, validTerminal); err != nil {
		t.Fatal(err)
	}
	var terminalActor, terminalCapability, terminalProvider string
	var terminalTask, terminalProgram, terminalRun, terminalStep, terminalAttempt domain.ID
	var terminalScheduled *domain.ID
	var terminalSchedulerAttempt *int
	if err := store.Pool.QueryRow(ctx, `SELECT actor,task_id,program_id,workflow_run_id,step_run_id,scheduled_execution_id,scheduler_attempt,provider_attempt_id,capability,provider FROM audit_events WHERE provider_attempt_id=$1 AND event_type='provider_invocation_failed'`, providerAttemptID).Scan(&terminalActor, &terminalTask, &terminalProgram, &terminalRun, &terminalStep, &terminalScheduled, &terminalSchedulerAttempt, &terminalAttempt, &terminalCapability, &terminalProvider); err != nil {
		t.Fatal(err)
	}
	if terminalActor != actionRequest.RequestedBy || terminalTask != taskID || terminalProgram != programID || terminalRun != runID || terminalStep != stepID || terminalScheduled != nil || terminalSchedulerAttempt != nil || terminalAttempt != providerAttemptID || terminalCapability != actionRequest.Capability || terminalProvider != "dnsx" {
		t.Fatalf("terminal lineage actor=%q task=%s program=%s run=%s step=%s scheduled=%v scheduler_attempt=%v attempt=%s capability=%q provider=%q", terminalActor, terminalTask, terminalProgram, terminalRun, terminalStep, terminalScheduled, terminalSchedulerAttempt, terminalAttempt, terminalCapability, terminalProvider)
	}

	exitCode := 1
	completed := now.Add(time.Second)
	tool := &domain.ToolRun{ID: toolID, StepRunID: stepID, Capability: "resolve.dns", Provider: "dnsx", ToolVersion: "test", SanitizedArguments: json.RawMessage(`{"stdin_bytes":19}`), ExecutionEnvironment: json.RawMessage(`{"kind":"local-process","shell":false}`), StartedAt: now, CompletedAt: &completed, ExitCode: &exitCode, StderrArtifactID: &artifactID, ProviderAttemptID: &providerAttemptID}
	expires := now.Add(-time.Minute)
	artifact := domain.Artifact{ID: artifactID, TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, ToolRunID: toolID, Type: "raw-provider-output", ContentType: "text/plain", Size: 24, SHA256: strings.Repeat("a", 64), StorageLocation: "synthetic://stderr.txt", CreatedAt: completed, ExpiresAt: &expires, RedactionState: "redacted"}
	step := domain.StepRun{ID: stepID, WorkflowRunID: runID, Capability: "resolve.dns", Status: domain.StepFailed, Output: json.RawMessage(`{"lines":[],"authorized":[],"filtered":[]}`), ErrorClassification: "provider_error", ErrorDetails: "exit status 1: fake DNS failure", CompletedAt: &completed, IdempotencyKey: state.Steps["dns"].Run.IdempotencyKey}
	action := domain.ActionResult{RequestID: actionRequest.ID, Status: "failed", Summary: "dnsx execution failed", Output: step.Output, Error: &domain.StructuredError{Classification: "provider_error", Message: step.ErrorDetails}}
	admission := &capability.ResultAdmissionProvenance{ProviderAttemptID: providerAttemptID, ActionRequestID: actionRequest.ID, StepAttempt: actionRequest.StepAttempt, ExecutionAuthorizationEventID: authorizationID, Provider: "dnsx"}
	wrongTool := *tool
	wrongTool.ProviderAttemptID = &authorizationID
	if err := store.PersistResult(ctx, programID, step, &wrongTool, []domain.Artifact{artifact}, action, admission); !errors.Is(err, ErrWorkflowResultConflict) {
		t.Fatalf("non-start provider attempt link error=%v", err)
	}
	if err := store.PersistResult(ctx, programID, step, tool, []domain.Artifact{artifact}, action, nil); !errors.Is(err, ErrWorkflowResultConflict) {
		t.Fatalf("provider-attempt ToolRun without trusted admission provenance error=%v", err)
	}
	if err := store.PersistResult(ctx, programID, step, tool, []domain.Artifact{artifact}, action, admission); err != nil {
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
	var stderrID, storedProviderAttempt domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT exit_code,stderr_artifact_id,provider_attempt_id FROM tool_runs WHERE id=$1`, toolID).Scan(&storedExit, &stderrID, &storedProviderAttempt); err != nil {
		t.Fatal(err)
	}
	if storedExit != exitCode || stderrID != artifactID || storedProviderAttempt != providerAttemptID {
		t.Fatalf("failed tool mismatch: exit=%d stderr=%s provider_attempt=%s", storedExit, stderrID, storedProviderAttempt)
	}
	var startAuthorization, startAction domain.ID
	var startAttempt int
	var startProvider *domain.ID
	var startDetails string
	if err := store.Pool.QueryRow(ctx, `SELECT execution_authorization_event_id,action_request_id,step_attempt,provider_attempt_id,details::text FROM audit_events WHERE id=$1`, providerAttemptID).Scan(&startAuthorization, &startAction, &startAttempt, &startProvider, &startDetails); err != nil {
		t.Fatal(err)
	}
	if startAuthorization != authorizationID || startAction != actionRequest.ID || startAttempt != 1 || startProvider != nil || startDetails != "{}" {
		t.Fatalf("start provenance authorization=%s action=%s attempt=%d provider=%v details=%s", startAuthorization, startAction, startAttempt, startProvider, startDetails)
	}
	var executionProvider, executionAction domain.ID
	var executionAttempt int
	var executionQueue *domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT provider_attempt_id,action_request_id,step_attempt,queue_job_id FROM audit_events WHERE event_type='tool_execution' AND tool_run_id=$1`, toolID).Scan(&executionProvider, &executionAction, &executionAttempt, &executionQueue); err != nil {
		t.Fatal(err)
	}
	if executionProvider != providerAttemptID || executionAction != actionRequest.ID || executionAttempt != 1 || executionQueue != nil {
		t.Fatalf("tool_execution provenance provider=%s action=%s attempt=%d queue=%v", executionProvider, executionAction, executionAttempt, executionQueue)
	}
	var storedTask, storedRun, storedStep, storedTool domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT task_id,workflow_run_id,step_run_id,tool_run_id FROM artifacts WHERE id=$1`, artifactID).Scan(&storedTask, &storedRun, &storedStep, &storedTool); err != nil {
		t.Fatal(err)
	}
	if storedTask != taskID || storedRun != runID || storedStep != stepID || storedTool != toolID {
		t.Fatalf("artifact lineage mismatch: task=%s run=%s step=%s tool=%s", storedTask, storedRun, storedStep, storedTool)
	}
	if _, err := store.RecordPolicyDecision(ctx, capability.PolicyDecisionRecord{ProgramID: programID, Action: domain.ActionRequest{TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, Capability: "resolve.dns", RequestedBy: "integration-test"}, Provider: "dnsx", PolicyID: "restricted", Phase: "execution", Evaluation: policy.Evaluation{Decision: policy.Deny, Reason: "synthetic denial"}}); err != nil {
		t.Fatal(err)
	}
	var policyEvents int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type='policy_denied'`, stepID).Scan(&policyEvents); err != nil || policyEvents != 1 {
		t.Fatalf("policy audit count=%d err=%v", policyEvents, err)
	}

	provenanceStepID := domain.NewID()
	provenanceKey := string(domain.NewID())
	if _, err := store.Pool.Exec(ctx, `INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,input,idempotency_key) VALUES($1,$2,'provider-provenance','test.provenance','running','{}',$3)`, provenanceStepID, runID, provenanceKey); err != nil {
		t.Fatal(err)
	}
	registry := capability.NewRegistry()
	provider := &postgresProvenanceCapability{}
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	rejectedAction := domain.ActionRequest{ID: domain.NewID(), TaskID: taskID, WorkflowRunID: runID, StepRunID: provenanceStepID, RequestedBy: "integration-test", Capability: "test.provenance", Input: json.RawMessage(`{}`), IdempotencyKey: provenanceKey, StepAttempt: 1}
	if _, err := registry.Execute(ctx, capability.Request{Action: rejectedAction, ProgramID: programID, Policy: policy.Policy{AllowedCapabilities: []string{"test.provenance"}}, Scope: integrationAllowScope{}, DecisionRecorder: store, InvocationRecorder: invalidPostgresStartRecorder{store: store}}); err == nil {
		t.Fatal("invalid provider start audit unexpectedly succeeded")
	}
	if provider.calls != 0 {
		t.Fatalf("provider callback ran after rejected start: calls=%d", provider.calls)
	}

	observedStartID := domain.ID("")
	detachedCtx, cancelDetached := context.WithCancel(ctx)
	observingProvider := &postgresProvenanceCapability{store: store, startID: &observedStartID, cancel: cancelDetached}
	observingRegistry := capability.NewRegistry()
	if err := observingRegistry.Register(observingProvider); err != nil {
		t.Fatal(err)
	}
	observingAction := rejectedAction
	observingAction.ID = domain.NewID()
	observedResult, err := observingRegistry.Execute(detachedCtx, capability.Request{Action: observingAction, ProgramID: programID, Policy: policy.Policy{AllowedCapabilities: []string{"test.provenance"}}, Scope: integrationAllowScope{}, DecisionRecorder: store, InvocationRecorder: observingPostgresRecorder{store: store, startID: &observedStartID}})
	if err != nil {
		t.Fatalf("cancelled caller context prevented detached terminal persistence: %v", err)
	}
	if !observingProvider.startVisible || observingProvider.observationErr != nil || observedResult.ProviderAttemptID == nil || *observedResult.ProviderAttemptID != observedStartID {
		t.Fatalf("provider did not observe committed start: visible=%v observation_err=%v result=%#v start=%s", observingProvider.startVisible, observingProvider.observationErr, observedResult, observedStartID)
	}
	var detachedTerminals int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE provider_attempt_id=$1 AND event_type='provider_invocation_succeeded'`, observedStartID).Scan(&detachedTerminals); err != nil || detachedTerminals != 1 {
		t.Fatalf("detached terminal rows=%d err=%v", detachedTerminals, err)
	}

	terminalCause := errors.New("synthetic terminal audit outage")
	successAction := rejectedAction
	successAction.ID = domain.NewID()
	result, err := (execution.Service{Registry: registry, Store: store, ProgramID: programID, ProviderAuditor: failingPostgresTerminalRecorder{store: store, err: terminalCause}}).Execute(ctx, capability.Request{Action: successAction, Policy: policy.Policy{AllowedCapabilities: []string{"test.provenance"}}, Scope: integrationAllowScope{}})
	if err != nil {
		t.Fatalf("terminal audit degradation changed provider success: %v", err)
	}
	if !errors.Is(result.TerminalAuditError, terminalCause) || result.ProviderAttemptID == nil || provider.calls != 1 {
		t.Fatalf("result=%#v provider_calls=%d", result, provider.calls)
	}
	var persistedStatus domain.StepStatus
	var persistedAttempt domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT sr.status,tr.provider_attempt_id FROM step_runs sr JOIN tool_runs tr ON tr.step_run_id=sr.id WHERE sr.id=$1`, provenanceStepID).Scan(&persistedStatus, &persistedAttempt); err != nil {
		t.Fatal(err)
	}
	if persistedStatus != domain.StepSucceeded || persistedAttempt != *result.ProviderAttemptID {
		t.Fatalf("persisted status=%s attempt=%s result_attempt=%s", persistedStatus, persistedAttempt, *result.ProviderAttemptID)
	}
	var missingTerminal int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE provider_attempt_id=$1 AND event_type IN ('provider_invocation_succeeded','provider_invocation_failed','provider_invocation_cancelled')`, *result.ProviderAttemptID).Scan(&missingTerminal); err != nil {
		t.Fatal(err)
	}
	if missingTerminal != 0 {
		t.Fatalf("terminal event was fabricated after audit failure: count=%d", missingTerminal)
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
