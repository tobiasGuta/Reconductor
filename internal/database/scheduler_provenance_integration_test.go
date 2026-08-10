package database

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

func TestScheduledExecutionStructuredProvenance(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	programID, definitionID := createSchedulerIntegrationProgram(t, ctx, store, "structured-provenance")
	var scopeVersionID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT id FROM scope_versions WHERE program_id=$1 ORDER BY created_at DESC LIMIT 1`, programID).Scan(&scopeVersionID); err != nil {
		t.Fatal(err)
	}

	schedule := createIntegrationSchedule(t, ctx, store, programID, "structured-provenance")
	execution, err := store.EnqueueRunNow(ctx, schedule.ID, "integration")
	if err != nil {
		t.Fatal(err)
	}
	assertSchedulerAuditProvenance(t, store, ctx, "scheduled_execution_planned", execution.ID, nil, nil)

	claimed, _, ok, err := store.ClaimPendingScheduledExecution(ctx, "provenance-owner-1", time.Minute)
	if err != nil || !ok || claimed.ID != execution.ID {
		t.Fatalf("claim=%#v ok=%v err=%v", claimed, ok, err)
	}
	assertSchedulerAuditProvenance(t, store, ctx, "scheduled_execution_claimed", execution.ID, intPointer(claimed.AttemptCount), nil)

	task := createIntegrationTask(t, ctx, store, programID, definitionID, "structured-provenance")
	if err := store.MarkScheduledExecutionTaskCreated(ctx, execution.ID, task.ID, "provenance-owner-1", claimed.AttemptCount); err != nil {
		t.Fatal(err)
	}
	assertSchedulerAuditProvenance(t, store, ctx, "scheduled_execution_task_linked", execution.ID, intPointer(claimed.AttemptCount), nil)

	now := time.Now().UTC()
	runID := domain.NewID()
	state := &workflow.State{
		Run:   domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "run_now", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{},
	}
	persister := WorkflowPersister{Store: store, File: workflow.FileStore{Root: t.TempDir()}, Lifecycle: func(lifecycleCtx context.Context, state *workflow.State) error {
		return store.MarkScheduledExecutionRunning(lifecycleCtx, execution.ID, task.ID, state.Run.ID, &scopeVersionID, "provenance-owner-1", claimed.AttemptCount)
	}}
	if err := persister.Save(WithScheduledExecutionFence(ctx, ScheduledExecutionFence{ExecutionID: execution.ID, LeaseOwner: "provenance-owner-1", Attempt: claimed.AttemptCount}), state); err != nil {
		t.Fatal(err)
	}
	assertSchedulerAuditProvenance(t, store, ctx, "scheduled_execution_started", execution.ID, intPointer(claimed.AttemptCount), &scopeVersionID)

	if err := store.MarkScheduledExecutionPaused(ctx, execution.ID, "provenance-owner-1", claimed.AttemptCount); err != nil {
		t.Fatal(err)
	}
	assertSchedulerAuditProvenance(t, store, ctx, "scheduled_execution_paused", execution.ID, intPointer(claimed.AttemptCount), &scopeVersionID)
	if err := store.RequestScheduledExecutionResume(ctx, execution.ID, "integration"); err != nil {
		t.Fatal(err)
	}
	assertSchedulerAuditProvenance(t, store, ctx, "scheduled_execution_resume_requested", execution.ID, nil, nil)

	resumed, _, ok, err := store.ClaimPendingScheduledExecution(ctx, "provenance-owner-2", time.Minute)
	if err != nil || !ok || resumed.ID != execution.ID {
		t.Fatalf("resumed claim=%#v ok=%v err=%v", resumed, ok, err)
	}
	if resumed.AttemptCount != claimed.AttemptCount+1 {
		t.Fatalf("resumed attempt=%d want=%d", resumed.AttemptCount, claimed.AttemptCount+1)
	}
	assertSchedulerAuditProvenance(t, store, ctx, "scheduled_execution_claimed", execution.ID, intPointer(resumed.AttemptCount), nil)
	if err := store.MarkScheduledExecutionFailed(ctx, execution.ID, "provenance-owner-2", resumed.AttemptCount, "integration", "cleanup"); err != nil {
		t.Fatal(err)
	}
	assertSchedulerAuditProvenance(t, store, ctx, "scheduled_execution_failed", execution.ID, intPointer(resumed.AttemptCount), nil)
	assertSchedulerAuditProvenance(t, store, ctx, "scheduled_execution_paused", execution.ID, intPointer(claimed.AttemptCount), &scopeVersionID)

	var firstAttemptRows, secondAttemptRows int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE scheduler_attempt=$2),count(*) FILTER (WHERE scheduler_attempt=$3) FROM audit_events WHERE scheduled_execution_id=$1`, execution.ID, claimed.AttemptCount, resumed.AttemptCount).Scan(&firstAttemptRows, &secondAttemptRows); err != nil {
		t.Fatal(err)
	}
	if firstAttemptRows < 3 || secondAttemptRows < 2 {
		t.Fatalf("immutable attempts first=%d second=%d", firstAttemptRows, secondAttemptRows)
	}
}

func TestScheduledExecutionTerminalStructuredProvenance(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	programID, definitionID := createSchedulerIntegrationProgram(t, ctx, store, "structured-terminal-provenance")
	var scopeVersionID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT id FROM scope_versions WHERE program_id=$1 ORDER BY created_at DESC LIMIT 1`, programID).Scan(&scopeVersionID); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		event      string
		running    bool
		transition func(domain.ScheduledExecution, string) error
	}{
		{
			name:    "running_completed",
			event:   "scheduled_execution_completed",
			running: true,
			transition: func(execution domain.ScheduledExecution, owner string) error {
				return store.MarkScheduledExecutionCompleted(ctx, execution.ID, owner, execution.AttemptCount)
			},
		},
		{
			name:    "running_failed",
			event:   "scheduled_execution_failed",
			running: true,
			transition: func(execution domain.ScheduledExecution, owner string) error {
				return store.MarkScheduledExecutionFailed(ctx, execution.ID, owner, execution.AttemptCount, "integration", "running failure")
			},
		},
		{
			name:    "running_cancelled",
			event:   "scheduled_execution_cancelled",
			running: true,
			transition: func(execution domain.ScheduledExecution, owner string) error {
				return store.MarkScheduledExecutionCancelled(ctx, execution.ID, owner, execution.AttemptCount)
			},
		},
		{
			name:  "claimed_failed",
			event: "scheduled_execution_failed",
			transition: func(execution domain.ScheduledExecution, owner string) error {
				return store.MarkScheduledExecutionFailed(ctx, execution.ID, owner, execution.AttemptCount, "integration", "claimed failure")
			},
		},
		{
			name:  "claimed_cancelled",
			event: "scheduled_execution_cancelled",
			transition: func(execution domain.ScheduledExecution, owner string) error {
				return store.MarkScheduledExecutionCancelled(ctx, execution.ID, owner, execution.AttemptCount)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			owner := "structured-terminal-" + test.name
			var execution domain.ScheduledExecution
			var wantScope *domain.ID
			if test.running {
				execution = startScheduledExecutionWithScope(t, store, ctx, programID, definitionID, test.name, owner, scopeVersionID)
				wantScope = &scopeVersionID
			} else {
				schedule := createIntegrationSchedule(t, ctx, store, programID, test.name)
				execution = enqueueAndClaim(t, ctx, store, schedule.ID, owner, time.Minute)
			}

			if err := test.transition(execution, owner); err != nil {
				t.Fatal(err)
			}
			assertSchedulerAuditProvenance(t, store, ctx, test.event, execution.ID, intPointer(execution.AttemptCount), wantScope)
		})
	}
}

func TestScheduledExecutionBlockedAndApprovalStructuredProvenance(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	programID, definitionID := createSchedulerIntegrationProgram(t, ctx, store, "structured-blocked-approval")
	var currentScopeVersionID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT id FROM scope_versions WHERE program_id=$1 ORDER BY created_at DESC LIMIT 1`, programID).Scan(&currentScopeVersionID); err != nil {
		t.Fatal(err)
	}

	blockedScopeVersionID := domain.NewID()
	if _, err := store.Pool.Exec(ctx, `INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,target_plan_digest,target_plan) VALUES($1,$2,'synthetic://blocked','blocked-scope','blocked-plan','{}')`, blockedScopeVersionID, programID); err != nil {
		t.Fatal(err)
	}
	blockedSchedule := createIntegrationSchedule(t, ctx, store, programID, "structured-blocked")
	blockedExecution := enqueueAndClaim(t, ctx, store, blockedSchedule.ID, "structured-blocked-owner", time.Minute)
	if err := store.MarkScheduledExecutionBlocked(ctx, blockedExecution.ID, blockedScopeVersionID, "structured-blocked-owner", blockedExecution.AttemptCount); err != nil {
		t.Fatal(err)
	}

	laterScopeVersionID := domain.NewID()
	if _, err := store.Pool.Exec(ctx, `INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,target_plan_digest,target_plan) VALUES($1,$2,'synthetic://later','later-scope','later-plan','{}')`, laterScopeVersionID, programID); err != nil {
		t.Fatal(err)
	}
	if blockedScopeVersionID == currentScopeVersionID || blockedScopeVersionID == laterScopeVersionID {
		t.Fatal("blocked scope fixture did not use a distinct historical scope")
	}
	assertSchedulerAuditProvenance(t, store, ctx, "scheduled_execution_blocked_scope_change", blockedExecution.ID, intPointer(blockedExecution.AttemptCount), &blockedScopeVersionID)

	approvalExecution := startScheduledExecutionWithScope(t, store, ctx, programID, definitionID, "structured-approval", "structured-approval-owner", currentScopeVersionID)
	if err := store.MarkScheduledExecutionPausedForApproval(ctx, approvalExecution.ID, "structured-approval-owner", approvalExecution.AttemptCount); err != nil {
		t.Fatal(err)
	}
	assertSchedulerAuditProvenance(t, store, ctx, "scheduled_execution_paused_for_approval", approvalExecution.ID, intPointer(approvalExecution.AttemptCount), &currentScopeVersionID)
}

func TestScheduledExecutionStructuredProvenanceFencingAndRollback(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	programID, definitionID := createSchedulerIntegrationProgram(t, ctx, store, "structured-fencing")

	schedule := createIntegrationSchedule(t, ctx, store, programID, "wrong-attempt")
	claimed := enqueueAndClaim(t, ctx, store, schedule.ID, "fenced-owner", time.Minute)
	if err := store.MarkScheduledExecutionFailed(ctx, claimed.ID, "wrong-owner", claimed.AttemptCount, "integration", "wrong owner"); err == nil {
		t.Fatal("wrong owner transition succeeded")
	}
	if err := store.MarkScheduledExecutionFailed(ctx, claimed.ID, "fenced-owner", claimed.AttemptCount+1, "integration", "wrong attempt"); err == nil {
		t.Fatal("wrong attempt transition succeeded")
	}
	assertSchedulerAuditAbsent(t, store, ctx, "scheduled_execution_failed", claimed.ID)

	rollbackSchedule := createIntegrationSchedule(t, ctx, store, programID, "audit-rollback")
	rollbackExecution := enqueueAndClaim(t, ctx, store, rollbackSchedule.ID, "rollback-owner", time.Minute)
	rollbackTask := createIntegrationTask(t, ctx, store, programID, definitionID, "audit-rollback")
	if err := store.MarkScheduledExecutionTaskCreated(ctx, rollbackExecution.ID, rollbackTask.ID, "rollback-owner", rollbackExecution.AttemptCount); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `CREATE FUNCTION reject_test_started_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='scheduled_execution_started' THEN RAISE EXCEPTION 'synthetic audit rejection'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_test_started_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_test_started_audit()`); err != nil {
		t.Fatal(err)
	}
	rollbackRunID := domain.NewID()
	now := time.Now().UTC()
	rollbackState := &workflow.State{Run: domain.WorkflowRun{ID: rollbackRunID, TaskID: rollbackTask.ID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "run_now", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{}}
	rollbackPersister := WorkflowPersister{Store: store, File: workflow.FileStore{Root: t.TempDir()}, Lifecycle: func(lifecycleCtx context.Context, state *workflow.State) error {
		return store.MarkScheduledExecutionRunning(lifecycleCtx, rollbackExecution.ID, rollbackTask.ID, state.Run.ID, nil, "rollback-owner", rollbackExecution.AttemptCount)
	}}
	if err := rollbackPersister.Save(WithScheduledExecutionFence(ctx, ScheduledExecutionFence{ExecutionID: rollbackExecution.ID, LeaseOwner: "rollback-owner", Attempt: rollbackExecution.AttemptCount}), rollbackState); err == nil {
		t.Fatal("synthetic audit rejection did not fail transaction")
	}
	if _, err := store.Pool.Exec(ctx, `DROP TRIGGER reject_test_started_audit ON audit_events; DROP FUNCTION reject_test_started_audit()`); err != nil {
		t.Fatal(err)
	}
	var status domain.ScheduledExecutionStatus
	var workflowRunID *domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT status,workflow_run_id FROM scheduled_executions WHERE id=$1`, rollbackExecution.ID).Scan(&status, &workflowRunID); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionClaimed || workflowRunID != nil {
		t.Fatalf("audit failure partially committed status=%s workflow=%v", status, workflowRunID)
	}
	assertSchedulerAuditAbsent(t, store, ctx, "scheduled_execution_started", rollbackExecution.ID)
}

func TestConcurrentScheduledExecutionsDoNotCrossLinkProvenance(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	programID, _ := createSchedulerIntegrationProgram(t, ctx, store, "structured-concurrency")
	first := enqueueAndClaim(t, ctx, store, createIntegrationSchedule(t, ctx, store, programID, "first").ID, "first-owner", time.Minute)
	second := enqueueAndClaim(t, ctx, store, createIntegrationSchedule(t, ctx, store, programID, "second").ID, "second-owner", time.Minute)

	errors := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		errors <- store.MarkScheduledExecutionFailed(ctx, first.ID, "first-owner", first.AttemptCount, "integration", "first")
	}()
	go func() {
		defer workers.Done()
		errors <- store.MarkScheduledExecutionFailed(ctx, second.ID, "second-owner", second.AttemptCount, "integration", "second")
	}()
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	assertSchedulerAuditProvenance(t, store, ctx, "scheduled_execution_failed", first.ID, intPointer(first.AttemptCount), nil)
	assertSchedulerAuditProvenance(t, store, ctx, "scheduled_execution_failed", second.ID, intPointer(second.AttemptCount), nil)
}

func assertSchedulerAuditProvenance(t *testing.T, store *Store, ctx context.Context, event string, executionID domain.ID, wantAttempt *int, wantScope *domain.ID) {
	t.Helper()
	var gotExecution domain.ID
	var gotAttempt *int
	var gotScope *domain.ID
	var detailsExecution domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT scheduled_execution_id,scheduler_attempt,scope_version_id,details->>'scheduled_execution_id' FROM audit_events WHERE event_type=$1 AND scheduled_execution_id=$2 ORDER BY occurred_at DESC,id DESC LIMIT 1`, event, executionID).Scan(&gotExecution, &gotAttempt, &gotScope, &detailsExecution); err != nil {
		t.Fatal(err)
	}
	if gotExecution != executionID || detailsExecution != executionID || !sameInt(gotAttempt, wantAttempt) || !sameRecoveryID(gotScope, wantScope) {
		t.Fatalf("audit %s execution=%s details_execution=%s attempt=%v scope=%v want execution=%s attempt=%v scope=%v", event, gotExecution, detailsExecution, gotAttempt, gotScope, executionID, wantAttempt, wantScope)
	}
}

func assertSchedulerAuditAbsent(t *testing.T, store *Store, ctx context.Context, event string, executionID domain.ID) {
	t.Helper()
	var count int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event_type=$1 AND scheduled_execution_id=$2`, event, executionID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("audit %s execution=%s count=%d want=0", event, executionID, count)
	}
}

func startScheduledExecutionWithScope(t *testing.T, store *Store, ctx context.Context, programID, definitionID domain.ID, name, owner string, scopeVersionID domain.ID) domain.ScheduledExecution {
	t.Helper()
	schedule := createIntegrationSchedule(t, ctx, store, programID, name)
	execution := enqueueAndClaim(t, ctx, store, schedule.ID, owner, time.Minute)
	task := createIntegrationTask(t, ctx, store, programID, definitionID, name)
	if err := store.MarkScheduledExecutionTaskCreated(ctx, execution.ID, task.ID, owner, execution.AttemptCount); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	state := &workflow.State{
		Run:   domain.WorkflowRun{ID: domain.NewID(), TaskID: task.ID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "run_now", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{},
	}
	persister := WorkflowPersister{Store: store, File: workflow.FileStore{Root: t.TempDir()}, Lifecycle: func(lifecycleCtx context.Context, state *workflow.State) error {
		return store.MarkScheduledExecutionRunning(lifecycleCtx, execution.ID, task.ID, state.Run.ID, &scopeVersionID, owner, execution.AttemptCount)
	}}
	if err := persister.Save(WithScheduledExecutionFence(ctx, ScheduledExecutionFence{ExecutionID: execution.ID, LeaseOwner: owner, Attempt: execution.AttemptCount}), state); err != nil {
		t.Fatal(err)
	}
	return execution
}

func intPointer(value int) *int {
	return &value
}

func sameInt(left, right *int) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
