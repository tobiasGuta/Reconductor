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
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

func TestScheduledExecutionLifecycleRecoveryAndOverlap(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	now := time.Now().UTC()
	programID, definitionID := domain.NewID(), domain.NewID()
	program := domain.Program{
		ID: programID, Name: "scheduler-" + string(programID), Platform: "integration",
		ScopeReference: "synthetic://local", PolicyReference: "integration",
		ScopeDigest: "scope", IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{},
		TargetPlanDigest: "plan", ScopePlanWarnings: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now,
	}
	snapshot := domain.ScopeSnapshot{ScopeReference: program.ScopeReference, ScopeDigest: program.ScopeDigest, IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: program.TargetPlanDigest, PlanningWarnings: json.RawMessage(`[]`), TargetPlan: json.RawMessage(`{}`), CreatedAt: now}
	if err := store.CreateProgram(ctx, program, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateWorkflowDefinition(ctx, definitionID, "scheduler-integration", "1", "synthetic", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}

	schedule := createIntegrationSchedule(t, ctx, store, programID, "primary")
	execution, err := store.EnqueueRunNow(ctx, schedule.ID, "integration")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnqueueRunNow(ctx, schedule.ID, "integration"); !errors.Is(err, ErrScheduleOverlap) {
		t.Fatalf("second run-now error = %v", err)
	}
	claimed, _, ok, err := store.ClaimPendingScheduledExecution(ctx, "owner-a", time.Minute)
	if err != nil || !ok || claimed.ID != execution.ID {
		t.Fatalf("claim = %#v ok=%v err=%v", claimed, ok, err)
	}
	task := createIntegrationTask(t, ctx, store, programID, definitionID, "primary")
	runID := domain.NewID()
	state := &workflow.State{
		Run:   domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "run_now", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{},
	}
	persister := WorkflowPersister{
		Store: store,
		File:  workflow.FileStore{Root: t.TempDir()},
		Lifecycle: func(lifecycleCtx context.Context, state *workflow.State) error {
			return store.MarkScheduledExecutionRunning(lifecycleCtx, execution.ID, task.ID, state.Run.ID, nil, "owner-a", claimed.AttemptCount)
		},
	}
	if err := persister.Save(ctx, state); err != nil {
		t.Fatal(err)
	}
	var status domain.ScheduledExecutionStatus
	var taskLineage, runLineage domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT status,task_id,workflow_run_id FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&status, &taskLineage, &runLineage); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionRunning || taskLineage != task.ID || runLineage != runID {
		t.Fatalf("lineage status=%s task=%s run=%s", status, taskLineage, runLineage)
	}
	if got, err := store.GetSchedule(ctx, schedule.ID); err != nil || got.LastRunAt == nil {
		t.Fatalf("last_run_at was not updated: schedule=%#v err=%v", got, err)
	}

	changeID := domain.NewID()
	if err := store.PersistChangeItems(ctx, programID, runID, nil, []domain.ChangeItem{{
		ID: changeID, Kind: "endpoint", EntityType: "endpoint", EntityKey: "endpoint-1",
		Priority: "medium", Title: "Changed endpoint", Summary: "synthetic",
		Reasons: json.RawMessage(`["HTTP status changed"]`), SourceCapabilities: []string{"classify.endpoint"},
		EvidenceArtifactIDs: []domain.ID{}, ObservedAt: now, CreatedAt: now,
	}}); err != nil {
		t.Fatal(err)
	}
	var linkedExecution domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT scheduled_execution_id FROM change_items WHERE id=$1`, changeID).Scan(&linkedExecution); err != nil {
		t.Fatal(err)
	}
	if linkedExecution != execution.ID {
		t.Fatalf("change item linked to %s, want %s", linkedExecution, execution.ID)
	}
	if err := store.MarkScheduledExecutionCompleted(ctx, execution.ID, "owner-a", claimed.AttemptCount); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionRunning(ctx, execution.ID, task.ID, runID, nil, "owner-a", claimed.AttemptCount); err == nil {
		t.Fatal("completed execution transitioned back to running")
	}

	rejectedSchedule := createIntegrationSchedule(t, ctx, store, programID, "rejected")
	rejectedExecution := enqueueAndClaim(t, ctx, store, rejectedSchedule.ID, "owner-b", time.Minute)
	rejectedTask := createIntegrationTask(t, ctx, store, programID, definitionID, "rejected")
	rejectedRunID, rejectedStepID := domain.NewID(), domain.NewID()
	rejectedState := &workflow.State{
		Run:   domain.WorkflowRun{ID: rejectedRunID, TaskID: rejectedTask.ID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunPaused, StartedAt: &now, TriggerSource: "run_now", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{"gated": {Run: domain.StepRun{ID: rejectedStepID, WorkflowRunID: rejectedRunID, StepDefinitionID: "gated", Capability: "scan.nuclei", Status: domain.StepAwaitingApproval, Input: json.RawMessage(`{}`), IdempotencyKey: "gated", ApprovalState: "pending"}}},
	}
	rejectedPersister := WorkflowPersister{Store: store, File: workflow.FileStore{Root: t.TempDir()}, Lifecycle: func(lifecycleCtx context.Context, state *workflow.State) error {
		return store.MarkScheduledExecutionRunning(lifecycleCtx, rejectedExecution.ID, rejectedTask.ID, state.Run.ID, nil, "owner-b", rejectedExecution.AttemptCount)
	}}
	if err := rejectedPersister.Save(ctx, rejectedState); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionPausedForApproval(ctx, rejectedExecution.ID, "owner-b", rejectedExecution.AttemptCount); err != nil {
		t.Fatal(err)
	}
	var approvalID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT id FROM approvals WHERE request_id=$1`, rejectedStepID).Scan(&approvalID); err != nil {
		t.Fatal(err)
	}
	if err := store.DecideApproval(ctx, approvalID, "rejected", "integration"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTaskStatusFromWorkflow(ctx, rejectedTask.ID, domain.TaskPaused); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, rejectedExecution.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionApprovalRejected {
		t.Fatalf("rejected execution status = %s", status)
	}
	var runStatus domain.RunStatus
	var taskStatus domain.TaskStatus
	var stepStatus domain.StepStatus
	if err := store.Pool.QueryRow(ctx, `SELECT status FROM workflow_runs WHERE id=$1`, rejectedRunID).Scan(&runStatus); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT status FROM tasks WHERE id=$1`, rejectedTask.ID).Scan(&taskStatus); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT status FROM step_runs WHERE id=$1`, rejectedStepID).Scan(&stepStatus); err != nil {
		t.Fatal(err)
	}
	if runStatus != domain.RunFailed || taskStatus != domain.TaskFailed || stepStatus != domain.StepFailed {
		t.Fatalf("rejected lineage remained active: task=%s run=%s step=%s", taskStatus, runStatus, stepStatus)
	}
	var activeOverlap bool
	if err := store.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM scheduled_executions WHERE schedule_id=$1 AND status IN ('claimed','running','paused_for_approval','paused_operator'))`, rejectedSchedule.ID).Scan(&activeOverlap); err != nil {
		t.Fatal(err)
	}
	if activeOverlap {
		t.Fatal("approval rejection left an active overlap")
	}
	laterExecution, err := store.EnqueueRunNow(ctx, rejectedSchedule.ID, "integration")
	if err != nil {
		t.Fatalf("run now remained blocked after rejection: %v", err)
	}
	laterClaim, _, ok, err := store.ClaimPendingScheduledExecution(ctx, "owner-b-later", time.Minute)
	if err != nil || !ok || laterClaim.ID != laterExecution.ID {
		t.Fatalf("later run-now claim = %#v ok=%v err=%v", laterClaim, ok, err)
	}
	if err := store.MarkScheduledExecutionFailed(ctx, laterClaim.ID, "owner-b-later", laterClaim.AttemptCount, "test", "cleanup"); err != nil {
		t.Fatal(err)
	}

	cancelledSchedule := createIntegrationSchedule(t, ctx, store, programID, "cancelled")
	cancelledExecution := enqueueAndClaim(t, ctx, store, cancelledSchedule.ID, "owner-c", time.Minute)
	cancelledTask := createIntegrationTask(t, ctx, store, programID, definitionID, "cancelled")
	cancelledRun := domain.NewID()
	if err := saveIntegrationRun(ctx, store, t.TempDir(), cancelledExecution.ID, cancelledTask, definitionID, cancelledRun, "owner-c", cancelledExecution.AttemptCount, now); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionCancelled(ctx, cancelledExecution.ID, "owner-c", cancelledExecution.AttemptCount); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, cancelledExecution.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionCancelled {
		t.Fatalf("cancelled execution status = %s", status)
	}

	operatorSchedule := createIntegrationSchedule(t, ctx, store, programID, "operator-pause")
	operatorExecution := enqueueAndClaim(t, ctx, store, operatorSchedule.ID, "owner-pause", time.Minute)
	operatorTask := createIntegrationTask(t, ctx, store, programID, definitionID, "operator-pause")
	if err := saveIntegrationRun(ctx, store, t.TempDir(), operatorExecution.ID, operatorTask, definitionID, domain.NewID(), "owner-pause", operatorExecution.AttemptCount, now); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionPaused(ctx, operatorExecution.ID, "owner-pause", operatorExecution.AttemptCount); err != nil {
		t.Fatal(err)
	}
	if err := store.RequestScheduledExecutionResume(ctx, operatorExecution.ID, "integration"); err != nil {
		t.Fatal(err)
	}
	var triggerSource string
	if err := store.Pool.QueryRow(ctx, `SELECT status,trigger_source FROM scheduled_executions WHERE id=$1`, operatorExecution.ID).Scan(&status, &triggerSource); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionPending || triggerSource != domain.ScheduleTriggerResume {
		t.Fatalf("operator resume status=%s trigger=%s", status, triggerSource)
	}
	resumed, _, ok, err := store.ClaimPendingScheduledExecution(ctx, "owner-resume", time.Minute)
	if err != nil || !ok || resumed.ID != operatorExecution.ID {
		t.Fatalf("operator resume claim = %#v ok=%v err=%v", resumed, ok, err)
	}
	if err := store.MarkScheduledExecutionFailed(ctx, resumed.ID, "owner-resume", resumed.AttemptCount, "test", "cleanup"); err != nil {
		t.Fatal(err)
	}

	blockedSchedule := createIntegrationSchedule(t, ctx, store, programID, "scope-blocked")
	blockedExecution := enqueueAndClaim(t, ctx, store, blockedSchedule.ID, "owner-blocked", time.Minute)
	var scopeVersionID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT id FROM scope_versions WHERE program_id=$1 ORDER BY created_at DESC LIMIT 1`, programID).Scan(&scopeVersionID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionBlocked(ctx, blockedExecution.ID, scopeVersionID, "owner-blocked", blockedExecution.AttemptCount); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, blockedExecution.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionBlockedScopeChange {
		t.Fatalf("scope-blocked execution status = %s", status)
	}

	staleSchedule := createIntegrationSchedule(t, ctx, store, programID, "stale-claim")
	staleExecution := enqueueAndClaim(t, ctx, store, staleSchedule.ID, "stale-owner", -time.Second)
	reclaimed, _, ok, err := store.ClaimPendingScheduledExecution(ctx, "new-owner", time.Minute)
	if err != nil || !ok || reclaimed.ID != staleExecution.ID || reclaimed.AttemptCount != 2 {
		t.Fatalf("stale claim recovery = %#v ok=%v err=%v", reclaimed, ok, err)
	}
	if err := store.MarkScheduledExecutionFailed(ctx, reclaimed.ID, "new-owner", reclaimed.AttemptCount, "test", "cleanup"); err != nil {
		t.Fatal(err)
	}

	interruptedSchedule := createIntegrationSchedule(t, ctx, store, programID, "interrupted")
	interruptedExecution := enqueueAndClaim(t, ctx, store, interruptedSchedule.ID, "old-owner", time.Minute)
	interruptedTask := createIntegrationTask(t, ctx, store, programID, definitionID, "interrupted")
	interruptedRun := domain.NewID()
	if err := saveIntegrationRun(ctx, store, t.TempDir(), interruptedExecution.ID, interruptedTask, definitionID, interruptedRun, "old-owner", interruptedExecution.AttemptCount, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `UPDATE scheduled_executions SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, interruptedExecution.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := store.ClaimPendingScheduledExecution(ctx, "new-owner", time.Minute); err != nil || ok {
		t.Fatalf("lineaged stale execution was re-claimed: ok=%v err=%v", ok, err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, interruptedExecution.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionInterrupted {
		t.Fatalf("lineaged stale execution status = %s", status)
	}

	duplicateSchedule := createIntegrationSchedule(t, ctx, store, programID, "duplicate-claim")
	firstID, secondID := domain.NewID(), domain.NewID()
	if _, err := store.Pool.Exec(ctx, `INSERT INTO scheduled_executions(id,schedule_id,planned_at,trigger_source,status,created_at,updated_at) VALUES($1,$3,$4,'run_now','pending',$4,$4),($2,$3,$5,'run_now','pending',$5,$5)`, firstID, secondID, duplicateSchedule.ID, now.Add(time.Second), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	firstClaim, _, ok, err := store.ClaimPendingScheduledExecution(ctx, "claim-owner-a", time.Minute)
	if err != nil || !ok || firstClaim.ID != firstID {
		t.Fatalf("first duplicate claim = %#v ok=%v err=%v", firstClaim, ok, err)
	}
	if _, _, ok, err := store.ClaimPendingScheduledExecution(ctx, "claim-owner-b", time.Minute); err != nil || ok {
		t.Fatalf("overlapping pending execution was claimed: ok=%v err=%v", ok, err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, secondID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionSkippedOverlap {
		t.Fatalf("second duplicate status = %s", status)
	}

	var auditCount int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE component='scheduler' AND event_type IN ('scheduled_execution_started','scheduled_execution_completed','scheduled_execution_approval_rejected','scheduled_execution_cancelled','scheduled_execution_stale_claim_recovered','scheduled_execution_interrupted','scheduled_execution_skipped_overlap')`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount < 7 {
		t.Fatalf("scheduler transition audit count = %d", auditCount)
	}
}

func TestWorkflowLifecycleRollbackIsAtomic(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	now := time.Now().UTC()
	programID, definitionID := domain.NewID(), domain.NewID()
	program := domain.Program{ID: programID, Name: "atomic-" + string(programID), Platform: "integration", ScopeReference: "synthetic://local", PolicyReference: "integration", ScopeDigest: "scope", IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: "plan", ScopePlanWarnings: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now}
	snapshot := domain.ScopeSnapshot{ScopeReference: program.ScopeReference, ScopeDigest: program.ScopeDigest, IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: program.TargetPlanDigest, PlanningWarnings: json.RawMessage(`[]`), TargetPlan: json.RawMessage(`{}`), CreatedAt: now}
	if err := store.CreateProgram(ctx, program, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateWorkflowDefinition(ctx, definitionID, "atomic", "1", "synthetic", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	schedule := createIntegrationSchedule(t, ctx, store, programID, "atomic")
	execution := enqueueAndClaim(t, ctx, store, schedule.ID, "atomic-owner", time.Minute)
	task := createIntegrationTask(t, ctx, store, programID, definitionID, "atomic")
	runID := domain.NewID()
	state := &workflow.State{Run: domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "run_now", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{}}
	persister := WorkflowPersister{Store: store, File: workflow.FileStore{Root: t.TempDir()}, Lifecycle: func(lifecycleCtx context.Context, state *workflow.State) error {
		if err := store.MarkScheduledExecutionRunning(lifecycleCtx, execution.ID, task.ID, state.Run.ID, nil, "atomic-owner", execution.AttemptCount); err != nil {
			return err
		}
		return errors.New("synthetic lifecycle failure")
	}}
	if err := persister.Save(ctx, state); err == nil {
		t.Fatal("expected lifecycle failure")
	}
	var taskID, workflowRunID *domain.ID
	var status domain.ScheduledExecutionStatus
	if err := store.Pool.QueryRow(ctx, `SELECT status,task_id,workflow_run_id FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&status, &taskID, &workflowRunID); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionClaimed || taskID != nil || workflowRunID != nil {
		t.Fatalf("lineage transaction partially committed: status=%s task=%v run=%v", status, taskID, workflowRunID)
	}
	var runCount int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM workflow_runs WHERE id=$1`, runID).Scan(&runCount); err != nil {
		t.Fatal(err)
	}
	if runCount != 0 {
		t.Fatalf("workflow run committed despite lifecycle rollback: %d", runCount)
	}
}

func TestScheduledExecutionRecoveryProtocolAndHeartbeatFencing(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	programID, definitionID := createSchedulerIntegrationProgram(t, ctx, store, "lease-fencing")

	schedule := createIntegrationSchedule(t, ctx, store, programID, "lease-fencing")
	pending, err := store.EnqueueRunNow(ctx, schedule.ID, "integration")
	if err != nil {
		t.Fatal(err)
	}
	var protocol int
	if err := store.Pool.QueryRow(ctx, `SELECT recovery_protocol_version FROM scheduled_executions WHERE id=$1`, pending.ID).Scan(&protocol); err != nil {
		t.Fatal(err)
	}
	if protocol != 0 {
		t.Fatalf("pending recovery protocol=%d want=0", protocol)
	}
	claimed, _, ok, err := store.ClaimPendingScheduledExecution(ctx, "lease-owner", time.Minute)
	if err != nil || !ok || claimed.ID != pending.ID {
		t.Fatalf("claim=%#v ok=%v err=%v", claimed, ok, err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT recovery_protocol_version FROM scheduled_executions WHERE id=$1`, claimed.ID).Scan(&protocol); err != nil {
		t.Fatal(err)
	}
	if protocol != 1 {
		t.Fatalf("claimed recovery protocol=%d want=1", protocol)
	}
	if err := store.HeartbeatScheduledExecution(ctx, claimed.ID, "lease-owner", claimed.AttemptCount, 2*time.Minute); err != nil {
		t.Fatalf("current heartbeat: %v", err)
	}
	var renewed bool
	if err := store.Pool.QueryRow(ctx, `SELECT lease_expires_at>now()+interval '90 seconds' FROM scheduled_executions WHERE id=$1`, claimed.ID).Scan(&renewed); err != nil {
		t.Fatal(err)
	}
	if !renewed {
		t.Fatal("current heartbeat did not extend the lease using database time")
	}
	if err := store.HeartbeatScheduledExecution(ctx, claimed.ID, "wrong-owner", claimed.AttemptCount, time.Minute); err == nil {
		t.Fatal("wrong owner heartbeat succeeded")
	}
	if err := store.HeartbeatScheduledExecution(ctx, claimed.ID, "lease-owner", claimed.AttemptCount+1, time.Minute); err == nil {
		t.Fatal("wrong attempt heartbeat succeeded")
	}

	terminalSchedule := createIntegrationSchedule(t, ctx, store, programID, "terminal-heartbeat")
	terminal := enqueueAndClaim(t, ctx, store, terminalSchedule.ID, "terminal-owner", time.Minute)
	if err := store.MarkScheduledExecutionFailed(ctx, terminal.ID, "terminal-owner", terminal.AttemptCount+1, "test", "wrong attempt"); err == nil {
		t.Fatal("wrong attempt terminal transition succeeded")
	}
	if err := store.MarkScheduledExecutionFailed(ctx, terminal.ID, "terminal-owner", terminal.AttemptCount, "test", "terminal heartbeat fixture"); err != nil {
		t.Fatal(err)
	}
	if err := store.HeartbeatScheduledExecution(ctx, terminal.ID, "terminal-owner", terminal.AttemptCount, time.Minute); err == nil {
		t.Fatal("terminal execution heartbeat succeeded")
	}

	runningSchedule := createIntegrationSchedule(t, ctx, store, programID, "running-attempt-fence")
	runningExecution := enqueueAndClaim(t, ctx, store, runningSchedule.ID, "running-owner", time.Minute)
	runningTask := createIntegrationTask(t, ctx, store, programID, definitionID, "running-attempt-fence")
	if err := store.MarkScheduledExecutionRunning(ctx, runningExecution.ID, runningTask.ID, domain.NewID(), nil, "running-owner", runningExecution.AttemptCount+1); err == nil {
		t.Fatal("wrong attempt running transition succeeded")
	}
	var fencedStatus domain.ScheduledExecutionStatus
	var fencedTaskID, fencedRunID *domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT status,task_id,workflow_run_id FROM scheduled_executions WHERE id=$1`, runningExecution.ID).Scan(&fencedStatus, &fencedTaskID, &fencedRunID); err != nil {
		t.Fatal(err)
	}
	if fencedStatus != domain.ScheduledExecutionClaimed || fencedTaskID != nil || fencedRunID != nil {
		t.Fatalf("wrong attempt changed running lineage status=%s task=%v run=%v", fencedStatus, fencedTaskID, fencedRunID)
	}
	var successAudits int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event_type='scheduled_execution_started' AND details->>'scheduled_execution_id'=$1`, runningExecution.ID).Scan(&successAudits); err != nil {
		t.Fatal(err)
	}
	if successAudits != 0 {
		t.Fatalf("wrong attempt appended running audits=%d", successAudits)
	}
	if err := store.MarkScheduledExecutionFailed(ctx, runningExecution.ID, "running-owner", runningExecution.AttemptCount, "test", "cleanup"); err != nil {
		t.Fatal(err)
	}

	blockedSchedule := createIntegrationSchedule(t, ctx, store, programID, "blocked-attempt-fence")
	blockedExecution := enqueueAndClaim(t, ctx, store, blockedSchedule.ID, "blocked-owner", time.Minute)
	var scopeVersionID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT id FROM scope_versions WHERE program_id=$1 ORDER BY created_at DESC LIMIT 1`, programID).Scan(&scopeVersionID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionBlocked(ctx, blockedExecution.ID, scopeVersionID, "blocked-owner", blockedExecution.AttemptCount+1); err == nil {
		t.Fatal("wrong attempt blocked transition succeeded")
	}
	var fencedScopeVersionID *domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT status,scope_version_id FROM scheduled_executions WHERE id=$1`, blockedExecution.ID).Scan(&fencedStatus, &fencedScopeVersionID); err != nil {
		t.Fatal(err)
	}
	if fencedStatus != domain.ScheduledExecutionClaimed || fencedScopeVersionID != nil {
		t.Fatalf("wrong attempt changed blocked state status=%s scope=%v", fencedStatus, fencedScopeVersionID)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event_type='scheduled_execution_blocked_scope_change' AND details->>'scheduled_execution_id'=$1`, blockedExecution.ID).Scan(&successAudits); err != nil {
		t.Fatal(err)
	}
	if successAudits != 0 {
		t.Fatalf("wrong attempt appended blocked audits=%d", successAudits)
	}
	if err := store.MarkScheduledExecutionFailed(ctx, blockedExecution.ID, "blocked-owner", blockedExecution.AttemptCount, "test", "cleanup"); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Pool.Exec(ctx, `UPDATE scheduled_executions SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, claimed.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.HeartbeatScheduledExecution(ctx, claimed.ID, "lease-owner", claimed.AttemptCount, time.Minute); err == nil {
		t.Fatal("expired lease was renewed")
	}
	var stillExpired bool
	if err := store.Pool.QueryRow(ctx, `SELECT lease_expires_at<=now() FROM scheduled_executions WHERE id=$1`, claimed.ID).Scan(&stillExpired); err != nil {
		t.Fatal(err)
	}
	if !stillExpired {
		t.Fatal("failed heartbeat changed the expired lease")
	}
}

func TestScheduledExecutionLeaseFencingUsesLiveDatabaseTime(t *testing.T) {
	t.Run("heartbeat blocked past expiry", func(t *testing.T) {
		store, ctx := schedulerIntegrationStore(t)
		programID, _ := createSchedulerIntegrationProgram(t, ctx, store, "heartbeat-lock-barrier")
		schedule := createIntegrationSchedule(t, ctx, store, programID, "heartbeat-lock-barrier")
		execution := enqueueAndClaim(t, ctx, store, schedule.ID, "heartbeat-lock-owner", 3*time.Second)

		lockTx, err := store.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		locked := true
		defer func() {
			if locked {
				_ = lockTx.Rollback(context.Background())
			}
		}()
		if err := lockTx.QueryRow(ctx, `SELECT id FROM scheduled_executions WHERE id=$1 FOR UPDATE`, execution.ID).Scan(new(domain.ID)); err != nil {
			t.Fatal(err)
		}
		var originalExpiry time.Time
		if err := store.Pool.QueryRow(ctx, `SELECT lease_expires_at FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&originalExpiry); err != nil {
			t.Fatal(err)
		}

		heartbeatCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		heartbeatResult := make(chan error, 1)
		go func() {
			heartbeatResult <- store.HeartbeatScheduledExecution(heartbeatCtx, execution.ID, "heartbeat-lock-owner", execution.AttemptCount, time.Minute)
		}()
		waitForPostgresLock(t, heartbeatCtx, store, `%WHERE se.id=$1%FOR UPDATE OF se%`)
		var validWhileBlocked bool
		if err := store.Pool.QueryRow(ctx, `SELECT lease_expires_at>clock_timestamp() FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&validWhileBlocked); err != nil {
			t.Fatal(err)
		}
		if !validWhileBlocked {
			t.Fatal("heartbeat did not begin blocking while the lease was valid")
		}
		for {
			var expired bool
			if err := store.Pool.QueryRow(ctx, `SELECT lease_expires_at<=clock_timestamp() FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&expired); err != nil {
				t.Fatal(err)
			}
			if expired {
				break
			}
			select {
			case <-heartbeatCtx.Done():
				t.Fatalf("lease did not expire before timeout: %v", heartbeatCtx.Err())
			case <-time.After(25 * time.Millisecond):
			}
		}
		if err := lockTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		locked = false
		select {
		case err := <-heartbeatResult:
			if err == nil {
				t.Fatal("heartbeat blocked past expiry renewed the lease")
			}
		case <-heartbeatCtx.Done():
			t.Fatalf("heartbeat did not finish after lock release: %v", heartbeatCtx.Err())
		}
		var persistedExpiry time.Time
		if err := store.Pool.QueryRow(ctx, `SELECT lease_expires_at FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&persistedExpiry); err != nil {
			t.Fatal(err)
		}
		if !persistedExpiry.Equal(originalExpiry) {
			t.Fatalf("failed heartbeat changed expiry from %s to %s", originalExpiry, persistedExpiry)
		}
	})

	t.Run("claim skips a locked stale recovery row", func(t *testing.T) {
		store, ctx := schedulerIntegrationStore(t)
		programID, _ := createSchedulerIntegrationProgram(t, ctx, store, "claim-lock-barrier")
		staleSchedule := createIntegrationSchedule(t, ctx, store, programID, "claim-lock-stale")
		stale := enqueueAndClaim(t, ctx, store, staleSchedule.ID, "stale-claim-owner", time.Minute)
		if _, err := store.Pool.Exec(ctx, `UPDATE scheduled_executions SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, stale.ID); err != nil {
			t.Fatal(err)
		}
		pendingSchedule := createIntegrationSchedule(t, ctx, store, programID, "claim-lock-pending")
		if _, err := store.EnqueueRunNow(ctx, pendingSchedule.ID, "integration"); err != nil {
			t.Fatal(err)
		}

		lockTx, err := store.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		locked := true
		defer func() {
			if locked {
				_ = lockTx.Rollback(context.Background())
			}
		}()
		if err := lockTx.QueryRow(ctx, `SELECT id FROM scheduled_executions WHERE id=$1 FOR UPDATE`, stale.ID).Scan(new(domain.ID)); err != nil {
			t.Fatal(err)
		}

		claimCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		type claimResult struct {
			execution domain.ScheduledExecution
			ok        bool
			err       error
		}
		claimedResult := make(chan claimResult, 1)
		go func() {
			execution, _, ok, err := store.ClaimPendingScheduledExecution(claimCtx, "live-claim-owner", 2*time.Second)
			claimedResult <- claimResult{execution: execution, ok: ok, err: err}
		}()
		var result claimResult
		select {
		case result = <-claimedResult:
		case <-claimCtx.Done():
			t.Fatalf("claim was blocked by an unrelated stale execution: %v", claimCtx.Err())
		}
		if result.err != nil || !result.ok {
			t.Fatalf("claim after lock wait execution=%#v ok=%v err=%v", result.execution, result.ok, result.err)
		}
		var hasFreshLease bool
		if err := store.Pool.QueryRow(ctx, `SELECT lease_expires_at>clock_timestamp()+interval '1.2 seconds' FROM scheduled_executions WHERE id=$1`, result.execution.ID).Scan(&hasFreshLease); err != nil {
			t.Fatal(err)
		}
		if !hasFreshLease {
			t.Fatal("claim did not receive a fresh live-database-time lease")
		}
		if err := lockTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		locked = false
	})
}

func waitForPostgresLock(t *testing.T, ctx context.Context, store *Store, queryPattern string) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := store.Pool.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM pg_stat_activity
			WHERE pid<>pg_backend_pid()
			  AND wait_event_type='Lock'
			  AND query LIKE $1
		)`, queryPattern).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("database statement did not reach lock barrier: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func TestPreUpgradeNoLineageClaimIsNotRequeued(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	programID, _ := createSchedulerIntegrationProgram(t, ctx, store, "legacy-recovery")
	schedule := createIntegrationSchedule(t, ctx, store, programID, "legacy-recovery")
	execution, err := store.EnqueueRunNow(ctx, schedule.ID, "integration")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `UPDATE scheduled_executions
		SET status='claimed',attempt_count=1,lease_owner='legacy-owner',lease_expires_at=now()-interval '1 second'
		WHERE id=$1`, execution.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := store.ClaimPendingScheduledExecution(ctx, "new-owner", time.Minute); err != nil || ok {
		t.Fatalf("legacy recovery claim ok=%v err=%v", ok, err)
	}
	var status domain.ScheduledExecutionStatus
	var protocol int
	var summary string
	if err := store.Pool.QueryRow(ctx, `SELECT status,recovery_protocol_version,error_summary FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&status, &protocol, &summary); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionInterrupted || protocol != 0 || summary != "persisted scheduler lineage is incomplete or contradictory and requires manual review" {
		t.Fatalf("legacy execution status=%s protocol=%d summary=%q", status, protocol, summary)
	}
}

func TestScheduledTaskCreationLinksAtomicallyAndIsFenced(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	programID, definitionID := createSchedulerIntegrationProgram(t, ctx, store, "task-linkage")
	newTask := func(name string) domain.Task {
		now := time.Now().UTC()
		return domain.Task{ID: domain.NewID(), ProgramID: programID, Objective: name, WorkflowDefinitionID: definitionID, Status: domain.TaskRunning, RequestedBy: "integration", CreatedAt: now, UpdatedAt: now}
	}
	assertAbsentAndUnlinked := func(taskID, executionID domain.ID) {
		t.Helper()
		var taskCount int
		var linkedTask *domain.ID
		if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE id=$1`, taskID).Scan(&taskCount); err != nil {
			t.Fatal(err)
		}
		if err := store.Pool.QueryRow(ctx, `SELECT task_id FROM scheduled_executions WHERE id=$1`, executionID).Scan(&linkedTask); err != nil {
			t.Fatal(err)
		}
		if taskCount != 0 || linkedTask != nil {
			t.Fatalf("task=%s count=%d execution task=%v", taskID, taskCount, linkedTask)
		}
	}

	schedule := createIntegrationSchedule(t, ctx, store, programID, "task-linkage")
	execution := enqueueAndClaim(t, ctx, store, schedule.ID, "task-owner", time.Minute)
	task := newTask("scheduled task")
	if err := store.CreateTaskWithLifecycle(ctx, task, func(lifecycleCtx context.Context, created domain.Task) error {
		return store.MarkScheduledExecutionTaskCreated(lifecycleCtx, execution.ID, created.ID, "task-owner", execution.AttemptCount)
	}); err != nil {
		t.Fatal(err)
	}
	var linkedTask domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT task_id FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&linkedTask); err != nil {
		t.Fatal(err)
	}
	if linkedTask != task.ID {
		t.Fatalf("linked task=%s want=%s", linkedTask, task.ID)
	}
	if err := store.MarkScheduledExecutionTaskCreated(ctx, execution.ID, task.ID, "task-owner", execution.AttemptCount); err != nil {
		t.Fatalf("same task linkage was not idempotent: %v", err)
	}
	var linkAudits int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE task_id=$1 AND event_type='scheduled_execution_task_linked'`, task.ID).Scan(&linkAudits); err != nil {
		t.Fatal(err)
	}
	if linkAudits != 1 {
		t.Fatalf("task link audits=%d want=1", linkAudits)
	}
	different := newTask("different task")
	if err := store.CreateTask(ctx, different); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionTaskCreated(ctx, execution.ID, different.ID, "task-owner", execution.AttemptCount); err == nil {
		t.Fatal("different task replaced scheduled lineage")
	}

	rollbackSchedule := createIntegrationSchedule(t, ctx, store, programID, "task-rollback")
	rollbackExecution := enqueueAndClaim(t, ctx, store, rollbackSchedule.ID, "rollback-owner", time.Minute)
	rollbackTask := newTask("rollback task")
	callbackErr := errors.New("synthetic task lifecycle failure")
	err := store.CreateTaskWithLifecycle(ctx, rollbackTask, func(lifecycleCtx context.Context, created domain.Task) error {
		if err := store.MarkScheduledExecutionTaskCreated(lifecycleCtx, rollbackExecution.ID, created.ID, "rollback-owner", rollbackExecution.AttemptCount); err != nil {
			return err
		}
		return callbackErr
	})
	if !errors.Is(err, callbackErr) {
		t.Fatalf("lifecycle error=%v want=%v", err, callbackErr)
	}
	assertAbsentAndUnlinked(rollbackTask.ID, rollbackExecution.ID)
	var rollbackAudits int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE task_id=$1 AND event_type IN ('task_created','scheduled_execution_task_linked')`, rollbackTask.ID).Scan(&rollbackAudits); err != nil {
		t.Fatal(err)
	}
	if rollbackAudits != 0 {
		t.Fatalf("rolled-back task audits=%d want=0", rollbackAudits)
	}

	fencedSchedule := createIntegrationSchedule(t, ctx, store, programID, "task-fencing")
	fencedExecution := enqueueAndClaim(t, ctx, store, fencedSchedule.ID, "fenced-owner", time.Minute)
	for name, tc := range map[string]struct {
		owner   string
		attempt int
	}{
		"wrong owner":   {owner: "wrong-owner", attempt: fencedExecution.AttemptCount},
		"wrong attempt": {owner: "fenced-owner", attempt: fencedExecution.AttemptCount + 1},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := newTask(name)
			err := store.CreateTaskWithLifecycle(ctx, candidate, func(lifecycleCtx context.Context, created domain.Task) error {
				return store.MarkScheduledExecutionTaskCreated(lifecycleCtx, fencedExecution.ID, created.ID, tc.owner, tc.attempt)
			})
			if err == nil {
				t.Fatal("invalid task linkage succeeded")
			}
			assertAbsentAndUnlinked(candidate.ID, fencedExecution.ID)
		})
	}
	if _, err := store.Pool.Exec(ctx, `UPDATE scheduled_executions SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, fencedExecution.ID); err != nil {
		t.Fatal(err)
	}
	expiredTask := newTask("expired lease")
	err = store.CreateTaskWithLifecycle(ctx, expiredTask, func(lifecycleCtx context.Context, created domain.Task) error {
		return store.MarkScheduledExecutionTaskCreated(lifecycleCtx, fencedExecution.ID, created.ID, "fenced-owner", fencedExecution.AttemptCount)
	})
	if err == nil {
		t.Fatal("expired lease task linkage succeeded")
	}
	assertAbsentAndUnlinked(expiredTask.ID, fencedExecution.ID)
	recoveredFenced, _, ok, err := store.ClaimPendingScheduledExecution(ctx, "fenced-cleanup-owner", time.Minute)
	if err != nil || !ok || recoveredFenced.ID != fencedExecution.ID {
		t.Fatalf("recover expired task-fencing execution=%#v ok=%v err=%v", recoveredFenced, ok, err)
	}
	if err := store.MarkScheduledExecutionFailed(ctx, recoveredFenced.ID, "fenced-cleanup-owner", recoveredFenced.AttemptCount, "test", "cleanup"); err != nil {
		t.Fatal(err)
	}

	sameSchedule := createIntegrationSchedule(t, ctx, store, programID, "same-task-concurrency")
	sameExecution := enqueueAndClaim(t, ctx, store, sameSchedule.ID, "same-task-owner", time.Minute)
	sameTask := newTask("concurrent same task")
	if err := store.CreateTask(ctx, sameTask); err != nil {
		t.Fatal(err)
	}
	sameCtx, cancelSame := context.WithTimeout(ctx, 5*time.Second)
	defer cancelSame()
	sameStart := make(chan struct{})
	sameResults := make(chan error, 2)
	for range 2 {
		go func() {
			<-sameStart
			sameResults <- store.MarkScheduledExecutionTaskCreated(sameCtx, sameExecution.ID, sameTask.ID, "same-task-owner", sameExecution.AttemptCount)
		}()
	}
	close(sameStart)
	for range 2 {
		select {
		case err := <-sameResults:
			if err != nil {
				t.Fatalf("concurrent same-task linkage: %v", err)
			}
		case <-sameCtx.Done():
			t.Fatalf("concurrent same-task linkage timed out: %v", sameCtx.Err())
		}
	}
	if err := store.Pool.QueryRow(ctx, `SELECT task_id FROM scheduled_executions WHERE id=$1`, sameExecution.ID).Scan(&linkedTask); err != nil {
		t.Fatal(err)
	}
	if linkedTask != sameTask.ID {
		t.Fatalf("concurrent same-task linkage=%s want=%s", linkedTask, sameTask.ID)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE task_id=$1 AND event_type='scheduled_execution_task_linked'`, sameTask.ID).Scan(&linkAudits); err != nil {
		t.Fatal(err)
	}
	if linkAudits != 1 {
		t.Fatalf("concurrent same-task audits=%d want=1", linkAudits)
	}

	competingSchedule := createIntegrationSchedule(t, ctx, store, programID, "competing-task-concurrency")
	competingExecution := enqueueAndClaim(t, ctx, store, competingSchedule.ID, "competing-task-owner", time.Minute)
	competingTasks := []domain.Task{newTask("competing task a"), newTask("competing task b")}
	type competingResult struct {
		taskID domain.ID
		err    error
	}
	competingCtx, cancelCompeting := context.WithTimeout(ctx, 5*time.Second)
	defer cancelCompeting()
	competingStart := make(chan struct{})
	competingResults := make(chan competingResult, len(competingTasks))
	for _, candidate := range competingTasks {
		candidate := candidate
		go func() {
			<-competingStart
			err := store.CreateTaskWithLifecycle(competingCtx, candidate, func(lifecycleCtx context.Context, created domain.Task) error {
				return store.MarkScheduledExecutionTaskCreated(lifecycleCtx, competingExecution.ID, created.ID, "competing-task-owner", competingExecution.AttemptCount)
			})
			competingResults <- competingResult{taskID: candidate.ID, err: err}
		}()
	}
	close(competingStart)
	succeeded := map[domain.ID]bool{}
	failed := 0
	for range competingTasks {
		select {
		case result := <-competingResults:
			if result.err == nil {
				succeeded[result.taskID] = true
			} else {
				failed++
			}
		case <-competingCtx.Done():
			t.Fatalf("competing task linkage timed out: %v", competingCtx.Err())
		}
	}
	if len(succeeded) != 1 || failed != 1 {
		t.Fatalf("competing task results succeeded=%v failed=%d", succeeded, failed)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT task_id FROM scheduled_executions WHERE id=$1`, competingExecution.ID).Scan(&linkedTask); err != nil {
		t.Fatal(err)
	}
	if !succeeded[linkedTask] {
		t.Fatalf("competing task linkage=%s successful=%v", linkedTask, succeeded)
	}
	var competingTaskRows int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE id=$1 OR id=$2`, competingTasks[0].ID, competingTasks[1].ID).Scan(&competingTaskRows); err != nil {
		t.Fatal(err)
	}
	if competingTaskRows != 1 {
		t.Fatalf("competing persisted tasks=%d want=1", competingTaskRows)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event_type='scheduled_execution_task_linked' AND details->>'scheduled_execution_id'=$1`, competingExecution.ID).Scan(&linkAudits); err != nil {
		t.Fatal(err)
	}
	if linkAudits != 1 {
		t.Fatalf("competing task link audits=%d want=1", linkAudits)
	}

	ordinary := newTask("ordinary unscheduled task")
	if err := store.CreateTask(ctx, ordinary); err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetTask(ctx, ordinary.ID)
	if err != nil || stored.ID != ordinary.ID {
		t.Fatalf("ordinary task=%#v err=%v", stored, err)
	}
}

func TestApprovalAcceptanceStillRequiresExplicitResume(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	programID, definitionID := createSchedulerIntegrationProgram(t, ctx, store, "approval-resume")
	schedule := createIntegrationSchedule(t, ctx, store, programID, "approval-resume")
	execution := enqueueAndClaim(t, ctx, store, schedule.ID, "approval-owner", time.Minute)
	now := time.Now().UTC()
	task := domain.Task{ID: domain.NewID(), ProgramID: programID, Objective: "approval resume", WorkflowDefinitionID: definitionID, Status: domain.TaskRunning, RequestedBy: "integration", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateTaskWithLifecycle(ctx, task, func(lifecycleCtx context.Context, created domain.Task) error {
		return store.MarkScheduledExecutionTaskCreated(lifecycleCtx, execution.ID, created.ID, "approval-owner", execution.AttemptCount)
	}); err != nil {
		t.Fatal(err)
	}
	runID, stepID := domain.NewID(), domain.NewID()
	state := &workflow.State{
		Run:   domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunPaused, StartedAt: &now, TriggerSource: "run_now", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{"gated": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "gated", Capability: "scan.nuclei", Status: domain.StepAwaitingApproval, Input: json.RawMessage(`{}`), IdempotencyKey: "approval-resume", ApprovalState: "pending"}}},
	}
	persister := WorkflowPersister{Store: store, File: workflow.FileStore{Root: t.TempDir()}, Lifecycle: func(lifecycleCtx context.Context, state *workflow.State) error {
		return store.MarkScheduledExecutionRunning(lifecycleCtx, execution.ID, task.ID, state.Run.ID, nil, "approval-owner", execution.AttemptCount)
	}}
	if err := persister.Save(ctx, state); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionPausedForApproval(ctx, execution.ID, "approval-owner", execution.AttemptCount); err != nil {
		t.Fatal(err)
	}
	var approvalID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT id FROM approvals WHERE request_id=$1`, stepID).Scan(&approvalID); err != nil {
		t.Fatal(err)
	}
	if err := store.DecideApproval(ctx, approvalID, "approved", "integration"); err != nil {
		t.Fatal(err)
	}
	var status domain.ScheduledExecutionStatus
	if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionPausedForApproval {
		t.Fatalf("approval implicitly resumed status=%s", status)
	}
	if err := store.RequestScheduledExecutionResume(ctx, execution.ID, "integration"); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionPending {
		t.Fatalf("explicit resume status=%s", status)
	}
	resumed, _, ok, err := store.ClaimPendingScheduledExecution(ctx, "approval-resume-owner", time.Minute)
	if err != nil || !ok || resumed.ID != execution.ID {
		t.Fatalf("resumed claim=%#v ok=%v err=%v", resumed, ok, err)
	}
	if resumed.AttemptCount != execution.AttemptCount+1 {
		t.Fatalf("resumed attempt=%d want=%d", resumed.AttemptCount, execution.AttemptCount+1)
	}
	differentTask := domain.Task{ID: domain.NewID(), ProgramID: programID, Objective: "different resume task", WorkflowDefinitionID: definitionID, Status: domain.TaskRunning, RequestedBy: "integration", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateTask(ctx, differentTask); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionRunning(ctx, resumed.ID, differentTask.ID, runID, nil, "approval-resume-owner", resumed.AttemptCount); err == nil {
		t.Fatal("resumed execution accepted a different task ID")
	}
	if err := store.MarkScheduledExecutionRunning(ctx, resumed.ID, task.ID, domain.NewID(), nil, "approval-resume-owner", resumed.AttemptCount); err == nil {
		t.Fatal("resumed execution accepted a different workflow run ID")
	}
	var persistedTaskID, persistedRunID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT status,task_id,workflow_run_id FROM scheduled_executions WHERE id=$1`, resumed.ID).Scan(&status, &persistedTaskID, &persistedRunID); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionClaimed || persistedTaskID != task.ID || persistedRunID != runID {
		t.Fatalf("rejected replacement changed lineage status=%s task=%s run=%s", status, persistedTaskID, persistedRunID)
	}
	state.Run.Status = domain.RunRunning
	resumedPersister := WorkflowPersister{Store: store, File: workflow.FileStore{Root: t.TempDir()}, Lifecycle: func(lifecycleCtx context.Context, state *workflow.State) error {
		return store.MarkScheduledExecutionRunning(lifecycleCtx, resumed.ID, task.ID, state.Run.ID, nil, "approval-resume-owner", resumed.AttemptCount)
	}}
	if err := resumedPersister.Save(ctx, state); err != nil {
		t.Fatalf("save resumed workflow lineage: %v", err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT status,task_id,workflow_run_id FROM scheduled_executions WHERE id=$1`, resumed.ID).Scan(&status, &persistedTaskID, &persistedRunID); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionRunning || persistedTaskID != task.ID || persistedRunID != runID {
		t.Fatalf("resumed lineage status=%s task=%s run=%s", status, persistedTaskID, persistedRunID)
	}
}

func createSchedulerIntegrationProgram(t *testing.T, ctx context.Context, store *Store, name string) (domain.ID, domain.ID) {
	t.Helper()
	now := time.Now().UTC()
	programID, definitionID := domain.NewID(), domain.NewID()
	program := domain.Program{ID: programID, Name: name + "-" + string(programID), Platform: "integration", ScopeReference: "synthetic://local", PolicyReference: "integration", ScopeDigest: "scope", IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: "plan", ScopePlanWarnings: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now}
	snapshot := domain.ScopeSnapshot{ScopeReference: program.ScopeReference, ScopeDigest: program.ScopeDigest, IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: program.TargetPlanDigest, PlanningWarnings: json.RawMessage(`[]`), TargetPlan: json.RawMessage(`{}`), CreatedAt: now}
	if err := store.CreateProgram(ctx, program, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateWorkflowDefinition(ctx, definitionID, name, "1", "synthetic", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	return programID, definitionID
}

func TestRepairProgramScopeReferencePreservesDigestsAndCurrentSnapshot(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	now := time.Now().UTC()
	programID := domain.NewID()
	program := domain.Program{
		ID: programID, Name: "scope-reference-" + string(programID), Platform: "integration",
		ScopeReference: "/scope/example.json", PolicyReference: "integration",
		ScopeDigest: "scope-digest", IncludeRuleDigests: []string{"include"}, ExcludeRuleDigests: []string{},
		TargetPlanDigest: "plan-digest", ScopePlanWarnings: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now,
	}
	snapshot := domain.ScopeSnapshot{
		ScopeReference: program.ScopeReference, ScopeDigest: program.ScopeDigest,
		IncludeRuleDigests: program.IncludeRuleDigests, ExcludeRuleDigests: program.ExcludeRuleDigests,
		TargetPlanDigest: program.TargetPlanDigest, PlanningWarnings: json.RawMessage(`[]`),
		TargetPlan: json.RawMessage(`{}`), CreatedAt: now,
	}
	if err := store.CreateProgram(ctx, program, snapshot); err != nil {
		t.Fatal(err)
	}

	const repaired = "scope/example.json"
	if err := store.RepairProgramScopeReference(ctx, programID, repaired, program.ScopeDigest, program.TargetPlanDigest, "integration"); err != nil {
		t.Fatal(err)
	}
	current, err := store.GetProgram(ctx, programID)
	if err != nil {
		t.Fatal(err)
	}
	if current.ScopeReference != repaired || current.ScopeDigest != program.ScopeDigest || current.TargetPlanDigest != program.TargetPlanDigest {
		t.Fatalf("repaired program = %#v", current)
	}
	var snapshotReference, snapshotScopeDigest, snapshotPlanDigest string
	if err := store.Pool.QueryRow(ctx, `SELECT scope_reference,scope_digest,target_plan_digest FROM scope_versions WHERE program_id=$1`, programID).Scan(&snapshotReference, &snapshotScopeDigest, &snapshotPlanDigest); err != nil {
		t.Fatal(err)
	}
	if snapshotReference != repaired || snapshotScopeDigest != program.ScopeDigest || snapshotPlanDigest != program.TargetPlanDigest {
		t.Fatalf("repaired snapshot reference=%q scope=%q plan=%q", snapshotReference, snapshotScopeDigest, snapshotPlanDigest)
	}
	var auditCount int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE program_id=$1 AND event_type='scope_reference_repaired'`, programID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("scope reference repair audit count = %d", auditCount)
	}

	if err := store.RepairProgramScopeReference(ctx, programID, "scope/other.json", "stale-scope-digest", program.TargetPlanDigest, "integration"); err == nil {
		t.Fatal("stale scope repair was accepted")
	}
	current, err = store.GetProgram(ctx, programID)
	if err != nil {
		t.Fatal(err)
	}
	if current.ScopeReference != repaired {
		t.Fatalf("stale repair changed reference to %q", current.ScopeReference)
	}
}

func schedulerIntegrationStore(t *testing.T) (*Store, context.Context) {
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
	schema := "scheduler_" + strings.ReplaceAll(string(domain.NewID()), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop integration schema: %v", err)
		}
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	store, err := Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return store, ctx
}

func createIntegrationSchedule(t *testing.T, ctx context.Context, store *Store, programID domain.ID, name string) domain.Schedule {
	t.Helper()
	now := time.Now().UTC()
	item := domain.Schedule{ID: domain.NewID(), ProgramID: programID, Name: name, WorkflowName: "continuous-web-recon", Objective: "integration " + name, CronExpression: "0 9 * * *", Timezone: "UTC", Enabled: true, CreatedBy: "integration", NextRunAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now}
	if err := store.CreateSchedule(ctx, item); err != nil {
		t.Fatal(err)
	}
	return item
}

func createIntegrationTask(t *testing.T, ctx context.Context, store *Store, programID, definitionID domain.ID, name string) domain.Task {
	t.Helper()
	now := time.Now().UTC()
	item := domain.Task{ID: domain.NewID(), ProgramID: programID, Objective: "integration " + name, WorkflowDefinitionID: definitionID, Status: domain.TaskRunning, RequestedBy: "integration", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateTask(ctx, item); err != nil {
		t.Fatal(err)
	}
	return item
}

func enqueueAndClaim(t *testing.T, ctx context.Context, store *Store, scheduleID domain.ID, owner string, lease time.Duration) domain.ScheduledExecution {
	t.Helper()
	item, err := store.EnqueueRunNow(ctx, scheduleID, "integration")
	if err != nil {
		t.Fatal(err)
	}
	claimed, _, ok, err := store.ClaimPendingScheduledExecution(ctx, owner, lease)
	if err != nil || !ok || claimed.ID != item.ID {
		t.Fatalf("claim = %#v ok=%v err=%v", claimed, ok, err)
	}
	return claimed
}

func saveIntegrationRun(ctx context.Context, store *Store, root string, executionID domain.ID, task domain.Task, definitionID, runID domain.ID, owner string, attempt int, now time.Time) error {
	state := &workflow.State{Run: domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "run_now", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{}}
	return (WorkflowPersister{Store: store, File: workflow.FileStore{Root: root}, Lifecycle: func(lifecycleCtx context.Context, state *workflow.State) error {
		return store.MarkScheduledExecutionRunning(lifecycleCtx, executionID, task.ID, state.Run.ID, nil, owner, attempt)
	}}).Save(ctx, state)
}
