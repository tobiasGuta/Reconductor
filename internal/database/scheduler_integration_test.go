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
			return store.MarkScheduledExecutionRunning(lifecycleCtx, execution.ID, task.ID, state.Run.ID, nil, "owner-a")
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
	if err := store.MarkScheduledExecutionCompleted(ctx, execution.ID, "owner-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionRunning(ctx, execution.ID, task.ID, runID, nil, "owner-a"); err == nil {
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
		return store.MarkScheduledExecutionRunning(lifecycleCtx, rejectedExecution.ID, rejectedTask.ID, state.Run.ID, nil, "owner-b")
	}}
	if err := rejectedPersister.Save(ctx, rejectedState); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionPausedForApproval(ctx, rejectedExecution.ID, "owner-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `UPDATE approvals SET decision='rejected',decided_by='integration',decided_at=now() WHERE request_id=$1`, rejectedStepID); err != nil {
		t.Fatal(err)
	}
	if err := store.RequestScheduledExecutionResume(ctx, rejectedExecution.ID, "integration"); !errors.Is(err, ErrApprovalRejected) {
		t.Fatalf("rejected resume error = %v", err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, rejectedExecution.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != domain.ScheduledExecutionApprovalRejected {
		t.Fatalf("rejected execution status = %s", status)
	}

	cancelledSchedule := createIntegrationSchedule(t, ctx, store, programID, "cancelled")
	cancelledExecution := enqueueAndClaim(t, ctx, store, cancelledSchedule.ID, "owner-c", time.Minute)
	cancelledTask := createIntegrationTask(t, ctx, store, programID, definitionID, "cancelled")
	cancelledRun := domain.NewID()
	if err := saveIntegrationRun(ctx, store, t.TempDir(), cancelledExecution.ID, cancelledTask, definitionID, cancelledRun, "owner-c", now); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionCancelled(ctx, cancelledExecution.ID, "owner-c"); err != nil {
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
	if err := saveIntegrationRun(ctx, store, t.TempDir(), operatorExecution.ID, operatorTask, definitionID, domain.NewID(), "owner-pause", now); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionPaused(ctx, operatorExecution.ID, "owner-pause"); err != nil {
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
	if err := store.MarkScheduledExecutionFailed(ctx, resumed.ID, "owner-resume", "test", "cleanup"); err != nil {
		t.Fatal(err)
	}

	blockedSchedule := createIntegrationSchedule(t, ctx, store, programID, "scope-blocked")
	blockedExecution := enqueueAndClaim(t, ctx, store, blockedSchedule.ID, "owner-blocked", time.Minute)
	var scopeVersionID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT id FROM scope_versions WHERE program_id=$1 ORDER BY created_at DESC LIMIT 1`, programID).Scan(&scopeVersionID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkScheduledExecutionBlocked(ctx, blockedExecution.ID, scopeVersionID, "owner-blocked"); err != nil {
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
	if err := store.MarkScheduledExecutionFailed(ctx, reclaimed.ID, "new-owner", "test", "cleanup"); err != nil {
		t.Fatal(err)
	}

	interruptedSchedule := createIntegrationSchedule(t, ctx, store, programID, "interrupted")
	interruptedExecution := enqueueAndClaim(t, ctx, store, interruptedSchedule.ID, "old-owner", -time.Second)
	interruptedTask := createIntegrationTask(t, ctx, store, programID, definitionID, "interrupted")
	interruptedRun := domain.NewID()
	if err := saveIntegrationRun(ctx, store, t.TempDir(), interruptedExecution.ID, interruptedTask, definitionID, interruptedRun, "old-owner", now); err != nil {
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
		if err := store.MarkScheduledExecutionRunning(lifecycleCtx, execution.ID, task.ID, state.Run.ID, nil, "atomic-owner"); err != nil {
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

func saveIntegrationRun(ctx context.Context, store *Store, root string, executionID domain.ID, task domain.Task, definitionID, runID domain.ID, owner string, now time.Time) error {
	state := &workflow.State{Run: domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "run_now", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{}}
	return (WorkflowPersister{Store: store, File: workflow.FileStore{Root: root}, Lifecycle: func(lifecycleCtx context.Context, state *workflow.State) error {
		return store.MarkScheduledExecutionRunning(lifecycleCtx, executionID, task.ID, state.Run.ID, nil, owner)
	}}).Save(ctx, state)
}
