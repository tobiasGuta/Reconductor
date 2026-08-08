package scheduler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/orchestration"
	"github.com/tobiasGuta/Reconductor/internal/workflows"
)

// ---------------------------------------------------------------------------
// recoveryIntegrationEnv – isolated program + schedule fixture
// ---------------------------------------------------------------------------

type recoveryIntegrationEnv struct {
	store      *database.Store
	ctx        context.Context
	programID  domain.ID
	scheduleID domain.ID
	root       string
}

func newRecoveryIntegrationEnv(t *testing.T, name string) recoveryIntegrationEnv {
	t.Helper()
	store, ctx := testDatabaseStore(t)
	now := time.Now().UTC()
	root := t.TempDir()

	absRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	absRepo, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve repo dir: %v", err)
	}
	if rel, relErr := filepath.Rel(absRepo, absRoot); relErr == nil && !strings.HasPrefix(rel, "..") {
		t.Fatalf("runtime root %s is inside the repository tree %s", absRoot, absRepo)
	}

	scopePath := filepath.Join(root, "scope.json")
	scopeJSON := `{"target":{"scope":{"exclude":[],"include":[{"enabled":true,"file":"^/.*","host":"^app\\.example\\.test$","port":"^443$","protocol":"https"}]}}}`
	if err := os.WriteFile(scopePath, []byte(scopeJSON), 0o600); err != nil {
		t.Fatalf("write scope.json: %v", err)
	}

	programID := domain.NewID()
	program := domain.Program{
		ID: programID, Name: "recovery-" + name, Platform: "integration",
		ScopeReference:     "scope.json",
		PolicyReference:    "integration",
		ScopeDigest:        "sha256:4217606229293ed61df52901c2eee1e6d27e389fd00586fef8b5225bb85a954a",
		IncludeRuleDigests: []string{},
		ExcludeRuleDigests: []string{},
		TargetPlanDigest:   "plan",
		ScopePlanWarnings:  json.RawMessage(`[]`),
		CreatedAt:          now, UpdatedAt: now,
	}
	snapshot := domain.ScopeSnapshot{
		ScopeReference:     program.ScopeReference,
		ScopeDigest:        program.ScopeDigest,
		IncludeRuleDigests: []string{},
		ExcludeRuleDigests: []string{},
		TargetPlanDigest:   program.TargetPlanDigest,
		PlanningWarnings:   json.RawMessage(`[]`),
		TargetPlan:         json.RawMessage(`{}`),
		CreatedAt:          now,
	}
	if err := store.CreateProgram(ctx, program, snapshot); err != nil {
		t.Fatalf("CreateProgram: %v", err)
	}

	// Register the workflow definition by running the setup workflow once.
	setupRegistry := capability.NewRegistry()
	setupExecute := func(ctx context.Context) (capability.Result, error) {
		return capability.Result{Action: domain.ActionResult{Output: json.RawMessage(`{"urls":[],"port_targets":[],"authorized_urls":[],"active_urls":[],"findings":[],"authorized_records":[],"lines":[],"scan_targets":[],"crawl_targets":[],"interesting_endpoints":[],"changes":[]}`)}}, nil
	}
	for _, capName := range allCaps() {
		setupRegistry.Register(&fakeProvider{name: capName, onExecute: setupExecute})
	}
	setupOrch := &orchestration.Service{Store: store, Registry: setupRegistry, Config: config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: root}, ArtifactStorage: config.ArtifactStorage{Root: root}}}
	if _, err := setupOrch.Run(ctx, orchestration.WorkflowRequest{ProgramID: programID, ScopeReference: "scope.json", WorkflowName: workflows.ContinuousName, AcknowledgeScopeExpansion: true}); err != nil {
		t.Fatalf("setup workflow run: %v", err)
	}

	scheduleID := domain.NewID()
	if err := store.CreateSchedule(ctx, domain.Schedule{ID: scheduleID, ProgramID: programID, Name: name, WorkflowName: workflows.ContinuousName, CronExpression: "*/5 * * * *", Enabled: true, NextRunAt: now, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("CreateSchedule: %v", err)
	}

	return recoveryIntegrationEnv{store: store, ctx: ctx, programID: programID, scheduleID: scheduleID, root: root}
}

func newRecoveryOrch(env recoveryIntegrationEnv, registry *capability.Registry) *orchestration.Service {
	return &orchestration.Service{Store: env.store, Registry: registry, Config: config.Config{Scope: config.Scope{Root: env.root}, Scheduler: config.Scheduler{WorkflowStateRoot: env.root}, ArtifactStorage: config.ArtifactStorage{Root: env.root}}}
}

func newRecoverySvc(env recoveryIntegrationEnv, orch *orchestration.Service, owner string) *Service {
	svc := New(env.store, orch, config.Scheduler{LeaseTimeout: 30 * time.Second, PollInterval: time.Hour})
	svc.Owner = owner
	return svc
}

// recoveryAuditCount counts audit_events rows for the given event_type whose
// JSONB details column carries the expected scheduled_execution_id.
func recoveryAuditCount(t *testing.T, env recoveryIntegrationEnv, execID domain.ID, event string) int {
	t.Helper()
	var n int
	if err := env.store.Pool.QueryRow(env.ctx,
		`SELECT count(*) FROM audit_events WHERE event_type=$1 AND details->>'scheduled_execution_id'=$2`,
		event, execID).Scan(&n); err != nil {
		t.Fatalf("recoveryAuditCount(%s): %v", event, err)
	}
	return n
}

// rowCount returns the number of rows in table for a WHERE id=$1 query.
func rowCount(t *testing.T, env recoveryIntegrationEnv, table string, id domain.ID) int {
	t.Helper()
	var n int
	if err := env.store.Pool.QueryRow(env.ctx,
		"SELECT count(*) FROM "+table+" WHERE id=$1", id).Scan(&n); err != nil {
		t.Fatalf("rowCount(%s,%s): %v", table, id, err)
	}
	return n
}

// programTaskCount returns the number of tasks rows that belong to env.programID.
// This is program-scoped to avoid cross-test interference when packages run
// concurrently against the same PostgreSQL database.
func programTaskCount(t *testing.T, env recoveryIntegrationEnv) int {
	t.Helper()
	var n int
	if err := env.store.Pool.QueryRow(env.ctx,
		`SELECT count(*) FROM tasks WHERE program_id=$1`,
		env.programID).Scan(&n); err != nil {
		t.Fatalf("programTaskCount: %v", err)
	}
	return n
}

// programRunCount returns the number of workflow_runs rows whose owning task
// belongs to env.programID.
func programRunCount(t *testing.T, env recoveryIntegrationEnv) int {
	t.Helper()
	var n int
	if err := env.store.Pool.QueryRow(env.ctx,
		`SELECT count(*) FROM workflow_runs wr JOIN tasks t ON t.id=wr.task_id WHERE t.program_id=$1`,
		env.programID).Scan(&n); err != nil {
		t.Fatalf("programRunCount: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// recoveryStoreWrapper – intercepts lifecycle callbacks and claim boundary
// ---------------------------------------------------------------------------

// recoveryStoreWrapper wraps *database.Store and records the attempt argument
// forwarded by scheduledExecutionLifecycle, and optionally installs a barrier
// at ClaimPendingScheduledExecution to make concurrent races deterministic.
type recoveryStoreWrapper struct {
	*database.Store

	// Lifecycle interception for Test 1.
	taskCreatedCalls  atomic.Int32
	runningCalls      atomic.Int32
	onMarkTaskCreated func(execID, taskID domain.ID, owner string, attempt int)
	onMarkRunning     func(execID, taskID, runID domain.ID, owner string, attempt int)

	// Claim barrier for Test 3. When claimBarrier is non-nil, each goroutine
	// that reaches ClaimPendingScheduledExecution sends to claimReady and then
	// blocks on claimGo before proceeding. This lets the test synchronize both
	// goroutines to the claim boundary before releasing them.
	claimBarrier *claimBarrierState
}

// claimBarrierState holds the coordination channels used by the claim barrier.
type claimBarrierState struct {
	ready chan struct{} // goroutine signals it has arrived
	go_   chan struct{} // test releases goroutine to proceed
}

func newClaimBarrier() *claimBarrierState {
	return &claimBarrierState{
		ready: make(chan struct{}, 2),
		go_:   make(chan struct{}),
	}
}

func (w *recoveryStoreWrapper) ClaimPendingScheduledExecution(ctx context.Context, owner string, timeout time.Duration) (domain.ScheduledExecution, domain.Schedule, bool, error) {
	if w.claimBarrier != nil {
		// Signal arrival; context-aware so a stuck goroutine doesn't block forever.
		select {
		case w.claimBarrier.ready <- struct{}{}:
		case <-ctx.Done():
			return domain.ScheduledExecution{}, domain.Schedule{}, false, ctx.Err()
		}
		// Wait for the test to release all goroutines simultaneously.
		select {
		case <-w.claimBarrier.go_:
		case <-ctx.Done():
			return domain.ScheduledExecution{}, domain.Schedule{}, false, ctx.Err()
		}
	}
	return w.Store.ClaimPendingScheduledExecution(ctx, owner, timeout)
}

func (w *recoveryStoreWrapper) MarkScheduledExecutionTaskCreated(ctx context.Context, execID, taskID domain.ID, owner string, attempt int) error {
	w.taskCreatedCalls.Add(1)
	if w.onMarkTaskCreated != nil {
		w.onMarkTaskCreated(execID, taskID, owner, attempt)
	}
	return w.Store.MarkScheduledExecutionTaskCreated(ctx, execID, taskID, owner, attempt)
}

func (w *recoveryStoreWrapper) MarkScheduledExecutionRunning(ctx context.Context, execID, taskID, runID domain.ID, scopeVersionID *domain.ID, owner string, attempt int) error {
	w.runningCalls.Add(1)
	if w.onMarkRunning != nil {
		w.onMarkRunning(execID, taskID, runID, owner, attempt)
	}
	return w.Store.MarkScheduledExecutionRunning(ctx, execID, taskID, runID, scopeVersionID, owner, attempt)
}

// Compile-time check: recoveryStoreWrapper must satisfy the scheduler.Store interface.
var _ Store = (*recoveryStoreWrapper)(nil)

// ---------------------------------------------------------------------------
// Test 1 – Scenario A: safe_no_lineage_claim → re-claim → complete
// ---------------------------------------------------------------------------

// TestServiceCrashRecoveryNoLineageReclaimsAndCompletes proves the complete
// scheduler.Service restart boundary for the only automatically reclaimable
// crash case (Scenario A / reasonCode: safe_no_lineage_claim).
//
// Crash fixture: Worker A called ClaimPendingScheduledExecution successfully
// (attempt_count=1, recovery_protocol_version=1, status='claimed') and then
// crashed before MarkScheduledExecutionTaskCreated committed. The durable state
// therefore has task_id IS NULL and workflow_run_id IS NULL.
//
// Service B's Dispatch calls ClaimPendingScheduledExecution which internally
// runs reconcileStaleScheduledExecutions. The reconciler classifies the stale
// row as Scenario A and resets it to pending. The same call then claims it again
// with attempt_count=2. Service B then completes the full workflow lifecycle.
func TestServiceCrashRecoveryNoLineageReclaimsAndCompletes(t *testing.T) {
	env := newRecoveryIntegrationEnv(t, "scenario-a-service")
	ctx := env.ctx

	// Snapshot baseline task/run counts (program-scoped) before the recovery dispatch.
	tasksBefore := programTaskCount(t, env)
	runsBefore := programRunCount(t, env)

	// Enqueue.
	original, err := env.store.EnqueueRunNow(ctx, env.scheduleID, "integration")
	if err != nil {
		t.Fatalf("EnqueueRunNow: %v", err)
	}

	// Claim as Worker A: sets attempt_count=1 and recovery_protocol_version=1.
	claimed, _, ok, err := env.store.ClaimPendingScheduledExecution(ctx, "worker-a", 30*time.Second)
	if err != nil || !ok || claimed.ID != original.ID {
		t.Fatalf("Worker A claim: ok=%v err=%v id=%s want=%s", ok, err, claimed.ID, original.ID)
	}
	if claimed.AttemptCount != 1 {
		t.Fatalf("Worker A attempt_count=%d want=1", claimed.AttemptCount)
	}

	// Simulate crash: expire the lease without starting any heartbeat goroutine.
	if _, err := env.store.Pool.Exec(ctx,
		`UPDATE scheduled_executions SET lease_expires_at=clock_timestamp()-make_interval(secs=>2) WHERE id=$1`,
		claimed.ID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	// Sanity-check the fixture.
	var fixtureStatus domain.ScheduledExecutionStatus
	var fixtureTaskID, fixtureRunID *domain.ID
	var fixtureProtocol int
	if err := env.store.Pool.QueryRow(ctx,
		`SELECT status,task_id,workflow_run_id,recovery_protocol_version FROM scheduled_executions WHERE id=$1`,
		claimed.ID).Scan(&fixtureStatus, &fixtureTaskID, &fixtureRunID, &fixtureProtocol); err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if fixtureStatus != domain.ScheduledExecutionClaimed || fixtureTaskID != nil || fixtureRunID != nil || fixtureProtocol != 1 {
		t.Fatalf("fixture wrong: status=%s task=%v run=%v protocol=%d", fixtureStatus, fixtureTaskID, fixtureRunID, fixtureProtocol)
	}

	// Instrumented registry.
	var providerCalls atomic.Int32
	fakeOutput := json.RawMessage(`{"urls":[],"port_targets":[],"authorized_urls":[],"active_urls":[],"findings":[],"authorized_records":[],"lines":[],"scan_targets":[],"crawl_targets":[],"interesting_endpoints":[],"changes":[]}`)
	registry := capability.NewRegistry()
	for _, capName := range allCaps() {
		cn := capName
		registry.Register(&fakeProvider{name: cn, onExecute: func(ctx context.Context) (capability.Result, error) {
			providerCalls.Add(1)
			return capability.Result{Action: domain.ActionResult{Output: fakeOutput}}, nil
		}})
	}

	// Intercept lifecycle callbacks: count invocations and capture attempt values.
	// taskCreatedAttempt/runningAttemptMin/Max are used to verify that every
	// invocation forwarded attempt=2. runningCalls may be >1 because the
	// WorkflowCreated lifecycle is fired on every workflow-state checkpoint (once
	// per step save); only the first call transitions claimed→running, subsequent
	// ones are idempotent at the DB level.
	var taskCreatedAttempt, runningAttemptMin, runningAttemptMax atomic.Int32
	runningAttemptMin.Store(int32(^uint32(0) >> 1)) // initialize to MaxInt32
	wrapper := &recoveryStoreWrapper{
		Store: env.store,
		onMarkTaskCreated: func(_, _ domain.ID, _ string, attempt int) {
			taskCreatedAttempt.Store(int32(attempt))
		},
		onMarkRunning: func(_, _, _ domain.ID, _ string, attempt int) {
			for {
				old := runningAttemptMin.Load()
				if int32(attempt) >= old || runningAttemptMin.CompareAndSwap(old, int32(attempt)) {
					break
				}
			}
			for {
				old := runningAttemptMax.Load()
				if int32(attempt) <= old || runningAttemptMax.CompareAndSwap(old, int32(attempt)) {
					break
				}
			}
		},
	}

	orch := newRecoveryOrch(env, registry)
	svc := newRecoverySvc(env, orch, "worker-b")
	svc.Store = wrapper

	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	if err := svc.Dispatch(testCtx); err != nil {
		t.Fatalf("Service B Dispatch: %v", err)
	}

	// Read the final state.
	var finalStatus domain.ScheduledExecutionStatus
	var finalAttempt int
	var finalTaskID, finalRunID *domain.ID
	if err := env.store.Pool.QueryRow(ctx,
		`SELECT status,attempt_count,task_id,workflow_run_id FROM scheduled_executions WHERE id=$1`,
		claimed.ID).Scan(&finalStatus, &finalAttempt, &finalTaskID, &finalRunID); err != nil {
		t.Fatalf("read final execution: %v", err)
	}

	// 1. Same execution ID (implicit: we query by claimed.ID throughout).

	// 2. attempt_count == 2.
	if finalAttempt != 2 {
		t.Errorf("attempt_count=%d want=2", finalAttempt)
	}

	// 3. scheduled execution status == completed.
	if finalStatus != domain.ScheduledExecutionCompleted {
		t.Errorf("execution status=%s want=completed", finalStatus)
	}

	// 4. +1 task: before/after total count increased by exactly one.
	if finalTaskID == nil {
		t.Fatal("task_id is nil after completion")
	}
	tasksAfter := programTaskCount(t, env)
	if tasksAfter != tasksBefore+1 {
		t.Errorf("tasks total (program-scoped): before=%d after=%d want before+1", tasksBefore, tasksAfter)
	}
	if rowCount(t, env, "tasks", *finalTaskID) != 1 {
		t.Errorf("task row count for id=%s want=1", *finalTaskID)
	}

	// 5. +1 workflow run: before/after program-scoped count increased by exactly one.
	if finalRunID == nil {
		t.Fatal("workflow_run_id is nil after completion")
	}
	runsAfter := programRunCount(t, env)
	if runsAfter != runsBefore+1 {
		t.Errorf("workflow_runs total (program-scoped): before=%d after=%d want before+1", runsBefore, runsAfter)
	}
	if rowCount(t, env, "workflow_runs", *finalRunID) != 1 {
		t.Errorf("workflow_run row count for id=%s want=1", *finalRunID)
	}

	// 6. provider executed at least once (workflow has multiple steps).
	if n := providerCalls.Load(); n < 1 {
		t.Errorf("provider calls=%d want>=1", n)
	}

	// 7. lifecycle callbacks:
	//    - TaskCreated: exactly one call with attempt=2.
	//    - Running: at least one call (fired once per workflow-state checkpoint;
	//      only the first transitions claimed→running, others are idempotent),
	//      and every call must forward attempt=2.
	if got := wrapper.taskCreatedCalls.Load(); got != 1 {
		t.Errorf("MarkScheduledExecutionTaskCreated call count=%d want=1", got)
	}
	if got := taskCreatedAttempt.Load(); got != 2 {
		t.Errorf("MarkScheduledExecutionTaskCreated attempt=%d want=2", got)
	}
	if got := wrapper.runningCalls.Load(); got < 1 {
		t.Errorf("MarkScheduledExecutionRunning call count=%d want>=1", got)
	}
	if min := runningAttemptMin.Load(); min != 2 {
		t.Errorf("MarkScheduledExecutionRunning min attempt=%d want=2 (all calls must use attempt 2)", min)
	}
	if max := runningAttemptMax.Load(); max != 2 {
		t.Errorf("MarkScheduledExecutionRunning max attempt=%d want=2 (all calls must use attempt 2)", max)
	}

	// 8. exactly one stale_claim_recovered audit.
	if n := recoveryAuditCount(t, env, claimed.ID, "scheduled_execution_stale_claim_recovered"); n != 1 {
		t.Errorf("stale_claim_recovered audit count=%d want=1", n)
	}

	// 9. exactly two scheduled_execution_claimed audits (Worker A + Worker B).
	if n := recoveryAuditCount(t, env, claimed.ID, "scheduled_execution_claimed"); n != 2 {
		t.Errorf("scheduled_execution_claimed audit count=%d want=2", n)
	}

	// 10. exactly one scheduled_execution_completed audit.
	if n := recoveryAuditCount(t, env, claimed.ID, "scheduled_execution_completed"); n != 1 {
		t.Errorf("scheduled_execution_completed audit count=%d want=1", n)
	}

	// 11. task status is completed (no duplicate terminal mutation).
	var taskStatus domain.TaskStatus
	if err := env.store.Pool.QueryRow(ctx, `SELECT status FROM tasks WHERE id=$1`, *finalTaskID).Scan(&taskStatus); err != nil {
		t.Fatalf("read task status: %v", err)
	}
	if taskStatus != domain.TaskCompleted {
		t.Errorf("task status=%s want=completed", taskStatus)
	}
}

// ---------------------------------------------------------------------------
// Test 2 – Scenario B: task_created_without_workflow → interrupted
// ---------------------------------------------------------------------------

// TestServiceCrashRecoveryTaskCreatedWithoutWorkflowInterrupts proves that once
// durable task lineage exists the reconciler permanently closes the execution
// rather than re-running uncertain work.
//
// Crash fixture: Worker A called ClaimPendingScheduledExecution (attempt_count=1,
// recovery_protocol_version=1) and committed MarkScheduledExecutionTaskCreated,
// then crashed before MarkScheduledExecutionRunning committed. The durable state
// has task_id IS SET and workflow_run_id IS NULL.
func TestServiceCrashRecoveryTaskCreatedWithoutWorkflowInterrupts(t *testing.T) {
	env := newRecoveryIntegrationEnv(t, "scenario-b-service")
	ctx := env.ctx

	// Enqueue.
	original, err := env.store.EnqueueRunNow(ctx, env.scheduleID, "integration")
	if err != nil {
		t.Fatalf("EnqueueRunNow: %v", err)
	}

	// Claim as Worker A.
	claimed, _, ok, err := env.store.ClaimPendingScheduledExecution(ctx, "worker-a", 30*time.Second)
	if err != nil || !ok || claimed.ID != original.ID {
		t.Fatalf("Worker A claim: ok=%v err=%v", ok, err)
	}

	// Reproduce the production path: Worker A called CreateTaskWithLifecycle which
	// atomically creates the task row and links it to the scheduled execution via
	// the lifecycle callback (MarkScheduledExecutionTaskCreated). We replicate this
	// exactly so the FK on scheduled_executions.task_id is satisfied.
	var wfDefID domain.ID
	if err := env.store.Pool.QueryRow(ctx, `SELECT id FROM workflow_definitions WHERE name=$1 LIMIT 1`, workflows.ContinuousName).Scan(&wfDefID); err != nil {
		t.Fatalf("query workflow definition ID: %v", err)
	}
	now := time.Now().UTC()
	crashTask := domain.Task{
		ID:                   domain.NewID(),
		ProgramID:            env.programID,
		Objective:            "crash-fixture",
		WorkflowDefinitionID: wfDefID,
		Status:               domain.TaskRunning,
		RequestedBy:          "worker-a",
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := env.store.CreateTaskWithLifecycle(ctx, crashTask, func(lCtx context.Context, t domain.Task) error {
		return env.store.MarkScheduledExecutionTaskCreated(lCtx, claimed.ID, t.ID, "worker-a", claimed.AttemptCount)
	}); err != nil {
		t.Fatalf("CreateTaskWithLifecycle (crash fixture): %v", err)
	}
	crashTaskID := crashTask.ID

	// Expire the lease.
	if _, err := env.store.Pool.Exec(ctx,
		`UPDATE scheduled_executions SET lease_expires_at=clock_timestamp()-make_interval(secs=>2) WHERE id=$1`,
		claimed.ID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	// Sanity-check the fixture.
	var fixtureStatus domain.ScheduledExecutionStatus
	var fixtureLinkedTask domain.ID
	var fixtureRunID *domain.ID
	if err := env.store.Pool.QueryRow(ctx,
		`SELECT status,task_id,workflow_run_id FROM scheduled_executions WHERE id=$1`,
		claimed.ID).Scan(&fixtureStatus, &fixtureLinkedTask, &fixtureRunID); err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if fixtureStatus != domain.ScheduledExecutionClaimed || fixtureLinkedTask == "" || fixtureRunID != nil {
		t.Fatalf("fixture wrong: status=%s task=%s run=%v", fixtureStatus, fixtureLinkedTask, fixtureRunID)
	}

	// Service B.
	var providerCalls atomic.Int32
	registry := capability.NewRegistry()
	fakeOutput := json.RawMessage(`{"urls":[],"port_targets":[],"authorized_urls":[],"active_urls":[],"findings":[],"authorized_records":[],"lines":[],"scan_targets":[],"crawl_targets":[],"interesting_endpoints":[],"changes":[]}`)
	for _, capName := range allCaps() {
		cn := capName
		registry.Register(&fakeProvider{name: cn, onExecute: func(ctx context.Context) (capability.Result, error) {
			providerCalls.Add(1)
			return capability.Result{Action: domain.ActionResult{Output: fakeOutput}}, nil
		}})
	}

	orch := newRecoveryOrch(env, registry)
	svc := newRecoverySvc(env, orch, "worker-b")

	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	// First Dispatch: reconciler closes the execution as Scenario B.
	if err := svc.Dispatch(testCtx); err != nil {
		t.Fatalf("Service B first Dispatch: %v", err)
	}

	// 1. execution status == interrupted.
	var execStatus domain.ScheduledExecutionStatus
	var execAttempt int
	var execClass string
	var execTaskID, execRunID *domain.ID
	if err := env.store.Pool.QueryRow(ctx,
		`SELECT status,attempt_count,error_classification,task_id,workflow_run_id FROM scheduled_executions WHERE id=$1`,
		claimed.ID).Scan(&execStatus, &execAttempt, &execClass, &execTaskID, &execRunID); err != nil {
		t.Fatalf("read execution: %v", err)
	}
	if execStatus != domain.ScheduledExecutionInterrupted {
		t.Errorf("execution status=%s want=interrupted", execStatus)
	}

	// 2. attempt_count remains 1.
	if execAttempt != 1 {
		t.Errorf("attempt_count=%d want=1", execAttempt)
	}

	// 3. error_classification == "interrupted".
	if execClass != "interrupted" {
		t.Errorf("error_classification=%q want=interrupted", execClass)
	}

	// 4. task status == failed.
	var taskStatus domain.TaskStatus
	if err := env.store.Pool.QueryRow(ctx, `SELECT status FROM tasks WHERE id=$1`, crashTaskID).Scan(&taskStatus); err != nil {
		t.Fatalf("read task: %v", err)
	}
	if taskStatus != domain.TaskFailed {
		t.Errorf("task status=%s want=failed", taskStatus)
	}

	// 5. no workflow run exists for the crash task.
	var runCount int
	if err := env.store.Pool.QueryRow(ctx, `SELECT count(*) FROM workflow_runs WHERE task_id=$1`, crashTaskID).Scan(&runCount); err != nil {
		t.Fatalf("count workflow_runs: %v", err)
	}
	if runCount != 0 {
		t.Errorf("workflow_run count=%d want=0", runCount)
	}
	if execRunID != nil {
		t.Errorf("execution workflow_run_id=%s want=nil", *execRunID)
	}

	// 6. provider was never invoked.
	if n := providerCalls.Load(); n != 0 {
		t.Errorf("provider calls=%d want=0", n)
	}

	// 7. exactly one lineage_interrupted audit.
	if n := recoveryAuditCount(t, env, claimed.ID, "scheduled_execution_lineage_interrupted"); n != 1 {
		t.Errorf("lineage_interrupted audit count=%d want=1", n)
	}

	// 8. exactly one scheduled_task_reconciled audit for the crash task.
	var taskReconcile int
	if err := env.store.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE event_type='scheduled_task_reconciled' AND task_id=$1`,
		crashTaskID).Scan(&taskReconcile); err != nil {
		t.Fatalf("count scheduled_task_reconciled: %v", err)
	}
	if taskReconcile != 1 {
		t.Errorf("scheduled_task_reconciled count=%d want=1", taskReconcile)
	}

	// 9. Second Dispatch is idempotent: snapshot program-scoped counts before,
	//    verify zero increase after.
	tasksBeforeSecond := programTaskCount(t, env)
	runsBeforeSecond := programRunCount(t, env)

	if err := svc.Dispatch(testCtx); err != nil {
		t.Fatalf("Service B second Dispatch: %v", err)
	}

	// Zero additional tasks or runs created (program-scoped).
	if after := programTaskCount(t, env); after != tasksBeforeSecond {
		t.Errorf("tasks total (program-scoped) after second dispatch: before=%d after=%d want no change", tasksBeforeSecond, after)
	}
	if after := programRunCount(t, env); after != runsBeforeSecond {
		t.Errorf("workflow_runs total (program-scoped) after second dispatch: before=%d after=%d want no change", runsBeforeSecond, after)
	}
	// The specific crash task row still exists exactly once.
	if rowCount(t, env, "tasks", crashTaskID) != 1 {
		t.Errorf("crash task row count want=1")
	}
	// Provider was never called.
	if n := providerCalls.Load(); n != 0 {
		t.Errorf("provider calls after second dispatch=%d want=0", n)
	}
	// Audit count is still exactly one (not duplicated).
	if n := recoveryAuditCount(t, env, claimed.ID, "scheduled_execution_lineage_interrupted"); n != 1 {
		t.Errorf("lineage_interrupted audit count after second dispatch=%d want=1 (idempotent)", n)
	}
	// attempt_count unchanged.
	var attemptAfter int
	if err := env.store.Pool.QueryRow(ctx, `SELECT attempt_count FROM scheduled_executions WHERE id=$1`, claimed.ID).Scan(&attemptAfter); err != nil {
		t.Fatalf("read attempt_count after second dispatch: %v", err)
	}
	if attemptAfter != 1 {
		t.Errorf("attempt_count after second dispatch=%d want=1", attemptAfter)
	}
}

// ---------------------------------------------------------------------------
// Test 3 – Two concurrent Services claim exactly one execution
// ---------------------------------------------------------------------------

// TestConcurrentServicesClaimPendingExecutionOnce verifies that two concurrent
// scheduler.Service instances racing to Dispatch against the same pending
// execution result in exactly one completed execution with no duplicate lineage.
//
// The race is made deterministic by installing a claim barrier on the Store
// interface so both goroutines reach ClaimPendingScheduledExecution
// simultaneously before either is allowed to proceed.
func TestConcurrentServicesClaimPendingExecutionOnce(t *testing.T) {
	env := newRecoveryIntegrationEnv(t, "concurrent-claim")
	ctx := env.ctx

	// Snapshot baseline counts (program-scoped) before the concurrent dispatch.
	tasksBefore := programTaskCount(t, env)
	runsBefore := programRunCount(t, env)

	original, err := env.store.EnqueueRunNow(ctx, env.scheduleID, "integration")
	if err != nil {
		t.Fatalf("EnqueueRunNow: %v", err)
	}

	var providerCalls atomic.Int32
	fakeOutput := json.RawMessage(`{"urls":[],"port_targets":[],"authorized_urls":[],"active_urls":[],"findings":[],"authorized_records":[],"lines":[],"scan_targets":[],"crawl_targets":[],"interesting_endpoints":[],"changes":[]}`)

	// barrier: both goroutines arrive, then both are released simultaneously.
	barrier := newClaimBarrier()

	makeWrappedSvc := func(owner string) *Service {
		r := capability.NewRegistry()
		for _, capName := range allCaps() {
			cn := capName
			r.Register(&fakeProvider{name: cn, onExecute: func(ctx context.Context) (capability.Result, error) {
				providerCalls.Add(1)
				return capability.Result{Action: domain.ActionResult{Output: fakeOutput}}, nil
			}})
		}
		orch := newRecoveryOrch(env, r)
		w := &recoveryStoreWrapper{Store: env.store, claimBarrier: barrier}
		svc := newRecoverySvc(env, orch, owner)
		svc.Store = w
		return svc
	}

	svc1 := makeWrappedSvc("worker-concurrent-1")
	svc2 := makeWrappedSvc("worker-concurrent-2")

	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, svc := range []*Service{svc1, svc2} {
		svc := svc
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := svc.Dispatch(testCtx); err != nil {
				errs <- err
			}
		}()
	}

	// Wait for both goroutines to arrive at ClaimPendingScheduledExecution, then
	// release them simultaneously. Use select+testCtx.Done() so a regression
	// cannot leave the test blocked indefinitely.
	for i := 0; i < 2; i++ {
		select {
		case <-barrier.ready:
		case <-testCtx.Done():
			t.Fatalf("timed out waiting for goroutine %d to reach claim barrier: %v", i+1, testCtx.Err())
		}
	}
	close(barrier.go_)

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("Dispatch error: %v", err)
	}

	// Read final state.
	var execStatus domain.ScheduledExecutionStatus
	var execAttempt int
	var execTaskID, execRunID *domain.ID
	if err := env.store.Pool.QueryRow(ctx,
		`SELECT status,attempt_count,task_id,workflow_run_id FROM scheduled_executions WHERE id=$1`,
		original.ID).Scan(&execStatus, &execAttempt, &execTaskID, &execRunID); err != nil {
		t.Fatalf("read execution: %v", err)
	}

	// 1. Execution must complete (not just any terminal state).
	if execStatus != domain.ScheduledExecutionCompleted {
		t.Errorf("execution status=%s want=completed", execStatus)
	}

	// 2. attempt_count == 1: only one claim succeeded.
	if execAttempt != 1 {
		t.Errorf("attempt_count=%d want=1", execAttempt)
	}

	// 3. +1 task (before/after).
	if execTaskID == nil {
		t.Fatal("task_id is nil after concurrent dispatch")
	}
	tasksAfter := programTaskCount(t, env)
	if tasksAfter != tasksBefore+1 {
		t.Errorf("tasks total (program-scoped): before=%d after=%d want before+1", tasksBefore, tasksAfter)
	}
	if rowCount(t, env, "tasks", *execTaskID) != 1 {
		t.Errorf("task row count for id=%s want=1", *execTaskID)
	}

	// 4. +1 workflow run (before/after, program-scoped).
	if execRunID == nil {
		t.Fatal("workflow_run_id is nil after concurrent dispatch")
	}
	runsAfter := programRunCount(t, env)
	if runsAfter != runsBefore+1 {
		t.Errorf("workflow_runs total (program-scoped): before=%d after=%d want before+1", runsBefore, runsAfter)
	}
	if rowCount(t, env, "workflow_runs", *execRunID) != 1 {
		t.Errorf("workflow_run row count for id=%s want=1", *execRunID)
	}

	// 5. one claim audit.
	if n := recoveryAuditCount(t, env, original.ID, "scheduled_execution_claimed"); n != 1 {
		t.Errorf("scheduled_execution_claimed audit count=%d want=1", n)
	}

	// 6. one task-link audit.
	var linkCount int
	if err := env.store.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE event_type='scheduled_execution_task_linked' AND details->>'scheduled_execution_id'=$1`,
		original.ID).Scan(&linkCount); err != nil {
		t.Fatalf("count task_linked audits: %v", err)
	}
	if linkCount != 1 {
		t.Errorf("scheduled_execution_task_linked audit count=%d want=1", linkCount)
	}

	// 7. provider was called at least once (workflow has multiple steps).
	if n := providerCalls.Load(); n < 1 {
		t.Errorf("provider calls=%d want>=1", n)
	}
}
