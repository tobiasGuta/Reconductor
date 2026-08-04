package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/orchestration"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/workflows"
)

func testDatabaseStore(t *testing.T) (*database.Store, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open admin database pool: %v", err)
	}
	t.Cleanup(admin.Close)
	schema := "scheduler_" + strings.ReplaceAll(string(domain.NewID()), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatalf("create isolated test schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Error(err)
		}
	})

	poolURL := databaseURL
	if strings.Contains(poolURL, "?") {
		poolURL += "&search_path=" + schema
	} else {
		poolURL += "?search_path=" + schema
	}

	store, err := database.Open(ctx, poolURL)
	if err != nil {
		t.Fatalf("open isolated database store: %v", err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("migrate isolated test schema: %v", err)
	}
	return store, ctx
}

type fakeProvider struct {
	name      string
	onExecute func(ctx context.Context) (capability.Result, error)
	risk      policy.Risk
	approval  bool
}

func (p *fakeProvider) Validate(ctx context.Context, req capability.Request) error {
	return nil
}

func (p *fakeProvider) Execute(ctx context.Context, req capability.Request) (capability.Result, error) {
	if p.onExecute != nil {
		return p.onExecute(ctx)
	}
	return capability.Result{}, nil
}
func (p *fakeProvider) Manifest() capability.Manifest {
	r := p.risk
	if r == "" {
		r = policy.Passive
	}
	return capability.Manifest{Name: p.name, Version: "1", Risk: r, ApprovalRequired: p.approval}
}

// Required wrapper to test heartbeat explicit joining without exposing it to the API
type storeWrapper struct {
	*database.Store
	heartbeatWg     sync.WaitGroup
	heartbeatActive atomic.Int32
	heartbeatCalls  atomic.Int32
	onHeartbeat     func(ctx context.Context, id domain.ID, owner string, attempt int, timeout time.Duration) error
	onMarkCompleted func(ctx context.Context, id domain.ID, owner string, attempt int) error
}

func (s *storeWrapper) HeartbeatScheduledExecution(ctx context.Context, id domain.ID, owner string, attempt int, timeout time.Duration) error {
	s.heartbeatWg.Add(1)
	s.heartbeatActive.Add(1)
	s.heartbeatCalls.Add(1)
	defer s.heartbeatActive.Add(-1)
	defer s.heartbeatWg.Done()
	if s.onHeartbeat != nil {
		return s.onHeartbeat(ctx, id, owner, attempt, timeout)
	}
	return s.Store.HeartbeatScheduledExecution(ctx, id, owner, attempt, timeout)
}
func (s *storeWrapper) MarkScheduledExecutionCompleted(ctx context.Context, id domain.ID, owner string, attempt int) error {
	if s.onMarkCompleted != nil {
		return s.onMarkCompleted(ctx, id, owner, attempt)
	}
	return s.Store.MarkScheduledExecutionCompleted(ctx, id, owner, attempt)
}

// allCaps returns the complete set of capabilities required by the ContinuousWebRecon
// workflow for any scope configuration, including those only used when discovery roots
// are present. All entries must be registered before calling orch.Run or Dispatch to
// prevent workflow.Validate from rejecting an unknown capability.
func allCaps() []string {
	return []string{
		"targeting.prepare",
		"discover.subdomains",
		"discover.archive_urls",
		"resolve.dns",
		"scan.ports",
		"scan.nuclei",
		"scan.ffuf",
		"crawl.urls",
		"crawl.web",
		"scan.wpscan",
		"take.screenshot",
		"report.brief",
		"classify.endpoint",
		"report.changes",
		"probe.http",
		"compare.assets",
	}
}

func TestHeartbeatOwnershipLossAll(t *testing.T) {
	store, ctx := testDatabaseStore(t)
	now := time.Now().UTC()
	root := t.TempDir()

	// Verify the runtime root is not inside the repository tree using real path
	// containment rather than substring matching (which would falsely reject paths
	// whose username or OS temp directory contains words like "internal").
	absRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("cannot resolve temp dir: %v", err)
	}
	absRepo, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("cannot resolve repo dir: %v", err)
	}
	rel, relErr := filepath.Rel(absRepo, absRoot)
	if relErr == nil && !strings.HasPrefix(rel, "..") {
		t.Fatalf("runtime root %s is inside the repository tree %s", absRoot, absRepo)
	}

	scopePath := filepath.Join(root, "scope.json")
	scopeJSON := `{"target":{"scope":{"exclude":[],"include":[{"enabled":true,"file":"^/.*","host":"^app\\.example\\.test$","port":"^443$","protocol":"https"}]}}}`
	if err := os.WriteFile(scopePath, []byte(scopeJSON), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	programID := domain.NewID()
	program := domain.Program{
		ID: programID, Name: "test", Platform: "integration",
		ScopeReference: "scope.json", PolicyReference: "integration",
		ScopeDigest: "sha256:4217606229293ed61df52901c2eee1e6d27e389fd00586fef8b5225bb85a954a", IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{},
		TargetPlanDigest: "plan", ScopePlanWarnings: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now,
	}
	snapshot := domain.ScopeSnapshot{ScopeReference: program.ScopeReference, ScopeDigest: program.ScopeDigest, IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: program.TargetPlanDigest, PlanningWarnings: json.RawMessage(`[]`), TargetPlan: json.RawMessage(`{}`), CreatedAt: now}
	if err := store.CreateProgram(ctx, program, snapshot); err != nil {
		t.Fatalf("CreateProgram failed: %v", err)
	}

	setupRegistry := capability.NewRegistry()
	setupExecute := func(ctx context.Context) (capability.Result, error) {
		return capability.Result{Action: domain.ActionResult{Output: json.RawMessage(`{"urls":[],"port_targets":[],"authorized_urls":[],"active_urls":[],"findings":[],"authorized_records":[],"lines":[],"scan_targets":[],"crawl_targets":[],"interesting_endpoints":[],"changes":[]}`)}}, nil
	}
	for _, capName := range allCaps() {
		setupRegistry.Register(&fakeProvider{name: capName, onExecute: setupExecute})
	}

	setupOrch := &orchestration.Service{Store: store, Registry: setupRegistry, Config: config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: root}, ArtifactStorage: config.ArtifactStorage{Root: root}}}
	if _, err := setupOrch.Run(ctx, orchestration.WorkflowRequest{ProgramID: programID, ScopeReference: "scope.json", WorkflowName: workflows.ContinuousName, AcknowledgeScopeExpansion: true}); err != nil {
		t.Fatalf("setup workflow run failed: %v", err)
	}

	runCase := func(name string, f func(t *testing.T, scheduleID domain.ID)) {
		t.Run(name, func(t *testing.T) {
			scheduleID := domain.NewID()
			if err := store.CreateSchedule(ctx, domain.Schedule{ID: scheduleID, ProgramID: programID, Name: name, WorkflowName: workflows.ContinuousName, CronExpression: "*/5 * * * *", Enabled: true, NextRunAt: now, CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatalf("CreateSchedule failed: %v", err)
			}
			f(t, scheduleID)
		})
	}

	// 1, 2, 3, 4, 5
	runCase("1_5_OwnershipLossCancelsProvider", func(t *testing.T, scheduleID domain.ID) {
		_, err := store.EnqueueRunNow(ctx, scheduleID, "integration")
		if err != nil {
			t.Fatalf("EnqueueRunNow failed: %v", err)
		}
		registry := capability.NewRegistry()
		ready := make(chan struct{})
		cancelObserved := make(chan struct{})
		fakeExecute := func(ctx context.Context) (capability.Result, error) {
			close(ready)
			<-ctx.Done()
			close(cancelObserved)
			return capability.Result{}, ctx.Err()
		}

		for _, capName := range allCaps() {
			registry.Register(&fakeProvider{name: capName, onExecute: fakeExecute})
		}
		orch := &orchestration.Service{Store: store, Registry: registry, Config: config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: root}, ArtifactStorage: config.ArtifactStorage{Root: root}}}
		svc := New(store, orch, config.Scheduler{LeaseTimeout: 1 * time.Second, PollInterval: time.Minute})
		svc.Owner = "test-owner"

		errs := make(chan error, 1)
		go func() { errs <- svc.Dispatch(ctx) }()
		<-ready
		var actualID domain.ID
		if err := store.Pool.QueryRow(ctx, `SELECT id FROM scheduled_executions WHERE schedule_id=$1 LIMIT 1`, scheduleID).Scan(&actualID); err != nil {
			t.Fatalf("failed to find claimed execution: %v", err)
		}
		if _, err := store.Pool.Exec(ctx, `UPDATE scheduled_executions SET lease_expires_at = clock_timestamp() - interval '1 second', lease_owner = 'stale-owner' WHERE id = $1`, actualID); err != nil {
			t.Fatalf("Update failed: %v", err)
		}
		<-cancelObserved

		dispatchErr := <-errs
		if !errors.Is(dispatchErr, database.ErrLostScheduledExecutionLease) {
			t.Fatalf("expected ErrLostScheduledExecutionLease, got: %v", dispatchErr)
		}
		var seStatus domain.ScheduledExecutionStatus

		if err := store.Pool.QueryRow(
			ctx,
			`SELECT status
	 FROM scheduled_executions
	 WHERE id=$1`,
			actualID,
		).Scan(&seStatus); err != nil {
			t.Fatalf("query scheduled execution status after lease loss: %v", err)
		}

		if seStatus == domain.ScheduledExecutionCancelled ||
			seStatus == domain.ScheduledExecutionFailed ||
			seStatus == domain.ScheduledExecutionCompleted {
			t.Fatalf("scheduled execution mutated to %s", seStatus)
		}

		var wfStatus domain.RunStatus

		if err := store.Pool.QueryRow(
			ctx,
			`SELECT wr.status
	 FROM workflow_runs wr
	 JOIN scheduled_executions se ON se.workflow_run_id = wr.id
	 WHERE se.id=$1`,
			actualID,
		).Scan(&wfStatus); err != nil {
			t.Fatalf("query workflow status after lease loss: %v", err)
		}

		if wfStatus == domain.RunCompleted ||
			wfStatus == domain.RunFailed ||
			wfStatus == domain.RunCancelled {
			t.Fatalf("workflow run illegally finalized to %s", wfStatus)
		}
	})

	// 6. Provider-result persistence racing with heartbeat loss cannot bypass result fencing.
	runCase("6_RacingPersistenceCannotBypassFencing", func(t *testing.T, scheduleID domain.ID) {
		execution, err := store.EnqueueRunNow(ctx, scheduleID, "integration")
		if err != nil {
			t.Fatalf("EnqueueRunNow failed: %v", err)
		}
		registry := capability.NewRegistry()
		providerDBErr := make(chan error, 1)
		fakeExecute := func(ctx context.Context) (capability.Result, error) {
			// Manually expire lease just as provider completes, before execution.Service persists result
			if _, err := store.Pool.Exec(context.Background(), `UPDATE scheduled_executions SET lease_expires_at = clock_timestamp() - interval '1 second', lease_owner = 'stale-owner' WHERE id = $1`, execution.ID); err != nil {
				providerDBErr <- err
				return capability.Result{}, err
			}
			return capability.Result{Action: domain.ActionResult{Output: json.RawMessage(`{"urls":[],"port_targets":[],"authorized_urls":[],"active_urls":[],"findings":[],"authorized_records":[],"lines":[],"scan_targets":[],"crawl_targets":[],"interesting_endpoints":[],"changes":[]}`)}}, nil
		}
		for _, capName := range allCaps() {
			registry.Register(&fakeProvider{name: capName, onExecute: fakeExecute})
		}
		orch := &orchestration.Service{Store: store, Registry: registry, Config: config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: root}, ArtifactStorage: config.ArtifactStorage{Root: root}}}
		svc := New(store, orch, config.Scheduler{LeaseTimeout: 10 * time.Second, PollInterval: time.Minute})
		svc.Owner = "test-owner"
		err = svc.Dispatch(ctx)
		select {
		case dbErr := <-providerDBErr:
			t.Fatalf("expire lease during provider completion: %v", dbErr)
		default:
		}
		if !errors.Is(err, database.ErrLostScheduledExecutionLease) {
			t.Fatalf("expected ErrLostScheduledExecutionLease, got: %v", err)
		}
	})

	// 7. Provider completion immediately before ownership loss resolves safely.
	runCase("7_ProviderCompletionBeforeOwnershipLoss", func(t *testing.T, scheduleID domain.ID) {
		_, err := store.EnqueueRunNow(ctx, scheduleID, "integration")
		if err != nil {
			t.Fatalf("EnqueueRunNow failed: %v", err)
		}
		registry := capability.NewRegistry()
		fakeExecute := func(ctx context.Context) (capability.Result, error) {
			return capability.Result{Action: domain.ActionResult{Output: json.RawMessage(`{"urls":[],"port_targets":[],"authorized_urls":[],"active_urls":[],"findings":[],"authorized_records":[],"lines":[],"scan_targets":[],"crawl_targets":[],"interesting_endpoints":[],"changes":[]}`)}}, nil
		}
		for _, capName := range allCaps() {
			registry.Register(&fakeProvider{name: capName, onExecute: fakeExecute})
		}

		wrapper := &storeWrapper{Store: store}
		wrapper.onMarkCompleted = func(ctx context.Context, id domain.ID, owner string, attempt int) error {
			// Simulate ownership loss right before completion is marked
			if _, err := store.Pool.Exec(context.Background(), `UPDATE scheduled_executions SET lease_expires_at = clock_timestamp() - interval '1 second', lease_owner = 'stale-owner' WHERE id = $1`, id); err != nil {
				return fmt.Errorf("expire lease before completion fence: %w", err)
			}
			return store.MarkScheduledExecutionCompleted(ctx, id, owner, attempt)
		}

		orch := &orchestration.Service{Store: store, Registry: registry, Config: config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: root}, ArtifactStorage: config.ArtifactStorage{Root: root}}}
		svc := New(store, orch, config.Scheduler{LeaseTimeout: 10 * time.Second, PollInterval: time.Minute})
		svc.Owner = "test-owner"
		svc.Store = wrapper

		err = svc.Dispatch(ctx)
		if err == nil || !strings.Contains(err.Error(), "cannot transition") {
			t.Fatalf("expected transition error due to DB fence, got: %v", err)
		}
	})

	// 8. Ownership loss immediately before provider completion resolves safely.
	runCase("8_OwnershipLossBeforeProviderCompletion", func(t *testing.T, scheduleID domain.ID) {
		execution, err := store.EnqueueRunNow(ctx, scheduleID, "integration")
		if err != nil {
			t.Fatalf("EnqueueRunNow failed: %v", err)
		}
		registry := capability.NewRegistry()
		providerStarted := make(chan struct{})
		providerCancellationObserved := make(chan struct{})
		heartbeatStarted := make(chan struct{})
		heartbeatLost := make(chan struct{})
		fakeExecute := func(ctx context.Context) (capability.Result, error) {
			close(providerStarted)
			<-ctx.Done()
			close(providerCancellationObserved)
			return capability.Result{Action: domain.ActionResult{Output: json.RawMessage(`{"urls":[],"port_targets":[],"authorized_urls":[],"active_urls":[],"findings":[],"authorized_records":[],"lines":[],"scan_targets":[],"crawl_targets":[],"interesting_endpoints":[],"changes":[]}`)}}, nil
		}
		for _, capName := range allCaps() {
			registry.Register(&fakeProvider{name: capName, onExecute: fakeExecute})
		}
		orch := &orchestration.Service{Store: store, Registry: registry, Config: config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: root}, ArtifactStorage: config.ArtifactStorage{Root: root}}}
		svc := New(store, orch, config.Scheduler{LeaseTimeout: 1 * time.Second, PollInterval: time.Minute})
		svc.Owner = "test-owner"
		wrapper := &storeWrapper{Store: store}
		wrapper.onHeartbeat = func(ctx context.Context, id domain.ID, owner string, attempt int, timeout time.Duration) error {
			close(heartbeatStarted)
			err := store.HeartbeatScheduledExecution(ctx, id, owner, attempt, timeout)
			if errors.Is(err, database.ErrLostScheduledExecutionLease) {
				close(heartbeatLost)
			}
			return err
		}
		svc.Store = wrapper

		errs := make(chan error, 1)
		go func() { errs <- svc.Dispatch(ctx) }()
		<-providerStarted
		var claimedStatus domain.ScheduledExecutionStatus
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&claimedStatus); err != nil {
			t.Fatalf("query claimed scheduled execution: %v", err)
		}
		if claimedStatus != domain.ScheduledExecutionRunning {
			t.Fatalf("provider started before scheduled execution was running: %s", claimedStatus)
		}
		if _, err := store.Pool.Exec(ctx, `UPDATE scheduled_executions SET lease_expires_at = clock_timestamp() - interval '1 second', lease_owner = 'stale-owner' WHERE id = $1`, execution.ID); err != nil {
			t.Fatalf("expire scheduled execution lease: %v", err)
		}
		<-heartbeatStarted
		<-heartbeatLost
		<-providerCancellationObserved

		err = <-errs
		if !errors.Is(err, database.ErrLostScheduledExecutionLease) {
			t.Fatalf("expected ErrLostScheduledExecutionLease, got: %v", err)
		}
		var scheduledStatus domain.ScheduledExecutionStatus
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&scheduledStatus); err != nil {
			t.Fatalf("query final scheduled execution status: %v", err)
		}
		if scheduledStatus == domain.ScheduledExecutionCompleted || scheduledStatus == domain.ScheduledExecutionFailed || scheduledStatus == domain.ScheduledExecutionCancelled {
			t.Fatalf("stale owner mutated scheduled execution to %s", scheduledStatus)
		}
		var workflowStatus domain.RunStatus
		if err := store.Pool.QueryRow(ctx, `SELECT wr.status FROM workflow_runs wr JOIN scheduled_executions se ON se.workflow_run_id=wr.id WHERE se.id=$1`, execution.ID).Scan(&workflowStatus); err != nil {
			t.Fatalf("query workflow status after stale provider result: %v", err)
		}
		if workflowStatus == domain.RunCompleted {
			t.Fatalf("stale provider output was accepted as a completed workflow")
		}
	})

	// 9. Normal scheduled completion remains unchanged.
	runCase("9_NormalScheduledCompletion", func(t *testing.T, scheduleID domain.ID) {
		execution, err := store.EnqueueRunNow(ctx, scheduleID, "integration")
		if err != nil {
			t.Fatalf("EnqueueRunNow failed: %v", err)
		}
		registry := capability.NewRegistry()
		fakeExecute := func(ctx context.Context) (capability.Result, error) {
			return capability.Result{Action: domain.ActionResult{Output: json.RawMessage(`{"urls":[],"port_targets":[],"authorized_urls":[],"active_urls":[],"findings":[],"authorized_records":[],"lines":[],"scan_targets":[],"crawl_targets":[],"interesting_endpoints":[],"changes":[]}`)}}, nil
		}
		for _, capName := range allCaps() {
			registry.Register(&fakeProvider{name: capName, onExecute: fakeExecute})
		}
		orch := &orchestration.Service{Store: store, Registry: registry, Config: config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: root}, ArtifactStorage: config.ArtifactStorage{Root: root}}}
		svc := New(store, orch, config.Scheduler{LeaseTimeout: 10 * time.Second, PollInterval: time.Minute})
		svc.Owner = "test-owner"
		if err := svc.Dispatch(ctx); err != nil {
			t.Fatalf("expected nil, got: %v", err)
		}
		var status domain.ScheduledExecutionStatus
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&status); err != nil {
			t.Fatalf("query final scheduled execution status: %v", err)
		}
		if status != domain.ScheduledExecutionCompleted {
			t.Fatalf("expected completed, got %v", status)
		}
	})

	// 10. Ordinary provider failure remains unchanged.
	runCase("10_OrdinaryProviderFailure", func(t *testing.T, scheduleID domain.ID) {
		execution, err := store.EnqueueRunNow(ctx, scheduleID, "integration")
		if err != nil {
			t.Fatalf("EnqueueRunNow failed: %v", err)
		}
		registry := capability.NewRegistry()
		fakeExecute := func(ctx context.Context) (capability.Result, error) {
			return capability.Result{}, errors.New("ordinary failure")
		}
		for _, capName := range allCaps() {
			registry.Register(&fakeProvider{name: capName, onExecute: fakeExecute})
		}
		orch := &orchestration.Service{Store: store, Registry: registry, Config: config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: root}, ArtifactStorage: config.ArtifactStorage{Root: root}}}
		svc := New(store, orch, config.Scheduler{LeaseTimeout: 10 * time.Second, PollInterval: time.Minute})
		svc.Owner = "test-owner"
		if err := svc.Dispatch(ctx); err != nil {
			t.Fatalf("expected nil from Dispatch (it handles failure internally), got: %v", err)
		}
		var status domain.ScheduledExecutionStatus
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&status); err != nil {
			t.Fatalf("query final scheduled execution status: %v", err)
		}
		if status != domain.ScheduledExecutionFailed {
			t.Fatalf("expected failed, got %v", status)
		}
	})

	// 11. Parent-context cancellation remains unchanged.
	runCase("11_ParentContextCancellation", func(t *testing.T, scheduleID domain.ID) {
		execution, err := store.EnqueueRunNow(ctx, scheduleID, "integration")
		if err != nil {
			t.Fatalf("EnqueueRunNow failed: %v", err)
		}
		registry := capability.NewRegistry()
		ready := make(chan struct{})
		fakeExecute := func(ctx context.Context) (capability.Result, error) {
			close(ready)
			<-ctx.Done()
			return capability.Result{}, ctx.Err()
		}
		for _, capName := range allCaps() {
			registry.Register(&fakeProvider{name: capName, onExecute: fakeExecute})
		}
		orch := &orchestration.Service{Store: store, Registry: registry, Config: config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: root}, ArtifactStorage: config.ArtifactStorage{Root: root}}}
		svc := New(store, orch, config.Scheduler{LeaseTimeout: 10 * time.Second, PollInterval: time.Minute})
		svc.Owner = "test-owner"

		cancelCtx, cancel := context.WithCancel(ctx)
		errs := make(chan error, 1)
		go func() { errs <- svc.Dispatch(cancelCtx) }()
		<-ready
		cancel()
		<-errs

		var status domain.ScheduledExecutionStatus
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&status); err != nil {
			t.Fatalf("query final scheduled execution status: %v", err)
		}
		if status != domain.ScheduledExecutionCancelled {
			t.Fatalf("expected cancelled, got %v", status)
		}
	})

	// 12. Approval pause and explicit operator-controlled resume.
	// Exercises the full lifecycle: enqueue → dispatch → paused_for_approval →
	// heartbeat quiesce → fetch real approval → DecideApproval (accepted) →
	// verify no auto-resume → RequestScheduledExecutionResume → pending →
	// re-dispatch → completed. Asserts task, workflow, step coherence and that
	// the approval-requiring step executes exactly once.
	runCase("12_ApprovalPauseAndResume", func(t *testing.T, scheduleID domain.ID) {
		execution, err := store.EnqueueRunNow(ctx, scheduleID, "integration")
		if err != nil {
			t.Fatalf("EnqueueRunNow failed: %v", err)
		}

		registry := capability.NewRegistry()
		var prepareCount int
		fakePrepareExecute := func(ctx context.Context) (capability.Result, error) {
			prepareCount++
			return capability.Result{Action: domain.ActionResult{Output: json.RawMessage(`{"urls":[],"port_targets":[],"authorized_urls":[],"active_urls":[],"findings":[],"authorized_records":[],"lines":[],"scan_targets":[],"crawl_targets":[],"interesting_endpoints":[],"changes":[]}`)}}, nil
		}
		fakeExecute := func(ctx context.Context) (capability.Result, error) {
			return capability.Result{Action: domain.ActionResult{Output: json.RawMessage(`{"urls":[],"port_targets":[],"authorized_urls":[],"active_urls":[],"findings":[],"authorized_records":[],"lines":[],"scan_targets":[],"crawl_targets":[],"interesting_endpoints":[],"changes":[]}`)}}, nil
		}
		for _, capName := range allCaps() {
			if capName == "targeting.prepare" {
				// targeting.prepare requires approval; faking moderate risk mirrors production
				registry.Register(&fakeProvider{name: capName, onExecute: fakePrepareExecute, risk: policy.Moderate, approval: true})
			} else {
				registry.Register(&fakeProvider{name: capName, onExecute: fakeExecute})
			}
		}

		wrapper := &storeWrapper{Store: store}
		orch := &orchestration.Service{Store: store, Registry: registry, Config: config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: root}, ArtifactStorage: config.ArtifactStorage{Root: root}}}
		svc := New(store, orch, config.Scheduler{LeaseTimeout: 10 * time.Second, PollInterval: time.Minute})
		svc.Owner = "test-owner"
		svc.Store = wrapper

		// Step 1-2: enqueue and dispatch; workflow pauses at the approval-required step.
		if err := svc.Dispatch(ctx); err != nil {
			t.Fatalf("first Dispatch failed: %v", err)
		}

		// Step 3: heartbeat goroutine must have terminated before we inspect state.
		wrapper.heartbeatWg.Wait()

		var seStatus domain.ScheduledExecutionStatus
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&seStatus); err != nil {
			t.Fatalf("query scheduled execution status: %v", err)
		}
		if seStatus != domain.ScheduledExecutionPausedForApproval {
			var reason string
			if err := store.Pool.QueryRow(ctx, `SELECT COALESCE(wr.error_reason, '') FROM workflow_runs wr JOIN scheduled_executions se ON se.workflow_run_id=wr.id WHERE se.id=$1`, execution.ID).Scan(&reason); err != nil {
				t.Fatalf("query workflow error reason: %v", err)
			}
			t.Fatalf("after first dispatch: want paused_for_approval, got %v (workflow error_reason: %s)", seStatus, reason)
		}

		// Step 4: fetch the real pending approval through the repository.
		var approvalID domain.ID
		if err := store.Pool.QueryRow(ctx,
			`SELECT a.id FROM approvals a
			 JOIN step_runs sr ON sr.id=a.request_id
			 JOIN scheduled_executions se ON se.workflow_run_id=sr.workflow_run_id
			 WHERE se.id=$1 AND a.decision='pending'`,
			execution.ID,
		).Scan(&approvalID); err != nil {
			t.Fatalf("pending approval not found: %v", err)
		}

		// Step 5: accept the approval through the real store operation.
		if err := store.DecideApproval(ctx, approvalID, "approved", "integration"); err != nil {
			t.Fatalf("DecideApproval failed: %v", err)
		}

		// Step 6: acceptance alone must NOT resume execution; it must remain paused.
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&seStatus); err != nil {
			t.Fatalf("query after approval: %v", err)
		}
		if seStatus != domain.ScheduledExecutionPausedForApproval {
			t.Fatalf("acceptance alone must not resume: want paused_for_approval, got %v", seStatus)
		}

		// Verify the approval record is now accepted and no duplicate exists.
		var approvalDecision string
		var approvalCount int
		if err := store.Pool.QueryRow(ctx, `SELECT decision FROM approvals WHERE id=$1`, approvalID).Scan(&approvalDecision); err != nil {
			t.Fatalf("query approval decision: %v", err)
		}
		if approvalDecision != "approved" {
			t.Fatalf("approval decision: want approved, got %s", approvalDecision)
		}
		if err := store.Pool.QueryRow(ctx,
			`SELECT count(*) FROM approvals a
			 JOIN step_runs sr ON sr.id=a.request_id
			 JOIN scheduled_executions se ON se.workflow_run_id=sr.workflow_run_id
			 WHERE se.id=$1`,
			execution.ID,
		).Scan(&approvalCount); err != nil {
			t.Fatalf("count approvals: %v", err)
		}
		if approvalCount != 1 {
			t.Fatalf("duplicate approval created: count=%d", approvalCount)
		}

		// Step 7: explicitly invoke the operator-controlled scheduled resume API.
		if err := store.RequestScheduledExecutionResume(ctx, execution.ID, "integration"); err != nil {
			t.Fatalf("RequestScheduledExecutionResume failed: %v", err)
		}

		// Step 8: after explicit resume the execution must be pending (re-claimable).
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&seStatus); err != nil {
			t.Fatalf("query after resume: %v", err)
		}
		if seStatus != domain.ScheduledExecutionPending {
			t.Fatalf("after resume: want pending, got %v", seStatus)
		}

		// Step 9: dispatch again; scheduler claims the pending execution and resumes the workflow.
		if err := svc.Dispatch(ctx); err != nil {
			t.Fatalf("second Dispatch failed: %v", err)
		}

		wrapper.heartbeatWg.Wait()

		// Step 10: verify all terminal states.
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&seStatus); err != nil {
			t.Fatalf("query final scheduled status: %v", err)
		}
		if seStatus != domain.ScheduledExecutionCompleted {
			t.Fatalf("after second dispatch: want completed, got %v", seStatus)
		}

		// Linked task must be completed.
		var taskStatus domain.TaskStatus
		if err := store.Pool.QueryRow(ctx,
			`SELECT t.status FROM tasks t JOIN scheduled_executions se ON se.task_id=t.id WHERE se.id=$1`,
			execution.ID,
		).Scan(&taskStatus); err != nil {
			t.Fatalf("query task status: %v", err)
		}
		if taskStatus != domain.TaskCompleted {
			t.Fatalf("task: want completed, got %v", taskStatus)
		}

		// Workflow run must be completed.
		var wfStatus domain.RunStatus
		if err := store.Pool.QueryRow(ctx,
			`SELECT wr.status FROM workflow_runs wr JOIN scheduled_executions se ON se.workflow_run_id=wr.id WHERE se.id=$1`,
			execution.ID,
		).Scan(&wfStatus); err != nil {
			t.Fatalf("query workflow status: %v", err)
		}
		if wfStatus != domain.RunCompleted {
			t.Fatalf("workflow: want completed, got %v", wfStatus)
		}

		// Step state: the approval-requiring step must have succeeded.
		var stepStatus domain.StepStatus
		var stepApprovalState string
		if err := store.Pool.QueryRow(ctx,
			`SELECT sr.status, sr.approval_state
			 FROM step_runs sr
			 JOIN workflow_runs wr ON wr.id=sr.workflow_run_id
			 JOIN scheduled_executions se ON se.workflow_run_id=wr.id
			 WHERE se.id=$1 AND sr.step_definition_id='prepare-authorized-targets'`,
			execution.ID,
		).Scan(&stepStatus, &stepApprovalState); err != nil {
			t.Fatalf("query step status: %v", err)
		}
		if stepStatus != domain.StepSucceeded {
			t.Fatalf("approval step: want succeeded, got %v", stepStatus)
		}
		if stepApprovalState != "approved" {
			t.Fatalf("approval step state: want approved, got %s", stepApprovalState)
		}

		// Approval must still be accepted and not duplicated.
		if err := store.Pool.QueryRow(ctx, `SELECT decision FROM approvals WHERE id=$1`, approvalID).Scan(&approvalDecision); err != nil {
			t.Fatalf("re-query approval: %v", err)
		}
		if approvalDecision != "approved" {
			t.Fatalf("approval must remain approved, got %s", approvalDecision)
		}
		if err := store.Pool.QueryRow(ctx,
			`SELECT count(*) FROM approvals a
			 JOIN step_runs sr ON sr.id=a.request_id
			 JOIN scheduled_executions se ON se.workflow_run_id=sr.workflow_run_id
			 WHERE se.id=$1`,
			execution.ID,
		).Scan(&approvalCount); err != nil {
			t.Fatalf("count approvals after resume: %v", err)
		}
		if approvalCount != 1 {
			t.Fatalf("duplicate approval after resume: count=%d", approvalCount)
		}

		// Provider must have executed exactly once after explicit resume.
		if prepareCount != 1 {
			t.Fatalf("targeting.prepare executed %d times, want 1 (executed exactly once after explicit resume)", prepareCount)
		}

		// attempt_count must be 2: one for the initial paused dispatch, one for the resumed dispatch.
		var attempts int
		if err := store.Pool.QueryRow(ctx, `SELECT attempt_count FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&attempts); err != nil {
			t.Fatalf("query attempt_count: %v", err)
		}
		if attempts != 2 {
			t.Fatalf("attempt_count: want 2, got %d", attempts)
		}

		// Audits must not contain a contradictory pause/failure/completion sequence.
		// Specifically: no failure event before completion, no duplicate pause events.
		type auditEvent struct {
			EventType string
		}
		rows, err := store.Pool.Query(ctx,
			`SELECT ae.event_type FROM audit_events ae
			 JOIN workflow_runs wr ON wr.id=ae.workflow_run_id
			 JOIN scheduled_executions se ON se.workflow_run_id=wr.id
			 WHERE se.id=$1
			 ORDER BY ae.id`,
			execution.ID,
		)
		if err != nil {
			t.Fatalf("query audit events: %v", err)
		}
		completedSeen, failedSeen := false, false
		var scanErr error
		contradictory := false
		for rows.Next() {
			var evType string
			if err := rows.Scan(&evType); err != nil {
				scanErr = err
				break
			}
			if evType == "workflow_completed" {
				completedSeen = true
			}
			if evType == "workflow_failed" {
				failedSeen = true
			}
			// No failure event must appear after completion in the sequence
			if failedSeen && completedSeen {
				contradictory = true
				break
			}
		}
		rowErr := rows.Err()
		rows.Close()
		if scanErr != nil {
			t.Fatalf("scan audit event: %v", scanErr)
		}
		if rowErr != nil {
			t.Fatalf("audit rows error: %v", rowErr)
		}
		if contradictory {
			t.Fatal("audit sequence: failure event appears after completion")
		}
	})

	// 13. Unscheduled workflow execution remains unchanged.
	runCase("13_UnscheduledWorkflowExecution", func(t *testing.T, scheduleID domain.ID) {
		registry := capability.NewRegistry()
		fakeExecute := func(ctx context.Context) (capability.Result, error) {
			return capability.Result{Action: domain.ActionResult{Output: json.RawMessage(`{"urls":[],"port_targets":[],"authorized_urls":[],"active_urls":[],"findings":[],"authorized_records":[],"lines":[],"scan_targets":[],"crawl_targets":[],"interesting_endpoints":[],"changes":[]}`)}}, nil
		}
		for _, capName := range allCaps() {
			registry.Register(&fakeProvider{name: capName, onExecute: fakeExecute})
		}
		orch := &orchestration.Service{Store: store, Registry: registry, Config: config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: root}, ArtifactStorage: config.ArtifactStorage{Root: root}}}
		if _, err := orch.Run(ctx, orchestration.WorkflowRequest{
			ProgramID:                 programID,
			WorkflowName:              workflows.ContinuousName,
			ScopeReference:            "scope.json",
			AcknowledgeScopeExpansion: true,
		}); err != nil {
			t.Fatalf("setup unscheduled workflow run: %v", err)
		}
	})

	// 14. Heartbeat goroutine termination is explicitly observed before execute returns.
	runCase("14_HeartbeatTerminationExplicit", func(t *testing.T, scheduleID domain.ID) {
		execution, err := store.EnqueueRunNow(ctx, scheduleID, "integration")
		if err != nil {
			t.Fatalf("EnqueueRunNow failed: %v", err)
		}
		registry := capability.NewRegistry()
		providerStarted := make(chan struct{})
		heartbeatStarted := make(chan struct{})
		heartbeatAtExitBarrier := make(chan struct{})
		allowHeartbeatReturn := make(chan struct{})
		heartbeatExited := make(chan struct{})
		var providerStartOnce sync.Once
		var heartbeatStartOnce sync.Once
		var releaseHeartbeatOnce sync.Once
		dispatchCtx, cancelDispatch := context.WithCancel(ctx)
		t.Cleanup(cancelDispatch)
		releaseHeartbeat := func() {
			releaseHeartbeatOnce.Do(func() {
				close(allowHeartbeatReturn)
			})
		}
		t.Cleanup(releaseHeartbeat)
		fakeExecute := func(ctx context.Context) (capability.Result, error) {
			providerStartOnce.Do(func() { close(providerStarted) })
			select {
			case <-heartbeatStarted:
			case <-ctx.Done():
				return capability.Result{}, ctx.Err()
			}
			return capability.Result{Action: domain.ActionResult{Output: json.RawMessage(`{"urls":[],"port_targets":[],"authorized_urls":[],"active_urls":[],"findings":[],"authorized_records":[],"lines":[],"scan_targets":[],"crawl_targets":[],"interesting_endpoints":[],"changes":[]}`)}}, nil
		}
		for _, capName := range allCaps() {
			registry.Register(&fakeProvider{name: capName, onExecute: fakeExecute})
		}

		wrapper := &storeWrapper{Store: store}
		wrapper.onHeartbeat = func(ctx context.Context, _ domain.ID, _ string, _ int, _ time.Duration) error {
			heartbeatStartOnce.Do(func() { close(heartbeatStarted) })
			<-ctx.Done()
			close(heartbeatAtExitBarrier)
			<-allowHeartbeatReturn
			close(heartbeatExited)
			return ctx.Err()
		}
		orch := &orchestration.Service{Store: store, Registry: registry, Config: config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: root}, ArtifactStorage: config.ArtifactStorage{Root: root}}}
		svc := New(store, orch, config.Scheduler{LeaseTimeout: 5 * time.Second, PollInterval: time.Minute})
		svc.Owner = "test-owner"
		svc.Store = wrapper

		dispatchErr := make(chan error, 1)
		go func() { dispatchErr <- svc.Dispatch(dispatchCtx) }()
		<-providerStarted
		<-heartbeatAtExitBarrier

		select {
		case err := <-dispatchErr:
			releaseHeartbeat()
			t.Fatalf("Dispatch returned before heartbeat termination was released: %v", err)
		default:
			// Expected: Dispatch is waiting for heartbeat termination.
		}

		releaseHeartbeat()
		if err := <-dispatchErr; err != nil {
			t.Fatalf("Dispatch failed after heartbeat termination: %v", err)
		}

		select {
		case <-heartbeatExited:
		default:
			t.Fatal("Dispatch returned before heartbeat exited")
		}
		if calls := wrapper.heartbeatCalls.Load(); calls != 1 {
			t.Fatalf("heartbeat hook calls=%d, want 1", calls)
		}
		if active := wrapper.heartbeatActive.Load(); active != 0 {
			t.Fatalf("active heartbeat calls=%d, want 0", active)
		}
		wrapper.heartbeatWg.Wait()

		var status domain.ScheduledExecutionStatus
		if err := store.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, execution.ID).Scan(&status); err != nil {
			t.Fatalf("query scheduled execution status: %v", err)
		}
		if status != domain.ScheduledExecutionCompleted {
			t.Fatalf("expected completed, got %v", status)
		}
	})

	// 15. Repeated cancellation causes no duplicate terminal mutation.
	runCase("15_RepeatedCancellationNoDuplicateMutation", func(t *testing.T, scheduleID domain.ID) {
		execution, err := store.EnqueueRunNow(ctx, scheduleID, "integration")
		if err != nil {
			t.Fatalf("EnqueueRunNow failed: %v", err)
		}
		registry := capability.NewRegistry()
		providerStarted := make(chan struct{})
		var providerStartOnce sync.Once
		var providerCalls atomic.Int32
		fakeExecute := func(ctx context.Context) (capability.Result, error) {
			providerCalls.Add(1)
			providerStartOnce.Do(func() { close(providerStarted) })
			<-ctx.Done()
			return capability.Result{}, ctx.Err()
		}
		for _, capName := range allCaps() {
			registry.Register(&fakeProvider{name: capName, onExecute: fakeExecute})
		}
		orch := &orchestration.Service{Store: store, Registry: registry, Config: config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: root}, ArtifactStorage: config.ArtifactStorage{Root: root}}}
		svc := New(store, orch, config.Scheduler{LeaseTimeout: 10 * time.Second, PollInterval: time.Minute})
		svc.Owner = "test-owner"
		cancelCtx, cancel := context.WithCancel(ctx)
		dispatchErr := make(chan error, 1)
		go func() { dispatchErr <- svc.Dispatch(cancelCtx) }()
		<-providerStarted
		cancel()
		cancel()
		cancel()
		if err := <-dispatchErr; err != nil {
			t.Fatalf("Dispatch failed after repeated cancellation: %v", err)
		}
		if calls := providerCalls.Load(); calls != 1 {
			t.Fatalf("provider calls=%d, want 1", calls)
		}

		var scheduledStatus domain.ScheduledExecutionStatus
		var taskStatus domain.TaskStatus
		var workflowStatus domain.RunStatus
		if err := store.Pool.QueryRow(ctx, `
			SELECT se.status,t.status,wr.status
			FROM scheduled_executions se
			JOIN tasks t ON t.id=se.task_id
			JOIN workflow_runs wr ON wr.id=se.workflow_run_id
			WHERE se.id=$1`, execution.ID).Scan(&scheduledStatus, &taskStatus, &workflowStatus); err != nil {
			t.Fatalf("query cancellation lineage: %v", err)
		}
		if scheduledStatus != domain.ScheduledExecutionCancelled || taskStatus != domain.TaskCancelled || workflowStatus != domain.RunCancelled {
			t.Fatalf("incoherent cancellation lineage: scheduled=%s task=%s workflow=%s", scheduledStatus, taskStatus, workflowStatus)
		}

		var terminalAuditCounts = map[string]int{}
		rows, err := store.Pool.Query(ctx, `
			SELECT ae.event_type, count(*)
			FROM audit_events ae
			JOIN scheduled_executions se ON se.workflow_run_id=ae.workflow_run_id
			WHERE se.id=$1
			  AND ae.event_type IN ('scheduled_execution_cancelled','scheduled_execution_completed','scheduled_execution_failed')
			GROUP BY ae.event_type`, execution.ID)
		if err != nil {
			t.Fatalf("query scheduled execution terminal audits: %v", err)
		}
		for rows.Next() {
			var eventType string
			var count int
			if err := rows.Scan(&eventType, &count); err != nil {
				rows.Close()
				t.Fatalf("scan scheduled execution terminal audit: %v", err)
			}
			terminalAuditCounts[eventType] = count
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatalf("iterate scheduled execution terminal audits: %v", err)
		}
		rows.Close()
		if terminalAuditCounts["scheduled_execution_cancelled"] != 1 {
			t.Fatalf("scheduled execution cancellation audits=%d, want 1", terminalAuditCounts["scheduled_execution_cancelled"])
		}
		if terminalAuditCounts["scheduled_execution_completed"] != 0 || terminalAuditCounts["scheduled_execution_failed"] != 0 {
			t.Fatalf("contradictory terminal audits: %#v", terminalAuditCounts)
		}
	})
}
