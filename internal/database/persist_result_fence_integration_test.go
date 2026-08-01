package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

type scheduledResultFixture struct {
	env            recoveryTestEnvironment
	lineage        recoveryTestFixture
	stepID         domain.ID
	idempotencyKey string
	capability     string
	fence          ScheduledExecutionFence
}

func TestScheduledPersistResultFenceAcceptanceAndRejection(t *testing.T) {
	t.Run("current scheduled HTTP result persists atomically", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-current-http", "probe.http")
		output := json.RawMessage(`{"lines":["http://127.0.0.1/"],"authorized_records":[{"provider":"httpx","kind":"url","target":"http://127.0.0.1/","status_code":200}]}`)
		step, tool, artifacts, result := scheduledResultPayload(fixture, output)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result); err != nil {
			t.Fatal(err)
		}
		assertResultRowCounts(t, fixture, 1, 1, 1, 0, 1)
		assertStepRecoveryStatus(t, fixture.env, fixture.stepID, domain.StepSucceeded)
	})

	t.Run("current scheduled Nuclei result persists finding evidence", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-current-finding", "scan.nuclei")
		line := `{"template-id":"harmless-info","matched-at":"http://127.0.0.1/","info":{"name":"Harmless local response","severity":"info"}}`
		output, err := json.Marshal(map[string]any{"lines": []string{line}})
		if err != nil {
			t.Fatal(err)
		}
		step, tool, artifacts, result := scheduledResultPayload(fixture, output)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result); err != nil {
			t.Fatal(err)
		}
		assertResultRowCounts(t, fixture, 1, 1, 0, 1, 1)
		var changeCount int
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT count(*) FROM change_items WHERE workflow_run_id=$1`, fixture.lineage.runID).Scan(&changeCount); err != nil || changeCount != 1 {
			t.Fatalf("change items=%d err=%v", changeCount, err)
		}
	})

	t.Run("expired live lease rejects before reconciliation", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-expired", "scan.nuclei")
		expireRecoveryLease(t, fixture.env, fixture.lineage.execution.ID, 1)
		assertScheduledValidResultRejectedNoMutation(t, fixture, fixture.context())
		if err := fixture.env.store.HeartbeatScheduledExecution(fixture.env.ctx, fixture.lineage.execution.ID, fixture.fence.LeaseOwner, fixture.fence.Attempt, time.Minute); err == nil {
			t.Fatal("expired owner extended the lease")
		}
		assertStepRecoveryStatus(t, fixture.env, fixture.stepID, domain.StepRunning)
	})

	t.Run("reconciled lineage rejects and preserves closed incomplete tool", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-reconciled", "scan.nuclei")
		toolID := insertRecoveryTool(t, fixture.env, fixture.stepID, false)
		expireRecoveryLease(t, fixture.env, fixture.lineage.execution.ID, 1)
		reconcileRecovery(t, fixture.env)
		var toolBefore string
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT to_jsonb(tool_runs)::text FROM tool_runs WHERE id=$1`, toolID).Scan(&toolBefore); err != nil {
			t.Fatal(err)
		}
		beforeAudit := recoveryAuditRecord(t, fixture.env, fixture.lineage.execution.ID, "scheduled_execution_lineage_interrupted")
		step, tool, artifacts, result := fixture.validPayload()
		tool.ID = toolID
		for index := range artifacts {
			artifacts[index].ToolRunID = toolID
		}
		assertScheduledResultRejectedNoMutation(t, fixture, fixture.context(), step, tool, artifacts, result)
		var toolAfter string
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT to_jsonb(tool_runs)::text FROM tool_runs WHERE id=$1`, toolID).Scan(&toolAfter); err != nil {
			t.Fatal(err)
		}
		if toolAfter != toolBefore {
			t.Fatalf("recovery-closed tool changed\nbefore=%s\nafter=%s", toolBefore, toolAfter)
		}
		afterAudit := recoveryAuditRecord(t, fixture.env, fixture.lineage.execution.ID, "scheduled_execution_lineage_interrupted")
		if fmt.Sprint(beforeAudit) != fmt.Sprint(afterAudit) {
			t.Fatalf("recovery audit changed\nbefore=%v\nafter=%v", beforeAudit, afterAudit)
		}
		var completedAt *time.Time
		var exitCode *int
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT completed_at,exit_code FROM tool_runs WHERE id=$1`, toolID).Scan(&completedAt, &exitCode); err != nil {
			t.Fatal(err)
		}
		if completedAt == nil || exitCode != nil {
			t.Fatalf("recovery-closed tool completed=%v exit=%v", completedAt, exitCode)
		}
	})

	for _, test := range []struct {
		name  string
		fence func(ScheduledExecutionFence) ScheduledExecutionFence
	}{
		{name: "wrong owner", fence: func(f ScheduledExecutionFence) ScheduledExecutionFence { f.LeaseOwner = "other-owner"; return f }},
		{name: "wrong attempt", fence: func(f ScheduledExecutionFence) ScheduledExecutionFence { f.Attempt++; return f }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "result-"+strings.ReplaceAll(test.name, " ", "-"), "scan.nuclei")
			ctx := WithScheduledExecutionFence(fixture.env.ctx, test.fence(fixture.fence))
			assertScheduledValidResultRejectedNoMutation(t, fixture, ctx)
		})
	}

	t.Run("missing scheduled claim fence", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-missing-fence", "scan.nuclei")
		assertScheduledValidResultRejectedNoMutation(t, fixture, fixture.env.ctx)
	})

	t.Run("workflow mismatch", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-workflow-mismatch", "scan.nuclei")
		step, tool, artifacts, result := fixture.validPayload()
		step.WorkflowRunID = domain.NewID()
		assertScheduledResultRejectedNoMutation(t, fixture, fixture.context(), step, tool, artifacts, result)
	})

	t.Run("step belongs to another workflow", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-step-workflow-mismatch", "scan.nuclei")
		otherRunID := domain.NewID()
		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,trigger_source,summary) VALUES($1,$2,$3,'1','running',clock_timestamp(),'integration','{}')`, otherRunID, fixture.lineage.task.ID, fixture.env.definitionID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE step_runs SET workflow_run_id=$2 WHERE id=$1`, fixture.stepID, otherRunID); err != nil {
			t.Fatal(err)
		}
		assertScheduledValidResultRejectedNoMutation(t, fixture, fixture.context())
	})

	t.Run("idempotency mismatch", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-idempotency-mismatch", "scan.nuclei")
		step, tool, artifacts, result := fixture.validPayload()
		step.IdempotencyKey = "other-idempotency-key"
		assertScheduledResultRejectedNoMutation(t, fixture, fixture.context(), step, tool, artifacts, result)
	})

	for _, status := range []domain.StepStatus{domain.StepSucceeded, domain.StepFailed, domain.StepCancelled, domain.StepPending, domain.StepBlocked, domain.StepAwaitingApproval} {
		t.Run("non-running step "+string(status), func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "result-step-"+string(status), "scan.nuclei")
			if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE step_runs SET status=$2 WHERE id=$1`, fixture.stepID, status); err != nil {
				t.Fatal(err)
			}
			assertScheduledValidResultRejectedNoMutation(t, fixture, fixture.context())
		})
	}

	for _, status := range []domain.ScheduledExecutionStatus{
		domain.ScheduledExecutionInterrupted,
		domain.ScheduledExecutionCompleted,
		domain.ScheduledExecutionFailed,
		domain.ScheduledExecutionCancelled,
		domain.ScheduledExecutionApprovalRejected,
		domain.ScheduledExecutionPausedForApproval,
		domain.ScheduledExecutionPausedOperator,
		domain.ScheduledExecutionPending,
		domain.ScheduledExecutionClaimed,
	} {
		t.Run("scheduled status "+string(status), func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "result-scheduled-"+string(status), "scan.nuclei")
			if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE scheduled_executions SET status=$2 WHERE id=$1`, fixture.lineage.execution.ID, status); err != nil {
				t.Fatal(err)
			}
			assertScheduledValidResultRejectedNoMutation(t, fixture, fixture.context())
		})
	}

	t.Run("later evidence failure rolls back the entire result transaction", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-atomic-rollback", "probe.http")
		step, tool, artifacts, result := fixture.validPayload()
		artifacts[0].Size = -1
		before := resultFenceSnapshot(t, fixture)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result); err == nil {
			t.Fatal("invalid artifact size was accepted")
		}
		after := resultFenceSnapshot(t, fixture)
		if after != before {
			t.Fatalf("failed result transaction mutated database\nbefore=%s\nafter=%s", before, after)
		}
	})
}

func TestScheduledWorkflowSaveFence(t *testing.T) {
	t.Run("current scheduled attempt saves", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "save-current", "probe.http")
		state := scheduledFixtureState(fixture, domain.RunRunning, domain.StepRunning)
		if err := fixture.env.store.SaveWorkflowState(fixture.context(), state); err != nil {
			t.Fatal(err)
		}
	})

	for _, test := range []struct {
		name    string
		prepare func(scheduledResultFixture)
		ctx     func(scheduledResultFixture) context.Context
	}{
		{name: "expired lease", prepare: func(f scheduledResultFixture) { expireRecoveryLease(t, f.env, f.lineage.execution.ID, 1) }, ctx: func(f scheduledResultFixture) context.Context { return f.context() }},
		{name: "wrong owner", prepare: func(scheduledResultFixture) {}, ctx: func(f scheduledResultFixture) context.Context {
			fence := f.fence
			fence.LeaseOwner = "wrong"
			return WithScheduledExecutionFence(f.env.ctx, fence)
		}},
		{name: "wrong attempt", prepare: func(scheduledResultFixture) {}, ctx: func(f scheduledResultFixture) context.Context {
			fence := f.fence
			fence.Attempt++
			return WithScheduledExecutionFence(f.env.ctx, fence)
		}},
		{name: "missing claim fence", prepare: func(scheduledResultFixture) {}, ctx: func(f scheduledResultFixture) context.Context { return f.env.ctx }},
		{name: "reconciled execution", prepare: func(f scheduledResultFixture) {
			expireRecoveryLease(t, f.env, f.lineage.execution.ID, 1)
			reconcileRecovery(t, f.env)
		}, ctx: func(f scheduledResultFixture) context.Context { return f.context() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "save-"+strings.ReplaceAll(test.name, " ", "-"), "probe.http")
			test.prepare(fixture)
			before := resultFenceSnapshot(t, fixture)
			err := fixture.env.store.SaveWorkflowState(test.ctx(fixture), scheduledFixtureState(fixture, domain.RunCompleted, domain.StepSucceeded))
			if !errors.Is(err, ErrLostScheduledExecutionLease) {
				t.Fatalf("save error=%v want %v", err, ErrLostScheduledExecutionLease)
			}
			after := resultFenceSnapshot(t, fixture)
			if after != before {
				t.Fatalf("rejected workflow save mutated database\nbefore=%s\nafter=%s", before, after)
			}
		})
	}

	t.Run("unscheduled workflow save and result remain supported", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "result-unscheduled")
		now := time.Now().UTC()
		task := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "unscheduled")
		runID, stepID := domain.NewID(), domain.NewID()
		key := "unscheduled-idempotency"
		state := &workflow.State{Run: domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: env.definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{"provider": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "provider", Capability: "probe.http", Status: domain.StepRunning, AttemptCount: 1, Input: json.RawMessage(`{}`), StartedAt: &now, IdempotencyKey: key, ApprovalState: "not_required"}}}}
		if err := env.store.SaveWorkflowState(env.ctx, state); err != nil {
			t.Fatal(err)
		}
		fixture := scheduledResultFixture{env: env, lineage: recoveryTestFixture{task: task, runID: runID}, stepID: stepID, idempotencyKey: key, capability: "probe.http"}
		step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":["http://127.0.0.1/"]}`))
		if err := env.store.PersistResult(env.ctx, env.programID, step, tool, artifacts, result); err != nil {
			t.Fatal(err)
		}
		assertStepRecoveryStatus(t, env, stepID, domain.StepSucceeded)
		var toolCount int
		if err := env.store.Pool.QueryRow(env.ctx, `SELECT count(*) FROM tool_runs WHERE step_run_id=$1`, stepID).Scan(&toolCount); err != nil || toolCount != 1 {
			t.Fatalf("unscheduled tool count=%d err=%v", toolCount, err)
		}
	})

	t.Run("unscheduled result identity conflicts remain strict", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "result-unscheduled-conflict")
		now := time.Now().UTC()
		task := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "unscheduled-conflict")
		runID, stepID := domain.NewID(), domain.NewID()
		state := &workflow.State{
			Run:   domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: env.definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration", Summary: json.RawMessage(`{}`)},
			Steps: map[string]*workflow.StepState{"provider": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "provider", Capability: "probe.http", Status: domain.StepRunning, AttemptCount: 1, Input: json.RawMessage(`{}`), StartedAt: &now, IdempotencyKey: "unscheduled-conflict-key", ApprovalState: "not_required"}}},
		}
		if err := env.store.SaveWorkflowState(env.ctx, state); err != nil {
			t.Fatal(err)
		}
		fixture := scheduledResultFixture{env: env, lineage: recoveryTestFixture{task: task, runID: runID}, stepID: stepID, idempotencyKey: "unscheduled-conflict-key", capability: "probe.http"}
		step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":["http://127.0.0.1/"]}`))
		step.IdempotencyKey = "wrong-key"
		if err := env.store.PersistResult(env.ctx, env.programID, step, tool, artifacts, result); !errors.Is(err, ErrWorkflowResultConflict) {
			t.Fatalf("unscheduled identity error=%v want %v", err, ErrWorkflowResultConflict)
		}
		assertStepRecoveryStatus(t, env, stepID, domain.StepRunning)
		assertResultRowCounts(t, fixture, 0, 0, 0, 0, 0)
	})
}

func TestPersistResultRecoveryConcurrency(t *testing.T) {
	t.Run("result locks first and recovery preserves the accepted terminal evidence", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-race-result-first", "scan.nuclei")
		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE scheduled_executions SET lease_expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, fixture.lineage.execution.ID); err != nil {
			t.Fatal(err)
		}
		installPersistResultStepBarrier(t, fixture.env)
		release := holdPersistResultStepBarrier(t, fixture.env, fixture.stepID)
		defer release()

		raceCtx, cancel := context.WithTimeout(fixture.context(), 8*time.Second)
		defer cancel()
		step, tool, artifacts, result := fixture.validPayload()
		persisted := make(chan error, 1)
		go func() {
			persisted <- fixture.env.store.PersistResult(raceCtx, fixture.env.programID, step, tool, artifacts, result)
		}()
		waitForPostgresLock(t, raceCtx, fixture.env.store, `%UPDATE step_runs%SET status=%`)
		waitForScheduledLeaseExpiry(t, raceCtx, fixture)

		recovered := make(chan error, 1)
		go func() {
			recovered <- fixture.env.store.reconcileStaleScheduledExecutions(raceCtx, 1)
		}()
		select {
		case err := <-recovered:
			if err != nil {
				t.Fatal(err)
			}
		case <-raceCtx.Done():
			t.Fatalf("recovery deadlocked behind result persistence: %v", raceCtx.Err())
		}
		assertScheduledRecoveryStatusAndClass(t, fixture.env, fixture.lineage.execution.ID, domain.ScheduledExecutionRunning, "")

		release()
		select {
		case err := <-persisted:
			if err != nil {
				t.Fatal(err)
			}
		case <-raceCtx.Done():
			t.Fatalf("result persistence did not finish: %v", raceCtx.Err())
		}
		assertResultRowCounts(t, fixture, 1, 1, 0, 1, 1)

		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE scheduled_executions SET lease_expires_at=clock_timestamp()+interval '1 minute' WHERE id=$1`, fixture.lineage.execution.ID); err != nil {
			t.Fatal(err)
		}
		if err := fixture.env.store.SaveWorkflowState(fixture.context(), scheduledFixtureState(fixture, domain.RunCompleted, domain.StepSucceeded)); err != nil {
			t.Fatal(err)
		}
		expireRecoveryLease(t, fixture.env, fixture.lineage.execution.ID, 1)
		reconcileRecovery(t, fixture.env)
		assertScheduledRecoveryStatusAndClass(t, fixture.env, fixture.lineage.execution.ID, domain.ScheduledExecutionCompleted, "")
		assertTaskRecoveryStatus(t, fixture.env, fixture.lineage.task.ID, domain.TaskCompleted)
		assertWorkflowRecoveryStatus(t, fixture.env, fixture.lineage.runID, domain.RunCompleted)
		assertStepRecoveryStatus(t, fixture.env, fixture.stepID, domain.StepSucceeded)
		assertResultRowCounts(t, fixture, 1, 1, 0, 1, 1)
		assertRecoveryAuditCount(t, fixture.env, fixture.lineage.execution.ID, "scheduled_execution_terminal_reconciled", 1)
	})

	t.Run("recovery locks first and the late result rejects", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-race-recovery-first", "scan.nuclei")
		expireRecoveryLease(t, fixture.env, fixture.lineage.execution.ID, 1)
		tx, err := fixture.env.store.Pool.Begin(fixture.env.ctx)
		if err != nil {
			t.Fatal(err)
		}
		committed := false
		defer func() {
			if !committed {
				_ = tx.Rollback(context.Background())
			}
		}()
		entry, found, err := lockNextStaleScheduledExecution(fixture.env.ctx, tx, nil)
		if err != nil || !found || entry.item.ID != fixture.lineage.execution.ID {
			t.Fatalf("locked recovery entry=%#v found=%v err=%v", entry, found, err)
		}

		raceCtx, cancel := context.WithTimeout(fixture.context(), 8*time.Second)
		defer cancel()
		step, tool, artifacts, result := fixture.validPayload()
		persisted := make(chan error, 1)
		go func() {
			persisted <- fixture.env.store.PersistResult(raceCtx, fixture.env.programID, step, tool, artifacts, result)
		}()
		waitForPostgresLock(t, raceCtx, fixture.env.store, `%WHERE se.id=$1%FOR UPDATE OF se%`)

		lineage, locked, err := lockScheduledExecutionLineage(fixture.env.ctx, tx, entry)
		if err != nil || !locked {
			t.Fatalf("lock recovery lineage locked=%v err=%v", locked, err)
		}
		if err := applyStaleLineageReconciliation(fixture.env.ctx, tx, entry, lineage, classifyStaleLineage(entry, &lineage)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(fixture.env.ctx); err != nil {
			t.Fatal(err)
		}
		committed = true
		select {
		case err := <-persisted:
			if !errors.Is(err, ErrStaleScheduledExecutionResult) {
				t.Fatalf("late result error=%v want %v", err, ErrStaleScheduledExecutionResult)
			}
		case <-raceCtx.Done():
			t.Fatalf("late result did not finish after recovery: %v", raceCtx.Err())
		}
		assertScheduledRecoveryStatusAndClass(t, fixture.env, fixture.lineage.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted")
		assertTaskRecoveryStatus(t, fixture.env, fixture.lineage.task.ID, domain.TaskFailed)
		assertWorkflowRecoveryStatus(t, fixture.env, fixture.lineage.runID, domain.RunFailed)
		assertStepRecoveryStatus(t, fixture.env, fixture.stepID, domain.StepFailed)
		assertResultRowCounts(t, fixture, 0, 0, 0, 0, 0)
		assertRecoveryAuditCount(t, fixture.env, fixture.lineage.execution.ID, "scheduled_execution_lineage_interrupted", 1)
	})
}

func TestConcurrentDuplicatePersistResult(t *testing.T) {
	fixture := newScheduledResultFixture(t, "result-race-duplicate", "probe.http")
	output := json.RawMessage(`{"lines":["http://127.0.0.1/"],"authorized_records":[{"provider":"httpx","kind":"url","target":"http://127.0.0.1/","status_code":200}]}`)
	step, tool, artifacts, result := scheduledResultPayload(fixture, output)
	raceCtx, cancel := context.WithTimeout(fixture.context(), 8*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			select {
			case <-start:
				results <- fixture.env.store.PersistResult(raceCtx, fixture.env.programID, step, tool, artifacts, result)
			case <-raceCtx.Done():
				results <- raceCtx.Err()
			}
		}()
	}
	close(start)
	succeeded, rejected := 0, 0
	for range 2 {
		select {
		case err := <-results:
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrStaleScheduledExecutionResult):
				rejected++
			default:
				t.Fatalf("duplicate result error=%v", err)
			}
		case <-raceCtx.Done():
			t.Fatalf("duplicate result calls did not finish: %v", raceCtx.Err())
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("duplicate result outcomes succeeded=%d rejected=%d", succeeded, rejected)
	}
	assertStepRecoveryStatus(t, fixture.env, fixture.stepID, domain.StepSucceeded)
	assertResultRowCounts(t, fixture, 1, 1, 1, 0, 1)
}

func newScheduledResultFixture(t *testing.T, name, capabilityName string) scheduledResultFixture {
	t.Helper()
	env := newRecoveryTestEnvironment(t, name)
	runStatus := domain.RunRunning
	lineage := createRecoveryFixture(t, env, name, &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "provider", status: domain.StepRunning, started: true, attemptCount: 1}})
	stepID := lineage.steps["provider"]
	if _, err := env.store.Pool.Exec(env.ctx, `UPDATE step_runs SET capability=$2 WHERE id=$1`, stepID, capabilityName); err != nil {
		t.Fatal(err)
	}
	var key string
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT idempotency_key FROM step_runs WHERE id=$1`, stepID).Scan(&key); err != nil {
		t.Fatal(err)
	}
	return scheduledResultFixture{
		env: env, lineage: lineage, stepID: stepID, idempotencyKey: key, capability: capabilityName,
		fence: ScheduledExecutionFence{ExecutionID: lineage.execution.ID, LeaseOwner: lineage.execution.LeaseOwner, Attempt: lineage.execution.AttemptCount},
	}
}

func (fixture scheduledResultFixture) context() context.Context {
	return WithScheduledExecutionFence(fixture.env.ctx, fixture.fence)
}

func (fixture scheduledResultFixture) validPayload() (domain.StepRun, *domain.ToolRun, []domain.Artifact, domain.ActionResult) {
	line := `{"template-id":"harmless-info","matched-at":"http://127.0.0.1/","info":{"name":"Harmless local response","severity":"info"}}`
	output, _ := json.Marshal(map[string]any{"lines": []string{line}})
	return scheduledResultPayload(fixture, output)
}

func scheduledResultPayload(fixture scheduledResultFixture, output json.RawMessage) (domain.StepRun, *domain.ToolRun, []domain.Artifact, domain.ActionResult) {
	now := time.Now().UTC()
	toolID, artifactID := domain.NewID(), domain.NewID()
	exitCode := 0
	step := domain.StepRun{ID: fixture.stepID, WorkflowRunID: fixture.lineage.runID, Capability: fixture.capability, Status: domain.StepSucceeded, Output: output, CompletedAt: &now, IdempotencyKey: fixture.idempotencyKey}
	tool := &domain.ToolRun{ID: toolID, StepRunID: fixture.stepID, Capability: fixture.capability, Provider: "fixture", ToolVersion: "1", SanitizedArguments: json.RawMessage(`{}`), ExecutionEnvironment: json.RawMessage(`{"kind":"integration"}`), StartedAt: now.Add(-time.Second), CompletedAt: &now, ExitCode: &exitCode, StdoutArtifactID: &artifactID}
	artifacts := []domain.Artifact{{ID: artifactID, TaskID: fixture.lineage.task.ID, WorkflowRunID: fixture.lineage.runID, StepRunID: fixture.stepID, ToolRunID: toolID, Type: "normalized-result", ContentType: "application/json", Size: int64(len(output)), SHA256: strings.Repeat("a", 64), StorageLocation: "synthetic://result.json", CreatedAt: now, RedactionState: "redacted"}}
	result := domain.ActionResult{RequestID: domain.NewID(), Status: "succeeded", Summary: "fixture result succeeded", Output: output, ArtifactIDs: []domain.ID{artifactID}}
	return step, tool, artifacts, result
}

func scheduledFixtureState(fixture scheduledResultFixture, runStatus domain.RunStatus, stepStatus domain.StepStatus) *workflow.State {
	now := time.Now().UTC()
	var runCompletedAt, stepCompletedAt *time.Time
	if recoveryRunTerminal(runStatus) {
		runCompletedAt = &now
	}
	if recoveryStepTerminal(stepStatus) {
		stepCompletedAt = &now
	}
	return &workflow.State{Run: domain.WorkflowRun{ID: fixture.lineage.runID, TaskID: fixture.lineage.task.ID, WorkflowDefinitionID: fixture.env.definitionID, WorkflowVersion: "1", Status: runStatus, StartedAt: &now, CompletedAt: runCompletedAt, TriggerSource: "run_now", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{"provider": {Run: domain.StepRun{ID: fixture.stepID, WorkflowRunID: fixture.lineage.runID, StepDefinitionID: "provider", Capability: fixture.capability, Status: stepStatus, AttemptCount: 1, Input: json.RawMessage(`{}`), Output: json.RawMessage(`{"preserved":true}`), StartedAt: &now, CompletedAt: stepCompletedAt, IdempotencyKey: fixture.idempotencyKey, ApprovalState: "not_required"}}}}
}

func assertScheduledResultRejectedNoMutation(t *testing.T, fixture scheduledResultFixture, ctx context.Context, step domain.StepRun, tool *domain.ToolRun, artifacts []domain.Artifact, result domain.ActionResult) {
	t.Helper()
	before := resultFenceSnapshot(t, fixture)
	err := fixture.env.store.PersistResult(ctx, fixture.env.programID, step, tool, artifacts, result)
	if !errors.Is(err, ErrStaleScheduledExecutionResult) {
		t.Fatalf("persist result error=%v want %v", err, ErrStaleScheduledExecutionResult)
	}
	after := resultFenceSnapshot(t, fixture)
	if after != before {
		t.Fatalf("rejected result mutated database\nbefore=%s\nafter=%s", before, after)
	}
}

func assertScheduledValidResultRejectedNoMutation(t *testing.T, fixture scheduledResultFixture, ctx context.Context) {
	t.Helper()
	step, tool, artifacts, result := fixture.validPayload()
	assertScheduledResultRejectedNoMutation(t, fixture, ctx, step, tool, artifacts, result)
}

func installPersistResultStepBarrier(t *testing.T, env recoveryTestEnvironment) {
	t.Helper()
	if _, err := env.store.Pool.Exec(env.ctx, `CREATE FUNCTION scheduler_result_step_barrier() RETURNS trigger AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(hashtext(NEW.id::text));
			RETURN NEW;
		END;
	$$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.Pool.Exec(env.ctx, `CREATE TRIGGER scheduler_result_step_barrier BEFORE UPDATE OF status ON step_runs FOR EACH ROW EXECUTE FUNCTION scheduler_result_step_barrier()`); err != nil {
		t.Fatal(err)
	}
}

func holdPersistResultStepBarrier(t *testing.T, env recoveryTestEnvironment, stepID domain.ID) func() {
	t.Helper()
	conn, err := env.store.Pool.Acquire(env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var key int32
	if err := conn.QueryRow(env.ctx, `SELECT hashtext($1::text)`, stepID).Scan(&key); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	if _, err := conn.Exec(env.ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	released := false
	return func() {
		if released {
			return
		}
		released = true
		if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key); err != nil {
			t.Errorf("release result step advisory lock: %v", err)
		}
		conn.Release()
	}
}

func waitForScheduledLeaseExpiry(t *testing.T, ctx context.Context, fixture scheduledResultFixture) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var expired bool
		if err := fixture.env.store.Pool.QueryRow(ctx, `SELECT lease_expires_at<=clock_timestamp() FROM scheduled_executions WHERE id=$1`, fixture.lineage.execution.ID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("scheduled lease did not expire: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func resultFenceSnapshot(t *testing.T, fixture scheduledResultFixture) string {
	t.Helper()
	var snapshot string
	err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT jsonb_build_object(
		'scheduled',(SELECT to_jsonb(se) FROM scheduled_executions se WHERE se.id=$1),
		'task',(SELECT to_jsonb(t) FROM tasks t WHERE t.id=$2),
		'workflow',(SELECT to_jsonb(wr) FROM workflow_runs wr WHERE wr.id=$3),
		'step',(SELECT to_jsonb(sr) FROM step_runs sr WHERE sr.id=$4),
		'tools',(SELECT COALESCE(jsonb_agg(to_jsonb(tr) ORDER BY tr.id),'[]'::jsonb) FROM tool_runs tr WHERE tr.step_run_id=$4),
		'artifacts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY a.id),'[]'::jsonb) FROM artifacts a WHERE a.workflow_run_id=$3),
		'assets',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY a.id),'[]'::jsonb) FROM assets a WHERE a.program_id=$5),
		'observations',(SELECT COALESCE(jsonb_agg(to_jsonb(ao) ORDER BY ao.id),'[]'::jsonb) FROM asset_observations ao JOIN assets a ON a.id=ao.asset_id WHERE a.program_id=$5),
		'candidates',(SELECT COALESCE(jsonb_agg(to_jsonb(cf) ORDER BY cf.id),'[]'::jsonb) FROM candidate_findings cf WHERE cf.workflow_run_id=$3),
		'changes',(SELECT COALESCE(jsonb_agg(to_jsonb(ci) ORDER BY ci.id),'[]'::jsonb) FROM change_items ci WHERE ci.workflow_run_id=$3),
		'approvals',(SELECT COALESCE(jsonb_agg(to_jsonb(ap) ORDER BY ap.id),'[]'::jsonb) FROM approvals ap WHERE ap.task_id=$2),
		'audits',(SELECT COALESCE(jsonb_agg(to_jsonb(ae) ORDER BY ae.id),'[]'::jsonb) FROM audit_events ae WHERE ae.workflow_run_id=$3 OR (ae.workflow_run_id IS NULL AND ae.task_id=$2))
	)::text`, fixture.lineage.execution.ID, fixture.lineage.task.ID, fixture.lineage.runID, fixture.stepID, fixture.env.programID).Scan(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertResultRowCounts(t *testing.T, fixture scheduledResultFixture, toolWant, artifactWant, observationWant, findingWant, toolAuditWant int) {
	t.Helper()
	var tools, artifacts, observations, findings, toolAudits int
	err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
		(SELECT count(*) FROM tool_runs WHERE step_run_id=$1),
		(SELECT count(*) FROM artifacts WHERE step_run_id=$1),
		(SELECT count(*) FROM asset_observations WHERE workflow_run_id=$2),
		(SELECT count(*) FROM candidate_findings WHERE workflow_run_id=$2),
		(SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type='tool_execution')`, fixture.stepID, fixture.lineage.runID).Scan(&tools, &artifacts, &observations, &findings, &toolAudits)
	if err != nil {
		t.Fatal(err)
	}
	if tools != toolWant || artifacts != artifactWant || observations != observationWant || findings != findingWant || toolAudits != toolAuditWant {
		t.Fatalf("result counts tools=%d artifacts=%d observations=%d findings=%d tool_audits=%d", tools, artifacts, observations, findings, toolAudits)
	}
}
