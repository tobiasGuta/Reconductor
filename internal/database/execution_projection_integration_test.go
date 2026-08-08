package database

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestExecutionProjectionIntegration(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "execution-projection")

	t.Run("pending execution has no optional lineage", func(t *testing.T) {
		schedule := createIntegrationSchedule(t, env.ctx, env.store, env.programID, "projection-pending")
		execution, err := env.store.EnqueueRunNow(env.ctx, schedule.ID, "integration")
		if err != nil {
			t.Fatal(err)
		}

		projection, err := env.store.GetExecutionProjection(env.ctx, execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.ObservedAt.IsZero() {
			t.Fatal("database observation time is zero")
		}
		if projection.Execution.ID != execution.ID || projection.Execution.ScheduleID != schedule.ID || projection.Execution.ProgramID != env.programID {
			t.Fatalf("execution identity = %#v", projection.Execution)
		}
		if projection.Scheduler.Status != domain.ScheduledExecutionPending || projection.Scheduler.LeaseState != ExecutionLeaseNotApplicable {
			t.Fatalf("scheduler = %#v", projection.Scheduler)
		}
		if projection.Task != nil || projection.Workflow != nil || projection.Scope != nil || len(projection.Steps) != 0 {
			t.Fatalf("unexpected optional lineage task=%#v workflow=%#v scope=%#v steps=%#v", projection.Task, projection.Workflow, projection.Scope, projection.Steps)
		}
		if projection.CurrentSchedule.Name != schedule.Name || projection.CurrentSchedule.Objective != schedule.Objective || projection.CurrentProgram.ID != env.programID {
			t.Fatalf("current context schedule=%#v program=%#v", projection.CurrentSchedule, projection.CurrentProgram)
		}
		if len(projection.Lineage.Issues) != 0 {
			t.Fatalf("lineage issues = %v", projection.Lineage.Issues)
		}
		claimed := enqueueSpecificProjectionExecution(t, env, execution.ID, "pending-cleanup")
		if err := env.store.MarkScheduledExecutionCancelled(env.ctx, claimed.ID, claimed.LeaseOwner, claimed.AttemptCount); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("claimed execution has an active lease", func(t *testing.T) {
		schedule := createIntegrationSchedule(t, env.ctx, env.store, env.programID, "projection-claimed")
		execution := enqueueAndClaim(t, env.ctx, env.store, schedule.ID, "projection-owner", time.Minute)

		projection, err := env.store.GetExecutionProjection(env.ctx, execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.Scheduler.Status != domain.ScheduledExecutionClaimed || projection.Scheduler.AttemptCount != 1 || projection.Scheduler.LeaseOwner != "projection-owner" || projection.Scheduler.LeaseExpiresAt == nil {
			t.Fatalf("scheduler = %#v", projection.Scheduler)
		}
		if projection.Scheduler.LeaseState != ExecutionLeaseActive {
			t.Fatalf("lease state = %q", projection.Scheduler.LeaseState)
		}
	})

	t.Run("claimed execution can expose an expired lease", func(t *testing.T) {
		schedule := createIntegrationSchedule(t, env.ctx, env.store, env.programID, "projection-expired")
		execution := enqueueAndClaim(t, env.ctx, env.store, schedule.ID, "expired-owner", time.Minute)
		expireRecoveryLease(t, env, execution.ID, 1)

		projection, err := env.store.GetExecutionProjection(env.ctx, execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.Scheduler.Status != domain.ScheduledExecutionClaimed || projection.Scheduler.LeaseState != ExecutionLeaseExpired {
			t.Fatalf("scheduler = %#v", projection.Scheduler)
		}
		reconcileRecovery(t, env)
		reclaimed := enqueueSpecificProjectionExecution(t, env, execution.ID, "expired-cleanup")
		if err := env.store.MarkScheduledExecutionCancelled(env.ctx, reclaimed.ID, reclaimed.LeaseOwner, reclaimed.AttemptCount); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("running execution retains independent state and assigned scope", func(t *testing.T) {
		running := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "projection-running", &running, domain.TaskRunning, []recoveryStepSpec{
			{name: "discover", status: domain.StepSucceeded, started: true, completed: true, attemptCount: 1},
			{name: "probe", status: domain.StepRunning, started: true, attemptCount: 2},
		})
		var scopeID domain.ID
		if err := env.store.Pool.QueryRow(env.ctx, `SELECT id FROM scope_versions WHERE program_id=$1 ORDER BY created_at DESC LIMIT 1`, env.programID).Scan(&scopeID); err != nil {
			t.Fatal(err)
		}
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE scheduled_executions SET scope_version_id=$2 WHERE id=$1`, fixture.execution.ID, scopeID); err != nil {
			t.Fatal(err)
		}
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE workflow_runs SET summary='{"secret":"workflow-summary"}'::jsonb WHERE id=$1`, fixture.runID); err != nil {
			t.Fatal(err)
		}
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE step_runs SET input='{"secret":"step-input"}'::jsonb,output='{"secret":"step-output"}'::jsonb,error_details='step-error-details' WHERE id=$1`, fixture.steps["probe"]); err != nil {
			t.Fatal(err)
		}

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.Scheduler.Status != domain.ScheduledExecutionRunning || projection.Scheduler.LeaseState != ExecutionLeaseActive {
			t.Fatalf("scheduler = %#v", projection.Scheduler)
		}
		if projection.Task == nil || projection.Task.Status != domain.TaskRunning {
			t.Fatalf("task = %#v", projection.Task)
		}
		if projection.Workflow == nil || projection.Workflow.Status != domain.RunRunning || projection.Workflow.DefinitionName == "" {
			t.Fatalf("workflow = %#v", projection.Workflow)
		}
		if containsLineageIssue(projection.Lineage.Issues, ExecutionLineageWorkflowDefinitionVersionMismatch) {
			t.Fatalf("matching workflow version reported mismatch: %v", projection.Lineage.Issues)
		}
		if projection.Scope == nil || projection.Scope.ID != scopeID || projection.Scope.ProgramID != env.programID {
			t.Fatalf("scope = %#v", projection.Scope)
		}
		if len(projection.Steps) != 2 || projection.Steps[0].Status != domain.StepSucceeded || projection.Steps[1].Status != domain.StepRunning {
			t.Fatalf("steps = %#v", projection.Steps)
		}
		encoded, err := json.Marshal(projection)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"workflow-summary", "step-input", "step-output", "step-error-details"} {
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("projection leaked %q: %s", secret, encoded)
			}
		}
	})

	t.Run("workflow definition version mismatch is visible without normalization", func(t *testing.T) {
		running := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "projection-version-mismatch", &running, domain.TaskRunning, []recoveryStepSpec{
			{name: "active", status: domain.StepRunning, started: true, attemptCount: 1},
		})
		const contradictoryRunVersion = "contradictory-version"
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE workflow_runs SET workflow_version=$2 WHERE id=$1`, fixture.runID, contradictoryRunVersion); err != nil {
			t.Fatal(err)
		}

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.Scheduler.Status != domain.ScheduledExecutionRunning || projection.Task == nil || projection.Task.Status != domain.TaskRunning || projection.Workflow == nil || projection.Workflow.Status != domain.RunRunning {
			t.Fatalf("mismatched projection scheduler=%#v task=%#v workflow=%#v", projection.Scheduler, projection.Task, projection.Workflow)
		}
		if projection.Workflow.WorkflowDefinitionID != env.definitionID || projection.Workflow.WorkflowVersion != contradictoryRunVersion {
			t.Fatalf("workflow identity/version was normalized: %#v", projection.Workflow)
		}
		if got := countLineageIssue(projection.Lineage.Issues, ExecutionLineageWorkflowDefinitionVersionMismatch); got != 1 {
			t.Fatalf("version mismatch issue count = %d, want 1; issues=%v", got, projection.Lineage.Issues)
		}
	})

	t.Run("completed execution preserves terminal states and released lease", func(t *testing.T) {
		completed := domain.RunCompleted
		fixture := createRecoveryFixture(t, env, "projection-completed", &completed, domain.TaskCompleted, []recoveryStepSpec{
			{name: "done", status: domain.StepSucceeded, started: true, completed: true, attemptCount: 1},
		})
		if err := env.store.MarkScheduledExecutionCompleted(env.ctx, fixture.execution.ID, "projection-completed-owner", fixture.execution.AttemptCount); err != nil {
			t.Fatal(err)
		}

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.Scheduler.Status != domain.ScheduledExecutionCompleted || projection.Scheduler.LeaseState != ExecutionLeaseReleased {
			t.Fatalf("scheduler = %#v", projection.Scheduler)
		}
		if projection.Task == nil || projection.Task.Status != domain.TaskCompleted || projection.Workflow == nil || projection.Workflow.Status != domain.RunCompleted || projection.Steps[0].Status != domain.StepSucceeded {
			t.Fatalf("terminal projection task=%#v workflow=%#v steps=%#v", projection.Task, projection.Workflow, projection.Steps)
		}
	})

	t.Run("interrupted recovery remains independently visible", func(t *testing.T) {
		running := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "projection-interrupted", &running, domain.TaskRunning, []recoveryStepSpec{
			{name: "active", status: domain.StepRunning, started: true, attemptCount: 1},
		})
		expireRecoveryLease(t, env, fixture.execution.ID, 1)
		reconcileRecovery(t, env)

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.Scheduler.Status != domain.ScheduledExecutionInterrupted || projection.Scheduler.LeaseState != ExecutionLeaseReleased {
			t.Fatalf("scheduler = %#v", projection.Scheduler)
		}
		if projection.Task == nil || projection.Task.Status != domain.TaskFailed || projection.Workflow == nil || projection.Workflow.Status != domain.RunFailed || projection.Steps[0].Status != domain.StepFailed {
			t.Fatalf("interrupted projection task=%#v workflow=%#v steps=%#v", projection.Task, projection.Workflow, projection.Steps)
		}
	})

	t.Run("reconciliation window is not normalized", func(t *testing.T) {
		completed := domain.RunCompleted
		fixture := createRecoveryFixture(t, env, "projection-reconciliation", &completed, domain.TaskCompleted, []recoveryStepSpec{
			{name: "done", status: domain.StepSucceeded, started: true, completed: true, attemptCount: 1},
		})

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.Scheduler.Status != domain.ScheduledExecutionRunning || projection.Task == nil || projection.Task.Status != domain.TaskCompleted || projection.Workflow == nil || projection.Workflow.Status != domain.RunCompleted {
			t.Fatalf("reconciliation projection scheduler=%#v task=%#v workflow=%#v", projection.Scheduler, projection.Task, projection.Workflow)
		}
	})

	t.Run("workflow without execution task is explicit", func(t *testing.T) {
		running := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "projection-missing-task-link", &running, domain.TaskRunning, []recoveryStepSpec{
			{name: "active", status: domain.StepRunning, started: true, attemptCount: 1},
		})
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE scheduled_executions SET task_id=NULL WHERE id=$1`, fixture.execution.ID); err != nil {
			t.Fatal(err)
		}

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.Task != nil || projection.Workflow == nil || len(projection.Steps) != 1 || !containsLineageIssue(projection.Lineage.Issues, ExecutionLineageWorkflowWithoutTask) {
			t.Fatalf("lineage task=%#v workflow=%#v steps=%#v issues=%v", projection.Task, projection.Workflow, projection.Steps, projection.Lineage.Issues)
		}
	})

	t.Run("inconsistent lease fields are reported", func(t *testing.T) {
		schedule := createIntegrationSchedule(t, env.ctx, env.store, env.programID, "projection-inconsistent-lease")
		execution := enqueueAndClaim(t, env.ctx, env.store, schedule.ID, "inconsistent-owner", time.Minute)
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE scheduled_executions SET lease_owner='' WHERE id=$1`, execution.ID); err != nil {
			t.Fatal(err)
		}

		projection, err := env.store.GetExecutionProjection(env.ctx, execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.Scheduler.LeaseState != ExecutionLeaseInconsistent {
			t.Fatalf("lease state = %q", projection.Scheduler.LeaseState)
		}
	})

	t.Run("missing execution returns typed error", func(t *testing.T) {
		_, err := env.store.GetExecutionProjection(env.ctx, domain.NewID())
		if !errors.Is(err, ErrScheduledExecutionNotFound) {
			t.Fatalf("error = %v, want ErrScheduledExecutionNotFound", err)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("database error leaked through not-found contract: %v", err)
		}
	})

	t.Run("repeatable read keeps one internally consistent snapshot", func(t *testing.T) {
		running := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "projection-snapshot", &running, domain.TaskRunning, []recoveryStepSpec{
			{name: "active", status: domain.StepRunning, started: true, attemptCount: 1},
		})
		ctx, cancel := context.WithTimeout(env.ctx, 15*time.Second)
		defer cancel()
		readTx, err := env.store.beginExecutionProjection(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer readTx.Rollback(context.Background())

		rootRead := make(chan struct{})
		continueRead := make(chan struct{})
		query := &projectionRootBarrier{
			executionProjectionQuerier: readTx,
			ctx:                        ctx,
			rootRead:                   rootRead,
			continueRead:               continueRead,
		}
		type projectionResult struct {
			projection ExecutionProjection
			err        error
		}
		result := make(chan projectionResult, 1)
		go func() {
			projection, queryErr := queryExecutionProjection(ctx, query, fixture.execution.ID)
			result <- projectionResult{projection: projection, err: queryErr}
		}()

		select {
		case <-rootRead:
		case <-ctx.Done():
			t.Fatalf("projection root was not read: %v", ctx.Err())
		}

		writeTx, err := env.store.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		committed := false
		defer func() {
			if !committed {
				writeTx.Rollback(context.Background())
			}
		}()
		completedAt := time.Now().UTC()
		if _, err := writeTx.Exec(ctx, `UPDATE tasks SET status='completed',updated_at=$2 WHERE id=$1`, fixture.task.ID, completedAt); err != nil {
			t.Fatal(err)
		}
		if _, err := writeTx.Exec(ctx, `UPDATE workflow_runs SET status='completed',completed_at=$2 WHERE id=$1`, fixture.runID, completedAt); err != nil {
			t.Fatal(err)
		}
		if _, err := writeTx.Exec(ctx, `UPDATE step_runs SET status='succeeded',completed_at=$2 WHERE id=$1`, fixture.steps["active"], completedAt); err != nil {
			t.Fatal(err)
		}
		if err := writeTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		committed = true
		close(continueRead)

		var first projectionResult
		select {
		case first = <-result:
		case <-ctx.Done():
			t.Fatalf("projection did not complete: %v", ctx.Err())
		}
		if first.err != nil {
			t.Fatal(first.err)
		}
		if first.projection.Task == nil || first.projection.Task.Status != domain.TaskRunning || first.projection.Workflow == nil || first.projection.Workflow.Status != domain.RunRunning || first.projection.Steps[0].Status != domain.StepRunning {
			t.Fatalf("first snapshot task=%#v workflow=%#v steps=%#v", first.projection.Task, first.projection.Workflow, first.projection.Steps)
		}
		if err := readTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}

		second, err := env.store.GetExecutionProjection(ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if second.Task == nil || second.Task.Status != domain.TaskCompleted || second.Workflow == nil || second.Workflow.Status != domain.RunCompleted || second.Steps[0].Status != domain.StepSucceeded {
			t.Fatalf("second snapshot task=%#v workflow=%#v steps=%#v", second.Task, second.Workflow, second.Steps)
		}
	})
}

func enqueueSpecificProjectionExecution(t *testing.T, env recoveryTestEnvironment, executionID domain.ID, owner string) domain.ScheduledExecution {
	t.Helper()
	claimed, _, ok, err := env.store.ClaimPendingScheduledExecution(env.ctx, owner, time.Minute)
	if err != nil || !ok || claimed.ID != executionID {
		t.Fatalf("claim execution=%#v ok=%v err=%v, want %s", claimed, ok, err, executionID)
	}
	return claimed
}

type projectionRootBarrier struct {
	executionProjectionQuerier
	ctx          context.Context
	rootRead     chan struct{}
	continueRead chan struct{}
}

func (query *projectionRootBarrier) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	row := query.executionProjectionQuerier.QueryRow(ctx, sql, args...)
	if !strings.Contains(sql, "FROM scheduled_executions se") {
		return row
	}
	return &projectionBarrierRow{
		Row:          row,
		ctx:          query.ctx,
		rootRead:     query.rootRead,
		continueRead: query.continueRead,
	}
}

type projectionBarrierRow struct {
	pgx.Row
	ctx          context.Context
	rootRead     chan struct{}
	continueRead chan struct{}
}

func (row *projectionBarrierRow) Scan(dest ...any) error {
	err := row.Row.Scan(dest...)
	close(row.rootRead)
	if err != nil {
		return err
	}
	select {
	case <-row.continueRead:
		return nil
	case <-row.ctx.Done():
		return row.ctx.Err()
	}
}

func containsLineageIssue(issues []ExecutionLineageIssue, want ExecutionLineageIssue) bool {
	return countLineageIssue(issues, want) > 0
}

func countLineageIssue(issues []ExecutionLineageIssue, want ExecutionLineageIssue) int {
	count := 0
	for _, issue := range issues {
		if issue == want {
			count++
		}
	}
	return count
}
