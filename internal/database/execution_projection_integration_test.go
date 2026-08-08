package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
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

		tx, err := env.store.beginExecutionProjection(env.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		counter := &projectionQueryCounter{executionProjectionQuerier: tx}
		projection, err := queryExecutionProjection(env.ctx, counter, execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if counter.count != 1 {
			t.Fatalf("pending projection query count = %d, want root query only", counter.count)
		}
		if err := tx.Commit(env.ctx); err != nil {
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
		if projection.ToolRuns.Items == nil || projection.Approvals.Items == nil || projection.Artifacts.Items == nil || projection.Candidates.Items == nil ||
			projection.ToolRuns.Total != 0 || projection.Approvals.Total != 0 || projection.Artifacts.Total != 0 || projection.Candidates.Total != 0 ||
			projection.ToolRuns.Truncated || projection.Approvals.Truncated || projection.Artifacts.Truncated || projection.Candidates.Truncated {
			t.Fatalf("empty children tools=%#v approvals=%#v artifacts=%#v candidates=%#v", projection.ToolRuns, projection.Approvals, projection.Artifacts, projection.Candidates)
		}
		if projection.AssetObservations.Total != 0 || projection.AssetObservations.DistinctAssetCount != 0 {
			t.Fatalf("pending observation summary = %#v", projection.AssetObservations)
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
		toolID, approvalID, artifactID, assetID, candidateID, observationID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
		if _, err := writeTx.Exec(ctx, `UPDATE tasks SET status='completed',updated_at=$2 WHERE id=$1`, fixture.task.ID, completedAt); err != nil {
			t.Fatal(err)
		}
		if _, err := writeTx.Exec(ctx, `UPDATE workflow_runs SET status='completed',completed_at=$2 WHERE id=$1`, fixture.runID, completedAt); err != nil {
			t.Fatal(err)
		}
		if _, err := writeTx.Exec(ctx, `UPDATE step_runs SET status='succeeded',completed_at=$2 WHERE id=$1`, fixture.steps["active"], completedAt); err != nil {
			t.Fatal(err)
		}
		if _, err := writeTx.Exec(ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,tool_version,sanitized_arguments,execution_environment,started_at,completed_at,exit_code,timed_out) VALUES($1,$2,'test.active','snapshot','1','{}','{}',$3,$3,0,false)`, toolID, fixture.steps["active"], completedAt); err != nil {
			t.Fatal(err)
		}
		if _, err := writeTx.Exec(ctx, `INSERT INTO approvals(id,request_id,task_id,action_request_id,requested_risk_level,reason,requested_at,decision) VALUES($1,$2,$3,$4,'moderate','snapshot child',$5,'pending')`, approvalID, fixture.steps["active"], fixture.task.ID, domain.NewID(), completedAt); err != nil {
			t.Fatal(err)
		}
		if _, err := writeTx.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,storage_location,created_at,expires_at,redaction_state,sensitive) VALUES($1,$2,$3,$4,$5,'normalized-result','application/json',2,'snapshot-sha','snapshot://hidden',$6,$7,'redacted',false)`, artifactID, fixture.task.ID, fixture.runID, fixture.steps["active"], toolID, completedAt, completedAt.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := writeTx.Exec(ctx, `INSERT INTO assets(id,program_id,type,canonical_value,created_at,updated_at) VALUES($1,$2,'url','https://snapshot-candidate.example.test/',$3,$3)`, assetID, env.programID, completedAt); err != nil {
			t.Fatal(err)
		}
		if _, err := writeTx.Exec(ctx, `INSERT INTO candidate_findings(id,task_id,workflow_run_id,target_asset_id,source_capability,template_id,claimed_vulnerability,severity,evidence_artifact_ids,detection_confidence,status,created_at,updated_at) VALUES($1,$2,$3,$4,'scan.nuclei','snapshot-template','snapshot candidate','medium','{}',0.7,'new',$5,$5)`, candidateID, fixture.task.ID, fixture.runID, assetID, completedAt); err != nil {
			t.Fatal(err)
		}
		if _, err := writeTx.Exec(ctx, `INSERT INTO asset_observations(id,asset_id,workflow_run_id,source_capability,observed_value,metadata,first_seen_at,observed_at,confidence,evidence_artifact_ids) VALUES($1,$2,$3,'probe.http','snapshot-observation','{}',$4,$4,1,'{}')`, observationID, assetID, fixture.runID, completedAt); err != nil {
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
		if first.projection.ToolRuns.Total != 0 || first.projection.Approvals.Total != 0 || first.projection.Artifacts.Total != 0 || first.projection.Candidates.Total != 0 || first.projection.AssetObservations.Total != 0 || first.projection.AssetObservations.DistinctAssetCount != 0 {
			t.Fatalf("first snapshot saw later children tools=%#v approvals=%#v artifacts=%#v candidates=%#v observations=%#v", first.projection.ToolRuns, first.projection.Approvals, first.projection.Artifacts, first.projection.Candidates, first.projection.AssetObservations)
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
		if second.ToolRuns.Total != 1 || second.Approvals.Total != 1 || second.Artifacts.Total != 1 || second.Candidates.Total != 1 || second.Candidates.Items[0].ID != candidateID || second.AssetObservations.Total != 1 || second.AssetObservations.DistinctAssetCount != 1 {
			t.Fatalf("second snapshot children tools=%#v approvals=%#v artifacts=%#v candidates=%#v observations=%#v", second.ToolRuns, second.Approvals, second.Artifacts, second.Candidates, second.AssetObservations)
		}
	})
}

func TestExecutionProjectionEvidenceChildrenIntegration(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "execution-projection-evidence")

	t.Run("tool membership ordering incomplete outcome and truncation", func(t *testing.T) {
		running := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "projection-tools", &running, domain.TaskRunning, []recoveryStepSpec{
			{name: "alpha", status: domain.StepRunning, started: true, attemptCount: 1},
			{name: "beta", status: domain.StepRunning, started: true, attemptCount: 1},
		})
		started := time.Now().UTC().Add(-time.Minute)
		firstID, secondID := domain.NewID(), domain.NewID()
		ids := []domain.ID{firstID, secondID}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		completed := started.Add(time.Second)
		exitCode := 0
		insertProjectionTool(t, env, firstID, fixture.steps["alpha"], "test.alpha", started, &completed, &exitCode, `{"secret":"tool-arguments-sentinel"}`, `{"secret":"tool-environment-sentinel"}`)
		insertProjectionTool(t, env, secondID, fixture.steps["beta"], "test.beta", started, nil, nil, `{}`, `{}`)

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.ToolRuns.Total != 2 || len(projection.ToolRuns.Items) != 2 || projection.ToolRuns.Truncated {
			t.Fatalf("tools = %#v", projection.ToolRuns)
		}
		if projection.ToolRuns.Items[0].ID != ids[0] || projection.ToolRuns.Items[1].ID != ids[1] {
			t.Fatalf("tool order = %s,%s want %s,%s", projection.ToolRuns.Items[0].ID, projection.ToolRuns.Items[1].ID, ids[0], ids[1])
		}
		for _, item := range projection.ToolRuns.Items {
			wantStep := map[domain.ID]string{firstID: "alpha", secondID: "beta"}[item.ID]
			if item.StepRunID != fixture.steps[wantStep] || item.StepDefinitionID != wantStep {
				t.Fatalf("tool step lineage = %#v want step %q", item, wantStep)
			}
		}
		incomplete := projection.ToolRuns.Items[0]
		if incomplete.ID != secondID {
			incomplete = projection.ToolRuns.Items[1]
		}
		if incomplete.CompletedAt != nil || incomplete.ExitCode != nil {
			t.Fatalf("incomplete tool synthesized outcome: %#v", incomplete)
		}
		encoded, err := json.Marshal(incomplete)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), `"status"`) {
			t.Fatalf("tool DTO invented status: %s", encoded)
		}

		limited := createRecoveryFixture(t, env, "projection-tool-limit", &running, domain.TaskRunning, []recoveryStepSpec{{name: "tool-limit", status: domain.StepRunning, started: true, attemptCount: 1}})
		for index := 0; index < executionProjectionToolRunLimit+1; index++ {
			when := started.Add(time.Duration(index) * time.Millisecond)
			insertProjectionTool(t, env, domain.NewID(), limited.steps["tool-limit"], "test.tool-limit", when, &when, &exitCode, `{}`, `{}`)
		}
		bounded, err := env.store.GetExecutionProjection(env.ctx, limited.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if bounded.ToolRuns.Total != int64(executionProjectionToolRunLimit+1) || len(bounded.ToolRuns.Items) != executionProjectionToolRunLimit || !bounded.ToolRuns.Truncated {
			t.Fatalf("bounded tools = %#v", bounded.ToolRuns)
		}
	})

	t.Run("approval step membership contradiction and truncation", func(t *testing.T) {
		running := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "projection-approvals", &running, domain.TaskRunning, []recoveryStepSpec{
			{name: "one", status: domain.StepAwaitingApproval, approvalState: "not_required"},
			{name: "two", status: domain.StepAwaitingApproval, approvalState: "not_required"},
			{name: "three", status: domain.StepAwaitingApproval, approvalState: "not_required"},
		})
		otherTask := domain.Task{ID: domain.NewID(), ProgramID: env.programID, Objective: "approval contradiction", WorkflowDefinitionID: env.definitionID, Status: domain.TaskPending, RequestedBy: "integration", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
		if err := env.store.CreateTask(env.ctx, otherTask); err != nil {
			t.Fatal(err)
		}
		requested := time.Now().UTC()
		validID := insertProjectionApproval(t, env, fixture.steps["one"], fixture.task.ID, requested)
		contradictoryIDs := []domain.ID{
			insertProjectionApproval(t, env, fixture.steps["two"], otherTask.ID, requested.Add(time.Millisecond)),
			insertProjectionApproval(t, env, fixture.steps["three"], otherTask.ID, requested.Add(2*time.Millisecond)),
		}

		otherRunID, otherStepID := domain.NewID(), domain.NewID()
		if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,trigger_source,summary) VALUES($1,$2,$3,'1','running',$4,'integration','{}')`, otherRunID, fixture.task.ID, env.definitionID, requested); err != nil {
			t.Fatal(err)
		}
		if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,idempotency_key) VALUES($1,$2,'other','test.other','awaiting_approval',$3)`, otherStepID, otherRunID, "approval-other-"+string(otherStepID)); err != nil {
			t.Fatal(err)
		}
		excludedID := insertProjectionApproval(t, env, otherStepID, fixture.task.ID, requested.Add(3*time.Millisecond))

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.Approvals.Total != 3 || len(projection.Approvals.Items) != 3 || projection.Approvals.Truncated {
			t.Fatalf("approvals = %#v", projection.Approvals)
		}
		seen := map[domain.ID]bool{}
		for _, item := range projection.Approvals.Items {
			seen[item.ID] = true
		}
		if !seen[validID] || !seen[contradictoryIDs[0]] || !seen[contradictoryIDs[1]] || seen[excludedID] {
			t.Fatalf("approval membership = %#v", seen)
		}
		if got := countLineageIssue(projection.Lineage.Issues, ExecutionLineageApprovalInconsistent); got != 1 {
			t.Fatalf("approval lineage issue count = %d, issues=%v", got, projection.Lineage.Issues)
		}

		specs := make([]recoveryStepSpec, 0, executionProjectionApprovalLimit+1)
		for index := 0; index < executionProjectionApprovalLimit+1; index++ {
			specs = append(specs, recoveryStepSpec{name: fmt.Sprintf("approval-%02d", index), status: domain.StepAwaitingApproval, approvalState: "not_required"})
		}
		limited := createRecoveryFixture(t, env, "projection-approval-limit", &running, domain.TaskRunning, specs)
		var contradictoryAfterLimitID domain.ID
		for index, spec := range specs {
			taskID := limited.task.ID
			if index == executionProjectionApprovalLimit {
				taskID = otherTask.ID
			}
			approvalID := insertProjectionApproval(t, env, limited.steps[spec.name], taskID, requested.Add(time.Duration(index)*time.Millisecond))
			if index == executionProjectionApprovalLimit {
				contradictoryAfterLimitID = approvalID
			}
		}
		bounded, err := env.store.GetExecutionProjection(env.ctx, limited.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if bounded.Approvals.Total != int64(executionProjectionApprovalLimit+1) || len(bounded.Approvals.Items) != executionProjectionApprovalLimit || !bounded.Approvals.Truncated {
			t.Fatalf("bounded approvals = %#v", bounded.Approvals)
		}
		for _, item := range bounded.Approvals.Items {
			if item.ID == contradictoryAfterLimitID {
				t.Fatalf("contradictory approval after limit was returned: %s", contradictoryAfterLimitID)
			}
		}
		if got := countLineageIssue(bounded.Lineage.Issues, ExecutionLineageApprovalInconsistent); got != 1 {
			t.Fatalf("bounded approval lineage issue count = %d, issues=%v", got, bounded.Lineage.Issues)
		}
	})

	t.Run("artifact visibility contradiction security and truncation", func(t *testing.T) {
		running := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "projection-artifacts", &running, domain.TaskRunning, []recoveryStepSpec{{name: "artifact", status: domain.StepRunning, started: true, attemptCount: 1}})
		now := time.Now().UTC()
		completed, exitCode := now, 0
		toolID := domain.NewID()
		insertProjectionTool(t, env, toolID, fixture.steps["artifact"], "test.artifact", now.Add(-time.Second), &completed, &exitCode, `{"secret":"artifact-tool-arguments-sentinel"}`, `{"secret":"artifact-tool-environment-sentinel"}`)
		visibleID := insertProjectionArtifact(t, env, projectionArtifactSpec{
			TaskID: fixture.task.ID, WorkflowRunID: fixture.runID, StepRunID: fixture.steps["artifact"], ToolRunID: toolID,
			Type: "normalized-result", StorageLocation: "artifact://visible-storage-sentinel", ExpiresAt: timePointer(now.Add(time.Hour)),
		})
		insertProjectionArtifact(t, env, projectionArtifactSpec{
			TaskID: fixture.task.ID, WorkflowRunID: fixture.runID, StepRunID: fixture.steps["artifact"], ToolRunID: toolID,
			Type: "sensitive-type-sentinel", StorageLocation: "artifact://sensitive-storage-sentinel", Sensitive: true, ExpiresAt: timePointer(now.Add(time.Hour)),
		})
		insertProjectionArtifact(t, env, projectionArtifactSpec{
			TaskID: fixture.task.ID, WorkflowRunID: fixture.runID, StepRunID: fixture.steps["artifact"], ToolRunID: toolID,
			Type: "expired-type-sentinel", StorageLocation: "artifact://expired-storage-sentinel", ExpiresAt: timePointer(now.Add(-time.Hour)),
		})

		other := createRecoveryFixture(t, env, "projection-artifact-other", &running, domain.TaskRunning, []recoveryStepSpec{{name: "other", status: domain.StepRunning, started: true, attemptCount: 1}})
		otherToolID := domain.NewID()
		insertProjectionTool(t, env, otherToolID, other.steps["other"], "test.other", now, &completed, &exitCode, `{}`, `{}`)
		contradictoryID := insertProjectionArtifact(t, env, projectionArtifactSpec{
			TaskID: other.task.ID, WorkflowRunID: fixture.runID, StepRunID: other.steps["other"], ToolRunID: otherToolID,
			Type: "contradictory", StorageLocation: "artifact://contradictory-storage-sentinel", ExpiresAt: timePointer(now.Add(time.Hour)),
		})

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.Artifacts.Total != 2 || len(projection.Artifacts.Items) != 2 || projection.Artifacts.Truncated {
			t.Fatalf("artifacts = %#v", projection.Artifacts)
		}
		seen := map[domain.ID]bool{}
		for _, item := range projection.Artifacts.Items {
			seen[item.ID] = true
		}
		if !seen[visibleID] || !seen[contradictoryID] {
			t.Fatalf("artifact membership = %#v", seen)
		}
		if got := countLineageIssue(projection.Lineage.Issues, ExecutionLineageArtifactInconsistent); got != 1 {
			t.Fatalf("artifact lineage issue count = %d, issues=%v", got, projection.Lineage.Issues)
		}
		encoded, err := json.Marshal(projection)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{
			"artifact-tool-arguments-sentinel", "artifact-tool-environment-sentinel",
			"visible-storage-sentinel", "sensitive-type-sentinel", "sensitive-storage-sentinel",
			"expired-type-sentinel", "expired-storage-sentinel", "contradictory-storage-sentinel",
		} {
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("projection leaked %q: %s", secret, encoded)
			}
		}

		limited := createRecoveryFixture(t, env, "projection-artifact-limit", &running, domain.TaskRunning, []recoveryStepSpec{{name: "artifact-limit", status: domain.StepRunning, started: true, attemptCount: 1}})
		limitedToolID := domain.NewID()
		insertProjectionTool(t, env, limitedToolID, limited.steps["artifact-limit"], "test.artifact-limit", now, &completed, &exitCode, `{}`, `{}`)
		var contradictoryAfterLimitID domain.ID
		for index := 0; index < executionProjectionArtifactLimit+1; index++ {
			created := now.Add(time.Duration(index) * time.Millisecond)
			taskID, stepRunID, toolRunID := limited.task.ID, limited.steps["artifact-limit"], limitedToolID
			if index == executionProjectionArtifactLimit {
				taskID, stepRunID, toolRunID = other.task.ID, other.steps["other"], otherToolID
			}
			artifactID := insertProjectionArtifact(t, env, projectionArtifactSpec{
				TaskID: taskID, WorkflowRunID: limited.runID, StepRunID: stepRunID, ToolRunID: toolRunID,
				Type: "normalized-result", StorageLocation: fmt.Sprintf("artifact://limit/%d", index), CreatedAt: &created, ExpiresAt: timePointer(now.Add(time.Hour)),
			})
			if index == executionProjectionArtifactLimit {
				contradictoryAfterLimitID = artifactID
			}
		}
		bounded, err := env.store.GetExecutionProjection(env.ctx, limited.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if bounded.Artifacts.Total != int64(executionProjectionArtifactLimit+1) || len(bounded.Artifacts.Items) != executionProjectionArtifactLimit || !bounded.Artifacts.Truncated {
			t.Fatalf("bounded artifacts = %#v", bounded.Artifacts)
		}
		for _, item := range bounded.Artifacts.Items {
			if item.ID == contradictoryAfterLimitID {
				t.Fatalf("contradictory artifact after limit was returned: %s", contradictoryAfterLimitID)
			}
		}
		if got := countLineageIssue(bounded.Lineage.Issues, ExecutionLineageArtifactInconsistent); got != 1 {
			t.Fatalf("bounded artifact lineage issue count = %d, issues=%v", got, bounded.Lineage.Issues)
		}
	})

	t.Run("query count remains fixed at maximum", func(t *testing.T) {
		running := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "projection-query-count", &running, domain.TaskRunning, []recoveryStepSpec{
			{name: "a", status: domain.StepRunning, started: true, attemptCount: 1},
			{name: "b", status: domain.StepRunning, started: true, attemptCount: 1},
			{name: "c", status: domain.StepRunning, started: true, attemptCount: 1},
		})
		var scopeID domain.ID
		if err := env.store.Pool.QueryRow(env.ctx, `SELECT id FROM scope_versions WHERE program_id=$1 ORDER BY created_at DESC LIMIT 1`, env.programID).Scan(&scopeID); err != nil {
			t.Fatal(err)
		}
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE scheduled_executions SET scope_version_id=$2 WHERE id=$1`, fixture.execution.ID, scopeID); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		exitCode := 0
		for index, stepName := range []string{"a", "b", "c"} {
			toolID := domain.NewID()
			insertProjectionTool(t, env, toolID, fixture.steps[stepName], "test."+stepName, now.Add(time.Duration(index)*time.Millisecond), &now, &exitCode, `{}`, `{}`)
			insertProjectionApproval(t, env, fixture.steps[stepName], fixture.task.ID, now.Add(time.Duration(index)*time.Millisecond))
			insertProjectionArtifact(t, env, projectionArtifactSpec{TaskID: fixture.task.ID, WorkflowRunID: fixture.runID, StepRunID: fixture.steps[stepName], ToolRunID: toolID, Type: "normalized-result", ExpiresAt: timePointer(now.Add(time.Hour))})
		}
		for index := 0; index < 3; index++ {
			assetID := insertProjectionAsset(t, env, env.programID, fmt.Sprintf("https://query-count-%d.example.test/", index))
			insertProjectionCandidate(t, env, projectionCandidateSpec{
				TaskID: fixture.task.ID, WorkflowRunID: fixture.runID, TargetAssetID: assetID,
				TemplateID: fmt.Sprintf("query-count-%d", index), CreatedAt: now.Add(time.Duration(index) * time.Millisecond),
			})
			for observationIndex := 0; observationIndex < 2; observationIndex++ {
				insertProjectionObservation(t, env, projectionObservationSpec{
					AssetID: assetID, WorkflowRunID: fixture.runID,
					SourceCapability: fmt.Sprintf("query.count.%d", observationIndex),
					ObservedValue:    fmt.Sprintf("query-count-%d-%d", index, observationIndex),
				})
			}
		}

		tx, err := env.store.beginExecutionProjection(env.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		counter := &projectionQueryCounter{executionProjectionQuerier: tx}
		projection, err := queryExecutionProjection(env.ctx, counter, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if counter.count != 10 {
			t.Fatalf("projection query count = %d, want 10", counter.count)
		}
		if len(projection.Steps) != 3 || projection.ToolRuns.Total != 3 || projection.Approvals.Total != 3 || projection.Artifacts.Total != 3 || projection.Candidates.Total != 3 || projection.AssetObservations.Total != 6 || projection.AssetObservations.DistinctAssetCount != 3 {
			t.Fatalf("counted projection steps=%d tools=%#v approvals=%#v artifacts=%#v candidates=%#v observations=%#v", len(projection.Steps), projection.ToolRuns, projection.Approvals, projection.Artifacts, projection.Candidates, projection.AssetObservations)
		}
		if err := tx.Commit(env.ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestExecutionProjectionCandidateChildrenIntegration(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "execution-projection-candidates")
	running := domain.RunRunning

	t.Run("workflow membership security and mutable current state", func(t *testing.T) {
		fixture := createRecoveryFixture(t, env, "projection-candidate-membership", &running, domain.TaskRunning, nil)
		now := time.Now().UTC()
		evidenceID := domain.NewID()
		visibleAssetID := insertProjectionAsset(t, env, env.programID, "https://candidate-target-sentinel.example.test/private?token=target-sentinel")
		visibleID := insertProjectionCandidate(t, env, projectionCandidateSpec{
			TaskID: fixture.task.ID, WorkflowRunID: fixture.runID, TargetAssetID: visibleAssetID,
			TemplateID: "candidate-template-sentinel", ClaimedVulnerability: "candidate-claim-sentinel",
			Severity: "candidate-severity-sentinel", EvidenceArtifactIDs: []domain.ID{evidenceID}, CreatedAt: now,
		})

		otherRunID := domain.NewID()
		if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,trigger_source,summary) VALUES($1,$2,$3,'1','running',$4,'integration','{}')`, otherRunID, fixture.task.ID, env.definitionID, now); err != nil {
			t.Fatal(err)
		}
		otherAssetID := insertProjectionAsset(t, env, env.programID, "https://other-workflow.example.test/")
		excludedID := insertProjectionCandidate(t, env, projectionCandidateSpec{
			TaskID: fixture.task.ID, WorkflowRunID: otherRunID, TargetAssetID: otherAssetID, TemplateID: "other-workflow", CreatedAt: now,
		})

		first, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if first.Candidates.Total != 1 || len(first.Candidates.Items) != 1 || first.Candidates.Truncated {
			t.Fatalf("candidates = %#v", first.Candidates)
		}
		candidate := first.Candidates.Items[0]
		if candidate.ID != visibleID || candidate.ID == excludedID || candidate.TaskID != fixture.task.ID || candidate.WorkflowRunID != fixture.runID || candidate.TargetAssetID != visibleAssetID {
			t.Fatalf("candidate membership = %#v excluded=%s", candidate, excludedID)
		}
		if candidate.SourceCapability != "scan.nuclei" || candidate.DetectionConfidence != 0.7 || candidate.Status != "new" || len(candidate.EvidenceArtifactIDs) != 1 || candidate.EvidenceArtifactIDs[0] != evidenceID {
			t.Fatalf("candidate allow-list fields = %#v", candidate)
		}
		encoded, err := json.Marshal(first)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"candidate-target-sentinel", "candidate-template-sentinel", "candidate-claim-sentinel", "candidate-severity-sentinel"} {
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("projection leaked %q: %s", secret, encoded)
			}
		}
		if !strings.Contains(string(encoded), string(evidenceID)) {
			t.Fatalf("opaque evidence reference missing: %s", encoded)
		}

		firstUpdatedAt := first.Candidates.Items[0].UpdatedAt
		updatedAt := now.Add(time.Hour)
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE candidate_findings SET status='needs_manual_review',updated_at=$2 WHERE id=$1`, visibleID, updatedAt); err != nil {
			t.Fatal(err)
		}
		second, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if first.Candidates.Items[0].Status != "new" {
			t.Fatalf("first projection was mutated: %#v", first.Candidates.Items[0])
		}
		if second.Candidates.Items[0].Status != "needs_manual_review" || !second.Candidates.Items[0].UpdatedAt.After(firstUpdatedAt) {
			t.Fatalf("second projection did not observe mutable state: %#v", second.Candidates.Items[0])
		}
	})

	t.Run("task and asset program contradictions are aggregate diagnostics", func(t *testing.T) {
		fixture := createRecoveryFixture(t, env, "projection-candidate-contradictions", &running, domain.TaskRunning, nil)
		now := time.Now().UTC()
		otherTask := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "candidate-contradiction")
		otherProgramID, _ := createSchedulerIntegrationProgram(t, env.ctx, env.store, "candidate-other-program")
		validAssetID := insertProjectionAsset(t, env, env.programID, "https://candidate-valid.example.test/")
		otherProgramAssetID := insertProjectionAsset(t, env, otherProgramID, "https://candidate-other-program.example.test/")

		ids := []domain.ID{
			insertProjectionCandidate(t, env, projectionCandidateSpec{TaskID: fixture.task.ID, WorkflowRunID: fixture.runID, TargetAssetID: validAssetID, TemplateID: "valid", CreatedAt: now}),
			insertProjectionCandidate(t, env, projectionCandidateSpec{TaskID: otherTask.ID, WorkflowRunID: fixture.runID, TargetAssetID: validAssetID, TemplateID: "wrong-task", CreatedAt: now.Add(time.Millisecond)}),
			insertProjectionCandidate(t, env, projectionCandidateSpec{TaskID: fixture.task.ID, WorkflowRunID: fixture.runID, TargetAssetID: otherProgramAssetID, TemplateID: "wrong-program", CreatedAt: now.Add(2 * time.Millisecond)}),
			insertProjectionCandidate(t, env, projectionCandidateSpec{TaskID: otherTask.ID, WorkflowRunID: fixture.runID, TargetAssetID: otherProgramAssetID, TemplateID: "both-wrong", CreatedAt: now.Add(3 * time.Millisecond)}),
		}

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.Candidates.Total != int64(len(ids)) || len(projection.Candidates.Items) != len(ids) || projection.Candidates.Truncated {
			t.Fatalf("contradictory candidates = %#v", projection.Candidates)
		}
		seen := map[domain.ID]bool{}
		for _, candidate := range projection.Candidates.Items {
			seen[candidate.ID] = true
		}
		for _, id := range ids {
			if !seen[id] {
				t.Fatalf("direct workflow member %s disappeared: %#v", id, projection.Candidates)
			}
		}
		if got := countLineageIssue(projection.Lineage.Issues, ExecutionLineageCandidateFindingInconsistent); got != 1 {
			t.Fatalf("candidate lineage issue count = %d, issues=%v", got, projection.Lineage.Issues)
		}
	})

	t.Run("created time and id ordering is deterministic", func(t *testing.T) {
		fixture := createRecoveryFixture(t, env, "projection-candidate-order", &running, domain.TaskRunning, nil)
		createdAt := time.Now().UTC()
		ids := []domain.ID{domain.NewID(), domain.NewID()}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		assetIDs := []domain.ID{
			insertProjectionAsset(t, env, env.programID, "https://candidate-order-a.example.test/"),
			insertProjectionAsset(t, env, env.programID, "https://candidate-order-b.example.test/"),
		}
		insertProjectionCandidate(t, env, projectionCandidateSpec{ID: ids[1], TaskID: fixture.task.ID, WorkflowRunID: fixture.runID, TargetAssetID: assetIDs[1], TemplateID: "order-b", CreatedAt: createdAt})
		insertProjectionCandidate(t, env, projectionCandidateSpec{ID: ids[0], TaskID: fixture.task.ID, WorkflowRunID: fixture.runID, TargetAssetID: assetIDs[0], TemplateID: "order-a", CreatedAt: createdAt})

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(projection.Candidates.Items) != 2 || projection.Candidates.Items[0].ID != ids[0] || projection.Candidates.Items[1].ID != ids[1] {
			t.Fatalf("candidate order = %#v want %s,%s", projection.Candidates.Items, ids[0], ids[1])
		}
	})

	t.Run("exact limit and contradiction after limit", func(t *testing.T) {
		fixture := createRecoveryFixture(t, env, "projection-candidate-limit", &running, domain.TaskRunning, nil)
		otherTask := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "candidate-limit-contradiction")
		createdAt := time.Now().UTC()
		for index := 0; index < executionProjectionCandidateLimit; index++ {
			assetID := insertProjectionAsset(t, env, env.programID, fmt.Sprintf("https://candidate-limit-%03d.example.test/", index))
			insertProjectionCandidate(t, env, projectionCandidateSpec{
				TaskID: fixture.task.ID, WorkflowRunID: fixture.runID, TargetAssetID: assetID,
				TemplateID: fmt.Sprintf("limit-%03d", index), CreatedAt: createdAt.Add(time.Duration(index) * time.Millisecond),
			})
		}

		exact, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if exact.Candidates.Total != executionProjectionCandidateLimit || len(exact.Candidates.Items) != executionProjectionCandidateLimit || exact.Candidates.Truncated {
			t.Fatalf("exact-limit candidates = %#v", exact.Candidates)
		}
		if containsLineageIssue(exact.Lineage.Issues, ExecutionLineageCandidateFindingInconsistent) {
			t.Fatalf("consistent exact-limit candidates reported contradiction: %v", exact.Lineage.Issues)
		}

		lastAssetID := insertProjectionAsset(t, env, env.programID, "https://candidate-limit-064.example.test/")
		contradictoryID := insertProjectionCandidate(t, env, projectionCandidateSpec{
			TaskID: otherTask.ID, WorkflowRunID: fixture.runID, TargetAssetID: lastAssetID,
			TemplateID: "limit-064", CreatedAt: createdAt.Add(executionProjectionCandidateLimit * time.Millisecond),
		})
		over, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if over.Candidates.Total != executionProjectionCandidateLimit+1 || len(over.Candidates.Items) != executionProjectionCandidateLimit || !over.Candidates.Truncated {
			t.Fatalf("over-limit candidates = %#v", over.Candidates)
		}
		for _, candidate := range over.Candidates.Items {
			if candidate.ID == contradictoryID {
				t.Fatalf("contradictory candidate after limit was returned: %s", contradictoryID)
			}
		}
		if got := countLineageIssue(over.Lineage.Issues, ExecutionLineageCandidateFindingInconsistent); got != 1 {
			t.Fatalf("post-limit candidate lineage issue count = %d, issues=%v", got, over.Lineage.Issues)
		}
	})
}

func TestExecutionProjectionAssetObservationSummaryIntegration(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "execution-projection-observations")
	running := domain.RunRunning

	t.Run("zero observations serialize as a non-null summary", func(t *testing.T) {
		fixture := createRecoveryFixture(t, env, "projection-observation-zero", &running, domain.TaskRunning, nil)
		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.AssetObservations.Total != 0 || projection.AssetObservations.DistinctAssetCount != 0 {
			t.Fatalf("zero observation summary = %#v", projection.AssetObservations)
		}
		if containsLineageIssue(projection.Lineage.Issues, ExecutionLineageAssetObservationInconsistent) {
			t.Fatalf("zero observations reported lineage inconsistency: %v", projection.Lineage.Issues)
		}
		encoded, err := json.Marshal(projection)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(encoded), `"asset_observations":{"total":0,"distinct_asset_count":0}`) {
			t.Fatalf("zero observation JSON contract missing: %s", encoded)
		}
	})

	t.Run("direct workflow membership distinct count and security boundary", func(t *testing.T) {
		fixture := createRecoveryFixture(t, env, "projection-observation-membership", &running, domain.TaskRunning, nil)
		now := time.Now().UTC()
		evidenceSentinel := domain.NewID()
		sharedAssetID := insertProjectionAsset(t, env, env.programID, "https://asset-canonical-observation-sentinel.example.test/private")
		uniqueAssetID := insertProjectionAsset(t, env, env.programID, "https://observation-second.example.test/")
		insertProjectionObservation(t, env, projectionObservationSpec{
			AssetID: sharedAssetID, WorkflowRunID: fixture.runID,
			SourceCapability:    "observation-source-capability-sentinel",
			ObservedValue:       "observation-observed-value-sentinel",
			Metadata:            json.RawMessage(`{"outer":{"inner":"observation-deep-metadata-sentinel"}}`),
			EvidenceArtifactIDs: []domain.ID{evidenceSentinel}, ObservedAt: now,
		})
		insertProjectionObservation(t, env, projectionObservationSpec{
			AssetID: sharedAssetID, WorkflowRunID: fixture.runID,
			SourceCapability: "probe.http", ObservedValue: "shared-asset-second-value", ObservedAt: now.Add(time.Millisecond),
		})
		insertProjectionObservation(t, env, projectionObservationSpec{
			AssetID: uniqueAssetID, WorkflowRunID: fixture.runID,
			SourceCapability: "probe.dns", ObservedValue: "unique-asset-value", ObservedAt: now.Add(2 * time.Millisecond),
		})

		otherRunID := domain.NewID()
		if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,trigger_source,summary) VALUES($1,$2,$3,'1','running',$4,'integration','{}')`, otherRunID, fixture.task.ID, env.definitionID, now); err != nil {
			t.Fatal(err)
		}
		otherProgramID, _ := createSchedulerIntegrationProgram(t, env.ctx, env.store, "observation-other-workflow-program")
		otherWorkflowAssetID := insertProjectionAsset(t, env, otherProgramID, "https://other-workflow-observation.example.test/")
		insertProjectionObservation(t, env, projectionObservationSpec{
			AssetID: otherWorkflowAssetID, WorkflowRunID: otherRunID,
			SourceCapability: "excluded.other.workflow", ObservedValue: "excluded-other-workflow-value", ObservedAt: now,
		})

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.AssetObservations.Total != 3 || projection.AssetObservations.DistinctAssetCount != 2 {
			t.Fatalf("workflow observation summary = %#v, want total=3 distinct=2", projection.AssetObservations)
		}
		if containsLineageIssue(projection.Lineage.Issues, ExecutionLineageAssetObservationInconsistent) {
			t.Fatalf("other-workflow contradiction affected lineage: %v", projection.Lineage.Issues)
		}
		encoded, err := json.Marshal(projection)
		if err != nil {
			t.Fatal(err)
		}
		for _, sentinel := range []string{
			"asset-canonical-observation-sentinel",
			"observation-source-capability-sentinel",
			"observation-observed-value-sentinel",
			"observation-deep-metadata-sentinel",
			string(evidenceSentinel),
			"excluded-other-workflow-value",
		} {
			if strings.Contains(string(encoded), sentinel) {
				t.Fatalf("observation summary leaked %q: %s", sentinel, encoded)
			}
		}
	})

	t.Run("cross-program observations count and emit one aggregate issue", func(t *testing.T) {
		fixture := createRecoveryFixture(t, env, "projection-observation-contradictions", &running, domain.TaskRunning, nil)
		otherProgramID, _ := createSchedulerIntegrationProgram(t, env.ctx, env.store, "observation-other-program")
		validAssetID := insertProjectionAsset(t, env, env.programID, "https://observation-valid.example.test/")
		wrongAssetA := insertProjectionAsset(t, env, otherProgramID, "https://observation-wrong-a.example.test/")
		wrongAssetB := insertProjectionAsset(t, env, otherProgramID, "https://observation-wrong-b.example.test/")
		for index, assetID := range []domain.ID{validAssetID, wrongAssetA, wrongAssetA, wrongAssetB} {
			insertProjectionObservation(t, env, projectionObservationSpec{
				AssetID: assetID, WorkflowRunID: fixture.runID,
				SourceCapability: fmt.Sprintf("contradiction.%d", index),
				ObservedValue:    fmt.Sprintf("contradiction-value-%d", index),
			})
		}

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.AssetObservations.Total != 4 || projection.AssetObservations.DistinctAssetCount != 3 {
			t.Fatalf("contradictory observation summary = %#v, want total=4 distinct=3", projection.AssetObservations)
		}
		if got := countLineageIssue(projection.Lineage.Issues, ExecutionLineageAssetObservationInconsistent); got != 1 {
			t.Fatalf("observation lineage issue count = %d, issues=%v", got, projection.Lineage.Issues)
		}
	})

	t.Run("high cardinality remains exact", func(t *testing.T) {
		fixture := createRecoveryFixture(t, env, "projection-observation-cardinality", &running, domain.TaskRunning, nil)
		const assetCount = 5
		const observationsPerAsset = 7
		for assetIndex := 0; assetIndex < assetCount; assetIndex++ {
			assetID := insertProjectionAsset(t, env, env.programID, fmt.Sprintf("https://observation-cardinality-%d.example.test/", assetIndex))
			for observationIndex := 0; observationIndex < observationsPerAsset; observationIndex++ {
				insertProjectionObservation(t, env, projectionObservationSpec{
					AssetID: assetID, WorkflowRunID: fixture.runID,
					SourceCapability: fmt.Sprintf("cardinality.%d", observationIndex),
					ObservedValue:    fmt.Sprintf("cardinality-%d-%d", assetIndex, observationIndex),
				})
			}
		}

		projection, err := env.store.GetExecutionProjection(env.ctx, fixture.execution.ID)
		if err != nil {
			t.Fatal(err)
		}
		if projection.AssetObservations.Total != assetCount*observationsPerAsset || projection.AssetObservations.DistinctAssetCount != assetCount {
			t.Fatalf("high-cardinality observation summary = %#v", projection.AssetObservations)
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

func insertProjectionTool(t *testing.T, env recoveryTestEnvironment, id, stepID domain.ID, capability string, startedAt time.Time, completedAt *time.Time, exitCode *int, sanitizedArguments, executionEnvironment string) {
	t.Helper()
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,tool_version,sanitized_arguments,execution_environment,started_at,completed_at,exit_code,timed_out)
		VALUES($1,$2,$3,'projection-fixture','1',$4,$5,$6,$7,$8,false)`, id, stepID, capability, json.RawMessage(sanitizedArguments), json.RawMessage(executionEnvironment), startedAt, completedAt, exitCode); err != nil {
		t.Fatal(err)
	}
}

func insertProjectionApproval(t *testing.T, env recoveryTestEnvironment, stepID, taskID domain.ID, requestedAt time.Time) domain.ID {
	t.Helper()
	id := domain.NewID()
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO approvals(id,request_id,task_id,action_request_id,requested_risk_level,reason,requested_at,decision)
		VALUES($1,$2,$3,$4,'moderate','projection fixture',$5,'pending')`, id, stepID, taskID, domain.NewID(), requestedAt); err != nil {
		t.Fatal(err)
	}
	return id
}

type projectionArtifactSpec struct {
	TaskID          domain.ID
	WorkflowRunID   domain.ID
	StepRunID       domain.ID
	ToolRunID       domain.ID
	Type            string
	StorageLocation string
	CreatedAt       *time.Time
	ExpiresAt       *time.Time
	Sensitive       bool
}

func insertProjectionArtifact(t *testing.T, env recoveryTestEnvironment, spec projectionArtifactSpec) domain.ID {
	t.Helper()
	id := domain.NewID()
	artifactType := spec.Type
	if artifactType == "" {
		artifactType = "normalized-result"
	}
	storageLocation := spec.StorageLocation
	if storageLocation == "" {
		storageLocation = "artifact://projection-fixture/" + string(id)
	}
	createdAt := time.Now().UTC()
	if spec.CreatedAt != nil {
		createdAt = *spec.CreatedAt
	}
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,storage_location,created_at,expires_at,redaction_state,sensitive)
		VALUES($1,$2,$3,$4,$5,$6,'application/json',2,$7,$8,$9,$10,$11,$12)`, id, spec.TaskID, spec.WorkflowRunID, spec.StepRunID, spec.ToolRunID, artifactType, "sha-"+string(id), storageLocation, createdAt, spec.ExpiresAt, map[bool]string{true: "sensitive-separated", false: "redacted"}[spec.Sensitive], spec.Sensitive); err != nil {
		t.Fatal(err)
	}
	return id
}

type projectionCandidateSpec struct {
	ID                   domain.ID
	TaskID               domain.ID
	WorkflowRunID        domain.ID
	TargetAssetID        domain.ID
	SourceCapability     string
	TemplateID           string
	ClaimedVulnerability string
	Severity             string
	EvidenceArtifactIDs  []domain.ID
	DetectionConfidence  float64
	Status               string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type projectionObservationSpec struct {
	AssetID             domain.ID
	WorkflowRunID       domain.ID
	SourceCapability    string
	ObservedValue       string
	Metadata            json.RawMessage
	EvidenceArtifactIDs []domain.ID
	ObservedAt          time.Time
}

func insertProjectionAsset(t *testing.T, env recoveryTestEnvironment, programID domain.ID, canonicalValue string) domain.ID {
	t.Helper()
	id := domain.NewID()
	now := time.Now().UTC()
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO assets(id,program_id,type,canonical_value,created_at,updated_at) VALUES($1,$2,'url',$3,$4,$4)`, id, programID, canonicalValue, now); err != nil {
		t.Fatal(err)
	}
	return id
}

func insertProjectionObservation(t *testing.T, env recoveryTestEnvironment, spec projectionObservationSpec) domain.ID {
	t.Helper()
	id := domain.NewID()
	if spec.SourceCapability == "" {
		spec.SourceCapability = "probe.http"
	}
	if spec.ObservedValue == "" {
		spec.ObservedValue = "projection-observation-" + string(id)
	}
	if spec.Metadata == nil {
		spec.Metadata = json.RawMessage(`{}`)
	}
	if spec.EvidenceArtifactIDs == nil {
		spec.EvidenceArtifactIDs = []domain.ID{}
	}
	if spec.ObservedAt.IsZero() {
		spec.ObservedAt = time.Now().UTC()
	}
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO asset_observations(id,asset_id,workflow_run_id,source_capability,observed_value,metadata,first_seen_at,observed_at,confidence,evidence_artifact_ids) VALUES($1,$2,$3,$4,$5,$6,$7,$7,1,$8)`, id, spec.AssetID, spec.WorkflowRunID, spec.SourceCapability, spec.ObservedValue, spec.Metadata, spec.ObservedAt, idStrings(spec.EvidenceArtifactIDs)); err != nil {
		t.Fatal(err)
	}
	return id
}

func insertProjectionCandidate(t *testing.T, env recoveryTestEnvironment, spec projectionCandidateSpec) domain.ID {
	t.Helper()
	if spec.ID == "" {
		spec.ID = domain.NewID()
	}
	if spec.SourceCapability == "" {
		spec.SourceCapability = "scan.nuclei"
	}
	if spec.TemplateID == "" {
		spec.TemplateID = "projection-" + string(spec.ID)
	}
	if spec.ClaimedVulnerability == "" {
		spec.ClaimedVulnerability = "projection candidate"
	}
	if spec.Severity == "" {
		spec.Severity = "medium"
	}
	if spec.DetectionConfidence == 0 {
		spec.DetectionConfidence = 0.7
	}
	if spec.Status == "" {
		spec.Status = "new"
	}
	if spec.CreatedAt.IsZero() {
		spec.CreatedAt = time.Now().UTC()
	}
	if spec.UpdatedAt.IsZero() {
		spec.UpdatedAt = spec.CreatedAt
	}
	if spec.EvidenceArtifactIDs == nil {
		spec.EvidenceArtifactIDs = []domain.ID{}
	}
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO candidate_findings(id,task_id,workflow_run_id,target_asset_id,source_capability,template_id,claimed_vulnerability,severity,evidence_artifact_ids,detection_confidence,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, spec.ID, spec.TaskID, spec.WorkflowRunID, spec.TargetAssetID, spec.SourceCapability, spec.TemplateID, spec.ClaimedVulnerability, spec.Severity, idStrings(spec.EvidenceArtifactIDs), spec.DetectionConfidence, spec.Status, spec.CreatedAt, spec.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	return spec.ID
}

func timePointer(value time.Time) *time.Time {
	return &value
}

type projectionQueryCounter struct {
	executionProjectionQuerier
	count int
}

func (query *projectionQueryCounter) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	query.count++
	return query.executionProjectionQuerier.QueryRow(ctx, sql, args...)
}

func (query *projectionQueryCounter) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	query.count++
	return query.executionProjectionQuerier.Query(ctx, sql, args...)
}
