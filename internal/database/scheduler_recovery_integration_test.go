package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

type recoveryTestEnvironment struct {
	store        *Store
	ctx          context.Context
	programID    domain.ID
	definitionID domain.ID
}

type recoveryStepSpec struct {
	name          string
	status        domain.StepStatus
	started       bool
	completed     bool
	attemptCount  int
	approvalState string
	output        json.RawMessage
}

type recoveryTestFixture struct {
	execution domain.ScheduledExecution
	task      domain.Task
	runID     domain.ID
	steps     map[string]domain.ID
	approval  *domain.ID
}

func TestStaleScheduledExecutionReconciliationScenariosAThroughE(t *testing.T) {
	t.Run("A safe versioned claim is requeued once and reclaimable", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-a")
		schedule := createIntegrationSchedule(t, env.ctx, env.store, env.programID, "scenario-a")
		execution := enqueueAndClaim(t, env.ctx, env.store, schedule.ID, "stale-a", time.Minute)
		expireRecoveryLease(t, env, execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecovery(t, env, execution.ID, domain.ScheduledExecutionPending, "", "", execution.AttemptCount)
		assertRecoveryAuditCount(t, env, execution.ID, "scheduled_execution_stale_claim_recovered", 1)
		reconcileRecovery(t, env)
		assertRecoveryAuditCount(t, env, execution.ID, "scheduled_execution_stale_claim_recovered", 1)

		reclaimed, _, ok, err := env.store.ClaimPendingScheduledExecution(env.ctx, "replacement-a", time.Minute)
		if err != nil || !ok || reclaimed.ID != execution.ID {
			t.Fatalf("reclaim=%#v ok=%v err=%v", reclaimed, ok, err)
		}
		if reclaimed.AttemptCount != execution.AttemptCount+1 {
			t.Fatalf("reclaimed attempt=%d want=%d", reclaimed.AttemptCount, execution.AttemptCount+1)
		}
	})

	t.Run("legacy no-lineage claim is inconsistent and not retryable", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-a-legacy")
		schedule := createIntegrationSchedule(t, env.ctx, env.store, env.programID, "scenario-a-legacy")
		execution, err := env.store.EnqueueRunNow(env.ctx, schedule.ID, "integration")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE scheduled_executions SET status='claimed',attempt_count=1,lease_owner='legacy',lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, execution.ID); err != nil {
			t.Fatal(err)
		}

		reconcileRecovery(t, env)
		assertScheduledRecovery(t, env, execution.ID, domain.ScheduledExecutionInterrupted, "lineage_inconsistent", "persisted scheduler lineage is incomplete or contradictory and requires manual review", 1)
		assertManualReviewAudit(t, env, execution.ID, "scheduled_execution_lineage_inconsistent")
		if _, _, ok, err := env.store.ClaimPendingScheduledExecution(env.ctx, "replacement", time.Minute); err != nil || ok {
			t.Fatalf("legacy inconsistent claim was retryable: ok=%v err=%v", ok, err)
		}
	})

	t.Run("B linked task without workflow is interrupted", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-b")
		fixture := createRecoveryFixture(t, env, "scenario-b", nil, domain.TaskRunning, nil)
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecovery(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted", "scheduler lease expired after task creation but before workflow state was established", fixture.execution.AttemptCount)
		assertTaskRecoveryStatus(t, env, fixture.task.ID, domain.TaskFailed)
		assertRecoveryAuditCount(t, env, fixture.execution.ID, "scheduled_execution_lineage_interrupted", 1)
		assertEntityAuditCount(t, env, "scheduled_task_reconciled", "task_id", fixture.task.ID, 1)
		assertExecutionLineage(t, env, fixture.execution.ID, &fixture.task.ID, nil)
		reconcileRecovery(t, env)
		assertRecoveryAuditCount(t, env, fixture.execution.ID, "scheduled_execution_lineage_interrupted", 1)
		assertEntityAuditCount(t, env, "scheduled_task_reconciled", "task_id", fixture.task.ID, 1)
	})

	t.Run("C future steps are cancelled when no step began", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-c")
		runStatus := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "scenario-c", &runStatus, domain.TaskRunning, []recoveryStepSpec{
			{name: "pending", status: domain.StepPending},
			{name: "blocked", status: domain.StepBlocked},
			{name: "skipped", status: domain.StepSkipped},
			{name: "cancelled", status: domain.StepCancelled},
		})
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecovery(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted", "scheduler lease expired before workflow steps began", fixture.execution.AttemptCount)
		assertTaskRecoveryStatus(t, env, fixture.task.ID, domain.TaskFailed)
		assertWorkflowRecoveryStatus(t, env, fixture.runID, domain.RunFailed)
		assertStepRecoveryStatus(t, env, fixture.steps["pending"], domain.StepCancelled)
		assertStepRecoveryStatus(t, env, fixture.steps["blocked"], domain.StepCancelled)
		for _, name := range []string{"skipped", "cancelled"} {
			assertStepRecoveryStatus(t, env, fixture.steps[name], map[string]domain.StepStatus{"skipped": domain.StepSkipped, "cancelled": domain.StepCancelled}[name])
		}
	})

	t.Run("D active steps fail while future steps cancel", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-d")
		runStatus := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "scenario-d", &runStatus, domain.TaskRunning, []recoveryStepSpec{
			{name: "running", status: domain.StepRunning, started: true},
			{name: "queued", status: domain.StepQueued},
			{name: "retryable", status: domain.StepRetryable, started: true},
			{name: "pending", status: domain.StepPending},
			{name: "blocked", status: domain.StepBlocked},
			{name: "succeeded", status: domain.StepSucceeded, started: true, completed: true, attemptCount: 1, output: json.RawMessage(`{"evidence":"preserved"}`)},
		})
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecovery(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted", "scheduler lease expired after workflow execution progressed", fixture.execution.AttemptCount)
		for _, name := range []string{"running", "queued", "retryable"} {
			assertStepRecoveryStatus(t, env, fixture.steps[name], domain.StepFailed)
			assertStepRecoveryClassification(t, env, fixture.steps[name], "interrupted")
		}
		for _, name := range []string{"pending", "blocked"} {
			assertStepRecoveryStatus(t, env, fixture.steps[name], domain.StepCancelled)
		}
		assertStepRecoveryStatus(t, env, fixture.steps["succeeded"], domain.StepSucceeded)
		assertEntityAuditCount(t, env, "scheduled_step_reconciled", "workflow_run_id", fixture.runID, 5)
		assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_lineage_interrupted", "changed_step_ids", []domain.ID{
			fixture.steps["blocked"], fixture.steps["pending"], fixture.steps["queued"], fixture.steps["retryable"], fixture.steps["running"],
		})
		assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_lineage_interrupted", "preserved_step_ids", []domain.ID{fixture.steps["succeeded"]})
	})

	t.Run("D terminal execution evidence means the workflow progressed", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-d-terminal-evidence")
		runStatus := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "scenario-d-terminal-evidence", &runStatus, domain.TaskRunning, []recoveryStepSpec{
			{name: "succeeded", status: domain.StepSucceeded, started: true, completed: true, attemptCount: 1, output: json.RawMessage(`{"evidence":"preserved"}`)},
			{name: "future", status: domain.StepPending},
		})
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecovery(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted", "scheduler lease expired after workflow execution progressed", fixture.execution.AttemptCount)
		assertRecoveryReason(t, env, fixture.execution.ID, "scheduled_execution_lineage_interrupted", "workflow_progressed")
		assertStepRecoveryStatus(t, env, fixture.steps["succeeded"], domain.StepSucceeded)
		assertStepRecoveryStatus(t, env, fixture.steps["future"], domain.StepCancelled)
		var output string
		if err := env.store.Pool.QueryRow(env.ctx, `SELECT output::text FROM step_runs WHERE id=$1`, fixture.steps["succeeded"]).Scan(&output); err != nil {
			t.Fatal(err)
		}
		if output != `{"evidence": "preserved"}` {
			t.Fatalf("succeeded step output changed: %s", output)
		}
		assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_lineage_interrupted", "changed_step_ids", []domain.ID{fixture.steps["future"]})
		assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_lineage_interrupted", "preserved_step_ids", []domain.ID{fixture.steps["succeeded"]})
	})

	t.Run("E incomplete tool closes without fabricated outcome", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-e")
		runStatus := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "scenario-e", &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "provider", status: domain.StepRunning, started: true}})
		toolID := insertRecoveryTool(t, env, fixture.steps["provider"], false)
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecovery(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted", "scheduler lease expired with an incomplete tool run; provider outcome is unknown", fixture.execution.AttemptCount)
		var completedAt *time.Time
		var exitCode *int
		var arguments string
		if err := env.store.Pool.QueryRow(env.ctx, `SELECT completed_at,exit_code,sanitized_arguments::text FROM tool_runs WHERE id=$1`, toolID).Scan(&completedAt, &exitCode, &arguments); err != nil {
			t.Fatal(err)
		}
		if completedAt == nil || exitCode != nil || arguments != `{"marker": "preserved"}` {
			t.Fatalf("tool completion=%v exit=%v arguments=%s", completedAt, exitCode, arguments)
		}
		assertEntityAuditCount(t, env, "scheduled_tool_run_interrupted", "tool_run_id", toolID, 1)
	})
}

func TestStaleScheduledExecutionReconciliationScenariosFAndG(t *testing.T) {
	t.Run("F completed workflow evidence remains unchanged", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-f")
		runStatus := domain.RunCompleted
		fixture := createRecoveryFixture(t, env, "scenario-f", &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "done", status: domain.StepSucceeded, started: true, completed: true, attemptCount: 1, approvalState: "approved", output: json.RawMessage(`{"evidence":"original"}`)}})
		toolID := insertRecoveryTool(t, env, fixture.steps["done"], true)
		artifactID, observationID := insertRecoveryEvidence(t, env, fixture, toolID)
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		before := recoveryEvidenceSnapshot(t, env, fixture.runID, fixture.steps["done"], toolID, artifactID, observationID)
		reconcileRecovery(t, env)
		after := recoveryEvidenceSnapshot(t, env, fixture.runID, fixture.steps["done"], toolID, artifactID, observationID)
		if before != after {
			t.Fatalf("terminal evidence changed\nbefore=%s\nafter=%s", before, after)
		}
		assertScheduledRecovery(t, env, fixture.execution.ID, domain.ScheduledExecutionCompleted, "", "", fixture.execution.AttemptCount)
		assertTaskRecoveryStatus(t, env, fixture.task.ID, domain.TaskCompleted)
		assertApprovalDecision(t, env, *fixture.approval, "approved")
		assertRecoveryAuditCount(t, env, fixture.execution.ID, "scheduled_execution_terminal_reconciled", 1)
		assertRecoveryAuditCount(t, env, fixture.execution.ID, "scheduled_execution_lineage_inconsistent", 0)
		assertEntityAuditCount(t, env, "scheduled_step_reconciled", "step_run_id", fixture.steps["done"], 0)
		assertEntityAuditCount(t, env, "scheduled_tool_run_interrupted", "tool_run_id", toolID, 0)
		assertEntityAuditCount(t, env, "scheduled_approval_reconciled", "step_run_id", fixture.steps["done"], 0)
		assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_terminal_reconciled", "changed_step_ids", nil)
		assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_terminal_reconciled", "preserved_step_ids", []domain.ID{fixture.steps["done"]})
		assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_terminal_reconciled", "preserved_approval_ids", []domain.ID{*fixture.approval})
	})

	tests := []struct {
		name       string
		runStatus  domain.RunStatus
		taskWant   domain.TaskStatus
		execWant   domain.ScheduledExecutionStatus
		classWant  string
		reasonWant string
	}{
		{name: "failed", runStatus: domain.RunFailed, taskWant: domain.TaskFailed, execWant: domain.ScheduledExecutionFailed, classWant: "execution", reasonWant: "workflow_failed"},
		{name: "cancelled", runStatus: domain.RunCancelled, taskWant: domain.TaskCancelled, execWant: domain.ScheduledExecutionCancelled, classWant: "cancelled", reasonWant: "workflow_cancelled"},
	}
	for _, test := range tests {
		t.Run("G terminal "+test.name, func(t *testing.T) {
			env := newRecoveryTestEnvironment(t, "scenario-g-"+test.name)
			fixture := createRecoveryFixture(t, env, "scenario-g-"+test.name, &test.runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "terminal", status: terminalStepForRun(test.runStatus), started: true, completed: true, attemptCount: 1, approvalState: "approved"}})
			expireRecoveryLease(t, env, fixture.execution.ID, 1)

			reconcileRecovery(t, env)
			assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, test.execWant, test.classWant)
			assertTaskRecoveryStatus(t, env, fixture.task.ID, test.taskWant)
			assertWorkflowRecoveryStatus(t, env, fixture.runID, test.runStatus)
			assertApprovalDecision(t, env, *fixture.approval, "approved")
			assertRecoveryReason(t, env, fixture.execution.ID, "scheduled_execution_terminal_reconciled", test.reasonWant)
			assertRecoveryAuditCount(t, env, fixture.execution.ID, "scheduled_execution_lineage_inconsistent", 0)
			assertEntityAuditCount(t, env, "scheduled_step_reconciled", "step_run_id", fixture.steps["terminal"], 0)
			assertEntityAuditCount(t, env, "scheduled_approval_reconciled", "step_run_id", fixture.steps["terminal"], 0)
		})
	}

	for _, decision := range []string{"pending", "approved"} {
		t.Run("G coherent "+decision+" approval gate", func(t *testing.T) {
			env := newRecoveryTestEnvironment(t, "scenario-g-approval-"+decision)
			runStatus := domain.RunPaused
			fixture := createRecoveryFixture(t, env, "scenario-g-approval-"+decision, &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "gate", status: domain.StepAwaitingApproval, approvalState: decision}})
			expireRecoveryLease(t, env, fixture.execution.ID, 1)

			reconcileRecovery(t, env)
			assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionPausedForApproval, "")
			assertTaskRecoveryStatus(t, env, fixture.task.ID, domain.TaskPaused)
			assertWorkflowRecoveryStatus(t, env, fixture.runID, domain.RunPaused)
			assertApprovalDecision(t, env, *fixture.approval, decision)
			assertRecoveryReason(t, env, fixture.execution.ID, "scheduled_execution_pause_reconciled", "approval_gate")
			assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_pause_reconciled", "changed_step_ids", nil)
			assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_pause_reconciled", "preserved_step_ids", []domain.ID{fixture.steps["gate"]})
			if decision == "approved" {
				if err := env.store.RequestScheduledExecutionResume(env.ctx, fixture.execution.ID, "integration"); err != nil {
					t.Fatal(err)
				}
				assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionPending, "")
				assertExecutionLineage(t, env, fixture.execution.ID, &fixture.task.ID, &fixture.runID)
			}
		})
	}

	t.Run("G rejected approval maps existing rejection evidence", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-g-rejected")
		runStatus := domain.RunFailed
		fixture := createRecoveryFixture(t, env, "scenario-g-rejected", &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "gate", status: domain.StepFailed, started: true, completed: true, attemptCount: 1, approvalState: "rejected"}})
		approvalID := insertRecoveryApproval(t, env, fixture, "rejected", fixture.steps["gate"])
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE step_runs SET error_classification='approval_rejected' WHERE id=$1`, fixture.steps["gate"]); err != nil {
			t.Fatal(err)
		}
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionApprovalRejected, "approval_rejected")
		assertTaskRecoveryStatus(t, env, fixture.task.ID, domain.TaskFailed)
		assertApprovalDecision(t, env, approvalID, "rejected")
		assertStepRecoveryStatus(t, env, fixture.steps["gate"], domain.StepFailed)
	})

	t.Run("G coherent operator pause remains paused", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-g-operator")
		runStatus := domain.RunPaused
		fixture := createRecoveryFixture(t, env, "scenario-g-operator", &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "future", status: domain.StepPending}})
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionPausedOperator, "")
		assertTaskRecoveryStatus(t, env, fixture.task.ID, domain.TaskPaused)
		assertStepRecoveryStatus(t, env, fixture.steps["future"], domain.StepPending)
		assertRecoveryReason(t, env, fixture.execution.ID, "scheduled_execution_pause_reconciled", "operator_pause")
	})
}

func TestStaleScheduledExecutionReconciliationScenarioH(t *testing.T) {
	t.Run("missing scheduled task link with workflow", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-h-missing-link")
		runStatus := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "scenario-h-missing-link", &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "running", status: domain.StepRunning, started: true}})
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE scheduled_executions SET task_id=NULL WHERE id=$1`, fixture.execution.ID); err != nil {
			t.Fatal(err)
		}
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScenarioHClosed(t, env, fixture, []string{"workflow_link_without_scheduled_task"})
	})

	t.Run("referenced workflow is missing", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-h-missing-workflow")
		fixture := createRecoveryFixture(t, env, "scenario-h-missing-workflow", nil, domain.TaskRunning, nil)
		missingRunID := domain.NewID()
		execWithoutForeignKeys(t, env, `UPDATE scheduled_executions SET workflow_run_id=$2,status='running' WHERE id=$1`, fixture.execution.ID, missingRunID)
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "lineage_inconsistent")
		assertTaskRecoveryStatus(t, env, fixture.task.ID, domain.TaskFailed)
		assertManualReviewConflict(t, env, fixture.execution.ID, "missing_workflow:"+string(missingRunID))
	})

	t.Run("referenced task is missing", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-h-missing-task")
		schedule := createIntegrationSchedule(t, env.ctx, env.store, env.programID, "scenario-h-missing-task")
		execution := enqueueAndClaim(t, env.ctx, env.store, schedule.ID, "missing-task-owner", time.Minute)
		missingTaskID := domain.NewID()
		execWithoutForeignKeys(t, env, `UPDATE scheduled_executions SET task_id=$2 WHERE id=$1`, execution.ID, missingTaskID)
		expireRecoveryLease(t, env, execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, execution.ID, domain.ScheduledExecutionInterrupted, "lineage_inconsistent")
		assertManualReviewConflict(t, env, execution.ID, "missing_task:"+string(missingTaskID))
	})

	t.Run("conflicting same-program task links preserve both ambiguous tasks", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-h-task-conflict")
		runStatus := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "scenario-h-task-conflict", &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "running", status: domain.StepRunning, started: true}})
		otherTask := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "other")
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE scheduled_executions SET task_id=$2 WHERE id=$1`, fixture.execution.ID, otherTask.ID); err != nil {
			t.Fatal(err)
		}
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "lineage_inconsistent")
		assertTaskRecoveryStatus(t, env, fixture.task.ID, domain.TaskRunning)
		assertTaskRecoveryStatus(t, env, otherTask.ID, domain.TaskRunning)
		assertWorkflowRecoveryStatus(t, env, fixture.runID, domain.RunFailed)
		assertStepRecoveryStatus(t, env, fixture.steps["running"], domain.StepFailed)
		assertEntityAuditCount(t, env, "scheduled_task_reconciled", "task_id", fixture.task.ID, 0)
		assertEntityAuditCount(t, env, "scheduled_task_reconciled", "task_id", otherTask.ID, 0)
		assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_lineage_inconsistent", "changed_task_ids", nil)
		assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_lineage_inconsistent", "preserved_task_ids", []domain.ID{fixture.task.ID, otherTask.ID})
		assertManualReviewConflict(t, env, fixture.execution.ID, "workflow_task_mismatch:"+string(otherTask.ID)+":"+string(fixture.task.ID))
		reconcileRecovery(t, env)
		assertRecoveryAuditCount(t, env, fixture.execution.ID, "scheduled_execution_lineage_inconsistent", 1)
	})

	t.Run("task from another program is inconsistent", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-h-program-conflict")
		runStatus := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "scenario-h-program-conflict", &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "running", status: domain.StepRunning, started: true}})
		otherProgramID, otherDefinitionID := createSchedulerIntegrationProgram(t, env.ctx, env.store, "scenario-h-other-program")
		otherTask := createIntegrationTask(t, env.ctx, env.store, otherProgramID, otherDefinitionID, "other-program")
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE scheduled_executions SET task_id=$2 WHERE id=$1`, fixture.execution.ID, otherTask.ID); err != nil {
			t.Fatal(err)
		}
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "lineage_inconsistent")
		assertTaskRecoveryStatus(t, env, otherTask.ID, domain.TaskRunning)
		assertTaskRecoveryStatus(t, env, fixture.task.ID, domain.TaskRunning)
		assertWorkflowRecoveryStatus(t, env, fixture.runID, domain.RunFailed)
		assertStepRecoveryStatus(t, env, fixture.steps["running"], domain.StepFailed)
		assertEntityAuditCount(t, env, "scheduled_task_reconciled", "task_id", fixture.task.ID, 0)
		assertEntityAuditCount(t, env, "scheduled_task_reconciled", "task_id", otherTask.ID, 0)
		assertManualReviewConflict(t, env, fixture.execution.ID, "task_program_mismatch:"+string(otherTask.ID)+":"+string(otherProgramID))
	})

	t.Run("workflow from another program is preserved for manual review", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-h-workflow-program-conflict")
		runStatus := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "scenario-h-workflow-program-conflict", &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "running", status: domain.StepRunning, started: true}})
		otherProgramID, otherDefinitionID := createSchedulerIntegrationProgram(t, env.ctx, env.store, "scenario-h-workflow-other-program")
		otherTask := createIntegrationTask(t, env.ctx, env.store, otherProgramID, otherDefinitionID, "workflow-other-program")
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE workflow_runs SET task_id=$2 WHERE id=$1`, fixture.runID, otherTask.ID); err != nil {
			t.Fatal(err)
		}
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "lineage_inconsistent")
		assertTaskRecoveryStatus(t, env, fixture.task.ID, domain.TaskRunning)
		assertTaskRecoveryStatus(t, env, otherTask.ID, domain.TaskRunning)
		assertWorkflowRecoveryStatus(t, env, fixture.runID, domain.RunRunning)
		assertStepRecoveryStatus(t, env, fixture.steps["running"], domain.StepRunning)
		assertEntityAuditCount(t, env, "scheduled_task_reconciled", "task_id", fixture.task.ID, 0)
		assertEntityAuditCount(t, env, "scheduled_task_reconciled", "task_id", otherTask.ID, 0)
		assertEntityAuditCount(t, env, "scheduled_workflow_reconciled", "workflow_run_id", fixture.runID, 0)
		assertEntityAuditCount(t, env, "scheduled_step_reconciled", "step_run_id", fixture.steps["running"], 0)
		assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_lineage_inconsistent", "changed_workflow_ids", nil)
		assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_lineage_inconsistent", "preserved_workflow_ids", []domain.ID{fixture.runID})
		assertManualReviewConflict(t, env, fixture.execution.ID, "task_program_mismatch:"+string(otherTask.ID)+":"+string(otherProgramID))
	})

	t.Run("terminal task without workflow is inconsistent", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-h-terminal-task")
		fixture := createRecoveryFixture(t, env, "scenario-h-terminal-task", nil, domain.TaskCompleted, nil)
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "lineage_inconsistent")
		assertTaskRecoveryStatus(t, env, fixture.task.ID, domain.TaskCompleted)
		assertManualReviewConflict(t, env, fixture.execution.ID, "terminal_task_without_workflow:"+string(fixture.task.ID))
	})

	t.Run("terminal workflow with active child is inconsistent", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-h-terminal-child")
		runStatus := domain.RunCompleted
		fixture := createRecoveryFixture(t, env, "scenario-h-terminal-child", &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "active", status: domain.StepRunning, started: true}})
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "lineage_inconsistent")
		assertWorkflowRecoveryStatus(t, env, fixture.runID, domain.RunCompleted)
		assertStepRecoveryStatus(t, env, fixture.steps["active"], domain.StepFailed)
		assertManualReviewConflict(t, env, fixture.execution.ID, "terminal_workflow_active_step:"+string(fixture.steps["active"]))
	})

	t.Run("action-request mismatch remains eligible through independent step and task links", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-h-approval")
		runStatus := domain.RunPaused
		fixture := createRecoveryFixture(t, env, "scenario-h-approval", &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "gate", status: domain.StepAwaitingApproval, approvalState: "pending"}})
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE approvals SET action_request_id=$2 WHERE id=$1`, *fixture.approval, domain.NewID()); err != nil {
			t.Fatal(err)
		}
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "lineage_inconsistent")
		assertApprovalDecision(t, env, *fixture.approval, "expired")
		assertStepRecoveryStatus(t, env, fixture.steps["gate"], domain.StepFailed)
		assertManualReviewConflict(t, env, fixture.execution.ID, "approval_request_mismatch:"+string(*fixture.approval))
	})

	t.Run("approval task mismatch is preserved for manual review", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-h-approval-task")
		runStatus := domain.RunPaused
		fixture := createRecoveryFixture(t, env, "scenario-h-approval-task", &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "gate", status: domain.StepAwaitingApproval, approvalState: "pending"}})
		otherTask := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "approval-owner-mismatch")
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE approvals SET task_id=$2 WHERE id=$1`, *fixture.approval, otherTask.ID); err != nil {
			t.Fatal(err)
		}
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "lineage_inconsistent")
		assertApprovalDecision(t, env, *fixture.approval, "pending")
		assertEntityAuditCount(t, env, "scheduled_approval_reconciled", "step_run_id", fixture.steps["gate"], 0)
		assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_lineage_inconsistent", "changed_approval_ids", nil)
		assertRecoveryAuditIDs(t, env, fixture.execution.ID, "scheduled_execution_lineage_inconsistent", "preserved_approval_ids", []domain.ID{*fixture.approval})
		assertManualReviewConflict(t, env, fixture.execution.ID, "approval_task_mismatch:"+string(*fixture.approval))
	})

	t.Run("pending approval on a non-awaiting step is inconsistent", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "scenario-h-active-approval")
		runStatus := domain.RunRunning
		fixture := createRecoveryFixture(t, env, "scenario-h-active-approval", &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "done", status: domain.StepSucceeded, started: true, completed: true, attemptCount: 1, approvalState: "pending"}})
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "lineage_inconsistent")
		assertStepRecoveryStatus(t, env, fixture.steps["done"], domain.StepSucceeded)
		assertApprovalDecision(t, env, *fixture.approval, "expired")
		assertManualReviewConflict(t, env, fixture.execution.ID, "active_approval_for_nonawaiting_step:"+string(*fixture.approval))
	})
}

func TestStaleScheduledExecutionReconciliationIdempotencyConcurrencyAndLeaseSafety(t *testing.T) {
	t.Run("same execution reconciles once under concurrent workers", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "recovery-concurrent-same")
		fixture := createRecoveryFixture(t, env, "recovery-concurrent-same", nil, domain.TaskRunning, nil)
		expireRecoveryLease(t, env, fixture.execution.ID, 1)

		workerCtx, cancel := context.WithTimeout(env.ctx, 8*time.Second)
		defer cancel()
		start := make(chan struct{})
		results := make(chan error, 2)
		for range 2 {
			go func() {
				select {
				case <-start:
					results <- env.store.reconcileStaleScheduledExecutions(workerCtx, 1)
				case <-workerCtx.Done():
					results <- workerCtx.Err()
				}
			}()
		}
		close(start)
		for range 2 {
			select {
			case err := <-results:
				if err != nil {
					t.Fatal(err)
				}
			case <-workerCtx.Done():
				t.Fatalf("concurrent same-execution recovery did not finish: %v", workerCtx.Err())
			}
		}
		assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted")
		assertRecoveryAuditCount(t, env, fixture.execution.ID, "scheduled_execution_lineage_interrupted", 1)
		assertEntityAuditCount(t, env, "scheduled_task_reconciled", "task_id", fixture.task.ID, 1)
	})

	t.Run("locked lineage does not block another stale execution", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "recovery-concurrent-different")
		first := createRecoveryFixture(t, env, "recovery-concurrent-first", nil, domain.TaskRunning, nil)
		second := createRecoveryFixture(t, env, "recovery-concurrent-second", nil, domain.TaskRunning, nil)
		expireRecoveryLease(t, env, first.execution.ID, 2)
		expireRecoveryLease(t, env, second.execution.ID, 1)

		lockTx, err := env.store.Pool.Begin(env.ctx)
		if err != nil {
			t.Fatal(err)
		}
		locked := true
		defer func() {
			if locked {
				_ = lockTx.Rollback(context.Background())
			}
		}()
		if err := lockTx.QueryRow(env.ctx, `SELECT id FROM tasks WHERE id=$1 FOR UPDATE`, first.task.ID).Scan(new(domain.ID)); err != nil {
			t.Fatal(err)
		}

		recoveryCtx, cancel := context.WithTimeout(env.ctx, 5*time.Second)
		defer cancel()
		if err := env.store.reconcileStaleScheduledExecutions(recoveryCtx, 2); err != nil {
			t.Fatal(err)
		}
		assertScheduledRecoveryStatusAndClass(t, env, first.execution.ID, domain.ScheduledExecutionClaimed, "")
		assertScheduledRecoveryStatusAndClass(t, env, second.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted")
		if err := lockTx.Commit(env.ctx); err != nil {
			t.Fatal(err)
		}
		locked = false
		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, first.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted")
	})

	t.Run("different stale executions are active concurrently", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "recovery-concurrent-two")
		first := createRecoveryFixture(t, env, "recovery-concurrent-two-first", nil, domain.TaskRunning, nil)
		second := createRecoveryFixture(t, env, "recovery-concurrent-two-second", nil, domain.TaskRunning, nil)
		expireRecoveryLease(t, env, first.execution.ID, 2)
		expireRecoveryLease(t, env, second.execution.ID, 1)

		installRecoveryTaskAdvisoryBarrier(t, env)
		releaseFirst := holdRecoveryTaskAdvisoryLock(t, env, first.task.ID)
		defer releaseFirst()
		releaseSecond := holdRecoveryTaskAdvisoryLock(t, env, second.task.ID)
		defer releaseSecond()
		workerCtx, cancel := context.WithTimeout(env.ctx, 8*time.Second)
		defer cancel()
		start := make(chan struct{})
		results := make(chan error, 2)
		for range 2 {
			go func() {
				select {
				case <-start:
					results <- env.store.reconcileStaleScheduledExecutions(workerCtx, 1)
				case <-workerCtx.Done():
					results <- workerCtx.Err()
				}
			}()
		}
		close(start)
		waitForRecoveryTaskWaiters(t, workerCtx, env, 2)
		releaseFirst()
		releaseSecond()
		for range 2 {
			select {
			case err := <-results:
				if err != nil {
					t.Fatal(err)
				}
			case <-workerCtx.Done():
				t.Fatalf("concurrent different-execution recovery did not finish: %v", workerCtx.Err())
			}
		}
		assertScheduledRecoveryStatusAndClass(t, env, first.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted")
		assertScheduledRecoveryStatusAndClass(t, env, second.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted")
		assertRecoveryAuditCount(t, env, first.execution.ID, "scheduled_execution_lineage_interrupted", 1)
		assertRecoveryAuditCount(t, env, second.execution.ID, "scheduled_execution_lineage_interrupted", 1)
	})

	t.Run("fresh and renewed leases are untouched", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "recovery-live-lease")
		schedule := createIntegrationSchedule(t, env.ctx, env.store, env.programID, "recovery-live-lease")
		execution := enqueueAndClaim(t, env.ctx, env.store, schedule.ID, "live-owner", time.Minute)
		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, execution.ID, domain.ScheduledExecutionClaimed, "")
		if err := env.store.HeartbeatScheduledExecution(env.ctx, execution.ID, "live-owner", execution.AttemptCount, 2*time.Minute); err != nil {
			t.Fatal(err)
		}
		reconcileRecovery(t, env)
		assertScheduledRecoveryStatusAndClass(t, env, execution.ID, domain.ScheduledExecutionClaimed, "")
		assertRecoveryAuditCount(t, env, execution.ID, "scheduled_execution_stale_claim_recovered", 0)
	})

	t.Run("recovery row lock defeats a stale-owner heartbeat", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "recovery-wins")
		schedule := createIntegrationSchedule(t, env.ctx, env.store, env.programID, "recovery-wins")
		execution := enqueueAndClaim(t, env.ctx, env.store, schedule.ID, "stale-owner", time.Minute)
		expireRecoveryLease(t, env, execution.ID, 1)

		tx, err := env.store.Pool.Begin(env.ctx)
		if err != nil {
			t.Fatal(err)
		}
		committed := false
		defer func() {
			if !committed {
				_ = tx.Rollback(context.Background())
			}
		}()
		entry, found, err := lockNextStaleScheduledExecution(env.ctx, tx, nil)
		if err != nil || !found || entry.item.ID != execution.ID {
			t.Fatalf("locked recovery entry=%#v found=%v err=%v", entry, found, err)
		}
		heartbeatCtx, cancel := context.WithTimeout(env.ctx, 5*time.Second)
		defer cancel()
		heartbeat := make(chan error, 1)
		go func() {
			heartbeat <- env.store.HeartbeatScheduledExecution(heartbeatCtx, execution.ID, "stale-owner", execution.AttemptCount, time.Minute)
		}()
		waitForPostgresLock(t, heartbeatCtx, env.store, `%WHERE se.id=$1%FOR UPDATE OF se%`)
		lineage, locked, err := lockScheduledExecutionLineage(env.ctx, tx, entry)
		if err != nil || !locked {
			t.Fatalf("lock lineage locked=%v err=%v", locked, err)
		}
		if err := applyStaleLineageReconciliation(env.ctx, tx, entry, lineage, classifyStaleLineage(entry, &lineage)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(env.ctx); err != nil {
			t.Fatal(err)
		}
		committed = true
		select {
		case err := <-heartbeat:
			if err == nil {
				t.Fatal("stale-owner heartbeat succeeded after recovery committed")
			}
		case <-heartbeatCtx.Done():
			t.Fatalf("heartbeat did not finish after recovery committed: %v", heartbeatCtx.Err())
		}
		assertScheduledRecoveryStatusAndClass(t, env, execution.ID, domain.ScheduledExecutionPending, "")
	})
}

func TestClaimReconcilesStaleLineageBeforePendingSelection(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "recovery-claim-integration")
	stale := createRecoveryFixture(t, env, "recovery-claim-stale", nil, domain.TaskRunning, nil)
	expireRecoveryLease(t, env, stale.execution.ID, 2)
	pendingSchedule := createIntegrationSchedule(t, env.ctx, env.store, env.programID, "recovery-claim-pending")
	pending, err := env.store.EnqueueRunNow(env.ctx, pendingSchedule.ID, "integration")
	if err != nil {
		t.Fatal(err)
	}

	claimed, _, ok, err := env.store.ClaimPendingScheduledExecution(env.ctx, "claim-owner", time.Minute)
	if err != nil || !ok || claimed.ID != pending.ID {
		t.Fatalf("claim=%#v ok=%v err=%v", claimed, ok, err)
	}
	assertScheduledRecoveryStatusAndClass(t, env, stale.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted")
	assertTaskRecoveryStatus(t, env, stale.task.ID, domain.TaskFailed)
	assertRecoveryAuditCount(t, env, stale.execution.ID, "scheduled_execution_lineage_interrupted", 1)
}

func TestClaimPreservesSameScheduleOverlapWhenStaleLineageIsLocked(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "recovery-same-schedule-lock")
	stale := createRecoveryFixture(t, env, "recovery-same-schedule-lock", nil, domain.TaskRunning, nil)
	expireRecoveryLease(t, env, stale.execution.ID, 2)
	pendingID := insertRecoveryPendingExecution(t, env, stale.execution.ScheduleID)

	lockTx, err := env.store.Pool.Begin(env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_ = lockTx.Rollback(context.Background())
		}
	}()
	if err := lockTx.QueryRow(env.ctx, `SELECT id FROM tasks WHERE id=$1 FOR UPDATE`, stale.task.ID).Scan(new(domain.ID)); err != nil {
		t.Fatal(err)
	}

	claimCtx, cancel := context.WithTimeout(env.ctx, 5*time.Second)
	defer cancel()
	if claimed, _, ok, err := env.store.ClaimPendingScheduledExecution(claimCtx, "same-schedule-owner", time.Minute); err != nil || ok {
		t.Fatalf("claim while stale lineage locked execution=%#v ok=%v err=%v", claimed, ok, err)
	}
	assertScheduledRecoveryStatusAndClass(t, env, stale.execution.ID, domain.ScheduledExecutionClaimed, "")
	assertExpiredActiveRecoveryLease(t, env, stale.execution.ID)
	assertScheduledStatusAndAttempt(t, env, pendingID, domain.ScheduledExecutionSkippedOverlap, 0)

	if err := lockTx.Commit(env.ctx); err != nil {
		t.Fatal(err)
	}
	locked = false
	if claimed, _, ok, err := env.store.ClaimPendingScheduledExecution(claimCtx, "same-schedule-owner", time.Minute); err != nil || ok {
		t.Fatalf("claim after stale lineage release execution=%#v ok=%v err=%v", claimed, ok, err)
	}
	assertScheduledRecoveryStatusAndClass(t, env, stale.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted")
	assertScheduledStatusAndAttempt(t, env, pendingID, domain.ScheduledExecutionSkippedOverlap, 0)
}

func TestStaleRecoveryBatchLimitPreservesOverlapSafety(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "recovery-batch-limit")
	fixtures := make([]recoveryTestFixture, 0, staleReconciliationBatchLimit+1)
	for index := 0; index < staleReconciliationBatchLimit+1; index++ {
		fixtures = append(fixtures, createRecoveryFixture(t, env, fmt.Sprintf("recovery-limit-%02d", index), nil, domain.TaskRunning, nil))
	}
	for index := 0; index < staleReconciliationBatchLimit; index++ {
		expireRecoveryLease(t, env, fixtures[index].execution.ID, 100+index)
	}
	protected := fixtures[len(fixtures)-1]
	expireRecoveryLease(t, env, protected.execution.ID, 1)
	protectedPendingID := insertRecoveryPendingExecution(t, env, protected.execution.ScheduleID)
	unrelatedSchedule := createIntegrationSchedule(t, env.ctx, env.store, env.programID, "recovery-limit-unrelated")
	unrelatedPending, err := env.store.EnqueueRunNow(env.ctx, unrelatedSchedule.ID, "integration")
	if err != nil {
		t.Fatal(err)
	}

	claimCtx, cancel := context.WithTimeout(env.ctx, 15*time.Second)
	defer cancel()
	claimed, _, ok, err := env.store.ClaimPendingScheduledExecution(claimCtx, "limit-owner", time.Minute)
	if err != nil || !ok || claimed.ID != unrelatedPending.ID {
		t.Fatalf("unrelated claim=%#v ok=%v err=%v", claimed, ok, err)
	}
	for index := 0; index < staleReconciliationBatchLimit; index++ {
		assertScheduledRecoveryStatusAndClass(t, env, fixtures[index].execution.ID, domain.ScheduledExecutionInterrupted, "interrupted")
	}
	assertScheduledRecoveryStatusAndClass(t, env, protected.execution.ID, domain.ScheduledExecutionClaimed, "")
	assertExpiredActiveRecoveryLease(t, env, protected.execution.ID)
	assertScheduledStatusAndAttempt(t, env, protectedPendingID, domain.ScheduledExecutionSkippedOverlap, 0)
	assertScheduledStatusAndAttempt(t, env, unrelatedPending.ID, domain.ScheduledExecutionClaimed, 1)

	if next, _, ok, err := env.store.ClaimPendingScheduledExecution(claimCtx, "limit-owner-next", time.Minute); err != nil || ok {
		t.Fatalf("claim after bounded remainder execution=%#v ok=%v err=%v", next, ok, err)
	}
	assertScheduledRecoveryStatusAndClass(t, env, protected.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted")
	assertRecoveryAuditCount(t, env, protected.execution.ID, "scheduled_execution_lineage_interrupted", 1)
	assertScheduledStatusAndAttempt(t, env, protectedPendingID, domain.ScheduledExecutionSkippedOverlap, 0)
}

func newRecoveryTestEnvironment(t *testing.T, name string) recoveryTestEnvironment {
	t.Helper()
	store, ctx := schedulerIntegrationStore(t)
	programID, definitionID := createSchedulerIntegrationProgram(t, ctx, store, name)
	return recoveryTestEnvironment{store: store, ctx: ctx, programID: programID, definitionID: definitionID}
}

func createRecoveryFixture(t *testing.T, env recoveryTestEnvironment, name string, runStatus *domain.RunStatus, taskStatus domain.TaskStatus, specs []recoveryStepSpec) recoveryTestFixture {
	t.Helper()
	schedule := createIntegrationSchedule(t, env.ctx, env.store, env.programID, name)
	execution := enqueueAndClaim(t, env.ctx, env.store, schedule.ID, name+"-owner", time.Minute)
	now := time.Now().UTC()
	task := domain.Task{ID: domain.NewID(), ProgramID: env.programID, Objective: name, WorkflowDefinitionID: env.definitionID, Status: domain.TaskRunning, RequestedBy: "integration", CreatedAt: now, UpdatedAt: now}
	if err := env.store.CreateTaskWithLifecycle(env.ctx, task, func(lifecycleCtx context.Context, created domain.Task) error {
		return env.store.MarkScheduledExecutionTaskCreated(lifecycleCtx, execution.ID, created.ID, name+"-owner", execution.AttemptCount)
	}); err != nil {
		t.Fatal(err)
	}
	fixture := recoveryTestFixture{execution: execution, task: task, steps: map[string]domain.ID{}}
	if runStatus != nil {
		fixture.runID = domain.NewID()
		completedAt := (*time.Time)(nil)
		if recoveryRunTerminal(*runStatus) {
			completedAt = &now
		}
		state := &workflow.State{
			Run:   domain.WorkflowRun{ID: fixture.runID, TaskID: task.ID, WorkflowDefinitionID: env.definitionID, WorkflowVersion: "1", Status: *runStatus, StartedAt: &now, CompletedAt: completedAt, TriggerSource: "run_now", Summary: json.RawMessage(`{"marker":"preserved"}`)},
			Steps: map[string]*workflow.StepState{},
		}
		for _, spec := range specs {
			stepID := domain.NewID()
			fixture.steps[spec.name] = stepID
			var startedAt, stepCompletedAt *time.Time
			if spec.started {
				startedAt = &now
			}
			if spec.completed {
				stepCompletedAt = &now
			}
			approvalState := spec.approvalState
			if approvalState == "" {
				approvalState = "not_required"
			}
			state.Steps[spec.name] = &workflow.StepState{Run: domain.StepRun{ID: stepID, WorkflowRunID: fixture.runID, StepDefinitionID: spec.name, Capability: "test." + spec.name, Status: spec.status, AttemptCount: spec.attemptCount, Input: json.RawMessage(`{"input":"preserved"}`), Output: spec.output, StartedAt: startedAt, CompletedAt: stepCompletedAt, IdempotencyKey: name + "-" + spec.name, ApprovalState: approvalState}}
		}
		fencedCtx := WithScheduledExecutionFence(env.ctx, ScheduledExecutionFence{ExecutionID: execution.ID, LeaseOwner: name + "-owner", Attempt: execution.AttemptCount})
		if err := env.store.saveWorkflowState(fencedCtx, state, func(lifecycleCtx context.Context, state *workflow.State) error {
			return env.store.MarkScheduledExecutionRunning(lifecycleCtx, execution.ID, task.ID, state.Run.ID, nil, name+"-owner", execution.AttemptCount)
		}); err != nil {
			t.Fatal(err)
		}
		if len(specs) == 1 && (specs[0].approvalState == "pending" || specs[0].approvalState == "approved") {
			var approvalID domain.ID
			if err := env.store.Pool.QueryRow(env.ctx, `SELECT id FROM approvals WHERE request_id=$1`, fixture.steps[specs[0].name]).Scan(&approvalID); err != nil {
				t.Fatal(err)
			}
			fixture.approval = &approvalID
		}
	}
	if taskStatus != domain.TaskRunning {
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE tasks SET status=$2 WHERE id=$1`, task.ID, taskStatus); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func expireRecoveryLease(t *testing.T, env recoveryTestEnvironment, executionID domain.ID, seconds int) {
	t.Helper()
	if _, err := env.store.Pool.Exec(env.ctx, `UPDATE scheduled_executions SET lease_expires_at=clock_timestamp()-make_interval(secs=>$2) WHERE id=$1`, executionID, seconds); err != nil {
		t.Fatal(err)
	}
}

func insertRecoveryPendingExecution(t *testing.T, env recoveryTestEnvironment, scheduleID domain.ID) domain.ID {
	t.Helper()
	id := domain.NewID()
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO scheduled_executions(id,schedule_id,planned_at,trigger_source,status,created_at,updated_at)
		VALUES($1,$2,clock_timestamp(),'run_now','pending',clock_timestamp(),clock_timestamp())`, id, scheduleID); err != nil {
		t.Fatal(err)
	}
	return id
}

func reconcileRecovery(t *testing.T, env recoveryTestEnvironment) {
	t.Helper()
	if err := env.store.reconcileStaleScheduledExecutions(env.ctx, staleReconciliationBatchLimit); err != nil {
		t.Fatal(err)
	}
}

func installRecoveryTaskAdvisoryBarrier(t *testing.T, env recoveryTestEnvironment) {
	t.Helper()
	if _, err := env.store.Pool.Exec(env.ctx, `CREATE FUNCTION scheduler_recovery_task_barrier() RETURNS trigger AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(hashtext(NEW.id::text));
			RETURN NEW;
		END;
	$$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.Pool.Exec(env.ctx, `CREATE TRIGGER scheduler_recovery_task_barrier BEFORE UPDATE OF status ON tasks FOR EACH ROW EXECUTE FUNCTION scheduler_recovery_task_barrier()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := env.store.Pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS scheduler_recovery_task_barrier ON tasks`); err != nil {
			t.Errorf("drop recovery barrier trigger: %v", err)
		}
		if _, err := env.store.Pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS scheduler_recovery_task_barrier()`); err != nil {
			t.Errorf("drop recovery barrier function: %v", err)
		}
	})
}

func holdRecoveryTaskAdvisoryLock(t *testing.T, env recoveryTestEnvironment, taskID domain.ID) func() {
	t.Helper()
	conn, err := env.store.Pool.Acquire(env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var key int32
	if err := conn.QueryRow(env.ctx, `SELECT hashtext($1::text)`, taskID).Scan(&key); err != nil {
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
			t.Errorf("release task advisory lock: %v", err)
		}
		conn.Release()
	}
}

func waitForRecoveryTaskWaiters(t *testing.T, ctx context.Context, env recoveryTestEnvironment, want int) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var count int
		if err := env.store.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE datname=current_database()
			  AND wait_event_type='Lock'
			  AND position('UPDATE tasks' in query)>0`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count >= want {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("saw %d of %d concurrently blocked recovery workers: %v", count, want, ctx.Err())
		}
	}
}

func insertRecoveryTool(t *testing.T, env recoveryTestEnvironment, stepID domain.ID, completed bool) domain.ID {
	t.Helper()
	id := domain.NewID()
	now := time.Now().UTC()
	var completedAt *time.Time
	var exitCode *int
	if completed {
		completedAt = &now
		zero := 0
		exitCode = &zero
	}
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,tool_version,sanitized_arguments,execution_environment,started_at,completed_at,exit_code) VALUES($1,$2,'test.provider','fixture','1',$3,$4,$5,$6,$7)`, id, stepID, json.RawMessage(`{"marker":"preserved"}`), json.RawMessage(`{"environment":"isolated"}`), now, completedAt, exitCode); err != nil {
		t.Fatal(err)
	}
	return id
}

func insertRecoveryEvidence(t *testing.T, env recoveryTestEnvironment, fixture recoveryTestFixture, toolID domain.ID) (domain.ID, domain.ID) {
	t.Helper()
	now := time.Now().UTC()
	artifactID := domain.NewID()
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,storage_location,created_at,redaction_state,sensitive) VALUES($1,$2,$3,$4,$5,'stdout','application/json',8,'preserved-sha','artifact://preserved',$6,'redacted',false)`, artifactID, fixture.task.ID, fixture.runID, fixture.steps["done"], toolID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.Pool.Exec(env.ctx, `UPDATE tool_runs SET stdout_artifact_id=$2 WHERE id=$1`, toolID, artifactID); err != nil {
		t.Fatal(err)
	}
	assetID, observationID := domain.NewID(), domain.NewID()
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO assets(id,program_id,type,canonical_value,created_at,updated_at) VALUES($1,$2,'url','http://127.0.0.1/',$3,$3)`, assetID, env.programID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO asset_observations(id,asset_id,workflow_run_id,source_capability,observed_value,metadata,first_seen_at,observed_at,confidence,evidence_artifact_ids) VALUES($1,$2,$3,'probe.http','http://127.0.0.1/',$4,$5,$5,1,$6)`, observationID, assetID, fixture.runID, json.RawMessage(`{"url":"http://127.0.0.1/","status_code":200}`), now, []string{string(artifactID)}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,tool_run_id,safe_message,details) VALUES($1,'terminal_evidence','test','test',$2,$3,$4,$5,$6,'preserved evidence',$7)`, domain.NewID(), fixture.task.ID, env.programID, fixture.runID, fixture.steps["done"], toolID, json.RawMessage(`{"marker":"preserved"}`)); err != nil {
		t.Fatal(err)
	}
	return artifactID, observationID
}

func insertRecoveryApproval(t *testing.T, env recoveryTestEnvironment, fixture recoveryTestFixture, decision string, stepID domain.ID) domain.ID {
	t.Helper()
	id := domain.NewID()
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO approvals(id,request_id,task_id,action_request_id,requested_risk_level,reason,decision,decided_by,decided_at) VALUES($1,$2,$3,$2,'moderate','fixture',$4,'fixture',clock_timestamp())`, id, stepID, fixture.task.ID, decision); err != nil {
		t.Fatal(err)
	}
	return id
}

func terminalStepForRun(status domain.RunStatus) domain.StepStatus {
	if status == domain.RunCancelled {
		return domain.StepCancelled
	}
	return domain.StepFailed
}

func recoveryEvidenceSnapshot(t *testing.T, env recoveryTestEnvironment, runID, stepID, toolID, artifactID, observationID domain.ID) string {
	t.Helper()
	var run, step, tool, artifact, observation string
	queries := []struct {
		query string
		id    domain.ID
		out   *string
	}{
		{`SELECT jsonb_build_object('status',status,'completed_at',completed_at,'summary',summary)::text FROM workflow_runs WHERE id=$1`, runID, &run},
		{`SELECT jsonb_build_object('status',status,'output',output,'error_classification',error_classification,'completed_at',completed_at)::text FROM step_runs WHERE id=$1`, stepID, &step},
		{`SELECT jsonb_build_object('completed_at',completed_at,'exit_code',exit_code,'sanitized_arguments',sanitized_arguments,'stdout_artifact_id',stdout_artifact_id)::text FROM tool_runs WHERE id=$1`, toolID, &tool},
		{`SELECT jsonb_build_object('sha256',sha256,'storage_location',storage_location,'redaction_state',redaction_state)::text FROM artifacts WHERE id=$1`, artifactID, &artifact},
		{`SELECT jsonb_build_object('observed_value',observed_value,'metadata',metadata,'evidence_artifact_ids',evidence_artifact_ids)::text FROM asset_observations WHERE id=$1`, observationID, &observation},
	}
	for _, item := range queries {
		if err := env.store.Pool.QueryRow(env.ctx, item.query, item.id).Scan(item.out); err != nil {
			t.Fatal(err)
		}
	}
	var evidenceAudits int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT count(*) FROM audit_events WHERE workflow_run_id=$1 AND event_type='terminal_evidence'`, runID).Scan(&evidenceAudits); err != nil {
		t.Fatal(err)
	}
	return strings.Join([]string{run, step, tool, artifact, observation, strconv.Itoa(evidenceAudits)}, "|")
}

func execWithoutForeignKeys(t *testing.T, env recoveryTestEnvironment, query string, args ...any) {
	t.Helper()
	conn, err := env.store.Pool.Acquire(env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(env.ctx, `SET session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := conn.Exec(context.Background(), `SET session_replication_role='origin'`); err != nil {
			t.Errorf("restore replication role: %v", err)
		}
	}()
	if _, err := conn.Exec(env.ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}

func assertScheduledRecovery(t *testing.T, env recoveryTestEnvironment, id domain.ID, status domain.ScheduledExecutionStatus, classification, summary string, attempt int) {
	t.Helper()
	var gotStatus domain.ScheduledExecutionStatus
	var gotClassification, gotSummary, owner string
	var gotAttempt int
	var lease, completed *time.Time
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT status,error_classification,error_summary,attempt_count,lease_owner,lease_expires_at,completed_at FROM scheduled_executions WHERE id=$1`, id).Scan(&gotStatus, &gotClassification, &gotSummary, &gotAttempt, &owner, &lease, &completed); err != nil {
		t.Fatal(err)
	}
	if gotStatus != status || gotClassification != classification || gotSummary != summary || gotAttempt != attempt || owner != "" || lease != nil {
		t.Fatalf("scheduled status=%s class=%q summary=%q attempt=%d owner=%q lease=%v", gotStatus, gotClassification, gotSummary, gotAttempt, owner, lease)
	}
	terminal := status == domain.ScheduledExecutionInterrupted || status == domain.ScheduledExecutionFailed || status == domain.ScheduledExecutionCancelled || status == domain.ScheduledExecutionApprovalRejected || status == domain.ScheduledExecutionCompleted
	if terminal != (completed != nil) {
		t.Fatalf("scheduled completed_at=%v for status=%s", completed, status)
	}
}

func assertScheduledRecoveryStatusAndClass(t *testing.T, env recoveryTestEnvironment, id domain.ID, wantStatus domain.ScheduledExecutionStatus, wantClass string) {
	t.Helper()
	var status domain.ScheduledExecutionStatus
	var classification string
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT status,error_classification FROM scheduled_executions WHERE id=$1`, id).Scan(&status, &classification); err != nil {
		t.Fatal(err)
	}
	if status != wantStatus || classification != wantClass {
		t.Fatalf("scheduled status=%s class=%q want status=%s class=%q", status, classification, wantStatus, wantClass)
	}
}

func assertScheduledStatusAndAttempt(t *testing.T, env recoveryTestEnvironment, id domain.ID, wantStatus domain.ScheduledExecutionStatus, wantAttempt int) {
	t.Helper()
	var status domain.ScheduledExecutionStatus
	var attempt int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT status,attempt_count FROM scheduled_executions WHERE id=$1`, id).Scan(&status, &attempt); err != nil {
		t.Fatal(err)
	}
	if status != wantStatus || attempt != wantAttempt {
		t.Fatalf("scheduled %s status=%s attempt=%d want status=%s attempt=%d", id, status, attempt, wantStatus, wantAttempt)
	}
}

func assertExpiredActiveRecoveryLease(t *testing.T, env recoveryTestEnvironment, id domain.ID) {
	t.Helper()
	var active, expired bool
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT status IN ('claimed','running'),lease_expires_at<=clock_timestamp() FROM scheduled_executions WHERE id=$1`, id).Scan(&active, &expired); err != nil {
		t.Fatal(err)
	}
	if !active || !expired {
		t.Fatalf("scheduled %s active=%v expired=%v", id, active, expired)
	}
}

func assertTaskRecoveryStatus(t *testing.T, env recoveryTestEnvironment, id domain.ID, want domain.TaskStatus) {
	t.Helper()
	var got domain.TaskStatus
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT status FROM tasks WHERE id=$1`, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("task %s status=%s want=%s", id, got, want)
	}
}

func assertWorkflowRecoveryStatus(t *testing.T, env recoveryTestEnvironment, id domain.ID, want domain.RunStatus) {
	t.Helper()
	var got domain.RunStatus
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT status FROM workflow_runs WHERE id=$1`, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("workflow %s status=%s want=%s", id, got, want)
	}
}

func assertStepRecoveryStatus(t *testing.T, env recoveryTestEnvironment, id domain.ID, want domain.StepStatus) {
	t.Helper()
	var got domain.StepStatus
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT status FROM step_runs WHERE id=$1`, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("step %s status=%s want=%s", id, got, want)
	}
}

func assertStepRecoveryClassification(t *testing.T, env recoveryTestEnvironment, id domain.ID, want string) {
	t.Helper()
	var got string
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT error_classification FROM step_runs WHERE id=$1`, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("step %s classification=%q want=%q", id, got, want)
	}
}

func assertApprovalDecision(t *testing.T, env recoveryTestEnvironment, id domain.ID, want string) {
	t.Helper()
	var got string
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT decision FROM approvals WHERE id=$1`, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("approval %s decision=%q want=%q", id, got, want)
	}
}

func assertExecutionLineage(t *testing.T, env recoveryTestEnvironment, id domain.ID, taskID, workflowRunID *domain.ID) {
	t.Helper()
	var gotTaskID, gotWorkflowRunID *domain.ID
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT task_id,workflow_run_id FROM scheduled_executions WHERE id=$1`, id).Scan(&gotTaskID, &gotWorkflowRunID); err != nil {
		t.Fatal(err)
	}
	if !sameRecoveryID(gotTaskID, taskID) || !sameRecoveryID(gotWorkflowRunID, workflowRunID) {
		t.Fatalf("lineage task=%v workflow=%v want task=%v workflow=%v", gotTaskID, gotWorkflowRunID, taskID, workflowRunID)
	}
}

func sameRecoveryID(left, right *domain.ID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func assertRecoveryAuditCount(t *testing.T, env recoveryTestEnvironment, executionID domain.ID, event string, want int) {
	t.Helper()
	var got int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT count(*) FROM audit_events WHERE event_type=$1 AND details->>'scheduled_execution_id'=$2`, event, executionID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("audit %s count=%d want=%d", event, got, want)
	}
}

func assertEntityAuditCount(t *testing.T, env recoveryTestEnvironment, event, column string, id domain.ID, want int) {
	t.Helper()
	if column != "task_id" && column != "workflow_run_id" && column != "step_run_id" && column != "tool_run_id" {
		t.Fatalf("unsupported audit column %q", column)
	}
	var got int
	query := `SELECT count(*) FROM audit_events WHERE event_type=$1 AND ` + column + `=$2`
	if err := env.store.Pool.QueryRow(env.ctx, query, event, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("audit %s %s=%s count=%d want=%d", event, column, id, got, want)
	}
}

func assertRecoveryReason(t *testing.T, env recoveryTestEnvironment, executionID domain.ID, event, want string) {
	t.Helper()
	details := recoveryAuditRecord(t, env, executionID, event)
	if got := details["reason_code"]; got != want {
		t.Fatalf("audit reason=%v want=%q", got, want)
	}
}

func assertManualReviewAudit(t *testing.T, env recoveryTestEnvironment, executionID domain.ID, event string) {
	t.Helper()
	details := recoveryAuditRecord(t, env, executionID, event)
	if manual, ok := details["manual_review_required"].(bool); !ok || !manual {
		t.Fatalf("manual_review_required=%v", details["manual_review_required"])
	}
	if retry, ok := details["retry_allowed"].(bool); !ok || retry {
		t.Fatalf("retry_allowed=%v", details["retry_allowed"])
	}
}

func assertManualReviewConflict(t *testing.T, env recoveryTestEnvironment, executionID domain.ID, want string) {
	t.Helper()
	details := recoveryAuditRecord(t, env, executionID, "scheduled_execution_lineage_inconsistent")
	assertManualReviewAudit(t, env, executionID, "scheduled_execution_lineage_inconsistent")
	conflicts, ok := details["conflicts"].([]any)
	if !ok {
		t.Fatalf("conflicts=%T %#v", details["conflicts"], details["conflicts"])
	}
	for _, conflict := range conflicts {
		if conflict == want {
			return
		}
	}
	t.Fatalf("conflicts=%v missing %q", conflicts, want)
}

func assertRecoveryAuditIDs(t *testing.T, env recoveryTestEnvironment, executionID domain.ID, event, field string, want []domain.ID) {
	t.Helper()
	details := recoveryAuditRecord(t, env, executionID, event)
	raw, ok := details[field].([]any)
	if !ok {
		t.Fatalf("audit %s field %s=%T %#v", event, field, details[field], details[field])
	}
	got := make([]domain.ID, 0, len(raw))
	for _, value := range raw {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("audit %s field %s contains %T %#v", event, field, value, value)
		}
		got = append(got, domain.ID(text))
	}
	got = sortedUniqueRecoveryIDs(got)
	want = sortedUniqueRecoveryIDs(want)
	if len(got) != len(want) {
		t.Fatalf("audit %s field %s=%v want=%v", event, field, got, want)
	}
	for index := range got {
		if got[index] != want[index] {
			t.Fatalf("audit %s field %s=%v want=%v", event, field, got, want)
		}
	}
	countField := strings.TrimSuffix(field, "_ids") + "_count"
	if count, ok := details[countField].(float64); !ok || int(count) != len(got) {
		t.Fatalf("audit %s field %s=%v want=%d", event, countField, details[countField], len(got))
	}
}

func assertScenarioHClosed(t *testing.T, env recoveryTestEnvironment, fixture recoveryTestFixture, conflicts []string) {
	t.Helper()
	assertScheduledRecoveryStatusAndClass(t, env, fixture.execution.ID, domain.ScheduledExecutionInterrupted, "lineage_inconsistent")
	assertTaskRecoveryStatus(t, env, fixture.task.ID, domain.TaskFailed)
	assertWorkflowRecoveryStatus(t, env, fixture.runID, domain.RunFailed)
	for _, conflict := range conflicts {
		assertManualReviewConflict(t, env, fixture.execution.ID, conflict)
	}
}

func recoveryAuditRecord(t *testing.T, env recoveryTestEnvironment, executionID domain.ID, event string) map[string]any {
	t.Helper()
	var raw json.RawMessage
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT details FROM audit_events WHERE event_type=$1 AND details->>'scheduled_execution_id'=$2 ORDER BY occurred_at DESC LIMIT 1`, event, executionID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var details map[string]any
	if err := json.Unmarshal(raw, &details); err != nil {
		t.Fatal(err)
	}
	return details
}
