package database

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type staleRecoveryEntry struct {
	item            domain.ScheduledExecution
	programID       domain.ID
	protocolVersion int
}

type recoveryTask struct {
	id        domain.ID
	programID domain.ID
	status    domain.TaskStatus
}

type recoveryWorkflow struct {
	id          domain.ID
	taskID      domain.ID
	status      domain.RunStatus
	completedAt *time.Time
}

type recoveryStep struct {
	id                  domain.ID
	workflowRunID       domain.ID
	status              domain.StepStatus
	attemptCount        int
	hasOutput           bool
	hasProviderEvidence bool
	startedAt           *time.Time
	completedAt         *time.Time
	approvalState       string
	capability          string
	errorClassification string
}

type recoveryTool struct {
	id          domain.ID
	stepRunID   domain.ID
	capability  string
	provider    string
	completedAt *time.Time
	exitCode    *int
}

type recoveryApproval struct {
	id              domain.ID
	requestID       domain.ID
	taskID          domain.ID
	actionRequestID domain.ID
	decision        string
}

type staleLineage struct {
	tasks           []recoveryTask
	workflow        *recoveryWorkflow
	steps           []recoveryStep
	tools           []recoveryTool
	approvals       []recoveryApproval
	missingTaskIDs  []domain.ID
	missingWorkflow bool
	conflicts       []string
}

type recoveryStepMode string

const (
	recoveryStepsUnchanged       recoveryStepMode = ""
	recoveryStepsCancelUnstarted recoveryStepMode = "cancel_unstarted"
	recoveryStepsInterruptActive recoveryStepMode = "interrupt_active"
)

type staleReconciliation struct {
	scenario            string
	reasonCode          string
	scheduledStatus     domain.ScheduledExecutionStatus
	taskStatus          *domain.TaskStatus
	workflowStatus      *domain.RunStatus
	stepMode            recoveryStepMode
	closeTools          bool
	expireApprovals     bool
	errorClassification string
	errorSummary        string
	eventType           string
	eventMessage        string
	retryAllowed        bool
	manualReview        bool
	completedAt         *time.Time
	eligibleTaskIDs     []domain.ID
	eligibleWorkflow    bool
	eligibleStepIDs     []domain.ID
	eligibleToolIDs     []domain.ID
	eligibleApprovalIDs []domain.ID
}

func (s *Store) reconcileStaleScheduledExecutions(ctx context.Context, limit int) error {
	if limit < 1 {
		return nil
	}
	excluded := make([]domain.ID, 0, limit)
	for attempts := 0; attempts < limit; attempts++ {
		tx, err := s.Pool.Begin(ctx)
		if err != nil {
			return err
		}
		entry, found, err := lockNextStaleScheduledExecution(ctx, tx, excluded)
		if err != nil {
			tx.Rollback(ctx)
			return err
		}
		if !found {
			tx.Rollback(ctx)
			return nil
		}
		excluded = append(excluded, entry.item.ID)
		stillStale, err := staleExecutionLeaseExpired(ctx, tx, entry.item.ID)
		if err != nil {
			tx.Rollback(ctx)
			return err
		}
		if !stillStale {
			tx.Rollback(ctx)
			continue
		}
		lineage, locked, err := lockScheduledExecutionLineage(ctx, tx, entry)
		if err != nil {
			tx.Rollback(ctx)
			return err
		}
		if !locked {
			tx.Rollback(ctx)
			continue
		}
		plan := classifyStaleLineage(entry, &lineage)
		if err := applyStaleLineageReconciliation(ctx, tx, entry, lineage, plan); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// lockNextStaleScheduledExecution establishes the recovery root lock. Every
// descendant is then locked in stable ID order. Descendant SKIP LOCKED checks
// deliberately defer a lineage being persisted through an older reverse-order
// path instead of creating a scheduler/workflow deadlock.
func lockNextStaleScheduledExecution(ctx context.Context, tx pgx.Tx, excluded []domain.ID) (staleRecoveryEntry, bool, error) {
	var entry staleRecoveryEntry
	err := tx.QueryRow(ctx, `SELECT se.id,se.schedule_id,se.planned_at,se.trigger_source,se.status,se.task_id,se.workflow_run_id,se.scope_version_id,se.attempt_count,se.lease_owner,se.lease_expires_at,se.error_classification,se.error_summary,se.started_at,se.completed_at,se.created_at,se.updated_at,s.program_id,se.recovery_protocol_version
		FROM scheduled_executions se
		JOIN schedules s ON s.id=se.schedule_id
		WHERE se.status IN ('claimed','running')
		  AND se.lease_expires_at<=clock_timestamp()
		  AND NOT (se.id=ANY($1::uuid[]))
		ORDER BY se.lease_expires_at,se.id
		LIMIT 1
		FOR UPDATE OF se SKIP LOCKED`, idStrings(excluded)).Scan(
		&entry.item.ID, &entry.item.ScheduleID, &entry.item.PlannedAt, &entry.item.TriggerSource, &entry.item.Status,
		&entry.item.TaskID, &entry.item.WorkflowRunID, &entry.item.ScopeVersionID, &entry.item.AttemptCount,
		&entry.item.LeaseOwner, &entry.item.LeaseExpiresAt, &entry.item.ErrorClassification, &entry.item.ErrorSummary,
		&entry.item.StartedAt, &entry.item.CompletedAt, &entry.item.CreatedAt, &entry.item.UpdatedAt,
		&entry.programID, &entry.protocolVersion,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return staleRecoveryEntry{}, false, nil
	}
	return entry, err == nil, err
}

func staleExecutionLeaseExpired(ctx context.Context, tx pgx.Tx, id domain.ID) (bool, error) {
	var stale bool
	err := tx.QueryRow(ctx, `SELECT status IN ('claimed','running') AND lease_expires_at<=clock_timestamp() FROM scheduled_executions WHERE id=$1`, id).Scan(&stale)
	return stale, err
}

func lockScheduledExecutionLineage(ctx context.Context, tx pgx.Tx, entry staleRecoveryEntry) (staleLineage, bool, error) {
	lineage := staleLineage{}
	candidateTaskIDs := []domain.ID{}
	if entry.item.TaskID != nil {
		candidateTaskIDs = append(candidateTaskIDs, *entry.item.TaskID)
	}
	var workflowTaskID domain.ID
	workflowExists := false
	if entry.item.WorkflowRunID != nil {
		err := tx.QueryRow(ctx, `SELECT task_id FROM workflow_runs WHERE id=$1`, *entry.item.WorkflowRunID).Scan(&workflowTaskID)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			lineage.missingWorkflow = true
		case err != nil:
			return staleLineage{}, false, err
		default:
			workflowExists = true
			candidateTaskIDs = append(candidateTaskIDs, workflowTaskID)
		}
	}
	candidateTaskIDs = sortedUniqueRecoveryIDs(candidateTaskIDs)

	existingTaskIDs, err := selectRecoveryIDs(ctx, tx, `SELECT id FROM tasks WHERE id=ANY($1::uuid[]) ORDER BY id`, candidateTaskIDs)
	if err != nil {
		return staleLineage{}, false, err
	}
	for _, id := range candidateTaskIDs {
		if !containsRecoveryID(existingTaskIDs, id) {
			lineage.missingTaskIDs = append(lineage.missingTaskIDs, id)
		}
	}
	if len(existingTaskIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT id,program_id,status FROM tasks WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE SKIP LOCKED`, idStrings(existingTaskIDs))
		if err != nil {
			return staleLineage{}, false, err
		}
		for rows.Next() {
			var item recoveryTask
			if err := rows.Scan(&item.id, &item.programID, &item.status); err != nil {
				rows.Close()
				return staleLineage{}, false, err
			}
			lineage.tasks = append(lineage.tasks, item)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return staleLineage{}, false, err
		}
		if len(lineage.tasks) != len(existingTaskIDs) {
			return staleLineage{}, false, nil
		}
	}

	if workflowExists {
		var item recoveryWorkflow
		err := tx.QueryRow(ctx, `SELECT id,task_id,status,completed_at FROM workflow_runs WHERE id=$1 FOR UPDATE SKIP LOCKED`, *entry.item.WorkflowRunID).Scan(&item.id, &item.taskID, &item.status, &item.completedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return staleLineage{}, false, nil
		}
		if err != nil {
			return staleLineage{}, false, err
		}
		lineage.workflow = &item
	}

	if lineage.workflow != nil {
		stepIDs, err := selectRecoveryIDs(ctx, tx, `SELECT id FROM step_runs WHERE workflow_run_id=ANY($1::uuid[]) ORDER BY id`, []domain.ID{lineage.workflow.id})
		if err != nil {
			return staleLineage{}, false, err
		}
		if len(stepIDs) > 0 {
			rows, err := tx.Query(ctx, `SELECT sr.id,sr.workflow_run_id,sr.status,sr.attempt_count,sr.output IS NOT NULL,
				EXISTS(SELECT 1 FROM tool_runs tr WHERE tr.step_run_id=sr.id),
				sr.started_at,sr.completed_at,sr.approval_state,sr.capability,sr.error_classification
				FROM step_runs sr WHERE sr.id=ANY($1::uuid[]) ORDER BY sr.id FOR UPDATE OF sr SKIP LOCKED`, idStrings(stepIDs))
			if err != nil {
				return staleLineage{}, false, err
			}
			for rows.Next() {
				var item recoveryStep
				if err := rows.Scan(&item.id, &item.workflowRunID, &item.status, &item.attemptCount, &item.hasOutput, &item.hasProviderEvidence, &item.startedAt, &item.completedAt, &item.approvalState, &item.capability, &item.errorClassification); err != nil {
					rows.Close()
					return staleLineage{}, false, err
				}
				lineage.steps = append(lineage.steps, item)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return staleLineage{}, false, err
			}
			if len(lineage.steps) != len(stepIDs) {
				return staleLineage{}, false, nil
			}
		}

		incompleteToolIDs, err := selectRecoveryIDs(ctx, tx, `SELECT id FROM tool_runs WHERE step_run_id=ANY($1::uuid[]) AND completed_at IS NULL ORDER BY id`, recoveryStepIDs(lineage.steps))
		if err != nil {
			return staleLineage{}, false, err
		}
		if len(incompleteToolIDs) > 0 {
			rows, err := tx.Query(ctx, `SELECT id,step_run_id,capability,provider,completed_at,exit_code FROM tool_runs WHERE id=ANY($1::uuid[]) AND completed_at IS NULL ORDER BY id FOR UPDATE SKIP LOCKED`, idStrings(incompleteToolIDs))
			if err != nil {
				return staleLineage{}, false, err
			}
			for rows.Next() {
				var item recoveryTool
				if err := rows.Scan(&item.id, &item.stepRunID, &item.capability, &item.provider, &item.completedAt, &item.exitCode); err != nil {
					rows.Close()
					return staleLineage{}, false, err
				}
				lineage.tools = append(lineage.tools, item)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return staleLineage{}, false, err
			}
			if len(lineage.tools) != len(incompleteToolIDs) {
				return staleLineage{}, false, nil
			}
		}
	}

	approvalIDs := []domain.ID{}
	if len(lineage.steps) > 0 || len(candidateTaskIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT id FROM approvals
			WHERE request_id=ANY($1::uuid[])
			   OR (task_id=ANY($2::uuid[]) AND decision='pending')
			ORDER BY id`, idStrings(recoveryStepIDs(lineage.steps)), idStrings(candidateTaskIDs))
		if err != nil {
			return staleLineage{}, false, err
		}
		for rows.Next() {
			var id domain.ID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return staleLineage{}, false, err
			}
			approvalIDs = append(approvalIDs, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return staleLineage{}, false, err
		}
	}
	if len(approvalIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT id,request_id,task_id,action_request_id,decision FROM approvals WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE SKIP LOCKED`, idStrings(approvalIDs))
		if err != nil {
			return staleLineage{}, false, err
		}
		for rows.Next() {
			var item recoveryApproval
			if err := rows.Scan(&item.id, &item.requestID, &item.taskID, &item.actionRequestID, &item.decision); err != nil {
				rows.Close()
				return staleLineage{}, false, err
			}
			lineage.approvals = append(lineage.approvals, item)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return staleLineage{}, false, err
		}
		if len(lineage.approvals) != len(approvalIDs) {
			return staleLineage{}, false, nil
		}
	}
	return lineage, true, nil
}

func selectRecoveryIDs(ctx context.Context, tx pgx.Tx, query string, ids []domain.ID) ([]domain.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, query, idStrings(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.ID{}
	for rows.Next() {
		var id domain.ID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func classifyStaleLineage(entry staleRecoveryEntry, lineage *staleLineage) (plan staleReconciliation) {
	defer func() {
		sort.Strings(lineage.conflicts)
		plan = withRecoveryEligibility(entry, *lineage, plan)
	}()
	item := entry.item
	for _, id := range lineage.missingTaskIDs {
		lineage.conflicts = append(lineage.conflicts, "missing_task:"+string(id))
	}
	if lineage.missingWorkflow && item.WorkflowRunID != nil {
		lineage.conflicts = append(lineage.conflicts, "missing_workflow:"+string(*item.WorkflowRunID))
	}
	if item.WorkflowRunID != nil && item.TaskID == nil {
		lineage.conflicts = append(lineage.conflicts, "workflow_link_without_scheduled_task")
	}
	if lineage.workflow != nil && item.TaskID != nil && lineage.workflow.taskID != *item.TaskID {
		lineage.conflicts = append(lineage.conflicts, fmt.Sprintf("workflow_task_mismatch:%s:%s", *item.TaskID, lineage.workflow.taskID))
	}
	for _, task := range lineage.tasks {
		if task.programID != entry.programID {
			lineage.conflicts = append(lineage.conflicts, fmt.Sprintf("task_program_mismatch:%s:%s", task.id, task.programID))
		}
	}
	stepByID := make(map[domain.ID]recoveryStep, len(lineage.steps))
	for _, step := range lineage.steps {
		stepByID[step.id] = step
	}
	approvalByStep := map[domain.ID][]recoveryApproval{}
	hasRejectedApproval := false
	for _, approval := range lineage.approvals {
		step, found := stepByID[approval.requestID]
		if !found {
			if approval.decision == "pending" {
				lineage.conflicts = append(lineage.conflicts, "approval_not_linked_to_workflow_step:"+string(approval.id))
			}
			continue
		}
		approvalByStep[step.id] = append(approvalByStep[step.id], approval)
		if lineage.workflow == nil || approval.taskID != lineage.workflow.taskID {
			lineage.conflicts = append(lineage.conflicts, "approval_task_mismatch:"+string(approval.id))
		}
		if approval.actionRequestID != approval.requestID {
			lineage.conflicts = append(lineage.conflicts, "approval_request_mismatch:"+string(approval.id))
		}
		if step.status != domain.StepAwaitingApproval && approval.decision == "pending" {
			lineage.conflicts = append(lineage.conflicts, "active_approval_for_nonawaiting_step:"+string(approval.id))
		}
		if approval.decision == "rejected" && step.status == domain.StepFailed && (step.approvalState == "rejected" || step.errorClassification == "approval_rejected") {
			hasRejectedApproval = true
		}
	}
	hasApprovalGate := false
	for _, step := range lineage.steps {
		if step.status != domain.StepAwaitingApproval {
			continue
		}
		hasApprovalGate = true
		approvals := approvalByStep[step.id]
		if len(approvals) != 1 {
			lineage.conflicts = append(lineage.conflicts, "awaiting_step_approval_count:"+string(step.id))
			continue
		}
		if approvals[0].decision != "pending" && approvals[0].decision != "approved" {
			lineage.conflicts = append(lineage.conflicts, "awaiting_step_invalid_approval:"+string(step.id))
		}
	}

	if lineage.workflow != nil {
		workflowTerminal := recoveryRunTerminal(lineage.workflow.status)
		if workflowTerminal && lineage.workflow.completedAt == nil {
			lineage.conflicts = append(lineage.conflicts, "terminal_workflow_missing_completion")
		}
		if workflowTerminal {
			for _, step := range lineage.steps {
				if !recoveryStepTerminal(step.status) {
					lineage.conflicts = append(lineage.conflicts, "terminal_workflow_active_step:"+string(step.id))
				}
			}
			if len(lineage.tools) > 0 {
				lineage.conflicts = append(lineage.conflicts, "terminal_workflow_incomplete_tool")
			}
		}
		for _, task := range lineage.tasks {
			if task.id != lineage.workflow.taskID {
				continue
			}
			if !workflowTerminal && recoveryTaskTerminal(task.status) {
				lineage.conflicts = append(lineage.conflicts, "active_workflow_terminal_task:"+string(task.id))
			}
			if workflowTerminal && recoveryTaskTerminal(task.status) && !taskMatchesWorkflowTerminal(task.status, lineage.workflow.status) {
				lineage.conflicts = append(lineage.conflicts, "terminal_task_workflow_mismatch:"+string(task.id))
			}
		}
	}
	if hasRejectedApproval && (lineage.workflow == nil || lineage.workflow.status != domain.RunFailed) {
		lineage.conflicts = append(lineage.conflicts, "rejected_approval_without_failed_workflow")
	}
	if lineage.workflow == nil && item.TaskID != nil {
		for _, task := range lineage.tasks {
			if recoveryTaskTerminal(task.status) {
				lineage.conflicts = append(lineage.conflicts, "terminal_task_without_workflow:"+string(task.id))
			}
		}
	}
	if len(lineage.conflicts) > 0 {
		return inconsistentReconciliation()
	}

	if lineage.workflow == nil {
		if item.TaskID == nil {
			if item.Status == domain.ScheduledExecutionClaimed && entry.protocolVersion == 1 {
				return staleReconciliation{scenario: "A", reasonCode: "safe_no_lineage_claim", scheduledStatus: domain.ScheduledExecutionPending, eventType: "scheduled_execution_stale_claim_recovered", eventMessage: "stale claim returned to pending", retryAllowed: true}
			}
			return inconsistentReconciliation()
		}
		failed := domain.TaskFailed
		return staleReconciliation{scenario: "B", reasonCode: "task_created_without_workflow", scheduledStatus: domain.ScheduledExecutionInterrupted, taskStatus: &failed, errorClassification: "interrupted", errorSummary: "scheduler lease expired after task creation but before workflow state was established", eventType: "scheduled_execution_lineage_interrupted", eventMessage: "scheduled execution lineage interrupted after lease expiry"}
	}

	if hasRejectedApproval {
		failed := domain.TaskFailed
		return staleReconciliation{scenario: "G", reasonCode: "approval_rejected", scheduledStatus: domain.ScheduledExecutionApprovalRejected, taskStatus: &failed, errorClassification: "approval_rejected", errorSummary: "moderate step approval was rejected", eventType: "scheduled_execution_terminal_reconciled", eventMessage: "scheduled execution reconciled from rejected approval"}
	}
	if hasApprovalGate {
		pausedTask, pausedRun := domain.TaskPaused, domain.RunPaused
		return staleReconciliation{scenario: "G", reasonCode: "approval_gate", scheduledStatus: domain.ScheduledExecutionPausedForApproval, taskStatus: &pausedTask, workflowStatus: &pausedRun, eventType: "scheduled_execution_pause_reconciled", eventMessage: "scheduled execution reconciled to approval pause"}
	}

	switch lineage.workflow.status {
	case domain.RunCompleted:
		completed := domain.TaskCompleted
		return staleReconciliation{scenario: "F", reasonCode: "workflow_completed", scheduledStatus: domain.ScheduledExecutionCompleted, taskStatus: &completed, eventType: "scheduled_execution_terminal_reconciled", eventMessage: "scheduled execution reconciled from completed workflow", completedAt: lineage.workflow.completedAt}
	case domain.RunFailed:
		failed := domain.TaskFailed
		return staleReconciliation{scenario: "G", reasonCode: "workflow_failed", scheduledStatus: domain.ScheduledExecutionFailed, taskStatus: &failed, errorClassification: "execution", errorSummary: "persisted workflow was already failed when scheduler lease expired", eventType: "scheduled_execution_terminal_reconciled", eventMessage: "scheduled execution reconciled from failed workflow", completedAt: lineage.workflow.completedAt}
	case domain.RunCancelled:
		cancelled := domain.TaskCancelled
		return staleReconciliation{scenario: "G", reasonCode: "workflow_cancelled", scheduledStatus: domain.ScheduledExecutionCancelled, taskStatus: &cancelled, errorClassification: "cancelled", errorSummary: "workflow execution was cancelled", eventType: "scheduled_execution_terminal_reconciled", eventMessage: "scheduled execution reconciled from cancelled workflow", completedAt: lineage.workflow.completedAt}
	case domain.RunPaused:
		for _, step := range lineage.steps {
			if step.status == domain.StepRunning || step.status == domain.StepQueued || step.status == domain.StepRetryable {
				lineage.conflicts = append(lineage.conflicts, "paused_workflow_active_step:"+string(step.id))
			}
		}
		if len(lineage.tools) > 0 || len(lineage.conflicts) > 0 {
			return inconsistentReconciliation()
		}
		pausedTask := domain.TaskPaused
		return staleReconciliation{scenario: "G", reasonCode: "operator_pause", scheduledStatus: domain.ScheduledExecutionPausedOperator, taskStatus: &pausedTask, eventType: "scheduled_execution_pause_reconciled", eventMessage: "scheduled execution reconciled to operator pause"}
	case domain.RunPending, domain.RunRunning:
		failedTask, failedRun := domain.TaskFailed, domain.RunFailed
		if len(lineage.tools) > 0 {
			return staleReconciliation{scenario: "E", reasonCode: "incomplete_tool_run", scheduledStatus: domain.ScheduledExecutionInterrupted, taskStatus: &failedTask, workflowStatus: &failedRun, stepMode: recoveryStepsInterruptActive, closeTools: true, expireApprovals: true, errorClassification: "interrupted", errorSummary: "scheduler lease expired with an incomplete tool run; provider outcome is unknown", eventType: "scheduled_execution_lineage_interrupted", eventMessage: "scheduled execution interrupted with incomplete provider work"}
		}
		if recoveryHasProgressedStep(lineage.steps) {
			return staleReconciliation{scenario: "D", reasonCode: "workflow_progressed", scheduledStatus: domain.ScheduledExecutionInterrupted, taskStatus: &failedTask, workflowStatus: &failedRun, stepMode: recoveryStepsInterruptActive, closeTools: true, expireApprovals: true, errorClassification: "interrupted", errorSummary: "scheduler lease expired after workflow execution progressed", eventType: "scheduled_execution_lineage_interrupted", eventMessage: "scheduled execution interrupted after workflow progress"}
		}
		return staleReconciliation{scenario: "C", reasonCode: "workflow_without_started_step", scheduledStatus: domain.ScheduledExecutionInterrupted, taskStatus: &failedTask, workflowStatus: &failedRun, stepMode: recoveryStepsCancelUnstarted, closeTools: true, expireApprovals: true, errorClassification: "interrupted", errorSummary: "scheduler lease expired before workflow steps began", eventType: "scheduled_execution_lineage_interrupted", eventMessage: "scheduled execution interrupted before workflow steps began"}
	default:
		return inconsistentReconciliation()
	}
}

func inconsistentReconciliation() staleReconciliation {
	// Tasks and workflow runs have no interrupted status. Failed is their safe
	// terminal representation; the scheduled execution and audits retain the
	// more precise lineage_inconsistent classification.
	failedTask, failedRun := domain.TaskFailed, domain.RunFailed
	return staleReconciliation{scenario: "H", reasonCode: "lineage_inconsistent", scheduledStatus: domain.ScheduledExecutionInterrupted, taskStatus: &failedTask, workflowStatus: &failedRun, stepMode: recoveryStepsInterruptActive, closeTools: true, expireApprovals: true, errorClassification: "lineage_inconsistent", errorSummary: "persisted scheduler lineage is incomplete or contradictory and requires manual review", eventType: "scheduled_execution_lineage_inconsistent", eventMessage: "scheduled execution lineage requires manual review", manualReview: true}
}

// withRecoveryEligibility turns classification into an explicit mutation
// boundary. Reachability alone is insufficient when persisted references
// disagree: ambiguous and foreign-program rows remain available for audit but
// are not eligible for recovery mutations.
func withRecoveryEligibility(entry staleRecoveryEntry, lineage staleLineage, plan staleReconciliation) staleReconciliation {
	taskMismatch := lineage.workflow != nil && entry.item.TaskID != nil && lineage.workflow.taskID != *entry.item.TaskID
	if !taskMismatch {
		for _, task := range lineage.tasks {
			if task.programID != entry.programID {
				continue
			}
			directScheduledTask := entry.item.TaskID != nil && task.id == *entry.item.TaskID
			directWorkflowTask := lineage.workflow != nil && task.id == lineage.workflow.taskID
			if directScheduledTask || directWorkflowTask {
				plan.eligibleTaskIDs = append(plan.eligibleTaskIDs, task.id)
			}
		}
	}
	plan.eligibleTaskIDs = sortedUniqueRecoveryIDs(plan.eligibleTaskIDs)

	plan.eligibleWorkflow = recoveryWorkflowBelongsToProgram(entry.programID, lineage)
	if !plan.eligibleWorkflow {
		return plan
	}
	plan.eligibleStepIDs = sortedUniqueRecoveryIDs(recoveryStepIDs(lineage.steps))
	plan.eligibleToolIDs = sortedUniqueRecoveryIDs(recoveryToolIDs(lineage.tools))
	for _, approval := range lineage.approvals {
		if approval.taskID == lineage.workflow.taskID && containsRecoveryID(plan.eligibleStepIDs, approval.requestID) {
			plan.eligibleApprovalIDs = append(plan.eligibleApprovalIDs, approval.id)
		}
	}
	plan.eligibleApprovalIDs = sortedUniqueRecoveryIDs(plan.eligibleApprovalIDs)
	return plan
}

func applyStaleLineageReconciliation(ctx context.Context, tx pgx.Tx, entry staleRecoveryEntry, lineage staleLineage, plan staleReconciliation) error {
	var recoveredAt time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&recoveredAt); err != nil {
		return err
	}
	base := recoveryAuditDetails(entry, lineage, plan)
	auditTaskID := entry.item.TaskID
	if auditTaskID != nil && containsRecoveryID(lineage.missingTaskIDs, *auditTaskID) {
		auditTaskID = nil
	}
	auditWorkflowRunID := entry.item.WorkflowRunID
	if lineage.missingWorkflow {
		auditWorkflowRunID = nil
	}
	if lineage.workflow != nil && !plan.eligibleWorkflow {
		auditWorkflowRunID = nil
	}
	if plan.taskStatus != nil {
		for index := range lineage.tasks {
			task := &lineage.tasks[index]
			if !containsRecoveryID(plan.eligibleTaskIDs, task.id) || recoveryTaskTerminal(task.status) || task.status == *plan.taskStatus {
				continue
			}
			previous := task.status
			tag, err := tx.Exec(ctx, `UPDATE tasks
				SET status=$2,
				    updated_at=$3,
				    cancelled_at=CASE WHEN $2='cancelled' THEN COALESCE(cancelled_at,$3) ELSE cancelled_at END,
				    cancellation_reason=CASE WHEN $2='cancelled' AND cancellation_reason='' THEN 'workflow was cancelled' ELSE cancellation_reason END
				WHERE id=$1 AND status=$4`, task.id, *plan.taskStatus, recoveredAt, previous)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("reconcile task %s from %s to %s", task.id, previous, *plan.taskStatus)
			}
			task.status = *plan.taskStatus
			details := recoveryChangeDetails(base, previous, task.status)
			var taskWorkflowRunID *domain.ID
			if plan.eligibleWorkflow && lineage.workflow != nil && lineage.workflow.taskID == task.id {
				taskWorkflowRunID = &lineage.workflow.id
			}
			if err := auditRecoveryRow(ctx, tx, "scheduled_task_reconciled", entry.programID, &task.id, taskWorkflowRunID, nil, nil, "", "", "scheduled task reconciled after lease expiry", details); err != nil {
				return err
			}
		}
	}
	if lineage.workflow != nil && plan.eligibleWorkflow && plan.workflowStatus != nil && !recoveryRunTerminal(lineage.workflow.status) && lineage.workflow.status != *plan.workflowStatus {
		previous := lineage.workflow.status
		completedAt := lineage.workflow.completedAt
		if recoveryRunTerminal(*plan.workflowStatus) {
			completedAt = &recoveredAt
		} else if *plan.workflowStatus == domain.RunPaused {
			completedAt = nil
		}
		tag, err := tx.Exec(ctx, `UPDATE workflow_runs SET status=$2,completed_at=$3 WHERE id=$1 AND status=$4`, lineage.workflow.id, *plan.workflowStatus, completedAt, previous)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("reconcile workflow %s from %s to %s", lineage.workflow.id, previous, *plan.workflowStatus)
		}
		lineage.workflow.status, lineage.workflow.completedAt = *plan.workflowStatus, completedAt
		details := recoveryChangeDetails(base, previous, lineage.workflow.status)
		if err := auditRecoveryRow(ctx, tx, "scheduled_workflow_reconciled", entry.programID, &lineage.workflow.taskID, &lineage.workflow.id, nil, nil, "", "", "scheduled workflow reconciled after lease expiry", details); err != nil {
			return err
		}
	}
	for index := range lineage.steps {
		step := &lineage.steps[index]
		if !containsRecoveryID(plan.eligibleStepIDs, step.id) {
			continue
		}
		target, change := recoveryStepTarget(step.status, plan.stepMode)
		if !change {
			continue
		}
		previous := step.status
		errorDetails := "scheduler lease expired before workflow could continue"
		if plan.scenario == "D" || plan.scenario == "E" {
			errorDetails = "provider outcome is unknown after scheduler lease expiry"
		}
		tag, err := tx.Exec(ctx, `UPDATE step_runs
			SET status=$2,
			    error_classification='interrupted',
			    error_details=$3,
			    completed_at=COALESCE(completed_at,$4),
			    approval_state=CASE WHEN approval_state='pending' THEN 'expired' ELSE approval_state END
			WHERE id=$1 AND status=$5`, step.id, target, errorDetails, recoveredAt, previous)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("reconcile step %s from %s to %s", step.id, previous, target)
		}
		step.status = target
		details := recoveryChangeDetails(base, previous, target)
		if err := auditRecoveryRow(ctx, tx, "scheduled_step_reconciled", entry.programID, &lineage.workflow.taskID, &lineage.workflow.id, &step.id, nil, step.capability, "", "scheduled workflow step reconciled after lease expiry", details); err != nil {
			return err
		}
	}
	if plan.closeTools {
		for index := range lineage.tools {
			tool := &lineage.tools[index]
			if !containsRecoveryID(plan.eligibleToolIDs, tool.id) || tool.completedAt != nil {
				continue
			}
			// Tool runs have neither status nor error columns. A recovery timestamp
			// with NULL exit_code is the schema's non-fabricated interruption form.
			tag, err := tx.Exec(ctx, `UPDATE tool_runs SET completed_at=$2 WHERE id=$1 AND completed_at IS NULL`, tool.id, recoveredAt)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("reconcile incomplete tool run %s", tool.id)
			}
			tool.completedAt = &recoveredAt
			details := recoveryChangeDetails(base, "incomplete", "interrupted")
			if err := auditRecoveryRow(ctx, tx, "scheduled_tool_run_interrupted", entry.programID, &lineage.workflow.taskID, &lineage.workflow.id, &tool.stepRunID, &tool.id, tool.capability, tool.provider, "incomplete tool run closed after scheduler lease expiry", details); err != nil {
				return err
			}
		}
	}
	if plan.expireApprovals {
		for index := range lineage.approvals {
			approval := &lineage.approvals[index]
			if !containsRecoveryID(plan.eligibleApprovalIDs, approval.id) || approval.decision != "pending" {
				continue
			}
			tag, err := tx.Exec(ctx, `UPDATE approvals SET decision='expired',decided_by='scheduler',decided_at=$2 WHERE id=$1 AND decision='pending'`, approval.id, recoveredAt)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("expire approval %s during reconciliation", approval.id)
			}
			approval.decision = "expired"
			details := recoveryChangeDetails(base, "pending", "expired")
			details["approval_id"] = approval.id
			if err := auditRecoveryRow(ctx, tx, "scheduled_approval_reconciled", entry.programID, &approval.taskID, &lineage.workflow.id, &approval.requestID, nil, "", "", "pending approval expired during scheduler reconciliation", details); err != nil {
				return err
			}
		}
	}

	completedAt := plan.completedAt
	if plan.scheduledStatus == domain.ScheduledExecutionInterrupted || plan.scheduledStatus == domain.ScheduledExecutionFailed || plan.scheduledStatus == domain.ScheduledExecutionCancelled || plan.scheduledStatus == domain.ScheduledExecutionApprovalRejected {
		completedAt = &recoveredAt
	}
	tag, err := tx.Exec(ctx, `UPDATE scheduled_executions
		SET status=$2,error_classification=$3,error_summary=$4,completed_at=$5,lease_owner='',lease_expires_at=NULL,updated_at=$6
		WHERE id=$1 AND status=$7 AND lease_expires_at<=clock_timestamp()`, entry.item.ID, plan.scheduledStatus, plan.errorClassification, plan.errorSummary, completedAt, recoveredAt, entry.item.Status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return invalidScheduledExecutionTransition(entry.item, plan.scheduledStatus)
	}
	entry.item.Status = plan.scheduledStatus
	entry.item.ErrorClassification = plan.errorClassification
	entry.item.ErrorSummary = plan.errorSummary
	entry.item.CompletedAt = completedAt
	entry.item.LeaseOwner = ""
	entry.item.LeaseExpiresAt = nil
	entry.item.UpdatedAt = recoveredAt
	// Corrupt lineage identifiers remain in the bounded structured details, but
	// cannot be copied into audit foreign-key columns when their rows are absent.
	auditItem := entry.item
	auditItem.TaskID = auditTaskID
	auditItem.WorkflowRunID = auditWorkflowRunID
	return auditExecution(ctx, tx, plan.eventType, "scheduler", entry.programID, auditItem, plan.eventMessage, base)
}

func recoveryAuditDetails(entry staleRecoveryEntry, lineage staleLineage, plan staleReconciliation) map[string]any {
	details := map[string]any{
		"scheduled_execution_id": entry.item.ID,
		"schedule_id":            entry.item.ScheduleID,
		"scenario":               plan.scenario,
		"reason_code":            plan.reasonCode,
		"previous_status":        entry.item.Status,
		"new_status":             plan.scheduledStatus,
		"expired_lease_owner":    entry.item.LeaseOwner,
		"attempt_count":          entry.item.AttemptCount,
		"lease_expires_at":       entry.item.LeaseExpiresAt,
		"task_id":                entry.item.TaskID,
		"workflow_run_id":        entry.item.WorkflowRunID,
		"retry_allowed":          plan.retryAllowed,
		"manual_review_required": plan.manualReview,
	}

	reachableTasks := recoveryTaskIDs(lineage.tasks)
	changedTasks := []domain.ID{}
	if plan.taskStatus != nil {
		for _, task := range lineage.tasks {
			if containsRecoveryID(plan.eligibleTaskIDs, task.id) && !recoveryTaskTerminal(task.status) && task.status != *plan.taskStatus {
				changedTasks = append(changedTasks, task.id)
			}
		}
	}
	reachableWorkflows := []domain.ID{}
	changedWorkflows := []domain.ID{}
	if lineage.workflow != nil {
		reachableWorkflows = append(reachableWorkflows, lineage.workflow.id)
		if plan.eligibleWorkflow && plan.workflowStatus != nil && !recoveryRunTerminal(lineage.workflow.status) && lineage.workflow.status != *plan.workflowStatus {
			changedWorkflows = append(changedWorkflows, lineage.workflow.id)
		}
	}
	reachableSteps := recoveryStepIDs(lineage.steps)
	changedSteps := []domain.ID{}
	for _, step := range lineage.steps {
		_, change := recoveryStepTarget(step.status, plan.stepMode)
		if containsRecoveryID(plan.eligibleStepIDs, step.id) && change {
			changedSteps = append(changedSteps, step.id)
		}
	}
	reachableTools := recoveryToolIDs(lineage.tools)
	changedTools := []domain.ID{}
	if plan.closeTools {
		for _, tool := range lineage.tools {
			if containsRecoveryID(plan.eligibleToolIDs, tool.id) && tool.completedAt == nil {
				changedTools = append(changedTools, tool.id)
			}
		}
	}
	reachableApprovals := recoveryApprovalIDs(lineage.approvals)
	changedApprovals := []domain.ID{}
	if plan.expireApprovals {
		for _, approval := range lineage.approvals {
			if containsRecoveryID(plan.eligibleApprovalIDs, approval.id) && approval.decision == "pending" {
				changedApprovals = append(changedApprovals, approval.id)
			}
		}
	}
	addRecoveryAuditIDDetails(details, "task", reachableTasks, changedTasks)
	addRecoveryAuditIDDetails(details, "workflow", reachableWorkflows, changedWorkflows)
	addRecoveryAuditIDDetails(details, "step", reachableSteps, changedSteps)
	addRecoveryAuditIDDetails(details, "tool_run", reachableTools, changedTools)
	addRecoveryAuditIDDetails(details, "approval", reachableApprovals, changedApprovals)

	if len(lineage.conflicts) > 0 {
		limit := len(lineage.conflicts)
		if limit > 32 {
			limit = 32
		}
		details["conflicts"] = append([]string(nil), lineage.conflicts[:limit]...)
		details["conflict_count"] = limit
		details["conflict_total_count"] = len(lineage.conflicts)
	}
	return details
}

func addRecoveryAuditIDDetails(details map[string]any, entity string, reachable, changed []domain.ID) {
	reachable = sortedUniqueRecoveryIDs(reachable)
	changed = sortedUniqueRecoveryIDs(changed)
	preserved := make([]domain.ID, 0, len(reachable))
	for _, id := range reachable {
		if !containsRecoveryID(changed, id) {
			preserved = append(preserved, id)
		}
	}
	addRecoveryAuditIDArray(details, "reachable_"+entity, reachable)
	addRecoveryAuditIDArray(details, "changed_"+entity, changed)
	addRecoveryAuditIDArray(details, "preserved_"+entity, preserved)
}

func addRecoveryAuditIDArray(details map[string]any, name string, ids []domain.ID) {
	const limit = 64
	bounded := boundedRecoveryIDs(ids, limit)
	details[name+"_ids"] = bounded
	details[name+"_count"] = len(bounded)
	details[name+"_total_count"] = len(ids)
}

func recoveryChangeDetails(base map[string]any, previous, next any) map[string]any {
	details := make(map[string]any, len(base)+2)
	for key, value := range base {
		details[key] = value
	}
	details["previous_child_status"] = previous
	details["new_child_status"] = next
	return details
}

func auditRecoveryRow(ctx context.Context, tx pgx.Tx, event string, programID domain.ID, taskID, workflowRunID, stepRunID, toolRunID *domain.ID, capability, provider, message string, details map[string]any) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,tool_run_id,capability,provider,safe_message,details)
		VALUES($1,$2,'scheduler','scheduler',$3,$4,$5,$6,$7,$8,$9,$10,$11)`, domain.NewID(), event, taskID, programID, workflowRunID, stepRunID, toolRunID, nullIfEmpty(capability), nullIfEmpty(provider), message, mustJSON(details))
	return err
}

func recoveryStepTarget(status domain.StepStatus, mode recoveryStepMode) (domain.StepStatus, bool) {
	if recoveryStepTerminal(status) || mode == recoveryStepsUnchanged {
		return status, false
	}
	if mode == recoveryStepsCancelUnstarted {
		return domain.StepCancelled, true
	}
	switch status {
	case domain.StepPending, domain.StepBlocked:
		return domain.StepCancelled, true
	default:
		// Steps have no interrupted status. Failed plus the deterministic
		// interrupted classification records the unknown provider outcome.
		return domain.StepFailed, true
	}
}

func recoveryTaskTerminal(status domain.TaskStatus) bool {
	return status == domain.TaskCompleted || status == domain.TaskFailed || status == domain.TaskCancelled
}

func recoveryWorkflowBelongsToProgram(programID domain.ID, lineage staleLineage) bool {
	if lineage.workflow == nil {
		return false
	}
	for _, task := range lineage.tasks {
		if task.id == lineage.workflow.taskID {
			return task.programID == programID
		}
	}
	return false
}

func recoveryRunTerminal(status domain.RunStatus) bool {
	return status == domain.RunCompleted || status == domain.RunFailed || status == domain.RunCancelled
}

func recoveryStepTerminal(status domain.StepStatus) bool {
	return status == domain.StepSucceeded || status == domain.StepFailed || status == domain.StepSkipped || status == domain.StepCancelled
}

func recoveryHasProgressedStep(steps []recoveryStep) bool {
	for _, step := range steps {
		if step.startedAt != nil || step.completedAt != nil || step.attemptCount > 0 || step.hasOutput || step.hasProviderEvidence {
			return true
		}
		switch step.status {
		case domain.StepQueued, domain.StepRunning, domain.StepRetryable, domain.StepSucceeded, domain.StepFailed:
			return true
		}
	}
	return false
}

func taskMatchesWorkflowTerminal(task domain.TaskStatus, run domain.RunStatus) bool {
	return (task == domain.TaskCompleted && run == domain.RunCompleted) ||
		(task == domain.TaskFailed && run == domain.RunFailed) ||
		(task == domain.TaskCancelled && run == domain.RunCancelled)
}

func sortedUniqueRecoveryIDs(values []domain.ID) []domain.ID {
	set := map[domain.ID]struct{}{}
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]domain.ID, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func containsRecoveryID(values []domain.ID, wanted domain.ID) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func recoveryStepIDs(values []recoveryStep) []domain.ID {
	out := make([]domain.ID, 0, len(values))
	for _, value := range values {
		out = append(out, value.id)
	}
	return out
}

func recoveryTaskIDs(values []recoveryTask) []domain.ID {
	out := make([]domain.ID, 0, len(values))
	for _, value := range values {
		out = append(out, value.id)
	}
	return out
}

func recoveryToolIDs(values []recoveryTool) []domain.ID {
	out := make([]domain.ID, 0, len(values))
	for _, value := range values {
		out = append(out, value.id)
	}
	return out
}

func recoveryApprovalIDs(values []recoveryApproval) []domain.ID {
	out := make([]domain.ID, 0, len(values))
	for _, value := range values {
		out = append(out, value.id)
	}
	return out
}

func boundedRecoveryIDs(values []domain.ID, limit int) []domain.ID {
	if len(values) > limit {
		values = values[:limit]
	}
	out := make([]domain.ID, len(values))
	copy(out, values)
	return out
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}
