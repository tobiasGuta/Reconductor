package database

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

var (
	ErrStaleScheduledExecutionResult = errors.New("stale scheduled execution result")
	ErrLostScheduledExecutionLease   = errors.New("scheduled execution lease lost")
	ErrWorkflowResultConflict        = errors.New("workflow result conflicts with persisted state")
)

type ScheduledExecutionFence struct {
	ExecutionID domain.ID
	LeaseOwner  string
	Attempt     int
}

type scheduledExecutionFenceContextKey struct{}

func WithScheduledExecutionFence(ctx context.Context, fence ScheduledExecutionFence) context.Context {
	return context.WithValue(ctx, scheduledExecutionFenceContextKey{}, fence)
}

func scheduledExecutionFenceFromContext(ctx context.Context) (ScheduledExecutionFence, bool) {
	fence, ok := ctx.Value(scheduledExecutionFenceContextKey{}).(ScheduledExecutionFence)
	return fence, ok
}

func IsScheduledExecutionFenceError(err error) bool {
	return errors.Is(err, ErrStaleScheduledExecutionResult) || errors.Is(err, ErrLostScheduledExecutionLease)
}

type lockedResultLineage struct {
	scheduled bool
	taskID    domain.ID
}

func lockConflictingResultTools(ctx context.Context, tx pgx.Tx, stepID domain.ID, tool *domain.ToolRun, scheduled bool) error {
	query := `SELECT id FROM tool_runs WHERE step_run_id=$1 ORDER BY id FOR UPDATE`
	args := []any{stepID}
	if tool != nil {
		query = `SELECT id FROM tool_runs WHERE step_run_id=$1 OR id=$2 ORDER BY id FOR UPDATE`
		args = append(args, tool.ID)
	}
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		return resultConflict(scheduled, "tool result already exists")
	}
	return rows.Err()
}

func lockAndValidateResultArtifacts(ctx context.Context, tx pgx.Tx, lineage lockedResultLineage, step domain.StepRun, tool *domain.ToolRun, artifacts []domain.Artifact) error {
	ids := make([]domain.ID, 0, len(artifacts))
	seen := make(map[domain.ID]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.ID == "" {
			return resultConflict(lineage.scheduled, "artifact identity is missing")
		}
		if _, duplicate := seen[artifact.ID]; duplicate {
			return resultConflict(lineage.scheduled, "artifact identity is duplicated")
		}
		seen[artifact.ID] = struct{}{}
		if tool == nil || artifact.TaskID != lineage.taskID || artifact.WorkflowRunID != step.WorkflowRunID || artifact.StepRunID != step.ID || artifact.ToolRunID != tool.ID {
			return resultConflict(lineage.scheduled, "artifact lineage does not match result step")
		}
		ids = append(ids, artifact.ID)
	}
	if len(ids) == 0 {
		return nil
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	rows, err := tx.Query(ctx, `SELECT id FROM artifacts WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, idStrings(ids))
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		return resultConflict(lineage.scheduled, "artifact metadata already exists")
	}
	return rows.Err()
}

func lockResultLineage(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun) (lockedResultLineage, error) {
	fence, fenced := scheduledExecutionFenceFromContext(ctx)
	if step.ID == "" || step.WorkflowRunID == "" {
		return lockedResultLineage{}, resultConflict(fenced, "result step identity is incomplete")
	}
	var scheduled domain.ScheduledExecution
	var scheduledProgramID domain.ID
	var hasScheduled bool
	var err error
	if fenced {
		if fence.ExecutionID == "" || fence.LeaseOwner == "" || fence.Attempt < 1 {
			return lockedResultLineage{}, staleResultError("claim identity is incomplete")
		}
		scheduled, scheduledProgramID, err = lockedScheduledExecution(ctx, tx, fence.ExecutionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return lockedResultLineage{}, staleResultError("scheduled execution does not exist")
		}
		if err != nil {
			return lockedResultLineage{}, err
		}
		hasScheduled = true
	} else {
		scheduled, scheduledProgramID, hasScheduled, err = lockedScheduledExecutionByWorkflow(ctx, tx, step.WorkflowRunID)
		if err != nil {
			return lockedResultLineage{}, err
		}
		if hasScheduled {
			return lockedResultLineage{}, staleResultError("scheduled claim identity is missing")
		}
	}

	if hasScheduled {
		if scheduledProgramID != programID {
			return lockedResultLineage{}, staleResultError("program lineage does not match")
		}
		if scheduled.Status != domain.ScheduledExecutionRunning {
			return lockedResultLineage{}, staleResultError("scheduled execution is not running")
		}
		if scheduled.TaskID == nil || scheduled.WorkflowRunID == nil || *scheduled.WorkflowRunID != step.WorkflowRunID {
			return lockedResultLineage{}, staleResultError("scheduled workflow lineage does not match")
		}
		if scheduled.LeaseOwner != fence.LeaseOwner {
			return lockedResultLineage{}, staleResultError("scheduler owner does not match")
		}
		if scheduled.AttemptCount != fence.Attempt {
			return lockedResultLineage{}, staleResultError("scheduler attempt does not match")
		}
		valid, validErr := lockedSchedulerLeaseValid(ctx, tx, scheduled.ID, fence.LeaseOwner, fence.Attempt)
		if validErr != nil {
			return lockedResultLineage{}, validErr
		}
		if !valid {
			return lockedResultLineage{}, staleResultError("scheduler lease is no longer valid")
		}
	}

	var taskID domain.ID
	var runStatus domain.RunStatus
	var taskProgramID domain.ID
	err = tx.QueryRow(ctx, `SELECT wr.task_id,wr.status,t.program_id
		FROM workflow_runs wr
		JOIN tasks t ON t.id=wr.task_id
		WHERE wr.id=$1
		FOR UPDATE OF wr`, step.WorkflowRunID).Scan(&taskID, &runStatus, &taskProgramID)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedResultLineage{}, resultConflict(hasScheduled, "workflow does not exist")
	}
	if err != nil {
		return lockedResultLineage{}, err
	}
	if taskProgramID != programID || (hasScheduled && *scheduled.TaskID != taskID) {
		return lockedResultLineage{}, resultConflict(hasScheduled, "task and workflow lineage do not match")
	}
	if runStatus != domain.RunRunning {
		return lockedResultLineage{}, resultConflict(hasScheduled, "workflow is not running")
	}

	var workflowRunID domain.ID
	var status domain.StepStatus
	var idempotencyKey, capabilityName string
	err = tx.QueryRow(ctx, `SELECT workflow_run_id,status,idempotency_key,capability FROM step_runs WHERE id=$1 FOR UPDATE`, step.ID).Scan(&workflowRunID, &status, &idempotencyKey, &capabilityName)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedResultLineage{}, resultConflict(hasScheduled, "step does not exist")
	}
	if err != nil {
		return lockedResultLineage{}, err
	}
	if workflowRunID != step.WorkflowRunID {
		return lockedResultLineage{}, resultConflict(hasScheduled, "step and workflow lineage do not match")
	}
	if status != domain.StepRunning {
		return lockedResultLineage{}, resultConflict(hasScheduled, "step is not running")
	}
	if step.IdempotencyKey == "" || idempotencyKey != step.IdempotencyKey {
		return lockedResultLineage{}, resultConflict(hasScheduled, "step idempotency identity does not match")
	}
	if step.Capability == "" || capabilityName != step.Capability {
		return lockedResultLineage{}, resultConflict(hasScheduled, "step capability does not match")
	}
	return lockedResultLineage{scheduled: hasScheduled, taskID: taskID}, nil
}

func lockAndValidateWorkflowSave(ctx context.Context, tx pgx.Tx, state *workflow.State, lifecyclePresent bool) error {
	fence, fenced := scheduledExecutionFenceFromContext(ctx)
	if !fenced {
		if lifecyclePresent {
			return lostLeaseError("scheduled claim identity is missing")
		}
		_, _, found, err := lockedScheduledExecutionByWorkflow(ctx, tx, state.Run.ID)
		if err != nil {
			return err
		}
		if found {
			return lostLeaseError("scheduled claim identity is missing")
		}
		return nil
	}
	if fence.ExecutionID == "" || fence.LeaseOwner == "" || fence.Attempt < 1 {
		return lostLeaseError("claim identity is incomplete")
	}
	item, _, err := lockedScheduledExecution(ctx, tx, fence.ExecutionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return lostLeaseError("scheduled execution does not exist")
	}
	if err != nil {
		return err
	}
	if item.LeaseOwner != fence.LeaseOwner || item.AttemptCount != fence.Attempt {
		return lostLeaseError("scheduler claim identity does not match")
	}
	valid, err := lockedSchedulerLeaseValid(ctx, tx, item.ID, fence.LeaseOwner, fence.Attempt)
	if err != nil {
		return err
	}
	if !valid {
		return lostLeaseError("scheduler lease is no longer valid")
	}
	if item.Status != domain.ScheduledExecutionClaimed && item.Status != domain.ScheduledExecutionRunning {
		return lostLeaseError("scheduled execution is not active")
	}
	if item.TaskID == nil || *item.TaskID != state.Run.TaskID {
		return lostLeaseError("scheduled task lineage does not match")
	}
	if item.Status == domain.ScheduledExecutionRunning {
		if item.WorkflowRunID == nil || *item.WorkflowRunID != state.Run.ID {
			return lostLeaseError("scheduled workflow lineage does not match")
		}
	} else if item.WorkflowRunID != nil && *item.WorkflowRunID != state.Run.ID {
		return lostLeaseError("scheduled workflow lineage does not match")
	}

	var persistedTaskID domain.ID
	var persistedStatus domain.RunStatus
	err = tx.QueryRow(ctx, `SELECT task_id,status FROM workflow_runs WHERE id=$1 FOR UPDATE`, state.Run.ID).Scan(&persistedTaskID, &persistedStatus)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if item.Status != domain.ScheduledExecutionClaimed {
			return lostLeaseError("linked workflow does not exist")
		}
	case err != nil:
		return err
	default:
		if persistedTaskID != state.Run.TaskID {
			return lostLeaseError("workflow task lineage does not match")
		}
		if recoveryRunTerminal(persistedStatus) {
			return lostLeaseError("workflow is already terminal")
		}
		if persistedStatus == domain.RunPaused && item.Status != domain.ScheduledExecutionClaimed {
			return lostLeaseError("paused workflow has not been reclaimed")
		}
	}

	stepIDs := make([]domain.ID, 0, len(state.Steps))
	for _, stepState := range state.Steps {
		if stepState.Run.WorkflowRunID != state.Run.ID || stepState.Run.IdempotencyKey == "" {
			return lostLeaseError("workflow step identity is invalid")
		}
		stepIDs = append(stepIDs, stepState.Run.ID)
	}
	sort.Slice(stepIDs, func(i, j int) bool { return stepIDs[i] < stepIDs[j] })
	if len(stepIDs) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT id,workflow_run_id,idempotency_key FROM step_runs WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, idStrings(stepIDs))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, workflowRunID domain.ID
		var idempotencyKey string
		if err := rows.Scan(&id, &workflowRunID, &idempotencyKey); err != nil {
			return err
		}
		if workflowRunID != state.Run.ID {
			return lostLeaseError("persisted step belongs to another workflow")
		}
		for _, stepState := range state.Steps {
			if stepState.Run.ID == id && stepState.Run.IdempotencyKey != idempotencyKey {
				return lostLeaseError("persisted step idempotency identity does not match")
			}
		}
	}
	return rows.Err()
}

func staleResultError(reason string) error {
	return fmt.Errorf("%w: %s", ErrStaleScheduledExecutionResult, reason)
}

func lostLeaseError(reason string) error {
	return fmt.Errorf("%w: %s", ErrLostScheduledExecutionLease, reason)
}

func resultConflict(scheduled bool, reason string) error {
	if scheduled {
		return staleResultError(reason)
	}
	return fmt.Errorf("%w: %s", ErrWorkflowResultConflict, reason)
}
