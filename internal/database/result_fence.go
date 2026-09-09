package database

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	artifactstorage "github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

var (
	ErrStaleScheduledExecutionResult = errors.New("stale scheduled execution result")
	ErrLostScheduledExecutionLease   = errors.New("scheduled execution lease lost")
	ErrWorkflowResultConflict        = errors.New("workflow result conflicts with persisted state")
)

type resultFenceReasonCode string

const (
	resultFenceInvalidResultIdentity         resultFenceReasonCode = "invalid_result_identity"
	resultFenceInvalidScheduledClaim         resultFenceReasonCode = "invalid_scheduled_claim"
	resultFenceScheduledExecutionUnavailable resultFenceReasonCode = "scheduled_execution_unavailable"
	resultFenceScheduledLineageMismatch      resultFenceReasonCode = "scheduled_lineage_mismatch"
	resultFenceScheduledClaimMismatch        resultFenceReasonCode = "scheduled_claim_mismatch"
	resultFenceScheduledLeaseExpired         resultFenceReasonCode = "scheduled_lease_expired"
	resultFenceWorkflowLineageMismatch       resultFenceReasonCode = "workflow_lineage_mismatch"
	resultFenceWorkflowNotRunning            resultFenceReasonCode = "workflow_not_running"
	resultFenceInvalidResultState            resultFenceReasonCode = "invalid_result_state"
	resultFenceToolLineageMismatch           resultFenceReasonCode = "tool_lineage_mismatch"
	resultFenceProviderProvenanceMismatch    resultFenceReasonCode = "provider_provenance_mismatch"
	resultFenceStepNotAdmittingResult        resultFenceReasonCode = "step_not_admitting_result"
	resultFenceStaleProviderStepAttempt      resultFenceReasonCode = "stale_provider_step_attempt"
	resultFenceToolResultConflict            resultFenceReasonCode = "tool_result_conflict"
	resultFenceArtifactIdentityInvalid       resultFenceReasonCode = "artifact_identity_invalid"
	resultFenceArtifactLineageMismatch       resultFenceReasonCode = "artifact_lineage_mismatch"
	resultFenceArtifactResultConflict        resultFenceReasonCode = "artifact_result_conflict"
	resultFenceConcurrentStepChange          resultFenceReasonCode = "concurrent_step_change"
)

type semanticResultFenceError struct {
	cause  error
	reason resultFenceReasonCode
	detail string
}

func (e *semanticResultFenceError) Error() string { return fmt.Sprintf("%v: %s", e.cause, e.detail) }
func (e *semanticResultFenceError) Unwrap() error { return e.cause }

func resultFenceRejection(err error) (*semanticResultFenceError, bool) {
	var rejection *semanticResultFenceError
	ok := errors.As(err, &rejection)
	return rejection, ok
}

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
	scheduled    bool
	taskID       domain.ID
	stepStatus   domain.StepStatus
	attemptCount int
}

func lockConflictingResultTools(ctx context.Context, tx pgx.Tx, stepID domain.ID, tool *domain.ToolRun, scheduled bool) error {
	query := `SELECT id FROM tool_runs WHERE step_run_id=$1 ORDER BY id FOR UPDATE`
	args := []any{stepID}
	if tool != nil && tool.ProviderAttemptID != nil {
		query = `SELECT id FROM tool_runs
			WHERE id=$2
			   OR provider_attempt_id=$3
			   OR (step_run_id=$1 AND provider_attempt_id IS NULL)
			ORDER BY id FOR UPDATE`
		args = append(args, tool.ID, *tool.ProviderAttemptID)
	} else if tool != nil {
		query = `SELECT id FROM tool_runs WHERE step_run_id=$1 OR id=$2 ORDER BY id FOR UPDATE`
		args = append(args, tool.ID)
	}
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		return resultConflict(scheduled, resultFenceToolResultConflict, "tool result already exists")
	}
	return rows.Err()
}

func lockAndValidateResultArtifacts(ctx context.Context, tx pgx.Tx, lineage lockedResultLineage, step domain.StepRun, tool *domain.ToolRun, artifacts []domain.Artifact) error {
	ids := make([]domain.ID, 0, len(artifacts))
	seen := make(map[domain.ID]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.ID == "" {
			return resultConflict(lineage.scheduled, resultFenceArtifactIdentityInvalid, "artifact identity is missing")
		}
		if artifact.AddressingVersion != 1 || artifact.ArtifactStoreID == nil || artifact.StorageKey == nil || artifact.StorageLocation != nil {
			return resultConflict(lineage.scheduled, resultFenceArtifactIdentityInvalid, "artifact addressing is not complete modern version 1")
		}
		if _, err := domain.ParseID(string(*artifact.ArtifactStoreID)); err != nil {
			return resultConflict(lineage.scheduled, resultFenceArtifactIdentityInvalid, "artifact store identity is not canonical")
		}
		if err := artifactstorage.ValidateStorageKey(*artifact.StorageKey, artifact.ID); err != nil {
			return resultConflict(lineage.scheduled, resultFenceArtifactIdentityInvalid, "artifact storage key does not match its identity")
		}
		if _, duplicate := seen[artifact.ID]; duplicate {
			return resultConflict(lineage.scheduled, resultFenceArtifactIdentityInvalid, "artifact identity is duplicated")
		}
		seen[artifact.ID] = struct{}{}
		if tool == nil || artifact.TaskID != lineage.taskID || artifact.WorkflowRunID != step.WorkflowRunID || artifact.StepRunID != step.ID || artifact.ToolRunID != tool.ID {
			return resultConflict(lineage.scheduled, resultFenceArtifactLineageMismatch, "artifact lineage does not match result step")
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
		return resultConflict(lineage.scheduled, resultFenceArtifactResultConflict, "artifact metadata already exists")
	}
	return rows.Err()
}

func lockResultLineage(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun) (lockedResultLineage, error) {
	fence, fenced := scheduledExecutionFenceFromContext(ctx)
	if step.ID == "" || step.WorkflowRunID == "" {
		return lockedResultLineage{}, resultConflict(fenced, resultFenceInvalidResultIdentity, "result step identity is incomplete")
	}
	var scheduled domain.ScheduledExecution
	var scheduledProgramID domain.ID
	var hasScheduled bool
	var err error
	if fenced {
		if fence.ExecutionID == "" || fence.LeaseOwner == "" || fence.Attempt < 1 {
			return lockedResultLineage{}, staleResultError(resultFenceInvalidScheduledClaim, "claim identity is incomplete")
		}
		scheduled, scheduledProgramID, err = lockedScheduledExecution(ctx, tx, fence.ExecutionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return lockedResultLineage{}, staleResultError(resultFenceScheduledExecutionUnavailable, "scheduled execution does not exist")
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
			return lockedResultLineage{}, staleResultError(resultFenceInvalidScheduledClaim, "scheduled claim identity is missing")
		}
	}

	if hasScheduled {
		if scheduledProgramID != programID {
			return lockedResultLineage{}, staleResultError(resultFenceScheduledLineageMismatch, "program lineage does not match")
		}
		if scheduled.Status != domain.ScheduledExecutionRunning {
			return lockedResultLineage{}, staleResultError(resultFenceScheduledExecutionUnavailable, "scheduled execution is not running")
		}
		if scheduled.TaskID == nil || scheduled.WorkflowRunID == nil || *scheduled.WorkflowRunID != step.WorkflowRunID {
			return lockedResultLineage{}, staleResultError(resultFenceScheduledLineageMismatch, "scheduled workflow lineage does not match")
		}
		if scheduled.LeaseOwner != fence.LeaseOwner {
			return lockedResultLineage{}, staleResultError(resultFenceScheduledClaimMismatch, "scheduler owner does not match")
		}
		if scheduled.AttemptCount != fence.Attempt {
			return lockedResultLineage{}, staleResultError(resultFenceScheduledClaimMismatch, "scheduler attempt does not match")
		}
		valid, validErr := lockedSchedulerLeaseValid(ctx, tx, scheduled.ID, fence.LeaseOwner, fence.Attempt)
		if validErr != nil {
			return lockedResultLineage{}, validErr
		}
		if !valid {
			return lockedResultLineage{}, staleResultError(resultFenceScheduledLeaseExpired, "scheduler lease is no longer valid")
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
		return lockedResultLineage{}, resultConflict(hasScheduled, resultFenceWorkflowLineageMismatch, "workflow does not exist")
	}
	if err != nil {
		return lockedResultLineage{}, err
	}
	if taskProgramID != programID || (hasScheduled && *scheduled.TaskID != taskID) {
		return lockedResultLineage{}, resultConflict(hasScheduled, resultFenceWorkflowLineageMismatch, "task and workflow lineage do not match")
	}
	if runStatus != domain.RunRunning {
		return lockedResultLineage{}, resultConflict(hasScheduled, resultFenceWorkflowNotRunning, "workflow is not running")
	}

	var workflowRunID domain.ID
	var status domain.StepStatus
	var attemptCount int
	var idempotencyKey, capabilityName string
	err = tx.QueryRow(ctx, `SELECT workflow_run_id,status,attempt_count,idempotency_key,capability FROM step_runs WHERE id=$1 FOR UPDATE`, step.ID).Scan(&workflowRunID, &status, &attemptCount, &idempotencyKey, &capabilityName)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedResultLineage{}, resultConflict(hasScheduled, resultFenceWorkflowLineageMismatch, "step does not exist")
	}
	if err != nil {
		return lockedResultLineage{}, err
	}
	if workflowRunID != step.WorkflowRunID {
		return lockedResultLineage{}, resultConflict(hasScheduled, resultFenceWorkflowLineageMismatch, "step and workflow lineage do not match")
	}
	if step.IdempotencyKey == "" || idempotencyKey != step.IdempotencyKey {
		return lockedResultLineage{}, resultConflict(hasScheduled, resultFenceWorkflowLineageMismatch, "step idempotency identity does not match")
	}
	if step.Capability == "" || capabilityName != step.Capability {
		return lockedResultLineage{}, resultConflict(hasScheduled, resultFenceWorkflowLineageMismatch, "step capability does not match")
	}
	return lockedResultLineage{scheduled: hasScheduled, taskID: taskID, stepStatus: status, attemptCount: attemptCount}, nil
}

func lockProviderStepAttempt(ctx context.Context, tx pgx.Tx, providerAttemptID domain.ID) (*int, error) {
	var stepAttempt *int
	err := tx.QueryRow(ctx, `SELECT step_attempt FROM audit_events WHERE id=$1 AND event_type='provider_invocation_started' FOR UPDATE`, providerAttemptID).Scan(&stepAttempt)
	if err != nil {
		return nil, err
	}
	return stepAttempt, nil
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
		var taskID domain.ID
		var persistedStatus domain.RunStatus
		var persistedSummary json.RawMessage
		err = tx.QueryRow(ctx, `SELECT task_id,status,summary FROM workflow_runs WHERE id=$1 FOR UPDATE`, state.Run.ID).Scan(&taskID, &persistedStatus, &persistedSummary)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if taskID != state.Run.TaskID {
			return fmt.Errorf("%w: workflow task lineage does not match", workflow.ErrWorkflowCheckpointConflict)
		}
		return validateAuthoritativeWorkflowLifecycle(state.Run, persistedStatus, persistedSummary)
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
	var persistedSummary json.RawMessage
	err = tx.QueryRow(ctx, `SELECT task_id,status,summary FROM workflow_runs WHERE id=$1 FOR UPDATE`, state.Run.ID).Scan(&persistedTaskID, &persistedStatus, &persistedSummary)
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
		if err := validateAuthoritativeWorkflowLifecycle(state.Run, persistedStatus, persistedSummary); err != nil {
			return err
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

func lockAndValidateAuthoritativeStepAttempts(ctx context.Context, tx pgx.Tx, state *workflow.State) error {
	steps := make(map[domain.ID]*workflow.StepState, len(state.Steps))
	stepIDs := make([]domain.ID, 0, len(state.Steps))
	for _, stepState := range state.Steps {
		if stepState == nil || stepState.Run.ID == "" {
			return fmt.Errorf("%w: workflow state contains an invalid StepRun", workflow.ErrEffectiveStepInputConflict)
		}
		if _, duplicate := steps[stepState.Run.ID]; duplicate {
			return fmt.Errorf("%w: workflow state repeats StepRun %s", workflow.ErrEffectiveStepInputConflict, stepState.Run.ID)
		}
		steps[stepState.Run.ID] = stepState
		stepIDs = append(stepIDs, stepState.Run.ID)
	}
	sort.Slice(stepIDs, func(i, j int) bool { return stepIDs[i] < stepIDs[j] })
	if len(stepIDs) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT id,status,attempt_count,input FROM step_runs WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, idStrings(stepIDs))
	if err != nil {
		return err
	}
	defer rows.Close()
	persisted := make(map[domain.ID]struct{}, len(stepIDs))
	for rows.Next() {
		var id domain.ID
		var status domain.StepStatus
		var attemptCount int
		var input json.RawMessage
		if err := rows.Scan(&id, &status, &attemptCount, &input); err != nil {
			return err
		}
		stepState := steps[id]
		persisted[id] = struct{}{}
		if stepState.Run.AttemptCount != attemptCount {
			return fmt.Errorf("%w: StepRun %s has authoritative attempt %d, not %d", workflow.ErrEffectiveStepInputConflict, id, attemptCount, stepState.Run.AttemptCount)
		}
		if attemptCount > 0 && (!bytes.Equal(stepState.Run.Input, input) || stepState.InputHash != workflow.InputDigest(input)) {
			return fmt.Errorf("%w: StepRun %s has different authoritative input", workflow.ErrEffectiveStepInputConflict, id)
		}
		if recoveryStepTerminal(status) && stepState.Run.Status != status {
			return fmt.Errorf("%w: terminal StepRun %s is %s, not %s", workflow.ErrWorkflowLifecycleConflict, id, status, stepState.Run.Status)
		}
		if status == domain.StepRetryable && stepState.Run.Status != domain.StepRetryable && stepState.Run.Status != domain.StepFailed {
			return fmt.Errorf("%w: result-owned retryable StepRun %s cannot transition to %s", workflow.ErrWorkflowLifecycleConflict, id, stepState.Run.Status)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range stepIDs {
		if _, found := persisted[id]; !found && steps[id].Run.AttemptCount != 0 {
			return fmt.Errorf("%w: StepRun %s attempt %d was not allocated by the result store", workflow.ErrEffectiveStepInputConflict, id, steps[id].Run.AttemptCount)
		}
	}
	return nil
}

func validateAuthoritativeWorkflowLifecycle(incoming domain.WorkflowRun, persistedStatus domain.RunStatus, persistedSummary json.RawMessage) error {
	if recoveryRunTerminal(persistedStatus) {
		if incoming.Status != persistedStatus {
			return fmt.Errorf("%w: terminal WorkflowRun %s is %s, not %s", workflow.ErrWorkflowLifecycleConflict, incoming.ID, persistedStatus, incoming.Status)
		}
		if !defaultWorkflowSummary(persistedSummary) && !equivalentJSON(persistedSummary, incoming.Summary) {
			return fmt.Errorf("%w: terminal WorkflowRun %s has a newer authoritative summary", workflow.ErrWorkflowLifecycleConflict, incoming.ID)
		}
	}
	return nil
}

func defaultWorkflowSummary(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || equivalentJSON(trimmed, json.RawMessage(`{}`))
}

func equivalentJSON(left, right json.RawMessage) bool {
	canonicalLeft, leftErr := canonicaljson.Marshal(left)
	canonicalRight, rightErr := canonicaljson.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(canonicalLeft, canonicalRight)
}

func staleResultError(reason resultFenceReasonCode, detail string) error {
	return &semanticResultFenceError{cause: ErrStaleScheduledExecutionResult, reason: reason, detail: detail}
}

func lostLeaseError(reason string) error {
	return fmt.Errorf("%w: %s", ErrLostScheduledExecutionLease, reason)
}

func resultConflict(scheduled bool, reason resultFenceReasonCode, detail string) error {
	if scheduled {
		return staleResultError(reason, detail)
	}
	return &semanticResultFenceError{cause: ErrWorkflowResultConflict, reason: reason, detail: detail}
}
