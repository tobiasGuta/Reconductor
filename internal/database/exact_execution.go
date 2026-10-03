package database

import (
	"context"
	"fmt"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
)

// LoadExactDispatchAction reads execution material only after committed intent.
// It neither re-admits dispatch nor opens the completed human review/evidence.
// The epoch is bound to historical intent, not current program authority.
func (s *Store) LoadExactDispatchAction(ctx context.Context, providerAttemptID domain.ID, expectedActionSHA string, expectedAuthorityEpoch int64) (exactaction.ActionContractV1, error) {
	var action exactaction.ActionContractV1
	if providerAttemptID == "" || expectedActionSHA == "" || expectedAuthorityEpoch < 0 {
		return action, fmt.Errorf("%w: invalid execution identity", ErrExactDispatchDenied)
	}
	var raw []byte
	var actionID, programID, taskID, runID, stepID domain.ID
	var attempt int
	// All identity comparisons occur in one read. The frozen contract and
	// durable intent cannot change; no mutable step input enters this query.
	err := s.Pool.QueryRow(ctx, `SELECT e.canonical_contract,e.action_request_id,e.program_id,e.task_id,
		e.workflow_run_id,e.step_run_id,e.step_attempt
		FROM exact_dispatch_attempts d
		JOIN exact_actions e ON e.action_request_id=d.action_request_id
		JOIN approvals a ON a.id=d.approval_id
		JOIN audit_events x ON x.id=d.provider_attempt_id
		WHERE d.provider_attempt_id=$1 AND d.state='DISPATCH_INTENT'
		AND d.authority_epoch=$5
		AND e.bound_provider_attempt_id=d.provider_attempt_id AND a.bound_provider_attempt_id=d.provider_attempt_id
		AND d.action_sha256=$2 AND e.action_sha256=$2 AND a.action_sha256=$2
		AND e.contract_schema=$3 AND e.capability_semantic_revision=$4
		AND a.approval_kind='exact_action' AND a.decision='approved'
		AND a.action_request_id=e.action_request_id AND a.task_id=e.task_id AND d.program_id=e.program_id
		AND x.event_type='provider_invocation_started' AND x.action_request_id=e.action_request_id
		AND x.program_id=e.program_id AND x.task_id=e.task_id AND x.workflow_run_id=e.workflow_run_id
		AND x.step_run_id=e.step_run_id AND x.step_attempt=e.step_attempt AND x.capability='http.request'`,
		providerAttemptID, expectedActionSHA, exactaction.ContractVersion, exactaction.CapabilityRevision, expectedAuthorityEpoch).
		Scan(&raw, &actionID, &programID, &taskID, &runID, &stepID, &attempt)
	if err != nil {
		return action, fmt.Errorf("%w: execution material unavailable: %w", ErrExactDispatchDenied, err)
	}
	action, err = exactaction.DecodeContract(raw, expectedActionSHA)
	if err != nil {
		return exactaction.ActionContractV1{}, fmt.Errorf("%w: invalid frozen execution contract", ErrExactDispatchDenied)
	}
	if action.ActionID != actionID || action.Ownership != (exactaction.Ownership{ProgramID: programID, TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, StepAttempt: attempt}) {
		return exactaction.ActionContractV1{}, fmt.Errorf("%w: execution material lineage mismatch", ErrExactDispatchDenied)
	}
	return action, nil
}

// ExactDispatchTrustedTime uses the same authority clock as launch admission.
// There is no caller timestamp or local-clock fallback.
func (s *Store) ExactDispatchTrustedTime(ctx context.Context) (time.Time, error) {
	var now time.Time
	err := s.Pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
	return now, err
}
