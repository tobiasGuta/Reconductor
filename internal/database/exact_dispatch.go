package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
	"github.com/tobiasGuta/Reconductor/internal/launchauthority"
	"github.com/tobiasGuta/Reconductor/internal/policy"
)

var ErrExactDispatchDenied = errors.New("exact dispatch denied")

// ExactDispatchPermit is an in-process, one-use proof of a committed local
// dispatch-intent transition. It performs no transport operation.
type ExactDispatchPermit struct {
	providerAttemptID domain.ID
	actionSHA256      string
	authorityEpoch    int64
	deadline          *time.Time
	used              *atomic.Bool
}

func (p *ExactDispatchPermit) ProviderAttemptID() domain.ID { return p.providerAttemptID }
func (p *ExactDispatchPermit) ActionSHA256() string         { return p.actionSHA256 }
func (p *ExactDispatchPermit) AuthorityEpoch() int64        { return p.authorityEpoch }
func (p *ExactDispatchPermit) Deadline() *time.Time {
	if p.deadline == nil {
		return nil
	}
	copy := *p.deadline
	return &copy
}

// ConsumeAt checks a trusted, conservatively advancing time before consuming
// the one-use permission. An expired check does not consume it, but can never
// revive an expired deadline when callers use advancing time.
func (p *ExactDispatchPermit) ConsumeAt(at time.Time) bool {
	if p == nil || p.used == nil || at.IsZero() || (p.deadline != nil && !at.Before(*p.deadline)) {
		return false
	}
	return p.used.CompareAndSwap(false, true)
}

// AdmitExactDispatch loads the frozen contract, checks current PostgreSQL
// authority, and commits intent for X once.
// It deliberately has no queue-policy or transport parameters.
func (s *Store) AdmitExactDispatch(ctx context.Context, programID domain.ID, step domain.StepRun, providerAttemptID domain.ID) (*ExactDispatchPermit, error) {
	return s.admitExactDispatch(ctx, programID, step, providerAttemptID, nil)
}

// beforeCommit is private fault injection for transaction-boundary tests.
func (s *Store) admitExactDispatch(ctx context.Context, programID domain.ID, step domain.StepRun, providerAttemptID domain.ID, beforeCommit func(pgx.Tx) error) (*ExactDispatchPermit, error) {
	if programID == "" || providerAttemptID == "" || step.Capability != "http.request" {
		return nil, fmt.Errorf("%w: incomplete exact lineage", ErrExactDispatchDenied)
	}
	if _, recovering := domain.PreparedRecoveryRequestFromContext(ctx); recovering {
		return nil, fmt.Errorf("%w: recovery cannot create dispatch intent", ErrExactDispatchDenied)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	lineage, err := lockResultLineage(ctx, tx, programID, step)
	if err != nil {
		return nil, err
	}
	if lineage.stepStatus != domain.StepRunning || lineage.attemptCount < 1 {
		return nil, fmt.Errorf("%w: step is not a running attempt", ErrExactDispatchDenied)
	}
	// The audit insert and companion update reference these parents. NOWAIT
	// avoids waiting backwards behind legacy task/program writers.
	var pinned domain.ID
	var taskStatus domain.TaskStatus
	if err := tx.QueryRow(ctx, `SELECT id,status FROM tasks WHERE id=$1 AND program_id=$2 FOR SHARE NOWAIT`, lineage.taskID, programID).Scan(&pinned, &taskStatus); err != nil {
		return nil, err
	}
	if taskStatus != domain.TaskRunning {
		return nil, fmt.Errorf("%w: task is not running", ErrExactDispatchDenied)
	}
	if err := pinLaunchProgramParent(ctx, tx, programID); err != nil {
		return nil, err
	}

	var approvalID, approvalTaskID, approvalActionID, approvalAttemptID domain.ID
	var approvalKind, decision, approvedSHA, reviewSHA string
	var revokedAt, expiresAt, decidedAt *time.Time
	var decidedBy *string
	err = tx.QueryRow(ctx, `SELECT id,task_id,action_request_id,bound_provider_attempt_id,approval_kind,decision,
		action_sha256,review_context_sha256,revoked_at,expires_at,decided_at,decided_by
		FROM approvals WHERE bound_provider_attempt_id=$1 FOR UPDATE`, providerAttemptID).
		Scan(&approvalID, &approvalTaskID, &approvalActionID, &approvalAttemptID, &approvalKind, &decision,
			&approvedSHA, &reviewSHA, &revokedAt, &expiresAt, &decidedAt, &decidedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: exact approval missing", ErrExactDispatchDenied)
	}
	if err != nil {
		return nil, err
	}
	if approvalKind != "exact_action" || decision != "approved" || revokedAt != nil ||
		reviewSHA == "" || approvalTaskID != lineage.taskID ||
		approvalAttemptID != providerAttemptID || decidedAt == nil || decidedBy == nil || strings.TrimSpace(*decidedBy) == "" {
		return nil, fmt.Errorf("%w: exact approval is invalid", ErrExactDispatchDenied)
	}

	var dispatchApprovalID, dispatchProgramID, dispatchActionID domain.ID
	var dispatchSHA, dispatchState string
	err = tx.QueryRow(ctx, `SELECT approval_id,program_id,action_request_id,action_sha256,state
		FROM exact_dispatch_attempts WHERE provider_attempt_id=$1 FOR UPDATE`, providerAttemptID).
		Scan(&dispatchApprovalID, &dispatchProgramID, &dispatchActionID, &dispatchSHA, &dispatchState)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: dispatch companion missing", ErrExactDispatchDenied)
	}
	if err != nil {
		return nil, err
	}
	var contractBytes, reviewBytes []byte
	var contractSchema, capabilityRevision, reviewSchema, actionSHA, frozenReviewSHA string
	var frozenActionID, frozenProviderAttemptID, frozenProgramID, frozenTaskID, frozenRunID, frozenStepID domain.ID
	var frozenAttempt int
	err = tx.QueryRow(ctx, `SELECT action_request_id,bound_provider_attempt_id,program_id,task_id,workflow_run_id,step_run_id,step_attempt,
		contract_schema,capability_semantic_revision,canonical_contract,action_sha256,review_schema,
		canonical_review_context,review_context_sha256 FROM exact_actions WHERE action_request_id=$1 FOR KEY SHARE NOWAIT`, approvalActionID).
		Scan(&frozenActionID, &frozenProviderAttemptID, &frozenProgramID, &frozenTaskID, &frozenRunID, &frozenStepID, &frozenAttempt,
			&contractSchema, &capabilityRevision, &contractBytes, &actionSHA, &reviewSchema, &reviewBytes, &frozenReviewSHA)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: frozen action missing", ErrExactDispatchDenied)
	}
	if err != nil {
		return nil, err
	}
	if contractSchema != exactaction.ContractVersion || capabilityRevision != exactaction.CapabilityRevision || reviewSchema != exactaction.ReviewVersion || frozenActionID != approvalActionID || frozenProviderAttemptID != providerAttemptID || frozenProgramID != programID || frozenTaskID != lineage.taskID || frozenRunID != step.WorkflowRunID || frozenStepID != step.ID || frozenAttempt != lineage.attemptCount || approvedSHA != actionSHA || reviewSHA != frozenReviewSHA {
		return nil, fmt.Errorf("%w: frozen action/approval lineage invalid", ErrExactDispatchDenied)
	}
	contract, err := exactaction.DecodeContract(contractBytes, actionSHA)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid frozen contract: %v", ErrExactDispatchDenied, err)
	}
	if _, err = exactaction.DecodeReview(reviewBytes, frozenReviewSHA); err != nil {
		return nil, fmt.Errorf("%w: invalid frozen review: %v", ErrExactDispatchDenied, err)
	}
	if contract.ActionID != approvalActionID || contract.Ownership != (exactaction.Ownership{ProgramID: programID, TaskID: lineage.taskID, WorkflowRunID: step.WorkflowRunID, StepRunID: step.ID, StepAttempt: lineage.attemptCount}) {
		return nil, fmt.Errorf("%w: contract ownership mismatch", ErrExactDispatchDenied)
	}
	if dispatchState != "UNDISPATCHED" || dispatchApprovalID != approvalID || dispatchProgramID != programID ||
		dispatchActionID != approvalActionID || dispatchSHA != actionSHA {
		return nil, fmt.Errorf("%w: dispatch identity or state invalid", ErrExactDispatchDenied)
	}
	var attemptActionID, authEventID domain.ID
	var attemptStep int
	var attemptScheduler *int
	var attemptScheduleID *domain.ID
	err = tx.QueryRow(ctx, `SELECT action_request_id,execution_authorization_event_id,step_attempt,
		scheduler_attempt,scheduled_execution_id FROM audit_events
		WHERE id=$1 AND event_type='provider_invocation_started' AND program_id=$2 AND task_id=$3
		  AND workflow_run_id=$4 AND step_run_id=$5 AND capability='http.request'
		FOR KEY SHARE NOWAIT`, providerAttemptID, programID, lineage.taskID, step.WorkflowRunID, step.ID).
		Scan(&attemptActionID, &authEventID, &attemptStep, &attemptScheduler, &attemptScheduleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: provider attempt lineage invalid", ErrExactDispatchDenied)
	}
	if err != nil {
		return nil, err
	}
	if attemptActionID != approvalActionID || authEventID == "" || attemptStep != lineage.attemptCount ||
		(lineage.scheduled && (attemptScheduleID == nil || *attemptScheduleID != *lineage.scheduledID || attemptScheduler == nil || *attemptScheduler != *lineage.schedulerAttempt)) ||
		(!lineage.scheduled && (attemptScheduleID != nil || attemptScheduler != nil)) {
		return nil, fmt.Errorf("%w: provider attempt fencing invalid", ErrExactDispatchDenied)
	}
	var authorized bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events
		WHERE id=$1 AND event_type='policy_allowed' AND details->>'phase'='execution'
		  AND program_id=$2 AND task_id=$3 AND workflow_run_id=$4 AND step_run_id=$5
		  AND action_request_id=$6 AND step_attempt=$7 AND capability='http.request'
		  AND scheduled_execution_id IS NOT DISTINCT FROM $8
		  AND scheduler_attempt IS NOT DISTINCT FROM $9)`,
		authEventID, programID, lineage.taskID, step.WorkflowRunID, step.ID, attemptActionID, attemptStep,
		optionalIDPointer(lineage.scheduledID), lineage.schedulerAttempt).Scan(&authorized)
	if err != nil {
		return nil, err
	}
	if !authorized {
		return nil, fmt.Errorf("%w: provider attempt authorization lineage invalid", ErrExactDispatchDenied)
	}

	var scopeID, policyID *domain.ID
	var epoch int64
	var status string
	err = tx.QueryRow(ctx, `SELECT active_scope_id,active_policy_id,authority_epoch,status
		FROM program_launch_authority WHERE program_id=$1 FOR SHARE`, programID).Scan(&scopeID, &policyID, &epoch, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: launch authority missing", ErrExactDispatchDenied)
	}
	if err != nil {
		return nil, err
	}
	if status != "READY" || scopeID == nil || policyID == nil {
		return nil, fmt.Errorf("%w: launch authority blocked or incomplete", ErrExactDispatchDenied)
	}
	pendingScope, err := unresolvedExactScopeCandidate(ctx, tx, programID)
	if err != nil {
		return nil, err
	}
	if pendingScope {
		return nil, fmt.Errorf("%w: scope candidate awaits acknowledgement", ErrExactDispatchDenied)
	}
	var scopeBytes, policyBytes []byte
	var scopeSHA, scopeDigest, scopeSchema, scopeEval, policySHA, policySchema, policyEval string
	err = tx.QueryRow(ctx, `SELECT canonical_material,material_sha256,scope_digest,material_schema,evaluator_revision
		FROM scopes WHERE id=$1 AND program_id=$2 FOR KEY SHARE NOWAIT`, *scopeID, programID).
		Scan(&scopeBytes, &scopeSHA, &scopeDigest, &scopeSchema, &scopeEval)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: active scope missing or wrongly owned", ErrExactDispatchDenied)
	}
	if err != nil {
		return nil, err
	}
	err = tx.QueryRow(ctx, `SELECT canonical_material,material_sha256,material_schema,evaluator_revision
		FROM policies WHERE id=$1 AND program_id=$2 FOR KEY SHARE NOWAIT`, *policyID, programID).
		Scan(&policyBytes, &policySHA, &policySchema, &policyEval)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: active policy missing or wrongly owned", ErrExactDispatchDenied)
	}
	if err != nil {
		return nil, err
	}
	if scopeSchema != launchauthority.ScopeSchemaV1 || scopeEval != launchauthority.ScopeEvaluatorV1 ||
		policySchema != launchauthority.PolicySchemaV1 || policyEval != launchauthority.PolicyEvaluatorV1 {
		return nil, fmt.Errorf("%w: unsupported material revision", ErrExactDispatchDenied)
	}
	sc, err := launchauthority.DecodeScope(scopeBytes, scopeSHA)
	if err != nil || sc.Digest() != scopeDigest {
		return nil, fmt.Errorf("%w: invalid active scope material", ErrExactDispatchDenied)
	}
	pol, err := launchauthority.DecodePolicy(policyBytes, policySHA)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid active policy material: %v", ErrExactDispatchDenied, err)
	}
	var currentProgramDigest string
	if err := tx.QueryRow(ctx, `SELECT scope_digest FROM programs WHERE id=$1`, programID).Scan(&currentProgramDigest); err != nil {
		return nil, err
	}
	if currentProgramDigest != scopeDigest {
		return nil, fmt.Errorf("%w: program scope no longer matches active material", ErrExactDispatchDenied)
	}
	var checkedAt time.Time
	var leaseDeadline *time.Time
	if lineage.scheduled {
		fence, ok := scheduledExecutionFenceFromContext(ctx)
		if !ok || lineage.scheduledID == nil || lineage.schedulerAttempt == nil || fence.Attempt != *lineage.schedulerAttempt {
			return nil, fmt.Errorf("%w: scheduled claim is missing", ErrExactDispatchDenied)
		}
		err = tx.QueryRow(ctx, `SELECT clock_timestamp(),lease_expires_at FROM scheduled_executions
			WHERE id=$1 AND status='running' AND lease_owner=$2 AND attempt_count=$3`,
			*lineage.scheduledID, fence.LeaseOwner, fence.Attempt).Scan(&checkedAt, &leaseDeadline)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: scheduled lease is no longer valid", ErrExactDispatchDenied)
		}
		if err != nil {
			return nil, err
		}
		if leaseDeadline == nil || !leaseDeadline.After(checkedAt) {
			return nil, fmt.Errorf("%w: scheduled lease is no longer valid", ErrExactDispatchDenied)
		}
	} else if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&checkedAt); err != nil {
		return nil, err
	}
	if decidedAt.After(checkedAt) || (expiresAt != nil && !expiresAt.After(checkedAt)) {
		return nil, fmt.Errorf("%w: approval is not currently valid", ErrExactDispatchDenied)
	}
	scopeTarget := fmt.Sprintf("https://%s:%d%s", contract.Request.Hostname, contract.Request.EffectivePort, contract.Request.RequestTarget)
	scopeDecision := sc.Evaluate(scopeTarget)
	if !scopeDecision.Allowed {
		return nil, fmt.Errorf("%w: current scope denied action (%s)", ErrExactDispatchDenied, scopeDecision.Reason)
	}
	policyInput, err := json.Marshal(struct {
		Method string `json:"method"`
	}{Method: contract.Request.Method})
	if err != nil {
		return nil, err
	}
	policyDecision := policy.EvaluateAt(pol, "http.request", policy.Low, true, policy.Requirements{}, policyInput, checkedAt)
	if policyDecision.Decision != policy.Allow {
		return nil, fmt.Errorf("%w: current policy denied action (%s)", ErrExactDispatchDenied, policyDecision.Reason)
	}
	windowDeadline, err := policy.CurrentScanWindowDeadline(pol.ScanWindows, checkedAt)
	if err != nil {
		return nil, err
	}
	deadline := earlierDeadline(earlierDeadline(expiresAt, windowDeadline), leaseDeadline)
	var intentAt time.Time
	err = tx.QueryRow(ctx, `UPDATE exact_dispatch_attempts SET state='DISPATCH_INTENT',active_scope_id=$2,
		scope_sha256=$3,active_policy_id=$4,policy_sha256=$5,authority_epoch=$6,
		scope_evaluator_revision=$7,policy_evaluator_revision=$8,scope_reason=$9,policy_reason=$10,
		eligibility_checked_at=$11,dispatch_intent_at=clock_timestamp()
		WHERE provider_attempt_id=$1 AND state='UNDISPATCHED'
		  AND ($12::timestamptz IS NULL OR clock_timestamp() < $12::timestamptz)
		RETURNING dispatch_intent_at`,
		providerAttemptID, *scopeID, scopeSHA, *policyID, policySHA, epoch, scopeEval, policyEval,
		string(scopeDecision.Reason), policyDecision.Reason, checkedAt, deadline).Scan(&intentAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: dispatch intent already exists or deadline expired", ErrExactDispatchDenied)
	}
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,
		workflow_run_id,step_run_id,scheduled_execution_id,scheduler_attempt,action_request_id,
		step_attempt,provider_attempt_id,capability,provider,safe_message,details)
		SELECT $1,'exact_dispatch_intent','platform','exact-dispatch',$2,$3,$4,$5,$6,$7,$8,$9,$10,
		'http.request','exact-action','exact dispatch intent committed',$11`,
		domain.NewID(), lineage.taskID, programID, step.WorkflowRunID, step.ID,
		optionalIDPointer(lineage.scheduledID), lineage.schedulerAttempt, approvalActionID, attemptStep,
		providerAttemptID, mustJSON(map[string]any{
			"action_sha256": actionSHA, "authority_epoch": epoch, "authority_status": status,
			"scope_id": scopeID, "scope_sha256": scopeSHA, "scope_digest": scopeDigest,
			"policy_id": policyID, "policy_sha256": policySHA, "scope_evaluator_revision": scopeEval,
			"policy_evaluator_revision": policyEval, "scope_reason": scopeDecision.Reason,
			"policy_decision": policyDecision.Decision, "policy_reason": policyDecision.Reason,
			"eligibility_checked_at": checkedAt, "dispatch_intent_at": intentAt,
		}))
	if err != nil {
		return nil, err
	}
	if beforeCommit != nil {
		if err := beforeCommit(tx); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &ExactDispatchPermit{providerAttemptID: providerAttemptID, actionSHA256: actionSHA, authorityEpoch: epoch, deadline: deadline, used: new(atomic.Bool)}, nil
}

func earlierDeadline(a, b *time.Time) *time.Time {
	if a == nil {
		return b
	}
	if b == nil || a.Before(*b) {
		return a
	}
	return b
}
