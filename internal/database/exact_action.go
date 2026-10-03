package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
)

var ErrExactApprovalDenied = errors.New("exact approval denied")

const exactTerminalDecisionSQL = `WITH decision_clock AS MATERIALIZED (SELECT clock_timestamp() AS decided_at)
	UPDATE approvals a SET decision=$2,decided_by=$3,decided_at=decision_clock.decided_at
	FROM decision_clock
	WHERE a.id=$1 AND a.approval_kind='exact_action' AND a.decision='pending'
	  AND a.bound_provider_attempt_id=$4 AND a.revoked_at IS NULL
	  AND ($2 <> 'approved' OR a.expires_at IS NULL OR a.expires_at > decision_clock.decided_at)`

// PrepareExactActionApproval freezes a proposed non-networked action and its
// review, then issues P and X's launch companion in one transaction. X must
// already have been allocated by the registered provider admission path.
func (s *Store) PrepareExactActionApproval(ctx context.Context, programID domain.ID, step domain.StepRun, providerAttemptID domain.ID, proposed exactaction.ProposedRequest, review exactaction.ReviewContextV1, actor string, expiresAt time.Time) (domain.ID, error) {
	return s.prepareExactActionApproval(ctx, programID, step, providerAttemptID, proposed, review, actor, expiresAt, nil)
}

func (s *Store) prepareExactActionApproval(ctx context.Context, programID domain.ID, step domain.StepRun, providerAttemptID domain.ID, proposed exactaction.ProposedRequest, review exactaction.ReviewContextV1, actor string, expiresAt time.Time, beforeCommit func(pgx.Tx) error) (domain.ID, error) {
	if programID == "" || providerAttemptID == "" || step.Capability != "http.request" || len(actor) < 1 || len(actor) > 80 || strings.TrimSpace(actor) == "" || expiresAt.IsZero() {
		return "", fmt.Errorf("%w: incomplete preparation", ErrExactApprovalDenied)
	}
	if _, recovering := domain.PreparedRecoveryRequestFromContext(ctx); recovering {
		return "", fmt.Errorf("%w: recovery cannot prepare exact action", ErrExactApprovalDenied)
	}
	if err := review.Validate(); err != nil {
		return "", err
	}
	var evidenceGuard artifact.VerifiedEvidenceGuard
	if len(exactReviewCitations(review)) > 0 {
		var err error
		evidenceGuard, err = s.acquireExactReviewEvidence(ctx)
		if err != nil {
			return "", fmt.Errorf("%w: verified evidence authority is unavailable", ErrExactApprovalDenied)
		}
		defer evidenceGuard.Close()
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	lineage, err := lockResultLineage(ctx, tx, programID, step)
	if err != nil {
		return "", err
	}
	if lineage.stepStatus != domain.StepRunning || lineage.attemptCount < 1 {
		return "", fmt.Errorf("%w: step is not running", ErrExactApprovalDenied)
	}
	var taskID domain.ID
	var taskStatus domain.TaskStatus
	if err := tx.QueryRow(ctx, `SELECT id,status FROM tasks WHERE id=$1 AND program_id=$2 FOR SHARE NOWAIT`, lineage.taskID, programID).Scan(&taskID, &taskStatus); err != nil {
		return "", err
	}
	if taskStatus != domain.TaskRunning {
		return "", fmt.Errorf("%w: task is not running", ErrExactApprovalDenied)
	}
	if err := pinLaunchProgramParent(ctx, tx, programID); err != nil {
		return "", err
	}
	var actionID, authID domain.ID
	var attempt int
	var scheduledID *domain.ID
	var schedulerAttempt *int
	err = tx.QueryRow(ctx, `SELECT action_request_id,execution_authorization_event_id,step_attempt,scheduled_execution_id,scheduler_attempt
		FROM audit_events WHERE id=$1 AND event_type='provider_invocation_started' AND program_id=$2 AND task_id=$3
		AND workflow_run_id=$4 AND step_run_id=$5 AND capability='http.request' FOR KEY SHARE NOWAIT`,
		providerAttemptID, programID, lineage.taskID, step.WorkflowRunID, step.ID).Scan(&actionID, &authID, &attempt, &scheduledID, &schedulerAttempt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: provider attempt lineage invalid", ErrExactApprovalDenied)
	}
	if err != nil {
		return "", err
	}
	if actionID == "" || authID == "" || attempt != lineage.attemptCount ||
		(lineage.scheduled && (scheduledID == nil || *scheduledID != *lineage.scheduledID || schedulerAttempt == nil || *schedulerAttempt != *lineage.schedulerAttempt)) ||
		(!lineage.scheduled && (scheduledID != nil || schedulerAttempt != nil)) {
		return "", fmt.Errorf("%w: provider attempt fencing invalid", ErrExactApprovalDenied)
	}
	var authorized bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events WHERE id=$1 AND event_type='policy_allowed' AND details->>'phase'='execution'
		AND program_id=$2 AND task_id=$3 AND workflow_run_id=$4 AND step_run_id=$5 AND action_request_id=$6
		AND step_attempt=$7 AND capability='http.request' AND scheduled_execution_id IS NOT DISTINCT FROM $8
		AND scheduler_attempt IS NOT DISTINCT FROM $9)`, authID, programID, lineage.taskID, step.WorkflowRunID, step.ID, actionID, attempt, optionalIDPointer(lineage.scheduledID), lineage.schedulerAttempt).Scan(&authorized)
	if err != nil {
		return "", err
	}
	if !authorized {
		return "", fmt.Errorf("%w: missing execution authorization provenance", ErrExactApprovalDenied)
	}
	action := exactaction.ActionContractV1{ContractVersion: exactaction.ContractVersion, ActionID: actionID,
		Ownership:  exactaction.Ownership{ProgramID: programID, TaskID: lineage.taskID, WorkflowRunID: step.WorkflowRunID, StepRunID: step.ID, StepAttempt: attempt},
		Capability: exactaction.Capability{Name: "http.request", SemanticRevision: exactaction.CapabilityRevision},
		Request:    exactaction.Request{Method: proposed.Method, Scheme: proposed.Scheme, Hostname: proposed.Hostname, EffectivePort: proposed.EffectivePort, RequestTarget: proposed.RequestTarget, Headers: []string{}},
		Identity:   exactaction.Identity{Kind: "anonymous"}, Limits: exactaction.Limits{MaxRequests: 1}}
	contractBytes, actionSHA, err := action.Freeze()
	if err != nil {
		return "", err
	}
	reviewBytes, reviewSHA, err := review.Freeze()
	if err != nil {
		return "", err
	}
	for _, citation := range exactReviewCitations(review) {
		if err := s.requireReviewableCitation(ctx, tx, programID, citation, false, evidenceGuard); err != nil {
			return "", err
		}
	}
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return "", err
	}
	if !expiresAt.After(now) {
		return "", fmt.Errorf("%w: approval expiry passed", ErrExactApprovalDenied)
	}
	_, err = tx.Exec(ctx, `INSERT INTO exact_actions(action_request_id,bound_provider_attempt_id,program_id,task_id,workflow_run_id,step_run_id,step_attempt,
		contract_schema,capability_semantic_revision,canonical_contract,action_sha256,review_schema,canonical_review_context,review_context_sha256,created_by)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, actionID, providerAttemptID, programID, lineage.taskID, step.WorkflowRunID, step.ID, attempt,
		exactaction.ContractVersion, exactaction.CapabilityRevision, contractBytes, actionSHA, exactaction.ReviewVersion, reviewBytes, reviewSHA, actor)
	if err != nil {
		return "", err
	}
	for _, citation := range exactReviewCitations(review) {
		if _, err := tx.Exec(ctx, `INSERT INTO exact_action_citations(action_request_id,artifact_id,artifact_sha256) VALUES($1,$2,$3)`, actionID, citation.ArtifactID, citation.ArtifactSHA256); err != nil {
			return "", err
		}
	}
	approvalID := domain.NewID()
	_, err = tx.Exec(ctx, `INSERT INTO approvals(id,request_id,task_id,action_request_id,requested_risk_level,reason,decision,expires_at,
		approval_kind,action_sha256,review_context_sha256,bound_provider_attempt_id)
		VALUES($1,$2,$3,$4,'low','frozen exact HTTP action','pending',$5,'exact_action',$6,$7,$8)`, approvalID, actionID, lineage.taskID, actionID, expiresAt, actionSHA, reviewSHA, providerAttemptID)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, `INSERT INTO exact_dispatch_attempts(provider_attempt_id,approval_id,program_id,action_request_id,action_sha256)
		VALUES($1,$2,$3,$4,$5)`, providerAttemptID, approvalID, programID, actionID, actionSHA)
	if err != nil {
		return "", err
	}
	if beforeCommit != nil {
		if err := beforeCommit(tx); err != nil {
			return "", err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return approvalID, nil
}

type ExactApprovalReview struct {
	ApprovalID           domain.ID
	ProviderAttemptID    domain.ID
	Action               exactaction.ActionContractV1
	Review               exactaction.ReviewContextV1
	ActionSHA256         string
	ReviewContextSHA256  string
	Decision             string
	ExpiresAt            time.Time
	CitationAvailability []ExactCitationAvailability
}

// Citation availability is current operational state, separate from frozen RH.
type ExactCitationAvailability struct {
	ArtifactID domain.ID
	Status     string // available, unavailable, or restricted
}

// GetExactApprovalReview reads only the frozen persistence and P. No mutable
// step input, queue payload, or proposal narrative contributes to the view.
func (s *Store) GetExactApprovalReview(ctx context.Context, approvalID domain.ID) (ExactApprovalReview, error) {
	var out ExactApprovalReview
	var contractBytes, reviewBytes []byte
	var contractSchema, capabilityRevision, reviewSchema string
	var actionID, frozenAttemptID, programID, taskID, runID, stepID, approvalActionID, approvalTaskID, dispatchActionID, dispatchProgramID, dispatchApprovalID domain.ID
	var stepAttempt int
	var approvedSHA, approvedReviewSHA, dispatchSHA, dispatchState string
	err := s.Pool.QueryRow(ctx, `SELECT a.id,a.bound_provider_attempt_id,a.action_request_id,a.task_id,a.action_sha256,a.review_context_sha256,a.decision,a.expires_at,
		e.action_request_id,e.bound_provider_attempt_id,e.program_id,e.task_id,e.workflow_run_id,e.step_run_id,e.step_attempt,e.contract_schema,e.capability_semantic_revision,
		e.canonical_contract,e.action_sha256,e.review_schema,e.canonical_review_context,e.review_context_sha256,
		d.approval_id,d.program_id,d.action_request_id,d.action_sha256,d.state
		FROM approvals a JOIN exact_actions e ON e.action_request_id=a.action_request_id
		JOIN exact_dispatch_attempts d ON d.provider_attempt_id=a.bound_provider_attempt_id
		WHERE a.id=$1 AND a.approval_kind='exact_action'`, approvalID).Scan(&out.ApprovalID, &out.ProviderAttemptID, &approvalActionID, &approvalTaskID, &approvedSHA, &approvedReviewSHA, &out.Decision, &out.ExpiresAt,
		&actionID, &frozenAttemptID, &programID, &taskID, &runID, &stepID, &stepAttempt, &contractSchema, &capabilityRevision, &contractBytes, &out.ActionSHA256, &reviewSchema, &reviewBytes, &out.ReviewContextSHA256,
		&dispatchApprovalID, &dispatchProgramID, &dispatchActionID, &dispatchSHA, &dispatchState)
	if err != nil {
		return out, err
	}
	if frozenAttemptID != out.ProviderAttemptID || contractSchema != exactaction.ContractVersion || capabilityRevision != exactaction.CapabilityRevision || reviewSchema != exactaction.ReviewVersion || approvedSHA != out.ActionSHA256 || approvedReviewSHA != out.ReviewContextSHA256 || approvalActionID != actionID || approvalTaskID != taskID || dispatchApprovalID != approvalID || dispatchProgramID != programID || dispatchActionID != actionID || dispatchSHA != out.ActionSHA256 || (dispatchState != "UNDISPATCHED" && dispatchState != "DISPATCH_INTENT") {
		return out, fmt.Errorf("%w: frozen review linkage invalid", ErrExactApprovalDenied)
	}
	out.Action, err = exactaction.DecodeContract(contractBytes, out.ActionSHA256)
	if err != nil {
		return out, err
	}
	out.Review, err = exactaction.DecodeReview(reviewBytes, out.ReviewContextSHA256)
	if err != nil {
		return out, err
	}
	if out.Action.ActionID != actionID || out.Action.Ownership != (exactaction.Ownership{ProgramID: programID, TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, StepAttempt: stepAttempt}) {
		return out, fmt.Errorf("%w: frozen contract lineage invalid", ErrExactApprovalDenied)
	}
	out.CitationAvailability = make([]ExactCitationAvailability, 0, len(out.Review.SupportingEvidence)+len(out.Review.ContradictoryEvidence))
	for _, citation := range exactReviewCitations(out.Review) {
		status, err := s.reviewCitationAvailability(ctx, citation)
		if err != nil {
			return out, err
		}
		out.CitationAvailability = append(out.CitationAvailability, ExactCitationAvailability{ArtifactID: citation.ArtifactID, Status: status})
	}
	return out, nil
}

// DecideExactApproval is deliberately separate from the legacy workflow-step
// endpoint. The operator must present both hashes read from frozen review.
func (s *Store) DecideExactApproval(ctx context.Context, approvalID domain.ID, actionSHA, reviewSHA, decision, actor string) error {
	if approvalID == "" || len(actor) < 1 || len(actor) > 80 || strings.TrimSpace(actor) == "" || (decision != "approved" && decision != "rejected") {
		return fmt.Errorf("%w: invalid exact decision", ErrExactApprovalDenied)
	}
	var evidenceGuard artifact.VerifiedEvidenceGuard
	if decision == "approved" {
		// The frozen review is immutable. This unlocked read only determines
		// whether shared store authority is needed before lineage locks.
		var reviewBytes []byte
		var frozenReviewSHA string
		if err := s.Pool.QueryRow(ctx, `SELECT e.canonical_review_context,e.review_context_sha256
			FROM approvals a JOIN exact_actions e ON e.action_request_id=a.action_request_id
			WHERE a.id=$1 AND a.approval_kind='exact_action'`, approvalID).Scan(&reviewBytes, &frozenReviewSHA); err != nil {
			return err
		}
		review, err := exactaction.DecodeReview(reviewBytes, frozenReviewSHA)
		if err != nil {
			return err
		}
		if len(exactReviewCitations(review)) > 0 {
			evidenceGuard, err = s.acquireExactReviewEvidence(ctx)
			if err != nil {
				return fmt.Errorf("%w: verified evidence authority is unavailable", ErrExactApprovalDenied)
			}
			defer evidenceGuard.Close()
		}
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// This is only an identity lookup. Locks begin with the scheduler root and
	// workflow, in the same direction as result and launch admission.
	var runID, stepID domain.ID
	err = tx.QueryRow(ctx, `SELECT e.workflow_run_id,e.step_run_id FROM approvals a JOIN exact_actions e ON e.action_request_id=a.action_request_id WHERE a.id=$1 AND a.approval_kind='exact_action'`, approvalID).Scan(&runID, &stepID)
	if err != nil {
		return err
	}
	scheduled, scheduledProgram, hasScheduled, err := lockedScheduledExecutionByWorkflow(ctx, tx, runID)
	if err != nil {
		return err
	}
	if err = lockApprovalWorkflow(ctx, tx, runID); err != nil {
		return err
	}
	var taskStatus domain.TaskStatus
	var stepStatus domain.StepStatus
	var currentAttempt int
	var stepCapability string
	var currentProgramID, currentTaskID domain.ID
	err = tx.QueryRow(ctx, `SELECT t.program_id,t.id,t.status,sr.status,sr.attempt_count,sr.capability
		FROM step_runs sr JOIN workflow_runs wr ON wr.id=sr.workflow_run_id JOIN tasks t ON t.id=wr.task_id
		WHERE sr.id=$1 AND wr.id=$2 FOR SHARE OF t NOWAIT`, stepID, runID).Scan(&currentProgramID, &currentTaskID, &taskStatus, &stepStatus, &currentAttempt, &stepCapability)
	if err != nil {
		return err
	}
	if taskStatus != domain.TaskRunning || stepStatus != domain.StepRunning || stepCapability != "http.request" {
		return fmt.Errorf("%w: lineage no longer current", ErrExactApprovalDenied)
	}
	if err = pinLaunchProgramParent(ctx, tx, currentProgramID); err != nil {
		return err
	}
	var programID, taskID, actionID, providerAttemptID, frozenAttemptID domain.ID
	var attempt int
	var frozenAction, frozenReview, approvedAction, approvedReview, kind, state, contractSchema, reviewSchema, capabilityRevision string
	var contractBytes, reviewBytes []byte
	var expiresAt, revokedAt *time.Time
	var approvalTask, approvalAction, dispatchApproval, dispatchProgram, dispatchAction domain.ID
	var dispatchSHA, dispatchState string
	err = tx.QueryRow(ctx, `SELECT e.program_id,e.task_id,e.action_request_id,e.bound_provider_attempt_id,e.step_attempt,e.contract_schema,e.capability_semantic_revision,e.review_schema,
		e.canonical_contract,e.action_sha256,e.canonical_review_context,e.review_context_sha256
		FROM exact_actions e WHERE e.action_request_id=(SELECT action_request_id FROM approvals WHERE id=$1 AND approval_kind='exact_action')
		AND e.workflow_run_id=$2 AND e.step_run_id=$3 FOR KEY SHARE OF e NOWAIT`, approvalID, runID, stepID).Scan(
		&programID, &taskID, &actionID, &frozenAttemptID, &attempt, &contractSchema, &capabilityRevision, &reviewSchema, &contractBytes, &frozenAction, &reviewBytes, &frozenReview,
	)
	if err != nil {
		return err
	}
	err = tx.QueryRow(ctx, `SELECT task_id,action_request_id,bound_provider_attempt_id,approval_kind,decision,action_sha256,review_context_sha256,expires_at,revoked_at
		FROM approvals WHERE id=$1 FOR UPDATE`, approvalID).Scan(&approvalTask, &approvalAction, &providerAttemptID, &kind, &state, &approvedAction, &approvedReview, &expiresAt, &revokedAt)
	if err != nil {
		return err
	}
	err = tx.QueryRow(ctx, `SELECT approval_id,program_id,action_request_id,action_sha256,state FROM exact_dispatch_attempts WHERE provider_attempt_id=$1 FOR UPDATE`, providerAttemptID).Scan(&dispatchApproval, &dispatchProgram, &dispatchAction, &dispatchSHA, &dispatchState)
	if err != nil {
		return err
	}
	if frozenAttemptID != providerAttemptID || programID != currentProgramID || taskID != currentTaskID || currentAttempt != attempt || contractSchema != exactaction.ContractVersion || capabilityRevision != exactaction.CapabilityRevision || reviewSchema != exactaction.ReviewVersion || kind != "exact_action" || state != "pending" || revokedAt != nil || expiresAt == nil || actionSHA != frozenAction || reviewSHA != frozenReview || approvedAction != frozenAction || approvedReview != frozenReview || approvalTask != taskID || approvalAction != actionID || dispatchApproval != approvalID || dispatchProgram != programID || dispatchAction != actionID || dispatchSHA != frozenAction || dispatchState != "UNDISPATCHED" {
		return fmt.Errorf("%w: stale or invalid frozen approval", ErrExactApprovalDenied)
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if !expiresAt.After(now) {
		return fmt.Errorf("%w: exact approval expired", ErrExactApprovalDenied)
	}
	action, err := exactaction.DecodeContract(contractBytes, frozenAction)
	if err != nil {
		return err
	}
	review, err := exactaction.DecodeReview(reviewBytes, frozenReview)
	if err != nil {
		return err
	}
	if action.ActionID != actionID || action.Ownership != (exactaction.Ownership{ProgramID: programID, TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, StepAttempt: attempt}) {
		return fmt.Errorf("%w: frozen lineage mismatch", ErrExactApprovalDenied)
	}
	var attemptAction, authID domain.ID
	var attemptCount int
	var attemptScheduledID *domain.ID
	var attemptScheduler *int
	err = tx.QueryRow(ctx, `SELECT action_request_id,execution_authorization_event_id,step_attempt,scheduled_execution_id,scheduler_attempt FROM audit_events WHERE id=$1 AND event_type='provider_invocation_started' AND program_id=$2 AND task_id=$3 AND workflow_run_id=$4 AND step_run_id=$5 AND capability='http.request' FOR KEY SHARE NOWAIT`, providerAttemptID, programID, taskID, runID, stepID).Scan(&attemptAction, &authID, &attemptCount, &attemptScheduledID, &attemptScheduler)
	if err != nil {
		return err
	}
	if attemptAction != actionID || authID == "" || attemptCount != attempt ||
		(hasScheduled && (scheduledProgram != programID || attemptScheduledID == nil || *attemptScheduledID != scheduled.ID || attemptScheduler == nil || *attemptScheduler != scheduled.AttemptCount)) ||
		(!hasScheduled && (attemptScheduledID != nil || attemptScheduler != nil)) {
		return fmt.Errorf("%w: X lineage mismatch", ErrExactApprovalDenied)
	}
	var authorized bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events WHERE id=$1 AND event_type='policy_allowed' AND details->>'phase'='execution'
		AND program_id=$2 AND task_id=$3 AND workflow_run_id=$4 AND step_run_id=$5 AND action_request_id=$6
		AND step_attempt=$7 AND capability='http.request' AND scheduled_execution_id IS NOT DISTINCT FROM $8
		AND scheduler_attempt IS NOT DISTINCT FROM $9)`, authID, programID, taskID, runID, stepID, actionID, attempt, attemptScheduledID, attemptScheduler).Scan(&authorized)
	if err != nil {
		return err
	}
	if !authorized {
		return fmt.Errorf("%w: X authorization lineage mismatch", ErrExactApprovalDenied)
	}
	if decision == "approved" {
		for _, citation := range exactReviewCitations(review) {
			if evidenceGuard == nil {
				return fmt.Errorf("%w: verified evidence authority is unavailable", ErrExactApprovalDenied)
			}
			if err := s.requireReviewableCitation(ctx, tx, programID, citation, true, evidenceGuard); err != nil {
				return err
			}
		}
	}
	// One PostgreSQL clock value both fences approval and becomes decided_at.
	// Rejection retains the existing pending/unexpired entry check above, but
	// does not gain authority and needs no terminal expiry predicate.
	tag, err := tx.Exec(ctx, exactTerminalDecisionSQL, approvalID, decision, actor, providerAttemptID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: decision lost race", ErrExactApprovalDenied)
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,action_request_id,step_attempt,provider_attempt_id,capability,safe_message,details)
		VALUES($1,'exact_approval_decided','platform',$2,$3,$4,$5,$6,$7,$8,$9,'http.request','frozen exact approval decided',$10)`, domain.NewID(), actor, taskID, programID, runID, stepID, actionID, attempt, providerAttemptID, mustJSON(map[string]string{"decision": decision, "action_sha256": frozenAction, "review_context_sha256": frozenReview}))
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func exactReviewCitations(review exactaction.ReviewContextV1) []exactaction.Citation {
	citations := make([]exactaction.Citation, 0, len(review.SupportingEvidence)+len(review.ContradictoryEvidence))
	citations = append(citations, review.SupportingEvidence...)
	return append(citations, review.ContradictoryEvidence...)
}

// The artifact SHARE lock excludes cleanup claims and access-state changes
// until preparation or the terminal decision commits. The trusted reader then
// checks adopted publication, redaction, sensitivity, and result provenance.
func (s *Store) requireReviewableCitation(ctx context.Context, tx pgx.Tx, programID domain.ID, citation exactaction.Citation, allowProtectedExpiry bool, reader artifact.VerifiedEvidenceGuard) error {
	var runID domain.ID
	var digest string
	err := tx.QueryRow(ctx, `SELECT a.workflow_run_id,a.sha256 FROM artifacts a JOIN tasks t ON t.id=a.task_id
		JOIN workflow_runs wr ON wr.id=a.workflow_run_id AND wr.task_id=t.id
		JOIN step_runs sr ON sr.id=a.step_run_id AND sr.workflow_run_id=wr.id
		WHERE a.id=$1 AND t.program_id=$2 AND a.content_deleted_at IS NULL AND a.cleanup_quarantined_at IS NULL
		AND a.cleanup_claim_token IS NULL
		AND ($3 OR a.expires_at IS NULL OR a.expires_at>clock_timestamp())
		FOR SHARE OF a NOWAIT`, citation.ArtifactID, programID, allowProtectedExpiry).Scan(&runID, &digest)
	if err != nil || digest != citation.ArtifactSHA256 {
		return fmt.Errorf("%w: review citation is not owned available evidence", ErrExactApprovalDenied)
	}
	authorized, err := authorizeEvidenceViewTx(ctx, tx, runID, citation.ArtifactID)
	if err != nil || authorized.Reference.ContentSHA256 != citation.ArtifactSHA256 {
		return fmt.Errorf("%w: review citation cannot be inspected", ErrExactApprovalDenied)
	}
	if err := inspectExactReviewBytes(ctx, reader, authorized.Reference); err != nil {
		return fmt.Errorf("%w: review citation bytes are unavailable", ErrExactApprovalDenied)
	}
	return nil
}

func inspectExactReviewBytes(ctx context.Context, reader artifact.SemanticArtifactReader, reference domain.ResultArtifactRefV1) error {
	if reader == nil {
		return artifact.ErrEvidenceUnavailable
	}
	verified, err := reader.OpenVerified(ctx, reference)
	if err != nil {
		return err
	}
	// The existing verified reader drains the content and checks both size and
	// SHA-256 on Close. No evidence bytes enter the review model.
	return verified.Close()
}

func (s *Store) acquireExactReviewEvidence(ctx context.Context) (artifact.VerifiedEvidenceGuard, error) {
	reader := s.exactReviewEvidenceReader()
	guarded, ok := reader.(interface {
		AcquireVerifiedEvidence(context.Context) (artifact.VerifiedEvidenceGuard, error)
	})
	if !ok {
		return nil, artifact.ErrEvidenceUnavailable
	}
	guard, err := guarded.AcquireVerifiedEvidence(ctx)
	if err != nil {
		return nil, err
	}
	if guard == nil {
		return nil, artifact.ErrEvidenceUnavailable
	}
	return guard, nil
}

func (s *Store) reviewCitationAvailability(ctx context.Context, citation exactaction.Citation) (string, error) {
	var runID domain.ID
	err := s.Pool.QueryRow(ctx, `SELECT workflow_run_id FROM artifacts WHERE id=$1`, citation.ArtifactID).Scan(&runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "unavailable", nil
	}
	if err != nil {
		return "", err
	}
	authorized, err := s.AuthorizeEvidenceView(ctx, runID, citation.ArtifactID)
	switch {
	case errors.Is(err, artifact.ErrEvidenceRestricted):
		return "restricted", nil
	case errors.Is(err, artifact.ErrEvidenceUnavailable):
		return "unavailable", nil
	case err != nil:
		return "", err
	case authorized.Reference.ContentSHA256 != citation.ArtifactSHA256:
		return "unavailable", nil
	default:
		if err := inspectExactReviewBytes(ctx, s.exactReviewEvidenceReader(), authorized.Reference); err != nil {
			return "unavailable", nil
		}
		return "available", nil
	}
}
