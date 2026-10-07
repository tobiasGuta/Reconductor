package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/resultadmission"
)

// RejectPreparedEvidence records known nonadmission without accepting a ToolRun,
// publishing artifacts, or manufacturing a replacement occurrence. It is the
// ALLOCATED -> RESOLVED_ABANDONED path authorized by the oversized-admission
// decision. No cleanup is performed by this transaction.
func (s *Store) RejectPreparedEvidence(ctx context.Context, programID domain.ID, step domain.StepRun, compiled resultadmission.CompiledResult, admission capability.ResultAdmissionProvenance, request artifact.PreparedStageRequest, limit domain.ResultContractLimitV1) error {
	if err := limit.Validate(); err != nil || limit.Subject != domain.LimitPreparedEvidence || limit.Unit != domain.LimitBytes || limit.Limit != uint64(admission.ReservedCapacityBytes) {
		return fmt.Errorf("invalid prepared nonadmission limit")
	}
	if compiled.PreparedSetID != admission.PreparedSetID || compiled.ManifestID != admission.ManifestID || compiled.ProviderTerminalEventID != admission.ProviderTerminalEventID || request.SetID != compiled.PreparedSetID || request.ManifestID != compiled.ManifestID || request.ReservedCapacityBytes != admission.ReservedCapacityBytes {
		return fmt.Errorf("prepared nonadmission identity contradiction")
	}
	// This fixed schema contains no provider text. The manifest digest commits to
	// every original publication/artifact identity without storing the payload.
	details, err := json.Marshal(struct {
		Code           string                              `json:"code"`
		Subject        domain.ResultContractLimitSubjectV1 `json:"subject"`
		Limit          uint64                              `json:"limit"`
		Observed       uint64                              `json:"observed"`
		ManifestSHA256 string                              `json:"manifest_sha256"`
	}{"result_contract_limit", limit.Subject, limit.Limit, limit.Observed, artifact.DigestString(artifact.DigestBytes(request.ManifestJSON))})
	if err != nil {
		return err
	}
	if len(details) > 512 {
		return fmt.Errorf("nonadmission metadata exceeds fixed bound")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	lineage, err := lockResultLineage(ctx, tx, programID, step)
	if err != nil {
		return err
	}
	if err := requireCurrentPreparedAttempt(lineage, &admission); err != nil {
		return err
	}
	tool := compiled.ToolRun
	if err := lockAndValidateProviderResult(ctx, tx, lineage, programID, step, &tool, domain.ActionResult{RequestID: admission.ActionRequestID}, &admission); err != nil {
		return err
	}
	if err := lockConflictingResultTools(ctx, tx, step.ID, nil, lineage.scheduled); err != nil {
		return err
	}
	var capacity int64
	if err := tx.QueryRow(ctx, `SELECT reserved_capacity_bytes FROM prepared_evidence_sets
		WHERE id=$1 AND manifest_id=$2 AND provider_attempt_id=$3 AND action_request_id=$4 AND step_attempt=$5
		AND lifecycle_state='ALLOCATED' AND program_id=$6 AND workflow_run_id=$7 AND step_run_id=$8
		FOR UPDATE`, admission.PreparedSetID, admission.ManifestID, admission.ProviderAttemptID, admission.ActionRequestID, admission.StepAttempt, programID, step.WorkflowRunID, step.ID).Scan(&capacity); err != nil {
		return err
	}
	if capacity != admission.ReservedCapacityBytes {
		return fmt.Errorf("prepared nonadmission capacity contradiction")
	}
	var publications int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM artifact_publications WHERE provider_attempt_id=$1`, admission.ProviderAttemptID).Scan(&publications); err != nil {
		return err
	}
	if publications != 0 {
		return fmt.Errorf("nonadmission cannot abandon a published result")
	}
	eventType, safeMessage, err := providerTerminalEvent(capability.ProviderInvocationOutcome(compiled.Envelope.ProviderOutcome))
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,scheduled_execution_id,scheduler_attempt,provider_attempt_id,capability,provider,safe_message,details)
		SELECT $1,$2,'provider',a.actor,a.task_id,a.program_id,a.workflow_run_id,a.step_run_id,a.scheduled_execution_id,a.scheduler_attempt,a.id,a.capability,a.provider,$3,$4
		FROM audit_events a WHERE a.id=$5 AND a.event_type='provider_invocation_started'`, admission.ProviderTerminalEventID, eventType, safeMessage, details, admission.ProviderAttemptID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("nonadmission terminal identity missing")
	}
	tag, err = tx.Exec(ctx, `UPDATE prepared_evidence_sets SET lifecycle_state='RESOLVED_ABANDONED',result_occurrence_id=$2,provider_terminal_event_id=$3,nonadmission_details=$4,resolved_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND lifecycle_state='ALLOCATED'`, admission.PreparedSetID, compiled.ResultOccurrenceID, admission.ProviderTerminalEventID, details)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("nonadmission resolution was not exact")
	}
	tag, err = tx.Exec(ctx, `UPDATE step_runs SET status='failed',output=NULL,error_classification='result_contract_limit',error_details='prepared evidence exceeded its authorized reservation',completed_at=clock_timestamp() WHERE id=$1 AND workflow_run_id=$2 AND attempt_count=$3 AND status=$4`, step.ID, step.WorkflowRunID, admission.StepAttempt, lineage.stepStatus)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("nonadmission step changed")
	}
	if err := tx.Commit(ctx); err != nil {
		var exact bool
		reconcileErr := s.Pool.QueryRow(context.WithoutCancel(ctx), `SELECT EXISTS(SELECT 1 FROM prepared_evidence_sets p
			JOIN audit_events a ON a.id=p.provider_terminal_event_id AND a.provider_attempt_id=p.provider_attempt_id
			WHERE p.id=$1 AND p.manifest_id=$2 AND p.provider_attempt_id=$3 AND p.result_occurrence_id=$4 AND p.provider_terminal_event_id=$5
			AND p.nonadmission_details=$6::jsonb AND p.lifecycle_state IN ('RESOLVED_ABANDONED','CLEANED'))`, admission.PreparedSetID, admission.ManifestID, admission.ProviderAttemptID, compiled.ResultOccurrenceID, admission.ProviderTerminalEventID, details).Scan(&exact)
		if reconcileErr == nil && exact {
			return nil
		}
		return &ResultCommitUnknownError{Operation: "prepared nonadmission", Err: errors.Join(err, reconcileErr)}
	}
	return nil
}
