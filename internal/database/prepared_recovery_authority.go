package database

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func hasUnresolvedScheduledPrepared(ctx context.Context, tx pgx.Tx, executionID domain.ID, attempt int) (bool, error) {
	var pending bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM prepared_evidence_sets p JOIN step_runs s ON s.id=p.step_run_id JOIN audit_events provider ON provider.id=p.provider_attempt_id
		WHERE provider.scheduled_execution_id=$1 AND provider.scheduler_attempt=$2 AND p.step_attempt=s.attempt_count AND p.lifecycle_state IN ('ALLOCATED','SEALED','QUARANTINED'))`, executionID, attempt).Scan(&pending)
	return pending, err
}

// validateLockedPreparedRecovery uses existing durable facts, not the store X
// lock or expired credentials, as the admission proof. Caller holds scheduler,
// workflow and step lineage locks. The prepared/provider/auth rows are locked
// last, with the same order as reservation and adoption.
func validateLockedPreparedRecovery(ctx context.Context, tx pgx.Tx, lineage lockedResultLineage, programID domain.ID, step domain.StepRun, request domain.PreparedRecoveryRequest) error {
	if request.StepAttempt < 1 || request.StepAttempt != lineage.attemptCount || (lineage.stepStatus != domain.StepRunning && lineage.stepStatus != domain.StepRetryable) {
		return fmt.Errorf("recovery attempt is not current and admitting")
	}
	var exact domain.ID
	err := tx.QueryRow(ctx, `SELECT p.id FROM prepared_evidence_sets p
		JOIN audit_events provider ON provider.id=p.provider_attempt_id AND provider.event_type='provider_invocation_started'
		JOIN audit_events auth ON auth.id=provider.execution_authorization_event_id AND auth.event_type='policy_allowed' AND auth.details->>'phase'='execution'
		WHERE p.id=$1 AND p.manifest_id=$2 AND p.provider_attempt_id=$3 AND p.action_request_id=$4 AND p.step_attempt=$5
		AND p.program_id=$6 AND p.task_id=$7 AND p.workflow_run_id=$8 AND p.step_run_id=$9
		AND ((p.lifecycle_state='ALLOCATED' AND p.result_occurrence_id IS NULL AND p.provider_terminal_event_id IS NULL)
		 OR (p.lifecycle_state='SEALED' AND p.result_occurrence_id=$10 AND p.provider_terminal_event_id=$11 AND p.manifest_sha256=$12))
		AND provider.program_id=p.program_id AND provider.task_id=p.task_id AND provider.workflow_run_id=p.workflow_run_id AND provider.step_run_id=p.step_run_id
		AND provider.action_request_id=p.action_request_id AND provider.step_attempt=p.step_attempt AND provider.capability=$13
		AND provider.scheduled_execution_id IS NOT DISTINCT FROM $14 AND provider.scheduler_attempt IS NOT DISTINCT FROM $15
		AND auth.program_id=provider.program_id AND auth.task_id=provider.task_id AND auth.workflow_run_id=provider.workflow_run_id AND auth.step_run_id=provider.step_run_id
		AND auth.action_request_id=provider.action_request_id AND auth.step_attempt=provider.step_attempt
		AND auth.scheduled_execution_id IS NOT DISTINCT FROM provider.scheduled_execution_id AND auth.scheduler_attempt IS NOT DISTINCT FROM provider.scheduler_attempt
		AND auth.queue_job_id IS NOT DISTINCT FROM provider.queue_job_id AND auth.provider=provider.provider AND auth.capability=provider.capability
		AND NOT EXISTS(SELECT 1 FROM audit_events accepted WHERE accepted.event_type='provider_result_accepted' AND accepted.step_run_id=p.step_run_id AND (accepted.step_attempt IS NULL OR accepted.step_attempt>=p.step_attempt))
		FOR UPDATE OF p,provider,auth`, request.SetID, request.ManifestID, request.ProviderAttemptID, request.ActionRequestID, request.StepAttempt, programID, lineage.taskID, step.WorkflowRunID, step.ID, request.ResultOccurrenceID, request.TerminalEventID, request.ManifestSHA256, step.Capability, optionalIDPointer(lineage.scheduledID), lineage.schedulerAttempt).Scan(&exact)
	if err != nil {
		return &domain.UnresolvedPersistenceError{Err: fmt.Errorf("durable recovery admission not proven: %w", err)}
	}
	return nil
}
