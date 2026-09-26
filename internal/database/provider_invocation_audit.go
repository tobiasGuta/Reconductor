package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

// RecordProviderInvocationStarted durably admits one request across the
// registered provider boundary. The returned audit event ID is the provider
// attempt identity; it does not assert that an external process was created.
func (s *Store) RecordProviderInvocationStarted(ctx context.Context, record capability.ProviderInvocationStartRecord) (domain.ID, error) {
	if record.ActionRequestID == "" || record.ExecutionAuthorizationEventID == "" {
		return "", fmt.Errorf("provider invocation start requires action and execution authorization identities")
	}
	eventID := domain.NewID()
	tag, err := insertProviderInvocationStarted(ctx, s.Pool, eventID, record)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", fmt.Errorf("execution authorization event is not an exact execution-phase allow for action %s", record.ActionRequestID)
	}
	return eventID, nil
}

type providerInvocationStartExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func insertProviderInvocationStarted(ctx context.Context, executor providerInvocationStartExecutor, eventID domain.ID, record capability.ProviderInvocationStartRecord) (pgconn.CommandTag, error) {
	if _, recovering := domain.PreparedRecoveryRequestFromContext(ctx); recovering {
		return pgconn.CommandTag{}, fmt.Errorf("recovery admission cannot authorize provider execution")
	}
	scheduledExecutionID, schedulerAttempt := providerSchedulerProvenance(ctx)
	return executor.Exec(ctx, `INSERT INTO audit_events(
		id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,
		execution_authorization_event_id,provider_attempt_id,capability,provider,safe_message,details)
		SELECT $1,'provider_invocation_started','provider',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULL,$13,$14,
			'provider invocation admitted across registered execution boundary','{}'::jsonb
		FROM audit_events auth_event
		WHERE auth_event.id=$12
		  AND auth_event.event_type='policy_allowed'
		  AND auth_event.details->>'phase'='execution'
		  AND auth_event.task_id IS NOT DISTINCT FROM $3
		  AND auth_event.program_id IS NOT DISTINCT FROM $4
		  AND auth_event.workflow_run_id IS NOT DISTINCT FROM $5
		  AND auth_event.step_run_id IS NOT DISTINCT FROM $6
		  AND auth_event.scheduled_execution_id IS NOT DISTINCT FROM $7
		  AND auth_event.scheduler_attempt IS NOT DISTINCT FROM $8
		  AND auth_event.action_request_id IS NOT DISTINCT FROM $9
		  AND auth_event.step_attempt IS NOT DISTINCT FROM $10
		  AND auth_event.queue_job_id IS NOT DISTINCT FROM $11
		  AND auth_event.capability IS NOT DISTINCT FROM $13
		  AND auth_event.provider IS NOT DISTINCT FROM $14`,
		eventID, providerInvocationActor(record.Actor), optionalID(record.TaskID), optionalID(record.ProgramID),
		optionalID(record.WorkflowRunID), optionalID(record.StepRunID), scheduledExecutionID, schedulerAttempt,
		record.ActionRequestID, exactPositiveInt(record.StepAttempt), optionalIDPointer(record.QueueJobID),
		record.ExecutionAuthorizationEventID, nullIfEmpty(record.Capability), nullIfEmpty(record.Provider))
}

func lockAndValidateProviderResult(ctx context.Context, tx pgx.Tx, lineage lockedResultLineage, programID domain.ID, step domain.StepRun, tool *domain.ToolRun, result domain.ActionResult, admission *capability.ResultAdmissionProvenance) error {
	if admission == nil {
		if tool != nil && tool.ProviderAttemptID != nil {
			return resultConflict(lineage.scheduled, resultFenceProviderProvenanceMismatch, "tool provider attempt has no trusted admission provenance")
		}
		return nil
	}
	if admission.ProviderAttemptID == "" || admission.ActionRequestID == "" || admission.ExecutionAuthorizationEventID == "" || admission.Provider == "" {
		return resultConflict(lineage.scheduled, resultFenceProviderProvenanceMismatch, "trusted provider admission provenance is incomplete")
	}
	if tool == nil || tool.ProviderAttemptID == nil || *tool.ProviderAttemptID == "" || *tool.ProviderAttemptID != admission.ProviderAttemptID {
		return resultConflict(lineage.scheduled, resultFenceProviderProvenanceMismatch, "tool provider attempt does not match trusted admission provenance")
	}
	if result.RequestID != admission.ActionRequestID {
		return resultConflict(lineage.scheduled, resultFenceProviderProvenanceMismatch, "result action request does not match trusted admission provenance")
	}
	if tool.Provider != admission.Provider {
		return resultConflict(lineage.scheduled, resultFenceProviderProvenanceMismatch, "tool provider does not match trusted admission provenance")
	}
	scheduledExecutionID, schedulerAttempt := providerSchedulerProvenance(ctx)
	var providerAttemptID domain.ID
	if lineage.recovery {
		scheduledExecutionID = optionalIDPointer(lineage.scheduledID)
		schedulerAttempt = lineage.schedulerAttempt
	}
	err := tx.QueryRow(ctx, `SELECT id FROM audit_events
		WHERE id=$1
		  AND event_type='provider_invocation_started'
		  AND program_id IS NOT DISTINCT FROM $2
		  AND task_id IS NOT DISTINCT FROM $3
		  AND workflow_run_id IS NOT DISTINCT FROM $4
		  AND step_run_id IS NOT DISTINCT FROM $5
		  AND action_request_id IS NOT DISTINCT FROM $6
		  AND step_attempt IS NOT DISTINCT FROM $7
		  AND queue_job_id IS NOT DISTINCT FROM $8
		  AND execution_authorization_event_id IS NOT DISTINCT FROM $9
		  AND capability IS NOT DISTINCT FROM $10
		  AND provider IS NOT DISTINCT FROM $11
		  AND scheduled_execution_id IS NOT DISTINCT FROM $12
		  AND scheduler_attempt IS NOT DISTINCT FROM $13
		FOR UPDATE`, admission.ProviderAttemptID, optionalID(programID), optionalID(lineage.taskID), optionalID(step.WorkflowRunID), optionalID(step.ID), optionalID(admission.ActionRequestID), exactPositiveInt(admission.StepAttempt), optionalIDPointer(admission.QueueJobID), optionalID(admission.ExecutionAuthorizationEventID), nullIfEmpty(step.Capability), nullIfEmpty(admission.Provider), scheduledExecutionID, schedulerAttempt).Scan(&providerAttemptID)
	if errors.Is(err, pgx.ErrNoRows) {
		return resultConflict(lineage.scheduled, resultFenceProviderProvenanceMismatch, "provider attempt does not exactly match trusted admission provenance")
	}
	return err
}

func persistProviderResultAccepted(ctx context.Context, tx pgx.Tx, providerAttemptID, toolRunID domain.ID) (domain.ID, error) {
	return persistProviderResultAcceptedWithID(ctx, tx, domain.NewID(), providerAttemptID, toolRunID)
}

func persistProviderResultAcceptedWithID(ctx context.Context, tx pgx.Tx, eventID, providerAttemptID, toolRunID domain.ID) (domain.ID, error) {
	tag, err := tx.Exec(ctx, `INSERT INTO audit_events(
		id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,tool_run_id,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,
		execution_authorization_event_id,provider_attempt_id,capability,provider,safe_message,details)
		SELECT $1,'provider_result_accepted','result_fence',provider_start.actor,provider_start.task_id,
			provider_start.program_id,provider_start.workflow_run_id,provider_start.step_run_id,tool.id,
			provider_start.scheduled_execution_id,provider_start.scheduler_attempt,provider_start.action_request_id,
			provider_start.step_attempt,provider_start.queue_job_id,provider_start.execution_authorization_event_id,
			provider_start.id,provider_start.capability,provider_start.provider,
			'provider result accepted by persistence fence','{}'::jsonb
		FROM audit_events provider_start
		JOIN tool_runs tool
		  ON tool.id=$2
		 AND tool.provider_attempt_id=provider_start.id
		 AND tool.step_run_id=provider_start.step_run_id
		WHERE provider_start.id=$3
		  AND provider_start.event_type='provider_invocation_started'
		  AND NOT EXISTS (
			SELECT 1 FROM audit_events existing
			WHERE existing.event_type='provider_result_accepted'
			  AND existing.provider_attempt_id=provider_start.id
		  )`, eventID, toolRunID, providerAttemptID)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", fmt.Errorf("provider attempt %s cannot record one accepted result decision", providerAttemptID)
	}
	return eventID, nil
}

func completeResultAdmission(admission *capability.ResultAdmissionProvenance) bool {
	return admission != nil && admission.ProviderAttemptID != "" && admission.ActionRequestID != "" && admission.ExecutionAuthorizationEventID != "" && admission.Provider != ""
}

func (s *Store) recordProviderResultRejected(ctx context.Context, admission *capability.ResultAdmissionProvenance, reason resultFenceReasonCode) (bool, error) {
	if !completeResultAdmission(admission) {
		return false, nil
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	var providerAttemptID domain.ID
	err = tx.QueryRow(ctx, `SELECT id FROM audit_events
		WHERE id=$1
		  AND event_type='provider_invocation_started'
		  AND action_request_id IS NOT DISTINCT FROM $2
		  AND step_attempt IS NOT DISTINCT FROM $3
		  AND queue_job_id IS NOT DISTINCT FROM $4
		  AND execution_authorization_event_id IS NOT DISTINCT FROM $5
		  AND provider IS NOT DISTINCT FROM $6
		FOR UPDATE`, admission.ProviderAttemptID, optionalID(admission.ActionRequestID), exactPositiveInt(admission.StepAttempt), optionalIDPointer(admission.QueueJobID), optionalID(admission.ExecutionAuthorizationEventID), nullIfEmpty(admission.Provider)).Scan(&providerAttemptID)
	if errors.Is(err, pgx.ErrNoRows) {
		if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
			return false, rollbackErr
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}

	_, err = tx.Exec(ctx, `INSERT INTO audit_events(
		id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,tool_run_id,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,
		execution_authorization_event_id,provider_attempt_id,capability,provider,safe_message,details)
		SELECT $1,'provider_result_rejected','result_fence',provider_start.actor,provider_start.task_id,
			provider_start.program_id,provider_start.workflow_run_id,provider_start.step_run_id,tool.id,
			provider_start.scheduled_execution_id,provider_start.scheduler_attempt,provider_start.action_request_id,
			provider_start.step_attempt,provider_start.queue_job_id,provider_start.execution_authorization_event_id,
			provider_start.id,provider_start.capability,provider_start.provider,
			'provider result rejected by persistence fence',$2
		FROM audit_events provider_start
		LEFT JOIN tool_runs tool
		  ON tool.provider_attempt_id=provider_start.id
		 AND tool.step_run_id=provider_start.step_run_id
		WHERE provider_start.id=$3
		  AND provider_start.event_type='provider_invocation_started'
		  AND NOT EXISTS (
			SELECT 1 FROM audit_events existing
			WHERE existing.event_type='provider_result_rejected'
			  AND existing.provider_attempt_id=provider_start.id
			  AND existing.details->>'reason_code'=$4
		  )`, domain.NewID(), mustJSON(map[string]string{"reason_code": string(reason)}), providerAttemptID, string(reason))
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) RecordProviderInvocationTerminal(ctx context.Context, record capability.ProviderInvocationTerminalRecord) error {
	if record.ProviderAttemptID == "" {
		return fmt.Errorf("provider invocation terminal requires provider attempt identity")
	}
	eventType, safeMessage, err := providerTerminalEvent(record.Outcome)
	if err != nil {
		return err
	}
	scheduledExecutionID, schedulerAttempt := providerSchedulerProvenance(ctx)
	writeCtx, cancel := providerTerminalContext(ctx)
	defer cancel()
	tag, err := s.Pool.Exec(writeCtx, `INSERT INTO audit_events(
		id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,
		scheduled_execution_id,scheduler_attempt,provider_attempt_id,capability,provider,safe_message,details)
		SELECT $1,$2,'provider',provider_start.actor,provider_start.task_id,provider_start.program_id,
			provider_start.workflow_run_id,provider_start.step_run_id,provider_start.scheduled_execution_id,
			provider_start.scheduler_attempt,provider_start.id,provider_start.capability,provider_start.provider,$3,'{}'::jsonb
		FROM audit_events provider_start
		WHERE provider_start.id=$4
		  AND provider_start.event_type='provider_invocation_started'
		  AND provider_start.actor=$5
		  AND provider_start.task_id IS NOT DISTINCT FROM $6
		  AND provider_start.program_id IS NOT DISTINCT FROM $7
		  AND provider_start.workflow_run_id IS NOT DISTINCT FROM $8
		  AND provider_start.step_run_id IS NOT DISTINCT FROM $9
		  AND provider_start.scheduled_execution_id IS NOT DISTINCT FROM $10
		  AND provider_start.scheduler_attempt IS NOT DISTINCT FROM $11
		  AND provider_start.capability IS NOT DISTINCT FROM $12
		  AND provider_start.provider IS NOT DISTINCT FROM $13`,
		domain.NewID(), eventType, safeMessage, record.ProviderAttemptID, providerInvocationActor(record.Actor),
		optionalID(record.TaskID), optionalID(record.ProgramID), optionalID(record.WorkflowRunID),
		optionalID(record.StepRunID), scheduledExecutionID, schedulerAttempt,
		nullIfEmpty(record.Capability), nullIfEmpty(record.Provider))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("provider attempt %s is not an exact matching provider start event", record.ProviderAttemptID)
	}
	return nil
}

func providerTerminalEvent(outcome capability.ProviderInvocationOutcome) (string, string, error) {
	switch outcome {
	case capability.ProviderInvocationSucceeded:
		return "provider_invocation_succeeded", "registered provider invocation returned successfully", nil
	case capability.ProviderInvocationFailed:
		return "provider_invocation_failed", "registered provider invocation returned a failure", nil
	case capability.ProviderInvocationCancelled:
		return "provider_invocation_cancelled", "registered provider invocation returned after cancellation", nil
	case capability.ProviderInvocationTimedOut:
		return "provider_invocation_timed_out", "registered provider invocation timed out", nil
	default:
		return "", "", fmt.Errorf("unsupported provider invocation outcome %q", outcome)
	}
}

func providerInvocationActor(actor string) string {
	if actor = strings.TrimSpace(actor); actor != "" {
		return actor
	}
	return "execution"
}

func providerSchedulerProvenance(ctx context.Context) (any, any) {
	fence, ok := scheduledExecutionFenceFromContext(ctx)
	if !ok || fence.ExecutionID == "" || fence.Attempt <= 0 {
		return nil, nil
	}
	return fence.ExecutionID, fence.Attempt
}

func providerTerminalContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx.Err() == nil {
		return ctx, func() {}
	}
	return context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
}
