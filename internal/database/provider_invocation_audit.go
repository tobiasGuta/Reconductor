package database

import (
	"context"
	"fmt"
	"strings"
	"time"

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
	scheduledExecutionID, schedulerAttempt := providerSchedulerProvenance(ctx)
	tag, err := s.Pool.Exec(ctx, `INSERT INTO audit_events(
		id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,
		execution_authorization_event_id,provider_attempt_id,capability,provider,safe_message,details)
		SELECT $1,'provider_invocation_started','provider',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULL,$13,$14,
			'provider invocation admitted across registered execution boundary','{}'::jsonb
		FROM audit_events auth_event
		WHERE auth_event.id=$12
		  AND auth_event.event_type='policy_allowed'
		  AND auth_event.details->>'phase'='execution'
		  AND auth_event.action_request_id=$9`,
		eventID, providerInvocationActor(record.Actor), optionalID(record.TaskID), optionalID(record.ProgramID),
		optionalID(record.WorkflowRunID), optionalID(record.StepRunID), scheduledExecutionID, schedulerAttempt,
		record.ActionRequestID, exactPositiveInt(record.StepAttempt), optionalIDPointer(record.QueueJobID),
		record.ExecutionAuthorizationEventID, nullIfEmpty(record.Capability), nullIfEmpty(record.Provider))
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", fmt.Errorf("execution authorization event is not an exact execution-phase allow for action %s", record.ActionRequestID)
	}
	return eventID, nil
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
