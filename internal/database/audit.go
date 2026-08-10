package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type schedulerAuditClassification uint8

const (
	schedulerAuditExecutionBoundNonAttempt schedulerAuditClassification = iota + 1
	schedulerAuditAttemptBound
	schedulerAuditRecoveryAttemptBound
)

type schedulerAuditRecord struct {
	classification       schedulerAuditClassification
	eventType            string
	actor                string
	programID            domain.ID
	scheduledExecutionID domain.ID
	schedulerAttempt     *int
	scopeVersionID       *domain.ID
	taskID               *domain.ID
	workflowRunID        *domain.ID
	stepRunID            *domain.ID
	toolRunID            *domain.ID
	capability           string
	provider             string
	safeMessage          string
	details              any
}

type schedulerAuditProvenance struct {
	classification       schedulerAuditClassification
	scheduledExecutionID domain.ID
	schedulerAttempt     *int
	scopeVersionID       *domain.ID
}

// scheduler_attempt is the scheduler execution attempt that this historical
// event describes. It is not a workflow-step, provider, Redis-delivery, or
// generic retry attempt. Attempt-bound callers must pass the exact attempt they
// already claimed, fenced, or locked for recovery; this writer never derives it
// from mutable current state.
func writeSchedulerAudit(ctx context.Context, tx pgx.Tx, record schedulerAuditRecord) error {
	if record.scheduledExecutionID == "" {
		return fmt.Errorf("scheduler audit %q requires scheduled execution id", record.eventType)
	}
	switch record.classification {
	case schedulerAuditExecutionBoundNonAttempt:
		if record.schedulerAttempt != nil {
			return fmt.Errorf("scheduler audit %q cannot attach an attempt to a non-attempt event", record.eventType)
		}
	case schedulerAuditAttemptBound, schedulerAuditRecoveryAttemptBound:
		if record.schedulerAttempt == nil || *record.schedulerAttempt <= 0 {
			return fmt.Errorf("scheduler audit %q requires a positive exact scheduler attempt", record.eventType)
		}
	default:
		return fmt.Errorf("scheduler audit %q has invalid classification", record.eventType)
	}
	if record.details == nil {
		record.details = map[string]any{}
	}
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(
		id,event_type,component,actor,program_id,scheduled_execution_id,scheduler_attempt,scope_version_id,
		task_id,workflow_run_id,step_run_id,tool_run_id,capability,provider,safe_message,details)
		VALUES($1,$2,'scheduler',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		domain.NewID(), record.eventType, record.actor, record.programID,
		record.scheduledExecutionID, record.schedulerAttempt, record.scopeVersionID,
		record.taskID, record.workflowRunID, record.stepRunID, record.toolRunID,
		nullIfEmpty(record.capability), nullIfEmpty(record.provider), record.safeMessage, mustJSON(record.details))
	return err
}

func auditScheduledExecution(ctx context.Context, tx pgx.Tx, classification schedulerAuditClassification, event, actor string, programID domain.ID, item domain.ScheduledExecution, schedulerAttempt *int, scopeVersionID *domain.ID, message string, details any) error {
	if details == nil {
		details = map[string]any{"scheduled_execution_id": item.ID, "schedule_id": item.ScheduleID, "status": item.Status, "trigger_source": item.TriggerSource}
	}
	return writeSchedulerAudit(ctx, tx, schedulerAuditRecord{
		classification:       classification,
		eventType:            event,
		actor:                actor,
		programID:            programID,
		scheduledExecutionID: item.ID,
		schedulerAttempt:     schedulerAttempt,
		scopeVersionID:       scopeVersionID,
		taskID:               item.TaskID,
		workflowRunID:        item.WorkflowRunID,
		safeMessage:          message,
		details:              details,
	})
}

func exactSchedulerAttempt(attempt int) *int {
	return &attempt
}

func recoverySchedulerAuditProvenance(item domain.ScheduledExecution) schedulerAuditProvenance {
	provenance := schedulerAuditProvenance{
		classification:       schedulerAuditRecoveryAttemptBound,
		scheduledExecutionID: item.ID,
		schedulerAttempt:     exactSchedulerAttempt(item.AttemptCount),
	}
	// A running row received its scope version while the same exact attempt was
	// fenced into running. A merely claimed row may retain a prior attempt's
	// mutable scope value after resume, so recovery must not copy it.
	if item.Status == domain.ScheduledExecutionRunning {
		provenance.scopeVersionID = item.ScopeVersionID
	}
	// Pre-protocol legacy rows can be active with attempt_count=0. Preserve their
	// recovery behavior without fabricating attempt 1 or violating the positive
	// scheduler_attempt contract.
	if item.AttemptCount <= 0 {
		provenance.classification = schedulerAuditExecutionBoundNonAttempt
		provenance.schedulerAttempt = nil
		provenance.scopeVersionID = nil
	}
	return provenance
}
