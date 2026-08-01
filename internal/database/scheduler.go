package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

var (
	ErrScheduleOverlap  = errors.New("schedule already has a queued or active execution")
	ErrApprovalRejected = errors.New("scheduled execution was closed because approval was rejected")
)

const staleReconciliationBatchLimit = 32

func (s *Store) CreateSchedule(ctx context.Context, item domain.Schedule) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO schedules(id,program_id,name,workflow_name,objective,cron_expression,timezone,enabled,headless,created_by,next_run_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, item.ID, item.ProgramID, item.Name, item.WorkflowName, item.Objective, item.CronExpression, item.Timezone, item.Enabled, item.Headless, item.CreatedBy, item.NextRunAt, item.CreatedAt, item.UpdatedAt)
	if err != nil {
		return err
	}
	if err := auditSchedule(ctx, tx, "schedule_created", item.CreatedBy, item.ProgramID, item.ID, "schedule created", item); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) UpdateSchedule(ctx context.Context, item domain.Schedule, actor string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE schedules SET name=$2,workflow_name=$3,objective=$4,cron_expression=$5,timezone=$6,enabled=$7,headless=$8,next_run_at=$9,updated_at=now() WHERE id=$1`, item.ID, item.Name, item.WorkflowName, item.Objective, item.CronExpression, item.Timezone, item.Enabled, item.Headless, item.NextRunAt)
	if err == nil && tag.RowsAffected() == 0 {
		return fmt.Errorf("schedule %s not found", item.ID)
	}
	if err != nil {
		return err
	}
	if err := auditSchedule(ctx, tx, "schedule_updated", actor, item.ProgramID, item.ID, "schedule updated", item); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) GetSchedule(ctx context.Context, id domain.ID) (domain.Schedule, error) {
	var item domain.Schedule
	err := s.Pool.QueryRow(ctx, `SELECT id,program_id,name,workflow_name,objective,cron_expression,timezone,enabled,headless,created_by,last_run_at,next_run_at,created_at,updated_at FROM schedules WHERE id=$1`, id).Scan(&item.ID, &item.ProgramID, &item.Name, &item.WorkflowName, &item.Objective, &item.CronExpression, &item.Timezone, &item.Enabled, &item.Headless, &item.CreatedBy, &item.LastRunAt, &item.NextRunAt, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func (s *Store) ListSchedules(ctx context.Context, programID domain.ID) ([]domain.Schedule, error) {
	query := `SELECT id,program_id,name,workflow_name,objective,cron_expression,timezone,enabled,headless,created_by,last_run_at,next_run_at,created_at,updated_at FROM schedules`
	args := []any{}
	if programID != "" {
		query += ` WHERE program_id=$1`
		args = append(args, programID)
	}
	query += ` ORDER BY program_id,name`
	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Schedule
	for rows.Next() {
		var item domain.Schedule
		if err := rows.Scan(&item.ID, &item.ProgramID, &item.Name, &item.WorkflowName, &item.Objective, &item.CronExpression, &item.Timezone, &item.Enabled, &item.Headless, &item.CreatedBy, &item.LastRunAt, &item.NextRunAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) SetScheduleEnabled(ctx context.Context, id domain.ID, enabled bool, actor string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var programID domain.ID
	err = tx.QueryRow(ctx, `UPDATE schedules SET enabled=$2,updated_at=now() WHERE id=$1 RETURNING program_id`, id, enabled).Scan(&programID)
	if err != nil {
		return err
	}
	event := "schedule_disabled"
	message := "schedule disabled"
	if enabled {
		event = "schedule_enabled"
		message = "schedule enabled"
	}
	if err := auditSchedule(ctx, tx, event, actor, programID, id, message, map[string]any{"enabled": enabled}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) EnqueueRunNow(ctx context.Context, scheduleID domain.ID, actor string) (domain.ScheduledExecution, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return domain.ScheduledExecution{}, err
	}
	defer tx.Rollback(ctx)
	var programID domain.ID
	if err := tx.QueryRow(ctx, `SELECT program_id FROM schedules WHERE id=$1 FOR UPDATE`, scheduleID).Scan(&programID); err != nil {
		return domain.ScheduledExecution{}, err
	}
	var overlap bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM scheduled_executions
		WHERE schedule_id=$1
		  AND status IN ('pending','claimed','running','paused_for_approval','paused_operator')
	)`, scheduleID).Scan(&overlap); err != nil {
		return domain.ScheduledExecution{}, err
	}
	if overlap {
		return domain.ScheduledExecution{}, fmt.Errorf("%w: %s", ErrScheduleOverlap, scheduleID)
	}
	now := time.Now().UTC()
	item := domain.ScheduledExecution{ID: domain.NewID(), ScheduleID: scheduleID, PlannedAt: now, TriggerSource: domain.ScheduleTriggerRunNow, Status: domain.ScheduledExecutionPending, CreatedAt: now, UpdatedAt: now}
	if _, err := tx.Exec(ctx, `INSERT INTO scheduled_executions(id,schedule_id,planned_at,trigger_source,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, item.ID, item.ScheduleID, item.PlannedAt, item.TriggerSource, item.Status, item.CreatedAt, item.UpdatedAt); err != nil {
		return domain.ScheduledExecution{}, err
	}
	if err := auditExecution(ctx, tx, "scheduled_execution_planned", actor, programID, item, "run now execution queued", nil); err != nil {
		return domain.ScheduledExecution{}, err
	}
	return item, tx.Commit(ctx)
}

func (s *Store) MaterializeDueSchedule(ctx context.Context, scheduleID domain.ID, now, nextRunAt time.Time) ([]domain.ScheduledExecution, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id,program_id,next_run_at FROM schedules WHERE id=$2 AND enabled=true AND next_run_at<=$1 FOR UPDATE SKIP LOCKED`, now, scheduleID)
	if err != nil {
		return nil, err
	}
	type due struct {
		id        domain.ID
		programID domain.ID
		planned   time.Time
	}
	var dueItems []due
	for rows.Next() {
		var item due
		if err := rows.Scan(&item.id, &item.programID, &item.planned); err != nil {
			rows.Close()
			return nil, err
		}
		dueItems = append(dueItems, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := []domain.ScheduledExecution{}
	for _, due := range dueItems {
		var active bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM scheduled_executions WHERE schedule_id=$1 AND status IN ('pending','claimed','running','paused_for_approval','paused_operator'))`, due.id).Scan(&active); err != nil {
			return nil, err
		}
		status := domain.ScheduledExecutionPending
		eventType := "scheduled_execution_planned"
		message := "scheduled execution planned"
		if active {
			status = domain.ScheduledExecutionSkippedOverlap
			eventType = "scheduled_execution_skipped_overlap"
			message = "scheduled execution skipped because another execution is active"
		}
		item := domain.ScheduledExecution{ID: domain.NewID(), ScheduleID: due.id, PlannedAt: due.planned, TriggerSource: domain.ScheduleTriggerScheduled, Status: status, CreatedAt: now, UpdatedAt: now}
		_, err := tx.Exec(ctx, `INSERT INTO scheduled_executions(id,schedule_id,planned_at,trigger_source,status,error_classification,error_summary,completed_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`, item.ID, item.ScheduleID, item.PlannedAt, item.TriggerSource, item.Status, map[bool]string{true: "overlap", false: ""}[active], map[bool]string{true: "same schedule already has an active execution", false: ""}[active], map[bool]any{true: now, false: nil}[active], item.CreatedAt, item.UpdatedAt)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE schedules SET next_run_at=$2,updated_at=now() WHERE id=$1`, due.id, nextRunAt); err != nil {
			return nil, err
		}
		if err := auditExecution(ctx, tx, eventType, "scheduler", due.programID, item, message, nil); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, tx.Commit(ctx)
}

func (s *Store) ClaimPendingScheduledExecution(ctx context.Context, owner string, leaseTimeout time.Duration) (domain.ScheduledExecution, domain.Schedule, bool, error) {
	if err := s.reconcileStaleScheduledExecutions(ctx, staleReconciliationBatchLimit); err != nil {
		return domain.ScheduledExecution{}, domain.Schedule{}, false, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return domain.ScheduledExecution{}, domain.Schedule{}, false, err
	}
	defer tx.Rollback(ctx)
	if err := skipOverlappingPendingExecutions(ctx, tx); err != nil {
		return domain.ScheduledExecution{}, domain.Schedule{}, false, err
	}
	var item domain.ScheduledExecution
	var sched domain.Schedule
	err = tx.QueryRow(ctx, `SELECT se.id,se.schedule_id,se.planned_at,se.trigger_source,se.status,se.task_id,se.workflow_run_id,se.scope_version_id,se.attempt_count,se.lease_owner,se.lease_expires_at,se.error_classification,se.error_summary,se.started_at,se.completed_at,se.created_at,se.updated_at,s.id,s.program_id,s.name,s.workflow_name,s.objective,s.cron_expression,s.timezone,s.enabled,s.headless,s.created_by,s.last_run_at,s.next_run_at,s.created_at,s.updated_at
		FROM scheduled_executions se
		JOIN schedules s ON s.id=se.schedule_id
		WHERE se.status='pending'
		  AND NOT EXISTS (
			SELECT 1 FROM scheduled_executions active
			WHERE active.schedule_id=se.schedule_id
			  AND active.id<>se.id
			  AND active.status IN ('claimed','running','paused_for_approval','paused_operator')
		  )
		ORDER BY se.planned_at,se.created_at
		LIMIT 1
		FOR UPDATE OF se,s SKIP LOCKED`).Scan(&item.ID, &item.ScheduleID, &item.PlannedAt, &item.TriggerSource, &item.Status, &item.TaskID, &item.WorkflowRunID, &item.ScopeVersionID, &item.AttemptCount, &item.LeaseOwner, &item.LeaseExpiresAt, &item.ErrorClassification, &item.ErrorSummary, &item.StartedAt, &item.CompletedAt, &item.CreatedAt, &item.UpdatedAt, &sched.ID, &sched.ProgramID, &sched.Name, &sched.WorkflowName, &sched.Objective, &sched.CronExpression, &sched.Timezone, &sched.Enabled, &sched.Headless, &sched.CreatedBy, &sched.LastRunAt, &sched.NextRunAt, &sched.CreatedAt, &sched.UpdatedAt)
	if err == pgx.ErrNoRows {
		return domain.ScheduledExecution{}, domain.Schedule{}, false, tx.Commit(ctx)
	}
	if err != nil {
		return domain.ScheduledExecution{}, domain.Schedule{}, false, err
	}
	err = tx.QueryRow(ctx, `UPDATE scheduled_executions
		SET status='claimed',
		    attempt_count=attempt_count+1,
		    recovery_protocol_version=1,
		    lease_owner=$2,
		    lease_expires_at=clock_timestamp()+($3::double precision * interval '1 second'),
		    updated_at=now()
		WHERE id=$1
		RETURNING status,attempt_count,lease_owner,lease_expires_at,updated_at`, item.ID, owner, leaseTimeout.Seconds()).Scan(&item.Status, &item.AttemptCount, &item.LeaseOwner, &item.LeaseExpiresAt, &item.UpdatedAt)
	if err != nil {
		return domain.ScheduledExecution{}, domain.Schedule{}, false, err
	}
	if err := auditExecution(ctx, tx, "scheduled_execution_claimed", owner, sched.ProgramID, item, "scheduled execution claimed", nil); err != nil {
		return domain.ScheduledExecution{}, domain.Schedule{}, false, err
	}
	return item, sched, true, tx.Commit(ctx)
}

func (s *Store) HeartbeatScheduledExecution(ctx context.Context, id domain.ID, owner string, attempt int, leaseTimeout time.Duration) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	item, _, err := lockedScheduledExecution(ctx, tx, id)
	if err != nil {
		return err
	}
	validLease, err := lockedSchedulerLeaseValid(ctx, tx, item.ID, owner, attempt)
	if err != nil {
		return err
	}
	if !containsExecutionStatus([]domain.ScheduledExecutionStatus{domain.ScheduledExecutionClaimed, domain.ScheduledExecutionRunning}, item.Status) || !validLease {
		return fmt.Errorf("scheduled execution %s cannot be heartbeated", id)
	}
	tag, err := tx.Exec(ctx, `UPDATE scheduled_executions
		SET lease_expires_at=clock_timestamp()+($4::double precision * interval '1 second'),updated_at=now()
		WHERE id=$1
		  AND lease_owner=$2
		  AND attempt_count=$3
		  AND status IN ('claimed','running')
		  AND lease_expires_at>clock_timestamp()`, id, owner, attempt, leaseTimeout.Seconds())
	if err == nil && tag.RowsAffected() != 1 {
		return fmt.Errorf("scheduled execution %s cannot be heartbeated", id)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) MarkScheduledExecutionRunning(ctx context.Context, id, taskID, workflowRunID domain.ID, scopeVersionID *domain.ID, owner string, attempt int) error {
	if tx, ok := transactionFromContext(ctx); ok {
		return markScheduledExecutionRunning(ctx, tx, id, taskID, workflowRunID, scopeVersionID, owner, attempt)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := markScheduledExecutionRunning(ctx, tx, id, taskID, workflowRunID, scopeVersionID, owner, attempt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) MarkScheduledExecutionPaused(ctx context.Context, id domain.ID, owner string, attempt int) error {
	return s.markScheduledExecution(ctx, id, domain.ScheduledExecutionPausedOperator, owner, attempt, "", "", []domain.ScheduledExecutionStatus{domain.ScheduledExecutionRunning}, "scheduled_execution_paused", "scheduled execution paused by operator")
}

func (s *Store) MarkScheduledExecutionPausedForApproval(ctx context.Context, id domain.ID, owner string, attempt int) error {
	err := s.markScheduledExecution(ctx, id, domain.ScheduledExecutionPausedForApproval, owner, attempt, "", "", []domain.ScheduledExecutionStatus{domain.ScheduledExecutionRunning}, "scheduled_execution_paused_for_approval", "scheduled execution paused for approval")
	if err == nil {
		return nil
	}
	var status domain.ScheduledExecutionStatus
	if queryErr := s.Pool.QueryRow(ctx, `SELECT status FROM scheduled_executions WHERE id=$1`, id).Scan(&status); queryErr == nil && status == domain.ScheduledExecutionApprovalRejected {
		return nil
	}
	return err
}

func (s *Store) MarkScheduledExecutionCompleted(ctx context.Context, id domain.ID, owner string, attempt int) error {
	return s.markScheduledExecution(ctx, id, domain.ScheduledExecutionCompleted, owner, attempt, "", "", []domain.ScheduledExecutionStatus{domain.ScheduledExecutionRunning}, "scheduled_execution_completed", "scheduled execution completed")
}

func (s *Store) MarkScheduledExecutionFailed(ctx context.Context, id domain.ID, owner string, attempt int, class, summary string) error {
	return s.markScheduledExecution(ctx, id, domain.ScheduledExecutionFailed, owner, attempt, class, safeSummary(summary), []domain.ScheduledExecutionStatus{domain.ScheduledExecutionClaimed, domain.ScheduledExecutionRunning}, "scheduled_execution_failed", "scheduled execution failed")
}

func (s *Store) MarkScheduledExecutionCancelled(ctx context.Context, id domain.ID, owner string, attempt int) error {
	return s.markScheduledExecution(ctx, id, domain.ScheduledExecutionCancelled, owner, attempt, "cancelled", "workflow execution was cancelled", []domain.ScheduledExecutionStatus{domain.ScheduledExecutionClaimed, domain.ScheduledExecutionRunning}, "scheduled_execution_cancelled", "scheduled execution cancelled")
}

func (s *Store) MarkScheduledExecutionBlocked(ctx context.Context, id domain.ID, scopeVersionID domain.ID, owner string, attempt int) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	item, programID, err := lockedScheduledExecution(ctx, tx, id)
	if err != nil {
		return err
	}
	validLease, err := lockedSchedulerLeaseValid(ctx, tx, item.ID, owner, attempt)
	if err != nil {
		return err
	}
	if item.Status != domain.ScheduledExecutionClaimed || !validLease {
		return invalidScheduledExecutionTransition(item, domain.ScheduledExecutionBlockedScopeChange)
	}
	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `UPDATE scheduled_executions SET status='blocked_scope_change',scope_version_id=$2,error_classification='scope_change',error_summary='unacknowledged scope expansion blocked scheduled execution',completed_at=$3,lease_owner='',lease_expires_at=NULL,updated_at=$3 WHERE id=$1 AND status='claimed' AND lease_owner=$4 AND attempt_count=$5 AND lease_expires_at>clock_timestamp()`, id, scopeVersionID, now, owner, attempt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return invalidScheduledExecutionTransition(item, domain.ScheduledExecutionBlockedScopeChange)
	}
	item.Status, item.ScopeVersionID, item.ErrorClassification, item.ErrorSummary, item.CompletedAt, item.UpdatedAt = domain.ScheduledExecutionBlockedScopeChange, &scopeVersionID, "scope_change", "unacknowledged scope expansion blocked scheduled execution", &now, now
	item.LeaseOwner, item.LeaseExpiresAt = "", nil
	if err := auditExecution(ctx, tx, "scheduled_execution_blocked_scope_change", owner, programID, item, "scheduled execution blocked by scope expansion", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) markScheduledExecution(ctx context.Context, id domain.ID, status domain.ScheduledExecutionStatus, owner string, attempt int, class, summary string, allowed []domain.ScheduledExecutionStatus, event, message string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	item, programID, err := lockedScheduledExecution(ctx, tx, id)
	if err != nil {
		return err
	}
	validLease, err := lockedSchedulerLeaseValid(ctx, tx, item.ID, owner, attempt)
	if err != nil {
		return err
	}
	if !containsExecutionStatus(allowed, item.Status) || !validLease {
		return invalidScheduledExecutionTransition(item, status)
	}
	now := time.Now().UTC()
	completedAt := item.CompletedAt
	if containsExecutionStatus([]domain.ScheduledExecutionStatus{domain.ScheduledExecutionCompleted, domain.ScheduledExecutionFailed, domain.ScheduledExecutionCancelled, domain.ScheduledExecutionApprovalRejected, domain.ScheduledExecutionInterrupted}, status) {
		completedAt = &now
	}
	tag, err := tx.Exec(ctx, `UPDATE scheduled_executions SET status=$2,error_classification=$3,error_summary=$4,completed_at=$5,lease_owner='',lease_expires_at=NULL,updated_at=$6 WHERE id=$1 AND status=$7 AND lease_owner=$8 AND attempt_count=$9 AND lease_expires_at>clock_timestamp()`, id, status, class, summary, completedAt, now, item.Status, owner, attempt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return invalidScheduledExecutionTransition(item, status)
	}
	item.Status, item.ErrorClassification, item.ErrorSummary, item.CompletedAt, item.UpdatedAt = status, class, summary, completedAt, now
	item.LeaseOwner, item.LeaseExpiresAt = "", nil
	if err := auditExecution(ctx, tx, event, owner, programID, item, message, nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type executionScanner interface {
	Scan(...any) error
}

func scanScheduledExecution(scanner executionScanner) (domain.ScheduledExecution, domain.ID, error) {
	var item domain.ScheduledExecution
	var programID domain.ID
	err := scanner.Scan(
		&item.ID, &item.ScheduleID, &item.PlannedAt, &item.TriggerSource, &item.Status,
		&item.TaskID, &item.WorkflowRunID, &item.ScopeVersionID, &item.AttemptCount,
		&item.LeaseOwner, &item.LeaseExpiresAt, &item.ErrorClassification, &item.ErrorSummary,
		&item.StartedAt, &item.CompletedAt, &item.CreatedAt, &item.UpdatedAt, &programID,
	)
	return item, programID, err
}

func lockedScheduledExecution(ctx context.Context, tx pgx.Tx, id domain.ID) (domain.ScheduledExecution, domain.ID, error) {
	return scanScheduledExecution(tx.QueryRow(ctx, `SELECT se.id,se.schedule_id,se.planned_at,se.trigger_source,se.status,se.task_id,se.workflow_run_id,se.scope_version_id,se.attempt_count,se.lease_owner,se.lease_expires_at,se.error_classification,se.error_summary,se.started_at,se.completed_at,se.created_at,se.updated_at,s.program_id
		FROM scheduled_executions se
		JOIN schedules s ON s.id=se.schedule_id
		WHERE se.id=$1
		FOR UPDATE OF se`, id))
}

func lockedScheduledExecutionByWorkflow(ctx context.Context, tx pgx.Tx, workflowRunID domain.ID) (domain.ScheduledExecution, domain.ID, bool, error) {
	item, programID, err := scanScheduledExecution(tx.QueryRow(ctx, `SELECT se.id,se.schedule_id,se.planned_at,se.trigger_source,se.status,se.task_id,se.workflow_run_id,se.scope_version_id,se.attempt_count,se.lease_owner,se.lease_expires_at,se.error_classification,se.error_summary,se.started_at,se.completed_at,se.created_at,se.updated_at,s.program_id
		FROM scheduled_executions se
		JOIN schedules s ON s.id=se.schedule_id
		WHERE se.workflow_run_id=$1
		FOR UPDATE OF se`, workflowRunID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ScheduledExecution{}, "", false, nil
	}
	return item, programID, err == nil, err
}

func lockedSchedulerLeaseValid(ctx context.Context, tx pgx.Tx, id domain.ID, owner string, attempt int) (bool, error) {
	var valid bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1
		FROM scheduled_executions
		WHERE id=$1
		  AND lease_owner=$2
		  AND attempt_count=$3
		  AND lease_expires_at>clock_timestamp()
	)`, id, owner, attempt).Scan(&valid)
	return valid, err
}

func (s *Store) MarkScheduledExecutionTaskCreated(ctx context.Context, id, taskID domain.ID, owner string, attempt int) error {
	if tx, ok := transactionFromContext(ctx); ok {
		return markScheduledExecutionTaskCreated(ctx, tx, id, taskID, owner, attempt)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := markScheduledExecutionTaskCreated(ctx, tx, id, taskID, owner, attempt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func markScheduledExecutionTaskCreated(ctx context.Context, tx pgx.Tx, id, taskID domain.ID, owner string, attempt int) error {
	item, programID, err := lockedScheduledExecution(ctx, tx, id)
	if err != nil {
		return err
	}
	validLease, err := lockedSchedulerLeaseValid(ctx, tx, item.ID, owner, attempt)
	if err != nil {
		return err
	}
	if item.Status != domain.ScheduledExecutionClaimed || !validLease || item.WorkflowRunID != nil {
		return invalidScheduledExecutionTransition(item, domain.ScheduledExecutionClaimed)
	}
	if item.TaskID != nil {
		if *item.TaskID == taskID {
			return nil
		}
		return fmt.Errorf("scheduled execution %s already links task %s, not %s", item.ID, *item.TaskID, taskID)
	}
	var updatedAt time.Time
	tag, err := tx.Exec(ctx, `UPDATE scheduled_executions
		SET task_id=$2,updated_at=now()
		WHERE id=$1
		  AND status='claimed'
		  AND task_id IS NULL
		  AND workflow_run_id IS NULL
		  AND lease_owner=$3
		  AND attempt_count=$4
		  AND lease_expires_at>clock_timestamp()`, id, taskID, owner, attempt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return invalidScheduledExecutionTransition(item, domain.ScheduledExecutionClaimed)
	}
	if err := tx.QueryRow(ctx, `SELECT updated_at FROM scheduled_executions WHERE id=$1`, id).Scan(&updatedAt); err != nil {
		return err
	}
	item.TaskID, item.UpdatedAt = &taskID, updatedAt
	return auditExecution(ctx, tx, "scheduled_execution_task_linked", owner, programID, item, "scheduled execution task linked", nil)
}

func rejectLockedScheduledExecutionForApproval(ctx context.Context, tx pgx.Tx, item domain.ScheduledExecution, programID domain.ID, actor string) error {
	if item.Status == domain.ScheduledExecutionApprovalRejected {
		return nil
	}
	if item.Status != domain.ScheduledExecutionPausedForApproval && item.Status != domain.ScheduledExecutionRunning {
		return invalidScheduledExecutionTransition(item, domain.ScheduledExecutionApprovalRejected)
	}
	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `UPDATE scheduled_executions
		SET status='approval_rejected',
		    error_classification='approval_rejected',
		    error_summary='moderate step approval was rejected',
		    completed_at=$2,
		    lease_owner='',
		    lease_expires_at=NULL,
		    updated_at=$2
		WHERE id=$1 AND status=$3`, item.ID, now, item.Status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return invalidScheduledExecutionTransition(item, domain.ScheduledExecutionApprovalRejected)
	}
	item.Status, item.ErrorClassification, item.ErrorSummary, item.CompletedAt, item.UpdatedAt = domain.ScheduledExecutionApprovalRejected, "approval_rejected", "moderate step approval was rejected", &now, now
	item.LeaseOwner, item.LeaseExpiresAt = "", nil
	return auditExecution(ctx, tx, "scheduled_execution_approval_rejected", actor, programID, item, "scheduled execution approval rejected", nil)
}

func markScheduledExecutionRunning(ctx context.Context, tx pgx.Tx, id, taskID, workflowRunID domain.ID, scopeVersionID *domain.ID, owner string, attempt int) error {
	item, programID, err := lockedScheduledExecution(ctx, tx, id)
	if err != nil {
		return err
	}
	validLease, err := lockedSchedulerLeaseValid(ctx, tx, item.ID, owner, attempt)
	if err != nil {
		return err
	}
	if !validLease {
		return invalidScheduledExecutionTransition(item, domain.ScheduledExecutionRunning)
	}
	if item.Status == domain.ScheduledExecutionRunning {
		if item.TaskID != nil && item.WorkflowRunID != nil && *item.TaskID == taskID && *item.WorkflowRunID == workflowRunID {
			return nil
		}
		return invalidScheduledExecutionTransition(item, domain.ScheduledExecutionRunning)
	}
	if item.Status != domain.ScheduledExecutionClaimed ||
		(item.TaskID != nil && *item.TaskID != taskID) ||
		(item.WorkflowRunID != nil && *item.WorkflowRunID != workflowRunID) {
		return invalidScheduledExecutionTransition(item, domain.ScheduledExecutionRunning)
	}
	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `UPDATE scheduled_executions
		SET status='running',task_id=$2,workflow_run_id=$3,scope_version_id=$4,started_at=COALESCE(started_at,$5),updated_at=$5
		WHERE id=$1
		  AND status='claimed'
		  AND (task_id IS NULL OR task_id=$2)
		  AND (workflow_run_id IS NULL OR workflow_run_id=$3)
		  AND lease_owner=$6
		  AND attempt_count=$7
		  AND lease_expires_at>clock_timestamp()`, id, taskID, workflowRunID, scopeVersionID, now, owner, attempt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return invalidScheduledExecutionTransition(item, domain.ScheduledExecutionRunning)
	}
	if _, err := tx.Exec(ctx, `UPDATE schedules SET last_run_at=$2,updated_at=$2 WHERE id=$1`, item.ScheduleID, now); err != nil {
		return err
	}
	item.Status, item.TaskID, item.WorkflowRunID, item.ScopeVersionID, item.StartedAt, item.UpdatedAt = domain.ScheduledExecutionRunning, &taskID, &workflowRunID, scopeVersionID, &now, now
	if err := auditExecution(ctx, tx, "scheduled_execution_started", owner, programID, item, "scheduled execution started", nil); err != nil {
		return err
	}
	return nil
}

func skipOverlappingPendingExecutions(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx, `SELECT se.id,se.schedule_id,se.planned_at,se.trigger_source,se.status,se.task_id,se.workflow_run_id,se.scope_version_id,se.attempt_count,se.lease_owner,se.lease_expires_at,se.error_classification,se.error_summary,se.started_at,se.completed_at,se.created_at,se.updated_at,s.program_id
		FROM scheduled_executions se
		JOIN schedules s ON s.id=se.schedule_id
		WHERE se.status='pending'
		  AND EXISTS (
			SELECT 1 FROM scheduled_executions active
			WHERE active.schedule_id=se.schedule_id
			  AND active.id<>se.id
			  AND active.status IN ('claimed','running','paused_for_approval','paused_operator')
		  )
		ORDER BY se.planned_at,se.created_at
		FOR UPDATE OF se`)
	if err != nil {
		return err
	}
	type overlapExecution struct {
		item      domain.ScheduledExecution
		programID domain.ID
	}
	var overlaps []overlapExecution
	for rows.Next() {
		item, programID, scanErr := scanScheduledExecution(rows)
		if scanErr != nil {
			rows.Close()
			return scanErr
		}
		overlaps = append(overlaps, overlapExecution{item: item, programID: programID})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, entry := range overlaps {
		now := time.Now().UTC()
		tag, err := tx.Exec(ctx, `UPDATE scheduled_executions SET status='skipped_overlap',error_classification='overlap',error_summary='same schedule already has an active execution',completed_at=$2,updated_at=$2 WHERE id=$1 AND status='pending'`, entry.item.ID, now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return invalidScheduledExecutionTransition(entry.item, domain.ScheduledExecutionSkippedOverlap)
		}
		item := entry.item
		item.Status, item.ErrorClassification, item.ErrorSummary, item.CompletedAt, item.UpdatedAt = domain.ScheduledExecutionSkippedOverlap, "overlap", "same schedule already has an active execution", &now, now
		if err := auditExecution(ctx, tx, "scheduled_execution_skipped_overlap", "scheduler", entry.programID, item, "scheduled execution skipped because another execution is active", nil); err != nil {
			return err
		}
	}
	return nil
}

func containsExecutionStatus(items []domain.ScheduledExecutionStatus, value domain.ScheduledExecutionStatus) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func invalidScheduledExecutionTransition(item domain.ScheduledExecution, next domain.ScheduledExecutionStatus) error {
	return fmt.Errorf("scheduled execution %s cannot transition from %s to %s", item.ID, item.Status, next)
}

func (s *Store) RequestScheduledExecutionResume(ctx context.Context, id domain.ID, actor string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	item, programID, err := lockedScheduledExecution(ctx, tx, id)
	if err != nil {
		return err
	}
	if item.Status != domain.ScheduledExecutionPausedForApproval && item.Status != domain.ScheduledExecutionPausedOperator {
		return invalidScheduledExecutionTransition(item, domain.ScheduledExecutionPending)
	}
	if item.Status == domain.ScheduledExecutionPausedForApproval {
		if item.WorkflowRunID == nil {
			return fmt.Errorf("scheduled execution %s has no workflow lineage", id)
		}
		var decision string
		err = tx.QueryRow(ctx, `SELECT a.decision FROM approvals a JOIN step_runs sr ON sr.id=a.request_id WHERE sr.workflow_run_id=$1 AND sr.status='awaiting_approval' ORDER BY a.requested_at DESC LIMIT 1`, item.WorkflowRunID).Scan(&decision)
		if err != nil {
			return err
		}
		if decision == "rejected" {
			now := time.Now().UTC()
			tag, updateErr := tx.Exec(ctx, `UPDATE scheduled_executions SET status='approval_rejected',error_classification='approval_rejected',error_summary='moderate step approval was rejected',completed_at=$2,updated_at=$2 WHERE id=$1 AND status='paused_for_approval'`, id, now)
			if updateErr != nil {
				return updateErr
			}
			if tag.RowsAffected() != 1 {
				return invalidScheduledExecutionTransition(item, domain.ScheduledExecutionApprovalRejected)
			}
			item.Status, item.ErrorClassification, item.ErrorSummary, item.CompletedAt, item.UpdatedAt = domain.ScheduledExecutionApprovalRejected, "approval_rejected", "moderate step approval was rejected", &now, now
			if err := auditExecution(ctx, tx, "scheduled_execution_approval_rejected", actor, programID, item, "scheduled execution approval rejected", nil); err != nil {
				return err
			}
			if err := tx.Commit(ctx); err != nil {
				return err
			}
			return fmt.Errorf("%w: %s", ErrApprovalRejected, id)
		}
		if decision != "approved" {
			return fmt.Errorf("scheduled execution %s does not have an approved pending step", id)
		}
	}
	var overlap bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM scheduled_executions
		WHERE schedule_id=$1
		  AND id<>$2
		  AND status IN ('claimed','running','paused_for_approval','paused_operator')
	)`, item.ScheduleID, item.ID).Scan(&overlap); err != nil {
		return err
	}
	if overlap {
		return fmt.Errorf("%w: %s", ErrScheduleOverlap, item.ScheduleID)
	}
	now := time.Now().UTC()
	tag, err := tx.Exec(ctx, `UPDATE scheduled_executions SET status='pending',trigger_source='resume',lease_owner='',lease_expires_at=NULL,error_classification='',error_summary='',completed_at=NULL,updated_at=$2 WHERE id=$1 AND status=$3`, id, now, item.Status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return invalidScheduledExecutionTransition(item, domain.ScheduledExecutionPending)
	}
	item.Status, item.TriggerSource, item.ErrorClassification, item.ErrorSummary, item.CompletedAt, item.UpdatedAt = domain.ScheduledExecutionPending, domain.ScheduleTriggerResume, "", "", nil, now
	if err := auditExecution(ctx, tx, "scheduled_execution_resume_requested", actor, programID, item, "scheduled execution resume requested", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ListScheduledExecutions(ctx context.Context, scheduleID domain.ID, limit int) ([]domain.ScheduledExecution, error) {
	if limit < 1 {
		limit = 50
	}
	query := `SELECT id,schedule_id,planned_at,trigger_source,status,task_id,workflow_run_id,scope_version_id,attempt_count,lease_owner,lease_expires_at,error_classification,error_summary,started_at,completed_at,created_at,updated_at FROM scheduled_executions`
	args := []any{}
	if scheduleID != "" {
		query += ` WHERE schedule_id=$1`
		args = append(args, scheduleID)
	}
	query += fmt.Sprintf(` ORDER BY planned_at DESC,created_at DESC LIMIT %d`, limit)
	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ScheduledExecution
	for rows.Next() {
		var item domain.ScheduledExecution
		if err := rows.Scan(&item.ID, &item.ScheduleID, &item.PlannedAt, &item.TriggerSource, &item.Status, &item.TaskID, &item.WorkflowRunID, &item.ScopeVersionID, &item.AttemptCount, &item.LeaseOwner, &item.LeaseExpiresAt, &item.ErrorClassification, &item.ErrorSummary, &item.StartedAt, &item.CompletedAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ListPendingScopeExpansions(ctx context.Context, programID domain.ID) ([]ConsolePendingScopeExpansion, error) {
	query := `SELECT id,program_id,scope_digest,target_plan_digest,planning_warnings,added_include_digests,removed_include_digests,added_exclude_digests,removed_exclude_digests,created_at FROM scope_versions WHERE expands_scope=true AND acknowledged_at IS NULL`
	args := []any{}
	if programID != "" {
		query += ` AND program_id=$1`
		args = append(args, programID)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConsolePendingScopeExpansion
	for rows.Next() {
		var item ConsolePendingScopeExpansion
		if err := rows.Scan(&item.ID, &item.ProgramID, &item.ScopeDigest, &item.TargetPlanDigest, &item.PlanningWarnings, &item.AddedIncludeDigests, &item.RemovedIncludeDigests, &item.AddedExcludeDigests, &item.RemovedExcludeDigests, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) AcknowledgeScopeVersion(ctx context.Context, scopeVersionID domain.ID, actor string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var snapshot domain.ScopeSnapshot
	err = tx.QueryRow(ctx, `SELECT id,program_id,scope_reference,scope_digest,include_rule_digests,exclude_rule_digests,target_plan_digest,planning_warnings FROM scope_versions WHERE id=$1 AND expands_scope=true AND acknowledged_at IS NULL FOR UPDATE`, scopeVersionID).Scan(&snapshot.ID, &snapshot.ProgramID, &snapshot.ScopeReference, &snapshot.ScopeDigest, &snapshot.IncludeRuleDigests, &snapshot.ExcludeRuleDigests, &snapshot.TargetPlanDigest, &snapshot.PlanningWarnings)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE scope_versions SET acknowledged_by=$2,acknowledged_at=now() WHERE id=$1`, scopeVersionID, actor); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE programs SET scope_reference=$2,scope_digest=$3,include_rule_digests=$4,exclude_rule_digests=$5,target_plan_digest=$6,scope_plan_warnings=$7,updated_at=now() WHERE id=$1`, snapshot.ProgramID, snapshot.ScopeReference, snapshot.ScopeDigest, snapshot.IncludeRuleDigests, snapshot.ExcludeRuleDigests, snapshot.TargetPlanDigest, snapshot.PlanningWarnings); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,'scope_expansion_acknowledged','targeting',$2,$3,'scope expansion acknowledged',$4)`, domain.NewID(), actor, snapshot.ProgramID, mustJSON(map[string]any{"scope_version_id": scopeVersionID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) PersistChangeItems(ctx context.Context, programID, workflowRunID domain.ID, scheduledExecutionID *domain.ID, items []domain.ChangeItem) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if scheduledExecutionID == nil {
		scheduledExecutionID, err = scheduledExecutionIDForWorkflow(ctx, tx, workflowRunID)
		if err != nil {
			return err
		}
	}
	for _, item := range items {
		_, err := tx.Exec(ctx, `INSERT INTO change_items(id,program_id,workflow_run_id,scheduled_execution_id,kind,entity_type,entity_key,priority,title,safe_summary,reasons,previous_value,current_value,source_capabilities,evidence_artifact_ids,observed_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) ON CONFLICT(workflow_run_id,kind,entity_type,entity_key) DO NOTHING`, item.ID, programID, workflowRunID, scheduledExecutionID, item.Kind, item.EntityType, item.EntityKey, item.Priority, item.Title, item.Summary, item.Reasons, item.Previous, item.Current, item.SourceCapabilities, idStrings(item.EvidenceArtifactIDs), item.ObservedAt, item.CreatedAt)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ListChangeItems(ctx context.Context, programID domain.ID, includeReviewed bool, limit int) ([]domain.ChangeItem, error) {
	if limit < 1 {
		limit = 100
	}
	query := `SELECT ci.id,ci.program_id,ci.workflow_run_id,ci.scheduled_execution_id,ci.kind,ci.entity_type,ci.entity_key,ci.priority,ci.title,ci.safe_summary,ci.reasons,ci.previous_value,ci.current_value,ci.source_capabilities,ci.evidence_artifact_ids,ci.observed_at,ci.created_at FROM change_items ci LEFT JOIN change_reviews cr ON cr.change_item_id=ci.id WHERE ci.program_id=$1`
	if !includeReviewed {
		query += ` AND COALESCE(cr.disposition,'unreviewed')='unreviewed'`
	}
	query += fmt.Sprintf(` ORDER BY CASE ci.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, ci.observed_at DESC LIMIT %d`, limit)
	rows, err := s.Pool.Query(ctx, query, programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ChangeItem
	for rows.Next() {
		var item domain.ChangeItem
		var evidence []string
		if err := rows.Scan(&item.ID, &item.ProgramID, &item.WorkflowRunID, &item.ScheduledExecutionID, &item.Kind, &item.EntityType, &item.EntityKey, &item.Priority, &item.Title, &item.Summary, &item.Reasons, &item.Previous, &item.Current, &item.SourceCapabilities, &evidence, &item.ObservedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.EvidenceArtifactIDs = idsFromStrings(evidence)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ReviewChangeItem(ctx context.Context, changeID domain.ID, disposition domain.ChangeReviewDisposition, note, actor string) error {
	if !validDisposition(disposition) {
		return fmt.Errorf("invalid disposition %q", disposition)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var programID domain.ID
	if err := tx.QueryRow(ctx, `SELECT program_id FROM change_items WHERE id=$1 FOR UPDATE`, changeID).Scan(&programID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO change_reviews(id,change_item_id,disposition,note,reviewed_by,reviewed_at) VALUES($1,$2,$3,$4,$5,now()) ON CONFLICT(change_item_id) DO UPDATE SET disposition=EXCLUDED.disposition,note=EXCLUDED.note,reviewed_by=EXCLUDED.reviewed_by,reviewed_at=EXCLUDED.reviewed_at,updated_at=now()`, domain.NewID(), changeID, disposition, safeSummary(note), actor)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,'change_reviewed','console',$2,$3,'change item reviewed',$4)`, domain.NewID(), actor, programID, mustJSON(map[string]any{"change_item_id": changeID, "disposition": disposition})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func validDisposition(value domain.ChangeReviewDisposition) bool {
	switch value {
	case domain.ChangeReviewUnreviewed, domain.ChangeReviewInteresting, domain.ChangeReviewInvestigating, domain.ChangeReviewExpectedChange, domain.ChangeReviewNotRelevant, domain.ChangeReviewResolved:
		return true
	default:
		return false
	}
}

func auditSchedule(ctx context.Context, tx pgx.Tx, event, actor string, programID, scheduleID domain.ID, message string, details any) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,$2,'scheduler',$3,$4,$5,$6)`, domain.NewID(), event, actor, programID, message, mustJSON(map[string]any{"schedule_id": scheduleID, "details": details}))
	return err
}

func auditExecution(ctx context.Context, tx pgx.Tx, event, actor string, programID domain.ID, item domain.ScheduledExecution, message string, details any) error {
	if details == nil {
		details = map[string]any{"scheduled_execution_id": item.ID, "schedule_id": item.ScheduleID, "status": item.Status, "trigger_source": item.TriggerSource}
	}
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,safe_message,details) VALUES($1,$2,'scheduler',$3,$4,$5,$6,$7,$8)`, domain.NewID(), event, actor, programID, item.TaskID, item.WorkflowRunID, message, mustJSON(details))
	return err
}

func safeSummary(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	if len(value) > 500 {
		return value[:500]
	}
	return value
}

func idsFromStrings(values []string) []domain.ID {
	out := make([]domain.ID, 0, len(values))
	for _, value := range values {
		out = append(out, domain.ID(value))
	}
	return out
}

func jsonDetails(value any) json.RawMessage {
	return mustJSON(value)
}
