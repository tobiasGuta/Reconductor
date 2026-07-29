package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

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
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM scheduled_executions WHERE schedule_id=$1 AND status IN ('claimed','running','paused_for_approval'))`, due.id).Scan(&active); err != nil {
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
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return domain.ScheduledExecution{}, domain.Schedule{}, false, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	_, _ = tx.Exec(ctx, `UPDATE scheduled_executions SET status='pending',lease_owner='',lease_expires_at=NULL,updated_at=now() WHERE status='claimed' AND lease_expires_at<now() AND task_id IS NULL AND workflow_run_id IS NULL`)
	_, _ = tx.Exec(ctx, `UPDATE scheduled_executions SET status='interrupted',error_classification='interrupted',error_summary='scheduler lease expired after workflow state was created',completed_at=now(),updated_at=now() WHERE status IN ('claimed','running') AND lease_expires_at<now() AND (task_id IS NOT NULL OR workflow_run_id IS NOT NULL)`)
	var item domain.ScheduledExecution
	var sched domain.Schedule
	err = tx.QueryRow(ctx, `SELECT se.id,se.schedule_id,se.planned_at,se.trigger_source,se.status,se.task_id,se.workflow_run_id,se.scope_version_id,se.attempt_count,se.lease_owner,se.lease_expires_at,se.error_classification,se.error_summary,se.started_at,se.completed_at,se.created_at,se.updated_at,s.id,s.program_id,s.name,s.workflow_name,s.objective,s.cron_expression,s.timezone,s.enabled,s.headless,s.created_by,s.last_run_at,s.next_run_at,s.created_at,s.updated_at FROM scheduled_executions se JOIN schedules s ON s.id=se.schedule_id WHERE se.status='pending' ORDER BY se.planned_at,se.created_at LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&item.ID, &item.ScheduleID, &item.PlannedAt, &item.TriggerSource, &item.Status, &item.TaskID, &item.WorkflowRunID, &item.ScopeVersionID, &item.AttemptCount, &item.LeaseOwner, &item.LeaseExpiresAt, &item.ErrorClassification, &item.ErrorSummary, &item.StartedAt, &item.CompletedAt, &item.CreatedAt, &item.UpdatedAt, &sched.ID, &sched.ProgramID, &sched.Name, &sched.WorkflowName, &sched.Objective, &sched.CronExpression, &sched.Timezone, &sched.Enabled, &sched.Headless, &sched.CreatedBy, &sched.LastRunAt, &sched.NextRunAt, &sched.CreatedAt, &sched.UpdatedAt)
	if err == pgx.ErrNoRows {
		return domain.ScheduledExecution{}, domain.Schedule{}, false, tx.Commit(ctx)
	}
	if err != nil {
		return domain.ScheduledExecution{}, domain.Schedule{}, false, err
	}
	expires := now.Add(leaseTimeout)
	err = tx.QueryRow(ctx, `UPDATE scheduled_executions SET status='claimed',attempt_count=attempt_count+1,lease_owner=$2,lease_expires_at=$3,updated_at=now() WHERE id=$1 RETURNING status,attempt_count,lease_owner,lease_expires_at,updated_at`, item.ID, owner, expires).Scan(&item.Status, &item.AttemptCount, &item.LeaseOwner, &item.LeaseExpiresAt, &item.UpdatedAt)
	if err != nil {
		return domain.ScheduledExecution{}, domain.Schedule{}, false, err
	}
	if err := auditExecution(ctx, tx, "scheduled_execution_claimed", owner, sched.ProgramID, item, "scheduled execution claimed", nil); err != nil {
		return domain.ScheduledExecution{}, domain.Schedule{}, false, err
	}
	return item, sched, true, tx.Commit(ctx)
}

func (s *Store) HeartbeatScheduledExecution(ctx context.Context, id domain.ID, owner string, leaseTimeout time.Duration) error {
	_, err := s.Pool.Exec(ctx, `UPDATE scheduled_executions SET lease_expires_at=$3,updated_at=now() WHERE id=$1 AND lease_owner=$2 AND status IN ('claimed','running')`, id, owner, time.Now().UTC().Add(leaseTimeout))
	return err
}

func (s *Store) MarkScheduledExecutionRunning(ctx context.Context, id, taskID, workflowRunID domain.ID, scopeVersionID *domain.ID, owner string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE scheduled_executions SET status='running',task_id=$2,workflow_run_id=$3,scope_version_id=$4,started_at=COALESCE(started_at,now()),updated_at=now() WHERE id=$1 AND lease_owner=$5`, id, taskID, workflowRunID, scopeVersionID, owner)
	return err
}

func (s *Store) MarkScheduledExecutionPaused(ctx context.Context, id domain.ID, owner string) error {
	return s.markScheduledExecution(ctx, id, domain.ScheduledExecutionPausedForApproval, owner, "", "")
}

func (s *Store) MarkScheduledExecutionCompleted(ctx context.Context, id domain.ID, owner string) error {
	return s.markScheduledExecution(ctx, id, domain.ScheduledExecutionCompleted, owner, "", "")
}

func (s *Store) MarkScheduledExecutionFailed(ctx context.Context, id domain.ID, owner, class, summary string) error {
	return s.markScheduledExecution(ctx, id, domain.ScheduledExecutionFailed, owner, class, safeSummary(summary))
}

func (s *Store) MarkScheduledExecutionCancelled(ctx context.Context, id domain.ID, owner string) error {
	return s.markScheduledExecution(ctx, id, domain.ScheduledExecutionCancelled, owner, "cancelled", "scheduler shutdown cancelled execution")
}

func (s *Store) MarkScheduledExecutionBlocked(ctx context.Context, id domain.ID, scopeVersionID domain.ID, owner string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE scheduled_executions SET status='blocked_scope_change',scope_version_id=$2,error_classification='scope_change',error_summary='unacknowledged scope expansion blocked scheduled execution',completed_at=now(),lease_owner='',lease_expires_at=NULL,updated_at=now() WHERE id=$1 AND lease_owner=$3`, id, scopeVersionID, owner)
	return err
}

func (s *Store) markScheduledExecution(ctx context.Context, id domain.ID, status domain.ScheduledExecutionStatus, owner, class, summary string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE scheduled_executions SET status=$2,error_classification=$3,error_summary=$4,completed_at=CASE WHEN $2 IN ('completed','failed','cancelled','approval_rejected','interrupted') THEN now() ELSE completed_at END,lease_owner=CASE WHEN $2 IN ('completed','failed','cancelled','paused_for_approval','approval_rejected','interrupted') THEN '' ELSE lease_owner END,lease_expires_at=CASE WHEN $2 IN ('completed','failed','cancelled','paused_for_approval','approval_rejected','interrupted') THEN NULL ELSE lease_expires_at END,updated_at=now() WHERE id=$1 AND ($5='' OR lease_owner=$5)`, id, status, class, summary, owner)
	return err
}

func (s *Store) RequestScheduledExecutionResume(ctx context.Context, id domain.ID, actor string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var item domain.ScheduledExecution
	var programID domain.ID
	err = tx.QueryRow(ctx, `SELECT se.id,se.schedule_id,se.workflow_run_id,s.program_id FROM scheduled_executions se JOIN schedules s ON s.id=se.schedule_id WHERE se.id=$1 AND se.status='paused_for_approval' FOR UPDATE`, id).Scan(&item.ID, &item.ScheduleID, &item.WorkflowRunID, &programID)
	if err != nil {
		return err
	}
	var decision string
	err = tx.QueryRow(ctx, `SELECT a.decision FROM approvals a JOIN step_runs sr ON sr.id=a.request_id WHERE sr.workflow_run_id=$1 AND sr.status='awaiting_approval' ORDER BY a.requested_at DESC LIMIT 1`, item.WorkflowRunID).Scan(&decision)
	if err != nil {
		return err
	}
	if decision == "rejected" {
		_, err = tx.Exec(ctx, `UPDATE scheduled_executions SET status='approval_rejected',error_classification='approval_rejected',error_summary='moderate step approval was rejected',completed_at=now(),updated_at=now() WHERE id=$1`, id)
		return err
	}
	if decision != "approved" {
		return fmt.Errorf("scheduled execution %s does not have an approved pending step", id)
	}
	if _, err := tx.Exec(ctx, `UPDATE scheduled_executions SET status='pending',trigger_source='resume',lease_owner='',lease_expires_at=NULL,updated_at=now() WHERE id=$1`, id); err != nil {
		return err
	}
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

func (s *Store) ListPendingScopeExpansions(ctx context.Context, programID domain.ID) ([]domain.ScopeSnapshot, error) {
	query := `SELECT id,program_id,scope_reference,scope_digest,include_rule_digests,exclude_rule_digests,target_plan_digest,planning_warnings,target_plan,expands_scope,added_include_digests,removed_include_digests,added_exclude_digests,removed_exclude_digests,COALESCE(acknowledged_by,''),acknowledged_at,created_at FROM scope_versions WHERE expands_scope=true AND acknowledged_at IS NULL`
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
	var out []domain.ScopeSnapshot
	for rows.Next() {
		var item domain.ScopeSnapshot
		if err := rows.Scan(&item.ID, &item.ProgramID, &item.ScopeReference, &item.ScopeDigest, &item.IncludeRuleDigests, &item.ExcludeRuleDigests, &item.TargetPlanDigest, &item.PlanningWarnings, &item.TargetPlan, &item.ExpandsScope, &item.AddedIncludeDigests, &item.RemovedIncludeDigests, &item.AddedExcludeDigests, &item.RemovedExcludeDigests, &item.AcknowledgedBy, &item.AcknowledgedAt, &item.CreatedAt); err != nil {
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
