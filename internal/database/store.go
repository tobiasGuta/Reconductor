package database

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/changes"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/findings"
	"github.com/tobiasGuta/Reconductor/internal/migrations"
	"github.com/tobiasGuta/Reconductor/internal/normalize"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err = p.Ping(ctx); err != nil {
		p.Close()
		return nil, fmt.Errorf("connect database: %w", err)
	}
	return &Store{Pool: p}, nil
}
func (s *Store) Close()                            { s.Pool.Close() }
func (s *Store) Migrate(ctx context.Context) error { return migrations.Up(ctx, s.Pool) }

func (s *Store) CreateProgram(ctx context.Context, p domain.Program, snapshot domain.ScopeSnapshot) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO programs(id,name,platform,description,scope_reference,policy_reference,scope_digest,include_rule_digests,exclude_rule_digests,target_plan_digest,scope_plan_warnings,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, p.ID, p.Name, p.Platform, p.Description, p.ScopeReference, p.PolicyReference, p.ScopeDigest, p.IncludeRuleDigests, p.ExcludeRuleDigests, p.TargetPlanDigest, p.ScopePlanWarnings, p.CreatedAt, p.UpdatedAt); err != nil {
		return err
	}
	if snapshot.ID == "" {
		snapshot.ID = domain.NewID()
	}
	snapshot.ProgramID = p.ID
	if snapshot.CreatedAt.IsZero() {
		snapshot.CreatedAt = p.CreatedAt
	}
	if snapshot.AcknowledgedAt == nil {
		snapshot.AcknowledgedAt = &snapshot.CreatedAt
	}
	if snapshot.AcknowledgedBy == "" {
		snapshot.AcknowledgedBy = "program-creator"
	}
	normalizeScopeSnapshotSlices(&snapshot)
	if _, err = tx.Exec(ctx, `INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,include_rule_digests,exclude_rule_digests,target_plan_digest,planning_warnings,target_plan,expands_scope,added_include_digests,removed_include_digests,added_exclude_digests,removed_exclude_digests,acknowledged_by,acknowledged_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,false,$10,$11,$12,$13,$14,$15,$16)`, snapshot.ID, snapshot.ProgramID, snapshot.ScopeReference, snapshot.ScopeDigest, snapshot.IncludeRuleDigests, snapshot.ExcludeRuleDigests, snapshot.TargetPlanDigest, snapshot.PlanningWarnings, snapshot.TargetPlan, snapshot.AddedIncludeDigests, snapshot.RemovedIncludeDigests, snapshot.AddedExcludeDigests, snapshot.RemovedExcludeDigests, snapshot.AcknowledgedBy, snapshot.AcknowledgedAt, snapshot.CreatedAt); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,'program_created','platform','cli',$2,$3,$4)`, domain.NewID(), p.ID, "program created with scope snapshot", mustJSON(p)); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,'target_plan_generated','targeting','cli',$2,'initial target plan generated',$3)`, domain.NewID(), p.ID, mustJSON(map[string]any{"scope_digest": p.ScopeDigest, "target_plan_digest": p.TargetPlanDigest, "warnings": p.ScopePlanWarnings})); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,'scope_file_loaded','targeting','cli',$2,'initial scope file loaded',$3)`, domain.NewID(), p.ID, mustJSON(map[string]string{"scope_reference": p.ScopeReference, "scope_digest": p.ScopeDigest})); err != nil {
		return err
	}
	if err := auditPlanDerivations(ctx, tx, snapshot, "cli"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) ListPrograms(ctx context.Context) ([]domain.Program, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,name,platform,description,scope_reference,policy_reference,scope_digest,include_rule_digests,exclude_rule_digests,target_plan_digest,scope_plan_warnings,created_at,updated_at FROM programs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Program
	for rows.Next() {
		var p domain.Program
		if err := rows.Scan(&p.ID, &p.Name, &p.Platform, &p.Description, &p.ScopeReference, &p.PolicyReference, &p.ScopeDigest, &p.IncludeRuleDigests, &p.ExcludeRuleDigests, &p.TargetPlanDigest, &p.ScopePlanWarnings, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetProgram(ctx context.Context, id domain.ID) (domain.Program, error) {
	var p domain.Program
	err := s.Pool.QueryRow(ctx, `SELECT id,name,platform,description,scope_reference,policy_reference,scope_digest,include_rule_digests,exclude_rule_digests,target_plan_digest,scope_plan_warnings,created_at,updated_at FROM programs WHERE id=$1`, id).Scan(&p.ID, &p.Name, &p.Platform, &p.Description, &p.ScopeReference, &p.PolicyReference, &p.ScopeDigest, &p.IncludeRuleDigests, &p.ExcludeRuleDigests, &p.TargetPlanDigest, &p.ScopePlanWarnings, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// RepairProgramScopeReference changes only the physical/logical locator for an
// unchanged authorized scope and target plan. The digest predicates prevent a
// stale repair from overwriting a concurrent scope change.
func (s *Store) RepairProgramScopeReference(ctx context.Context, programID domain.ID, reference, expectedScopeDigest, expectedTargetPlanDigest, actor string) error {
	if programID == "" || strings.TrimSpace(reference) == "" {
		return fmt.Errorf("program id and scope reference are required")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var scopeVersionID domain.ID
	err = tx.QueryRow(ctx, `SELECT id FROM scope_versions WHERE program_id=$1 AND scope_digest=$2 AND target_plan_digest=$3 FOR UPDATE`, programID, expectedScopeDigest, expectedTargetPlanDigest).Scan(&scopeVersionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("current scope version was not found for reference repair")
		}
		return err
	}
	var previousReference, scopeDigest, targetPlanDigest string
	err = tx.QueryRow(ctx, `SELECT scope_reference,scope_digest,target_plan_digest FROM programs WHERE id=$1 FOR UPDATE`, programID).Scan(&previousReference, &scopeDigest, &targetPlanDigest)
	if err != nil {
		return err
	}
	if scopeDigest != expectedScopeDigest || targetPlanDigest != expectedTargetPlanDigest {
		return fmt.Errorf("scope changed while repairing its reference")
	}
	if _, err = tx.Exec(ctx, `UPDATE programs SET scope_reference=$2,updated_at=now() WHERE id=$1`, programID, reference); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE scope_versions SET scope_reference=$2 WHERE id=$1`, scopeVersionID, reference); err != nil {
		return err
	}
	if strings.TrimSpace(actor) == "" {
		actor = "cli"
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,'scope_reference_repaired','targeting',$2,$3,'scope reference repaired without changing authorization',$4)`, domain.NewID(), actor, programID, mustJSON(map[string]string{
		"previous_scope_reference": previousReference,
		"scope_reference":          reference,
		"scope_digest":             expectedScopeDigest,
		"target_plan_digest":       expectedTargetPlanDigest,
	})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CheckAndRecordScopeSnapshot(ctx context.Context, snapshot domain.ScopeSnapshot, acknowledgeExpansion bool, actor string) (domain.ScopeChange, error) {
	normalizeScopeSnapshotSlices(&snapshot)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return domain.ScopeChange{}, err
	}
	defer tx.Rollback(ctx)
	var previousID domain.ID
	var previousInclude, previousExclude []string
	var previousPlan string
	err = tx.QueryRow(ctx, `SELECT id,include_rule_digests,exclude_rule_digests,target_plan_digest FROM scope_versions WHERE program_id=$1 AND (expands_scope=false OR acknowledged_at IS NOT NULL) ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, snapshot.ProgramID).Scan(&previousID, &previousInclude, &previousExclude, &previousPlan)
	if err != nil && err != pgx.ErrNoRows {
		return domain.ScopeChange{}, err
	}
	if err == pgx.ErrNoRows {
		previousInclude, previousExclude, previousPlan = nil, nil, ""
	}
	change := scopeChange(previousPlan, previousInclude, previousExclude, snapshot)
	change.ScopeVersionID = previousID
	if !change.Changed {
		for _, event := range []struct{ eventType, message string }{{"scope_file_loaded", "scope file loaded"}, {"target_plan_generated", "target plan generated"}} {
			if _, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,$2,'targeting',$3,$4,$5,$6)`, domain.NewID(), event.eventType, actor, snapshot.ProgramID, event.message, mustJSON(map[string]string{"scope_digest": snapshot.ScopeDigest, "target_plan_digest": snapshot.TargetPlanDigest})); err != nil {
				return change, err
			}
		}
		if err := auditPlanDerivations(ctx, tx, snapshot, actor); err != nil {
			return change, err
		}
		return change, tx.Commit(ctx)
	}
	change.Acknowledged = !change.ExpandsScope || acknowledgeExpansion
	now := time.Now().UTC()
	snapshot.ID = domain.NewID()
	snapshot.ExpandsScope = change.ExpandsScope
	snapshot.AddedIncludeDigests = change.AddedIncludeDigests
	snapshot.RemovedIncludeDigests = change.RemovedIncludeDigests
	snapshot.AddedExcludeDigests = change.AddedExcludeDigests
	snapshot.RemovedExcludeDigests = change.RemovedExcludeDigests
	snapshot.CreatedAt = now
	var acknowledgedAt any
	var acknowledgedBy any
	if change.Acknowledged {
		acknowledgedAt, acknowledgedBy = now, actor
	}
	err = tx.QueryRow(ctx, `INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,include_rule_digests,exclude_rule_digests,target_plan_digest,planning_warnings,target_plan,expands_scope,added_include_digests,removed_include_digests,added_exclude_digests,removed_exclude_digests,acknowledged_by,acknowledged_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) ON CONFLICT(program_id,target_plan_digest) DO UPDATE SET acknowledged_by=COALESCE(scope_versions.acknowledged_by,EXCLUDED.acknowledged_by),acknowledged_at=COALESCE(scope_versions.acknowledged_at,EXCLUDED.acknowledged_at) RETURNING id`, snapshot.ID, snapshot.ProgramID, snapshot.ScopeReference, snapshot.ScopeDigest, snapshot.IncludeRuleDigests, snapshot.ExcludeRuleDigests, snapshot.TargetPlanDigest, snapshot.PlanningWarnings, snapshot.TargetPlan, snapshot.ExpandsScope, snapshot.AddedIncludeDigests, snapshot.RemovedIncludeDigests, snapshot.AddedExcludeDigests, snapshot.RemovedExcludeDigests, acknowledgedBy, acknowledgedAt, now).Scan(&change.ScopeVersionID)
	if err != nil {
		return change, err
	}
	if change.Acknowledged {
		_, err = tx.Exec(ctx, `UPDATE programs SET scope_reference=$2,scope_digest=$3,include_rule_digests=$4,exclude_rule_digests=$5,target_plan_digest=$6,scope_plan_warnings=$7,updated_at=now() WHERE id=$1`, snapshot.ProgramID, snapshot.ScopeReference, snapshot.ScopeDigest, snapshot.IncludeRuleDigests, snapshot.ExcludeRuleDigests, snapshot.TargetPlanDigest, snapshot.PlanningWarnings)
		if err != nil {
			return change, err
		}
	}
	for _, event := range []struct{ eventType, message string }{{"scope_file_loaded", "scope file loaded"}, {"target_plan_generated", "target plan generated"}, {"scope_change_detected", "scope change detected"}} {
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,$2,'targeting',$3,$4,$5,$6)`, domain.NewID(), event.eventType, actor, snapshot.ProgramID, event.message, mustJSON(change))
		if err != nil {
			return change, err
		}
	}
	if err := auditPlanDerivations(ctx, tx, snapshot, actor); err != nil {
		return change, err
	}
	return change, tx.Commit(ctx)
}

func normalizeScopeSnapshotSlices(snapshot *domain.ScopeSnapshot) {
	if snapshot.IncludeRuleDigests == nil {
		snapshot.IncludeRuleDigests = []string{}
	}
	if snapshot.ExcludeRuleDigests == nil {
		snapshot.ExcludeRuleDigests = []string{}
	}
	if snapshot.AddedIncludeDigests == nil {
		snapshot.AddedIncludeDigests = []string{}
	}
	if snapshot.RemovedIncludeDigests == nil {
		snapshot.RemovedIncludeDigests = []string{}
	}
	if snapshot.AddedExcludeDigests == nil {
		snapshot.AddedExcludeDigests = []string{}
	}
	if snapshot.RemovedExcludeDigests == nil {
		snapshot.RemovedExcludeDigests = []string{}
	}
}

func auditPlanDerivations(ctx context.Context, tx pgx.Tx, snapshot domain.ScopeSnapshot, actor string) error {
	var plan struct {
		DiscoveryRoots []map[string]any `json:"discovery_roots"`
		ExactSeeds     []map[string]any `json:"exact_active_seeds"`
		WildcardRules  []map[string]any `json:"wildcard_rules"`
	}
	if json.Unmarshal(snapshot.TargetPlan, &plan) != nil {
		return nil
	}
	for _, item := range plan.DiscoveryRoots {
		eventType := "discovery_root_derived"
		if item["source"] == "manual" {
			eventType = "discovery_root_manually_supplied"
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,$2,'targeting',$3,$4,'discovery root recorded',$5)`, domain.NewID(), eventType, actor, snapshot.ProgramID, mustJSON(item)); err != nil {
			return err
		}
	}
	for _, item := range plan.ExactSeeds {
		if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,'exact_seed_derived','targeting',$2,$3,'exact seed derived',$4)`, domain.NewID(), actor, snapshot.ProgramID, mustJSON(item)); err != nil {
			return err
		}
	}
	for _, item := range plan.WildcardRules {
		if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,'wildcard_rule_derived','targeting',$2,$3,'wildcard rule derived',$4)`, domain.NewID(), actor, snapshot.ProgramID, mustJSON(item)); err != nil {
			return err
		}
	}
	return nil
}

func difference(left, right []string) []string {
	set := map[string]bool{}
	for _, value := range right {
		set[value] = true
	}
	out := []string{}
	for _, value := range left {
		if !set[value] {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func scopeChange(previousPlan string, previousInclude, previousExclude []string, snapshot domain.ScopeSnapshot) domain.ScopeChange {
	change := domain.ScopeChange{Changed: previousPlan != snapshot.TargetPlanDigest, AddedIncludeDigests: difference(snapshot.IncludeRuleDigests, previousInclude), RemovedIncludeDigests: difference(previousInclude, snapshot.IncludeRuleDigests), AddedExcludeDigests: difference(snapshot.ExcludeRuleDigests, previousExclude), RemovedExcludeDigests: difference(previousExclude, snapshot.ExcludeRuleDigests)}
	change.ExpandsScope = previousPlan != "" && (len(change.AddedIncludeDigests) > 0 || len(change.RemovedExcludeDigests) > 0)
	return change
}
func (s *Store) CreateWorkflowDefinition(ctx context.Context, id domain.ID, name, version, description string, definition json.RawMessage) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO workflow_definitions(id,name,version,description,definition) VALUES($1,$2,$3,$4,$5) ON CONFLICT(name,version) DO UPDATE SET description=EXCLUDED.description,definition=EXCLUDED.definition`, id, name, version, description, definition)
	return err
}
func (s *Store) WorkflowDefinitionID(ctx context.Context, name, version string) (domain.ID, error) {
	var id domain.ID
	err := s.Pool.QueryRow(ctx, `SELECT id FROM workflow_definitions WHERE name=$1 AND version=$2`, name, version).Scan(&id)
	return id, err
}
func (s *Store) CreateTask(ctx context.Context, t domain.Task) error {
	return s.createTask(ctx, t, nil)
}

func (s *Store) CreateTaskWithLifecycle(ctx context.Context, t domain.Task, lifecycle func(context.Context, domain.Task) error) error {
	return s.createTask(ctx, t, lifecycle)
}

func (s *Store) createTask(ctx context.Context, t domain.Task, lifecycle func(context.Context, domain.Task) error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by,schedule_reference,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, t.ID, t.ProgramID, t.Objective, t.WorkflowDefinitionID, t.Status, t.RequestedBy, t.ScheduleReference, t.CreatedAt, t.UpdatedAt); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,safe_message,details) VALUES($1,'task_created','platform',$2,$3,'task created',$4)`, domain.NewID(), t.RequestedBy, t.ID, mustJSON(t)); err != nil {
		return err
	}
	if lifecycle != nil {
		if err := lifecycle(contextWithTransaction(ctx, tx), t); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func (s *Store) ListTasks(ctx context.Context) ([]domain.Task, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,program_id,objective,workflow_definition_id,status,requested_by,created_at,updated_at,schedule_reference,cancelled_at,cancellation_reason FROM tasks ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Task
	for rows.Next() {
		var t domain.Task
		if err := rows.Scan(&t.ID, &t.ProgramID, &t.Objective, &t.WorkflowDefinitionID, &t.Status, &t.RequestedBy, &t.CreatedAt, &t.UpdatedAt, &t.ScheduleReference, &t.CancelledAt, &t.CancellationReason); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
func (s *Store) GetTask(ctx context.Context, id domain.ID) (domain.Task, error) {
	var t domain.Task
	err := s.Pool.QueryRow(ctx, `SELECT id,program_id,objective,workflow_definition_id,status,requested_by,created_at,updated_at,schedule_reference,cancelled_at,cancellation_reason FROM tasks WHERE id=$1`, id).Scan(&t.ID, &t.ProgramID, &t.Objective, &t.WorkflowDefinitionID, &t.Status, &t.RequestedBy, &t.CreatedAt, &t.UpdatedAt, &t.ScheduleReference, &t.CancelledAt, &t.CancellationReason)
	return t, err
}
func (s *Store) SetTaskStatus(ctx context.Context, id domain.ID, status domain.TaskStatus, reason string) error {
	var cancelled any
	if status == domain.TaskCancelled {
		cancelled = time.Now().UTC()
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE tasks SET status=$2,updated_at=now(),cancelled_at=COALESCE($3,cancelled_at),cancellation_reason=CASE WHEN $4<>'' THEN $4 ELSE cancellation_reason END WHERE id=$1`, id, status, cancelled, reason)
	if err == nil && tag.RowsAffected() == 0 {
		return fmt.Errorf("task %s not found", id)
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,safe_message,details) VALUES($1,'task_status_changed','platform','human',$2,$3,$4)`, domain.NewID(), id, "task status changed", mustJSON(map[string]any{"status": status, "reason": reason})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) SetTaskStatusFromWorkflow(ctx context.Context, id domain.ID, status domain.TaskStatus) error {
	var cancelled any
	if status == domain.TaskCancelled {
		cancelled = time.Now().UTC()
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE tasks
		SET status=$2,
		    updated_at=now(),
		    cancelled_at=COALESCE($3,cancelled_at),
		    cancellation_reason=CASE WHEN $2='cancelled' AND cancellation_reason='' THEN 'workflow was cancelled' ELSE cancellation_reason END
		WHERE id=$1 AND status IN ('pending','running','paused')`, id, status, cancelled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var current domain.TaskStatus
		if err := tx.QueryRow(ctx, `SELECT status FROM tasks WHERE id=$1`, id).Scan(&current); err != nil {
			return err
		}
		if current == domain.TaskCompleted || current == domain.TaskFailed || current == domain.TaskCancelled {
			return tx.Commit(ctx)
		}
		return fmt.Errorf("task %s cannot transition from %s to %s", id, current, status)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,safe_message,details) VALUES($1,'task_status_changed','workflow','workflow',$2,'task status reconciled from workflow',$3)`, domain.NewID(), id, mustJSON(map[string]any{"status": status})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CreateWorkflowRun(ctx context.Context, r domain.WorkflowRun) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,completed_at,previous_run_id,trigger_source,summary) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, r.ID, r.TaskID, r.WorkflowDefinitionID, r.WorkflowVersion, r.Status, r.StartedAt, r.CompletedAt, r.PreviousRunID, r.TriggerSource, r.Summary)
	return err
}
func (s *Store) GetWorkflowRun(ctx context.Context, id domain.ID) (domain.WorkflowRun, error) {
	var r domain.WorkflowRun
	err := s.Pool.QueryRow(ctx, `SELECT id,task_id,workflow_definition_id,workflow_version,status,started_at,completed_at,previous_run_id,trigger_source,summary FROM workflow_runs WHERE id=$1`, id).Scan(&r.ID, &r.TaskID, &r.WorkflowDefinitionID, &r.WorkflowVersion, &r.Status, &r.StartedAt, &r.CompletedAt, &r.PreviousRunID, &r.TriggerSource, &r.Summary)
	return r, err
}

type ApprovalListItem struct {
	ID              domain.ID  `json:"id"`
	RequestID       domain.ID  `json:"request_id"`
	TaskID          domain.ID  `json:"task_id"`
	ActionRequestID domain.ID  `json:"action_request_id"`
	Risk            string     `json:"risk"`
	Reason          string     `json:"reason"`
	RequestedAt     time.Time  `json:"requested_at"`
	Decision        string     `json:"decision"`
	DecidedBy       *string    `json:"decided_by"`
	DecidedAt       *time.Time `json:"decided_at"`
	ExpiresAt       *time.Time `json:"expires_at"`
}

func (s *Store) ListApprovals(ctx context.Context) ([]ApprovalListItem, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,request_id,task_id,action_request_id,requested_risk_level,reason,requested_at,decision,decided_by,decided_at,expires_at FROM approvals ORDER BY requested_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ApprovalListItem
	for rows.Next() {
		var item ApprovalListItem
		var rawID, rawRequestID, rawTaskID, rawActionRequestID any
		if err := rows.Scan(&rawID, &rawRequestID, &rawTaskID, &rawActionRequestID, &item.Risk, &item.Reason, &item.RequestedAt, &item.Decision, &item.DecidedBy, &item.DecidedAt, &item.ExpiresAt); err != nil {
			return nil, err
		}
		if err := assignApprovalUUIDs(&item, rawID, rawRequestID, rawTaskID, rawActionRequestID); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func assignApprovalUUIDs(item *ApprovalListItem, rawID, rawRequestID, rawTaskID, rawActionRequestID any) error {
	for _, field := range []struct {
		name   string
		raw    any
		target *domain.ID
	}{
		{name: "id", raw: rawID, target: &item.ID},
		{name: "request_id", raw: rawRequestID, target: &item.RequestID},
		{name: "task_id", raw: rawTaskID, target: &item.TaskID},
		{name: "action_request_id", raw: rawActionRequestID, target: &item.ActionRequestID},
	} {
		value, err := approvalUUID(field.raw, field.name, false)
		if err != nil {
			return err
		}
		*field.target = *value
	}
	return nil
}

func approvalUUID(value any, field string, optional bool) (*domain.ID, error) {
	if value == nil {
		if optional {
			return nil, nil
		}
		return nil, fmt.Errorf("approval %s: UUID is required", field)
	}
	var raw []byte
	switch value := value.(type) {
	case [16]byte:
		raw = value[:]
	case []byte:
		raw = value
	case domain.ID:
		decoded, err := decodeUUIDString(string(value))
		if err != nil {
			return nil, fmt.Errorf("approval %s: %w", field, err)
		}
		raw = decoded
	case string:
		decoded, err := decodeUUIDString(value)
		if err != nil {
			return nil, fmt.Errorf("approval %s: %w", field, err)
		}
		raw = decoded
	default:
		return nil, fmt.Errorf("approval %s: unsupported UUID value type %T", field, value)
	}
	if len(raw) != 16 {
		return nil, fmt.Errorf("approval %s: UUID byte length is %d, want 16", field, len(raw))
	}
	id := domain.ID(hex.EncodeToString(raw[0:4]) + "-" + hex.EncodeToString(raw[4:6]) + "-" + hex.EncodeToString(raw[6:8]) + "-" + hex.EncodeToString(raw[8:10]) + "-" + hex.EncodeToString(raw[10:16]))
	return &id, nil
}

func decodeUUIDString(value string) ([]byte, error) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return nil, fmt.Errorf("UUID string must use 8-4-4-4-12 canonical form")
	}
	decoded, err := hex.DecodeString(value[0:8] + value[9:13] + value[14:18] + value[19:23] + value[24:36])
	if err != nil {
		return nil, fmt.Errorf("invalid UUID string: %w", err)
	}
	return decoded, nil
}

func (s *Store) DecideApproval(ctx context.Context, id domain.ID, decision, actor string) error {
	if decision != "approved" && decision != "rejected" {
		return fmt.Errorf("invalid decision")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var stepID, workflowRunID, taskID, programID domain.ID
	if err := tx.QueryRow(ctx, `SELECT a.request_id,sr.workflow_run_id,wr.task_id,t.program_id
		FROM approvals a
		JOIN step_runs sr ON sr.id=a.request_id
		JOIN workflow_runs wr ON wr.id=sr.workflow_run_id
		JOIN tasks t ON t.id=wr.task_id
		WHERE a.id=$1`, id).Scan(&stepID, &workflowRunID, &taskID, &programID); err != nil {
		return err
	}
	var scheduledExecution domain.ScheduledExecution
	var scheduledProgramID domain.ID
	var hasScheduledExecution bool
	if decision == "rejected" {
		scheduledExecution, scheduledProgramID, hasScheduledExecution, err = lockedScheduledExecutionByWorkflow(ctx, tx, workflowRunID)
		if err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE approvals SET decision=$2,decided_by=$3,decided_at=now() WHERE id=$1 AND decision='pending'`, id, decision, actor)
	if err == nil && tag.RowsAffected() == 0 {
		return fmt.Errorf("pending approval %s not found", id)
	}
	if err != nil {
		return err
	}
	eventType := "moderate_approval_rejected"
	if decision == "approved" {
		eventType = "moderate_approval_accepted"
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,safe_message,details) VALUES($1,$2,'platform',$3,$4,$5,$6,$7,'moderate approval decided',$8)`, domain.NewID(), eventType, actor, taskID, programID, workflowRunID, stepID, mustJSON(map[string]string{"decision": decision})); err != nil {
		return err
	}
	if decision == "rejected" {
		now := time.Now().UTC()
		stepTag, updateErr := tx.Exec(ctx, `UPDATE step_runs
			SET status='failed',
			    approval_state='rejected',
			    error_classification='approval_rejected',
			    error_details='moderate step approval was rejected',
			    completed_at=$2
			WHERE id=$1 AND status='awaiting_approval'`, stepID, now)
		if updateErr != nil {
			return updateErr
		}
		if stepTag.RowsAffected() != 1 {
			return fmt.Errorf("approval step %s is not awaiting approval", stepID)
		}
		runTag, updateErr := tx.Exec(ctx, `UPDATE workflow_runs SET status='failed',completed_at=$2 WHERE id=$1 AND status IN ('running','paused')`, workflowRunID, now)
		if updateErr != nil {
			return updateErr
		}
		if runTag.RowsAffected() != 1 {
			return fmt.Errorf("workflow run %s cannot be rejected", workflowRunID)
		}
		taskTag, updateErr := tx.Exec(ctx, `UPDATE tasks SET status='failed',updated_at=$2 WHERE id=$1 AND status IN ('pending','running','paused')`, taskID, now)
		if updateErr != nil {
			return updateErr
		}
		if taskTag.RowsAffected() != 1 {
			return fmt.Errorf("task %s cannot be rejected", taskID)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,safe_message,details) VALUES($1,'workflow_approval_rejected','workflow',$2,$3,$4,$5,$6,'workflow closed after approval rejection',$7)`, domain.NewID(), actor, taskID, programID, workflowRunID, stepID, mustJSON(map[string]any{"status": domain.RunFailed, "reason": "approval_rejected"})); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,safe_message,details) VALUES($1,'task_status_changed','platform',$2,$3,$4,$5,'task failed after approval rejection',$6)`, domain.NewID(), actor, taskID, programID, workflowRunID, mustJSON(map[string]any{"status": domain.TaskFailed, "reason": "approval_rejected"})); err != nil {
			return err
		}
		if hasScheduledExecution {
			if err := rejectLockedScheduledExecutionForApproval(ctx, tx, scheduledExecution, scheduledProgramID, actor); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}
func (s *Store) StepApproved(ctx context.Context, stepID domain.ID) (bool, error) {
	var approved bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM approvals WHERE request_id=$1 AND decision='approved' AND (expires_at IS NULL OR expires_at>now()))`, stepID).Scan(&approved)
	return approved, err
}
func (s *Store) StepApprovalDecision(ctx context.Context, stepID domain.ID) (string, error) {
	var decision string
	err := s.Pool.QueryRow(ctx, `SELECT decision FROM approvals WHERE request_id=$1`, stepID).Scan(&decision)
	return decision, err
}

func (s *Store) RecordVerification(ctx context.Context, candidateID domain.ID, independentProvider string, verification findings.Verification, evidenceArtifactIDs []domain.ID) (domain.ID, error) {
	if candidateID == "" {
		return "", fmt.Errorf("candidate id is required")
	}
	if strings.TrimSpace(independentProvider) == "" {
		return "", fmt.Errorf("independent provider is required")
	}
	if strings.TrimSpace(verification.Playbook) == "" {
		return "", fmt.Errorf("verification playbook is required")
	}
	if strings.TrimSpace(verification.Summary) == "" {
		return "", fmt.Errorf("verification summary is required")
	}
	if !validVerificationVerdict(verification.Verdict) || !validEvidenceVerdict(verification.EvidenceVerdict) || !validImpactVerdict(verification.ImpactVerdict) {
		return "", fmt.Errorf("verification verdicts are invalid")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	id := domain.NewID()
	if _, err := tx.Exec(ctx, `INSERT INTO verification_results(id,candidate_id,playbook,independent_provider,verdict,evidence_verdict,impact_verdict,summary,evidence_artifact_ids) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, candidateID, verification.Playbook, independentProvider, verification.Verdict, verification.EvidenceVerdict, verification.ImpactVerdict, verification.Summary, idStrings(evidenceArtifactIDs)); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,safe_message,details) SELECT $1,'verification_recorded','findings',$2,cf.task_id,t.program_id,cf.workflow_run_id,'verification verdict recorded',$3 FROM candidate_findings cf JOIN tasks t ON t.id=cf.task_id WHERE cf.id=$4`, domain.NewID(), independentProvider, mustJSON(map[string]any{"candidate_id": candidateID, "verification_id": id, "playbook": verification.Playbook, "verdict": verification.Verdict, "evidence_verdict": verification.EvidenceVerdict, "impact_verdict": verification.ImpactVerdict}), candidateID); err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}

func (s *Store) PromoteVerifiedFinding(ctx context.Context, candidateID domain.ID, actor string) (domain.ID, error) {
	if candidateID == "" {
		return "", fmt.Errorf("candidate id is required")
	}
	if strings.TrimSpace(actor) == "" {
		actor = "verification"
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var programID, assetID domain.ID
	var title, severity, impact string
	err = tx.QueryRow(ctx, `WITH latest AS (
		SELECT summary,evidence_verdict,impact_verdict
		FROM verification_results
		WHERE candidate_id=$1
		ORDER BY created_at DESC,id DESC
		LIMIT 1
	)
	SELECT t.program_id,cf.target_asset_id,cf.claimed_vulnerability,cf.severity,latest.summary
	FROM candidate_findings cf
	JOIN tasks t ON t.id=cf.task_id
	JOIN latest ON latest.evidence_verdict='observed' AND latest.impact_verdict='confirmed'
	WHERE cf.id=$1`, candidateID).Scan(&programID, &assetID, &title, &severity, &impact)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("candidate %s does not have observed evidence with confirmed impact", candidateID)
	}
	if err != nil {
		return "", err
	}
	id := domain.NewID()
	if err := tx.QueryRow(ctx, `INSERT INTO verified_findings(id,candidate_id,program_id,asset_id,title,severity,status,impact_statement) VALUES($1,$2,$3,$4,$5,$6,'open',$7) ON CONFLICT(candidate_id) DO UPDATE SET title=EXCLUDED.title,severity=EXCLUDED.severity,impact_statement=EXCLUDED.impact_statement,last_verified_at=now() RETURNING id`, id, candidateID, programID, assetID, title, severity, impact).Scan(&id); err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, `UPDATE candidate_findings SET status='confirmed',updated_at=now() WHERE id=$1`, candidateID); err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details) VALUES($1,'verified_finding_promoted','findings',$2,$3,'verified finding promoted',$4)`, domain.NewID(), actor, programID, mustJSON(map[string]any{"candidate_id": candidateID, "verified_finding_id": id})); err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}

func (s *Store) AlreadySucceeded(ctx context.Context, key string) (bool, error) {
	var ok bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM step_runs WHERE idempotency_key=$1 AND status='succeeded')`, key).Scan(&ok)
	return ok, err
}

func (s *Store) RecordPolicyDecision(ctx context.Context, record capability.PolicyDecisionRecord) error {
	eventType := map[policy.Decision]string{policy.Allow: "policy_allowed", policy.Deny: "policy_denied", policy.RequireApproval: "policy_approval_required"}[record.Evaluation.Decision]
	if eventType == "" {
		eventType = "policy_decision"
	}
	message := "policy " + string(record.Evaluation.Decision) + " for capability " + record.Action.Capability
	details := mustJSON(map[string]any{
		"policy_id":    record.PolicyID,
		"phase":        record.Phase,
		"decision":     record.Evaluation.Decision,
		"reason":       record.Evaluation.Reason,
		"requirements": record.Requirements,
	})
	_, err := s.Pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,capability,provider,safe_message,details) VALUES($1,$2,'policy',$3,$4,$5,$6,$7,$8,$9,$10,$11)`, domain.NewID(), eventType, policyActor(record), optionalID(record.Action.TaskID), optionalID(record.ProgramID), optionalID(record.Action.WorkflowRunID), optionalID(record.Action.StepRunID), record.Action.Capability, record.Provider, message, details)
	return err
}

func (s *Store) PersistResult(ctx context.Context, programID domain.ID, step domain.StepRun, tool *domain.ToolRun, artifacts []domain.Artifact, result domain.ActionResult) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE step_runs SET status=$2,output=$3,error_classification=$4,error_details=$5,completed_at=$6 WHERE id=$1`, step.ID, step.Status, step.Output, step.ErrorClassification, step.ErrorDetails, step.CompletedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("step run %s does not exist", step.ID)
	}
	if tool != nil {
		_, err = tx.Exec(ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,tool_version,sanitized_arguments,execution_environment,started_at,completed_at,exit_code,timed_out,stdout_artifact_id,stderr_artifact_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(id) DO NOTHING`, tool.ID, tool.StepRunID, tool.Capability, tool.Provider, tool.ToolVersion, tool.SanitizedArguments, tool.ExecutionEnvironment, tool.StartedAt, tool.CompletedAt, tool.ExitCode, tool.TimedOut, tool.StdoutArtifactID, tool.StderrArtifactID)
		if err != nil {
			return err
		}
	}
	for _, a := range artifacts {
		_, err = tx.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,storage_location,created_at,expires_at,redaction_state,sensitive) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(id) DO NOTHING`, a.ID, a.TaskID, a.WorkflowRunID, a.StepRunID, a.ToolRunID, a.Type, a.ContentType, a.Size, a.SHA256, a.StorageLocation, a.CreatedAt, a.ExpiresAt, a.RedactionState, a.Sensitive)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,tool_run_id,capability,provider,safe_message,details) VALUES($1,'artifact_retention_applied','retention','worker',$2,$3,$4,$5,$6,$7,$8,'artifact retention recorded',$9)`, domain.NewID(), a.TaskID, programID, a.WorkflowRunID, a.StepRunID, a.ToolRunID, step.Capability, providerName(tool), mustJSON(map[string]any{"artifact_id": a.ID, "expires_at": a.ExpiresAt}))
		if err != nil {
			return err
		}
	}
	if step.Status == domain.StepSucceeded {
		if err := persistObservations(ctx, tx, programID, step, result, artifacts); err != nil {
			return err
		}
		if step.Capability == "scan.nuclei" {
			if err := persistCandidates(ctx, tx, programID, step, result, artifacts); err != nil {
				return err
			}
		}
		if step.Capability == "report.changes" {
			if err := persistChangeItemsFromResult(ctx, tx, programID, step.WorkflowRunID, nil, result.Output); err != nil {
				return err
			}
		}
		if step.Capability == "classify.endpoint" {
			if err := persistEndpoints(ctx, tx, programID, result.Output); err != nil {
				return err
			}
		}
	}
	details, _ := json.Marshal(result)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,workflow_run_id,step_run_id,tool_run_id,capability,provider,safe_message,details) SELECT $1,'tool_execution','worker','worker',wr.task_id,$2,$3,$4,$5,$6,$7,$8 FROM workflow_runs wr WHERE wr.id=$2`, domain.NewID(), step.WorkflowRunID, step.ID, toolID(tool), step.Capability, providerName(tool), result.Summary, details)
	if err != nil {
		return err
	}
	if err := persistTargetDecisions(ctx, tx, programID, step, tool, result.Output); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func persistTargetDecisions(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, tool *domain.ToolRun, raw json.RawMessage) error {
	var payload struct {
		Authorized []string `json:"authorized"`
		Filtered   []struct {
			Target string `json:"target"`
			Reason string `json:"reason"`
		} `json:"filtered"`
	}
	if json.Unmarshal(raw, &payload) != nil {
		return nil
	}
	for _, target := range payload.Authorized {
		_, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,workflow_run_id,step_run_id,tool_run_id,capability,provider,safe_message,details) VALUES($1,'target_accepted','targeting','worker',$2,$3,$4,$5,$6,$7,'target accepted',$8)`, domain.NewID(), programID, step.WorkflowRunID, step.ID, toolID(tool), step.Capability, providerName(tool), mustJSON(map[string]string{"target": target}))
		if err != nil {
			return err
		}
	}
	for _, item := range payload.Filtered {
		eventType := "target_filtered"
		switch item.Reason {
		case "matched_exclusion":
			eventType = "exclusion_matched"
		case "protocol_not_authorized", "port_not_authorized":
			eventType = "protocol_or_port_rejected"
		}
		_, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,workflow_run_id,step_run_id,tool_run_id,capability,provider,safe_message,details) VALUES($1,$2,'targeting','worker',$3,$4,$5,$6,$7,$8,'target filtered',$9)`, domain.NewID(), eventType, programID, step.WorkflowRunID, step.ID, toolID(tool), step.Capability, providerName(tool), mustJSON(item))
		if err != nil {
			return err
		}
	}
	return nil
}

func persistObservations(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, result domain.ActionResult, artifacts []domain.Artifact) error {
	assetType := map[string]string{"discover.subdomains": "subdomain", "resolve.dns": "subdomain", "scan.ports": "network_service", "probe.http": "http_service", "crawl.web": "url", "discover.archive_urls": "url"}[step.Capability]
	if assetType == "" {
		return nil
	}
	for _, line := range observationLines(result.Output) {
		value := extractValue(line)
		if value == "" {
			continue
		}
		assetID := domain.NewID()
		if err := tx.QueryRow(ctx, `INSERT INTO assets(id,program_id,type,canonical_value) VALUES($1,$2,$3,$4) ON CONFLICT(program_id,type,canonical_value) DO UPDATE SET updated_at=now() RETURNING id`, assetID, programID, assetType, value).Scan(&assetID); err != nil {
			return err
		}
		metadata := json.RawMessage(line)
		if !json.Valid(metadata) {
			metadata, _ = json.Marshal(map[string]string{"value": line})
		}
		evidence := artifactStrings(artifacts)
		_, err := tx.Exec(ctx, `INSERT INTO asset_observations(id,asset_id,workflow_run_id,source_capability,observed_value,metadata,first_seen_at,observed_at,confidence,evidence_artifact_ids) VALUES($1,$2,$3,$4,$5,$6,now(),now(),$7,$8) ON CONFLICT(asset_id,workflow_run_id,source_capability,observed_value) DO UPDATE SET metadata=EXCLUDED.metadata,observed_at=EXCLUDED.observed_at,evidence_artifact_ids=EXCLUDED.evidence_artifact_ids`, domain.NewID(), assetID, step.WorkflowRunID, step.Capability, value, metadata, 1.0, evidence)
		if err != nil {
			return err
		}
	}
	return nil
}
func persistCandidates(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, result domain.ActionResult, artifacts []domain.Artifact) error {
	for _, line := range outputLines(result.Output) {
		var match map[string]any
		if json.Unmarshal([]byte(line), &match) != nil {
			continue
		}
		templateID := stringField(match, "template-id", "templateID", "template")
		target := stringField(match, "matched-at", "matched", "host", "url")
		if templateID == "" || target == "" {
			continue
		}
		name, severity := "Nuclei scanner match", "unknown"
		if info, ok := match["info"].(map[string]any); ok {
			name = stringField(info, "name")
			severity = stringField(info, "severity")
		}
		assetID := domain.NewID()
		if err := tx.QueryRow(ctx, `INSERT INTO assets(id,program_id,type,canonical_value) VALUES($1,$2,'url',$3) ON CONFLICT(program_id,type,canonical_value) DO UPDATE SET updated_at=now() RETURNING id`, assetID, programID, target).Scan(&assetID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO candidate_findings(id,task_id,workflow_run_id,target_asset_id,source_capability,template_id,claimed_vulnerability,severity,evidence_artifact_ids,detection_confidence,status) SELECT $1,wr.task_id,$2,$3,$4,$5,$6,$7,$8,$9,'new' FROM workflow_runs wr WHERE wr.id=$2 ON CONFLICT(workflow_run_id,target_asset_id,template_id) DO UPDATE SET evidence_artifact_ids=EXCLUDED.evidence_artifact_ids,updated_at=now()`, domain.NewID(), step.WorkflowRunID, assetID, step.Capability, templateID, name, severity, artifactStrings(artifacts), 0.7)
		if err != nil {
			return err
		}
		evidence := make([]domain.ID, 0, len(artifacts))
		for _, artifact := range artifacts {
			evidence = append(evidence, artifact.ID)
		}
		if item, ok := changes.CandidateFromLine(line, evidence, time.Now().UTC()); ok {
			if err := persistChangeItems(ctx, tx, programID, step.WorkflowRunID, nil, []changes.Item{item}); err != nil {
				return err
			}
		}
	}
	return nil
}

func persistChangeItemsFromResult(ctx context.Context, tx pgx.Tx, programID, workflowRunID domain.ID, scheduledExecutionID *domain.ID, raw json.RawMessage) error {
	items, err := changes.FromReportRaw(raw, time.Now().UTC())
	if err != nil {
		return err
	}
	return persistChangeItems(ctx, tx, programID, workflowRunID, scheduledExecutionID, items)
}

func persistChangeItems(ctx context.Context, tx pgx.Tx, programID, workflowRunID domain.ID, scheduledExecutionID *domain.ID, items []changes.Item) error {
	if scheduledExecutionID == nil {
		var err error
		scheduledExecutionID, err = scheduledExecutionIDForWorkflow(ctx, tx, workflowRunID)
		if err != nil {
			return err
		}
	}
	for _, item := range items {
		reasons, _ := json.Marshal(item.Reasons)
		if len(item.Previous) == 0 {
			item.Previous = nil
		}
		if len(item.Current) == 0 {
			item.Current = nil
		}
		if item.ObservedAt.IsZero() {
			item.ObservedAt = time.Now().UTC()
		}
		_, err := tx.Exec(ctx, `INSERT INTO change_items(id,program_id,workflow_run_id,scheduled_execution_id,kind,entity_type,entity_key,priority,title,safe_summary,reasons,previous_value,current_value,source_capabilities,evidence_artifact_ids,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT(workflow_run_id,kind,entity_type,entity_key) DO NOTHING`, domain.NewID(), programID, workflowRunID, scheduledExecutionID, item.Kind, item.EntityType, item.EntityKey, item.Priority, item.Title, item.Summary, reasons, item.Previous, item.Current, item.SourceCapabilities, idStrings(item.EvidenceArtifactIDs), item.ObservedAt)
		if err != nil {
			return err
		}
	}
	return nil
}

func scheduledExecutionIDForWorkflow(ctx context.Context, tx pgx.Tx, workflowRunID domain.ID) (*domain.ID, error) {
	var id domain.ID
	err := tx.QueryRow(ctx, `SELECT id FROM scheduled_executions WHERE workflow_run_id=$1`, workflowRunID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}
func outputLines(raw json.RawMessage) []string {
	var v struct {
		Lines []string `json:"lines"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	return v.Lines
}
func observationLines(raw json.RawMessage) []string {
	var payload struct {
		AuthorizedRecords []json.RawMessage `json:"authorized_records"`
	}
	if json.Unmarshal(raw, &payload) == nil && len(payload.AuthorizedRecords) > 0 {
		out := make([]string, 0, len(payload.AuthorizedRecords))
		for _, record := range payload.AuthorizedRecords {
			if json.Valid(record) {
				out = append(out, string(record))
			}
		}
		return out
	}
	return outputLines(raw)
}
func extractValue(line string) string {
	var v map[string]any
	if json.Unmarshal([]byte(line), &v) == nil {
		if s := stringField(v, "target", "url", "input", "host", "ip", "matched-at"); s != "" {
			return s
		}
	}
	return strings.TrimSpace(line)
}
func stringField(v map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := v[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
func artifactStrings(items []domain.Artifact) []string {
	out := make([]string, 0, len(items))
	for _, a := range items {
		out = append(out, string(a.ID))
	}
	return out
}
func idStrings(items []domain.ID) []string {
	out := make([]string, 0, len(items))
	for _, id := range items {
		out = append(out, string(id))
	}
	return out
}

func validVerificationVerdict(value findings.Verdict) bool {
	switch value {
	case findings.VerdictConfirmed, findings.VerdictRejected, findings.VerdictInconclusive, findings.VerdictManual:
		return true
	default:
		return false
	}
}

func validEvidenceVerdict(value findings.EvidenceVerdict) bool {
	switch value {
	case findings.EvidenceObserved, findings.EvidenceNotObserved, findings.EvidenceInconclusive:
		return true
	default:
		return false
	}
}

func validImpactVerdict(value findings.ImpactVerdict) bool {
	switch value {
	case findings.ImpactUnreviewed, findings.ImpactConfirmed, findings.ImpactRejected:
		return true
	default:
		return false
	}
}

func persistEndpoints(ctx context.Context, tx pgx.Tx, programID domain.ID, raw json.RawMessage) error {
	var payload struct {
		Endpoints []normalize.EndpointKey `json:"endpoints"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return err
	}
	for _, e := range payload.Endpoints {
		params, _ := json.Marshal(e.QueryParameters)
		_, err := tx.Exec(ctx, `INSERT INTO endpoints(id,program_id,exact_url,route_signature,method,content_type,parameter_schema,first_seen,last_seen) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,now(),now()) ON CONFLICT(program_id,route_signature,method,content_type,parameter_schema) DO UPDATE SET exact_url=EXCLUDED.exact_url,last_seen=now()`, domain.NewID(), programID, e.ExactURL, e.RouteSignature, e.Method, e.ContentType, string(params))
		if err != nil {
			return err
		}
	}
	return nil
}
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
func toolID(t *domain.ToolRun) any {
	if t == nil {
		return nil
	}
	return t.ID
}
func providerName(t *domain.ToolRun) string {
	if t == nil {
		return "platform"
	}
	return t.Provider
}

func optionalID(id domain.ID) any {
	if id == "" {
		return nil
	}
	return id
}

func policyActor(record capability.PolicyDecisionRecord) string {
	if value := strings.TrimSpace(record.Action.RequestedBy); value != "" {
		return value
	}
	if value := strings.TrimSpace(record.Phase); value != "" {
		return value
	}
	return "platform"
}

func (s *Store) ExpiredArtifacts(ctx context.Context, limit int) ([]domain.Artifact, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,storage_location,created_at,expires_at,redaction_state,sensitive FROM artifacts WHERE expires_at IS NOT NULL AND expires_at<=now() ORDER BY expires_at,id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []domain.Artifact{}
	for rows.Next() {
		var item domain.Artifact
		if err := rows.Scan(&item.ID, &item.TaskID, &item.WorkflowRunID, &item.StepRunID, &item.ToolRunID, &item.Type, &item.ContentType, &item.Size, &item.SHA256, &item.StorageLocation, &item.CreatedAt, &item.ExpiresAt, &item.RedactionState, &item.Sensitive); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) DeleteArtifact(ctx context.Context, id domain.ID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,tool_run_id,capability,provider,safe_message,details) SELECT $1,'artifact_expired','retention','retention',a.task_id,t.program_id,a.workflow_run_id,a.step_run_id,a.tool_run_id,tr.capability,tr.provider,'expired artifact removed',$2 FROM artifacts a JOIN tasks t ON t.id=a.task_id LEFT JOIN tool_runs tr ON tr.id=a.tool_run_id WHERE a.id=$3 AND a.expires_at IS NOT NULL AND a.expires_at<=now()`, domain.NewID(), mustJSON(map[string]any{"artifact_id": id}), id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("expired artifact %s not found", id)
	}
	for _, statement := range []string{
		`UPDATE tool_runs SET stdout_artifact_id=NULL WHERE stdout_artifact_id=$1`,
		`UPDATE tool_runs SET stderr_artifact_id=NULL WHERE stderr_artifact_id=$1`,
		`UPDATE asset_observations SET evidence_artifact_ids=array_remove(evidence_artifact_ids,$1) WHERE $1=ANY(evidence_artifact_ids)`,
		`UPDATE candidate_findings SET evidence_artifact_ids=array_remove(evidence_artifact_ids,$1) WHERE $1=ANY(evidence_artifact_ids)`,
		`UPDATE verification_results SET evidence_artifact_ids=array_remove(evidence_artifact_ids,$1) WHERE $1=ANY(evidence_artifact_ids)`,
	} {
		if _, err := tx.Exec(ctx, statement, id); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM artifacts WHERE id=$1 AND expires_at IS NOT NULL AND expires_at<=now()`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) LatestChanges(ctx context.Context, programID domain.ID) (json.RawMessage, error) {
	var summary json.RawMessage
	err := s.Pool.QueryRow(ctx, `SELECT wr.summary FROM workflow_runs wr JOIN tasks t ON t.id=wr.task_id WHERE t.program_id=$1 AND wr.status='completed' ORDER BY wr.completed_at DESC NULLS LAST LIMIT 1`, programID).Scan(&summary)
	return summary, err
}
func (s *Store) PreviousObservationValues(ctx context.Context, programID, currentRunID domain.ID, capabilityName string) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `WITH previous_run AS (SELECT wr.id FROM workflow_runs wr JOIN tasks t ON t.id=wr.task_id WHERE t.program_id=$1 AND wr.status='completed' AND wr.id<>$2 ORDER BY wr.completed_at DESC NULLS LAST LIMIT 1) SELECT ao.metadata, ao.observed_value FROM asset_observations ao JOIN previous_run pr ON pr.id=ao.workflow_run_id WHERE ao.source_capability=$3 ORDER BY ao.observed_value`, programID, currentRunID, capabilityName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var metadata json.RawMessage
		var observedValue string
		if err := rows.Scan(&metadata, &observedValue); err != nil {
			return nil, err
		}
		out = append(out, previousObservationValue(metadata, observedValue))
	}
	return out, rows.Err()
}

func previousObservationValue(metadata json.RawMessage, observedValue string) string {
	var fields map[string]json.RawMessage
	if json.Unmarshal(metadata, &fields) == nil && len(fields) == 1 {
		var value string
		if raw, ok := fields["value"]; ok && json.Unmarshal(raw, &value) == nil && value == observedValue {
			return observedValue
		}
	}
	return string(metadata)
}

type transactionContextKey struct{}

func contextWithTransaction(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, transactionContextKey{}, tx)
}

func transactionFromContext(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(transactionContextKey{}).(pgx.Tx)
	return tx, ok
}

func (s *Store) SaveWorkflowState(ctx context.Context, state *workflow.State) error {
	return s.saveWorkflowState(ctx, state, nil)
}

func (s *Store) saveWorkflowState(ctx context.Context, state *workflow.State, lifecycle func(context.Context, *workflow.State) error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	r := state.Run
	_, err = tx.Exec(ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,completed_at,previous_run_id,trigger_source,summary) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status,started_at=EXCLUDED.started_at,completed_at=EXCLUDED.completed_at,summary=EXCLUDED.summary`, r.ID, r.TaskID, r.WorkflowDefinitionID, r.WorkflowVersion, r.Status, r.StartedAt, r.CompletedAt, r.PreviousRunID, r.TriggerSource, r.Summary)
	if err != nil {
		return err
	}
	if lifecycle != nil {
		if err := lifecycle(contextWithTransaction(ctx, tx), state); err != nil {
			return err
		}
	}
	for _, ss := range state.Steps {
		x := ss.Run
		_, err = tx.Exec(ctx, `INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,attempt_count,input,output,error_classification,error_details,started_at,completed_at,idempotency_key,approval_state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status,attempt_count=EXCLUDED.attempt_count,input=EXCLUDED.input,output=EXCLUDED.output,error_classification=EXCLUDED.error_classification,error_details=EXCLUDED.error_details,started_at=EXCLUDED.started_at,completed_at=EXCLUDED.completed_at,approval_state=EXCLUDED.approval_state`, x.ID, x.WorkflowRunID, x.StepDefinitionID, x.Capability, x.Status, x.AttemptCount, x.Input, x.Output, x.ErrorClassification, x.ErrorDetails, x.StartedAt, x.CompletedAt, x.IdempotencyKey, x.ApprovalState)
		if err != nil {
			return err
		}
		if x.ApprovalState == "pending" || x.ApprovalState == "approved" {
			decision := x.ApprovalState
			var decidedBy any
			var decidedAt any
			if decision == "approved" {
				decidedBy = "workflow-operator"
				decidedAt = time.Now().UTC()
			}
			_, err = tx.Exec(ctx, `INSERT INTO approvals(id,request_id,task_id,action_request_id,requested_risk_level,reason,decision,decided_by,decided_at) VALUES($1,$2,$3,$2,'moderate',$4,$5,$6,$7) ON CONFLICT(request_id) DO UPDATE SET decision=CASE WHEN approvals.decision IN ('approved','rejected') THEN approvals.decision ELSE EXCLUDED.decision END,decided_by=COALESCE(approvals.decided_by,EXCLUDED.decided_by),decided_at=COALESCE(approvals.decided_at,EXCLUDED.decided_at)`, domain.NewID(), x.ID, state.Run.TaskID, "workflow step "+x.StepDefinitionID, decision, decidedBy, decidedAt)
			if err != nil {
				return err
			}
			if x.ApprovalState == "pending" {
				_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,capability,safe_message,details) SELECT $1,'moderate_approval_requested','workflow','workflow',$2,t.program_id,$3,$4,$5,'moderate approval requested',$6 FROM tasks t WHERE t.id=$2`, domain.NewID(), state.Run.TaskID, state.Run.ID, x.ID, x.Capability, mustJSON(map[string]string{"step": x.StepDefinitionID}))
				if err != nil {
					return err
				}
			}
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,workflow_run_id,safe_message,details) VALUES($1,$2,'workflow','workflow',$3,$4,$5,$6)`, domain.NewID(), "workflow_state", state.Run.TaskID, state.Run.ID, "workflow state persisted", mustJSON(map[string]any{"status": state.Run.Status, "event_count": len(state.Events)}))
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type WorkflowPersister struct {
	Store     *Store
	File      workflow.FileStore
	Lifecycle func(context.Context, *workflow.State) error
}

func (p WorkflowPersister) Save(ctx context.Context, state *workflow.State) error {
	if err := p.Store.saveWorkflowState(ctx, state, p.Lifecycle); err != nil {
		return err
	}
	return p.File.Save(ctx, state)
}
