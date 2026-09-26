package database

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/changes"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/findings"
	"github.com/tobiasGuta/Reconductor/internal/migrations"
	"github.com/tobiasGuta/Reconductor/internal/normalize"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
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
func (s *Store) RequireCurrentSchema(ctx context.Context) error {
	return migrations.RequireCurrent(ctx, s.Pool)
}

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

func (s *Store) ScopeTargetPlan(ctx context.Context, scopeVersionID, programID domain.ID) (targeting.TargetPlan, error) {
	var raw json.RawMessage
	var digest string
	if err := s.Pool.QueryRow(ctx, `SELECT target_plan,target_plan_digest FROM scope_versions WHERE id=$1 AND program_id=$2`, scopeVersionID, programID).Scan(&raw, &digest); err != nil {
		return targeting.TargetPlan{}, err
	}
	var plan targeting.TargetPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		return targeting.TargetPlan{}, fmt.Errorf("%w: original target plan is invalid: %v", workflow.ErrWorkflowCheckpointConflict, err)
	}
	if plan.Digest == "" || plan.Digest != digest {
		return targeting.TargetPlan{}, fmt.Errorf("%w: original target plan identity does not match its scope version", workflow.ErrWorkflowCheckpointConflict)
	}
	for _, root := range plan.DiscoveryRoots {
		if strings.TrimSpace(root.Domain) == "" || len(root.SourceRuleIDs) == 0 {
			return targeting.TargetPlan{}, fmt.Errorf("%w: original discovery root lacks deterministic source-rule provenance", workflow.ErrWorkflowCheckpointConflict)
		}
	}
	return plan, nil
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
func (s *Store) EnsureWorkflowTemplate(ctx context.Context, template workflow.Template) error {
	descriptor, err := template.Descriptor()
	if err != nil {
		return err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	createdAt := template.CreatedAt.UTC().Truncate(time.Microsecond)
	if _, err = tx.Exec(ctx, `INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, template.ID, template.Name, template.Version, template.Description, descriptor, template.DefaultPolicyRequirements, createdAt); err != nil {
		return err
	}
	type persistedTemplate struct {
		id                         domain.ID
		name, version, description string
		definition, requirements   json.RawMessage
		createdAt                  time.Time
	}
	rows, err := tx.Query(ctx, `SELECT id,name,version,description,definition,default_policy_requirements,created_at
		FROM workflow_definitions WHERE id=$1 OR (name=$2 AND version=$3) ORDER BY id FOR UPDATE`, template.ID, template.Name, template.Version)
	if err != nil {
		return err
	}
	defer rows.Close()
	persisted := make([]persistedTemplate, 0, 2)
	for rows.Next() {
		var item persistedTemplate
		if err := rows.Scan(&item.id, &item.name, &item.version, &item.description, &item.definition, &item.requirements, &item.createdAt); err != nil {
			return err
		}
		persisted = append(persisted, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(persisted) != 1 || persisted[0].id != template.ID || persisted[0].name != template.Name || persisted[0].version != template.Version {
		return fmt.Errorf("%w: id=%s name=%s version=%s", workflow.ErrWorkflowTemplateIdentityConflict, template.ID, template.Name, template.Version)
	}
	item := persisted[0]
	var definitionEqual, requirementsEqual bool
	if err := tx.QueryRow(ctx, `SELECT $1::jsonb=$2::jsonb,$3::jsonb=$4::jsonb`, item.definition, descriptor, item.requirements, template.DefaultPolicyRequirements).Scan(&definitionEqual, &requirementsEqual); err != nil {
		return err
	}
	if item.description != template.Description || !definitionEqual || !requirementsEqual || !item.createdAt.Equal(createdAt) {
		return fmt.Errorf("%w: id=%s name=%s version=%s", workflow.ErrWorkflowTemplateDefinitionConflict, template.ID, template.Name, template.Version)
	}
	return tx.Commit(ctx)
}

func (s *Store) WorkflowTemplate(ctx context.Context, id domain.ID) (workflow.Template, error) {
	var template workflow.Template
	var raw json.RawMessage
	err := s.Pool.QueryRow(ctx, `SELECT id,name,version,description,definition,default_policy_requirements,created_at FROM workflow_definitions WHERE id=$1`, id).Scan(
		&template.ID, &template.Name, &template.Version, &template.Description, &raw, &template.DefaultPolicyRequirements, &template.CreatedAt,
	)
	if err != nil {
		return workflow.Template{}, err
	}
	descriptor, err := workflow.DecodeTemplateDescriptor(raw)
	if err != nil {
		return workflow.Template{}, fmt.Errorf("%w: template %s has no supported static descriptor", workflow.ErrTaskWorkflowTemplateUnavailable, id)
	}
	template.Materializer = descriptor.Materializer
	return template, nil
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
	return s.SaveWorkflowState(ctx, &workflow.State{Run: r, Steps: map[string]*workflow.StepState{}})
}
func (s *Store) GetWorkflowRun(ctx context.Context, id domain.ID) (domain.WorkflowRun, error) {
	var r domain.WorkflowRun
	err := scanWorkflowRun(s.Pool.QueryRow(ctx, `SELECT id,task_id,workflow_definition_id,workflow_version,status,started_at,completed_at,previous_run_id,trigger_source,summary,materialized_definition,materialization_digest,original_scope_version_id FROM workflow_runs WHERE id=$1`, id), &r)
	return r, err
}

type workflowRunScanner interface {
	Scan(...any) error
}

func scanWorkflowRun(row workflowRunScanner, run *domain.WorkflowRun) error {
	var materializedDefinition []byte
	var materializationDigest pgtype.Text
	var originalScopeVersionID pgtype.UUID
	if err := row.Scan(
		&run.ID, &run.TaskID, &run.WorkflowDefinitionID, &run.WorkflowVersion, &run.Status, &run.StartedAt, &run.CompletedAt, &run.PreviousRunID, &run.TriggerSource, &run.Summary,
		&materializedDefinition, &materializationDigest, &originalScopeVersionID,
	); err != nil {
		return err
	}
	run.MaterializedDefinition = append(json.RawMessage(nil), materializedDefinition...)
	run.MaterializationDigest = ""
	if materializationDigest.Valid {
		run.MaterializationDigest = materializationDigest.String
	}
	run.OriginalScopeVersionID = nil
	if originalScopeVersionID.Valid {
		value := domain.ID(originalScopeVersionID.String())
		run.OriginalScopeVersionID = &value
	}
	return nil
}

func (s *Store) LoadWorkflowState(ctx context.Context, id domain.ID) (*workflow.State, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	state := &workflow.State{Steps: map[string]*workflow.StepState{}}
	r := &state.Run
	if err := scanWorkflowRun(tx.QueryRow(ctx, `SELECT id,task_id,workflow_definition_id,workflow_version,status,started_at,completed_at,previous_run_id,trigger_source,summary,materialized_definition,materialization_digest,original_scope_version_id FROM workflow_runs WHERE id=$1`, id), r); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT id,workflow_run_id,step_definition_id,capability,status,attempt_count,input,output,error_classification,error_details,started_at,completed_at,idempotency_key,approval_state FROM step_runs WHERE workflow_run_id=$1 ORDER BY step_definition_id,id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var run domain.StepRun
		if err := rows.Scan(&run.ID, &run.WorkflowRunID, &run.StepDefinitionID, &run.Capability, &run.Status, &run.AttemptCount, &run.Input, &run.Output, &run.ErrorClassification, &run.ErrorDetails, &run.StartedAt, &run.CompletedAt, &run.IdempotencyKey, &run.ApprovalState); err != nil {
			return nil, err
		}
		state.Steps[run.StepDefinitionID] = &workflow.StepState{Run: run, InputHash: workflow.InputDigest(run.Input)}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return state, nil
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
	return decideApprovalTx(ctx, tx, id, decision, actor)
}

func decideApprovalTx(ctx context.Context, tx pgx.Tx, id domain.ID, decision, actor string) error {
	var err error
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
		// Serialize with allocation/adoption before touching approval or lineage.
		if err := lockApprovalWorkflow(ctx, tx, workflowRunID); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE approvals SET decision=$2,decided_by=$3,decided_at=now() WHERE id=$1 AND decision='pending'`, id, decision, actor)
	if err == nil && tag.RowsAffected() == 0 {
		var existing string
		if err := tx.QueryRow(ctx, `SELECT decision FROM approvals WHERE id=$1`, id).Scan(&existing); err != nil {
			return err
		}
		if decision != "rejected" || existing != decision {
			return fmt.Errorf("pending approval %s not found", id)
		}
	}
	if err != nil {
		return err
	}
	eventType := "moderate_approval_rejected"
	if decision == "approved" {
		eventType = "moderate_approval_accepted"
	}
	if tag.RowsAffected() == 1 {
		if _, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,safe_message,details) VALUES($1,$2,'platform',$3,$4,$5,$6,$7,'moderate approval decided',$8)`, domain.NewID(), eventType, actor, taskID, programID, workflowRunID, stepID, mustJSON(map[string]string{"decision": decision})); err != nil {
			return err
		}
	}
	if decision == "rejected" {
		pending, err := hasUnresolvedWorkflowPrepared(ctx, tx, workflowRunID)
		if err != nil {
			return err
		}
		if pending {
			// The human decision commits; every execution-lineage field stays put.
			return commitApprovalDecision(ctx, tx)
		}
		var status domain.StepStatus
		if err := tx.QueryRow(ctx, `SELECT status FROM step_runs WHERE id=$1`, stepID).Scan(&status); err != nil {
			return err
		}
		if status == domain.StepFailed {
			return commitApprovalDecision(ctx, tx)
		}
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
	return commitApprovalDecision(ctx, tx)
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

func (s *Store) RecordPolicyDecision(ctx context.Context, record capability.PolicyDecisionRecord) (domain.ID, error) {
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
	eventID := domain.NewID()
	scheduledExecutionID, schedulerAttempt := providerSchedulerProvenance(ctx)
	_, err := s.Pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,capability,provider,safe_message,details) VALUES($1,$2,'policy',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, eventID, eventType, policyActor(record), optionalID(record.Action.TaskID), optionalID(record.ProgramID), optionalID(record.Action.WorkflowRunID), optionalID(record.Action.StepRunID), scheduledExecutionID, schedulerAttempt, optionalID(record.Action.ID), exactPositiveInt(record.Action.StepAttempt), optionalIDPointer(record.QueueJobID), record.Action.Capability, record.Provider, message, details)
	if err != nil {
		return "", err
	}
	return eventID, nil
}

func (s *Store) PersistResult(ctx context.Context, programID domain.ID, step domain.StepRun, tool *domain.ToolRun, artifacts []domain.Artifact, result domain.ActionResult, admission *capability.ResultAdmissionProvenance) error {
	resultCopy := result
	return s.persistResult(ctx, programID, step, tool, &resultCopy, admission, func(context.Context) ([]domain.Artifact, error) {
		return artifacts, nil
	})
}

func (s *Store) PersistResultWithArtifactPublication(ctx context.Context, programID domain.ID, step domain.StepRun, tool *domain.ToolRun, result *domain.ActionResult, admission *capability.ResultAdmissionProvenance, publish func(context.Context) ([]domain.Artifact, error)) error {
	if result == nil {
		return fmt.Errorf("result is required")
	}
	return s.persistResult(ctx, programID, step, tool, result, admission, publish)
}

func (s *Store) persistResult(ctx context.Context, programID domain.ID, step domain.StepRun, tool *domain.ToolRun, result *domain.ActionResult, admission *capability.ResultAdmissionProvenance, publish func(context.Context) ([]domain.Artifact, error)) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackResultTransaction(ctx, tx)
	if err := persistResultTransactionWithArtifactPublication(ctx, tx, programID, step, tool, result, admission, publish); err != nil {
		rejection, semantic := resultFenceRejection(err)
		if !semantic {
			return err
		}
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanupCtx); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("roll back rejected provider result: %w", rollbackErr))
		}
		if _, auditErr := s.recordProviderResultRejected(cleanupCtx, admission, rejection.reason); auditErr != nil {
			return errors.Join(err, fmt.Errorf("persist provider result rejection: %w", auditErr))
		}
		return err
	}
	return tx.Commit(ctx)
}

func rollbackResultTransaction(ctx context.Context, tx pgx.Tx) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	_ = tx.Rollback(cleanupCtx)
}

func persistResultTransaction(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, tool *domain.ToolRun, artifacts []domain.Artifact, result domain.ActionResult, admission *capability.ResultAdmissionProvenance) error {
	resultCopy := result
	return persistResultTransactionWithArtifactPublication(ctx, tx, programID, step, tool, &resultCopy, admission, func(context.Context) ([]domain.Artifact, error) {
		return artifacts, nil
	})
}

func persistResultTransactionWithArtifactPublication(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, tool *domain.ToolRun, resultPointer *domain.ActionResult, admission *capability.ResultAdmissionProvenance, publish func(context.Context) ([]domain.Artifact, error)) error {
	if resultPointer == nil {
		return fmt.Errorf("result is required")
	}
	result := *resultPointer
	lineage, err := lockResultLineage(ctx, tx, programID, step)
	if err != nil {
		return err
	}
	switch step.Status {
	case domain.StepSucceeded, domain.StepFailed, domain.StepRetryable, domain.StepCancelled:
	default:
		return resultConflict(lineage.scheduled, resultFenceInvalidResultState, "result status is not persistable")
	}
	if step.Status == domain.StepRetryable && step.CompletedAt != nil {
		return resultConflict(lineage.scheduled, resultFenceInvalidResultState, "retryable result is completed")
	}
	if (step.Status == domain.StepSucceeded || step.Status == domain.StepFailed || step.Status == domain.StepCancelled) && step.CompletedAt == nil {
		return resultConflict(lineage.scheduled, resultFenceInvalidResultState, "terminal result is not completed")
	}
	if tool != nil {
		if tool.ID == "" || tool.StepRunID != step.ID || tool.Capability != step.Capability {
			return resultConflict(lineage.scheduled, resultFenceToolLineageMismatch, "tool lineage does not match result step")
		}
	}
	if err := lockAndValidateProviderResult(ctx, tx, lineage, programID, step, tool, result, admission); err != nil {
		return err
	}
	exactProviderAttempt := admission != nil
	if lineage.stepStatus != domain.StepRunning && (!exactProviderAttempt || lineage.stepStatus != domain.StepRetryable) {
		return resultConflict(lineage.scheduled, resultFenceStepNotAdmittingResult, "step does not admit this result")
	}
	attemptCount := lineage.attemptCount
	if exactProviderAttempt {
		stepAttempt, err := lockProviderStepAttempt(ctx, tx, admission.ProviderAttemptID)
		if err != nil {
			return err
		}
		if stepAttempt != nil {
			if *stepAttempt < attemptCount {
				return resultConflict(lineage.scheduled, resultFenceStaleProviderStepAttempt, "provider step attempt is stale")
			}
			if *stepAttempt > attemptCount {
				attemptCount = *stepAttempt
			}
		}
	}
	if err := lockConflictingResultTools(ctx, tx, step.ID, tool, lineage.scheduled); err != nil {
		return err
	}
	resultSnapshot := result
	resultSnapshot.ArtifactIDs = append([]domain.ID(nil), result.ArtifactIDs...)
	var toolSnapshot *domain.ToolRun
	if tool != nil {
		copy := *tool
		copy.ArtifactIDs = append([]domain.ID(nil), tool.ArtifactIDs...)
		toolSnapshot = &copy
	}
	var artifacts []domain.Artifact
	if publish != nil {
		artifacts, err = publish(ctx)
		if err != nil {
			if tool != nil {
				*tool = *toolSnapshot
			}
			*resultPointer = resultSnapshot
			return fmt.Errorf("publish result artifacts: %w", err)
		}
	}
	if tool != nil {
		publishedArtifactIDs := append([]domain.ID(nil), tool.ArtifactIDs...)
		publishedStdoutID := tool.StdoutArtifactID
		publishedStderrID := tool.StderrArtifactID
		*tool = *toolSnapshot
		tool.ArtifactIDs = publishedArtifactIDs
		tool.StdoutArtifactID = publishedStdoutID
		tool.StderrArtifactID = publishedStderrID
	}
	publishedResultArtifactIDs := append([]domain.ID(nil), resultPointer.ArtifactIDs...)
	*resultPointer = resultSnapshot
	resultPointer.ArtifactIDs = publishedResultArtifactIDs
	result = *resultPointer
	if err := lockAndValidateResultArtifacts(ctx, tx, lineage, step, tool, artifacts); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE step_runs
		SET status=$2,output=$3,error_classification=$4,error_details=$5,completed_at=$6,attempt_count=$7
		WHERE id=$1 AND workflow_run_id=$8 AND idempotency_key=$9 AND status=$10`, step.ID, step.Status, step.Output, step.ErrorClassification, step.ErrorDetails, step.CompletedAt, attemptCount, step.WorkflowRunID, step.IdempotencyKey, lineage.stepStatus)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return resultConflict(lineage.scheduled, resultFenceConcurrentStepChange, "step changed before result persistence")
	}
	if tool != nil {
		tag, err := tx.Exec(ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,tool_version,sanitized_arguments,execution_environment,started_at,completed_at,exit_code,timed_out,stdout_artifact_id,stderr_artifact_id,provider_attempt_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (id) DO NOTHING`, tool.ID, tool.StepRunID, tool.Capability, tool.Provider, tool.ToolVersion, tool.SanitizedArguments, tool.ExecutionEnvironment, tool.StartedAt, tool.CompletedAt, tool.ExitCode, tool.TimedOut, tool.StdoutArtifactID, tool.StderrArtifactID, tool.ProviderAttemptID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return resultConflict(lineage.scheduled, resultFenceToolResultConflict, "tool result already exists")
		}
	}
	for _, a := range artifacts {
		tag, err := tx.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,storage_location,created_at,expires_at,redaction_state,sensitive) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) ON CONFLICT (id) DO NOTHING`, a.ID, a.TaskID, a.WorkflowRunID, a.StepRunID, a.ToolRunID, a.Type, a.ContentType, a.Size, a.SHA256, a.AddressingVersion, a.ArtifactStoreID, a.StorageKey, a.StorageLocation, a.CreatedAt, a.ExpiresAt, a.RedactionState, a.Sensitive)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return resultConflict(lineage.scheduled, resultFenceArtifactResultConflict, "artifact metadata already exists")
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,tool_run_id,capability,provider,safe_message,details) VALUES($1,'artifact_retention_applied','retention-policy','worker',$2,$3,$4,$5,$6,$7,$8,'artifact expiry policy assigned',$9)`, domain.NewID(), a.TaskID, programID, a.WorkflowRunID, a.StepRunID, a.ToolRunID, step.Capability, providerName(tool), mustJSON(map[string]any{"artifact_id": a.ID, "expires_at": a.ExpiresAt}))
		if err != nil {
			return err
		}
	}
	probeSources, err := prepareProbeHTTPSourceRecords(programID, step, result, admission)
	if err != nil {
		return err
	}
	observationIDs := []domain.ID{}
	if step.Status == domain.StepSucceeded {
		observationIDs, err = persistObservations(ctx, tx, programID, step, result, artifacts)
		if err != nil {
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
			if err := persistEndpoints(ctx, tx, programID, step.CompletedAt, result.Output); err != nil {
				return err
			}
		}
		if err := persistTargetDecisions(ctx, tx, programID, step, tool, result.Output); err != nil {
			return err
		}
	}
	details, _ := json.Marshal(result)
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,workflow_run_id,step_run_id,tool_run_id,action_request_id,step_attempt,queue_job_id,provider_attempt_id,capability,provider,safe_message,details)
		SELECT $1,'tool_execution','worker','worker',wr.task_id,$2,$3,$4,pa.action_request_id,pa.step_attempt,pa.queue_job_id,$5,$6,$7,$8,$9
		FROM workflow_runs wr
		LEFT JOIN audit_events pa ON pa.id=$5 AND pa.event_type='provider_invocation_started'
		WHERE wr.id=$2`, domain.NewID(), step.WorkflowRunID, step.ID, toolID(tool), providerAttemptID(tool), step.Capability, providerName(tool), result.Summary, details)
	if err != nil {
		return err
	}
	if exactProviderAttempt {
		acceptedEventID, err := persistProviderResultAccepted(ctx, tx, admission.ProviderAttemptID, tool.ID)
		if err != nil {
			return err
		}
		if step.Status == domain.StepSucceeded && len(observationIDs) > 0 {
			if err := persistAssetObservationEmissions(ctx, tx, programID, observationIDs, acceptedEventID); err != nil {
				return err
			}
		}
		if probeSources != nil {
			if err := persistProbeHTTPSourceRecords(ctx, tx, programID, step, artifacts, *probeSources, acceptedEventID); err != nil {
				return err
			}
		}
	}
	return nil
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

func persistObservations(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, result domain.ActionResult, artifacts []domain.Artifact) ([]domain.ID, error) {
	assetType := map[string]string{"discover.subdomains": "subdomain", "resolve.dns": "subdomain", "scan.ports": "network_service", "probe.http": "http_service", "crawl.web": "url", "discover.archive_urls": "url"}[step.Capability]
	if assetType == "" {
		return []domain.ID{}, nil
	}
	observationIDs := make([]domain.ID, 0)
	seenObservationIDs := make(map[domain.ID]struct{})
	for _, line := range observationLines(result.Output) {
		value := extractValue(line)
		if value == "" {
			continue
		}
		assetID := domain.NewID()
		if err := tx.QueryRow(ctx, `INSERT INTO assets(id,program_id,type,canonical_value) VALUES($1,$2,$3,$4) ON CONFLICT(program_id,type,canonical_value) DO UPDATE SET updated_at=now() RETURNING id`, assetID, programID, assetType, value).Scan(&assetID); err != nil {
			return nil, err
		}
		metadata := json.RawMessage(line)
		if !json.Valid(metadata) {
			metadata, _ = json.Marshal(map[string]string{"value": line})
		}
		evidence := artifactStrings(artifacts)
		observationID := domain.NewID()
		if err := tx.QueryRow(ctx, `INSERT INTO asset_observations(id,asset_id,workflow_run_id,source_capability,observed_value,metadata,first_seen_at,observed_at,confidence,evidence_artifact_ids) VALUES($1,$2,$3,$4,$5,$6,now(),now(),$7,$8) ON CONFLICT(asset_id,workflow_run_id,source_capability,observed_value) DO UPDATE SET metadata=EXCLUDED.metadata,observed_at=EXCLUDED.observed_at,evidence_artifact_ids=EXCLUDED.evidence_artifact_ids RETURNING id`, observationID, assetID, step.WorkflowRunID, step.Capability, value, metadata, 1.0, evidence).Scan(&observationID); err != nil {
			return nil, err
		}
		if _, seen := seenObservationIDs[observationID]; !seen {
			seenObservationIDs[observationID] = struct{}{}
			observationIDs = append(observationIDs, observationID)
		}
	}
	return observationIDs, nil
}

func persistAssetObservationEmissions(ctx context.Context, tx pgx.Tx, programID domain.ID, observationIDs []domain.ID, acceptedEventID domain.ID) error {
	for _, observationID := range observationIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO asset_observation_emissions(program_id,asset_observation_id,provider_result_accepted_event_id) VALUES($1,$2,$3)`, programID, observationID, acceptedEventID); err != nil {
			return err
		}
	}
	return nil
}

func prepareProbeHTTPSourceRecords(programID domain.ID, step domain.StepRun, result domain.ActionResult, admission *capability.ResultAdmissionProvenance) (*normalize.ProbeHTTPSourceOutput, error) {
	if step.Capability != "probe.http" {
		return nil, nil
	}
	// Failed and retryable provider output is retained as ordinary result
	// evidence, but no serialized lineage from it is eligible for trusted 3A
	// persistence.
	if step.Status != domain.StepSucceeded {
		return nil, nil
	}
	providerAttemptID := ""
	if admission != nil {
		providerAttemptID = string(admission.ProviderAttemptID)
	}
	payload, present, err := normalize.ParseProbeHTTPSourceOutput(result.Output, string(programID), providerAttemptID)
	if err != nil {
		return nil, fmt.Errorf("validate probe HTTP source lineage: %w", err)
	}
	if !present {
		return nil, nil
	}
	if admission == nil {
		return nil, fmt.Errorf("validate probe HTTP source lineage: %w", normalize.ErrProbeHTTPSourceContract)
	}
	return &payload, nil
}

type concreteHTTPResourceKey struct {
	identityNamespace string
	scheme            string
	host              string
	effectivePort     int
	escapedPath       string
	canonicalQuery    string
}

func keyForConcreteHTTPResource(resource normalize.CanonicalConcreteHTTPResource) concreteHTTPResourceKey {
	return concreteHTTPResourceKey{
		identityNamespace: resource.IdentityNamespace,
		scheme:            resource.Scheme,
		host:              resource.Host,
		effectivePort:     resource.EffectivePort,
		escapedPath:       resource.ConcreteEscapedPath,
		canonicalQuery:    resource.CanonicalQuery,
	}
}

func lessConcreteHTTPResourceKey(left, right concreteHTTPResourceKey) bool {
	if left.identityNamespace != right.identityNamespace {
		return left.identityNamespace < right.identityNamespace
	}
	if left.scheme != right.scheme {
		return left.scheme < right.scheme
	}
	if left.host != right.host {
		return left.host < right.host
	}
	if left.effectivePort != right.effectivePort {
		return left.effectivePort < right.effectivePort
	}
	if left.escapedPath != right.escapedPath {
		return left.escapedPath < right.escapedPath
	}
	return left.canonicalQuery < right.canonicalQuery
}

func persistProbeHTTPSourceRecords(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, artifacts []domain.Artifact, payload normalize.ProbeHTTPSourceOutput, acceptedEventID domain.ID) error {
	normalizedArtifactID, err := normalizedResultArtifactID(artifacts)
	if err != nil {
		return fmt.Errorf("persist probe HTTP source lineage: %w", err)
	}
	type sourcePersistence struct {
		source normalize.AuthorizedSourceRecord
		target string
		key    concreteHTTPResourceKey
	}
	entries := make([]sourcePersistence, 0, len(payload.AuthorizedSourceRecords))
	resources := make(map[concreteHTTPResourceKey]normalize.CanonicalConcreteHTTPResource, len(payload.AuthorizedSourceRecords))
	for _, source := range payload.AuthorizedSourceRecords {
		if source.AuthorizedRecordIndex < 0 || source.AuthorizedRecordIndex >= len(payload.AuthorizedRecords) {
			return fmt.Errorf("persist probe HTTP source lineage: %w", normalize.ErrProbeHTTPSourceContract)
		}
		record := payload.AuthorizedRecords[source.AuthorizedRecordIndex]
		resource, err := normalize.ConcreteHTTPResource(record.Target)
		if err != nil {
			return fmt.Errorf("persist probe HTTP source lineage: %w", normalize.ErrProbeHTTPSourceContract)
		}
		key := keyForConcreteHTTPResource(resource)
		resources[key] = resource
		entries = append(entries, sourcePersistence{source: source, target: record.Target, key: key})
	}
	resourceKeys := make([]concreteHTTPResourceKey, 0, len(resources))
	for key := range resources {
		resourceKeys = append(resourceKeys, key)
	}
	sort.Slice(resourceKeys, func(i, j int) bool { return lessConcreteHTTPResourceKey(resourceKeys[i], resourceKeys[j]) })
	resourceIDs := make(map[concreteHTTPResourceKey]domain.ID, len(resourceKeys))
	for _, key := range resourceKeys {
		resource := resources[key]
		resourceID := domain.NewID()
		if err := tx.QueryRow(ctx, `INSERT INTO canonical_concrete_http_resources(
			id,program_id,identity_namespace,scheme,host,effective_port,concrete_escaped_path,canonical_query
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT(program_id,identity_namespace,scheme,host,effective_port,concrete_escaped_path,canonical_query)
		DO UPDATE SET id=canonical_concrete_http_resources.id
		RETURNING id`, resourceID, programID, resource.IdentityNamespace, resource.Scheme, resource.Host, resource.EffectivePort, resource.ConcreteEscapedPath, resource.CanonicalQuery).Scan(&resourceID); err != nil {
			return err
		}
		resourceIDs[key] = resourceID
	}
	for _, entry := range entries {
		source := entry.source
		resourceID := resourceIDs[entry.key]
		var observationID domain.ID
		err = tx.QueryRow(ctx, `SELECT observation.id
			FROM asset_observations observation
			JOIN assets asset ON asset.id=observation.asset_id
			JOIN asset_observation_emissions emission ON emission.asset_observation_id=observation.id
			WHERE asset.program_id=$1
			  AND asset.type='http_service'
			  AND asset.canonical_value=$2
			  AND observation.observed_value=$2
			  AND observation.workflow_run_id=$3
			  AND observation.source_capability='probe.http'
			  AND emission.program_id=$1
			  AND emission.provider_result_accepted_event_id=$4
			FOR SHARE OF observation,asset,emission`, programID, entry.target, step.WorkflowRunID, acceptedEventID).Scan(&observationID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("persist probe HTTP source lineage: %w", normalize.ErrProbeHTTPSourceContract)
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO probe_http_source_records(
			source_locator,program_id,concrete_http_resource_id,asset_observation_id,provider_result_accepted_event_id,
			provider_attempt_id,normalized_result_artifact_id,authorized_record_index,record_digest,
			request_method_state,request_method_value,request_content_type_state,request_content_type_value,
			identity_namespace,derivation_version
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			source.SourceLocator, programID, resourceID, observationID, acceptedEventID, source.ProviderAttemptID,
			normalizedArtifactID, source.AuthorizedRecordIndex, source.RecordDigest,
			source.RequestMethod.State, nullableSourceValue(source.RequestMethod), source.RequestContentType.State, nullableSourceValue(source.RequestContentType),
			source.IdentityNamespace, source.DerivationVersion); err != nil {
			return err
		}
	}
	return nil
}

func normalizedResultArtifactID(artifacts []domain.Artifact) (any, error) {
	var artifactID domain.ID
	for _, artifact := range artifacts {
		if artifact.Type != "normalized-result" {
			continue
		}
		if artifactID != "" {
			return nil, fmt.Errorf("multiple normalized result artifacts")
		}
		artifactID = artifact.ID
	}
	if artifactID == "" {
		return nil, nil
	}
	return artifactID, nil
}

func nullableSourceValue(value normalize.ValueSemantics) any {
	if value.Value == nil {
		return nil
	}
	return *value.Value
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

func persistEndpoints(ctx context.Context, tx pgx.Tx, programID domain.ID, completedAt *time.Time, raw json.RawMessage) error {
	if completedAt == nil || completedAt.IsZero() {
		return fmt.Errorf("classify.endpoint successful StepRun completion time is required")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("decode classify.endpoint result: %w", err)
	}
	encodedEndpoints, ok := envelope["endpoints"]
	if !ok || len(encodedEndpoints) == 0 || strings.TrimSpace(string(encodedEndpoints)) == "null" {
		return fmt.Errorf("classify.endpoint result requires a non-null endpoints array")
	}
	var encodedKeys []json.RawMessage
	if err := json.Unmarshal(encodedEndpoints, &encodedKeys); err != nil {
		return fmt.Errorf("decode classify.endpoint endpoints: %w", err)
	}
	for index, encodedKey := range encodedKeys {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encodedKey, &fields); err != nil {
			return fmt.Errorf("decode classify.endpoint endpoint %d: %w", index, err)
		}
		for _, required := range []string{"exact_url", "route_signature", "method", "content_type", "query_parameters", "digest"} {
			value, exists := fields[required]
			if !exists || len(value) == 0 || strings.TrimSpace(string(value)) == "null" {
				return fmt.Errorf("classify.endpoint endpoint %d requires field %s", index, required)
			}
		}
		var serialized normalize.EndpointKey
		if err := json.Unmarshal(encodedKey, &serialized); err != nil {
			return fmt.Errorf("decode classify.endpoint endpoint %d: %w", index, err)
		}
		if strings.TrimSpace(serialized.ExactURL) == "" || strings.TrimSpace(serialized.RouteSignature) == "" || strings.TrimSpace(serialized.Method) == "" || strings.TrimSpace(serialized.Digest) == "" || serialized.QueryParameters == nil {
			return fmt.Errorf("classify.endpoint endpoint %d is structurally incomplete", index)
		}
		canonical, origin, err := normalize.CanonicalEndpoint(serialized.ExactURL, serialized.Method, serialized.ContentType)
		if err != nil {
			return fmt.Errorf("classify.endpoint endpoint %d canonicalization failed", index)
		}
		if canonical.ExactURL != serialized.ExactURL {
			return fmt.Errorf("classify.endpoint endpoint %d exact_url does not match canonical identity", index)
		}
		if canonical.RouteSignature != serialized.RouteSignature {
			return fmt.Errorf("classify.endpoint endpoint %d route_signature does not match canonical identity", index)
		}
		if canonical.Method != serialized.Method {
			return fmt.Errorf("classify.endpoint endpoint %d method does not match canonical identity", index)
		}
		if canonical.ContentType != serialized.ContentType {
			return fmt.Errorf("classify.endpoint endpoint %d content_type does not match canonical identity", index)
		}
		if !slices.Equal(canonical.QueryParameters, serialized.QueryParameters) {
			return fmt.Errorf("classify.endpoint endpoint %d query_parameters do not match canonical identity", index)
		}
		if canonical.Digest != serialized.Digest {
			return fmt.Errorf("classify.endpoint endpoint %d digest does not match canonical identity", index)
		}
		params, err := json.Marshal(canonical.QueryParameters)
		if err != nil {
			return fmt.Errorf("encode classify.endpoint endpoint %d parameters: %w", index, err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO endpoints(
			id,program_id,exact_url,route_signature,method,content_type,parameter_schema,
			origin_scheme,origin_host,origin_effective_port,first_seen,last_seen
		) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$11)
		ON CONFLICT(
			program_id,origin_scheme,origin_host,origin_effective_port,route_signature,method,content_type,parameter_schema
		) WHERE origin_scheme IS NOT NULL AND origin_host IS NOT NULL AND origin_effective_port IS NOT NULL
		DO UPDATE SET
			exact_url=LEAST(endpoints.exact_url COLLATE "C",EXCLUDED.exact_url COLLATE "C"),
			first_seen=LEAST(endpoints.first_seen,EXCLUDED.first_seen),
			last_seen=GREATEST(endpoints.last_seen,EXCLUDED.last_seen)`,
			domain.NewID(), programID, canonical.ExactURL, canonical.RouteSignature, canonical.Method, canonical.ContentType, string(params), origin.Scheme, origin.Host, origin.EffectivePort, completedAt.UTC())
		if err != nil {
			return fmt.Errorf("persist classify.endpoint endpoint %d: %w", index, err)
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

func optionalIDPointer(id *domain.ID) any {
	if id == nil || *id == "" {
		return nil
	}
	return *id
}

func exactPositiveInt(value int) any {
	if value <= 0 {
		return nil
	}
	return value
}

func providerAttemptID(tool *domain.ToolRun) any {
	if tool == nil || tool.ProviderAttemptID == nil {
		return nil
	}
	return *tool.ProviderAttemptID
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

func (s *Store) LoadEffectiveStepInput(ctx context.Context, programID domain.ID, action domain.ActionRequest) (json.RawMessage, bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)
	step := effectiveInputStep(action)
	if _, err := lockResultLineage(ctx, tx, programID, step); err != nil {
		return nil, false, err
	}
	var input json.RawMessage
	var attemptCount int
	if err := tx.QueryRow(ctx, `SELECT input,attempt_count FROM step_runs WHERE id=$1`, action.StepRunID).Scan(&input, &attemptCount); err != nil {
		return nil, false, err
	}
	if action.StepAttempt < attemptCount {
		return nil, false, &workflow.StepAttemptOwnershipError{StepRunID: action.StepRunID, RequestedAttempt: action.StepAttempt, AuthoritativeAttempt: attemptCount}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return append(json.RawMessage(nil), input...), attemptCount > 0, nil
}

func (s *Store) PersistEffectiveStepInput(ctx context.Context, programID domain.ID, action domain.ActionRequest, proposed json.RawMessage) (json.RawMessage, error) {
	if _, recovering := domain.PreparedRecoveryRequestFromContext(ctx); recovering {
		return nil, fmt.Errorf("recovery admission cannot allocate attempts")
	}
	if action.StepAttempt < 1 || len(proposed) == 0 || !json.Valid(proposed) {
		return nil, fmt.Errorf("%w: effective input or attempt is invalid", workflow.ErrEffectiveStepInputConflict)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	step := effectiveInputStep(action)
	if _, err := lockResultLineage(ctx, tx, programID, step); err != nil {
		return nil, err
	}
	if err := ensureNoUnresolvedPrepared(ctx, tx, action.StepRunID); err != nil {
		return nil, err
	}
	var persisted json.RawMessage
	var attemptCount int
	if err := tx.QueryRow(ctx, `SELECT input,attempt_count FROM step_runs WHERE id=$1`, action.StepRunID).Scan(&persisted, &attemptCount); err != nil {
		return nil, err
	}
	if attemptCount > 0 {
		if action.StepAttempt <= attemptCount {
			return nil, &workflow.StepAttemptOwnershipError{StepRunID: action.StepRunID, RequestedAttempt: action.StepAttempt, AuthoritativeAttempt: attemptCount}
		}
		var equal bool
		if err := tx.QueryRow(ctx, `SELECT $1::jsonb=$2::jsonb`, persisted, proposed).Scan(&equal); err != nil {
			return nil, err
		}
		if action.StepAttempt != attemptCount+1 || !equal {
			return nil, fmt.Errorf("%w: StepRun %s already has authoritative attempt %d input", workflow.ErrEffectiveStepInputConflict, action.StepRunID, attemptCount)
		}
		if err := tx.QueryRow(ctx, `UPDATE step_runs SET attempt_count=$2 WHERE id=$1 AND attempt_count=$3 RETURNING input`, action.StepRunID, action.StepAttempt, attemptCount).Scan(&persisted); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return append(json.RawMessage(nil), persisted...), nil
	}
	if action.StepAttempt != 1 {
		return nil, fmt.Errorf("%w: first durable attempt for StepRun %s must be 1, got %d", workflow.ErrEffectiveStepInputConflict, action.StepRunID, action.StepAttempt)
	}
	if err := tx.QueryRow(ctx, `UPDATE step_runs SET input=$2,attempt_count=$3 WHERE id=$1 AND attempt_count=0 RETURNING input`, action.StepRunID, proposed, action.StepAttempt).Scan(&persisted); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), persisted...), nil
}

func effectiveInputStep(action domain.ActionRequest) domain.StepRun {
	return domain.StepRun{ID: action.StepRunID, WorkflowRunID: action.WorkflowRunID, Capability: action.Capability, IdempotencyKey: action.IdempotencyKey}
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
	if err := lockAndValidateWorkflowSave(ctx, tx, state, lifecycle != nil); err != nil {
		return err
	}
	if err := lockAndValidateAuthoritativeStepAttempts(ctx, tx, state); err != nil {
		return err
	}
	r := state.Run
	initial, err := guardInitialWorkflowRun(ctx, tx, r)
	if err != nil {
		return err
	}
	if initial {
		result, updateErr := tx.Exec(ctx, `UPDATE tasks SET status='running',updated_at=now() WHERE id=$1 AND status IN ('pending','running')`, r.TaskID)
		if updateErr != nil {
			return updateErr
		}
		if result.RowsAffected() != 1 {
			return fmt.Errorf("task %s is not in a recoverable pre-run state", r.TaskID)
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,completed_at,previous_run_id,trigger_source,summary,materialized_definition,materialization_digest,original_scope_version_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT(id) DO UPDATE SET
			status=EXCLUDED.status,
			started_at=COALESCE(workflow_runs.started_at,EXCLUDED.started_at),
			completed_at=CASE WHEN workflow_runs.status IN ('completed','failed','cancelled') THEN workflow_runs.completed_at ELSE EXCLUDED.completed_at END,
			summary=CASE WHEN workflow_runs.status IN ('completed','failed','cancelled') THEN workflow_runs.summary ELSE EXCLUDED.summary END`,
		r.ID, r.TaskID, r.WorkflowDefinitionID, r.WorkflowVersion, r.Status, r.StartedAt, r.CompletedAt, r.PreviousRunID, r.TriggerSource, r.Summary, r.MaterializedDefinition, r.MaterializationDigest, r.OriginalScopeVersionID)
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
		_, err = tx.Exec(ctx, `INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,attempt_count,input,output,error_classification,error_details,started_at,completed_at,idempotency_key,approval_state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(id) DO UPDATE SET
			status=EXCLUDED.status,
			attempt_count=EXCLUDED.attempt_count,
			input=EXCLUDED.input,
			output=CASE WHEN step_runs.status IN ('succeeded','failed','skipped','cancelled') OR (step_runs.status='retryable' AND EXCLUDED.status='retryable') THEN step_runs.output ELSE EXCLUDED.output END,
			error_classification=CASE WHEN step_runs.status IN ('succeeded','failed','skipped','cancelled') OR (step_runs.status='retryable' AND EXCLUDED.status='retryable') THEN step_runs.error_classification ELSE EXCLUDED.error_classification END,
			error_details=CASE WHEN step_runs.status IN ('succeeded','failed','skipped','cancelled') OR (step_runs.status='retryable' AND EXCLUDED.status='retryable') THEN step_runs.error_details ELSE EXCLUDED.error_details END,
			started_at=COALESCE(step_runs.started_at,EXCLUDED.started_at),
			completed_at=CASE WHEN step_runs.status IN ('succeeded','failed','skipped','cancelled') OR (step_runs.status='retryable' AND EXCLUDED.status='retryable') THEN step_runs.completed_at ELSE EXCLUDED.completed_at END,
			approval_state=EXCLUDED.approval_state`, x.ID, x.WorkflowRunID, x.StepDefinitionID, x.Capability, x.Status, x.AttemptCount, x.Input, x.Output, x.ErrorClassification, x.ErrorDetails, x.StartedAt, x.CompletedAt, x.IdempotencyKey, x.ApprovalState)
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

func guardInitialWorkflowRun(ctx context.Context, tx pgx.Tx, run domain.WorkflowRun) (bool, error) {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM workflow_runs WHERE id=$1)`, run.ID).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if run.OriginalScopeVersionID == nil {
		return false, fmt.Errorf("%w: new run has no original scope version", workflow.ErrWorkflowCheckpointConflict)
	}
	definition, err := workflow.VerifyMaterialization(run.MaterializedDefinition, run.MaterializationDigest)
	if err != nil {
		return false, err
	}
	if definition.ID != run.WorkflowDefinitionID || definition.Version != run.WorkflowVersion {
		return false, fmt.Errorf("%w: materialized definition identity differs from WorkflowRun", workflow.ErrWorkflowCheckpointConflict)
	}
	var taskProgramID, taskTemplateID domain.ID
	if err := tx.QueryRow(ctx, `SELECT program_id,workflow_definition_id FROM tasks WHERE id=$1 FOR UPDATE`, run.TaskID).Scan(&taskProgramID, &taskTemplateID); err != nil {
		return false, err
	}
	if taskTemplateID != run.WorkflowDefinitionID {
		return false, fmt.Errorf("%w: task %s pins template %s, not %s", workflow.ErrTaskWorkflowTemplateUnavailable, run.TaskID, taskTemplateID, run.WorkflowDefinitionID)
	}
	var templateName, templateVersion, templateDescription string
	var templateDescriptor, templateRequirements json.RawMessage
	var templateCreatedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT name,version,description,definition,default_policy_requirements,created_at FROM workflow_definitions WHERE id=$1`, taskTemplateID).Scan(&templateName, &templateVersion, &templateDescription, &templateDescriptor, &templateRequirements, &templateCreatedAt); err != nil {
		return false, err
	}
	descriptor, err := workflow.DecodeTemplateDescriptor(templateDescriptor)
	if err != nil {
		return false, fmt.Errorf("%w: template %s has no supported static descriptor", workflow.ErrTaskWorkflowTemplateUnavailable, taskTemplateID)
	}
	var requirementsEqual bool
	if err := tx.QueryRow(ctx, `SELECT $1::jsonb=$2::jsonb`, templateRequirements, definition.DefaultPolicyRequirements).Scan(&requirementsEqual); err != nil {
		return false, err
	}
	if definition.Name != templateName || definition.Version != templateVersion || definition.Materializer != descriptor.Materializer || definition.Description != templateDescription || !definition.CreatedAt.Equal(templateCreatedAt) || !requirementsEqual {
		return false, fmt.Errorf("%w: materialized definition release metadata differs from template", workflow.ErrWorkflowCheckpointConflict)
	}
	var scopeProgramID domain.ID
	if err := tx.QueryRow(ctx, `SELECT program_id FROM scope_versions WHERE id=$1`, *run.OriginalScopeVersionID).Scan(&scopeProgramID); err != nil {
		return false, err
	}
	if scopeProgramID != taskProgramID {
		return false, fmt.Errorf("%w: original scope version belongs to program %s, not %s", workflow.ErrWorkflowCheckpointConflict, scopeProgramID, taskProgramID)
	}
	rows, err := tx.Query(ctx, `SELECT id FROM workflow_runs WHERE task_id=$1 AND status IN ('pending','running','paused') ORDER BY id FOR UPDATE`, run.TaskID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	active := make([]domain.ID, 0, 2)
	for rows.Next() {
		var id domain.ID
		if err := rows.Scan(&id); err != nil {
			return false, err
		}
		active = append(active, id)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	switch len(active) {
	case 0:
		return true, nil
	case 1:
		return false, &workflow.RunLineageError{Cause: workflow.ErrWorkflowRunAlreadyActive, TaskID: run.TaskID, RunID: active[0]}
	default:
		return false, &workflow.RunLineageError{Cause: workflow.ErrWorkflowRunLineageConflict, TaskID: run.TaskID, Detail: fmt.Sprintf("%d non-terminal runs already exist", len(active))}
	}
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
	if err := p.File.Save(ctx, state); err != nil {
		return &workflow.RunLineageError{Cause: workflow.ErrWorkflowCheckpointUnavailable, TaskID: state.Run.TaskID, RunID: state.Run.ID, Detail: err.Error()}
	}
	return nil
}
