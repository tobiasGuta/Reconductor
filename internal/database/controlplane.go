package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

// ConsoleSnapshot is the read model consumed by the local operator console.
// It intentionally excludes artifact storage paths, raw provider output, step
// input, and other fields that could disclose credentials or unredacted data.
type ConsoleSnapshot struct {
	GeneratedAt            time.Time                   `json:"generated_at"`
	SelectedProgramID      domain.ID                   `json:"selected_program_id,omitempty"`
	Programs               []domain.Program            `json:"programs"`
	Scope                  *ConsoleScope               `json:"scope,omitempty"`
	Stats                  ConsoleStats                `json:"stats"`
	Runs                   []ConsoleRun                `json:"runs"`
	Steps                  []ConsoleStep               `json:"steps"`
	Tools                  []ConsoleToolRun            `json:"tool_runs"`
	Assets                 []ConsoleAsset              `json:"assets"`
	Candidates             []ConsoleCandidate          `json:"candidate_findings"`
	Verifications          []ConsoleVerification       `json:"verification_results"`
	VerifiedFindings       []ConsoleVerifiedFinding    `json:"verified_findings"`
	Approvals              []ConsoleApproval           `json:"approvals"`
	Schedules              []domain.Schedule           `json:"schedules"`
	ScheduledExecutions    []domain.ScheduledExecution `json:"scheduled_executions"`
	ChangeItems            []ConsoleChangeItem         `json:"change_items"`
	PendingScopeExpansions []domain.ScopeSnapshot      `json:"pending_scope_expansions"`
	AuditEvents            []ConsoleAuditEvent         `json:"audit_events"`
	LatestChanges          json.RawMessage             `json:"latest_changes"`
	WorkflowDefinition     json.RawMessage             `json:"workflow_definition,omitempty"`
}

type ConsoleScope struct {
	ScopeReference   string          `json:"scope_reference"`
	ScopeDigest      string          `json:"scope_digest"`
	TargetPlanDigest string          `json:"target_plan_digest"`
	IncludeRuleCount int             `json:"include_rule_count"`
	ExcludeRuleCount int             `json:"exclude_rule_count"`
	PlanningWarnings json.RawMessage `json:"planning_warnings"`
	ExpandsScope     bool            `json:"expands_scope"`
	AcknowledgedBy   string          `json:"acknowledged_by,omitempty"`
	AcknowledgedAt   *time.Time      `json:"acknowledged_at,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
}

type ConsoleStats struct {
	Assets           int `json:"assets"`
	ActiveRuns       int `json:"active_runs"`
	PendingApprovals int `json:"pending_approvals"`
	Candidates       int `json:"candidates"`
	VerifiedFindings int `json:"verified_findings"`
	FailedSteps      int `json:"failed_steps"`
}

type ConsoleRun struct {
	ID              domain.ID        `json:"id"`
	TaskID          domain.ID        `json:"task_id"`
	Objective       string           `json:"objective"`
	WorkflowName    string           `json:"workflow_name"`
	WorkflowVersion string           `json:"workflow_version"`
	Status          domain.RunStatus `json:"status"`
	StartedAt       *time.Time       `json:"started_at,omitempty"`
	CompletedAt     *time.Time       `json:"completed_at,omitempty"`
	TriggerSource   string           `json:"trigger_source"`
	Summary         json.RawMessage  `json:"summary"`
}

type ConsoleStep struct {
	ID                  domain.ID         `json:"id"`
	WorkflowRunID       domain.ID         `json:"workflow_run_id"`
	StepDefinitionID    string            `json:"step_definition_id"`
	Capability          string            `json:"capability"`
	Status              domain.StepStatus `json:"status"`
	AttemptCount        int               `json:"attempt_count"`
	ErrorClassification string            `json:"error_classification,omitempty"`
	ErrorDetails        string            `json:"error_details,omitempty"`
	StartedAt           *time.Time        `json:"started_at,omitempty"`
	CompletedAt         *time.Time        `json:"completed_at,omitempty"`
	ApprovalState       string            `json:"approval_state"`
}

type ConsoleToolRun struct {
	ID                 domain.ID       `json:"id"`
	WorkflowRunID      domain.ID       `json:"workflow_run_id"`
	StepDefinitionID   string          `json:"step_definition_id"`
	Provider           string          `json:"provider"`
	ToolVersion        string          `json:"tool_version"`
	SanitizedArguments json.RawMessage `json:"sanitized_arguments"`
	StartedAt          time.Time       `json:"started_at"`
	CompletedAt        *time.Time      `json:"completed_at,omitempty"`
	ExitCode           *int            `json:"exit_code,omitempty"`
	TimedOut           bool            `json:"timed_out"`
	ArtifactCount      int             `json:"artifact_count"`
}

type ConsoleAsset struct {
	ID               domain.ID       `json:"id"`
	Type             string          `json:"type"`
	CanonicalValue   string          `json:"canonical_value"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
	LastObservedAt   *time.Time      `json:"last_observed_at,omitempty"`
	SourceCapability string          `json:"source_capability,omitempty"`
	Metadata         json.RawMessage `json:"metadata"`
	ObservationCount int             `json:"observation_count"`
}

type ConsoleCandidate struct {
	ID                        domain.ID `json:"id"`
	WorkflowRunID             domain.ID `json:"workflow_run_id"`
	Target                    string    `json:"target"`
	SourceCapability          string    `json:"source_capability"`
	TemplateID                string    `json:"template_id"`
	ClaimedVulnerability      string    `json:"claimed_vulnerability"`
	Severity                  string    `json:"severity"`
	DetectionConfidence       float64   `json:"detection_confidence"`
	Status                    string    `json:"status"`
	LatestVerdict             string    `json:"latest_verdict,omitempty"`
	LatestEvidenceVerdict     string    `json:"latest_evidence_verdict,omitempty"`
	LatestImpactVerdict       string    `json:"latest_impact_verdict,omitempty"`
	LatestVerificationSummary string    `json:"latest_verification_summary,omitempty"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

type ConsoleVerification struct {
	ID                  domain.ID `json:"id"`
	CandidateID         domain.ID `json:"candidate_id"`
	Playbook            string    `json:"playbook"`
	IndependentProvider string    `json:"independent_provider"`
	Verdict             string    `json:"verdict"`
	EvidenceVerdict     string    `json:"evidence_verdict"`
	ImpactVerdict       string    `json:"impact_verdict"`
	Summary             string    `json:"summary"`
	CreatedAt           time.Time `json:"created_at"`
}

type ConsoleVerifiedFinding struct {
	ID              domain.ID  `json:"id"`
	CandidateID     *domain.ID `json:"candidate_id,omitempty"`
	Target          string     `json:"target"`
	Title           string     `json:"title"`
	Severity        string     `json:"severity"`
	Status          string     `json:"status"`
	ImpactStatement string     `json:"impact_statement"`
	FirstVerifiedAt time.Time  `json:"first_verified_at"`
	LastVerifiedAt  time.Time  `json:"last_verified_at"`
}

type ConsoleApproval struct {
	ID          domain.ID  `json:"id"`
	RequestID   domain.ID  `json:"request_id"`
	TaskID      domain.ID  `json:"task_id"`
	Objective   string     `json:"objective"`
	Risk        string     `json:"risk"`
	Reason      string     `json:"reason"`
	RequestedAt time.Time  `json:"requested_at"`
	Decision    string     `json:"decision"`
	DecidedBy   *string    `json:"decided_by,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type ConsoleChangeItem struct {
	domain.ChangeItem
	Disposition string     `json:"disposition"`
	ReviewNote  string     `json:"review_note,omitempty"`
	ReviewedBy  string     `json:"reviewed_by,omitempty"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
}

type ConsoleAuditEvent struct {
	ID            domain.ID       `json:"id"`
	OccurredAt    time.Time       `json:"occurred_at"`
	EventType     string          `json:"event_type"`
	Component     string          `json:"component"`
	Actor         string          `json:"actor"`
	WorkflowRunID *domain.ID      `json:"workflow_run_id,omitempty"`
	Capability    *string         `json:"capability,omitempty"`
	Provider      *string         `json:"provider,omitempty"`
	SafeMessage   string          `json:"safe_message"`
	Details       json.RawMessage `json:"details"`
}

func (s *Store) ConsoleSnapshot(ctx context.Context, requestedProgramID domain.ID) (ConsoleSnapshot, error) {
	programs, err := s.ListPrograms(ctx)
	if err != nil {
		return ConsoleSnapshot{}, err
	}
	snapshot := ConsoleSnapshot{
		GeneratedAt:            time.Now().UTC(),
		Programs:               nonNil(programs),
		Runs:                   []ConsoleRun{},
		Steps:                  []ConsoleStep{},
		Tools:                  []ConsoleToolRun{},
		Assets:                 []ConsoleAsset{},
		Candidates:             []ConsoleCandidate{},
		Verifications:          []ConsoleVerification{},
		VerifiedFindings:       []ConsoleVerifiedFinding{},
		Approvals:              []ConsoleApproval{},
		Schedules:              []domain.Schedule{},
		ScheduledExecutions:    []domain.ScheduledExecution{},
		ChangeItems:            []ConsoleChangeItem{},
		PendingScopeExpansions: []domain.ScopeSnapshot{},
		AuditEvents:            []ConsoleAuditEvent{},
		LatestChanges:          json.RawMessage(`{}`),
	}
	if len(programs) == 0 {
		return snapshot, nil
	}
	selected := requestedProgramID
	if selected == "" {
		selected = programs[0].ID
	}
	if !containsProgram(programs, selected) {
		return ConsoleSnapshot{}, fmt.Errorf("program %s not found", selected)
	}
	snapshot.SelectedProgramID = selected

	if err := s.loadConsoleScope(ctx, selected, &snapshot); err != nil {
		return ConsoleSnapshot{}, err
	}
	if err := s.loadConsoleStats(ctx, selected, &snapshot); err != nil {
		return ConsoleSnapshot{}, err
	}
	if err := s.loadConsoleRuns(ctx, selected, &snapshot); err != nil {
		return ConsoleSnapshot{}, err
	}
	if err := s.loadConsoleSteps(ctx, selected, &snapshot); err != nil {
		return ConsoleSnapshot{}, err
	}
	if err := s.loadConsoleTools(ctx, selected, &snapshot); err != nil {
		return ConsoleSnapshot{}, err
	}
	if err := s.loadConsoleAssets(ctx, selected, &snapshot); err != nil {
		return ConsoleSnapshot{}, err
	}
	if err := s.loadConsoleFindings(ctx, selected, &snapshot); err != nil {
		return ConsoleSnapshot{}, err
	}
	if err := s.loadConsoleApprovals(ctx, selected, &snapshot); err != nil {
		return ConsoleSnapshot{}, err
	}
	if err := s.loadConsoleSchedules(ctx, selected, &snapshot); err != nil {
		return ConsoleSnapshot{}, err
	}
	if err := s.loadConsoleChangeItems(ctx, selected, &snapshot); err != nil {
		return ConsoleSnapshot{}, err
	}
	if err := s.loadConsoleAudit(ctx, selected, &snapshot); err != nil {
		return ConsoleSnapshot{}, err
	}
	if changes, err := s.LatestChanges(ctx, selected); err == nil {
		snapshot.LatestChanges = changes
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return ConsoleSnapshot{}, err
	}
	return snapshot, nil
}

func (s *Store) loadConsoleSchedules(ctx context.Context, programID domain.ID, out *ConsoleSnapshot) error {
	schedules, err := s.ListSchedules(ctx, programID)
	if err != nil {
		return err
	}
	out.Schedules = nonNil(schedules)
	executions, err := s.ListScheduledExecutions(ctx, "", 100)
	if err != nil {
		return err
	}
	allowed := map[domain.ID]bool{}
	for _, schedule := range schedules {
		allowed[schedule.ID] = true
	}
	for _, execution := range executions {
		if allowed[execution.ScheduleID] {
			out.ScheduledExecutions = append(out.ScheduledExecutions, execution)
		}
	}
	pending, err := s.ListPendingScopeExpansions(ctx, programID)
	if err != nil {
		return err
	}
	out.PendingScopeExpansions = nonNil(pending)
	return nil
}

func (s *Store) loadConsoleChangeItems(ctx context.Context, programID domain.ID, out *ConsoleSnapshot) error {
	rows, err := s.Pool.Query(ctx, `SELECT ci.id,ci.program_id,ci.workflow_run_id,ci.scheduled_execution_id,ci.kind,ci.entity_type,ci.entity_key,ci.priority,ci.title,ci.safe_summary,ci.reasons,ci.previous_value,ci.current_value,ci.source_capabilities,ci.evidence_artifact_ids,ci.observed_at,ci.created_at,COALESCE(cr.disposition,'unreviewed'),COALESCE(cr.note,''),COALESCE(cr.reviewed_by,''),cr.reviewed_at FROM change_items ci LEFT JOIN change_reviews cr ON cr.change_item_id=ci.id WHERE ci.program_id=$1 ORDER BY CASE ci.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, ci.observed_at DESC LIMIT 150`, programID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item ConsoleChangeItem
		var evidence []string
		if err := rows.Scan(&item.ID, &item.ProgramID, &item.WorkflowRunID, &item.ScheduledExecutionID, &item.Kind, &item.EntityType, &item.EntityKey, &item.Priority, &item.Title, &item.Summary, &item.Reasons, &item.Previous, &item.Current, &item.SourceCapabilities, &evidence, &item.ObservedAt, &item.CreatedAt, &item.Disposition, &item.ReviewNote, &item.ReviewedBy, &item.ReviewedAt); err != nil {
			return err
		}
		item.EvidenceArtifactIDs = idsFromStrings(evidence)
		out.ChangeItems = append(out.ChangeItems, item)
	}
	return rows.Err()
}

func (s *Store) loadConsoleScope(ctx context.Context, programID domain.ID, out *ConsoleSnapshot) error {
	var scope ConsoleScope
	err := s.Pool.QueryRow(ctx, `SELECT scope_reference,scope_digest,target_plan_digest,cardinality(include_rule_digests),cardinality(exclude_rule_digests),planning_warnings,expands_scope,COALESCE(acknowledged_by,''),acknowledged_at,created_at FROM scope_versions WHERE program_id=$1 ORDER BY created_at DESC LIMIT 1`, programID).Scan(&scope.ScopeReference, &scope.ScopeDigest, &scope.TargetPlanDigest, &scope.IncludeRuleCount, &scope.ExcludeRuleCount, &scope.PlanningWarnings, &scope.ExpandsScope, &scope.AcknowledgedBy, &scope.AcknowledgedAt, &scope.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	out.Scope = &scope
	return nil
}

func (s *Store) loadConsoleStats(ctx context.Context, programID domain.ID, out *ConsoleSnapshot) error {
	return s.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM assets WHERE program_id=$1),
		(SELECT count(*) FROM workflow_runs wr JOIN tasks t ON t.id=wr.task_id WHERE t.program_id=$1 AND wr.status IN ('pending','running','paused')),
		(SELECT count(*) FROM approvals a JOIN tasks t ON t.id=a.task_id WHERE t.program_id=$1 AND a.decision='pending'),
		(SELECT count(*) FROM candidate_findings cf JOIN tasks t ON t.id=cf.task_id WHERE t.program_id=$1 AND cf.status NOT IN ('rejected','informational')),
		(SELECT count(*) FROM verified_findings WHERE program_id=$1 AND status='open'),
		(SELECT count(*) FROM step_runs sr JOIN workflow_runs wr ON wr.id=sr.workflow_run_id JOIN tasks t ON t.id=wr.task_id WHERE t.program_id=$1 AND sr.status IN ('failed','retryable'))`, programID).Scan(&out.Stats.Assets, &out.Stats.ActiveRuns, &out.Stats.PendingApprovals, &out.Stats.Candidates, &out.Stats.VerifiedFindings, &out.Stats.FailedSteps)
}

func (s *Store) loadConsoleRuns(ctx context.Context, programID domain.ID, out *ConsoleSnapshot) error {
	rows, err := s.Pool.Query(ctx, `SELECT wr.id,wr.task_id,t.objective,wd.name,wr.workflow_version,wr.status,wr.started_at,wr.completed_at,wr.trigger_source,wr.summary FROM workflow_runs wr JOIN tasks t ON t.id=wr.task_id JOIN workflow_definitions wd ON wd.id=wr.workflow_definition_id WHERE t.program_id=$1 ORDER BY COALESCE(wr.started_at,t.created_at) DESC LIMIT 40`, programID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item ConsoleRun
		if err := rows.Scan(&item.ID, &item.TaskID, &item.Objective, &item.WorkflowName, &item.WorkflowVersion, &item.Status, &item.StartedAt, &item.CompletedAt, &item.TriggerSource, &item.Summary); err != nil {
			return err
		}
		out.Runs = append(out.Runs, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(out.Runs) > 0 {
		err = s.Pool.QueryRow(ctx, `SELECT wd.definition FROM workflow_runs wr JOIN workflow_definitions wd ON wd.id=wr.workflow_definition_id WHERE wr.id=$1`, out.Runs[0].ID).Scan(&out.WorkflowDefinition)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}
	return nil
}

func (s *Store) loadConsoleSteps(ctx context.Context, programID domain.ID, out *ConsoleSnapshot) error {
	rows, err := s.Pool.Query(ctx, `SELECT sr.id,sr.workflow_run_id,sr.step_definition_id,sr.capability,sr.status,sr.attempt_count,sr.error_classification,sr.error_details,sr.started_at,sr.completed_at,sr.approval_state FROM step_runs sr JOIN workflow_runs wr ON wr.id=sr.workflow_run_id JOIN tasks t ON t.id=wr.task_id WHERE t.program_id=$1 ORDER BY COALESCE(sr.started_at,wr.started_at) DESC NULLS LAST LIMIT 240`, programID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item ConsoleStep
		if err := rows.Scan(&item.ID, &item.WorkflowRunID, &item.StepDefinitionID, &item.Capability, &item.Status, &item.AttemptCount, &item.ErrorClassification, &item.ErrorDetails, &item.StartedAt, &item.CompletedAt, &item.ApprovalState); err != nil {
			return err
		}
		out.Steps = append(out.Steps, item)
	}
	return rows.Err()
}

func (s *Store) loadConsoleTools(ctx context.Context, programID domain.ID, out *ConsoleSnapshot) error {
	rows, err := s.Pool.Query(ctx, `SELECT tr.id,sr.workflow_run_id,sr.step_definition_id,tr.provider,tr.tool_version,tr.sanitized_arguments,tr.started_at,tr.completed_at,tr.exit_code,tr.timed_out,(SELECT count(*) FROM artifacts a WHERE a.tool_run_id=tr.id AND a.sensitive=false AND (a.expires_at IS NULL OR a.expires_at>now())) FROM tool_runs tr JOIN step_runs sr ON sr.id=tr.step_run_id JOIN workflow_runs wr ON wr.id=sr.workflow_run_id JOIN tasks t ON t.id=wr.task_id WHERE t.program_id=$1 ORDER BY tr.started_at DESC LIMIT 120`, programID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item ConsoleToolRun
		if err := rows.Scan(&item.ID, &item.WorkflowRunID, &item.StepDefinitionID, &item.Provider, &item.ToolVersion, &item.SanitizedArguments, &item.StartedAt, &item.CompletedAt, &item.ExitCode, &item.TimedOut, &item.ArtifactCount); err != nil {
			return err
		}
		out.Tools = append(out.Tools, item)
	}
	return rows.Err()
}

func (s *Store) loadConsoleAssets(ctx context.Context, programID domain.ID, out *ConsoleSnapshot) error {
	rows, err := s.Pool.Query(ctx, `SELECT a.id,a.type,a.canonical_value,a.created_at,a.updated_at,latest.observed_at,COALESCE(latest.source_capability,''),COALESCE(latest.metadata,'{}'::jsonb),(SELECT count(*) FROM asset_observations ao WHERE ao.asset_id=a.id) FROM assets a LEFT JOIN LATERAL (SELECT ao.observed_at,ao.source_capability,ao.metadata FROM asset_observations ao WHERE ao.asset_id=a.id ORDER BY ao.observed_at DESC LIMIT 1) latest ON true WHERE a.program_id=$1 ORDER BY COALESCE(latest.observed_at,a.updated_at) DESC LIMIT 300`, programID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item ConsoleAsset
		if err := rows.Scan(&item.ID, &item.Type, &item.CanonicalValue, &item.CreatedAt, &item.UpdatedAt, &item.LastObservedAt, &item.SourceCapability, &item.Metadata, &item.ObservationCount); err != nil {
			return err
		}
		out.Assets = append(out.Assets, item)
	}
	return rows.Err()
}

func (s *Store) loadConsoleFindings(ctx context.Context, programID domain.ID, out *ConsoleSnapshot) error {
	rows, err := s.Pool.Query(ctx, `SELECT cf.id,cf.workflow_run_id,a.canonical_value,cf.source_capability,cf.template_id,cf.claimed_vulnerability,cf.severity,cf.detection_confidence,cf.status,COALESCE(latest.verdict,''),COALESCE(latest.evidence_verdict,''),COALESCE(latest.impact_verdict,''),COALESCE(latest.summary,''),cf.created_at,cf.updated_at FROM candidate_findings cf JOIN tasks t ON t.id=cf.task_id JOIN assets a ON a.id=cf.target_asset_id LEFT JOIN LATERAL (SELECT verdict,evidence_verdict,impact_verdict,summary FROM verification_results vr WHERE vr.candidate_id=cf.id ORDER BY vr.created_at DESC,vr.id DESC LIMIT 1) latest ON true WHERE t.program_id=$1 ORDER BY cf.updated_at DESC LIMIT 150`, programID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item ConsoleCandidate
		if err := rows.Scan(&item.ID, &item.WorkflowRunID, &item.Target, &item.SourceCapability, &item.TemplateID, &item.ClaimedVulnerability, &item.Severity, &item.DetectionConfidence, &item.Status, &item.LatestVerdict, &item.LatestEvidenceVerdict, &item.LatestImpactVerdict, &item.LatestVerificationSummary, &item.CreatedAt, &item.UpdatedAt); err != nil {
			rows.Close()
			return err
		}
		out.Candidates = append(out.Candidates, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `SELECT vr.id,vr.candidate_id,vr.playbook,vr.independent_provider,vr.verdict,vr.evidence_verdict,vr.impact_verdict,vr.summary,vr.created_at FROM verification_results vr JOIN candidate_findings cf ON cf.id=vr.candidate_id JOIN tasks t ON t.id=cf.task_id WHERE t.program_id=$1 ORDER BY vr.created_at DESC LIMIT 150`, programID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var item ConsoleVerification
		if err := rows.Scan(&item.ID, &item.CandidateID, &item.Playbook, &item.IndependentProvider, &item.Verdict, &item.EvidenceVerdict, &item.ImpactVerdict, &item.Summary, &item.CreatedAt); err != nil {
			rows.Close()
			return err
		}
		out.Verifications = append(out.Verifications, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	rows, err = s.Pool.Query(ctx, `SELECT vf.id,vf.candidate_id,COALESCE(a.canonical_value,''),vf.title,vf.severity,vf.status,vf.impact_statement,vf.first_verified_at,vf.last_verified_at FROM verified_findings vf LEFT JOIN assets a ON a.id=vf.asset_id WHERE vf.program_id=$1 ORDER BY vf.last_verified_at DESC LIMIT 150`, programID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item ConsoleVerifiedFinding
		if err := rows.Scan(&item.ID, &item.CandidateID, &item.Target, &item.Title, &item.Severity, &item.Status, &item.ImpactStatement, &item.FirstVerifiedAt, &item.LastVerifiedAt); err != nil {
			return err
		}
		out.VerifiedFindings = append(out.VerifiedFindings, item)
	}
	return rows.Err()
}

func (s *Store) loadConsoleApprovals(ctx context.Context, programID domain.ID, out *ConsoleSnapshot) error {
	rows, err := s.Pool.Query(ctx, `SELECT a.id,a.request_id,a.task_id,t.objective,a.requested_risk_level,a.reason,a.requested_at,a.decision,a.decided_by,a.decided_at,a.expires_at FROM approvals a JOIN tasks t ON t.id=a.task_id WHERE t.program_id=$1 ORDER BY (a.decision='pending') DESC,a.requested_at DESC LIMIT 100`, programID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item ConsoleApproval
		if err := rows.Scan(&item.ID, &item.RequestID, &item.TaskID, &item.Objective, &item.Risk, &item.Reason, &item.RequestedAt, &item.Decision, &item.DecidedBy, &item.DecidedAt, &item.ExpiresAt); err != nil {
			return err
		}
		out.Approvals = append(out.Approvals, item)
	}
	return rows.Err()
}

func (s *Store) loadConsoleAudit(ctx context.Context, programID domain.ID, out *ConsoleSnapshot) error {
	rows, err := s.Pool.Query(ctx, `SELECT ae.id,ae.occurred_at,ae.event_type,ae.component,ae.actor,ae.workflow_run_id,ae.capability,ae.provider,ae.safe_message,ae.details FROM audit_events ae WHERE ae.program_id=$1 OR EXISTS (SELECT 1 FROM tasks t WHERE t.id=ae.task_id AND t.program_id=$1) ORDER BY ae.occurred_at DESC LIMIT 160`, programID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var item ConsoleAuditEvent
		if err := rows.Scan(&item.ID, &item.OccurredAt, &item.EventType, &item.Component, &item.Actor, &item.WorkflowRunID, &item.Capability, &item.Provider, &item.SafeMessage, &item.Details); err != nil {
			return err
		}
		out.AuditEvents = append(out.AuditEvents, item)
	}
	return rows.Err()
}

func containsProgram(programs []domain.Program, id domain.ID) bool {
	for _, program := range programs {
		if program.ID == id {
			return true
		}
	}
	return false
}

func nonNil[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}
