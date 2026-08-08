package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

// ErrScheduledExecutionNotFound is returned when an execution projection root
// does not exist. Callers can use errors.Is without depending on pgx errors.
var ErrScheduledExecutionNotFound = errors.New("scheduled execution not found")

type ExecutionLeaseState string

const (
	ExecutionLeaseNotApplicable ExecutionLeaseState = "not_applicable"
	ExecutionLeaseActive        ExecutionLeaseState = "active"
	ExecutionLeaseExpired       ExecutionLeaseState = "expired"
	ExecutionLeaseReleased      ExecutionLeaseState = "released"
	ExecutionLeaseInconsistent  ExecutionLeaseState = "inconsistent"
)

type ExecutionLineageIssue string

const (
	ExecutionLineageScopeMissing                      ExecutionLineageIssue = "scope_missing"
	ExecutionLineageScopeProgramMismatch              ExecutionLineageIssue = "scope_program_mismatch"
	ExecutionLineageTaskMissing                       ExecutionLineageIssue = "task_missing"
	ExecutionLineageTaskProgramMismatch               ExecutionLineageIssue = "task_program_mismatch"
	ExecutionLineageWorkflowMissing                   ExecutionLineageIssue = "workflow_missing"
	ExecutionLineageWorkflowWithoutTask               ExecutionLineageIssue = "workflow_without_execution_task"
	ExecutionLineageWorkflowTaskMismatch              ExecutionLineageIssue = "workflow_task_mismatch"
	ExecutionLineageWorkflowDefinitionMissing         ExecutionLineageIssue = "workflow_definition_missing"
	ExecutionLineageWorkflowDefinitionMismatch        ExecutionLineageIssue = "workflow_definition_mismatch"
	ExecutionLineageWorkflowDefinitionVersionMismatch ExecutionLineageIssue = "workflow_definition_version_mismatch"
	ExecutionLineageApprovalInconsistent              ExecutionLineageIssue = "approval_lineage_inconsistent"
	ExecutionLineageArtifactInconsistent              ExecutionLineageIssue = "artifact_lineage_inconsistent"
	ExecutionLineageCandidateFindingInconsistent      ExecutionLineageIssue = "candidate_finding_lineage_inconsistent"
)

// ExecutionProjection is a read-only observation of independently
// authoritative scheduler, task, workflow, and step state.
type ExecutionProjection struct {
	ObservedAt      time.Time                                                   `json:"observed_at"`
	Execution       ExecutionProjectionExecution                                `json:"execution"`
	Trigger         ExecutionProjectionTrigger                                  `json:"trigger"`
	Scheduler       ExecutionProjectionScheduler                                `json:"scheduler"`
	CurrentSchedule ExecutionProjectionCurrentSchedule                          `json:"current_schedule"`
	CurrentProgram  ExecutionProjectionCurrentProgram                           `json:"current_program"`
	Scope           *ExecutionProjectionScope                                   `json:"scope,omitempty"`
	Task            *ExecutionProjectionTask                                    `json:"task,omitempty"`
	Workflow        *ExecutionProjectionWorkflow                                `json:"workflow,omitempty"`
	Steps           []ExecutionProjectionStep                                   `json:"steps"`
	ToolRuns        ExecutionProjectionCollection[ExecutionProjectionToolRun]   `json:"tool_runs"`
	Approvals       ExecutionProjectionCollection[ExecutionProjectionApproval]  `json:"approvals"`
	Artifacts       ExecutionProjectionCollection[ExecutionProjectionArtifact]  `json:"artifacts"`
	Candidates      ExecutionProjectionCollection[ExecutionProjectionCandidate] `json:"candidate_findings"`
	Lineage         ExecutionProjectionLineage                                  `json:"lineage"`
}

type ExecutionProjectionExecution struct {
	ID             domain.ID  `json:"id"`
	ScheduleID     domain.ID  `json:"schedule_id"`
	ProgramID      domain.ID  `json:"program_id"`
	TaskID         *domain.ID `json:"task_id,omitempty"`
	WorkflowRunID  *domain.ID `json:"workflow_run_id,omitempty"`
	ScopeVersionID *domain.ID `json:"scope_version_id,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type ExecutionProjectionTrigger struct {
	Source    string    `json:"source"`
	PlannedAt time.Time `json:"planned_at"`
}

type ExecutionProjectionScheduler struct {
	Status                  domain.ScheduledExecutionStatus `json:"status"`
	AttemptCount            int                             `json:"attempt_count"`
	LeaseOwner              string                          `json:"lease_owner,omitempty"`
	LeaseExpiresAt          *time.Time                      `json:"lease_expires_at,omitempty"`
	LeaseState              ExecutionLeaseState             `json:"lease_state"`
	RecoveryProtocolVersion int                             `json:"recovery_protocol_version"`
	ErrorClassification     string                          `json:"error_classification,omitempty"`
	ErrorSummary            string                          `json:"error_summary,omitempty"`
	StartedAt               *time.Time                      `json:"started_at,omitempty"`
	CompletedAt             *time.Time                      `json:"completed_at,omitempty"`
}

// ExecutionProjectionCurrentSchedule is mutable current schedule context. Its
// fields must not be interpreted as an execution-time schedule snapshot.
type ExecutionProjectionCurrentSchedule struct {
	ID             domain.ID  `json:"id"`
	ProgramID      domain.ID  `json:"program_id"`
	Name           string     `json:"name"`
	WorkflowName   string     `json:"workflow_name"`
	Objective      string     `json:"objective"`
	CronExpression string     `json:"cron_expression"`
	Timezone       string     `json:"timezone"`
	Enabled        bool       `json:"enabled"`
	Headless       bool       `json:"headless"`
	CreatedBy      string     `json:"created_by"`
	LastRunAt      *time.Time `json:"last_run_at,omitempty"`
	NextRunAt      time.Time  `json:"next_run_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// ExecutionProjectionCurrentProgram contains only allow-listed current
// program identity fields.
type ExecutionProjectionCurrentProgram struct {
	ID       domain.ID `json:"id"`
	Name     string    `json:"name"`
	Platform string    `json:"platform"`
}

// ExecutionProjectionScope identifies the scope-version row assigned to this
// execution. Digests are historical values on that row; ScopeReference can be
// repaired in place and is therefore current locator metadata.
type ExecutionProjectionScope struct {
	ID               domain.ID  `json:"id"`
	ProgramID        domain.ID  `json:"program_id"`
	ScopeReference   string     `json:"scope_reference"`
	ScopeDigest      string     `json:"scope_digest"`
	TargetPlanDigest string     `json:"target_plan_digest"`
	ExpandsScope     bool       `json:"expands_scope"`
	AcknowledgedAt   *time.Time `json:"acknowledged_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

type ExecutionProjectionTask struct {
	ID                   domain.ID         `json:"id"`
	ProgramID            domain.ID         `json:"program_id"`
	Objective            string            `json:"objective"`
	WorkflowDefinitionID domain.ID         `json:"workflow_definition_id"`
	Status               domain.TaskStatus `json:"status"`
	RequestedBy          string            `json:"requested_by"`
	ScheduleReference    *string           `json:"schedule_reference,omitempty"`
	CancelledAt          *time.Time        `json:"cancelled_at,omitempty"`
	CreatedAt            time.Time         `json:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at"`
}

type ExecutionProjectionWorkflow struct {
	ID                   domain.ID        `json:"id"`
	TaskID               domain.ID        `json:"task_id"`
	WorkflowDefinitionID domain.ID        `json:"workflow_definition_id"`
	DefinitionName       string           `json:"definition_name,omitempty"`
	WorkflowVersion      string           `json:"workflow_version"`
	Status               domain.RunStatus `json:"status"`
	StartedAt            *time.Time       `json:"started_at,omitempty"`
	CompletedAt          *time.Time       `json:"completed_at,omitempty"`
	PreviousRunID        *domain.ID       `json:"previous_run_id,omitempty"`
	TriggerSource        string           `json:"trigger_source"`
}

type ExecutionProjectionStep struct {
	ID                  domain.ID         `json:"id"`
	WorkflowRunID       domain.ID         `json:"workflow_run_id"`
	StepDefinitionID    string            `json:"step_definition_id"`
	Capability          string            `json:"capability"`
	Status              domain.StepStatus `json:"status"`
	AttemptCount        int               `json:"attempt_count"`
	ErrorClassification string            `json:"error_classification,omitempty"`
	StartedAt           *time.Time        `json:"started_at,omitempty"`
	CompletedAt         *time.Time        `json:"completed_at,omitempty"`
	ApprovalState       string            `json:"approval_state"`
}

type ExecutionProjectionLineage struct {
	Issues []ExecutionLineageIssue `json:"issues"`
}

type executionProjectionQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

var executionProjectionTxOptions = pgx.TxOptions{
	IsoLevel:   pgx.RepeatableRead,
	AccessMode: pgx.ReadOnly,
}

// statement_timestamp() is captured once by the root SELECT as the coherent
// observation instant for this projection. Scheduler ownership enforcement
// retains its separate clock semantics in the scheduler write paths.
const executionProjectionRootQuery = `SELECT
	statement_timestamp(),
	se.id,se.schedule_id,s.program_id,se.task_id,se.workflow_run_id,se.scope_version_id,se.created_at,se.updated_at,
	se.trigger_source,se.planned_at,
	se.status,se.attempt_count,se.lease_owner,se.lease_expires_at,se.recovery_protocol_version,se.error_classification,se.error_summary,se.started_at,se.completed_at,
	s.id,s.program_id,s.name,s.workflow_name,s.objective,s.cron_expression,s.timezone,s.enabled,s.headless,s.created_by,s.last_run_at,s.next_run_at,s.created_at,s.updated_at,
	p.id,p.name,p.platform
FROM scheduled_executions se
JOIN schedules s ON s.id=se.schedule_id
JOIN programs p ON p.id=s.program_id
WHERE se.id=$1`

// GetExecutionProjection loads one coherent observation without acquiring row
// locks. All projection queries share a read-only, repeatable-read snapshot.
func (s *Store) GetExecutionProjection(ctx context.Context, id domain.ID) (ExecutionProjection, error) {
	tx, err := s.beginExecutionProjection(ctx)
	if err != nil {
		return ExecutionProjection{}, fmt.Errorf("begin execution projection: %w", err)
	}
	defer tx.Rollback(ctx)

	projection, err := queryExecutionProjection(ctx, tx, id)
	if err != nil {
		return ExecutionProjection{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ExecutionProjection{}, fmt.Errorf("commit execution projection: %w", err)
	}
	return projection, nil
}

func (s *Store) beginExecutionProjection(ctx context.Context) (pgx.Tx, error) {
	return s.Pool.BeginTx(ctx, executionProjectionTxOptions)
}

func queryExecutionProjection(ctx context.Context, query executionProjectionQuerier, id domain.ID) (ExecutionProjection, error) {
	projection := ExecutionProjection{
		Steps:      []ExecutionProjectionStep{},
		ToolRuns:   newExecutionProjectionCollection[ExecutionProjectionToolRun](),
		Approvals:  newExecutionProjectionCollection[ExecutionProjectionApproval](),
		Artifacts:  newExecutionProjectionCollection[ExecutionProjectionArtifact](),
		Candidates: newExecutionProjectionCollection[ExecutionProjectionCandidate](),
		Lineage:    ExecutionProjectionLineage{Issues: []ExecutionLineageIssue{}},
	}
	err := query.QueryRow(ctx, executionProjectionRootQuery, id).Scan(
		&projection.ObservedAt,
		&projection.Execution.ID, &projection.Execution.ScheduleID, &projection.Execution.ProgramID,
		&projection.Execution.TaskID, &projection.Execution.WorkflowRunID, &projection.Execution.ScopeVersionID,
		&projection.Execution.CreatedAt, &projection.Execution.UpdatedAt,
		&projection.Trigger.Source, &projection.Trigger.PlannedAt,
		&projection.Scheduler.Status, &projection.Scheduler.AttemptCount, &projection.Scheduler.LeaseOwner,
		&projection.Scheduler.LeaseExpiresAt, &projection.Scheduler.RecoveryProtocolVersion,
		&projection.Scheduler.ErrorClassification, &projection.Scheduler.ErrorSummary,
		&projection.Scheduler.StartedAt, &projection.Scheduler.CompletedAt,
		&projection.CurrentSchedule.ID, &projection.CurrentSchedule.ProgramID, &projection.CurrentSchedule.Name,
		&projection.CurrentSchedule.WorkflowName, &projection.CurrentSchedule.Objective,
		&projection.CurrentSchedule.CronExpression, &projection.CurrentSchedule.Timezone,
		&projection.CurrentSchedule.Enabled, &projection.CurrentSchedule.Headless,
		&projection.CurrentSchedule.CreatedBy, &projection.CurrentSchedule.LastRunAt,
		&projection.CurrentSchedule.NextRunAt, &projection.CurrentSchedule.CreatedAt,
		&projection.CurrentSchedule.UpdatedAt,
		&projection.CurrentProgram.ID, &projection.CurrentProgram.Name, &projection.CurrentProgram.Platform,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ExecutionProjection{}, fmt.Errorf("%w: %s", ErrScheduledExecutionNotFound, id)
	}
	if err != nil {
		return ExecutionProjection{}, fmt.Errorf("query execution projection root: %w", err)
	}

	projection.Scheduler.LeaseState = deriveExecutionLeaseState(
		projection.Scheduler.Status,
		projection.Scheduler.AttemptCount,
		projection.Scheduler.LeaseOwner,
		projection.Scheduler.LeaseExpiresAt,
		projection.ObservedAt,
	)

	if err := loadExecutionProjectionScope(ctx, query, &projection); err != nil {
		return ExecutionProjection{}, err
	}
	if err := loadExecutionProjectionTask(ctx, query, &projection); err != nil {
		return ExecutionProjection{}, err
	}
	if err := loadExecutionProjectionWorkflow(ctx, query, &projection); err != nil {
		return ExecutionProjection{}, err
	}
	if err := loadExecutionProjectionSteps(ctx, query, &projection); err != nil {
		return ExecutionProjection{}, err
	}
	deriveExecutionLineageIssues(&projection)
	if err := loadExecutionProjectionToolRuns(ctx, query, &projection); err != nil {
		return ExecutionProjection{}, err
	}
	if err := loadExecutionProjectionApprovals(ctx, query, &projection); err != nil {
		return ExecutionProjection{}, err
	}
	if err := loadExecutionProjectionArtifacts(ctx, query, &projection); err != nil {
		return ExecutionProjection{}, err
	}
	if err := loadExecutionProjectionCandidates(ctx, query, &projection); err != nil {
		return ExecutionProjection{}, err
	}
	return projection, nil
}

func loadExecutionProjectionScope(ctx context.Context, query executionProjectionQuerier, projection *ExecutionProjection) error {
	if projection.Execution.ScopeVersionID == nil {
		return nil
	}
	var scope ExecutionProjectionScope
	err := query.QueryRow(ctx, `SELECT id,program_id,scope_reference,scope_digest,target_plan_digest,expands_scope,acknowledged_at,created_at
		FROM scope_versions WHERE id=$1`, *projection.Execution.ScopeVersionID).Scan(
		&scope.ID, &scope.ProgramID, &scope.ScopeReference, &scope.ScopeDigest,
		&scope.TargetPlanDigest, &scope.ExpandsScope, &scope.AcknowledgedAt, &scope.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		projection.Lineage.Issues = append(projection.Lineage.Issues, ExecutionLineageScopeMissing)
		return nil
	}
	if err != nil {
		return fmt.Errorf("query execution projection scope: %w", err)
	}
	projection.Scope = &scope
	return nil
}

func loadExecutionProjectionTask(ctx context.Context, query executionProjectionQuerier, projection *ExecutionProjection) error {
	if projection.Execution.TaskID == nil {
		return nil
	}
	var task ExecutionProjectionTask
	err := query.QueryRow(ctx, `SELECT id,program_id,objective,workflow_definition_id,status,requested_by,schedule_reference,cancelled_at,created_at,updated_at
		FROM tasks WHERE id=$1`, *projection.Execution.TaskID).Scan(
		&task.ID, &task.ProgramID, &task.Objective, &task.WorkflowDefinitionID,
		&task.Status, &task.RequestedBy, &task.ScheduleReference, &task.CancelledAt,
		&task.CreatedAt, &task.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		projection.Lineage.Issues = append(projection.Lineage.Issues, ExecutionLineageTaskMissing)
		return nil
	}
	if err != nil {
		return fmt.Errorf("query execution projection task: %w", err)
	}
	projection.Task = &task
	return nil
}

func loadExecutionProjectionWorkflow(ctx context.Context, query executionProjectionQuerier, projection *ExecutionProjection) error {
	if projection.Execution.WorkflowRunID == nil {
		return nil
	}
	var workflow ExecutionProjectionWorkflow
	var definitionExists bool
	var definitionVersion string
	err := query.QueryRow(ctx, `SELECT wr.id,wr.task_id,wr.workflow_definition_id,COALESCE(wd.name,''),COALESCE(wd.version,''),wd.id IS NOT NULL,
		wr.workflow_version,wr.status,wr.started_at,wr.completed_at,wr.previous_run_id,wr.trigger_source
		FROM workflow_runs wr
		LEFT JOIN workflow_definitions wd ON wd.id=wr.workflow_definition_id
		WHERE wr.id=$1`, *projection.Execution.WorkflowRunID).Scan(
		&workflow.ID, &workflow.TaskID, &workflow.WorkflowDefinitionID,
		&workflow.DefinitionName, &definitionVersion, &definitionExists, &workflow.WorkflowVersion,
		&workflow.Status, &workflow.StartedAt, &workflow.CompletedAt,
		&workflow.PreviousRunID, &workflow.TriggerSource,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		projection.Lineage.Issues = append(projection.Lineage.Issues, ExecutionLineageWorkflowMissing)
		return nil
	}
	if err != nil {
		return fmt.Errorf("query execution projection workflow: %w", err)
	}
	if !definitionExists {
		projection.Lineage.Issues = append(projection.Lineage.Issues, ExecutionLineageWorkflowDefinitionMissing)
	} else if workflow.WorkflowVersion != definitionVersion {
		projection.Lineage.Issues = append(projection.Lineage.Issues, ExecutionLineageWorkflowDefinitionVersionMismatch)
	}
	projection.Workflow = &workflow
	return nil
}

func loadExecutionProjectionSteps(ctx context.Context, query executionProjectionQuerier, projection *ExecutionProjection) error {
	if projection.Workflow == nil {
		return nil
	}
	rows, err := query.Query(ctx, `SELECT id,workflow_run_id,step_definition_id,capability,status,attempt_count,error_classification,started_at,completed_at,approval_state
		FROM step_runs
		WHERE workflow_run_id=$1
		ORDER BY step_definition_id,id`, projection.Workflow.ID)
	if err != nil {
		return fmt.Errorf("query execution projection steps: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var step ExecutionProjectionStep
		if err := rows.Scan(
			&step.ID, &step.WorkflowRunID, &step.StepDefinitionID, &step.Capability,
			&step.Status, &step.AttemptCount, &step.ErrorClassification,
			&step.StartedAt, &step.CompletedAt, &step.ApprovalState,
		); err != nil {
			return fmt.Errorf("scan execution projection step: %w", err)
		}
		projection.Steps = append(projection.Steps, step)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate execution projection steps: %w", err)
	}
	return nil
}

func deriveExecutionLineageIssues(projection *ExecutionProjection) {
	if projection.Scope != nil && projection.Scope.ProgramID != projection.Execution.ProgramID {
		projection.Lineage.Issues = append(projection.Lineage.Issues, ExecutionLineageScopeProgramMismatch)
	}
	if projection.Task != nil && projection.Task.ProgramID != projection.Execution.ProgramID {
		projection.Lineage.Issues = append(projection.Lineage.Issues, ExecutionLineageTaskProgramMismatch)
	}
	if projection.Workflow == nil {
		return
	}
	if projection.Execution.TaskID == nil {
		projection.Lineage.Issues = append(projection.Lineage.Issues, ExecutionLineageWorkflowWithoutTask)
	} else if projection.Workflow.TaskID != *projection.Execution.TaskID {
		projection.Lineage.Issues = append(projection.Lineage.Issues, ExecutionLineageWorkflowTaskMismatch)
	}
	if projection.Task != nil && projection.Workflow.WorkflowDefinitionID != projection.Task.WorkflowDefinitionID {
		projection.Lineage.Issues = append(projection.Lineage.Issues, ExecutionLineageWorkflowDefinitionMismatch)
	}
}

// deriveExecutionLeaseState describes persisted scheduler lease health at one
// database-sourced observation time. Scheduler transitions only retain a
// complete owner/expiry pair while claimed or running. Pause, terminal,
// recovery, and resume transitions release both fields. Pending with attempts
// therefore means a previous lease was released; pending without attempts and
// never-claimed terminal rows have no applicable lease. Any partial pair,
// active status without a lease, lease on another status, non-positive leased
// attempt, negative attempt, or unknown status is inconsistent.
func deriveExecutionLeaseState(status domain.ScheduledExecutionStatus, attemptCount int, owner string, expiresAt *time.Time, observedAt time.Time) ExecutionLeaseState {
	if attemptCount < 0 || !knownScheduledExecutionStatus(status) {
		return ExecutionLeaseInconsistent
	}
	hasOwner := owner != ""
	hasExpiry := expiresAt != nil
	if hasOwner != hasExpiry {
		return ExecutionLeaseInconsistent
	}
	activeStatus := status == domain.ScheduledExecutionClaimed || status == domain.ScheduledExecutionRunning
	if hasOwner {
		if !activeStatus || attemptCount == 0 {
			return ExecutionLeaseInconsistent
		}
		if expiresAt.After(observedAt) {
			return ExecutionLeaseActive
		}
		return ExecutionLeaseExpired
	}
	if activeStatus {
		return ExecutionLeaseInconsistent
	}
	if attemptCount == 0 {
		return ExecutionLeaseNotApplicable
	}
	return ExecutionLeaseReleased
}

func knownScheduledExecutionStatus(status domain.ScheduledExecutionStatus) bool {
	switch status {
	case domain.ScheduledExecutionPending,
		domain.ScheduledExecutionClaimed,
		domain.ScheduledExecutionRunning,
		domain.ScheduledExecutionPausedForApproval,
		domain.ScheduledExecutionPausedOperator,
		domain.ScheduledExecutionCompleted,
		domain.ScheduledExecutionFailed,
		domain.ScheduledExecutionCancelled,
		domain.ScheduledExecutionBlockedScopeChange,
		domain.ScheduledExecutionApprovalRejected,
		domain.ScheduledExecutionSkippedOverlap,
		domain.ScheduledExecutionInterrupted:
		return true
	default:
		return false
	}
}
