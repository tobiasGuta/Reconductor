package database

import (
	"context"
	"fmt"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

const (
	executionProjectionToolRunLimit  = 64
	executionProjectionApprovalLimit = 32
	executionProjectionArtifactLimit = 128

	executionProjectionToolRunsQuery = `SELECT tr.id,tr.step_run_id,sr.step_definition_id,tr.capability,tr.provider,tr.tool_version,
		tr.started_at,tr.completed_at,tr.exit_code,tr.timed_out,tr.stdout_artifact_id,tr.stderr_artifact_id,count(*) OVER()
		FROM tool_runs tr
		JOIN step_runs sr ON sr.id=tr.step_run_id
		WHERE sr.workflow_run_id=$1
		ORDER BY tr.started_at ASC,tr.id ASC
		LIMIT $2`
	executionProjectionApprovalsQuery = `SELECT a.id,a.request_id,a.task_id,a.requested_risk_level,a.reason,a.requested_at,
		a.decision,a.decided_by,a.decided_at,a.expires_at,count(*) OVER(),bool_or(a.task_id<>$2) OVER()
		FROM approvals a
		JOIN step_runs sr ON sr.id=a.request_id
		WHERE sr.workflow_run_id=$1
		ORDER BY a.requested_at ASC,a.id ASC
		LIMIT $3`
	executionProjectionArtifactsQuery = `SELECT a.id,a.task_id,a.workflow_run_id,a.step_run_id,a.tool_run_id,a.type,a.content_type,
		a.size,a.sha256,a.redaction_state,a.created_at,a.expires_at,count(*) OVER(),
		bool_or(a.task_id<>$3 OR sr.workflow_run_id IS DISTINCT FROM $1 OR tr.step_run_id IS DISTINCT FROM a.step_run_id) OVER()
		FROM artifacts a
		LEFT JOIN step_runs sr ON sr.id=a.step_run_id
		LEFT JOIN tool_runs tr ON tr.id=a.tool_run_id
		WHERE a.workflow_run_id=$1
		  AND a.sensitive=false
		  AND (a.expires_at IS NULL OR a.expires_at>$2)
		ORDER BY a.created_at ASC,a.id ASC
		LIMIT $4`
)

// ExecutionProjectionCollection is a bounded child collection observed in the
// same database snapshot as its execution projection. Total counts only items
// visible under the collection's projection policy.
type ExecutionProjectionCollection[T any] struct {
	Items     []T   `json:"items"`
	Total     int64 `json:"total"`
	Truncated bool  `json:"truncated"`
}

type ExecutionProjectionToolRun struct {
	ID               domain.ID  `json:"id"`
	StepRunID        domain.ID  `json:"step_run_id"`
	StepDefinitionID string     `json:"step_definition_id"`
	Capability       string     `json:"capability"`
	Provider         string     `json:"provider"`
	ToolVersion      string     `json:"tool_version"`
	StartedAt        time.Time  `json:"started_at"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	ExitCode         *int       `json:"exit_code,omitempty"`
	TimedOut         bool       `json:"timed_out"`
	StdoutArtifactID *domain.ID `json:"stdout_artifact_id,omitempty"`
	StderrArtifactID *domain.ID `json:"stderr_artifact_id,omitempty"`
}

type ExecutionProjectionApproval struct {
	ID                 domain.ID  `json:"id"`
	StepRunID          domain.ID  `json:"step_run_id"`
	TaskID             domain.ID  `json:"task_id"`
	RequestedRiskLevel string     `json:"requested_risk_level"`
	Reason             string     `json:"reason"`
	RequestedAt        time.Time  `json:"requested_at"`
	Decision           string     `json:"decision"`
	DecidedBy          *string    `json:"decided_by,omitempty"`
	DecidedAt          *time.Time `json:"decided_at,omitempty"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
}

type ExecutionProjectionArtifact struct {
	ID             domain.ID  `json:"id"`
	TaskID         domain.ID  `json:"task_id"`
	WorkflowRunID  domain.ID  `json:"workflow_run_id"`
	StepRunID      domain.ID  `json:"step_run_id"`
	ToolRunID      domain.ID  `json:"tool_run_id"`
	Type           string     `json:"type"`
	ContentType    string     `json:"content_type"`
	Size           int64      `json:"size"`
	SHA256         string     `json:"sha256"`
	RedactionState string     `json:"redaction_state"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

func newExecutionProjectionCollection[T any]() ExecutionProjectionCollection[T] {
	return ExecutionProjectionCollection[T]{Items: []T{}}
}

func finalizeExecutionProjectionCollection[T any](collection *ExecutionProjectionCollection[T]) {
	collection.Truncated = collection.Total > int64(len(collection.Items))
}

func loadExecutionProjectionToolRuns(ctx context.Context, query executionProjectionQuerier, projection *ExecutionProjection) error {
	if projection.Workflow == nil {
		return nil
	}
	rows, err := query.Query(ctx, executionProjectionToolRunsQuery, projection.Workflow.ID, executionProjectionToolRunLimit)
	if err != nil {
		return fmt.Errorf("query execution projection tool runs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var item ExecutionProjectionToolRun
		if err := rows.Scan(
			&item.ID, &item.StepRunID, &item.StepDefinitionID, &item.Capability,
			&item.Provider, &item.ToolVersion, &item.StartedAt, &item.CompletedAt,
			&item.ExitCode, &item.TimedOut, &item.StdoutArtifactID, &item.StderrArtifactID,
			&projection.ToolRuns.Total,
		); err != nil {
			return fmt.Errorf("scan execution projection tool run: %w", err)
		}
		projection.ToolRuns.Items = append(projection.ToolRuns.Items, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate execution projection tool runs: %w", err)
	}
	finalizeExecutionProjectionCollection(&projection.ToolRuns)
	return nil
}

func loadExecutionProjectionApprovals(ctx context.Context, query executionProjectionQuerier, projection *ExecutionProjection) error {
	if projection.Workflow == nil {
		return nil
	}
	rows, err := query.Query(ctx, executionProjectionApprovalsQuery, projection.Workflow.ID, projection.Workflow.TaskID, executionProjectionApprovalLimit)
	if err != nil {
		return fmt.Errorf("query execution projection approvals: %w", err)
	}
	defer rows.Close()
	inconsistent := false
	for rows.Next() {
		var item ExecutionProjectionApproval
		if err := rows.Scan(
			&item.ID, &item.StepRunID, &item.TaskID, &item.RequestedRiskLevel,
			&item.Reason, &item.RequestedAt, &item.Decision, &item.DecidedBy,
			&item.DecidedAt, &item.ExpiresAt, &projection.Approvals.Total, &inconsistent,
		); err != nil {
			return fmt.Errorf("scan execution projection approval: %w", err)
		}
		projection.Approvals.Items = append(projection.Approvals.Items, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate execution projection approvals: %w", err)
	}
	if inconsistent {
		appendExecutionLineageIssue(&projection.Lineage, ExecutionLineageApprovalInconsistent)
	}
	finalizeExecutionProjectionCollection(&projection.Approvals)
	return nil
}

func loadExecutionProjectionArtifacts(ctx context.Context, query executionProjectionQuerier, projection *ExecutionProjection) error {
	if projection.Workflow == nil {
		return nil
	}
	rows, err := query.Query(ctx, executionProjectionArtifactsQuery, projection.Workflow.ID, projection.ObservedAt, projection.Workflow.TaskID, executionProjectionArtifactLimit)
	if err != nil {
		return fmt.Errorf("query execution projection artifacts: %w", err)
	}
	defer rows.Close()
	inconsistent := false
	for rows.Next() {
		var item ExecutionProjectionArtifact
		if err := rows.Scan(
			&item.ID, &item.TaskID, &item.WorkflowRunID, &item.StepRunID, &item.ToolRunID,
			&item.Type, &item.ContentType, &item.Size, &item.SHA256, &item.RedactionState,
			&item.CreatedAt, &item.ExpiresAt, &projection.Artifacts.Total, &inconsistent,
		); err != nil {
			return fmt.Errorf("scan execution projection artifact: %w", err)
		}
		projection.Artifacts.Items = append(projection.Artifacts.Items, item)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate execution projection artifacts: %w", err)
	}
	if inconsistent {
		appendExecutionLineageIssue(&projection.Lineage, ExecutionLineageArtifactInconsistent)
	}
	finalizeExecutionProjectionCollection(&projection.Artifacts)
	return nil
}

func appendExecutionLineageIssue(lineage *ExecutionProjectionLineage, issue ExecutionLineageIssue) {
	for _, existing := range lineage.Issues {
		if existing == issue {
			return
		}
	}
	lineage.Issues = append(lineage.Issues, issue)
}
