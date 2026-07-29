package domain

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type ID string

func NewID() ID {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("generate id: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return ID(hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" + hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16]))
}

type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"
	TaskRunning   TaskStatus = "running"
	TaskPaused    TaskStatus = "paused"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
	TaskCancelled TaskStatus = "cancelled"
)

type RunStatus string

const (
	RunPending   RunStatus = "pending"
	RunRunning   RunStatus = "running"
	RunPaused    RunStatus = "paused"
	RunCompleted RunStatus = "completed"
	RunFailed    RunStatus = "failed"
	RunCancelled RunStatus = "cancelled"
)

type StepStatus string

const (
	StepPending          StepStatus = "pending"
	StepBlocked          StepStatus = "blocked"
	StepAwaitingApproval StepStatus = "awaiting_approval"
	StepQueued           StepStatus = "queued"
	StepRunning          StepStatus = "running"
	StepSucceeded        StepStatus = "succeeded"
	StepFailed           StepStatus = "failed"
	StepRetryable        StepStatus = "retryable"
	StepSkipped          StepStatus = "skipped"
	StepCancelled        StepStatus = "cancelled"
)

type Program struct {
	ID                 ID              `json:"id"`
	Name               string          `json:"name"`
	Platform           string          `json:"platform"`
	Description        string          `json:"description"`
	ScopeReference     string          `json:"scope_reference"`
	PolicyReference    string          `json:"policy_reference"`
	ScopeDigest        string          `json:"scope_digest"`
	IncludeRuleDigests []string        `json:"include_rule_digests"`
	ExcludeRuleDigests []string        `json:"exclude_rule_digests"`
	TargetPlanDigest   string          `json:"target_plan_digest"`
	ScopePlanWarnings  json.RawMessage `json:"scope_plan_warnings"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

type ScopeSnapshot struct {
	ID                    ID              `json:"id"`
	ProgramID             ID              `json:"program_id"`
	ScopeReference        string          `json:"scope_reference"`
	ScopeDigest           string          `json:"scope_digest"`
	IncludeRuleDigests    []string        `json:"include_rule_digests"`
	ExcludeRuleDigests    []string        `json:"exclude_rule_digests"`
	TargetPlanDigest      string          `json:"target_plan_digest"`
	PlanningWarnings      json.RawMessage `json:"planning_warnings"`
	TargetPlan            json.RawMessage `json:"target_plan"`
	ExpandsScope          bool            `json:"expands_scope"`
	AddedIncludeDigests   []string        `json:"added_include_digests"`
	RemovedIncludeDigests []string        `json:"removed_include_digests"`
	AddedExcludeDigests   []string        `json:"added_exclude_digests"`
	RemovedExcludeDigests []string        `json:"removed_exclude_digests"`
	AcknowledgedBy        string          `json:"acknowledged_by,omitempty"`
	AcknowledgedAt        *time.Time      `json:"acknowledged_at,omitempty"`
	CreatedAt             time.Time       `json:"created_at"`
}

type ScopeChange struct {
	Changed               bool     `json:"changed"`
	ExpandsScope          bool     `json:"expands_scope"`
	Acknowledged          bool     `json:"acknowledged"`
	ScopeVersionID        ID       `json:"scope_version_id,omitempty"`
	AddedIncludeDigests   []string `json:"added_include_digests"`
	RemovedIncludeDigests []string `json:"removed_include_digests"`
	AddedExcludeDigests   []string `json:"added_exclude_digests"`
	RemovedExcludeDigests []string `json:"removed_exclude_digests"`
}

type ScheduledExecutionStatus string

const (
	ScheduledExecutionPending            ScheduledExecutionStatus = "pending"
	ScheduledExecutionClaimed            ScheduledExecutionStatus = "claimed"
	ScheduledExecutionRunning            ScheduledExecutionStatus = "running"
	ScheduledExecutionPausedForApproval  ScheduledExecutionStatus = "paused_for_approval"
	ScheduledExecutionPausedOperator     ScheduledExecutionStatus = "paused_operator"
	ScheduledExecutionCompleted          ScheduledExecutionStatus = "completed"
	ScheduledExecutionFailed             ScheduledExecutionStatus = "failed"
	ScheduledExecutionCancelled          ScheduledExecutionStatus = "cancelled"
	ScheduledExecutionBlockedScopeChange ScheduledExecutionStatus = "blocked_scope_change"
	ScheduledExecutionApprovalRejected   ScheduledExecutionStatus = "approval_rejected"
	ScheduledExecutionSkippedOverlap     ScheduledExecutionStatus = "skipped_overlap"
	ScheduledExecutionInterrupted        ScheduledExecutionStatus = "interrupted"
)

const (
	ScheduleTriggerScheduled = "scheduled"
	ScheduleTriggerRunNow    = "run_now"
	ScheduleTriggerResume    = "resume"
)

type Schedule struct {
	ID             ID         `json:"id"`
	ProgramID      ID         `json:"program_id"`
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

type ScheduledExecution struct {
	ID                  ID                       `json:"id"`
	ScheduleID          ID                       `json:"schedule_id"`
	PlannedAt           time.Time                `json:"planned_at"`
	TriggerSource       string                   `json:"trigger_source"`
	Status              ScheduledExecutionStatus `json:"status"`
	TaskID              *ID                      `json:"task_id,omitempty"`
	WorkflowRunID       *ID                      `json:"workflow_run_id,omitempty"`
	ScopeVersionID      *ID                      `json:"scope_version_id,omitempty"`
	AttemptCount        int                      `json:"attempt_count"`
	LeaseOwner          string                   `json:"lease_owner,omitempty"`
	LeaseExpiresAt      *time.Time               `json:"lease_expires_at,omitempty"`
	ErrorClassification string                   `json:"error_classification,omitempty"`
	ErrorSummary        string                   `json:"error_summary,omitempty"`
	StartedAt           *time.Time               `json:"started_at,omitempty"`
	CompletedAt         *time.Time               `json:"completed_at,omitempty"`
	CreatedAt           time.Time                `json:"created_at"`
	UpdatedAt           time.Time                `json:"updated_at"`
}

type ChangeReviewDisposition string

const (
	ChangeReviewUnreviewed     ChangeReviewDisposition = "unreviewed"
	ChangeReviewInteresting    ChangeReviewDisposition = "interesting"
	ChangeReviewInvestigating  ChangeReviewDisposition = "investigating"
	ChangeReviewExpectedChange ChangeReviewDisposition = "expected_change"
	ChangeReviewNotRelevant    ChangeReviewDisposition = "not_relevant"
	ChangeReviewResolved       ChangeReviewDisposition = "resolved"
)

type ChangeItem struct {
	ID                   ID              `json:"id"`
	ProgramID            ID              `json:"program_id"`
	WorkflowRunID        ID              `json:"workflow_run_id"`
	ScheduledExecutionID *ID             `json:"scheduled_execution_id,omitempty"`
	Kind                 string          `json:"kind"`
	EntityType           string          `json:"entity_type"`
	EntityKey            string          `json:"entity_key"`
	Priority             string          `json:"priority"`
	Title                string          `json:"title"`
	Summary              string          `json:"summary"`
	Reasons              json.RawMessage `json:"reasons"`
	Previous             json.RawMessage `json:"previous,omitempty"`
	Current              json.RawMessage `json:"current,omitempty"`
	SourceCapabilities   []string        `json:"source_capabilities"`
	EvidenceArtifactIDs  []ID            `json:"evidence_artifact_ids"`
	ObservedAt           time.Time       `json:"observed_at"`
	CreatedAt            time.Time       `json:"created_at"`
}

type ChangeReview struct {
	ID           ID                      `json:"id"`
	ChangeItemID ID                      `json:"change_item_id"`
	Disposition  ChangeReviewDisposition `json:"disposition"`
	Note         string                  `json:"note"`
	ReviewedBy   string                  `json:"reviewed_by"`
	ReviewedAt   time.Time               `json:"reviewed_at"`
	CreatedAt    time.Time               `json:"created_at"`
	UpdatedAt    time.Time               `json:"updated_at"`
}
type Task struct {
	ID                   ID         `json:"id"`
	ProgramID            ID         `json:"program_id"`
	Objective            string     `json:"objective"`
	WorkflowDefinitionID ID         `json:"workflow_definition_id"`
	Status               TaskStatus `json:"status"`
	RequestedBy          string     `json:"requested_by"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	ScheduleReference    *string    `json:"schedule_reference,omitempty"`
	CancelledAt          *time.Time `json:"cancelled_at,omitempty"`
	CancellationReason   string     `json:"cancellation_reason,omitempty"`
}
type WorkflowRun struct {
	ID                   ID              `json:"id"`
	TaskID               ID              `json:"task_id"`
	WorkflowDefinitionID ID              `json:"workflow_definition_id"`
	WorkflowVersion      string          `json:"workflow_version"`
	Status               RunStatus       `json:"status"`
	StartedAt            *time.Time      `json:"started_at,omitempty"`
	CompletedAt          *time.Time      `json:"completed_at,omitempty"`
	PreviousRunID        *ID             `json:"previous_run_id,omitempty"`
	TriggerSource        string          `json:"trigger_source"`
	Summary              json.RawMessage `json:"summary,omitempty"`
}
type StepRun struct {
	ID                  ID              `json:"id"`
	WorkflowRunID       ID              `json:"workflow_run_id"`
	StepDefinitionID    string          `json:"step_definition_id"`
	Capability          string          `json:"capability"`
	Status              StepStatus      `json:"status"`
	AttemptCount        int             `json:"attempt_count"`
	Input               json.RawMessage `json:"input"`
	Output              json.RawMessage `json:"output,omitempty"`
	ErrorClassification string          `json:"error_classification,omitempty"`
	ErrorDetails        string          `json:"error_details,omitempty"`
	StartedAt           *time.Time      `json:"started_at,omitempty"`
	CompletedAt         *time.Time      `json:"completed_at,omitempty"`
	IdempotencyKey      string          `json:"idempotency_key"`
	ApprovalState       string          `json:"approval_state"`
}
type ToolRun struct {
	ID                   ID              `json:"id"`
	StepRunID            ID              `json:"step_run_id"`
	Capability           string          `json:"capability"`
	Provider             string          `json:"provider"`
	ToolVersion          string          `json:"tool_version"`
	SanitizedArguments   json.RawMessage `json:"sanitized_arguments"`
	ExecutionEnvironment json.RawMessage `json:"execution_environment"`
	StartedAt            time.Time       `json:"started_at"`
	CompletedAt          *time.Time      `json:"completed_at,omitempty"`
	ExitCode             *int            `json:"exit_code,omitempty"`
	TimedOut             bool            `json:"timed_out"`
	ArtifactIDs          []ID            `json:"artifact_ids"`
	StdoutArtifactID     *ID             `json:"stdout_artifact_id,omitempty"`
	StderrArtifactID     *ID             `json:"stderr_artifact_id,omitempty"`
}
type ActionRequest struct {
	ID             ID              `json:"id"`
	TaskID         ID              `json:"task_id"`
	WorkflowRunID  ID              `json:"workflow_run_id"`
	StepRunID      ID              `json:"step_run_id"`
	RequestedBy    string          `json:"requested_by"`
	Capability     string          `json:"capability"`
	Reason         string          `json:"reason"`
	Input          json.RawMessage `json:"input"`
	IdempotencyKey string          `json:"idempotency_key"`
}
type StructuredError struct {
	Classification string `json:"classification"`
	Message        string `json:"message"`
	Retryable      bool   `json:"retryable"`
}
type ActionResult struct {
	RequestID   ID               `json:"request_id"`
	Status      string           `json:"status"`
	Summary     string           `json:"summary"`
	Output      json.RawMessage  `json:"output,omitempty"`
	ArtifactIDs []ID             `json:"artifact_ids,omitempty"`
	Error       *StructuredError `json:"error,omitempty"`
}
type Artifact struct {
	ID              ID         `json:"id"`
	TaskID          ID         `json:"task_id"`
	WorkflowRunID   ID         `json:"workflow_run_id"`
	StepRunID       ID         `json:"step_run_id"`
	ToolRunID       ID         `json:"tool_run_id"`
	Type            string     `json:"type"`
	ContentType     string     `json:"content_type"`
	Size            int64      `json:"size"`
	SHA256          string     `json:"sha256"`
	StorageLocation string     `json:"storage_location"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	RedactionState  string     `json:"redaction_state"`
	Sensitive       bool       `json:"sensitive"`
}
type Asset struct {
	ID             ID        `json:"id"`
	ProgramID      ID        `json:"program_id"`
	Type           string    `json:"type"`
	CanonicalValue string    `json:"canonical_value"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
type AssetObservation struct {
	ID                  ID              `json:"id"`
	AssetID             ID              `json:"asset_id"`
	WorkflowRunID       ID              `json:"workflow_run_id"`
	SourceCapability    string          `json:"source_capability"`
	ObservedValue       string          `json:"observed_value"`
	Metadata            json.RawMessage `json:"metadata"`
	FirstSeenAt         time.Time       `json:"first_seen_at"`
	ObservedAt          time.Time       `json:"observed_at"`
	Confidence          float64         `json:"confidence"`
	EvidenceArtifactIDs []ID            `json:"evidence_artifact_ids"`
}
