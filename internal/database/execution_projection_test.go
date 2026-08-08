package database

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestExecutionProjectionTransactionOptions(t *testing.T) {
	if executionProjectionTxOptions.IsoLevel != pgx.RepeatableRead {
		t.Fatalf("isolation = %q, want %q", executionProjectionTxOptions.IsoLevel, pgx.RepeatableRead)
	}
	if executionProjectionTxOptions.AccessMode != pgx.ReadOnly {
		t.Fatalf("access mode = %q, want %q", executionProjectionTxOptions.AccessMode, pgx.ReadOnly)
	}
}

func TestExecutionProjectionRootUsesOnePostgreSQLStatementTimestamp(t *testing.T) {
	if count := strings.Count(executionProjectionRootQuery, "statement_timestamp()"); count != 1 {
		t.Fatalf("root query statement_timestamp count = %d, want 1", count)
	}
	if strings.Contains(executionProjectionRootQuery, "clock_timestamp()") {
		t.Fatal("root query must not use clock_timestamp")
	}
}

func TestExecutionProjectionEvidenceCollectionContracts(t *testing.T) {
	if executionProjectionToolRunLimit != 64 || executionProjectionApprovalLimit != 32 || executionProjectionArtifactLimit != 128 || executionProjectionCandidateLimit != 64 || executionProjectionChangeItemLimit != 64 {
		t.Fatalf("collection limits tool=%d approval=%d artifact=%d candidate=%d change_item=%d", executionProjectionToolRunLimit, executionProjectionApprovalLimit, executionProjectionArtifactLimit, executionProjectionCandidateLimit, executionProjectionChangeItemLimit)
	}
	for name, query := range map[string]string{
		"tool runs":  executionProjectionToolRunsQuery,
		"approvals":  executionProjectionApprovalsQuery,
		"artifacts":  executionProjectionArtifactsQuery,
		"candidates": executionProjectionCandidatesQuery,
	} {
		if count := strings.Count(query, "count(*) OVER()"); count != 1 {
			t.Fatalf("%s window count = %d, want 1", name, count)
		}
	}
	if strings.Contains(executionProjectionToolRunsQuery, "sanitized_arguments") || strings.Contains(executionProjectionToolRunsQuery, "execution_environment") {
		t.Fatalf("tool query selects unsafe state: %s", executionProjectionToolRunsQuery)
	}
	if !strings.Contains(executionProjectionApprovalsQuery, "JOIN step_runs sr ON sr.id=a.request_id") || strings.Contains(executionProjectionApprovalsQuery, "action_request_id") {
		t.Fatalf("approval query does not use the step membership contract: %s", executionProjectionApprovalsQuery)
	}
	if !strings.Contains(executionProjectionApprovalsQuery, "bool_or(a.task_id<>$2) OVER()") {
		t.Fatalf("approval query does not aggregate pre-limit inconsistency: %s", executionProjectionApprovalsQuery)
	}
	if !strings.Contains(executionProjectionArtifactsQuery, "a.expires_at>$2") ||
		!strings.Contains(executionProjectionArtifactsQuery, "bool_or(a.task_id<>$3 OR sr.workflow_run_id IS DISTINCT FROM $1 OR tr.step_run_id IS DISTINCT FROM a.step_run_id) OVER()") ||
		strings.Contains(executionProjectionArtifactsQuery, "now()") ||
		strings.Contains(executionProjectionArtifactsQuery, "clock_timestamp()") ||
		strings.Contains(executionProjectionArtifactsQuery, "storage_location") {
		t.Fatalf("artifact query violates visibility or allow-list contract: %s", executionProjectionArtifactsQuery)
	}
	if !strings.Contains(executionProjectionCandidatesQuery, "LEFT JOIN assets a ON a.id=cf.target_asset_id") ||
		!strings.Contains(executionProjectionCandidatesQuery, "WHERE cf.workflow_run_id=$1") ||
		!strings.Contains(executionProjectionCandidatesQuery, "bool_or(cf.task_id<>$2 OR a.program_id IS DISTINCT FROM $3) OVER()") ||
		!strings.Contains(executionProjectionCandidatesQuery, "ORDER BY cf.created_at ASC,cf.id ASC") {
		t.Fatalf("candidate query violates membership, lineage, or ordering contract: %s", executionProjectionCandidatesQuery)
	}
	for _, excluded := range []string{"canonical_value", "template_id", "claimed_vulnerability", "severity", "verification_results", "storage_location"} {
		if strings.Contains(executionProjectionCandidatesQuery, excluded) {
			t.Fatalf("candidate query selects excluded field %q: %s", excluded, executionProjectionCandidatesQuery)
		}
	}
}

func TestExecutionProjectionChangeItemQueryContract(t *testing.T) {
	query := strings.ToLower(executionProjectionChangeItemsQuery)
	for _, required := range []string{
		"count(*) over()",
		"bool_or(ci.workflow_run_id is distinct from $2 or ci.program_id is distinct from $3) over()",
		"where ci.scheduled_execution_id=$1",
		"order by ci.observed_at asc,ci.created_at asc,ci.id asc",
		"limit $4",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("change-item query missing %q: %s", required, executionProjectionChangeItemsQuery)
		}
	}
	where := strings.Index(query, "where ")
	order := strings.Index(query, "order by ")
	if where < 0 || order < where {
		t.Fatalf("change-item query has no bounded membership clause: %s", executionProjectionChangeItemsQuery)
	}
	membership := query[where:order]
	if strings.Contains(membership, "workflow_run_id") || strings.Contains(membership, "program_id") {
		t.Fatalf("change-item membership must use only scheduled_execution_id: %s", membership)
	}
	for _, excluded := range []string{
		"ci.entity_key", "ci.title", "ci.safe_summary", "ci.reasons", "ci.previous_value", "ci.current_value",
		"change_reviews", " join ", "verification_results", "verified_findings",
	} {
		if strings.Contains(query, excluded) {
			t.Fatalf("change-item query selects or dereferences excluded state %q: %s", excluded, executionProjectionChangeItemsQuery)
		}
	}
}

func TestExecutionProjectionAssetObservationSummaryQueryContract(t *testing.T) {
	query := strings.ToLower(executionProjectionAssetObservationsQuery)
	for _, required := range []string{
		"count(*)",
		"count(distinct ao.asset_id)",
		"left join assets a on a.id=ao.asset_id",
		"a.program_id is distinct from $2",
		"where ao.workflow_run_id=$1",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("observation summary query missing %q: %s", required, executionProjectionAssetObservationsQuery)
		}
	}
	where := strings.Index(query, "where ")
	if where < 0 || strings.TrimSpace(query[where:]) != "where ao.workflow_run_id=$1" {
		t.Fatalf("observation membership must filter only by workflow_run_id: %s", executionProjectionAssetObservationsQuery)
	}
	for _, excluded := range []string{"observed_value", "metadata", "canonical_value", "evidence_artifact_ids", "source_capability"} {
		if strings.Contains(query, excluded) {
			t.Fatalf("observation summary query selects excluded field %q: %s", excluded, executionProjectionAssetObservationsQuery)
		}
	}
}

func TestExecutionProjectionCollectionFinalization(t *testing.T) {
	collection := newExecutionProjectionCollection[int]()
	if collection.Items == nil || collection.Total != 0 || collection.Truncated {
		t.Fatalf("empty collection = %#v", collection)
	}
	collection.Items = append(collection.Items, 1, 2)
	collection.Total = 3
	finalizeExecutionProjectionCollection(&collection)
	if !collection.Truncated {
		t.Fatalf("bounded collection = %#v, want truncated", collection)
	}
	collection.Total = 2
	finalizeExecutionProjectionCollection(&collection)
	if collection.Truncated {
		t.Fatalf("complete collection = %#v, want not truncated", collection)
	}
}

func TestDeriveExecutionLeaseStateUsesCapturedObservedAt(t *testing.T) {
	expiresAt := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	beforeExpiry := expiresAt.Add(-time.Nanosecond)
	if got := deriveExecutionLeaseState(domain.ScheduledExecutionRunning, 1, "worker", &expiresAt, beforeExpiry); got != ExecutionLeaseActive {
		t.Fatalf("lease before captured expiry = %q, want %q", got, ExecutionLeaseActive)
	}
	if got := deriveExecutionLeaseState(domain.ScheduledExecutionRunning, 1, "worker", &expiresAt, expiresAt); got != ExecutionLeaseExpired {
		t.Fatalf("lease at captured expiry = %q, want %q", got, ExecutionLeaseExpired)
	}
}

func TestDeriveExecutionLeaseState(t *testing.T) {
	observedAt := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	past := observedAt.Add(-time.Second)
	equal := observedAt
	future := observedAt.Add(time.Second)

	tests := []struct {
		name         string
		status       domain.ScheduledExecutionStatus
		attemptCount int
		owner        string
		expiresAt    *time.Time
		want         ExecutionLeaseState
	}{
		{name: "new pending execution", status: domain.ScheduledExecutionPending, want: ExecutionLeaseNotApplicable},
		{name: "never claimed skipped execution", status: domain.ScheduledExecutionSkippedOverlap, want: ExecutionLeaseNotApplicable},
		{name: "requeued execution", status: domain.ScheduledExecutionPending, attemptCount: 1, want: ExecutionLeaseReleased},
		{name: "paused execution", status: domain.ScheduledExecutionPausedOperator, attemptCount: 1, want: ExecutionLeaseReleased},
		{name: "completed execution", status: domain.ScheduledExecutionCompleted, attemptCount: 1, want: ExecutionLeaseReleased},
		{name: "active claimed lease", status: domain.ScheduledExecutionClaimed, attemptCount: 1, owner: "worker", expiresAt: &future, want: ExecutionLeaseActive},
		{name: "active running lease", status: domain.ScheduledExecutionRunning, attemptCount: 2, owner: "worker", expiresAt: &future, want: ExecutionLeaseActive},
		{name: "expired claimed lease", status: domain.ScheduledExecutionClaimed, attemptCount: 1, owner: "worker", expiresAt: &past, want: ExecutionLeaseExpired},
		{name: "lease expires at observation", status: domain.ScheduledExecutionRunning, attemptCount: 1, owner: "worker", expiresAt: &equal, want: ExecutionLeaseExpired},
		{name: "owner without expiry", status: domain.ScheduledExecutionClaimed, attemptCount: 1, owner: "worker", want: ExecutionLeaseInconsistent},
		{name: "expiry without owner", status: domain.ScheduledExecutionClaimed, attemptCount: 1, expiresAt: &future, want: ExecutionLeaseInconsistent},
		{name: "active status without lease", status: domain.ScheduledExecutionRunning, attemptCount: 1, want: ExecutionLeaseInconsistent},
		{name: "lease on pending status", status: domain.ScheduledExecutionPending, attemptCount: 1, owner: "worker", expiresAt: &future, want: ExecutionLeaseInconsistent},
		{name: "leased zero attempt", status: domain.ScheduledExecutionClaimed, owner: "worker", expiresAt: &future, want: ExecutionLeaseInconsistent},
		{name: "negative attempt", status: domain.ScheduledExecutionPending, attemptCount: -1, want: ExecutionLeaseInconsistent},
		{name: "unknown status", status: domain.ScheduledExecutionStatus("unknown"), want: ExecutionLeaseInconsistent},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := deriveExecutionLeaseState(test.status, test.attemptCount, test.owner, test.expiresAt, observedAt)
			if got != test.want {
				t.Fatalf("deriveExecutionLeaseState() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestExecutionProjectionJSONOmitsUnsafeState(t *testing.T) {
	projection := ExecutionProjection{
		Steps:       []ExecutionProjectionStep{},
		ToolRuns:    newExecutionProjectionCollection[ExecutionProjectionToolRun](),
		Approvals:   newExecutionProjectionCollection[ExecutionProjectionApproval](),
		Artifacts:   newExecutionProjectionCollection[ExecutionProjectionArtifact](),
		Candidates:  newExecutionProjectionCollection[ExecutionProjectionCandidate](),
		ChangeItems: newExecutionProjectionCollection[ExecutionProjectionChangeItem](),
		Lineage:     ExecutionProjectionLineage{Issues: []ExecutionLineageIssue{}},
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(encoded)
	for _, excluded := range []string{
		`"input":`,
		`"output":`,
		`"error_details":`,
		`"summary":`,
		`"definition":`,
		`"sanitized_arguments":`,
		`"execution_environment":`,
		`"action_request_id":`,
		`"storage_location":`,
		`"audit_details":`,
		`"entity_key":`,
		`"safe_summary":`,
		`"reasons":`,
		`"previous_value":`,
		`"current_value":`,
		`"change_reviews":`,
		`"reviewed_by":`,
		`"reviewed_at":`,
	} {
		if strings.Contains(serialized, excluded) {
			t.Fatalf("projection serialized excluded field %s: %s", excluded, serialized)
		}
	}
	for _, empty := range []string{
		`"steps":[]`,
		`"tool_runs":{"items":[],"total":0,"truncated":false}`,
		`"approvals":{"items":[],"total":0,"truncated":false}`,
		`"artifacts":{"items":[],"total":0,"truncated":false}`,
		`"candidate_findings":{"items":[],"total":0,"truncated":false}`,
		`"asset_observations":{"total":0,"distinct_asset_count":0}`,
		`"change_items":{"items":[],"total":0,"truncated":false}`,
		`"issues":[]`,
	} {
		if !strings.Contains(serialized, empty) {
			t.Fatalf("projection must serialize empty collection %s, got %s", empty, serialized)
		}
	}
}
