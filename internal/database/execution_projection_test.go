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
		Steps:   []ExecutionProjectionStep{},
		Lineage: ExecutionProjectionLineage{Issues: []ExecutionLineageIssue{}},
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
		`"execution_environment":`,
		`"storage_location":`,
		`"audit_details":`,
	} {
		if strings.Contains(serialized, excluded) {
			t.Fatalf("projection serialized excluded field %s: %s", excluded, serialized)
		}
	}
	if !strings.Contains(serialized, `"steps":[]`) || !strings.Contains(serialized, `"issues":[]`) {
		t.Fatalf("projection must serialize empty collections, got %s", serialized)
	}
}
