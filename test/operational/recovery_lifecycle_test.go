//go:build operational

package operational

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestRecoveryLifecycle(t *testing.T) {
	operationalRunMu.Lock()
	t.Cleanup(operationalRunMu.Unlock)

	timeout := 7 * time.Minute
	if value := os.Getenv("RECONDUCTOR_E2E_TIMEOUT"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed <= 0 {
			t.Fatalf("RECONDUCTOR_E2E_TIMEOUT=%q must be a positive duration", value)
		}
		timeout = parsed
	}
	timeoutCtx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	ctx, stop := signal.NotifyContext(timeoutCtx, os.Interrupt)
	t.Cleanup(stop)

	h := newHarness(t, ctx)
	h.preflight()
	h.prepare()
	h.startInfrastructure()
	h.buildBinaries()
	h.validateTemplate()
	h.migrate()
	h.startScheduler()

	recovery := h.runToApproval("recovery")
	h.assertPreApproval(recovery)
	h.assertGuardScanCount(0)

	paused := h.captureLineage(recovery)
	h.assertPausedRecoverySnapshot("initial approval pause", paused, "pending")

	t.Log("recovery scenario A: scheduler restart while paused for approval")
	h.crashSchedulerTree()
	h.observeStoppedPollIntervals()
	stopped := h.captureLineage(recovery)
	h.assertSnapshotUnchanged("paused execution while scheduler stopped", paused, stopped)

	h.restartScheduler()
	h.observeSchedulerPollIntervals()
	restarted := h.captureLineage(recovery)
	h.assertSnapshotUnchanged("paused execution after scheduler restart", paused, restarted)
	h.assertPausedRecoverySnapshot("paused execution after scheduler restart", restarted, "pending")

	t.Log("recovery scenario B: approval recorded while scheduler is stopped")
	h.crashSchedulerTree()
	h.observeStoppedPollIntervals()
	beforeApproval := h.captureLineage(recovery)
	h.assertSnapshotUnchanged("paused execution before stopped approval", paused, beforeApproval)

	h.approveWithoutResume(recovery)
	approvedStopped := h.captureLineage(recovery)
	expectedApproved := beforeApproval
	expectedApproved.ApprovalDecision = "approved"
	h.assertSnapshotUnchanged("approval recorded while scheduler stopped", expectedApproved, approvedStopped)
	h.assertPausedRecoverySnapshot("approved execution while scheduler stopped", approvedStopped, "approved")

	h.restartScheduler()
	h.observeSchedulerPollIntervals()
	approvedPaused := h.captureLineage(recovery)
	h.assertSnapshotUnchanged("approved paused execution after scheduler restart", approvedStopped, approvedPaused)
	h.assertPausedRecoverySnapshot("approved paused execution after scheduler restart", approvedPaused, "approved")

	t.Log("recovery scenario C: explicit resume while scheduler is stopped")
	h.crashSchedulerTree()
	h.observeStoppedPollIntervals()
	beforeResume := h.captureLineage(recovery)
	h.assertSnapshotUnchanged("approved pause before explicit resume", approvedPaused, beforeResume)

	if output, err := h.runCLI("schedule", "resume", string(recovery.execution.ID)); err != nil {
		t.Fatalf("explicit schedule resume while stopped: %v (%s)", err, trimOutput(output))
	}
	pending := h.captureLineage(recovery)
	expectedPending := beforeResume
	expectedPending.ExecutionStatus = domain.ScheduledExecutionPending
	expectedPending.TriggerSource = domain.ScheduleTriggerResume
	expectedPending.ResumeAuditCount++
	h.assertSnapshotUnchanged("safe pre-claim resume state", expectedPending, pending)
	if pending.LeaseOwner != "" || pending.LeaseExpiresAt != nil {
		t.Fatalf("resumed pending execution retained lease owner=%q expiry=%v", pending.LeaseOwner, pending.LeaseExpiresAt)
	}

	h.restartScheduler()
	recovery.execution = h.waitExecution(recovery.schedule.ID, recovery.execution.ID, domain.ScheduledExecutionCompleted)
	recovery.state = h.waitWorkflowState(*recovery.execution.WorkflowRunID, domain.RunCompleted)
	completed := h.captureLineage(recovery)
	h.assertStableLineage("completed resumed execution", pending, completed, "enrich-recon-brief")
	h.assertPriorSucceededStepsUnchanged("completed resumed execution", pending, completed)
	h.assertCompletedRecoverySnapshot(pending, completed)
	h.assertApprovedCompletion(recovery)
}

func (h *harness) assertPausedRecoverySnapshot(name string, snapshot lineageSnapshot, approvalDecision string) {
	h.t.Helper()
	if snapshot.ExecutionStatus != domain.ScheduledExecutionPausedForApproval {
		h.t.Fatalf("%s execution status=%s", name, snapshot.ExecutionStatus)
	}
	if snapshot.LeaseOwner != "" || snapshot.LeaseExpiresAt != nil {
		h.t.Fatalf("%s retained lease owner=%q expiry=%v", name, snapshot.LeaseOwner, snapshot.LeaseExpiresAt)
	}
	if snapshot.TaskStatus != domain.TaskPaused || snapshot.WorkflowStatus != domain.RunPaused {
		h.t.Fatalf("%s task=%s workflow=%s, want paused/paused", name, snapshot.TaskStatus, snapshot.WorkflowStatus)
	}
	if snapshot.ApprovalDecision != approvalDecision {
		h.t.Fatalf("%s approval=%s want=%s", name, snapshot.ApprovalDecision, approvalDecision)
	}
	if snapshot.ApprovalCount != 1 {
		h.t.Fatalf("%s approval records=%d want=1", name, snapshot.ApprovalCount)
	}
	if snapshot.ExecutionAttemptCount != 1 || snapshot.ClaimAuditCount != 1 || snapshot.ResumeAuditCount != 0 {
		h.t.Fatalf("%s execution attempts=%d claim audits=%d resume audits=%d, want 1/1/0", name, snapshot.ExecutionAttemptCount, snapshot.ClaimAuditCount, snapshot.ResumeAuditCount)
	}
	nuclei := snapshot.Steps["run-safe-nuclei-profile"]
	if nuclei.ID == "" || nuclei.ID != snapshot.NucleiStepRunID || nuclei.Status != domain.StepAwaitingApproval || nuclei.IdempotencyKey == "" {
		h.t.Fatalf("%s Nuclei step=%#v", name, nuclei)
	}
	for field, value := range map[string]domain.ID{
		"schedule":                snapshot.ScheduleID,
		"execution":               snapshot.ExecutionID,
		"task":                    snapshot.TaskID,
		"workflow run":            snapshot.WorkflowRunID,
		"approval":                snapshot.ApprovalID,
		"approval request":        snapshot.ApprovalRequestID,
		"approval action request": snapshot.ApprovalActionRequestID,
		"approval task":           snapshot.ApprovalTaskID,
	} {
		if value == "" {
			h.t.Fatalf("%s has empty %s ID", name, field)
		}
	}
	if snapshot.ApprovalRequestID != snapshot.NucleiStepRunID || snapshot.ApprovalTaskID != snapshot.TaskID {
		h.t.Fatalf("%s approval linkage request=%s task=%s step=%s execution task=%s", name, snapshot.ApprovalRequestID, snapshot.ApprovalTaskID, snapshot.NucleiStepRunID, snapshot.TaskID)
	}
	if snapshot.Guard.Validation != 1 || snapshot.Guard.Version != 0 || snapshot.Guard.Scan != 0 || snapshot.Guard.Rejected != 0 {
		h.t.Fatalf("%s guard counters=%#v, want validation=1 version=0 scan=0 rejected=0", name, snapshot.Guard)
	}
	if snapshot.Fixture.Nuclei != 0 {
		h.t.Fatalf("%s fixture Nuclei requests=%d want=0", name, snapshot.Fixture.Nuclei)
	}
}

func (h *harness) assertCompletedRecoverySnapshot(before, completed lineageSnapshot) {
	h.t.Helper()
	if completed.ExecutionStatus != domain.ScheduledExecutionCompleted ||
		completed.TaskStatus != domain.TaskCompleted ||
		completed.WorkflowStatus != domain.RunCompleted {
		h.t.Fatalf("completed recovery execution=%s task=%s workflow=%s", completed.ExecutionStatus, completed.TaskStatus, completed.WorkflowStatus)
	}
	if completed.ExecutionAttemptCount != before.ExecutionAttemptCount+1 {
		h.t.Fatalf("completed recovery claim attempts=%d want=%d", completed.ExecutionAttemptCount, before.ExecutionAttemptCount+1)
	}
	if completed.ClaimAuditCount != before.ClaimAuditCount+1 {
		h.t.Fatalf("completed recovery claim audits=%d want=%d", completed.ClaimAuditCount, before.ClaimAuditCount+1)
	}
	if completed.ResumeAuditCount != before.ResumeAuditCount {
		h.t.Fatalf("completed recovery resume audits=%d want=%d", completed.ResumeAuditCount, before.ResumeAuditCount)
	}
	nucleiBefore := before.Steps["run-safe-nuclei-profile"]
	nucleiAfter := completed.Steps["run-safe-nuclei-profile"]
	if nucleiAfter.Status != domain.StepSucceeded || nucleiAfter.AttemptCount != nucleiBefore.AttemptCount+1 {
		h.t.Fatalf("completed recovery Nuclei before=%#v after=%#v", nucleiBefore, nucleiAfter)
	}
	if completed.ToolRunCounts["run-safe-nuclei-profile"] != before.ToolRunCounts["run-safe-nuclei-profile"]+1 {
		h.t.Fatalf("completed recovery Nuclei tool runs=%d want=%d", completed.ToolRunCounts["run-safe-nuclei-profile"], before.ToolRunCounts["run-safe-nuclei-profile"]+1)
	}
	if diffs := recoveryToolRunDiff(before.ToolRunCounts, completed.ToolRunCounts); len(diffs) != 0 {
		h.t.Fatalf("completed recovery tool-run counts changed unexpectedly:\n%s", strings.Join(diffs, "\n"))
	}
	if completed.Fixture.Total != before.Fixture.Total+1 || completed.Fixture.Nuclei != before.Fixture.Nuclei+1 {
		h.t.Fatalf("completed recovery fixture before=%#v after=%#v, want exactly one Nuclei request", before.Fixture, completed.Fixture)
	}
	if completed.Guard.Validation != before.Guard.Validation ||
		completed.Guard.Version != before.Guard.Version+1 ||
		completed.Guard.Scan != before.Guard.Scan+1 ||
		completed.Guard.Rejected != before.Guard.Rejected {
		h.t.Fatalf("completed recovery guard before=%#v after=%#v", before.Guard, completed.Guard)
	}
	if completed.ApprovalDecision != "approved" {
		h.t.Fatalf("completed recovery approval=%s want=approved", completed.ApprovalDecision)
	}
	enrich := completed.Steps["enrich-recon-brief"]
	if enrich.ID == "" || enrich.Capability != "report.changes" || enrich.Status != domain.StepSucceeded || enrich.AttemptCount != 1 || enrich.IdempotencyKey == "" {
		h.t.Fatalf("completed recovery enrich step=%#v", enrich)
	}
	if diffs := terminalStepDiff(completed.Steps); len(diffs) != 0 {
		h.t.Fatalf("completed recovery retained nonterminal steps:\n%s", strings.Join(diffs, "\n"))
	}
	if completed.LeaseOwner != "" || completed.LeaseExpiresAt != nil {
		h.t.Fatalf("completed recovery retained lease owner=%q expiry=%v", completed.LeaseOwner, completed.LeaseExpiresAt)
	}
	if violation := h.fixture.Violation(); violation != "" {
		h.t.Fatalf("completed recovery observed non-loopback traffic: %s", violation)
	}
}

func recoveryToolRunDiff(before, completed map[string]int) []string {
	expected := make(map[string]int, len(before)+2)
	for id, count := range before {
		expected[id] = count
	}
	expected["run-safe-nuclei-profile"]++
	expected["enrich-recon-brief"]++
	var diffs []string
	appendValueDiff(&diffs, "tool-run counts", expected, completed)
	return diffs
}

func terminalStepDiff(steps map[string]lineageStepSnapshot) []string {
	ids := make([]string, 0, len(steps))
	for id := range steps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var diffs []string
	for _, id := range ids {
		status := steps[id].Status
		if status != domain.StepSucceeded && status != domain.StepSkipped {
			diffs = append(diffs, fmt.Sprintf("step %s status=%s", id, status))
		}
	}
	return diffs
}
