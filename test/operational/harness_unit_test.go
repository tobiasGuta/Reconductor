//go:build operational

package operational

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestValidateTemporaryRootRequiresImmediateOwnedPrefix(t *testing.T) {
	valid, err := os.MkdirTemp("", "reconductor-operational-e2e-unit-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(valid) })
	if err := validateTemporaryRoot(valid); err != nil {
		t.Fatalf("valid temporary root rejected: %v", err)
	}

	wrongPrefix, err := os.MkdirTemp("", "other-operational-root-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(wrongPrefix) })
	if err := validateTemporaryRoot(wrongPrefix); err == nil || !strings.Contains(err.Error(), "required safety prefix") {
		t.Fatalf("wrong-prefix error=%v", err)
	}

	nested := filepath.Join(valid, "reconductor-operational-e2e-nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateTemporaryRoot(nested); err == nil || !strings.Contains(err.Error(), "immediate child") {
		t.Fatalf("nested-root error=%v", err)
	}
}

func TestRemoveTemporaryRootDoesNotFollowSymlink(t *testing.T) {
	root, err := os.MkdirTemp("", "reconductor-operational-e2e-remove-")
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	marker := filepath.Join(outside, "marker.txt")
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "outside-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Logf("symlink cleanup case unavailable: %v", err)
		_ = os.RemoveAll(root)
		return
	}
	if err := removeTemporaryRoot(root); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "preserve" {
		t.Fatalf("cleanup followed symlink outside generated root: data=%q err=%v", data, err)
	}
}

func TestScrubOperationalEnvironmentRemovesInheritedControlAndProxyValues(t *testing.T) {
	base := []string{
		"PATH=test",
		"SYSTEMROOT=C:\\Windows",
		"DATABASE_URL=postgres://normal",
		"NUCLEI_TEMPLATE_DIR=C:\\Users\\normal\\nuclei-templates",
		"POLICY_INTRUSIVE_CHECKS=true",
		"RECON_HEADLESS=true",
		"HTTP_PROXY=https://proxy.example.test",
		"PDCP_API_KEY=secret",
		"CHAOS_KEY=secret",
	}
	got := scrubOperationalEnvironment(base)
	joined := strings.Join(got, "\n")
	for _, forbidden := range []string{
		"DATABASE_URL", "NUCLEI_TEMPLATE_DIR", "POLICY_INTRUSIVE_CHECKS", "RECON_HEADLESS",
		"HTTP_PROXY", "PDCP_API_KEY", "CHAOS_KEY",
	} {
		if strings.Contains(joined, forbidden+"=") {
			t.Fatalf("unsafe inherited variable %s remained: %v", forbidden, got)
		}
	}
	for _, required := range []string{"PATH=test", "SYSTEMROOT=C:\\Windows"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("safe system variable %q was removed: %v", required, got)
		}
	}
}

func TestOwnedContainerLabelsRequireExactRunIdentity(t *testing.T) {
	if !ownedContainerLabels("run123|true", "run123") {
		t.Fatal("exact ownership labels were rejected")
	}
	for _, value := range []string{"run123|false", "run124|true", "|true", "run123|true|extra"} {
		if ownedContainerLabels(value, "run123") {
			t.Fatalf("non-owned labels %q were accepted", value)
		}
	}
}

func TestSchedulerGenerationReadinessIsLogIsolated(t *testing.T) {
	var log lockedBuffer
	_, _ = log.Write([]byte("Reconductor scheduler ready\n"))
	offset := log.Len()
	if schedulerReadyFrom(&log, offset) {
		t.Fatal("stale readiness output satisfied a later generation")
	}
	_, _ = log.Write([]byte("generation 2 starting\n"))
	if schedulerReadyFrom(&log, offset) {
		t.Fatal("non-readiness output satisfied generation readiness")
	}
	_, _ = log.Write([]byte("Reconductor scheduler ready\n"))
	if !schedulerReadyFrom(&log, offset) {
		t.Fatal("current generation readiness output was not detected")
	}
}

type countingWaiter struct {
	count   atomic.Int32
	release <-chan struct{}
	err     error
}

func (w *countingWaiter) Wait() error {
	w.count.Add(1)
	<-w.release
	return w.err
}

func TestSchedulerGenerationWaitRunsExactlyOnce(t *testing.T) {
	release := make(chan struct{})
	waiter := &countingWaiter{release: release}
	generation := newSchedulerGeneration(1, nil, "scheduler", 123, 0, time.Now())
	generation.beginWait(waiter, nil)
	generation.beginWait(waiter, nil)
	close(release)
	select {
	case <-generation.Done:
	case <-time.After(time.Second):
		t.Fatal("scheduler generation wait did not finish")
	}
	if got := waiter.count.Load(); got != 1 {
		t.Fatalf("Wait calls=%d want=1", got)
	}
}

func TestSchedulerGenerationStopIsSafeWhenRepeated(t *testing.T) {
	release := make(chan struct{})
	waiter := &countingWaiter{release: release}
	generation := newSchedulerGeneration(1, nil, "scheduler", 123, 0, time.Now())
	generation.beginWait(waiter, nil)
	var terminateCalls atomic.Int32
	terminate := func(context.Context, int) error {
		terminateCalls.Add(1)
		close(release)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := generation.stop(ctx, terminate); err != nil {
		t.Fatal(err)
	}
	if err := generation.stop(ctx, terminate); err != nil {
		t.Fatal(err)
	}
	if got := terminateCalls.Load(); got != 1 {
		t.Fatalf("terminate calls=%d want=1", got)
	}
	if got := waiter.count.Load(); got != 1 {
		t.Fatalf("Wait calls=%d want=1", got)
	}
}

func TestSchedulerGenerationOwnershipRequiresExactProcessAndExecutable(t *testing.T) {
	expected := filepath.Join(t.TempDir(), "scheduler")
	cmd := &exec.Cmd{Path: expected, Process: &os.Process{Pid: 123}}
	generation := newSchedulerGeneration(1, cmd, expected, 123, 0, time.Now())
	if !generation.ownsExecutable(expected) {
		t.Fatal("exact owned scheduler process was rejected")
	}
	generation.Executable = filepath.Join(filepath.Dir(expected), "other")
	if generation.ownsExecutable(expected) {
		t.Fatal("mismatched scheduler executable was accepted")
	}
}

func TestLineageSnapshotComparisonReportsIdentityAndIdempotencyChanges(t *testing.T) {
	before := lineageSnapshot{
		ScheduleID:              "schedule",
		ExecutionID:             "execution",
		TaskID:                  "task",
		WorkflowRunID:           "run",
		NucleiStepRunID:         "nuclei-step",
		ApprovalID:              "approval",
		ApprovalRequestID:       "nuclei-step",
		ApprovalActionRequestID: "action",
		ApprovalTaskID:          "task",
		Steps: map[string]lineageStepSnapshot{
			"probe-http": {ID: "probe", Status: domain.StepSucceeded, AttemptCount: 1, IdempotencyKey: "stable-key"},
		},
	}
	after := before
	after.Steps = map[string]lineageStepSnapshot{
		"probe-http": {ID: "probe", Status: domain.StepSucceeded, AttemptCount: 1, IdempotencyKey: "stable-key"},
	}
	if diffs := before.stableDiff(after); len(diffs) != 0 {
		t.Fatalf("equal lineage diff=%v", diffs)
	}
	after.ExecutionID = "different-execution"
	step := after.Steps["probe-http"]
	step.IdempotencyKey = "different-key"
	after.Steps["probe-http"] = step
	diffs := strings.Join(before.stableDiff(after), "\n")
	for _, required := range []string{"execution ID changed", "idempotency key changed"} {
		if !strings.Contains(diffs, required) {
			t.Fatalf("lineage diff %q does not contain %q", diffs, required)
		}
	}
}

func TestPowerShellSuiteSelectorRejectsArbitraryValues(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell wrapper is Windows-only")
	}
	powershell, err := exec.LookPath("powershell.exe")
	if err != nil {
		powershell, err = exec.LookPath("pwsh.exe")
	}
	if err != nil {
		t.Skip("PowerShell is unavailable")
	}
	root, err := findRepositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "scripts", "test-operational-e2e.ps1")
	output, err := exec.Command(powershell, "-NoProfile", "-File", script, "-Suite", "ArbitraryGoTestExpression").CombinedOutput()
	if err == nil {
		t.Fatalf("arbitrary suite selector was accepted:\n%s", output)
	}
	if !strings.Contains(string(output), "ValidateSet") && !strings.Contains(string(output), "valid values") {
		t.Fatalf("unexpected suite validation failure:\n%s", output)
	}
}
