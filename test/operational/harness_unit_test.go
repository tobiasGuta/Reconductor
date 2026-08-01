//go:build operational

package operational

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
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
	readyLine := "2026/08/01 12:00:00 INFO Reconductor scheduler ready poll_interval=100ms max_concurrent_runs=1"
	_, _ = log.Write([]byte(readyLine + "\n"))
	offset := log.Len()
	if schedulerReadyFrom(&log, offset) {
		t.Fatal("stale readiness output satisfied a later generation")
	}
	_, _ = log.Write([]byte("2026/08/01 12:00:01 ERROR startup failed error=\"Reconductor scheduler ready\"\n"))
	if schedulerReadyFrom(&log, offset) {
		t.Fatal("an error containing the readiness message satisfied generation readiness")
	}
	_, _ = log.Write([]byte(readyLine))
	if schedulerReadyFrom(&log, offset) {
		t.Fatal("a partial readiness line satisfied generation readiness")
	}
	_, _ = log.Write([]byte("\n"))
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
	generation := newSchedulerGeneration(1, nil, "scheduler", "identity", 123, 0, time.Now())
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
	generation := newSchedulerGeneration(1, nil, "scheduler", "identity", 123, 0, time.Now())
	generation.beginWait(waiter, nil)
	var terminateCalls atomic.Int32
	terminate := func(context.Context, *schedulerGeneration) error {
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

func TestSchedulerGenerationStopRetriesAfterTerminationFailure(t *testing.T) {
	release := make(chan struct{})
	waiter := &countingWaiter{release: release}
	generation := newSchedulerGeneration(1, nil, "scheduler", "identity", 123, 0, time.Now())
	generation.beginWait(waiter, nil)
	sentinel := errors.New("first termination failed")
	var terminateCalls atomic.Int32
	terminate := func(context.Context, *schedulerGeneration) error {
		if terminateCalls.Add(1) == 1 {
			return sentinel
		}
		close(release)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := generation.stop(ctx, terminate); !errors.Is(err, sentinel) {
		t.Fatalf("first stop error=%v want=%v", err, sentinel)
	}
	if err := generation.stop(ctx, terminate); err != nil {
		t.Fatal(err)
	}
	if got := terminateCalls.Load(); got != 2 {
		t.Fatalf("terminate calls=%d want=2", got)
	}
}

func TestSchedulerGenerationStopPreservesTerminationErrorAfterExit(t *testing.T) {
	release := make(chan struct{})
	waiter := &countingWaiter{release: release}
	generation := newSchedulerGeneration(1, nil, "scheduler", "identity", 123, 0, time.Now())
	generation.beginWait(waiter, nil)
	sentinel := errors.New("tree termination was partial")
	terminate := func(context.Context, *schedulerGeneration) error {
		close(release)
		<-generation.Done
		return sentinel
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := generation.stop(ctx, terminate); !errors.Is(err, sentinel) {
		t.Fatalf("stop error=%v want=%v", err, sentinel)
	}
}

func TestSchedulerGenerationStopReportsNaturalExit(t *testing.T) {
	release := make(chan struct{})
	waiter := &countingWaiter{release: release}
	generation := newSchedulerGeneration(1, nil, "scheduler", "identity", 123, 0, time.Now())
	generation.beginWait(waiter, nil)
	close(release)
	<-generation.Done
	var terminateCalls atomic.Int32
	err := generation.stop(context.Background(), func(context.Context, *schedulerGeneration) error {
		terminateCalls.Add(1)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "exited before owned termination") {
		t.Fatalf("natural-exit stop error=%v", err)
	}
	if got := terminateCalls.Load(); got != 0 {
		t.Fatalf("terminate calls=%d want=0", got)
	}
}

func TestSchedulerGenerationOwnershipRequiresLiveIdentity(t *testing.T) {
	expected := filepath.Join(t.TempDir(), "scheduler")
	cmd := &exec.Cmd{Path: expected, Process: &os.Process{Pid: 123}}
	generation := newSchedulerGeneration(1, cmd, expected, "creation-token", 123, 0, time.Now())
	live := schedulerProcessIdentity{PID: 123, Executable: expected, Token: "creation-token"}
	if !generation.ownsExecutable(expected, live) {
		t.Fatal("exact owned scheduler process was rejected")
	}
	for name, mutate := range map[string]func(*schedulerProcessIdentity){
		"PID": func(value *schedulerProcessIdentity) { value.PID++ },
		"executable": func(value *schedulerProcessIdentity) {
			value.Executable = filepath.Join(filepath.Dir(expected), "other")
		},
		"token": func(value *schedulerProcessIdentity) { value.Token = "reused-process" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := live
			mutate(&changed)
			if generation.ownsExecutable(expected, changed) {
				t.Fatalf("mismatched live %s was accepted: %#v", name, changed)
			}
		})
	}
}

func TestInspectSchedulerProcessReturnsCurrentLiveIdentity(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skip("live process identity is supported only on Windows and Linux")
	}
	live, err := inspectSchedulerProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if live.PID != os.Getpid() || live.Token == "" || !samePath(live.Executable, executable) {
		t.Fatalf("live identity=%#v executable=%q", live, executable)
	}
}

func TestSchedulerPIDRecordIsCompleteAndAtomic(t *testing.T) {
	root := t.TempDir()
	expected := filepath.Join(root, "scheduler")
	cmd := &exec.Cmd{Path: expected, Process: &os.Process{Pid: 123}}
	generation := newSchedulerGeneration(7, cmd, expected, "creation-token", 123, 0, time.Now().UTC())
	h := &harness{root: root}
	if err := h.writeSchedulerPID(generation); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "scheduler.pid"))
	if err != nil {
		t.Fatal(err)
	}
	var record schedulerPIDRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.PID != 123 || record.Generation != 7 || record.Identity != "creation-token" || !samePath(record.Executable, expected) {
		t.Fatalf("PID identity record=%#v", record)
	}
	if _, err := os.Stat(filepath.Join(root, "scheduler.pid.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary PID identity record remained: %v", err)
	}
	incomplete := newSchedulerGeneration(8, cmd, expected, "", 123, 0, time.Now())
	if err := h.writeSchedulerPID(incomplete); err == nil {
		t.Fatal("incomplete PID identity record was accepted")
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
		ApprovalCount:           1,
		Steps: map[string]lineageStepSnapshot{
			"probe-http": {ID: "probe", Capability: "probe.http", Status: domain.StepSucceeded, AttemptCount: 1, IdempotencyKey: "stable-key"},
		},
	}
	after := before
	after.Steps = map[string]lineageStepSnapshot{
		"probe-http": {ID: "probe", Capability: "probe.http", Status: domain.StepSucceeded, AttemptCount: 1, IdempotencyKey: "stable-key"},
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

func TestLineageSnapshotComparisonDetectsUnexpectedAndMissingNewSteps(t *testing.T) {
	before := lineageSnapshot{ApprovalCount: 1, Steps: map[string]lineageStepSnapshot{
		"probe-http": {ID: "probe", Capability: "probe.http", IdempotencyKey: "probe-key"},
	}}
	after := before
	after.Steps = map[string]lineageStepSnapshot{
		"probe-http":         before.Steps["probe-http"],
		"unexpected-retry":   {ID: "retry", Capability: "probe.http", IdempotencyKey: "retry-key"},
		"enrich-recon-brief": {ID: "enrich", Capability: "report.changes", IdempotencyKey: "enrich-key"},
	}
	diffs := strings.Join(before.stableDiff(after, "enrich-recon-brief"), "\n")
	if !strings.Contains(diffs, "step unexpected-retry appeared unexpectedly") {
		t.Fatalf("unexpected-step diff=%q", diffs)
	}
	delete(after.Steps, "unexpected-retry")
	if diffs := before.stableDiff(after, "enrich-recon-brief"); len(diffs) != 0 {
		t.Fatalf("allowed enrich step diff=%v", diffs)
	}
	delete(after.Steps, "enrich-recon-brief")
	if diffs := strings.Join(before.stableDiff(after, "enrich-recon-brief"), "\n"); !strings.Contains(diffs, "expected new step enrich-recon-brief did not appear") {
		t.Fatalf("missing expected-step diff=%q", diffs)
	}
	after.ApprovalCount = 2
	if diffs := strings.Join(before.stableDiff(after), "\n"); !strings.Contains(diffs, "approval record count changed") {
		t.Fatalf("extra-approval diff=%q", diffs)
	}
}

func TestStepStoreDiffDetectsPostgreSQLFileDivergence(t *testing.T) {
	runID := domain.ID("run")
	newValues := func() (map[string]*workflow.StepState, []database.ConsoleStep) {
		file := map[string]*workflow.StepState{
			"probe-http": {Run: domain.StepRun{ID: "step", WorkflowRunID: runID, StepDefinitionID: "probe-http", Capability: "probe.http", Status: domain.StepSucceeded, AttemptCount: 1, ApprovalState: "not_required"}},
		}
		rows := []database.ConsoleStep{{ID: "step", WorkflowRunID: runID, StepDefinitionID: "probe-http", Capability: "probe.http", Status: domain.StepSucceeded, AttemptCount: 1, ApprovalState: "not_required"}}
		return file, rows
	}
	file, rows := newValues()
	if diffs := stepStoreDiff(runID, file, rows); len(diffs) != 0 {
		t.Fatalf("equal step stores diff=%v", diffs)
	}
	tests := []struct {
		name   string
		want   string
		mutate func(map[string]*workflow.StepState, []database.ConsoleStep) []database.ConsoleStep
	}{
		{name: "status mismatch", want: "status changed", mutate: func(_ map[string]*workflow.StepState, rows []database.ConsoleStep) []database.ConsoleStep {
			rows[0].Status = domain.StepRunning
			return rows
		}},
		{name: "missing row", want: "is missing", mutate: func(_ map[string]*workflow.StepState, _ []database.ConsoleStep) []database.ConsoleStep { return nil }},
		{name: "extra row", want: "unexpected step extra", mutate: func(_ map[string]*workflow.StepState, rows []database.ConsoleStep) []database.ConsoleStep {
			return append(rows, database.ConsoleStep{ID: "extra", WorkflowRunID: runID, StepDefinitionID: "extra"})
		}},
		{name: "duplicate row", want: "has 2 rows", mutate: func(_ map[string]*workflow.StepState, rows []database.ConsoleStep) []database.ConsoleStep {
			duplicate := rows[0]
			duplicate.ID = "duplicate"
			return append(rows, duplicate)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, rows := newValues()
			rows = test.mutate(file, rows)
			diffs := strings.Join(stepStoreDiff(runID, file, rows), "\n")
			if !strings.Contains(diffs, test.want) {
				t.Fatalf("step-store diff=%q want substring %q", diffs, test.want)
			}
		})
	}
}

func TestScheduledExecutionAuditCountsUseExecutionDetails(t *testing.T) {
	executionID := domain.ID("execution")
	otherExecutionID := domain.ID("other-execution")
	events := []database.ConsoleAuditEvent{
		{ID: "claim", EventType: "scheduled_execution_claimed", Details: json.RawMessage(`{"scheduled_execution_id":"execution"}`)},
		{ID: "other-claim", EventType: "scheduled_execution_claimed", Details: json.RawMessage(`{"scheduled_execution_id":"other-execution"}`)},
		{ID: "resume", EventType: "scheduled_execution_resume_requested", Details: json.RawMessage(`{"scheduled_execution_id":"execution"}`)},
		{ID: "unrelated", EventType: "workflow_started", Details: json.RawMessage(`{}`)},
	}
	claims, resumes, err := scheduledExecutionAuditCounts(executionID, events)
	if err != nil {
		t.Fatal(err)
	}
	if claims != 1 || resumes != 1 {
		t.Fatalf("claim audits=%d resume audits=%d want=1/1", claims, resumes)
	}
	claims, resumes, err = scheduledExecutionAuditCounts(otherExecutionID, events)
	if err != nil {
		t.Fatal(err)
	}
	if claims != 1 || resumes != 0 {
		t.Fatalf("other claim audits=%d resume audits=%d want=1/0", claims, resumes)
	}
	if _, _, err := scheduledExecutionAuditCounts(executionID, []database.ConsoleAuditEvent{{ID: "bad", EventType: "scheduled_execution_claimed", Details: json.RawMessage(`{}`)}}); err == nil {
		t.Fatal("claim audit without scheduled-execution identity was accepted")
	}
}

func TestRecoveryCompletionDiffsDetectExtraToolRunAndNonterminalStep(t *testing.T) {
	beforeTools := map[string]int{"probe-http": 1}
	expectedTools := map[string]int{"probe-http": 1, "run-safe-nuclei-profile": 1, "enrich-recon-brief": 1}
	if diffs := recoveryToolRunDiff(beforeTools, expectedTools); len(diffs) != 0 {
		t.Fatalf("expected tool-run diff=%v", diffs)
	}
	withExtra := map[string]int{"probe-http": 1, "run-safe-nuclei-profile": 1, "enrich-recon-brief": 1, "unexpected": 1}
	if diffs := recoveryToolRunDiff(beforeTools, withExtra); len(diffs) == 0 {
		t.Fatal("unexpected tool run was not detected")
	}
	steps := map[string]lineageStepSnapshot{"done": {Status: domain.StepSucceeded}, "skipped": {Status: domain.StepSkipped}}
	if diffs := terminalStepDiff(steps); len(diffs) != 0 {
		t.Fatalf("terminal step diff=%v", diffs)
	}
	steps["stale"] = lineageStepSnapshot{Status: domain.StepAwaitingApproval}
	if diffs := terminalStepDiff(steps); len(diffs) == 0 {
		t.Fatal("nonterminal completed step was not detected")
	}
}

func TestExactLoopbackRejectsOtherLoopbackHosts(t *testing.T) {
	for _, accepted := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1"} {
		if !isExactLoopback(net.ParseIP(accepted)) {
			t.Fatalf("exact loopback %s was rejected", accepted)
		}
	}
	for _, rejected := range []string{"127.0.0.2", "127.255.255.255", "::2", "192.0.2.1"} {
		if isExactLoopback(net.ParseIP(rejected)) {
			t.Fatalf("non-exact loopback %s was accepted", rejected)
		}
	}
}

func TestSchedulerDiagnosticsRedactSecretsBeforeBounding(t *testing.T) {
	log := &lockedBuffer{}
	databaseURL := "postgres://operator:e2e_secret@127.0.0.1:5432/reconductor"
	_, _ = log.Write([]byte(strings.Repeat("x", 9000) + databaseURL + " redis=e2e_secret"))
	h := &harness{schedulerLog: log, databaseURL: databaseURL, redisPass: "e2e_secret"}
	got := h.schedulerLogs(nil)
	if strings.Contains(got, databaseURL) || strings.Contains(got, "e2e_secret") {
		t.Fatalf("scheduler diagnostics leaked a credential: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") || len(got) > 8192 {
		t.Fatalf("scheduler diagnostics were not redacted and bounded: len=%d", len(got))
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

func TestPowerShellWrapperPreservesNativeGoExitCode(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell wrapper is Windows-only")
	}
	powershell := testPowerShell(t, true)
	script := operationalWrapperPath(t)
	fakePath := writeFakeGo(t, "@echo off\r\nexit /b 7\r\n")
	driver := filepath.Join(t.TempDir(), "invoke-wrapper.ps1")
	driverSource := fmt.Sprintf("$PSNativeCommandUseErrorActionPreference = $true\r\n& '%s' -Suite Approval\r\nexit $LASTEXITCODE\r\n", strings.ReplaceAll(script, "'", "''"))
	if err := os.WriteFile(driver, []byte(driverSource), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(powershell, "-NoProfile", "-File", driver)
	cmd.Env = environmentWithPathPrefix(os.Environ(), fakePath)
	output, err := cmd.CombinedOutput()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 7 {
		t.Fatalf("wrapper error=%v exit=%d want=7:\n%s", err, commandExitCode(err), output)
	}
}

func TestPowerShellWrapperKeepsLegitimateGoSkipSuccessful(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell wrapper is Windows-only")
	}
	powershell := testPowerShell(t, false)
	script := operationalWrapperPath(t)
	fakePath := writeFakeGo(t, "@echo off\r\necho --- SKIP: TestApprovalLifecycle (0.00s)\r\nexit /b 0\r\n")

	cmd := exec.Command(powershell, "-NoProfile", "-File", script, "-Suite", "Approval")
	cmd.Env = environmentWithPathPrefix(os.Environ(), fakePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wrapper changed a successful Go skip into failure: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "SKIP: TestApprovalLifecycle") {
		t.Fatalf("fake Go skip output was not preserved:\n%s", output)
	}
}

func TestPowerShellWrapperFailsWhenDockerDisappearsWithCleanupIntent(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell wrapper is Windows-only")
	}
	powershell := testPowerShell(t, false)
	script := operationalWrapperPath(t)
	fakePath := writeFakeGo(t, "@echo off\r\necho owned>\"%RECONDUCTOR_E2E_ROOT%\\postgres.container.intent\"\r\nexit /b 0\r\n")
	windowsRoot := os.Getenv("SystemRoot")
	limitedPath := strings.Join([]string{fakePath, filepath.Join(windowsRoot, "System32"), windowsRoot}, string(os.PathListSeparator))

	cmd := exec.Command(powershell, "-NoProfile", "-File", script, "-Suite", "Approval")
	cmd.Env = environmentWithExactPath(os.Environ(), limitedPath)
	output, err := cmd.CombinedOutput()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 1 {
		t.Fatalf("wrapper error=%v exit=%d want=1:\n%s", err, commandExitCode(err), output)
	}
	if !strings.Contains(string(output), "Docker CLI became unavailable while owned E2E container intents remained") {
		t.Fatalf("wrapper did not report unprovable container cleanup:\n%s", output)
	}
}

func testPowerShell(t *testing.T, preferPowerShell7 bool) string {
	t.Helper()
	names := []string{"powershell.exe", "pwsh.exe"}
	if preferPowerShell7 {
		names[0], names[1] = names[1], names[0]
	}
	for _, name := range names {
		if executable, err := exec.LookPath(name); err == nil {
			return executable
		}
	}
	t.Skip("PowerShell is unavailable")
	return ""
}

func operationalWrapperPath(t *testing.T) string {
	t.Helper()
	root, err := findRepositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "scripts", "test-operational-e2e.ps1")
}

func writeFakeGo(t *testing.T, body string) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "go.cmd"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return directory
}

func environmentWithPathPrefix(environment []string, prefix string) []string {
	return environmentWithExactPath(environment, prefix+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func environmentWithExactPath(environment []string, value string) []string {
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		if found && strings.EqualFold(name, "PATH") {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "PATH="+value)
}

func commandExitCode(err error) int {
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}
