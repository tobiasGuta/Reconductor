//go:build operational

package operational

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/providercheck"
	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	commandprovider "github.com/tobiasGuta/Reconductor/internal/providers/command"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

const (
	postgresImage = "postgres:15.13-alpine"
	redisImage    = "redis:7.4.5-alpine"
)

var operationalRunMu sync.Mutex

type harness struct {
	t        *testing.T
	ctx      context.Context
	repoRoot string
	root     string
	runID    string

	docker       string
	providerPath map[string]string
	postgresName string
	redisName    string
	databaseURL  string
	redisAddr    string
	redisPass    string

	fixture      *localFixture
	scopeRef     string
	templateDir  string
	templateFile string
	isolatedHome string
	guardLog     string

	platform  string
	scheduler string
	guard     string
	env       []string

	schedulerCmd *exec.Cmd
	schedulerLog *lockedBuffer
	store        *database.Store
}

type scenario struct {
	name      string
	program   domain.Program
	schedule  domain.Schedule
	execution domain.ScheduledExecution
	state     *workflow.State
	approval  database.ApprovalListItem
}

type guardLogEntry struct {
	Kind          string   `json:"kind"`
	Accepted      bool     `json:"accepted"`
	OriginalArgs  []string `json:"original_args"`
	DelegatedArgs []string `json:"delegated_args"`
	Targets       []string `json:"targets"`
	TemplatePaths []string `json:"template_paths"`
}

func newHarness(t *testing.T, ctx context.Context) *harness {
	t.Helper()
	repoRoot, err := findRepositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	runID := strings.ToLower(strings.ReplaceAll(os.Getenv("RECONDUCTOR_E2E_RUN_ID"), "-", ""))
	if runID == "" {
		runID = strings.ReplaceAll(string(domain.NewID()), "-", "")
	}
	if len(runID) > 16 {
		runID = runID[:16]
	}
	for _, r := range runID {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			t.Fatalf("operational run ID %q contains an unsafe character", runID)
		}
	}
	return &harness{
		t:            t,
		ctx:          ctx,
		repoRoot:     repoRoot,
		runID:        runID,
		providerPath: map[string]string{},
		postgresName: "reconductor-e2e-pg-" + runID,
		redisName:    "reconductor-e2e-redis-" + runID,
		redisPass:    "e2e_" + runID,
		schedulerLog: &lockedBuffer{},
	}
}

func (h *harness) preflight() {
	h.t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		h.t.Skip("operational E2E skipped: Go executable is unavailable")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		h.t.Skip("operational E2E skipped: Docker CLI is unavailable")
	}
	h.docker = docker
	if output, err := h.runExternal(h.ctx, docker, nil, "info", "--format", "{{.ServerVersion}}"); err != nil {
		h.t.Skipf("operational E2E skipped: Docker daemon is unavailable: %v (%s)", err, trimOutput(output))
	}
	for _, image := range []string{postgresImage, redisImage} {
		if output, err := h.runExternal(h.ctx, docker, nil, "image", "inspect", image); err != nil {
			h.t.Skipf("operational E2E skipped: required local image %s is unavailable; the harness never pulls images: %v (%s)", image, err, trimOutput(output))
		}
	}

	specs := []providercheck.Spec{
		{Name: "dnsx", DisplayName: "DNSx", Executable: configuredExecutable("DNSX_EXECUTABLE", "dnsx"), ExecutableEnv: "DNSX_EXECUTABLE", VersionArgs: []string{"-version"}, CompatiblePrefix: "1."},
		{Name: "naabu", DisplayName: "Naabu", Executable: configuredExecutable("NAABU_EXECUTABLE", "naabu"), ExecutableEnv: "NAABU_EXECUTABLE", VersionArgs: []string{"-version"}, CompatiblePrefix: "2."},
		{Name: "httpx", DisplayName: "HTTPX", Executable: configuredExecutable("HTTPX_EXECUTABLE", "httpx"), ExecutableEnv: "HTTPX_EXECUTABLE", VersionArgs: []string{"-version"}, CompatiblePrefix: "1."},
		{Name: "katana", DisplayName: "Katana", Executable: configuredExecutable("KATANA_EXECUTABLE", "katana"), ExecutableEnv: "KATANA_EXECUTABLE", VersionArgs: []string{"-version"}, CompatiblePrefix: "1."},
		{Name: "nuclei", DisplayName: "Nuclei", Executable: configuredExecutable("NUCLEI_EXECUTABLE", "nuclei"), ExecutableEnv: "NUCLEI_EXECUTABLE", VersionArgs: []string{"-version"}, CompatiblePrefix: "3."},
	}
	for _, spec := range specs {
		result := providercheck.Check(h.ctx, spec, providercheck.OSRunner{})
		if result.Status == providercheck.Missing {
			h.t.Skipf("operational E2E skipped: %s is unavailable; configure %s", spec.DisplayName, spec.ExecutableEnv)
		}
		if result.Status != providercheck.Compatible {
			h.t.Fatalf("%s prerequisite failed identity/version validation: status=%s path=%q expected=%q detected=%q details=%s", spec.DisplayName, result.Status, result.Path, result.ExpectedVersion, result.DetectedVersion, result.Details)
		}
		h.providerPath[spec.Name] = result.Path
	}
}

func (h *harness) prepare() {
	h.t.Helper()
	root := strings.TrimSpace(os.Getenv("RECONDUCTOR_E2E_ROOT"))
	if root == "" {
		var err error
		root, err = os.MkdirTemp("", "reconductor-operational-e2e-"+h.runID+"-")
		if err != nil {
			h.t.Fatal(err)
		}
	} else {
		var err error
		root, err = filepath.Abs(root)
		if err != nil {
			h.t.Fatal(err)
		}
		if err := os.MkdirAll(root, 0o700); err != nil {
			h.t.Fatal(err)
		}
	}
	if err := validateTemporaryRoot(root); err != nil {
		h.t.Fatal(err)
	}
	h.root = root
	h.t.Cleanup(func() {
		if h.t.Failed() && envTrue("RECONDUCTOR_E2E_PRESERVE_FAILURE") {
			h.t.Logf("preserving operational E2E diagnostics at %s", h.root)
			return
		}
		if err := removeTemporaryRoot(h.root); err != nil {
			h.t.Errorf("remove operational E2E root: %v", err)
		}
	})

	for _, dir := range []string{
		filepath.Join(root, "bin"),
		filepath.Join(root, "scope"),
		filepath.Join(root, "state", "runs"),
		filepath.Join(root, "artifacts"),
		filepath.Join(root, "nuclei-templates"),
		filepath.Join(root, "home", "nuclei-config"),
		filepath.Join(root, "home", "appdata"),
		filepath.Join(root, "home", "localappdata"),
		filepath.Join(root, "home", ".config"),
		filepath.Join(root, "home", "tmp"),
		filepath.Join(root, "logs"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			h.t.Fatal(err)
		}
	}
	h.scopeRef = "scope/local-approval.json"
	h.templateDir = filepath.Join(root, "nuclei-templates")
	h.templateFile = filepath.Join(h.templateDir, "local-http-200.yaml")
	h.isolatedHome = filepath.Join(root, "home")
	h.guardLog = filepath.Join(root, "logs", "nuclei-invocations.jsonl")
}

func (h *harness) startInfrastructure() {
	h.t.Helper()
	h.startPostgres()
	h.startRedis()
	h.fixture = startLocalFixture(h.t, h.runID)
	h.t.Cleanup(h.fixture.Close)
	h.writeScope()
	h.writeTemplate()
}

func (h *harness) startPostgres() {
	h.t.Helper()
	args := []string{
		"run", "-d", "--rm", "--pull=never",
		"--name", h.postgresName,
		"--label", "reconductor.operational-e2e=true",
		"--label", "reconductor.operational-e2e.run=" + h.runID,
		"-e", "POSTGRES_USER=reconductor_e2e",
		"-e", "POSTGRES_PASSWORD=" + h.redisPass,
		"-e", "POSTGRES_DB=reconductor_e2e",
		"-p", "127.0.0.1::5432",
		postgresImage,
	}
	if output, err := h.runExternal(h.ctx, h.docker, nil, args...); err != nil {
		cleanupErr := h.removeContainer(h.postgresName)
		if cleanupErr != nil {
			h.t.Fatalf("start PostgreSQL container: %v (%s); cleanup: %v", err, trimOutput(output), cleanupErr)
		}
		h.t.Fatalf("start PostgreSQL container: %v (%s)", err, trimOutput(output))
	}
	h.t.Cleanup(func() {
		if err := h.removeContainer(h.postgresName); err != nil {
			h.t.Errorf("remove PostgreSQL container: %v", err)
		}
	})
	h.waitContainerReady(h.postgresName, "accepting connections", "pg_isready", "-U", "reconductor_e2e", "-d", "reconductor_e2e")
	address := h.containerPort(h.postgresName, "5432/tcp")
	parsed := &url.URL{Scheme: "postgres", User: url.UserPassword("reconductor_e2e", h.redisPass), Host: address, Path: "/reconductor_e2e"}
	query := parsed.Query()
	query.Set("sslmode", "disable")
	parsed.RawQuery = query.Encode()
	h.databaseURL = parsed.String()
}

func (h *harness) startRedis() {
	h.t.Helper()
	args := []string{
		"run", "-d", "--rm", "--pull=never",
		"--name", h.redisName,
		"--label", "reconductor.operational-e2e=true",
		"--label", "reconductor.operational-e2e.run=" + h.runID,
		"-p", "127.0.0.1::6379",
		redisImage,
		"redis-server", "--appendonly", "no", "--requirepass", h.redisPass,
	}
	if output, err := h.runExternal(h.ctx, h.docker, nil, args...); err != nil {
		cleanupErr := h.removeContainer(h.redisName)
		if cleanupErr != nil {
			h.t.Fatalf("start Redis container: %v (%s); cleanup: %v", err, trimOutput(output), cleanupErr)
		}
		h.t.Fatalf("start Redis container: %v (%s)", err, trimOutput(output))
	}
	h.t.Cleanup(func() {
		if err := h.removeContainer(h.redisName); err != nil {
			h.t.Errorf("remove Redis container: %v", err)
		}
	})
	h.waitContainerReady(h.redisName, "PONG", "redis-cli", "-a", h.redisPass, "ping")
	h.redisAddr = h.containerPort(h.redisName, "6379/tcp")
}

func (h *harness) waitContainerReady(name, expected string, command ...string) {
	h.t.Helper()
	var last string
	err := poll(h.ctx, 45*time.Second, 250*time.Millisecond, func() (bool, error) {
		args := append([]string{"exec", name}, command...)
		output, err := h.runExternal(h.ctx, h.docker, nil, args...)
		last = trimOutput(output)
		if err != nil {
			return false, nil
		}
		return strings.Contains(last, expected), nil
	})
	if err != nil {
		h.t.Fatalf("wait for container %s readiness (last=%q): %v", name, last, err)
	}
}

func (h *harness) containerPort(name, containerPort string) string {
	h.t.Helper()
	output, err := h.runExternal(h.ctx, h.docker, nil, "port", name, containerPort)
	if err != nil {
		h.t.Fatalf("inspect %s published port: %v (%s)", name, err, trimOutput(output))
	}
	address := strings.TrimSpace(strings.Split(string(output), "\n")[0])
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != "127.0.0.1" || port == "" {
		h.t.Fatalf("container %s was not published only on dynamic loopback: %q", name, address)
	}
	return net.JoinHostPort(host, port)
}

func (h *harness) removeContainer(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	format := `{{index .Config.Labels "reconductor.operational-e2e.run"}}|{{index .Config.Labels "reconductor.operational-e2e"}}`
	output, err := h.runExternal(ctx, h.docker, nil, "inspect", "--format", format, name)
	if err != nil {
		if strings.Contains(strings.ToLower(string(output)), "no such object") {
			return nil
		}
		return fmt.Errorf("inspect ownership labels for %s: %w (%s)", name, err, trimOutput(output))
	}
	if got := strings.TrimSpace(string(output)); !ownedContainerLabels(got, h.runID) {
		return fmt.Errorf("refusing to remove container %s with ownership labels %q", name, got)
	}
	output, err = h.runExternal(ctx, h.docker, nil, "rm", "-f", name)
	if err != nil {
		return fmt.Errorf("remove owned container %s: %w (%s)", name, err, trimOutput(output))
	}
	return nil
}

func (h *harness) writeScope() {
	h.t.Helper()
	_, portText, err := net.SplitHostPort(h.fixture.listener.Addr().String())
	if err != nil {
		h.t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		h.t.Fatal(err)
	}
	value := map[string]any{
		"target": map[string]any{
			"scope": map[string]any{
				"include": []map[string]any{{
					"enabled":  true,
					"protocol": "^http$",
					"host":     `^127\.0\.0\.1$`,
					"port":     fmt.Sprintf("^%d$", port),
					"file":     `^/.*`,
				}},
				"exclude": []any{},
			},
		},
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.root, filepath.FromSlash(h.scopeRef)), data, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) writeTemplate() {
	h.t.Helper()
	source := filepath.Join(h.repoRoot, "test", "operational", "testdata", "nuclei", "local-http-200.yaml")
	data, err := os.ReadFile(source)
	if err != nil {
		h.t.Fatal(err)
	}
	data = bytes.ReplaceAll(data, []byte("__RECONDUCTOR_E2E_RUN_ID__"), []byte(h.runID))
	if err := os.WriteFile(h.templateFile, data, 0o600); err != nil {
		h.t.Fatal(err)
	}
	entries, err := os.ReadDir(h.templateDir)
	if err != nil {
		h.t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(h.templateFile) {
		h.t.Fatalf("isolated Nuclei directory contains unexpected entries: %#v", entries)
	}
}

func (h *harness) buildBinaries() {
	h.t.Helper()
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	h.platform = filepath.Join(h.root, "bin", "platform"+suffix)
	h.scheduler = filepath.Join(h.root, "bin", "scheduler"+suffix)
	h.guard = filepath.Join(h.root, "bin", "nuclei"+suffix)
	for _, build := range []struct {
		output string
		args   []string
	}{
		{h.platform, []string{"build", "-o", h.platform, "./cmd/platform"}},
		{h.scheduler, []string{"build", "-o", h.scheduler, "./cmd/scheduler"}},
		{h.guard, []string{"build", "-tags=operational", "-o", h.guard, "./test/operational/cmd/nuclei-guard"}},
	} {
		output, err := h.runExternal(h.ctx, "go", nil, build.args...)
		if err != nil {
			h.t.Fatalf("build %s: %v (%s)", filepath.Base(build.output), err, trimOutput(output))
		}
	}
	h.env = h.schedulerEnvironment()
}

func (h *harness) schedulerEnvironment() []string {
	overrides := map[string]string{
		"DATABASE_URL":                             h.databaseURL,
		"REDIS_ADDR":                               h.redisAddr,
		"REDIS_PASSWORD":                           h.redisPass,
		"REDIS_DB":                                 "0",
		"REDIS_TLS":                                "false",
		"SCOPE_ROOT":                               h.root,
		"WORKFLOW_STATE_ROOT":                      filepath.Join(h.root, "state", "runs"),
		"ARTIFACT_ROOT":                            filepath.Join(h.root, "artifacts"),
		"HOME":                                     h.isolatedHome,
		"USERPROFILE":                              h.isolatedHome,
		"HOMEDRIVE":                                filepath.VolumeName(h.isolatedHome),
		"HOMEPATH":                                 strings.TrimPrefix(h.isolatedHome, filepath.VolumeName(h.isolatedHome)),
		"APPDATA":                                  filepath.Join(h.isolatedHome, "appdata"),
		"LOCALAPPDATA":                             filepath.Join(h.isolatedHome, "localappdata"),
		"XDG_CONFIG_HOME":                          filepath.Join(h.isolatedHome, ".config"),
		"TEMP":                                     filepath.Join(h.isolatedHome, "tmp"),
		"TMP":                                      filepath.Join(h.isolatedHome, "tmp"),
		"NO_PROXY":                                 "127.0.0.1,localhost",
		"no_proxy":                                 "127.0.0.1,localhost",
		"DNSX_EXECUTABLE":                          h.providerPath["dnsx"],
		"NAABU_EXECUTABLE":                         h.providerPath["naabu"],
		"HTTPX_EXECUTABLE":                         h.providerPath["httpx"],
		"KATANA_EXECUTABLE":                        h.providerPath["katana"],
		"NUCLEI_EXECUTABLE":                        h.guard,
		"NUCLEI_TEMPLATE_DIR":                      h.templateDir,
		"NUCLEI_TEMPLATES_DIR":                     h.templateDir,
		"NUCLEI_CONFIG_DIR":                        filepath.Join(h.isolatedHome, "nuclei-config"),
		"NUCLEI_INCLUDE_TAGS":                      "reconductor-e2e",
		"NUCLEI_SEVERITY":                          "info",
		"NUCLEI_EXCLUDE_TAGS":                      "dos,fuzz,bruteforce,intrusive",
		"NUCLEI_UPDATE_TEMPLATES":                  "false",
		"NUCLEI_RATE_LIMIT":                        "1",
		"NUCLEI_HOST_CONCURRENCY":                  "1",
		"NUCLEI_TEMPLATE_CONCURRENCY":              "1",
		"NUCLEI_HEADLESS_CONCURRENCY":              "1",
		"RECON_RATE_LIMIT":                         "1",
		"RECON_CONCURRENCY":                        "1",
		"RECON_HEADLESS":                           "false",
		"RECON_PROVIDER_UPDATE":                    "false",
		"POLICY_RATE_LIMIT":                        "1",
		"POLICY_CONCURRENCY":                       "1",
		"POLICY_PROVIDER_CONCURRENCY":              "1",
		"POLICY_HOST_CONCURRENCY":                  "1",
		"POLICY_ALLOWED_METHODS":                   "GET,HEAD,OPTIONS",
		"POLICY_FOLLOW_REDIRECTS":                  "false",
		"POLICY_AUTHENTICATION_USAGE":              "false",
		"POLICY_DIRECTORY_FUZZING":                 "false",
		"POLICY_CROSS_ORIGIN":                      "false",
		"POLICY_INTRUSIVE_CHECKS":                  "false",
		"SCHEDULER_POLL_INTERVAL":                  "100ms",
		"SCHEDULER_MAX_CONCURRENT_RUNS":            "1",
		"SCHEDULER_LEASE_TIMEOUT":                  "30s",
		"RECON_TIMEOUT":                            "2m",
		"NUCLEI_TIMEOUT":                           "2m",
		"RECONDUCTOR_E2E_REAL_NUCLEI":              h.providerPath["nuclei"],
		"RECONDUCTOR_E2E_FIXTURE_URL":              h.fixture.URL(),
		"RECONDUCTOR_E2E_TEMPLATE_DIR":             h.templateDir,
		"RECONDUCTOR_E2E_TEMPLATE_FILE":            h.templateFile,
		"RECONDUCTOR_E2E_INVOCATION_LOG":           h.guardLog,
		"RECONDUCTOR_E2E_HOME":                     h.isolatedHome,
		"DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD": "true",
		"DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD": "true",
		"DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD": "true",
		"DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD":    "true",
		"DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD":  "true",
	}
	return environmentWithOverrides(scrubOperationalEnvironment(os.Environ()), overrides)
}

func (h *harness) validateTemplate() {
	h.t.Helper()
	output, err := h.runExternalInDir(h.ctx, h.root, h.guard, h.env, "-validate", "-t", h.templateFile, "-severity", "info", "-tags", "reconductor-e2e")
	if err != nil {
		h.t.Fatalf("validate isolated Nuclei template: %v (%s)", err, trimOutput(output))
	}
}

func (h *harness) migrate() {
	h.t.Helper()
	output, err := h.runCLI("migrate")
	if err != nil {
		h.t.Fatalf("run migrations: %v (%s)", err, trimOutput(output))
	}
	store, err := database.Open(h.ctx, h.databaseURL)
	if err != nil {
		h.t.Fatal(err)
	}
	h.store = store
	h.t.Cleanup(store.Close)
}

func (h *harness) startScheduler() {
	h.t.Helper()
	logFile, err := os.OpenFile(filepath.Join(h.root, "logs", "scheduler.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = logFile.Close() })
	cmd := exec.CommandContext(h.ctx, h.scheduler)
	cmd.Dir = h.root
	cmd.Env = h.env
	writer := io.MultiWriter(logFile, h.schedulerLog)
	cmd.Stdout = writer
	cmd.Stderr = writer
	if err := cmd.Start(); err != nil {
		h.t.Fatalf("start scheduler: %v", err)
	}
	h.schedulerCmd = cmd
	if err := os.WriteFile(filepath.Join(h.root, "scheduler.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { h.stopScheduler() })
	err = poll(h.ctx, 20*time.Second, 50*time.Millisecond, func() (bool, error) {
		if strings.Contains(h.schedulerLog.String(), "Reconductor scheduler ready") {
			return true, nil
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return false, fmt.Errorf("scheduler exited before readiness")
		}
		return false, nil
	})
	if err != nil {
		h.t.Fatalf("wait for exact scheduler readiness log: %v\n%s", err, h.schedulerLog.String())
	}
}

func (h *harness) stopScheduler() {
	if h.schedulerCmd == nil || h.schedulerCmd.Process == nil {
		return
	}
	process := h.schedulerCmd.Process
	if runtime.GOOS == "windows" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = h.runExternal(ctx, "taskkill.exe", nil, "/PID", strconv.Itoa(process.Pid), "/T", "/F")
	} else {
		_ = process.Kill()
	}
	done := make(chan struct{})
	go func() {
		_ = h.schedulerCmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		h.t.Errorf("scheduler process %d did not exit", process.Pid)
	}
	_ = os.Remove(filepath.Join(h.root, "scheduler.pid"))
}

func (h *harness) runToApproval(name string) scenario {
	h.t.Helper()
	program := h.createProgram(name)
	schedule := h.createSchedule(program, name)
	var execution domain.ScheduledExecution
	h.runCLIJSON(&execution, "schedule", "run-now", string(schedule.ID))
	execution = h.waitExecution(schedule.ID, execution.ID, domain.ScheduledExecutionPausedForApproval)
	if execution.WorkflowRunID == nil || execution.TaskID == nil {
		h.t.Fatalf("%s execution reached approval without task/run lineage: %#v", name, execution)
	}
	state := h.waitWorkflowState(*execution.WorkflowRunID, domain.RunPaused)
	approval := h.waitPendingApproval(state.Steps["run-safe-nuclei-profile"].Run.ID, *execution.TaskID)
	return scenario{name: name, program: program, schedule: schedule, execution: execution, state: state, approval: approval}
}

func (h *harness) createProgram(name string) domain.Program {
	h.t.Helper()
	var program domain.Program
	h.runCLIJSON(&program,
		"program", "create",
		"--name", "operational-"+name+"-"+h.runID,
		"--platform", "lab",
		"--description", "disposable loopback-only approval lifecycle",
		"--scope", h.scopeRef,
		"--policy", "default",
	)
	if program.ScopeReference != h.scopeRef {
		h.t.Fatalf("program persisted scope reference %q, want logical %q", program.ScopeReference, h.scopeRef)
	}
	return program
}

func (h *harness) createSchedule(program domain.Program, name string) domain.Schedule {
	h.t.Helper()
	var schedule domain.Schedule
	h.runCLIJSON(&schedule,
		"schedule", "create",
		"--program-id", string(program.ID),
		"--name", "operational-"+name+"-"+h.runID,
		"--workflow", "authorized-web-baseline",
		"--cron", "0 0 1 1 *",
		"--timezone", "UTC",
		"--objective", "disposable local approval lifecycle "+name,
		"--created-by", "operational-e2e",
	)
	return schedule
}

func (h *harness) assertPreApproval(s scenario) {
	h.t.Helper()
	target := h.fixture.URL()
	probe := requiredStep(h.t, s.state, "probe-http")
	if probe.Run.Status != domain.StepSucceeded {
		h.t.Fatalf("%s probe-http status=%s", s.name, probe.Run.Status)
	}
	var probeOutput commandprovider.ProviderOutput
	decodeJSON(h.t, probe.Run.Output, &probeOutput, "probe-http output")
	if len(probeOutput.AuthorizedRecords) != 1 {
		h.t.Fatalf("%s HTTPX authorized records=%#v, want exactly one", s.name, probeOutput.AuthorizedRecords)
	}
	record := probeOutput.AuthorizedRecords[0]
	if record.Target != target || record.StatusCode != http.StatusOK {
		h.t.Fatalf("%s structured HTTP record=%#v, want target=%q status=200", s.name, record, target)
	}

	compare := requiredStep(h.t, s.state, "compare-assets")
	var compareInput providers.CompareAssetsInput
	decodeJSON(h.t, compare.Run.Input, &compareInput, "compare-assets input")
	if compareInput.Previous == nil || len(compareInput.Previous) != 0 {
		h.t.Fatalf("%s compare-assets previous=%#v, want non-nil empty array", s.name, compareInput.Previous)
	}
	if len(compareInput.Current) != 1 {
		h.t.Fatalf("%s compare-assets current=%#v, want one structured record", s.name, compareInput.Current)
	}
	var compareRecord provideroutput.Record
	decodeJSON(h.t, []byte(compareInput.Current[0]), &compareRecord, "compare-assets structured current observation")
	if compareRecord.Target != target || compareRecord.StatusCode != http.StatusOK || compareRecord.Kind != provideroutput.URLRecord {
		h.t.Fatalf("%s compare-assets structured current record=%#v, want URL target=%q status=200", s.name, compareRecord, target)
	}
	var compareOutput providers.CompareAssetsOutput
	decodeJSON(h.t, compare.Run.Output, &compareOutput, "compare-assets output")
	assertExactStrings(h.t, s.name+" active route", compareOutput.StatusRoutes.Active, []string{target})
	assertExactStrings(h.t, s.name+" scan_targets", compareOutput.ScanTargets, []string{target})

	nuclei := requiredStep(h.t, s.state, "run-safe-nuclei-profile")
	if nuclei.Run.Status != domain.StepAwaitingApproval || nuclei.Run.ApprovalState != "pending" {
		h.t.Fatalf("%s Nuclei pre-approval status=%s approval_state=%q", s.name, nuclei.Run.Status, nuclei.Run.ApprovalState)
	}
	var input commandprovider.Input
	decodeJSON(h.t, nuclei.Run.Input, &input, "Nuclei input")
	assertExactStrings(h.t, s.name+" Nuclei input targets", input.Targets, []string{target})
}

func (h *harness) reject(s scenario) {
	h.t.Helper()
	if output, err := h.runCLI("approvals", "reject", string(s.approval.ID), "operational-e2e"); err != nil {
		h.t.Fatalf("reject approval: %v (%s)", err, trimOutput(output))
	}
}

func (h *harness) assertRejected(s scenario) {
	h.t.Helper()
	execution := h.waitExecution(s.schedule.ID, s.execution.ID, domain.ScheduledExecutionApprovalRejected)
	if execution.ErrorClassification != "approval_rejected" {
		h.t.Fatalf("rejected execution classification=%q", execution.ErrorClassification)
	}
	approval := h.waitApprovalDecision(s.approval.ID, "rejected")
	if approval.Decision != "rejected" {
		h.t.Fatalf("approval decision=%q", approval.Decision)
	}
	task, err := h.store.GetTask(h.ctx, *execution.TaskID)
	if err != nil {
		h.t.Fatal(err)
	}
	run, err := h.store.GetWorkflowRun(h.ctx, *execution.WorkflowRunID)
	if err != nil {
		h.t.Fatal(err)
	}
	if task.Status != domain.TaskFailed || run.Status != domain.RunFailed {
		h.t.Fatalf("rejected lineage task=%s workflow=%s", task.Status, run.Status)
	}
	snapshot := h.waitSnapshotStep(s.program.ID, *execution.WorkflowRunID, "run-safe-nuclei-profile", domain.StepFailed)
	if snapshot.ApprovalState != "rejected" || snapshot.ErrorClassification != "approval_rejected" {
		h.t.Fatalf("rejected step=%#v", snapshot)
	}
}

func (h *harness) approveWithoutResume(s scenario) {
	h.t.Helper()
	if output, err := h.runCLI("approvals", "approve", string(s.approval.ID), "operational-e2e"); err != nil {
		h.t.Fatalf("approve approval: %v (%s)", err, trimOutput(output))
	}
	h.waitApprovalDecision(s.approval.ID, "approved")
	timer := time.NewTimer(750 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-h.ctx.Done():
		h.t.Fatal(h.ctx.Err())
	case <-timer.C:
	}
	execution := h.getExecution(s.schedule.ID, s.execution.ID)
	if execution.Status != domain.ScheduledExecutionPausedForApproval {
		h.t.Fatalf("approval implicitly resumed execution: status=%s", execution.Status)
	}
}

func (h *harness) resumeAndComplete(s scenario) {
	h.t.Helper()
	if output, err := h.runCLI("schedule", "resume", string(s.execution.ID)); err != nil {
		h.t.Fatalf("explicit schedule resume: %v (%s)", err, trimOutput(output))
	}
	s.execution = h.waitExecution(s.schedule.ID, s.execution.ID, domain.ScheduledExecutionCompleted)
	s.state = h.waitWorkflowState(*s.execution.WorkflowRunID, domain.RunCompleted)
}

func (h *harness) assertApprovedCompletion(s scenario) {
	h.t.Helper()
	execution := h.getExecution(s.schedule.ID, s.execution.ID)
	if execution.Status != domain.ScheduledExecutionCompleted {
		h.t.Fatalf("approved execution status=%s", execution.Status)
	}
	task, err := h.store.GetTask(h.ctx, *execution.TaskID)
	if err != nil {
		h.t.Fatal(err)
	}
	run, err := h.store.GetWorkflowRun(h.ctx, *execution.WorkflowRunID)
	if err != nil {
		h.t.Fatal(err)
	}
	if task.Status != domain.TaskCompleted || run.Status != domain.RunCompleted {
		h.t.Fatalf("approved lineage task=%s workflow=%s", task.Status, run.Status)
	}
	state := h.waitWorkflowState(*execution.WorkflowRunID, domain.RunCompleted)
	nuclei := requiredStep(h.t, state, "run-safe-nuclei-profile")
	if nuclei.Run.Status != domain.StepSucceeded || nuclei.Run.ApprovalState != "approved" {
		h.t.Fatalf("approved Nuclei step status=%s approval_state=%q", nuclei.Run.Status, nuclei.Run.ApprovalState)
	}
	var input commandprovider.Input
	decodeJSON(h.t, nuclei.Run.Input, &input, "approved Nuclei input")
	assertExactStrings(h.t, "approved Nuclei targets", input.Targets, []string{h.fixture.URL()})
	if !bytes.Contains(nuclei.Run.Output, []byte("reconductor-local-approval")) {
		h.t.Fatalf("Nuclei output does not contain isolated template ID: %s", nuclei.Run.Output)
	}
	h.assertGuardScanCount(1)
	entries := h.guardEntries()
	var scan *guardLogEntry
	for index := range entries {
		if entries[index].Accepted && entries[index].Kind == "scan" {
			scan = &entries[index]
		}
	}
	if scan == nil || len(scan.TemplatePaths) != 1 || !samePath(scan.TemplatePaths[0], h.templateDir) {
		h.t.Fatalf("guard did not observe only isolated template directory: %#v", scan)
	}
	if got := h.fixture.nucleiRequests.Load(); got != 1 {
		h.t.Fatalf("fixture Nuclei-header requests=%d want=1 (total requests=%d)", got, h.fixture.totalRequests.Load())
	}
	if violation := h.fixture.Violation(); violation != "" {
		h.t.Fatalf("fixture observed a non-loopback request: %s", violation)
	}
	snapshot, err := h.store.ConsoleSnapshot(h.ctx, s.program.ID)
	if err != nil {
		h.t.Fatal(err)
	}
	foundTool := false
	for _, tool := range snapshot.Tools {
		if tool.WorkflowRunID != *execution.WorkflowRunID || tool.StepDefinitionID != "run-safe-nuclei-profile" {
			continue
		}
		foundTool = true
		var safe map[string]any
		decodeJSON(h.t, tool.SanitizedArguments, &safe, "Nuclei sanitized arguments")
		if safe["target_count"] != float64(1) {
			h.t.Fatalf("Nuclei sanitized target_count=%v want=1", safe["target_count"])
		}
	}
	if !foundTool {
		h.t.Fatal("completed workflow has no persisted Nuclei tool run")
	}
}

func (h *harness) waitExecution(scheduleID, executionID domain.ID, desired domain.ScheduledExecutionStatus) domain.ScheduledExecution {
	h.t.Helper()
	var last domain.ScheduledExecution
	err := poll(h.ctx, 2*time.Minute, 150*time.Millisecond, func() (bool, error) {
		last = h.getExecution(scheduleID, executionID)
		if isTerminalExecution(last.Status) && last.Status != desired {
			return false, fmt.Errorf("execution reached terminal status %s: classification=%s summary=%s", last.Status, last.ErrorClassification, last.ErrorSummary)
		}
		return last.Status == desired, nil
	})
	if err != nil {
		h.t.Fatalf("wait for execution %s status %s (last=%s): %v\nscheduler log:\n%s", executionID, desired, last.Status, err, h.schedulerLog.String())
	}
	return last
}

func (h *harness) getExecution(scheduleID, executionID domain.ID) domain.ScheduledExecution {
	h.t.Helper()
	var items []domain.ScheduledExecution
	h.runCLIJSON(&items, "schedule", "executions", "--schedule-id", string(scheduleID))
	for _, item := range items {
		if item.ID == executionID {
			return item
		}
	}
	h.t.Fatalf("execution %s not found for schedule %s", executionID, scheduleID)
	return domain.ScheduledExecution{}
}

func (h *harness) waitWorkflowState(runID domain.ID, status domain.RunStatus) *workflow.State {
	h.t.Helper()
	var last domain.RunStatus
	var state *workflow.State
	err := poll(h.ctx, 30*time.Second, 100*time.Millisecond, func() (bool, error) {
		loaded, err := (workflow.FileStore{Root: filepath.Join(h.root, "state", "runs")}).Load(string(runID))
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		state = loaded
		last = loaded.Run.Status
		return last == status, nil
	})
	if err != nil {
		h.t.Fatalf("wait for workflow state %s status %s (last=%s): %v", runID, status, last, err)
	}
	return state
}

func (h *harness) waitPendingApproval(stepID, taskID domain.ID) database.ApprovalListItem {
	h.t.Helper()
	var found database.ApprovalListItem
	err := poll(h.ctx, 30*time.Second, 100*time.Millisecond, func() (bool, error) {
		var approvals []database.ApprovalListItem
		h.runCLIJSON(&approvals, "approvals", "list")
		for _, approval := range approvals {
			if approval.RequestID == stepID && approval.TaskID == taskID && approval.Decision == "pending" {
				found = approval
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		h.t.Fatalf("wait for pending approval for step %s: %v", stepID, err)
	}
	return found
}

func (h *harness) waitApprovalDecision(id domain.ID, decision string) database.ApprovalListItem {
	h.t.Helper()
	var found database.ApprovalListItem
	err := poll(h.ctx, 20*time.Second, 100*time.Millisecond, func() (bool, error) {
		var approvals []database.ApprovalListItem
		h.runCLIJSON(&approvals, "approvals", "list")
		for _, approval := range approvals {
			if approval.ID == id {
				found = approval
				return approval.Decision == decision, nil
			}
		}
		return false, nil
	})
	if err != nil {
		h.t.Fatalf("wait for approval %s decision %s (last=%s): %v", id, decision, found.Decision, err)
	}
	return found
}

func (h *harness) waitSnapshotStep(programID, runID domain.ID, stepID string, status domain.StepStatus) database.ConsoleStep {
	h.t.Helper()
	var last database.ConsoleStep
	err := poll(h.ctx, 20*time.Second, 100*time.Millisecond, func() (bool, error) {
		snapshot, err := h.store.ConsoleSnapshot(h.ctx, programID)
		if err != nil {
			return false, err
		}
		for _, step := range snapshot.Steps {
			if step.WorkflowRunID == runID && step.StepDefinitionID == stepID {
				last = step
				return step.Status == status, nil
			}
		}
		return false, nil
	})
	if err != nil {
		h.t.Fatalf("wait for step %s status %s (last=%s): %v", stepID, status, last.Status, err)
	}
	return last
}

func (h *harness) assertGuardScanCount(want int) {
	h.t.Helper()
	count := 0
	for _, entry := range h.guardEntries() {
		if entry.Accepted && entry.Kind == "scan" {
			count++
		}
	}
	if count != want {
		h.t.Fatalf("accepted Nuclei scan count=%d want=%d", count, want)
	}
}

func (h *harness) guardEntries() []guardLogEntry {
	h.t.Helper()
	file, err := os.Open(h.guardLog)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	defer file.Close()
	var entries []guardLogEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry guardLogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			h.t.Fatalf("decode guard invocation log: %v", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		h.t.Fatal(err)
	}
	return entries
}

func (h *harness) runCLI(args ...string) ([]byte, error) {
	return h.runExternalInDir(h.ctx, h.root, h.platform, h.env, args...)
}

func (h *harness) runCLIJSON(target any, args ...string) {
	h.t.Helper()
	output, err := h.runCLI(args...)
	if err != nil {
		h.t.Fatalf("platform %s: %v (%s)", strings.Join(args, " "), err, trimOutput(output))
	}
	if err := json.Unmarshal(output, target); err != nil {
		h.t.Fatalf("decode platform %s JSON: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func (h *harness) runExternal(ctx context.Context, executable string, environment []string, args ...string) ([]byte, error) {
	return h.runExternalInDir(ctx, h.repoRoot, executable, environment, args...)
}

func (h *harness) runExternalInDir(ctx context.Context, directory, executable string, environment []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = directory
	if environment != nil {
		cmd.Env = environment
	}
	return cmd.CombinedOutput()
}

type localFixture struct {
	listener       net.Listener
	server         *http.Server
	url            string
	runID          string
	totalRequests  atomic.Int64
	nucleiRequests atomic.Int64
	mu             sync.Mutex
	violation      string
}

func startLocalFixture(t *testing.T, runID string) *localFixture {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &localFixture{listener: listener, runID: runID}
	fixture.url = "http://" + listener.Addr().String() + "/"
	fixture.server = &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fixture.totalRequests.Add(1)
			host, _, splitErr := net.SplitHostPort(r.Host)
			ip := net.ParseIP(host)
			remoteHost, _, remoteErr := net.SplitHostPort(r.RemoteAddr)
			remoteIP := net.ParseIP(remoteHost)
			if splitErr != nil || ip == nil || !ip.IsLoopback() || remoteErr != nil || remoteIP == nil || !remoteIP.IsLoopback() {
				fixture.mu.Lock()
				if fixture.violation == "" {
					fixture.violation = fmt.Sprintf("host=%q remote=%q", r.Host, r.RemoteAddr)
				}
				fixture.mu.Unlock()
				http.Error(w, "loopback only", http.StatusForbidden)
				return
			}
			if r.Header.Get("X-Reconductor-E2E-Nuclei") == runID {
				fixture.nucleiRequests.Add(1)
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "<!doctype html><title>Reconductor E2E</title><p>loopback fixture</p>")
		}),
	}
	go func() {
		_ = fixture.server.Serve(listener)
	}()
	return fixture
}

func (f *localFixture) URL() string { return f.url }

func (f *localFixture) Violation() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.violation
}

func (f *localFixture) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = f.server.Shutdown(ctx)
	_ = f.listener.Close()
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(value)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func poll(parent context.Context, timeout, interval time.Duration, check func() (bool, error)) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		ok, err := check()
		if err != nil || ok {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func findRepositoryRoot() (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		data, readErr := os.ReadFile(filepath.Join(current, "go.mod"))
		if readErr == nil && bytes.Contains(data, []byte("module github.com/tobiasGuta/Reconductor")) {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("repository root containing Reconductor go.mod was not found")
		}
		current = parent
	}
}

func configuredExecutable(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func environmentWithOverrides(base []string, overrides map[string]string) []string {
	normalized := make(map[string]string, len(overrides))
	for key, value := range overrides {
		normalized[strings.ToUpper(key)] = value
	}
	out := make([]string, 0, len(base)+len(overrides))
	for _, item := range base {
		key, _, ok := strings.Cut(item, "=")
		if ok {
			if _, replaced := normalized[strings.ToUpper(key)]; replaced {
				continue
			}
		}
		out = append(out, item)
	}
	for key, value := range overrides {
		out = append(out, key+"="+value)
	}
	return out
}

func scrubOperationalEnvironment(base []string) []string {
	unsafePrefixes := []string{
		"ARTIFACT_", "AWS_", "AZURE_", "DATABASE_", "GITHUB_", "GITLAB_", "NUCLEI_",
		"PDCP_", "POLICY_", "RECON_", "RECONDUCTOR_E2E_", "REDACT_", "REDIS_", "SCHEDULER_",
		"SCOPE_", "WORKER_", "WORKFLOW_STATE_",
	}
	unsafeExact := map[string]bool{
		"ALL_PROXY": true, "CHAOS_KEY": true, "DNSX_EXECUTABLE": true, "GAU_EXECUTABLE": true,
		"HTTP_PROXY": true, "HTTPS_PROXY": true, "HTTPX_EXECUTABLE": true, "KATANA_EXECUTABLE": true,
		"NAABU_EXECUTABLE": true, "NO_PROXY": true, "SUBFINDER_EXECUTABLE": true,
	}
	out := make([]string, 0, len(base))
	for _, item := range base {
		key, _, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		upper := strings.ToUpper(key)
		if unsafeExact[upper] {
			continue
		}
		unsafe := false
		for _, prefix := range unsafePrefixes {
			if strings.HasPrefix(upper, prefix) {
				unsafe = true
				break
			}
		}
		if !unsafe {
			out = append(out, item)
		}
	}
	return out
}

func ownedContainerLabels(value, runID string) bool {
	return value == runID+"|true"
}

func validateTemporaryRoot(root string) error {
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return err
	}
	tempAbs, err := filepath.Abs(filepath.Clean(os.TempDir()))
	if err != nil {
		return err
	}
	parentInfo, err := os.Stat(filepath.Dir(rootAbs))
	if err != nil {
		return fmt.Errorf("inspect operational root parent: %w", err)
	}
	tempInfo, err := os.Stat(tempAbs)
	if err != nil {
		return fmt.Errorf("inspect system temporary directory: %w", err)
	}
	if !os.SameFile(parentInfo, tempInfo) {
		return fmt.Errorf("operational root %q must be an immediate child of system temporary directory %q", rootAbs, tempAbs)
	}
	if !strings.HasPrefix(strings.ToLower(filepath.Base(rootAbs)), "reconductor-operational-e2e-") {
		return fmt.Errorf("operational root %q does not use the required safety prefix", rootAbs)
	}
	return nil
}

func removeTemporaryRoot(root string) error {
	if err := validateTemporaryRoot(root); err != nil {
		return err
	}
	return os.RemoveAll(root)
}

func envTrue(key string) bool {
	value, err := strconv.ParseBool(strings.TrimSpace(os.Getenv(key)))
	return err == nil && value
}

func requiredStep(t *testing.T, state *workflow.State, id string) *workflow.StepState {
	t.Helper()
	step := state.Steps[id]
	if step == nil {
		t.Fatalf("workflow state has no step %q", id)
	}
	return step
}

func decodeJSON(t *testing.T, raw []byte, target any, name string) {
	t.Helper()
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("decode %s: %v\n%s", name, err, raw)
	}
}

func assertExactStrings(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s=%#v want=%#v", name, got, want)
	}
	for index := range got {
		if got[index] != want[index] {
			t.Fatalf("%s=%#v want=%#v", name, got, want)
		}
	}
}

func samePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(filepath.Clean(left))
	rightAbs, rightErr := filepath.Abs(filepath.Clean(right))
	if leftErr != nil || rightErr != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(leftAbs, rightAbs)
	}
	return leftAbs == rightAbs
}

func isTerminalExecution(status domain.ScheduledExecutionStatus) bool {
	switch status {
	case domain.ScheduledExecutionCompleted,
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

func trimOutput(value []byte) string {
	const limit = 2048
	text := strings.TrimSpace(string(value))
	if len(text) > limit {
		return text[:limit]
	}
	return text
}
