package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/console"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/doctor"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/execution"
	"github.com/tobiasGuta/Reconductor/internal/orchestration"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	"github.com/tobiasGuta/Reconductor/internal/queue"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
	schedulecron "github.com/tobiasGuta/Reconductor/internal/scheduler"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
	"github.com/tobiasGuta/Reconductor/internal/workflows"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		if !errors.Is(err, doctor.ErrUnhealthy) {
			slog.Error("command failed", "error", err)
		}
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usage()
	}
	_ = config.LoadEnvFile(".env")
	if args[0] == "scope" {
		cfg, err := config.LoadPlanning()
		if err != nil {
			return err
		}
		return scopeCommand(ctx, cfg, args[1:])
	}
	if args[0] == "doctor" {
		cfg, configErr := config.LoadDoctor()
		return doctorCommand(ctx, cfg, configErr, args[1:])
	}
	planning := args[0] == "workflow" && len(args) > 1 && args[1] == "plan"
	var cfg config.Config
	var err error
	if planning {
		cfg, err = config.LoadPlanning()
	} else {
		cfg, err = config.Load()
	}
	if err != nil {
		return err
	}
	switch args[0] {
	case "migrate":
		return withStore(ctx, cfg, func(s *database.Store) error { return s.Migrate(ctx) })
	case "artifact-store":
		return artifactStoreCommand(ctx, cfg, args[1:])
	case "program":
		return programCommand(ctx, cfg, args[1:])
	case "task":
		return taskCommand(ctx, cfg, args[1:])
	case "workflow":
		return workflowCommand(ctx, cfg, args[1:])
	case "run":
		return runCommand(ctx, cfg, args[1:])
	case "approvals":
		return approvalCommand(ctx, cfg, args[1:])
	case "queue":
		return queueCommand(ctx, cfg, args[1:])
	case "report":
		return reportCommand(ctx, cfg, args[1:])
	case "schedule":
		return scheduleCommand(ctx, cfg, args[1:])
	case "changes":
		return changesCommand(ctx, cfg, args[1:])
	case "console":
		return consoleCommand(ctx, cfg, args[1:])
	case "capabilities":
		b, _ := json.MarshalIndent(providers.Registry(cfg).Names(), "", "  ")
		fmt.Println(string(b))
		return nil
	default:
		return usage()
	}
}
func usage() error {
	return fmt.Errorf("usage: platform <migrate|artifact-store|program|task|scope|workflow|run|approvals|queue|report|schedule|changes|console|capabilities|doctor> ...")
}

type artifactStoreInitOutput struct {
	StoreID       domain.ID `json:"store_id"`
	BackendKind   string    `json:"backend_kind"`
	MarkerFormat  string    `json:"marker_format"`
	MarkerVersion int       `json:"marker_version"`
	Status        string    `json:"status"`
}

func artifactStoreCommand(ctx context.Context, cfg config.Config, args []string) error {
	return artifactStoreCommandWithCleanup(ctx, cfg, args, cleanupArtifactStore)
}

func artifactStoreCommandWithCleanup(ctx context.Context, cfg config.Config, args []string, cleanup func(context.Context, config.Config, domain.ID, int) (artifact.CleanupResult, error)) error {
	if len(args) == 0 {
		return fmt.Errorf("artifact-store requires init, cleanup, prepared-limits, or prepared-recover")
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("artifact-store init", flag.ContinueOnError)
		allowNonempty := fs.Bool("allow-nonempty-root", false, "acknowledge initialization of a nonempty unmarked legacy root")
		resumeRegistration := fs.Bool("resume-registration", false, "resume database registration from an existing exact marker")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("artifact-store init accepts no positional arguments")
		}
		storeID, err := cfg.ArtifactStorage.RequiredStoreID()
		if err != nil {
			return err
		}
		store, err := readyStore(ctx, cfg)
		if err != nil {
			return err
		}
		defer store.Close()
		result, err := artifact.InitializeLocal(ctx, cfg.ArtifactStorage.Root, storeID, store, artifact.InitializationOptions{AllowNonemptyRoot: *allowNonempty, ResumeRegistration: *resumeRegistration})
		if err != nil {
			return err
		}
		return printJSON(artifactStoreInitOutput{StoreID: result.Store.ID, BackendKind: result.Store.BackendKind, MarkerFormat: result.Store.MarkerFormat, MarkerVersion: result.Store.MarkerVersion, Status: result.Status})

	case "cleanup":
		fs := flag.NewFlagSet("artifact-store cleanup", flag.ContinueOnError)
		batchSize := fs.Int("batch-size", 100, "maximum number of expired artifacts to claim and clean in this batch (1..1000)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("artifact-store cleanup accepts no positional arguments")
		}
		if *batchSize < 1 || *batchSize > 1000 {
			return fmt.Errorf("batch-size %d must be between 1 and 1000", *batchSize)
		}
		storeID, err := cfg.ArtifactStorage.RequiredStoreID()
		if err != nil {
			return err
		}
		result, err := cleanup(ctx, cfg, storeID, *batchSize)
		if err != nil {
			return err
		}
		return printJSON(result)

	case "prepared-limits":
		fs := flag.NewFlagSet("artifact-store prepared-limits", flag.ContinueOnError)
		maxOpen := fs.Int("max-open-sets", 0, "maximum unresolved prepared sets")
		maxSet := fs.Int64("max-set-bytes", 0, "pessimistic bytes reserved for one prepared set")
		maxUnresolved := fs.Int64("max-unresolved-bytes", 0, "maximum unresolved prepared bytes")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("artifact-store prepared-limits accepts no positional arguments")
		}
		storeID, err := cfg.ArtifactStorage.RequiredStoreID()
		if err != nil {
			return err
		}
		store, err := readyStore(ctx, cfg)
		if err != nil {
			return err
		}
		defer store.Close()
		if err := store.RequireCurrentSchema(ctx); err != nil {
			return err
		}
		if err := store.ConfigurePreparedEvidenceLimits(ctx, storeID, *maxOpen, *maxSet, *maxUnresolved); err != nil {
			return err
		}
		return printJSON(map[string]any{"store_id": storeID, "max_open_sets": *maxOpen, "max_set_bytes": *maxSet, "max_unresolved_bytes": *maxUnresolved, "status": "configured"})

	case "prepared-recover":
		fs := flag.NewFlagSet("artifact-store prepared-recover", flag.ContinueOnError)
		batchSize := fs.Int("batch-size", 100, "maximum prepared sets to reconcile or clean (1..1000)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *batchSize < 1 || *batchSize > 1000 {
			return fmt.Errorf("artifact-store prepared-recover requires batch-size between 1 and 1000 and accepts no positional arguments")
		}
		storeID, err := cfg.ArtifactStorage.RequiredStoreID()
		if err != nil {
			return err
		}
		store, err := readyStore(ctx, cfg)
		if err != nil {
			return err
		}
		defer store.Close()
		if err := store.RequireCurrentSchema(ctx); err != nil {
			return err
		}
		localStore, err := artifact.OpenLocal(ctx, cfg.ArtifactStorage.Root, storeID, store, nil)
		if err != nil {
			return err
		}
		if err := (execution.Service{Store: store, Artifacts: localStore}).RecoverPreparedEvidence(ctx, *batchSize); err != nil {
			return err
		}
		prepared, err := store.PreparedEvidenceStatus(ctx, storeID)
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"store_id": storeID, "batch_size": *batchSize, "status": "reconciled", "open_sets": prepared.OpenSets, "max_open_sets": prepared.MaxOpenSets, "unresolved_bytes": prepared.UnresolvedBytes, "max_unresolved_bytes": prepared.MaxUnresolvedBytes, "max_set_bytes": prepared.MaxSetBytes})

	default:
		return fmt.Errorf("artifact-store requires init, cleanup, prepared-limits, or prepared-recover")
	}
}

func cleanupArtifactStore(ctx context.Context, cfg config.Config, storeID domain.ID, batchSize int) (artifact.CleanupResult, error) {
	store, err := readyStore(ctx, cfg)
	if err != nil {
		return artifact.CleanupResult{}, err
	}
	defer store.Close()
	if err := store.RequireCurrentSchema(ctx); err != nil {
		return artifact.CleanupResult{}, err
	}
	localStore, err := artifact.OpenLocal(ctx, cfg.ArtifactStorage.Root, storeID, store, nil)
	if err != nil {
		return artifact.CleanupResult{}, err
	}
	if localStore.StoreID() != storeID {
		return artifact.CleanupResult{}, fmt.Errorf("local artifact store ID does not match configured store")
	}
	return artifact.CleanupBatch(ctx, store, localStore, batchSize)
}

func consoleCommand(ctx context.Context, cfg config.Config, args []string) error {
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8088", "loopback address for the local operator console")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireLoopbackAddress(*listen); err != nil {
		return err
	}
	store, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	rdb := redisClient(cfg)
	defer rdb.Close()
	workQueue := queue.New(rdb, cfg.Worker.ConsumerGroup, cfg.Worker.ConsumerName, cfg.Worker.MaxRetries, cfg.Worker.RetryBase)
	if err := workQueue.EnsureGroup(ctx); err != nil {
		return fmt.Errorf("initialize console queue view: %w", err)
	}
	validator := &schedulecron.ScheduleValidator{Programs: store, Registry: providers.Registry(cfg), ScopeRoot: cfg.Scope.Root}
	server := console.HTTPServer(*listen, console.New(store, workQueue, validator))
	slog.Info("Reconductor operator console ready", "url", "http://"+*listen)
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func requireLoopbackAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return fmt.Errorf("console --listen must be a loopback host:port")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("console refuses non-loopback address %q because authentication is not configured", address)
	}
	return nil
}

func doctorCommand(ctx context.Context, cfg config.Config, configErr error, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	format := fs.String("format", "table", "output format: table or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	report := doctor.Run(ctx, cfg, configErr)
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "table":
		if err := doctor.WriteTable(os.Stdout, report); err != nil {
			return err
		}
	case "json":
		if err := doctor.WriteJSON(os.Stdout, report); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported doctor format %q (use table or json)", *format)
	}
	if !report.Healthy {
		return doctor.ErrUnhealthy
	}
	return nil
}
func withStore(ctx context.Context, cfg config.Config, fn func(*database.Store) error) error {
	s, err := database.Open(ctx, cfg.Database.URL)
	if err != nil {
		return err
	}
	defer s.Close()
	return fn(s)
}
func readyStore(ctx context.Context, cfg config.Config) (*database.Store, error) {
	s, err := database.Open(ctx, cfg.Database.URL)
	if err != nil {
		return nil, err
	}
	if err := s.RequireCurrentSchema(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err == nil {
		fmt.Println(string(b))
	}
	return err
}

func programCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("program requires create or list")
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("program create", flag.ContinueOnError)
		name := fs.String("name", "", "program name")
		platform := fs.String("platform", "private", "HackerOne, Bugcrowd, private, lab, or internal")
		description := fs.String("description", "", "description")
		scopeRef := fs.String("scope", "", "scope file/reference")
		policyRef := fs.String("policy", "default", "policy reference")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" || *scopeRef == "" {
			return fmt.Errorf("--name and --scope are required")
		}
		reference, err := platformscope.CanonicalReference(*scopeRef)
		if err != nil {
			return err
		}
		sc, err := platformscope.LoadBurpReference(reference, cfg.Scope.Root)
		if err != nil {
			return fmt.Errorf("load scope: %w", err)
		}
		plan, err := targeting.Plan(sc, nil)
		if err != nil {
			return err
		}
		if !plan.HasExecutableTargets() {
			return fmt.Errorf("target plan has no executable authorized targets")
		}
		now := time.Now().UTC()
		warnings, _ := json.Marshal(plan.Warnings)
		p := domain.Program{ID: domain.NewID(), Name: *name, Platform: *platform, Description: *description, ScopeReference: reference, PolicyReference: *policyRef, ScopeDigest: sc.Digest(), IncludeRuleDigests: sc.IncludeDigests(), ExcludeRuleDigests: sc.ExcludeDigests(), TargetPlanDigest: plan.Digest, ScopePlanWarnings: warnings, CreatedAt: now, UpdatedAt: now}
		if err := s.CreateProgram(ctx, p, scopeSnapshot(p.ID, reference, sc, plan)); err != nil {
			return err
		}
		return printJSON(p)
	case "list":
		p, err := s.ListPrograms(ctx)
		if err != nil {
			return err
		}
		return printJSON(p)
	default:
		return fmt.Errorf("unknown program command %q", args[0])
	}
}
func taskCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("task requires create, list, show, pause, resume, or cancel")
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("task create", flag.ContinueOnError)
		programID := fs.String("program-id", "", "program UUID")
		objective := fs.String("objective", "", "human objective")
		requested := fs.String("requested-by", "cli", "request source")
		workflowName := fs.String("workflow", workflows.ContinuousName, "workflow template name")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *programID == "" || *objective == "" {
			return fmt.Errorf("--program-id and --objective are required")
		}
		template, err := workflows.CurrentTemplate(*workflowName)
		if err != nil {
			return err
		}
		if err := s.EnsureWorkflowTemplate(ctx, template); err != nil {
			return err
		}
		now := time.Now().UTC()
		t := domain.Task{ID: domain.NewID(), ProgramID: domain.ID(*programID), Objective: *objective, WorkflowDefinitionID: template.ID, Status: domain.TaskPending, RequestedBy: *requested, CreatedAt: now, UpdatedAt: now}
		if err := s.CreateTask(ctx, t); err != nil {
			return err
		}
		return printJSON(t)
	case "list":
		items, err := s.ListTasks(ctx)
		if err != nil {
			return err
		}
		return printJSON(items)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("task show <task-id>")
		}
		t, err := s.GetTask(ctx, domain.ID(args[1]))
		if err != nil {
			return err
		}
		return printJSON(t)
	case "pause", "resume", "cancel":
		if len(args) < 2 {
			return fmt.Errorf("task %s <task-id>", args[0])
		}
		status := map[string]domain.TaskStatus{"pause": domain.TaskPaused, "resume": domain.TaskRunning, "cancel": domain.TaskCancelled}[args[0]]
		reason := ""
		if args[0] == "cancel" && len(args) > 2 {
			reason = strings.Join(args[2:], " ")
		}
		return s.SetTaskStatus(ctx, domain.ID(args[1]), status, reason)
	default:
		return fmt.Errorf("unknown task command %q", args[0])
	}
}

type stringFlags []string

func (s *stringFlags) String() string         { return strings.Join(*s, ",") }
func (s *stringFlags) Set(value string) error { *s = append(*s, value); return nil }

type positiveIntFlag struct{ value int }

func (f *positiveIntFlag) String() string { return strconv.Itoa(f.value) }
func (f *positiveIntFlag) Set(value string) error {
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 {
		return fmt.Errorf("must be a positive integer")
	}
	f.value = n
	return nil
}

func scopeCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("scope requires plan or update")
	}
	switch args[0] {
	case "plan":
		return scopePlanCommand(cfg, args[1:])
	case "update":
		return scopeUpdateCommand(ctx, cfg, args[1:])
	default:
		return fmt.Errorf("unknown scope command %q", args[0])
	}
}

func scopePlanCommand(cfg config.Config, args []string) error {
	fs := flag.NewFlagSet("scope plan", flag.ContinueOnError)
	scopePath := fs.String("scope", "", "Burp-compatible scope JSON")
	var roots stringFlags
	fs.Var(&roots, "discovery-root", "manual passive discovery root (repeatable)")
	reason := fs.String("discovery-root-reason", "", "auditable reason for manual discovery roots")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scopePath == "" {
		return fmt.Errorf("--scope is required")
	}
	manual, err := manualRoots(roots, *reason, "")
	if err != nil {
		return err
	}
	plan, err := loadTargetPlan(*scopePath, cfg.Scope.Root, manual)
	if err != nil {
		return err
	}
	return printJSON(plan)
}

func scopeUpdateCommand(ctx context.Context, cfg config.Config, args []string) error {
	fs := flag.NewFlagSet("scope update", flag.ContinueOnError)
	programID := fs.String("program-id", "", "program UUID")
	scopeReference := fs.String("scope", "", "replacement logical scope reference")
	actor := fs.String("actor", "cli", "audited actor")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *programID == "" || *scopeReference == "" {
		return fmt.Errorf("--program-id and --scope are required")
	}
	reference, err := platformscope.CanonicalReference(*scopeReference)
	if err != nil {
		return err
	}
	store, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()
	program, err := store.GetProgram(ctx, domain.ID(*programID))
	if err != nil {
		return err
	}
	sc, err := platformscope.LoadBurpReference(reference, cfg.Scope.Root)
	if err != nil {
		return fmt.Errorf("load scope: %w", err)
	}
	plan, err := targeting.Plan(sc, nil)
	if err != nil {
		return err
	}
	if sc.Digest() != program.ScopeDigest || plan.Digest != program.TargetPlanDigest {
		return fmt.Errorf("scope update changes authorization or its target plan; use the workflow scope-change review path instead")
	}
	if err := store.RepairProgramScopeReference(ctx, program.ID, reference, program.ScopeDigest, program.TargetPlanDigest, *actor); err != nil {
		return err
	}
	program.ScopeReference = reference
	program.UpdatedAt = time.Now().UTC()
	return printJSON(program)
}

func loadTargetPlan(reference, scopeRoot string, manual []targeting.ManualDiscoveryRoot) (targeting.TargetPlan, error) {
	sc, err := platformscope.LoadBurpReference(reference, scopeRoot)
	if err != nil {
		return targeting.TargetPlan{}, fmt.Errorf("load scope: %w", err)
	}
	plan, err := targeting.Plan(sc, manual)
	if err != nil {
		return targeting.TargetPlan{}, err
	}
	return plan, nil
}

func scopeSnapshot(programID domain.ID, reference string, sc platformscope.Scope, plan targeting.TargetPlan) domain.ScopeSnapshot {
	warnings, _ := json.Marshal(plan.Warnings)
	planJSON, _ := json.Marshal(plan)
	return domain.ScopeSnapshot{ID: domain.NewID(), ProgramID: programID, ScopeReference: reference, ScopeDigest: sc.Digest(), IncludeRuleDigests: sc.IncludeDigests(), ExcludeRuleDigests: sc.ExcludeDigests(), TargetPlanDigest: plan.Digest, PlanningWarnings: warnings, TargetPlan: planJSON, AddedIncludeDigests: []string{}, RemovedIncludeDigests: []string{}, AddedExcludeDigests: []string{}, RemovedExcludeDigests: []string{}, CreatedAt: time.Now().UTC()}
}

func manualRoots(roots []string, reason, deprecatedDomain string) ([]targeting.ManualDiscoveryRoot, error) {
	if len(roots) > 0 && strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("--discovery-root-reason is required with --discovery-root")
	}
	out := make([]targeting.ManualDiscoveryRoot, 0, len(roots)+1)
	for _, root := range roots {
		out = append(out, targeting.ManualDiscoveryRoot{Domain: root, Reason: reason})
	}
	if strings.TrimSpace(deprecatedDomain) != "" {
		out = append(out, targeting.ManualDiscoveryRoot{Domain: deprecatedDomain, Reason: "deprecated --domain compatibility input"})
	}
	return out, nil
}

func workflowPlan(cfg config.Config, registry *capability.Registry, args []string) error {
	fs := flag.NewFlagSet("workflow plan", flag.ContinueOnError)
	programID := fs.String("program-id", "", "program UUID (recorded only; no database access)")
	scopePath := fs.String("scope", "", "Burp-compatible scope JSON")
	workflowName := fs.String("workflow", workflows.ContinuousName, "workflow name")
	headless := fs.Bool("headless", false, "show policy-approved headless mode")
	deprecatedDomain := fs.String("domain", "", "deprecated passive discovery root")
	var roots stringFlags
	fs.Var(&roots, "discovery-root", "manual passive discovery root (repeatable)")
	reason := fs.String("discovery-root-reason", "", "auditable reason for manual discovery roots")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *programID == "" || *scopePath == "" {
		return fmt.Errorf("--program-id and --scope are required")
	}
	manual, err := manualRoots(roots, *reason, *deprecatedDomain)
	if err != nil {
		return err
	}
	if *deprecatedDomain != "" {
		fmt.Fprintln(os.Stderr, "warning: --domain is deprecated; it is treated only as a passive discovery root")
	}
	plan, err := loadTargetPlan(*scopePath, cfg.Scope.Root, manual)
	if err != nil {
		return err
	}
	if !plan.HasExecutableTargets() {
		return fmt.Errorf("target plan has no executable authorized targets")
	}
	def, err := workflows.Build(*workflowName, plan, *headless)
	if err != nil {
		return err
	}
	if err := workflow.Validate(def, registry); err != nil {
		return err
	}
	type plannedCapability struct {
		Step             string      `json:"step"`
		Capability       string      `json:"capability"`
		Provider         string      `json:"provider,omitempty"`
		Risk             policy.Risk `json:"risk"`
		ApprovalRequired bool        `json:"approval_required"`
	}
	capabilities := make([]plannedCapability, 0, len(def.Steps))
	for _, step := range def.Steps {
		c, ok := registry.Get(step.Capability)
		if !ok {
			continue
		}
		m := c.Manifest()
		capabilities = append(capabilities, plannedCapability{Step: step.ID, Capability: step.Capability, Provider: step.Provider, Risk: m.Risk, ApprovalRequired: step.ApprovalRequired || m.ApprovalRequired})
	}
	return printJSON(map[string]any{
		"network_execution": false, "program_id": *programID, "workflow": map[string]any{"name": def.Name, "version": def.Version}, "target_plan": plan,
		"initial_active_targets": plan.InitialURLs(), "capabilities": capabilities, "rate_limit": cfg.Policy.DefaultRateLimit, "concurrency": cfg.Policy.DefaultConcurrency,
		"authorized_ports": plan.AllowedPorts, "headless": *headless, "nuclei_profile": map[string]any{"approval_required": true, "severity": cfg.Nuclei.Severity, "include_tags": cfg.Nuclei.IncludeTags, "exclude_tags": cfg.Nuclei.ExcludeTags, "rate_limit": cfg.Nuclei.RateLimit}, "warnings": plan.Warnings,
	})
}

func workflowCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("workflow requires validate, plan, or run")
	}
	registry := providers.Registry(cfg)
	switch args[0] {
	case "validate":
		fs := flag.NewFlagSet("workflow validate", flag.ContinueOnError)
		scopePath := fs.String("scope", "", "Burp-compatible scope JSON")
		workflowName := fs.String("workflow", workflows.ContinuousName, "workflow name")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *scopePath == "" {
			return fmt.Errorf("--scope is required")
		}
		plan, err := loadTargetPlan(*scopePath, cfg.Scope.Root, nil)
		if err != nil {
			return err
		}
		if !plan.HasExecutableTargets() {
			return fmt.Errorf("target plan has no executable authorized targets")
		}
		def, err := workflows.Build(*workflowName, plan, cfg.Recon.Headless)
		if err != nil {
			return err
		}
		if err := workflow.Validate(def, registry); err != nil {
			return err
		}
		return printJSON(map[string]any{"name": def.Name, "version": def.Version, "valid": true, "steps": len(def.Steps)})
	case "plan":
		return workflowPlan(cfg, registry, args[1:])
	case "run":
		return workflowRun(ctx, cfg, registry, args[1:])
	default:
		return fmt.Errorf("unknown workflow command %q", args[0])
	}
}
func workflowRun(ctx context.Context, cfg config.Config, registry *capability.Registry, args []string) error {
	fs := flag.NewFlagSet("workflow run", flag.ContinueOnError)
	programID := fs.String("program-id", "", "program UUID")
	taskID := fs.String("task-id", "", "existing task UUID (optional)")
	objective := fs.String("objective", "continuous authorized web reconnaissance", "task objective")
	domainName := fs.String("domain", "", "authorized root domain")
	scopePath := fs.String("scope", "", "Burp scope JSON path")
	workflowName := fs.String("workflow", workflows.ContinuousName, "workflow name")
	var discoveryRoots stringFlags
	fs.Var(&discoveryRoots, "discovery-root", "manual passive discovery root (repeatable)")
	discoveryReason := fs.String("discovery-root-reason", "", "auditable reason for manually supplied passive roots")
	ackScopeExpansion := fs.Bool("acknowledge-scope-expansion", false, "acknowledge an expanded scope plan")
	resumeID := fs.String("resume", "", "workflow run UUID to resume")
	approve := fs.Bool("approve-moderate", false, "explicitly approve the safe moderate Nuclei step for this run")
	headless := fs.Bool("headless", cfg.Recon.Headless, "enable policy-approved Katana headless mode")
	var maxStepAttempts positiveIntFlag
	fs.Var(&maxStepAttempts, "max-step-attempts", "optional positive ceiling for workflow-authorized attempts per step")
	if err := fs.Parse(args); err != nil {
		return err
	}
	manual, err := manualRoots(discoveryRoots, *discoveryReason, *domainName)
	if err != nil {
		return err
	}
	if *domainName != "" {
		fmt.Fprintln(os.Stderr, "warning: --domain is deprecated; it is treated only as a passive discovery root")
	}
	storeID, err := cfg.ArtifactStorage.RequiredStoreID()
	if err != nil {
		return err
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	artifacts, err := artifact.OpenLocal(ctx, cfg.ArtifactStorage.Root, storeID, s, redaction.New(cfg.Logging.SecretNames...))
	if err != nil {
		return err
	}
	if _, err := s.RequirePreparedEvidenceReady(ctx, storeID); err != nil {
		return fmt.Errorf("prepared evidence readiness: %w", err)
	}
	if *programID == "" && *resumeID != "" {
		state, err := s.LoadWorkflowState(ctx, domain.ID(*resumeID))
		if err != nil {
			return err
		}
		task, err := s.GetTask(ctx, state.Run.TaskID)
		if err != nil {
			return err
		}
		*programID = string(task.ProgramID)
	}
	if *programID == "" {
		return fmt.Errorf("--program-id is required")
	}
	req := orchestration.WorkflowRequest{ProgramID: domain.ID(*programID), WorkflowName: *workflowName, Objective: *objective, RequestedBy: "cli", ScopeReference: *scopePath, ManualDiscoveryRoots: manual, AcknowledgeScopeExpansion: *ackScopeExpansion, ResumeRunID: domain.ID(*resumeID), ExistingTaskID: domain.ID(*taskID), ApproveModerate: *approve, Headless: *headless, OperatorAttemptCeiling: maxStepAttempts.value}
	result, err := (orchestration.Service{Config: cfg, Store: s, Registry: registry, Artifacts: artifacts}).Run(ctx, req)
	_ = printJSON(result.State)
	if errors.Is(err, orchestration.ErrScopeExpansion) {
		return fmt.Errorf("scope change expands authorization; review the plan and rerun with --acknowledge-scope-expansion")
	}
	return err
}

type taskReader interface {
	GetTask(context.Context, domain.ID) (domain.Task, error)
}

func watchTaskControlsInterval(ctx context.Context, store taskReader, taskID domain.ID, controls *workflow.Controls, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			task, err := store.GetTask(ctx, taskID)
			if err != nil {
				slog.Warn("workflow task control refresh failed", "task_id", taskID, "error", err)
				continue
			}
			switch task.Status {
			case domain.TaskCancelled:
				controls.Cancel()
				return
			case domain.TaskPaused:
				controls.Pause()
			case domain.TaskRunning:
				controls.Resume()
			}
		}
	}
}

func runCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("run show|retry <run-id>")
	}
	if args[0] == "retry" {
		forward := append([]string{"--resume", args[1]}, args[2:]...)
		return workflowRun(ctx, cfg, providers.Registry(cfg), forward)
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	switch args[0] {
	case "show":
		r, err := s.GetWorkflowRun(ctx, domain.ID(args[1]))
		if err != nil {
			return err
		}
		return printJSON(r)
	default:
		return fmt.Errorf("unknown run command")
	}
}
func approvalCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("approvals requires list, approve, or reject")
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	switch args[0] {
	case "list":
		v, err := s.ListApprovals(ctx)
		if err != nil {
			return err
		}
		return printJSON(v)
	case "approve", "reject":
		if len(args) < 2 {
			return fmt.Errorf("approvals %s <approval-id> [actor]", args[0])
		}
		actor := "human"
		if len(args) > 2 {
			actor = args[2]
		}
		decision := map[string]string{"approve": "approved", "reject": "rejected"}[args[0]]
		return s.DecideApproval(ctx, domain.ID(args[1]), decision, actor)
	default:
		return fmt.Errorf("unknown approvals command")
	}
}
func queueCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("queue requires pending, failed, or retry")
	}
	rdb := redisClient(cfg)
	defer rdb.Close()
	q := queue.New(rdb, cfg.Worker.ConsumerGroup, cfg.Worker.ConsumerName, cfg.Worker.MaxRetries, cfg.Worker.RetryBase)
	if err := q.EnsureGroup(ctx); err != nil {
		return err
	}
	switch args[0] {
	case "pending":
		p, err := q.Pending(ctx)
		if err != nil {
			return err
		}
		return printJSON(p)
	case "failed":
		v, err := q.DeadLetters(ctx, 100)
		if err != nil {
			return err
		}
		return printJSON(v)
	case "retry":
		if len(args) < 2 {
			return fmt.Errorf("queue retry <dead-letter-message-id>")
		}
		return q.RetryDeadLetter(ctx, args[1])
	default:
		return fmt.Errorf("unknown queue command")
	}
}
func reportCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) < 2 || args[0] != "changes" {
		return fmt.Errorf("report changes <program-id>")
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	v, err := s.LatestChanges(ctx, domain.ID(args[1]))
	if err != nil {
		return err
	}
	fmt.Println(string(v))
	return nil
}

func scheduleCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("schedule requires create, list, show, update, enable, disable, run-now, executions, or resume")
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("schedule create", flag.ContinueOnError)
		programID := fs.String("program-id", "", "program UUID")
		name := fs.String("name", "", "schedule name")
		workflowName := fs.String("workflow", workflows.ContinuousName, "workflow name")
		cronExpr := fs.String("cron", "", "five-field cron expression")
		timezone := fs.String("timezone", "UTC", "IANA timezone")
		objective := fs.String("objective", "", "scheduled objective")
		actor := fs.String("created-by", "cli", "creating actor")
		headless := fs.Bool("headless", cfg.Recon.Headless, "enable policy-approved headless mode")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *programID == "" || strings.TrimSpace(*name) == "" || strings.TrimSpace(*objective) == "" {
			return fmt.Errorf("--program-id, --name, and --objective are required")
		}
		now := time.Now().UTC()
		item := domain.Schedule{ID: domain.NewID(), ProgramID: domain.ID(*programID), Name: *name, WorkflowName: *workflowName, Objective: *objective, CronExpression: *cronExpr, Timezone: *timezone, Enabled: true, Headless: *headless, CreatedBy: *actor, CreatedAt: now, UpdatedAt: now}
		item, err = (schedulecron.ScheduleValidator{Programs: s, Registry: providers.Registry(cfg), ScopeRoot: cfg.Scope.Root}).Validate(ctx, item, now)
		if err != nil {
			return err
		}
		if err := s.CreateSchedule(ctx, item); err != nil {
			return err
		}
		return printJSON(item)
	case "list":
		fs := flag.NewFlagSet("schedule list", flag.ContinueOnError)
		programID := fs.String("program-id", "", "program UUID")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		items, err := s.ListSchedules(ctx, domain.ID(*programID))
		if err != nil {
			return err
		}
		return printJSON(items)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("schedule show <schedule-id>")
		}
		item, err := s.GetSchedule(ctx, domain.ID(args[1]))
		if err != nil {
			return err
		}
		return printJSON(item)
	case "update":
		if len(args) < 2 {
			return fmt.Errorf("schedule update <schedule-id> [flags]")
		}
		item, err := s.GetSchedule(ctx, domain.ID(args[1]))
		if err != nil {
			return err
		}
		fs := flag.NewFlagSet("schedule update", flag.ContinueOnError)
		name := fs.String("name", item.Name, "schedule name")
		workflowName := fs.String("workflow", item.WorkflowName, "workflow name")
		objective := fs.String("objective", item.Objective, "objective")
		cronExpr := fs.String("cron", item.CronExpression, "five-field cron")
		timezone := fs.String("timezone", item.Timezone, "IANA timezone")
		headless := fs.Bool("headless", item.Headless, "headless mode")
		actor := fs.String("actor", "cli", "actor")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		item.Name, item.WorkflowName, item.Objective, item.CronExpression, item.Timezone, item.Headless = *name, *workflowName, *objective, *cronExpr, *timezone, *headless
		item, err = (schedulecron.ScheduleValidator{Programs: s, Registry: providers.Registry(cfg), ScopeRoot: cfg.Scope.Root}).Validate(ctx, item, time.Now())
		if err != nil {
			return err
		}
		if err := s.UpdateSchedule(ctx, item, *actor); err != nil {
			return err
		}
		return printJSON(item)
	case "enable", "disable":
		if len(args) < 2 {
			return fmt.Errorf("schedule %s <schedule-id>", args[0])
		}
		return s.SetScheduleEnabled(ctx, domain.ID(args[1]), args[0] == "enable", "cli")
	case "run-now":
		if len(args) < 2 {
			return fmt.Errorf("schedule run-now <schedule-id>")
		}
		item, err := s.EnqueueRunNow(ctx, domain.ID(args[1]), "cli")
		if err != nil {
			return err
		}
		return printJSON(item)
	case "executions":
		fs := flag.NewFlagSet("schedule executions", flag.ContinueOnError)
		scheduleID := fs.String("schedule-id", "", "schedule UUID")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		items, err := s.ListScheduledExecutions(ctx, domain.ID(*scheduleID), 100)
		if err != nil {
			return err
		}
		return printJSON(items)
	case "resume":
		if len(args) < 2 {
			return fmt.Errorf("schedule resume <scheduled-execution-id>")
		}
		return s.RequestScheduledExecutionResume(ctx, domain.ID(args[1]), "cli")
	default:
		return fmt.Errorf("unknown schedule command %q", args[0])
	}
}

func changesCommand(ctx context.Context, cfg config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("changes requires list or review")
	}
	s, err := readyStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("changes list", flag.ContinueOnError)
		programID := fs.String("program-id", "", "program UUID")
		all := fs.Bool("all", false, "include reviewed items")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *programID == "" {
			return fmt.Errorf("--program-id is required")
		}
		items, err := s.ListChangeItems(ctx, domain.ID(*programID), *all, 100)
		if err != nil {
			return err
		}
		return printJSON(items)
	case "review":
		if len(args) < 2 {
			return fmt.Errorf("changes review <change-id> --disposition <value> --note <note> --actor <actor>")
		}
		fs := flag.NewFlagSet("changes review", flag.ContinueOnError)
		disposition := fs.String("disposition", "", "review disposition")
		note := fs.String("note", "", "safe review note")
		actor := fs.String("actor", "human", "reviewing actor")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		return s.ReviewChangeItem(ctx, domain.ID(args[1]), domain.ChangeReviewDisposition(*disposition), *note, *actor)
	default:
		return fmt.Errorf("unknown changes command %q", args[0])
	}
}
func redisClient(cfg config.Config) *redis.Client {
	opts := &redis.Options{Addr: cfg.Redis.Address, Username: cfg.Redis.Username, Password: cfg.Redis.Password, DB: cfg.Redis.DB, DialTimeout: 5 * time.Second, ReadTimeout: cfg.Worker.ReadBlock + time.Second, WriteTimeout: 5 * time.Second}
	if cfg.Redis.TLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return redis.NewClient(opts)
}
