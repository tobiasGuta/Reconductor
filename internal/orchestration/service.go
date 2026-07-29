package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/budget"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/execution"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
	"github.com/tobiasGuta/Reconductor/internal/workflows"
)

var ErrScopeExpansion = errors.New("scope change expands authorization")

type WorkflowRequest struct {
	ProgramID                 domain.ID
	WorkflowName              string
	Objective                 string
	RequestedBy               string
	ScopeReference            string
	ScheduleReference         *string
	ExistingTaskID            domain.ID
	ResumeRunID               domain.ID
	Headless                  bool
	AcknowledgeScopeExpansion bool
	ManualDiscoveryRoots      []targeting.ManualDiscoveryRoot
	ApproveModerate           bool
}

type WorkflowResult struct {
	Task        domain.Task
	State       *workflow.State
	ScopeChange domain.ScopeChange
}

type Service struct {
	Config   config.Config
	Store    *database.Store
	Registry *capability.Registry
}

func (s Service) Run(ctx context.Context, req WorkflowRequest) (WorkflowResult, error) {
	if req.ProgramID == "" {
		return WorkflowResult{}, fmt.Errorf("program id is required")
	}
	program, err := s.Store.GetProgram(ctx, req.ProgramID)
	if err != nil {
		return WorkflowResult{}, err
	}
	if req.ScopeReference == "" {
		req.ScopeReference = program.ScopeReference
	}
	if req.WorkflowName == "" {
		req.WorkflowName = workflows.ContinuousName
	}
	if req.RequestedBy == "" {
		req.RequestedBy = "cli"
	}
	sc, err := platformscope.LoadBurp(req.ScopeReference)
	if err != nil {
		return WorkflowResult{}, fmt.Errorf("load scope: %w", err)
	}
	plan, err := targeting.Plan(sc, req.ManualDiscoveryRoots)
	if err != nil {
		return WorkflowResult{}, err
	}
	if !plan.HasExecutableTargets() {
		return WorkflowResult{}, fmt.Errorf("target plan has no executable authorized targets")
	}
	snapshot := scopeSnapshot(req.ProgramID, req.ScopeReference, sc, plan)
	change, err := s.Store.CheckAndRecordScopeSnapshot(ctx, snapshot, req.AcknowledgeScopeExpansion, req.RequestedBy)
	if err != nil {
		return WorkflowResult{ScopeChange: change}, err
	}
	if change.ExpandsScope && !change.Acknowledged {
		return WorkflowResult{ScopeChange: change}, ErrScopeExpansion
	}
	def, err := workflows.Build(req.WorkflowName, plan, req.Headless)
	if err != nil {
		return WorkflowResult{ScopeChange: change}, err
	}
	if err := workflow.Validate(def, s.Registry); err != nil {
		return WorkflowResult{ScopeChange: change}, err
	}
	defJSON, _ := json.Marshal(def)
	if err := s.Store.CreateWorkflowDefinition(ctx, def.ID, def.Name, def.Version, def.Description, defJSON); err != nil {
		return WorkflowResult{ScopeChange: change}, err
	}
	fileStore := workflow.FileStore{Root: s.Config.Scheduler.WorkflowStateRoot}
	var state *workflow.State
	if req.ResumeRunID != "" {
		state, err = fileStore.Load(string(req.ResumeRunID))
		if err != nil {
			return WorkflowResult{ScopeChange: change}, err
		}
	}
	task, err := s.resolveTask(ctx, req, def, state)
	if err != nil {
		return WorkflowResult{ScopeChange: change}, err
	}
	if task.ProgramID != req.ProgramID {
		return WorkflowResult{Task: task, ScopeChange: change}, fmt.Errorf("task %s belongs to program %s, not %s", task.ID, task.ProgramID, req.ProgramID)
	}
	engine, err := s.engine(ctx, task, sc, req.Headless, fileStore)
	if err != nil {
		return WorkflowResult{Task: task, ScopeChange: change}, err
	}
	approvedByRecord, err := s.resumeApproval(ctx, state)
	if err != nil {
		return WorkflowResult{Task: task, State: state, ScopeChange: change}, err
	}
	if req.ApproveModerate || approvedByRecord {
		engine.Approval = func(context.Context, workflow.Step, policy.Risk) (bool, error) { return true, nil }
	}
	controls := &workflow.Controls{}
	if task.Status == domain.TaskCancelled {
		controls.Cancel()
	} else if task.Status == domain.TaskPaused {
		controls.Resume()
	}
	watchCtx, stopWatching := context.WithCancel(ctx)
	defer stopWatching()
	go WatchTaskControls(watchCtx, s.Store, task.ID, controls)
	state, runErr := engine.Run(ctx, def, state, task, controls)
	if state != nil {
		status := map[domain.RunStatus]domain.TaskStatus{domain.RunCompleted: domain.TaskCompleted, domain.RunPaused: domain.TaskPaused, domain.RunFailed: domain.TaskFailed, domain.RunCancelled: domain.TaskCancelled}[state.Run.Status]
		if status != "" {
			_ = s.Store.SetTaskStatus(context.WithoutCancel(ctx), task.ID, status, "")
		}
	}
	return WorkflowResult{Task: task, State: state, ScopeChange: change}, runErr
}

func (s Service) resolveTask(ctx context.Context, req WorkflowRequest, def workflow.Definition, state *workflow.State) (domain.Task, error) {
	var task domain.Task
	var err error
	if state != nil {
		task, err = s.Store.GetTask(ctx, state.Run.TaskID)
		if err != nil {
			return domain.Task{}, err
		}
		if task.Status == domain.TaskPaused {
			_ = s.Store.SetTaskStatus(ctx, task.ID, domain.TaskRunning, "")
			task.Status = domain.TaskRunning
		}
		return task, nil
	}
	if req.ExistingTaskID != "" {
		return s.Store.GetTask(ctx, req.ExistingTaskID)
	}
	now := time.Now().UTC()
	objective := req.Objective
	if objective == "" {
		objective = "continuous authorized web reconnaissance"
	}
	task = domain.Task{ID: domain.NewID(), ProgramID: req.ProgramID, Objective: objective, WorkflowDefinitionID: def.ID, Status: domain.TaskRunning, RequestedBy: req.RequestedBy, ScheduleReference: req.ScheduleReference, CreatedAt: now, UpdatedAt: now}
	if err := s.Store.CreateTask(ctx, task); err != nil {
		return domain.Task{}, err
	}
	return task, nil
}

func (s Service) engine(ctx context.Context, task domain.Task, sc platformscope.Scope, headless bool, fileStore workflow.FileStore) (workflow.Engine, error) {
	redactor := redaction.New(s.Config.Logging.SecretNames...)
	artifacts, err := artifact.NewLocal(s.Config.ArtifactStorage.Root, redactor)
	if err != nil {
		return workflow.Engine{}, err
	}
	if _, err := artifact.PurgeExpired(ctx, s.Store, artifacts, 1000); err != nil {
		return workflow.Engine{}, fmt.Errorf("purge expired artifacts: %w", err)
	}
	pol := policy.Policy{ID: "runtime", AllowedCapabilities: s.Registry.Names(), RateLimit: s.Config.Policy.DefaultRateLimit, Concurrency: s.Config.Policy.DefaultConcurrency, ProviderConcurrency: s.Config.Policy.DefaultProviderConcurrency, HostConcurrency: s.Config.Policy.DefaultHostConcurrency, ScanWindows: s.Config.Policy.ScanWindows, AllowedHTTPMethods: s.Config.Policy.AllowedMethods, AuthenticationUsage: s.Config.Policy.AuthenticationUsage, HeadlessBrowser: headless, DirectoryFuzzing: s.Config.Policy.DirectoryFuzzing, MaximumPayloadSize: s.Config.Policy.MaxPayloadBytes, FollowRedirects: s.Config.Policy.FollowRedirects, CrossOrigin: s.Config.Policy.CrossOrigin, IntrusiveChecks: s.Config.Policy.IntrusiveChecks, ArtifactRetention: s.Config.Policy.ArtifactRetention, ExcludedTemplateTags: s.Config.Nuclei.ExcludeTags}
	maxParallel := policy.ProgramParallelism(pol)
	limiter := budget.NewLocal(budget.Limits{Program: maxParallel, Provider: pol.ProviderConcurrency, Host: pol.HostConcurrency})
	return workflow.Engine{Registry: s.Registry, Executor: execution.Service{Registry: s.Registry, Store: s.Store, Artifacts: artifacts, ProgramID: task.ProgramID}, Persister: database.WorkflowPersister{Store: s.Store, File: fileStore}, Policy: pol, Scope: sc, Budget: limiter, MaxParallel: maxParallel}, nil
}

func (s Service) resumeApproval(ctx context.Context, state *workflow.State) (bool, error) {
	if state == nil {
		return false, nil
	}
	approved := false
	for _, ss := range state.Steps {
		if ss.Run.Status != domain.StepAwaitingApproval {
			continue
		}
		decision, err := s.Store.StepApprovalDecision(ctx, ss.Run.ID)
		if err != nil {
			return false, err
		}
		if decision == "rejected" {
			return false, fmt.Errorf("approval for step %s was rejected", ss.Run.StepDefinitionID)
		}
		approved = approved || decision == "approved"
	}
	return approved, nil
}

type TaskReader interface {
	GetTask(context.Context, domain.ID) (domain.Task, error)
}

func WatchTaskControls(ctx context.Context, store TaskReader, taskID domain.ID, controls *workflow.Controls) {
	ticker := time.NewTicker(500 * time.Millisecond)
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
			}
		}
	}
}

func scopeSnapshot(programID domain.ID, reference string, sc platformscope.Scope, plan targeting.TargetPlan) domain.ScopeSnapshot {
	warnings, _ := json.Marshal(plan.Warnings)
	planJSON, _ := json.Marshal(plan)
	return domain.ScopeSnapshot{ID: domain.NewID(), ProgramID: programID, ScopeReference: reference, ScopeDigest: sc.Digest(), IncludeRuleDigests: sc.IncludeDigests(), ExcludeRuleDigests: sc.ExcludeDigests(), TargetPlanDigest: plan.Digest, PlanningWarnings: warnings, TargetPlan: planJSON, AddedIncludeDigests: []string{}, RemovedIncludeDigests: []string{}, AddedExcludeDigests: []string{}, RemovedExcludeDigests: []string{}, CreatedAt: time.Now().UTC()}
}
