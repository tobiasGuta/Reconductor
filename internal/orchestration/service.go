package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
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

type Lifecycle interface {
	TaskCreated(context.Context, domain.Task) error
	WorkflowCreated(context.Context, domain.Task, domain.WorkflowRun, domain.ID) error
}

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
	Lifecycle                 Lifecycle
}

type WorkflowResult struct {
	Task        domain.Task
	State       *workflow.State
	ScopeChange domain.ScopeChange
}

type Service struct {
	Config          config.Config
	Store           *database.Store
	Registry        *capability.Registry
	ArtifactFactory func(string, *redaction.Redactor) (*artifact.Local, error)
}

func (s Service) Run(ctx context.Context, req WorkflowRequest) (WorkflowResult, error) {
	fileStore := workflow.FileStore{Root: s.Config.Scheduler.WorkflowStateRoot}
	var state *workflow.State
	var task domain.Task
	var def workflow.Definition
	var template workflow.Template
	var err error
	if req.ResumeRunID != "" {
		state, err = s.Store.LoadWorkflowState(ctx, req.ResumeRunID)
		if err != nil {
			return WorkflowResult{}, err
		}
		if state.Run.MaterializedDefinition == nil || state.Run.MaterializationDigest == "" || state.Run.OriginalScopeVersionID == nil {
			return WorkflowResult{State: state}, &workflow.RunLineageError{Cause: workflow.ErrWorkflowResumeUnavailable, TaskID: state.Run.TaskID, RunID: state.Run.ID, Detail: "legacy run has no immutable materialization"}
		}
		def, err = workflow.VerifyMaterialization(state.Run.MaterializedDefinition, state.Run.MaterializationDigest)
		if err != nil {
			return WorkflowResult{State: state}, err
		}
		if def.ID != state.Run.WorkflowDefinitionID || def.Version != state.Run.WorkflowVersion {
			return WorkflowResult{State: state}, fmt.Errorf("%w: DB materialization identity differs from WorkflowRun", workflow.ErrWorkflowCheckpointConflict)
		}
		task, err = s.Store.GetTask(ctx, state.Run.TaskID)
		if err != nil {
			return WorkflowResult{State: state}, err
		}
		if task.WorkflowDefinitionID != state.Run.WorkflowDefinitionID {
			return WorkflowResult{Task: task, State: state}, fmt.Errorf("%w: task and run template identity differ", workflow.ErrWorkflowCheckpointConflict)
		}
		template, err = s.Store.WorkflowTemplate(ctx, task.WorkflowDefinitionID)
		if err != nil {
			return WorkflowResult{Task: task, State: state}, err
		}
		if template.ID != def.ID || template.Name != def.Name || template.Version != def.Version || template.Materializer != def.Materializer {
			return WorkflowResult{Task: task, State: state}, fmt.Errorf("%w: materialization and template release identity differ", workflow.ErrWorkflowCheckpointConflict)
		}
		if !workflows.SupportsRelease(template.ID, template.Name, template.Version, template.Materializer) {
			return WorkflowResult{Task: task, State: state}, fmt.Errorf("%w: unsupported workflow template release %s %s (%s)", workflow.ErrWorkflowCheckpointConflict, template.Name, template.Version, template.Materializer)
		}
		if req.ProgramID == "" {
			req.ProgramID = task.ProgramID
		}
		req.WorkflowName = template.Name
	}
	if req.ProgramID == "" {
		return WorkflowResult{}, fmt.Errorf("program id is required")
	}
	program, err := s.Store.GetProgram(ctx, req.ProgramID)
	if err != nil {
		return WorkflowResult{}, err
	}
	if task.ID != "" && task.ProgramID != req.ProgramID {
		return WorkflowResult{Task: task, State: state}, fmt.Errorf("task %s belongs to program %s, not %s", task.ID, task.ProgramID, req.ProgramID)
	}
	if state != nil {
		if err := workflow.Validate(def, s.Registry); err != nil {
			return WorkflowResult{Task: task, State: state}, err
		}
		state, err = reconcileCheckpoint(ctx, fileStore, state)
		if err != nil {
			return WorkflowResult{Task: task, State: state}, err
		}
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
	sc, err := s.loadScope(req.ScopeReference)
	if err != nil {
		return WorkflowResult{}, fmt.Errorf("load scope: %w", err)
	}
	plan, err := targeting.Plan(sc, req.ManualDiscoveryRoots)
	if err != nil {
		return WorkflowResult{}, err
	}
	pinnedPlan := plan
	if state != nil {
		pinnedPlan, err = s.Store.ScopeTargetPlan(ctx, *state.Run.OriginalScopeVersionID, req.ProgramID)
		if err != nil {
			return WorkflowResult{Task: task, State: state}, err
		}
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
	if state == nil {
		template, err = workflows.CurrentTemplate(req.WorkflowName)
		if err != nil {
			return WorkflowResult{ScopeChange: change}, err
		}
		if err := s.Store.EnsureWorkflowTemplate(ctx, template); err != nil {
			return WorkflowResult{ScopeChange: change}, err
		}
		def, err = workflows.Build(template.Name, plan, req.Headless)
		if err != nil {
			return WorkflowResult{ScopeChange: change}, err
		}
		if !workflows.SupportsRelease(def.ID, def.Name, def.Version, def.Materializer) || def.ID != template.ID || def.Materializer != template.Materializer {
			return WorkflowResult{ScopeChange: change}, fmt.Errorf("%w: built workflow release identity is unsupported", workflow.ErrWorkflowCheckpointConflict)
		}
		if err := workflow.Validate(def, s.Registry); err != nil {
			return WorkflowResult{ScopeChange: change}, err
		}
		task, err = s.resolveTask(ctx, req, def, nil)
		if err != nil {
			return WorkflowResult{ScopeChange: change}, err
		}
		if task.WorkflowDefinitionID != template.ID {
			return WorkflowResult{Task: task, ScopeChange: change}, &workflow.RunLineageError{Cause: workflow.ErrTaskWorkflowTemplateUnavailable, TaskID: task.ID, Detail: fmt.Sprintf("task pins %s; current %s %s is %s", task.WorkflowDefinitionID, template.Name, template.Version, template.ID)}
		}
	}
	if task.ProgramID != req.ProgramID {
		return WorkflowResult{Task: task, ScopeChange: change}, fmt.Errorf("task %s belongs to program %s, not %s", task.ID, task.ProgramID, req.ProgramID)
	}
	lifecycleScopeVersionID := change.ScopeVersionID
	if state != nil && state.Run.OriginalScopeVersionID != nil {
		lifecycleScopeVersionID = *state.Run.OriginalScopeVersionID
	}
	runtimeScope := targeting.WithDiscoveryRoots(sc, pinnedPlan.DiscoveryRoots, plan.DiscoveryRoots)
	engine, err := s.engine(ctx, task, runtimeScope, req.Headless, fileStore, req.Lifecycle, lifecycleScopeVersionID)
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
	if state != nil && task.Status == domain.TaskPaused {
		if err := s.Store.SetTaskStatus(ctx, task.ID, domain.TaskRunning, ""); err != nil {
			return WorkflowResult{Task: task, State: state, ScopeChange: change}, err
		}
		task.Status = domain.TaskRunning
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
	if state != nil && !database.IsScheduledExecutionFenceError(runErr) {
		status := map[domain.RunStatus]domain.TaskStatus{domain.RunCompleted: domain.TaskCompleted, domain.RunPaused: domain.TaskPaused, domain.RunFailed: domain.TaskFailed, domain.RunCancelled: domain.TaskCancelled}[state.Run.Status]
		if status != "" {
			_ = s.Store.SetTaskStatusFromWorkflow(context.WithoutCancel(ctx), task.ID, status)
		}
	}
	return WorkflowResult{Task: task, State: state, ScopeChange: change}, runErr
}

type checkpointStore interface {
	Load(string) (*workflow.State, error)
	Save(context.Context, *workflow.State) error
}

func reconcileCheckpoint(ctx context.Context, fileStore checkpointStore, databaseState *workflow.State) (*workflow.State, error) {
	definition, err := workflow.VerifyMaterialization(databaseState.Run.MaterializedDefinition, databaseState.Run.MaterializationDigest)
	if err != nil {
		return databaseState, err
	}
	if definition.ID != databaseState.Run.WorkflowDefinitionID || definition.Version != databaseState.Run.WorkflowVersion || databaseState.Run.OriginalScopeVersionID == nil {
		return databaseState, fmt.Errorf("%w: database materialization identity differs from WorkflowRun", workflow.ErrWorkflowCheckpointConflict)
	}
	checkpoint, err := fileStore.Load(string(databaseState.Run.ID))
	if err == nil {
		if err := verifyCheckpointIdentity(databaseState, checkpoint); err != nil {
			return databaseState, err
		}
		databaseState.Events = append([]workflow.Event(nil), checkpoint.Events...)
		return databaseState, nil
	}
	if !os.IsNotExist(err) {
		return databaseState, classifyCheckpointLoadError(databaseState, err)
	}
	if terminalRun(databaseState.Run.Status) || databaseState.Run.StartedAt == nil || len(databaseState.Steps) != 0 {
		return databaseState, &workflow.RunLineageError{Cause: workflow.ErrWorkflowCheckpointUnavailable, TaskID: databaseState.Run.TaskID, RunID: databaseState.Run.ID, Detail: "missing checkpoint is not a reconstructable initial run"}
	}
	databaseState.Events = []workflow.Event{{At: *databaseState.Run.StartedAt, Type: "workflow_started", Message: "workflow execution started"}}
	if err := fileStore.Save(ctx, databaseState); err != nil {
		return databaseState, &workflow.RunLineageError{Cause: workflow.ErrWorkflowCheckpointUnavailable, TaskID: databaseState.Run.TaskID, RunID: databaseState.Run.ID, Detail: err.Error()}
	}
	checkpoint, err = fileStore.Load(string(databaseState.Run.ID))
	if err != nil {
		return databaseState, classifyCheckpointLoadError(databaseState, err)
	}
	if err := verifyCheckpointIdentity(databaseState, checkpoint); err != nil {
		return databaseState, err
	}
	return databaseState, nil
}

func classifyCheckpointLoadError(databaseState *workflow.State, err error) error {
	var decodeError *workflow.CheckpointDecodeError
	if errors.As(err, &decodeError) {
		return fmt.Errorf("%w: malformed checkpoint for run %s", workflow.ErrWorkflowCheckpointConflict, databaseState.Run.ID)
	}
	return &workflow.RunLineageError{Cause: workflow.ErrWorkflowCheckpointUnavailable, TaskID: databaseState.Run.TaskID, RunID: databaseState.Run.ID, Detail: err.Error()}
}

func verifyCheckpointIdentity(databaseState, checkpoint *workflow.State) error {
	dbRun, fileRun := databaseState.Run, checkpoint.Run
	if fileRun.ID != dbRun.ID || fileRun.TaskID != dbRun.TaskID || fileRun.WorkflowDefinitionID != dbRun.WorkflowDefinitionID || fileRun.WorkflowVersion != dbRun.WorkflowVersion || fileRun.MaterializationDigest != dbRun.MaterializationDigest || fileRun.OriginalScopeVersionID == nil || dbRun.OriginalScopeVersionID == nil || *fileRun.OriginalScopeVersionID != *dbRun.OriginalScopeVersionID {
		return fmt.Errorf("%w: checkpoint run lineage differs from database", workflow.ErrWorkflowCheckpointConflict)
	}
	fileDefinition, err := workflow.VerifyMaterialization(fileRun.MaterializedDefinition, fileRun.MaterializationDigest)
	if err != nil {
		return err
	}
	dbDefinition, err := workflow.VerifyMaterialization(dbRun.MaterializedDefinition, dbRun.MaterializationDigest)
	if err != nil {
		return err
	}
	if fileDefinition.ID != dbDefinition.ID || fileDefinition.Name != dbDefinition.Name || fileDefinition.Version != dbDefinition.Version || fileDefinition.Materializer != dbDefinition.Materializer {
		return fmt.Errorf("%w: checkpoint materialization identity differs from database", workflow.ErrWorkflowCheckpointConflict)
	}
	if len(checkpoint.Steps) != len(databaseState.Steps) {
		return fmt.Errorf("%w: checkpoint StepRun set differs from database", workflow.ErrWorkflowCheckpointConflict)
	}
	for stepID, databaseStep := range databaseState.Steps {
		fileStep, ok := checkpoint.Steps[stepID]
		if !ok || fileStep.Run.ID != databaseStep.Run.ID || fileStep.Run.WorkflowRunID != dbRun.ID || fileStep.Run.StepDefinitionID != stepID || fileStep.Run.Capability != databaseStep.Run.Capability || fileStep.Run.IdempotencyKey != databaseStep.Run.IdempotencyKey {
			return fmt.Errorf("%w: checkpoint step %s lineage differs from database", workflow.ErrWorkflowCheckpointConflict, stepID)
		}
	}
	return nil
}

func terminalRun(status domain.RunStatus) bool {
	return status == domain.RunCompleted || status == domain.RunFailed || status == domain.RunCancelled
}

func (s Service) loadScope(reference string) (platformscope.Scope, error) {
	return platformscope.LoadBurpReference(reference, s.Config.Scope.Root)
}

func (s Service) resolveTask(ctx context.Context, req WorkflowRequest, def workflow.Definition, state *workflow.State) (domain.Task, error) {
	var task domain.Task
	var err error
	if state != nil {
		task, err = s.Store.GetTask(ctx, state.Run.TaskID)
		if err != nil {
			return domain.Task{}, err
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
	task = domain.Task{ID: domain.NewID(), ProgramID: req.ProgramID, Objective: objective, WorkflowDefinitionID: def.ID, Status: domain.TaskPending, RequestedBy: req.RequestedBy, ScheduleReference: req.ScheduleReference, CreatedAt: now, UpdatedAt: now}
	if req.Lifecycle == nil {
		if err := s.Store.CreateTask(ctx, task); err != nil {
			return domain.Task{}, err
		}
		return task, nil
	}
	if err := s.Store.CreateTaskWithLifecycle(ctx, task, req.Lifecycle.TaskCreated); err != nil {
		return domain.Task{}, err
	}
	return task, nil
}

func (s Service) engine(ctx context.Context, task domain.Task, sc capability.Scope, headless bool, fileStore workflow.FileStore, lifecycle Lifecycle, scopeVersionID domain.ID) (workflow.Engine, error) {
	redactor := redaction.New(s.Config.Logging.SecretNames...)
	artifactFactory := s.ArtifactFactory
	if artifactFactory == nil {
		artifactFactory = artifact.NewLocal
	}
	artifacts, err := artifactFactory(s.Config.ArtifactStorage.Root, redactor)
	if err != nil {
		return workflow.Engine{}, err
	}
	if _, err := artifact.PurgeExpired(ctx, s.Store, artifacts, 1000); err != nil {
		return workflow.Engine{}, fmt.Errorf("purge expired artifacts: %w", err)
	}
	pol := policy.Policy{ID: "runtime", AllowedCapabilities: s.Registry.Names(), RateLimit: s.Config.Policy.DefaultRateLimit, Concurrency: s.Config.Policy.DefaultConcurrency, ProviderConcurrency: s.Config.Policy.DefaultProviderConcurrency, HostConcurrency: s.Config.Policy.DefaultHostConcurrency, ScanWindows: s.Config.Policy.ScanWindows, AllowedHTTPMethods: s.Config.Policy.AllowedMethods, AuthenticationUsage: s.Config.Policy.AuthenticationUsage, HeadlessBrowser: headless, DirectoryFuzzing: s.Config.Policy.DirectoryFuzzing, MaximumPayloadSize: s.Config.Policy.MaxPayloadBytes, FollowRedirects: s.Config.Policy.FollowRedirects, CrossOrigin: s.Config.Policy.CrossOrigin, IntrusiveChecks: s.Config.Policy.IntrusiveChecks, ArtifactRetention: s.Config.Policy.ArtifactRetention, ExcludedTemplateTags: s.Config.Nuclei.ExcludeTags}
	maxParallel := policy.ProgramParallelism(pol)
	limiter := budget.NewLocal(budget.Limits{Program: maxParallel, Provider: pol.ProviderConcurrency, Host: pol.HostConcurrency})
	persister := database.WorkflowPersister{Store: s.Store, File: fileStore}
	if lifecycle != nil {
		persister.Lifecycle = func(ctx context.Context, state *workflow.State) error {
			return lifecycle.WorkflowCreated(ctx, task, state.Run, scopeVersionID)
		}
	}
	return workflow.Engine{Registry: s.Registry, Executor: execution.Service{Registry: s.Registry, Store: s.Store, Artifacts: artifacts, ProgramID: task.ProgramID}, Persister: persister, Policy: pol, Scope: sc, Budget: limiter, MaxParallel: maxParallel, OriginalScopeVersionID: scopeVersionID}, nil
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
