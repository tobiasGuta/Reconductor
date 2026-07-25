package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/budget"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
)

type Definition struct {
	ID                        domain.ID       `json:"id"`
	Name                      string          `json:"name"`
	Version                   string          `json:"version"`
	Description               string          `json:"description"`
	Steps                     []Step          `json:"steps"`
	DefaultPolicyRequirements json.RawMessage `json:"default_policy_requirements"`
	CreatedAt                 time.Time       `json:"created_at"`
}
type Step struct {
	ID                 string            `json:"id"`
	Capability         string            `json:"capability"`
	Provider           string            `json:"provider,omitempty"`
	DependsOn          []string          `json:"depends_on,omitempty"`
	Condition          string            `json:"condition,omitempty"`
	Input              json.RawMessage   `json:"input"`
	Bindings           map[string]string `json:"bindings,omitempty"`
	Retry              RetryPolicy       `json:"retry"`
	Timeout            time.Duration     `json:"timeout"`
	ApprovalRequired   bool              `json:"approval_required,omitempty"`
	RerunOnInputChange bool              `json:"rerun_on_input_change,omitempty"`
}
type RetryPolicy struct {
	MaxAttempts int           `json:"max_attempts"`
	BaseDelay   time.Duration `json:"base_delay"`
}
type StepState struct {
	Run       domain.StepRun `json:"run"`
	InputHash string         `json:"input_hash"`
}
type State struct {
	Run    domain.WorkflowRun    `json:"run"`
	Steps  map[string]*StepState `json:"steps"`
	Events []Event               `json:"events"`
}
type Event struct {
	At      time.Time `json:"at"`
	Type    string    `json:"type"`
	StepID  string    `json:"step_id,omitempty"`
	Message string    `json:"message"`
}
type Executor interface {
	Execute(context.Context, capability.Request) (capability.Result, error)
}
type Persister interface {
	Save(context.Context, *State) error
}
type ApprovalFunc func(context.Context, Step, policy.Risk) (bool, error)
type Controls struct {
	mu                sync.RWMutex
	paused, cancelled bool
	cancelledCh       chan struct{}
}

func (c *Controls) Pause()  { c.mu.Lock(); defer c.mu.Unlock(); c.paused = true }
func (c *Controls) Resume() { c.mu.Lock(); defer c.mu.Unlock(); c.paused = false }
func (c *Controls) Cancel() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancelled {
		return
	}
	c.cancelled = true
	if c.cancelledCh == nil {
		c.cancelledCh = make(chan struct{})
	}
	close(c.cancelledCh)
}
func (c *Controls) state() (bool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.paused, c.cancelled
}
func (c *Controls) Done() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancelledCh == nil {
		c.cancelledCh = make(chan struct{})
		if c.cancelled {
			close(c.cancelledCh)
		}
	}
	return c.cancelledCh
}

type Engine struct {
	Registry  *capability.Registry
	Executor  Executor
	Persister Persister
	Approval  ApprovalFunc
	Policy    policy.Policy
	Scope     capability.Scope
	Budget    budget.Limiter
	// MaxParallel is the maximum number of ready steps in one deterministic
	// execution wave. Zero preserves the legacy single-step behavior.
	MaxParallel int
}

func Validate(d Definition, r *capability.Registry) error {
	if d.Name == "" || d.Version == "" {
		return fmt.Errorf("workflow name and version are required")
	}
	byID := map[string]Step{}
	for _, s := range d.Steps {
		if s.ID == "" {
			return fmt.Errorf("step id is required")
		}
		if _, ok := byID[s.ID]; ok {
			return fmt.Errorf("duplicate step %q", s.ID)
		}
		if _, ok := r.Get(s.Capability); !ok {
			return fmt.Errorf("step %s uses unknown capability %q", s.ID, s.Capability)
		}
		if len(s.Input) == 0 || !json.Valid(s.Input) {
			return fmt.Errorf("step %s has invalid input JSON", s.ID)
		}
		if err := r.ValidateDefinitionInput(s.Capability, s.Input); err != nil {
			return fmt.Errorf("step %s input schema: %w", s.ID, err)
		}
		if s.Condition != "" && !strings.HasPrefix(s.Condition, "success:") && !strings.HasPrefix(s.Condition, "changed:") && !strings.HasPrefix(s.Condition, "nonempty:") {
			return fmt.Errorf("step %s has unsupported condition %q", s.ID, s.Condition)
		}
		byID[s.ID] = s
	}
	for _, s := range d.Steps {
		for _, dep := range s.DependsOn {
			if _, ok := byID[dep]; !ok {
				return fmt.Errorf("step %s depends on unknown step %s", s.ID, dep)
			}
		}
		for _, binding := range s.Bindings {
			parts := strings.Split(binding, ".")
			if len(parts) < 3 || parts[1] != "output" {
				return fmt.Errorf("step %s has unsupported binding %q", s.ID, binding)
			}
			if _, ok := byID[parts[0]]; !ok {
				return fmt.Errorf("step %s binding references unknown step %s", s.ID, parts[0])
			}
			if err := validateOutputPath(r, byID[parts[0]], parts[2]); err != nil {
				return fmt.Errorf("step %s binding %q: %w", s.ID, binding, err)
			}
		}
		if s.Condition != "" {
			_, reference, _ := strings.Cut(s.Condition, ":")
			parts := strings.Split(reference, ".")
			source := parts[0]
			if _, ok := byID[source]; !ok {
				return fmt.Errorf("step %s condition references unknown step %s", s.ID, source)
			}
			if len(parts) >= 3 && parts[1] == "output" {
				if err := validateOutputPath(r, byID[source], parts[2]); err != nil {
					return fmt.Errorf("step %s condition %q: %w", s.ID, s.Condition, err)
				}
			}
		}
	}
	visiting, visited := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return fmt.Errorf("cyclic dependency at step %s", id)
		}
		if visited[id] {
			return nil
		}
		visiting[id] = true
		for _, dep := range byID[id].DependsOn {
			if err := visit(dep); err != nil {
				return err
			}
		}
		visiting[id] = false
		visited[id] = true
		return nil
	}
	for id := range byID {
		if err := visit(id); err != nil {
			return err
		}
	}
	for _, step := range d.Steps {
		for _, binding := range step.Bindings {
			source := strings.Split(binding, ".")[0]
			if !transitivelyDependsOn(step.ID, source, byID) {
				return fmt.Errorf("step %s binding source %s must be a dependency", step.ID, source)
			}
		}
		if step.Condition != "" {
			_, reference, _ := strings.Cut(step.Condition, ":")
			source := strings.Split(reference, ".")[0]
			if !transitivelyDependsOn(step.ID, source, byID) {
				return fmt.Errorf("step %s condition source %s must be a dependency", step.ID, source)
			}
		}
	}
	return nil
}

func validateOutputPath(r *capability.Registry, source Step, field string) error {
	implementation, ok := r.Get(source.Capability)
	if !ok {
		return fmt.Errorf("source capability %q is not registered", source.Capability)
	}
	raw := implementation.Manifest().OutputSchema
	if len(raw) == 0 {
		return nil
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil || len(schema.Properties) == 0 {
		return nil
	}
	if _, ok := schema.Properties[field]; !ok {
		return fmt.Errorf("source capability %q does not declare output field %q", source.Capability, field)
	}
	return nil
}

func transitivelyDependsOn(stepID, sourceID string, definitions map[string]Step) bool {
	seen := map[string]bool{}
	var contains func(string) bool
	contains = func(id string) bool {
		if seen[id] {
			return false
		}
		seen[id] = true
		for _, dependency := range definitions[id].DependsOn {
			if dependency == sourceID || contains(dependency) {
				return true
			}
		}
		return false
	}
	return contains(stepID)
}
func (e *Engine) Run(ctx context.Context, d Definition, state *State, task domain.Task, controls *Controls) (*State, error) {
	if err := Validate(d, e.Registry); err != nil {
		return nil, err
	}
	if e.Executor == nil {
		e.Executor = e.Registry
	}
	if controls == nil {
		controls = &Controls{}
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-controls.Done():
			cancelRun()
		case <-ctx.Done():
			cancelRun()
		case <-watchDone:
		}
	}()
	defer func() {
		close(watchDone)
		cancelRun()
	}()

	now := time.Now().UTC()
	resuming := state != nil
	if state == nil {
		state = &State{Run: domain.WorkflowRun{ID: domain.NewID(), TaskID: task.ID, WorkflowDefinitionID: d.ID, WorkflowVersion: d.Version, Status: domain.RunRunning, StartedAt: &now, TriggerSource: task.RequestedBy, Summary: json.RawMessage(`{}`)}, Steps: map[string]*StepState{}}
		state.Events = append(state.Events, Event{now, "workflow_started", "", "workflow execution started"})
	} else {
		state.Run.Status = domain.RunRunning
		state.Run.CompletedAt = nil
		state.Events = append(state.Events, Event{now, "workflow_resumed", "", "workflow execution resumed"})
	}
	if err := e.save(runCtx, state); err != nil {
		return state, err
	}
	ordered := topological(d)
	rank := make(map[string]int, len(ordered))
	finished := make(map[string]bool, len(ordered))
	blockedApprovals := make(map[string]bool)
	for index, step := range ordered {
		rank[step.ID] = index
		if existing := state.Steps[step.ID]; existing != nil && existing.Run.Status == domain.StepSucceeded && !step.RerunOnInputChange {
			finished[step.ID] = true
			if resuming {
				e.event(state, "step_resumed", step.ID, "previous successful result retained")
			}
		}
	}
	maxParallel := e.MaxParallel
	if maxParallel < 1 {
		maxParallel = 1
	}

	for len(finished) < len(ordered) {
		paused, cancelled := controls.state()
		if cancelled {
			return e.terminal(runCtx, state, domain.RunCancelled, "workflow_cancelled")
		}
		if ctx.Err() != nil {
			terminal, terminalErr := e.terminal(runCtx, state, domain.RunCancelled, "workflow_cancelled")
			return terminal, errors.Join(ctx.Err(), terminalErr)
		}
		if paused {
			state.Run.Status = domain.RunPaused
			e.event(state, "workflow_paused", "", "pause requested")
			_ = e.save(runCtx, state)
			return state, nil
		}

		ready := make([]Step, 0, len(ordered))
		for _, step := range ordered {
			if finished[step.ID] || blockedApprovals[step.ID] {
				continue
			}
			if dependenciesSucceeded(step, state) {
				ready = append(ready, step)
			}
		}
		if len(ready) == 0 {
			if len(blockedApprovals) > 0 {
				state.Run.Status = domain.RunPaused
				e.event(state, "workflow_paused", "", "approval is required before execution can continue")
				_ = e.save(runCtx, state)
				return state, nil
			}
			return e.fail(runCtx, state, "", "dependency", errors.New("workflow has no runnable steps"))
		}

		plans := make([]stepPlan, 0, maxParallel)
		stateChanged := false
		for _, step := range ready {
			if len(plans) >= maxParallel {
				break
			}
			input, err := resolveInput(step, state)
			if err != nil {
				return e.fail(runCtx, state, step.ID, "input_resolution", err)
			}
			hash := inputHash(input)
			if existing := state.Steps[step.ID]; existing != nil && existing.Run.Status == domain.StepSucceeded && (!step.RerunOnInputChange || existing.InputHash == hash) {
				finished[step.ID] = true
				e.event(state, "step_resumed", step.ID, "previous successful result retained")
				stateChanged = true
				continue
			}
			if !condition(step.Condition, state) {
				ss := transitionStep(state, step, input, hash, domain.StepSkipped)
				done := time.Now().UTC()
				ss.Run.CompletedAt = &done
				state.Steps[step.ID] = ss
				finished[step.ID] = true
				e.event(state, "step_skipped", step.ID, "condition was false")
				stateChanged = true
				continue
			}
			capabilityImpl, _ := e.Registry.Get(step.Capability)
			manifest := capabilityImpl.Manifest()
			approved := false
			if step.ApprovalRequired || manifest.ApprovalRequired {
				if e.Approval == nil {
					ss := transitionStep(state, step, input, hash, domain.StepAwaitingApproval)
					ss.Run.ApprovalState = "pending"
					state.Steps[step.ID] = ss
					blockedApprovals[step.ID] = true
					e.event(state, "approval_required", step.ID, "approval is required before execution")
					stateChanged = true
					continue
				}
				approved, err = e.Approval(runCtx, step, manifest.Risk)
				if err != nil {
					return e.fail(runCtx, state, step.ID, "approval", err)
				}
				if !approved {
					return e.fail(runCtx, state, step.ID, "approval_rejected", errors.New("approval rejected"))
				}
			}
			ss := transitionStep(state, step, input, hash, domain.StepRunning)
			started := time.Now().UTC()
			ss.Run.StartedAt = &started
			ss.Run.ApprovalState = map[bool]string{true: "approved", false: "not_required"}[approved]
			state.Steps[step.ID] = ss
			e.event(state, "step_started", step.ID, "capability execution started")
			stateChanged = true
			provider := step.Provider
			if provider == "" && len(manifest.SupportedProviders) > 0 {
				provider = manifest.SupportedProviders[0]
			}
			if provider == "" {
				provider = step.Capability
			}
			plans = append(plans, stepPlan{Definition: step, State: *ss, Input: input, Approved: approved, Provider: provider})
		}
		if stateChanged {
			if err := e.save(runCtx, state); err != nil {
				return state, err
			}
		}
		if len(plans) == 0 {
			continue
		}
		for index := range plans {
			plans[index].ParallelShare = len(plans)
		}

		outcomes := e.executeWave(runCtx, task, state.Run.ID, plans)
		sort.Slice(outcomes, func(i, j int) bool { return rank[outcomes[i].Definition.ID] < rank[outcomes[j].Definition.ID] })
		var primaryFailure *stepOutcome
		for index := range outcomes {
			outcome := &outcomes[index]
			ss := outcome.State
			state.Steps[outcome.Definition.ID] = &ss
			if outcome.Err == nil {
				ss.Run.Status = domain.StepSucceeded
				ss.Run.Output = outcome.Result.Action.Output
				state.Steps[outcome.Definition.ID] = &ss
				finished[outcome.Definition.ID] = true
				if outcome.Definition.Capability == "report.changes" && len(outcome.Result.Action.Output) > 0 {
					state.Run.Summary = append(json.RawMessage(nil), outcome.Result.Action.Output...)
				}
				e.event(state, "step_succeeded", outcome.Definition.ID, outcome.Result.Action.Summary)
			} else if outcome.PrimaryFailure {
				ss.Run.Status = domain.StepFailed
				ss.Run.ErrorClassification = executionClassification(outcome.Result, outcome.Err)
				ss.Run.ErrorDetails = outcome.Err.Error()
				state.Steps[outcome.Definition.ID] = &ss
				e.event(state, "step_failed", outcome.Definition.ID, outcome.Err.Error())
				if primaryFailure == nil {
					primaryFailure = outcome
				}
			} else {
				ss.Run.Status = domain.StepCancelled
				ss.Run.ErrorClassification = "cancelled"
				ss.Run.ErrorDetails = outcome.Err.Error()
				state.Steps[outcome.Definition.ID] = &ss
				e.event(state, "step_cancelled", outcome.Definition.ID, "cancelled because the workflow wave stopped")
			}
			if err := e.save(runCtx, state); err != nil {
				return state, err
			}
		}
		_, cancelled = controls.state()
		if cancelled || ctx.Err() != nil {
			terminal, terminalErr := e.terminal(runCtx, state, domain.RunCancelled, "workflow_cancelled")
			if ctx.Err() != nil {
				return terminal, errors.Join(ctx.Err(), terminalErr)
			}
			return terminal, terminalErr
		}
		if primaryFailure != nil {
			return e.fail(runCtx, state, primaryFailure.Definition.ID, executionClassification(primaryFailure.Result, primaryFailure.Err), primaryFailure.Err)
		}
	}
	return e.terminal(runCtx, state, domain.RunCompleted, "workflow_completed")
}

type stepPlan struct {
	Definition    Step
	State         StepState
	Input         json.RawMessage
	Approved      bool
	Provider      string
	ParallelShare int
}

type stepOutcome struct {
	Definition     Step
	State          StepState
	Result         capability.Result
	Err            error
	PrimaryFailure bool
}

func (e *Engine) executeWave(ctx context.Context, task domain.Task, runID domain.ID, plans []stepPlan) []stepOutcome {
	outcomes := make(chan stepOutcome, len(plans))
	var group sync.WaitGroup
	for _, plan := range plans {
		plan := plan
		group.Add(1)
		go func() {
			defer group.Done()
			outcome := e.executeStep(ctx, task, runID, plan)
			outcome.PrimaryFailure = outcome.Err != nil && ctx.Err() == nil
			outcomes <- outcome
		}()
	}
	group.Wait()
	close(outcomes)
	result := make([]stepOutcome, 0, len(plans))
	for outcome := range outcomes {
		result = append(result, outcome)
	}
	return result
}

func (e *Engine) executeStep(ctx context.Context, task domain.Task, runID domain.ID, plan stepPlan) stepOutcome {
	outcome := stepOutcome{Definition: plan.Definition, State: plan.State}
	if e.Budget != nil {
		release, err := e.Budget.Acquire(ctx, budget.Request{ProgramID: task.ProgramID, Provider: plan.Provider, Hosts: budget.HostsFromInput(plan.Input)})
		if err != nil {
			outcome.Err = err
			completeStep(&outcome.State)
			return outcome
		}
		defer release()
	}
	maxAttempts := plan.Definition.Retry.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		outcome.State.Run.AttemptCount = attempt
		action := domain.ActionRequest{ID: domain.NewID(), TaskID: task.ID, WorkflowRunID: runID, StepRunID: outcome.State.Run.ID, RequestedBy: "workflow", Capability: plan.Definition.Capability, Reason: "deterministic workflow step " + plan.Definition.ID, Input: plan.Input, IdempotencyKey: outcome.State.Run.IdempotencyKey}
		attemptCtx := ctx
		cancelAttempt := func() {}
		if plan.Definition.Timeout > 0 {
			attemptCtx, cancelAttempt = context.WithTimeout(ctx, plan.Definition.Timeout)
		}
		outcome.Result, outcome.Err = e.Executor.Execute(attemptCtx, capability.Request{Action: action, Provider: plan.Definition.Provider, Approved: plan.Approved, Policy: policy.ParallelShare(e.Policy, plan.ParallelShare), Scope: e.Scope})
		cancelAttempt()
		if outcome.Err == nil {
			break
		}
		if outcome.Result.Action.Error == nil || !outcome.Result.Action.Error.Retryable || attempt == maxAttempts {
			break
		}
		delay := plan.Definition.Retry.BaseDelay
		if delay <= 0 {
			delay = time.Second
		}
		timer := time.NewTimer(delay * time.Duration(1<<(attempt-1)))
		select {
		case <-ctx.Done():
			timer.Stop()
			outcome.Err = ctx.Err()
			completeStep(&outcome.State)
			return outcome
		case <-timer.C:
		}
	}
	completeStep(&outcome.State)
	return outcome
}

func completeStep(state *StepState) {
	done := time.Now().UTC()
	state.Run.CompletedAt = &done
}

func executionClassification(result capability.Result, err error) string {
	if result.Action.Error != nil && result.Action.Error.Classification != "" {
		return result.Action.Error.Classification
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "execution"
}

func (e *Engine) save(ctx context.Context, s *State) error {
	if e.Persister != nil {
		persistCtx := ctx
		cancel := func() {}
		if ctx.Err() != nil {
			persistCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		}
		defer cancel()
		return e.Persister.Save(persistCtx, s)
	}
	return nil
}
func (e *Engine) event(s *State, t, step, msg string) {
	s.Events = append(s.Events, Event{time.Now().UTC(), t, step, msg})
}
func (e *Engine) terminal(ctx context.Context, s *State, status domain.RunStatus, event string) (*State, error) {
	now := time.Now().UTC()
	s.Run.Status = status
	s.Run.CompletedAt = &now
	e.event(s, event, "", string(status))
	return s, e.save(ctx, s)
}
func (e *Engine) fail(ctx context.Context, s *State, step, class string, err error) (*State, error) {
	s.Run.Status = domain.RunFailed
	e.event(s, "workflow_failed", step, class+": "+err.Error())
	_ = e.save(ctx, s)
	return s, err
}
func newStep(state *State, s Step, input json.RawMessage, hash string, status domain.StepStatus) *StepState {
	keySum := sha256.Sum256([]byte(string(state.Run.ID) + "\x00" + s.ID + "\x00" + hash))
	return &StepState{Run: domain.StepRun{ID: domain.NewID(), WorkflowRunID: state.Run.ID, StepDefinitionID: s.ID, Capability: s.Capability, Status: status, Input: input, IdempotencyKey: hex.EncodeToString(keySum[:]), ApprovalState: "not_required"}, InputHash: hash}
}

func transitionStep(state *State, s Step, input json.RawMessage, hash string, status domain.StepStatus) *StepState {
	next := newStep(state, s, input, hash, status)
	if previous := state.Steps[s.ID]; previous != nil && previous.Run.IdempotencyKey == next.Run.IdempotencyKey {
		next.Run.ID = previous.Run.ID
	}
	return next
}

func inputHash(in []byte) string { sum := sha256.Sum256(in); return hex.EncodeToString(sum[:]) }
func dependenciesSucceeded(s Step, state *State) bool {
	for _, d := range s.DependsOn {
		run := state.Steps[d]
		if run == nil || (run.Run.Status != domain.StepSucceeded && run.Run.Status != domain.StepSkipped) {
			return false
		}
	}
	return true
}
func condition(expr string, state *State) bool {
	if expr == "" {
		return true
	}
	kind, reference, _ := strings.Cut(expr, ":")
	id := strings.Split(reference, ".")[0]
	s := state.Steps[id]
	if s == nil {
		return false
	}
	if kind == "success" {
		return s.Run.Status == domain.StepSucceeded
	}
	if kind == "changed" {
		var v map[string]any
		if json.Unmarshal(s.Run.Output, &v) != nil {
			return false
		}
		changes, ok := v["changes"].([]any)
		return ok && len(changes) > 0
	}
	if kind == "nonempty" {
		parts := strings.Split(reference, ".")
		var value any
		if json.Unmarshal(s.Run.Output, &value) != nil {
			return false
		}
		for _, part := range parts[2:] {
			m, ok := value.(map[string]any)
			if !ok {
				return false
			}
			value, ok = m[part]
			if !ok {
				return false
			}
		}
		switch v := value.(type) {
		case []any:
			return len(v) > 0
		case string:
			return v != ""
		default:
			return v != nil
		}
	}
	return false
}
func resolveInput(s Step, state *State) (json.RawMessage, error) {
	var target map[string]any
	if err := json.Unmarshal(s.Input, &target); err != nil {
		return nil, err
	}
	for field, binding := range s.Bindings {
		parts := strings.Split(binding, ".")
		source := state.Steps[parts[0]]
		if source == nil {
			return nil, fmt.Errorf("binding source %s has no state", parts[0])
		}
		if len(source.Run.Output) == 0 && source.Run.Status == domain.StepSkipped {
			continue
		}
		var value any
		if err := json.Unmarshal(source.Run.Output, &value); err != nil {
			return nil, err
		}
		for _, part := range parts[2:] {
			if strings.HasSuffix(part, "[]") {
				part = strings.TrimSuffix(part, "[]")
				m, ok := value.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("binding %s is not an object", binding)
				}
				arr, ok := m[part].([]any)
				if !ok {
					return nil, fmt.Errorf("binding %s is not an array", binding)
				}
				value = arr
				continue
			}
			if arr, ok := value.([]any); ok {
				extracted := make([]any, 0, len(arr))
				for _, item := range arr {
					if raw, ok := item.(string); ok {
						var parsed map[string]any
						if json.Unmarshal([]byte(raw), &parsed) == nil {
							if v, ok := parsed[part]; ok {
								extracted = append(extracted, v)
								continue
							}
						}
					}
					if m, ok := item.(map[string]any); ok {
						if v, ok := m[part]; ok {
							extracted = append(extracted, v)
						}
					}
				}
				value = extracted
				continue
			}
			m, ok := value.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("binding %s is not an object", binding)
			}
			value, ok = m[part]
			if !ok {
				return nil, fmt.Errorf("binding %s not found", binding)
			}
		}
		target[field] = value
	}
	return json.Marshal(target)
}
func topological(d Definition) []Step {
	byID := map[string]Step{}
	for _, s := range d.Steps {
		byID[s.ID] = s
	}
	seen := map[string]bool{}
	out := make([]Step, 0, len(d.Steps))
	var add func(string)
	add = func(id string) {
		if seen[id] {
			return
		}
		deps := append([]string(nil), byID[id].DependsOn...)
		sort.Strings(deps)
		for _, dep := range deps {
			add(dep)
		}
		seen[id] = true
		out = append(out, byID[id])
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		add(id)
	}
	return out
}

type RegistryExecutor struct{ Registry *capability.Registry }

func (r RegistryExecutor) Execute(ctx context.Context, req capability.Request) (capability.Result, error) {
	return r.Registry.Execute(ctx, req)
}
