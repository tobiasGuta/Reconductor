package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/budget"
	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
)

func TestMaterializationStrictReleaseContract(t *testing.T) {
	definition := Definition{ID: domain.NewID(), Name: "strict", Version: "1", Materializer: "web-recon/v1", Description: "strict decode", Steps: []Step{}, DefaultPolicyRequirements: json.RawMessage(`{}`), CreatedAt: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)}
	raw, digest, err := Materialize(definition)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyMaterialization(raw, digest)
	if err != nil || verified.Materializer != "web-recon/v1" {
		t.Fatalf("supported materialization verified=%#v error=%v", verified, err)
	}

	unknown := append(json.RawMessage(nil), raw[:len(raw)-1]...)
	unknown = append(unknown, []byte(`,"unexpected":true}`)...)
	canonical, err := canonicaljson.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	if _, err := VerifyMaterialization(unknown, hex.EncodeToString(sum[:])); !errors.Is(err, ErrWorkflowCheckpointConflict) {
		t.Fatalf("unknown definition field error=%v", err)
	}
	if _, err := VerifyMaterialization(append(append(json.RawMessage(nil), raw...), []byte(` {}`)...), digest); !errors.Is(err, ErrWorkflowCheckpointConflict) {
		t.Fatalf("trailing definition JSON error=%v", err)
	}
	missingRevision := definition
	missingRevision.Materializer = ""
	missingRaw, missingDigest, err := Materialize(missingRevision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMaterialization(missingRaw, missingDigest); !errors.Is(err, ErrWorkflowCheckpointConflict) {
		t.Fatalf("missing materializer error=%v", err)
	}
	unsupportedRevision := definition
	unsupportedRevision.Materializer = "web-recon/v99"
	unsupportedRaw, unsupportedDigest, err := Materialize(unsupportedRevision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyMaterialization(unsupportedRaw, unsupportedDigest); !errors.Is(err, ErrWorkflowCheckpointConflict) {
		t.Fatalf("unsupported materializer error=%v", err)
	}
}

func TestTemplateDescriptorStrictDecoding(t *testing.T) {
	valid := json.RawMessage(`{"schema_version":1,"kind":"built-in","materializer":"web-recon/v1"}`)
	if descriptor, err := DecodeTemplateDescriptor(valid); err != nil || descriptor.Materializer != "web-recon/v1" {
		t.Fatalf("valid descriptor=%#v error=%v", descriptor, err)
	}
	for name, raw := range map[string]json.RawMessage{
		"unknown field":        json.RawMessage(`{"schema_version":1,"kind":"built-in","materializer":"web-recon/v1","unexpected":true}`),
		"trailing JSON":        json.RawMessage(`{"schema_version":1,"kind":"built-in","materializer":"web-recon/v1"} {}`),
		"unsupported revision": json.RawMessage(`{"schema_version":1,"kind":"built-in","materializer":"web-recon/v99"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeTemplateDescriptor(raw); err == nil {
				t.Fatal("expected strict descriptor rejection")
			}
		})
	}
	if _, err := (Template{Materializer: "web-recon/v99"}).Descriptor(); err == nil {
		t.Fatal("unsupported template materializer revision was accepted")
	}
}

type testCap struct {
	name     string
	calls    *int
	failOnce bool
}

func (c testCap) Manifest() capability.Manifest {
	return capability.Manifest{Name: c.name, Version: "1", Risk: policy.Low, RetrySafe: true, Idempotent: true}
}
func (c testCap) Validate(context.Context, capability.Request) error { return nil }
func (c testCap) Execute(_ context.Context, r capability.Request) (capability.Result, error) {
	*c.calls++
	if c.failOnce && *c.calls == 1 {
		return capability.Result{Action: domain.ActionResult{RequestID: r.Action.ID, Error: &domain.StructuredError{Retryable: true}}}, errors.New("temporary")
	}
	return capability.Result{Action: domain.ActionResult{RequestID: r.Action.ID, Status: "succeeded", Summary: "ok", Output: json.RawMessage(`{"lines":["https://example.test"]}`)}}, nil
}

type allScope struct{}

func (allScope) Allows(string) bool { return true }

type memoryPersist struct {
	mu    sync.Mutex
	saves int
}

type workflowTestRecorder struct{}

func (workflowTestRecorder) RecordPolicyDecision(context.Context, capability.PolicyDecisionRecord) (domain.ID, error) {
	return domain.NewID(), nil
}
func (workflowTestRecorder) RecordProviderInvocationStarted(context.Context, capability.ProviderInvocationStartRecord) (domain.ID, error) {
	return domain.NewID(), nil
}
func (workflowTestRecorder) RecordProviderInvocationTerminal(context.Context, capability.ProviderInvocationTerminalRecord) error {
	return nil
}

type testRegistryExecutor struct {
	registry *capability.Registry
	mu       sync.Mutex
	requests []capability.Request
}

func (e *testRegistryExecutor) Execute(ctx context.Context, req capability.Request) (capability.Result, error) {
	e.mu.Lock()
	e.requests = append(e.requests, req)
	e.mu.Unlock()
	recorder := workflowTestRecorder{}
	req.DecisionRecorder = recorder
	req.InvocationRecorder = recorder
	return e.registry.Execute(ctx, req)
}

func (p *memoryPersist) Save(context.Context, *State) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saves++
	return nil
}
func registryFor(t *testing.T, capabilityImpl capability.Capability) *capability.Registry {
	t.Helper()
	r := capability.NewRegistry()
	if err := r.Register(capabilityImpl); err != nil {
		t.Fatal(err)
	}
	return r
}
func TestDependencyValidation(t *testing.T) {
	calls := 0
	r := registryFor(t, testCap{"x", &calls, false})
	base := Definition{Name: "w", Version: "1", Steps: []Step{{ID: "a", Capability: "x", Input: json.RawMessage(`{}`)}}}
	if err := Validate(base, r); err != nil {
		t.Fatal(err)
	}
	cyclic := base
	cyclic.Steps = []Step{{ID: "a", Capability: "x", DependsOn: []string{"b"}, Input: json.RawMessage(`{}`)}, {ID: "b", Capability: "x", DependsOn: []string{"a"}, Input: json.RawMessage(`{}`)}}
	if err := Validate(cyclic, r); err == nil {
		t.Fatal("cycle accepted")
	}
	shell := base
	shell.Steps[0].Capability = "shell"
	if err := Validate(shell, r); err == nil {
		t.Fatal("unknown shell capability accepted")
	}
	crossBranch := Definition{Name: "cross-branch", Version: "1", Steps: []Step{
		{ID: "a", Capability: "x", Input: json.RawMessage(`{}`)},
		{ID: "b", Capability: "x", Input: json.RawMessage(`{}`)},
		{ID: "consumer", Capability: "x", DependsOn: []string{"a"}, Input: json.RawMessage(`{"value":[]}`), Bindings: map[string]string{"value": "b.output.lines"}},
	}}
	if err := Validate(crossBranch, r); err == nil {
		t.Fatal("binding from an unordered branch was accepted")
	}
}

type schemaCap struct {
	name   string
	output json.RawMessage
}

func (c schemaCap) Manifest() capability.Manifest {
	return capability.Manifest{Name: c.name, Version: "1", Risk: policy.Low, RetrySafe: true, Idempotent: true, OutputSchema: c.output}
}
func (c schemaCap) Validate(context.Context, capability.Request) error { return nil }
func (c schemaCap) Execute(context.Context, capability.Request) (capability.Result, error) {
	return capability.Result{}, nil
}

func TestValidationRejectsUndeclaredOutputBindingsAndConditions(t *testing.T) {
	registry := capability.NewRegistry()
	if err := registry.Register(schemaCap{name: "source", output: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["lines","status_routes","records"],"properties":{"lines":{"type":"array","items":{"type":"string"}},"status_routes":{"type":"object","additionalProperties":false,"required":["active"],"properties":{"active":{"type":"array","items":{"type":"string"}}}},"records":{"type":"array","items":{"$ref":"#/$defs/record"}}},"$defs":{"record":{"type":"object","additionalProperties":false,"required":["provider","target"],"properties":{"provider":{"type":"string"},"target":{"type":"string"}}}}}`)}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(schemaCap{name: "sink", output: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["ok"],"properties":{"ok":{"type":"boolean"}}}`)}); err != nil {
		t.Fatal(err)
	}
	valid := Definition{Name: "schema-bindings", Version: "1", Steps: []Step{
		{ID: "source-step", Capability: "source", Input: json.RawMessage(`{}`)},
		{ID: "sink-step", Capability: "sink", DependsOn: []string{"source-step"}, Input: json.RawMessage(`{"value":[]}`), Bindings: map[string]string{"value": "source-step.output.lines", "active": "source-step.output.status_routes.active", "provider": "source-step.output.records.provider", "target": "source-step.output.records[].target"}, Condition: "nonempty:source-step.output.status_routes.active"},
	}}
	if err := Validate(valid, registry); err != nil {
		t.Fatalf("valid declared output binding rejected: %v", err)
	}
	invalidBinding := valid
	invalidBinding.Steps = append([]Step(nil), valid.Steps...)
	invalidBinding.Steps[1].Bindings = map[string]string{"value": "source-step.output.authorized_records"}
	if err := Validate(invalidBinding, registry); err == nil {
		t.Fatal("undeclared output binding was accepted")
	}
	invalidCondition := valid
	invalidCondition.Steps = append([]Step(nil), valid.Steps...)
	invalidCondition.Steps[1].Condition = "nonempty:source-step.output.typo"
	if err := Validate(invalidCondition, registry); err == nil {
		t.Fatal("undeclared output condition was accepted")
	}
	invalidNested := valid
	invalidNested.Steps = append([]Step(nil), valid.Steps...)
	invalidNested.Steps[1].Bindings = map[string]string{"value": "source-step.output.status_routes.nonexistent_field"}
	if err := Validate(invalidNested, registry); err == nil || !strings.Contains(err.Error(), `status_routes.nonexistent_field`) {
		t.Fatal("undeclared nested output binding was accepted")
	}
	invalidArrayItem := valid
	invalidArrayItem.Steps = append([]Step(nil), valid.Steps...)
	invalidArrayItem.Steps[1].Bindings = map[string]string{"value": "source-step.output.records.nonexistent_field"}
	if err := Validate(invalidArrayItem, registry); err == nil || !strings.Contains(err.Error(), `records.nonexistent_field`) {
		t.Fatal("undeclared array item output binding was accepted")
	}
}

func TestResolveInputPreservesJSONNumbersInBoundProviderOutput(t *testing.T) {
	state := &State{Steps: map[string]*StepState{
		"probe": {Run: domain.StepRun{Output: json.RawMessage(`{"authorized_records":[{"fields":{"status_code":200,"confidence":2e-1,"large":9007199254740993}}]}`)}},
	}}
	resolved, err := resolveInput(Step{
		Input:    json.RawMessage(`{"http_observations":[]}`),
		Bindings: map[string]string{"http_observations": "probe.output.authorized_records"},
	}, state)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(resolved)))
	decoder.UseNumber()
	var input map[string]any
	if err := decoder.Decode(&input); err != nil {
		t.Fatal(err)
	}
	records, ok := input["http_observations"].([]any)
	if !ok || len(records) != 1 {
		t.Fatalf("resolved records=%#v", input)
	}
	fields := records[0].(map[string]any)["fields"].(map[string]any)
	for key, want := range map[string]string{"status_code": "200", "confidence": "2e-1", "large": "9007199254740993"} {
		value, ok := fields[key].(json.Number)
		if !ok || value.String() != want {
			t.Fatalf("%s=%#v want json.Number(%q)", key, fields[key], want)
		}
	}
}
func TestRetryIdempotencyAndResume(t *testing.T) {
	calls := 0
	r := registryFor(t, testCap{"x", &calls, true})
	persist := &memoryPersist{}
	executor := &testRegistryExecutor{registry: r}
	engine := Engine{Registry: r, Executor: executor, Persister: persist, Policy: policy.Policy{AllowedCapabilities: []string{"x"}}, Scope: allScope{}}
	def := Definition{ID: domain.NewID(), Name: "w", Version: "1", Steps: []Step{{ID: "a", Capability: "x", Input: json.RawMessage(`{"target":"x"}`), Retry: RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond}}}}
	task := domain.Task{ID: domain.NewID(), WorkflowDefinitionID: def.ID, RequestedBy: "cli"}
	state, err := engine.Run(context.Background(), def, nil, task, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
	key := state.Steps["a"].Run.IdempotencyKey
	state, err = engine.Run(context.Background(), def, state, task, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("successful step reran after resume")
	}
	if state.Steps["a"].Run.IdempotencyKey != key {
		t.Fatal("idempotency key changed")
	}
	if persist.saves < 3 {
		t.Fatal("state was not persisted across transitions")
	}
	if len(executor.requests) != 2 || executor.requests[0].Action.StepAttempt != 1 || executor.requests[1].Action.StepAttempt != 2 || executor.requests[0].Action.ID == executor.requests[1].Action.ID || executor.requests[0].Action.IdempotencyKey != executor.requests[1].Action.IdempotencyKey {
		t.Fatalf("retry action provenance=%#v", executor.requests)
	}
}

type unavailableCheckpointPersister struct{}

func (unavailableCheckpointPersister) Save(context.Context, *State) error {
	return ErrWorkflowCheckpointUnavailable
}

func TestInitialCheckpointFailurePreventsProviderExecution(t *testing.T) {
	calls := 0
	registry := registryFor(t, testCap{"x", &calls, false})
	definition := Definition{ID: domain.NewID(), Name: "checkpoint-failure", Version: "1", Steps: []Step{{ID: "provider", Capability: "x", Input: json.RawMessage(`{}`)}}}
	engine := Engine{Registry: registry, Executor: &testRegistryExecutor{registry: registry}, Persister: unavailableCheckpointPersister{}, Policy: policy.Policy{AllowedCapabilities: []string{"x"}}, Scope: allScope{}}
	state, err := engine.Run(context.Background(), definition, nil, domain.Task{ID: domain.NewID(), WorkflowDefinitionID: definition.ID}, nil)
	if !errors.Is(err, ErrWorkflowCheckpointUnavailable) {
		t.Fatalf("error=%v state=%#v", err, state)
	}
	if calls != 0 {
		t.Fatalf("provider calls=%d after initial checkpoint failure", calls)
	}
}

type degradedRetryExecutor struct{ calls int }

func (e *degradedRetryExecutor) Execute(_ context.Context, req capability.Request) (capability.Result, error) {
	e.calls++
	result := capability.Result{
		Action:             domain.ActionResult{RequestID: req.Action.ID},
		TerminalAuditError: errors.New("database host and internal detail must not persist"),
	}
	if e.calls == 1 {
		result.Action.Status = "failed"
		result.Action.Error = &domain.StructuredError{Classification: "provider_error", Message: "safe provider failure", Retryable: true}
		return result, errors.New("temporary provider failure")
	}
	result.Action.Status = "succeeded"
	result.Action.Summary = "provider truth"
	result.Action.Output = json.RawMessage(`{"lines":[]}`)
	return result, nil
}

func TestWorkflowPreservesSafeTerminalAuditDegradationForEveryAttempt(t *testing.T) {
	registryCalls := 0
	registry := registryFor(t, testCap{"x", &registryCalls, false})
	executor := &degradedRetryExecutor{}
	engine := Engine{Registry: registry, Executor: executor, Policy: policy.Policy{AllowedCapabilities: []string{"x"}}, Scope: allScope{}}
	definition := Definition{ID: domain.NewID(), Name: "terminal-audit-degradation", Version: "1", Steps: []Step{{ID: "a", Capability: "x", Input: json.RawMessage(`{}`), Retry: RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond}}}}
	state, err := engine.Run(context.Background(), definition, nil, domain.Task{ID: domain.NewID(), WorkflowDefinitionID: definition.ID}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if executor.calls != 2 || state.Steps["a"].Run.Status != domain.StepSucceeded {
		t.Fatalf("provider truth or retry changed: calls=%d step=%#v", executor.calls, state.Steps["a"].Run)
	}
	degradations := 0
	for _, event := range state.Events {
		if event.Type != providerTerminalAuditDegradedEvent {
			continue
		}
		degradations++
		if event.StepID != "a" || event.Message != providerTerminalAuditDegradedMessage || strings.Contains(event.Message, "database host") || strings.Contains(event.Message, "internal detail") {
			t.Fatalf("unsafe or misattributed degradation event: %#v", event)
		}
	}
	if degradations != 2 {
		t.Fatalf("degradation events=%d want one for each of two attempts: %#v", degradations, state.Events)
	}
}

func TestActionRequestStepAttemptJSONCompatibility(t *testing.T) {
	var legacy domain.ActionRequest
	if err := json.Unmarshal([]byte(`{"id":"00000000-0000-4000-8000-000000000001","capability":"x"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.StepAttempt != 0 {
		t.Fatalf("legacy step attempt=%d want unknown zero", legacy.StepAttempt)
	}
	encoded, err := json.Marshal(domain.ActionRequest{ID: legacy.ID, Capability: "x", StepAttempt: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"step_attempt":2`) {
		t.Fatalf("positive step attempt missing from JSON: %s", encoded)
	}
}
func TestApprovalPause(t *testing.T) {
	calls := 0
	r := registryFor(t, testCap{"x", &calls, false})
	engine := Engine{Registry: r, Executor: r, Policy: policy.Policy{AllowedCapabilities: []string{"x"}}, Scope: allScope{}}
	def := Definition{ID: domain.NewID(), Name: "w", Version: "1", Steps: []Step{{ID: "a", Capability: "x", ApprovalRequired: true, Input: json.RawMessage(`{}`)}}}
	state, err := engine.Run(context.Background(), def, nil, domain.Task{ID: domain.NewID()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.Run.Status != domain.RunPaused || state.Steps["a"].Run.Status != domain.StepAwaitingApproval || calls != 0 {
		t.Fatalf("unexpected state: %#v", state)
	}
}
func TestResumeAfterFileBackedRestart(t *testing.T) {
	calls := 0
	r := registryFor(t, testCap{"x", &calls, false})
	store := FileStore{Root: t.TempDir()}
	executor := &testRegistryExecutor{registry: r}
	engine := Engine{Registry: r, Executor: executor, Persister: store, Policy: policy.Policy{AllowedCapabilities: []string{"x"}}, Scope: allScope{}}
	def := Definition{ID: domain.NewID(), Name: "w", Version: "1", Steps: []Step{{ID: "a", Capability: "x", Input: json.RawMessage(`{}`)}}}
	task := domain.Task{ID: domain.NewID()}
	state, err := engine.Run(context.Background(), def, nil, task, nil)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(string(state.Run.ID))
	if err != nil {
		t.Fatal(err)
	}
	restarted := Engine{Registry: r, Executor: executor, Persister: store, Policy: engine.Policy, Scope: allScope{}}
	if _, err := restarted.Run(context.Background(), def, loaded, task, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("restart reran completed work; calls=%d", calls)
	}
}

type namedCap string

func (c namedCap) Manifest() capability.Manifest {
	return capability.Manifest{Name: string(c), Version: "1", Risk: policy.Low, RetrySafe: true, Idempotent: true}
}
func (c namedCap) Validate(context.Context, capability.Request) error { return nil }
func (c namedCap) Execute(context.Context, capability.Request) (capability.Result, error) {
	panic("workflow test executor should be used")
}

type dnsFailureExecutor struct {
	calls      map[string]int
	dnsTargets []string
}

func (e *dnsFailureExecutor) Execute(_ context.Context, req capability.Request) (capability.Result, error) {
	e.calls[req.Action.Capability]++
	if req.Action.Capability == "resolve.dns" {
		var input struct {
			Targets []string `json:"targets"`
		}
		if err := json.Unmarshal(req.Action.Input, &input); err != nil {
			return capability.Result{}, err
		}
		e.dnsTargets = append([]string(nil), input.Targets...)
		return capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "failed", Error: &domain.StructuredError{Classification: "provider_error", Message: "mock dns failure"}}}, errors.New("mock dns failure")
	}
	output := json.RawMessage(`{"lines":["https://authorized.example.test/"],"authorized_urls":["https://authorized.example.test/"]}`)
	if req.Action.Capability == "targeting.prepare" {
		output = json.RawMessage(`{"urls":["https://authorized.example.test/"]}`)
	}
	return capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Summary: "ok", Output: output}}, nil
}

func TestResumeAfterDNSFailureRetainsSuccessfulScopePreparation(t *testing.T) {
	registry := capability.NewRegistry()
	for _, name := range []string{"discover.subdomains", "targeting.prepare", "resolve.dns"} {
		if err := registry.Register(namedCap(name)); err != nil {
			t.Fatal(err)
		}
	}
	executor := &dnsFailureExecutor{calls: map[string]int{}}
	engine := Engine{Registry: registry, Executor: executor, Policy: policy.Policy{AllowedCapabilities: registry.Names()}, Scope: allScope{}}
	def := Definition{ID: domain.NewID(), Name: "dns-failure", Version: "1", Steps: []Step{
		{ID: "discover", Capability: "discover.subdomains", Input: json.RawMessage(`{}`)},
		{ID: "prepare", Capability: "targeting.prepare", DependsOn: []string{"discover"}, Input: json.RawMessage(`{}`)},
		{ID: "dns", Capability: "resolve.dns", DependsOn: []string{"prepare"}, Input: json.RawMessage(`{"targets":[]}`), Bindings: map[string]string{"targets": "prepare.output.urls"}, Retry: RetryPolicy{MaxAttempts: 1}},
	}}
	task := domain.Task{ID: domain.NewID(), WorkflowDefinitionID: def.ID, RequestedBy: "test"}
	state, err := engine.Run(context.Background(), def, nil, task, nil)
	if err == nil {
		t.Fatal("expected DNS failure")
	}
	if state.Steps["discover"].Run.Status != domain.StepSucceeded || state.Steps["prepare"].Run.Status != domain.StepSucceeded || state.Steps["dns"].Run.Status != domain.StepFailed {
		t.Fatalf("unexpected state: %#v", state.Steps)
	}
	dnsStepRunID := state.Steps["dns"].Run.ID
	state, err = engine.Run(context.Background(), def, state, task, nil)
	if err == nil {
		t.Fatal("expected retry DNS failure")
	}
	if executor.calls["discover.subdomains"] != 1 || executor.calls["targeting.prepare"] != 1 || executor.calls["resolve.dns"] != 1 {
		t.Fatalf("unexpected resume calls: %#v", executor.calls)
	}
	if state.Steps["dns"].Run.ID != dnsStepRunID {
		t.Fatalf("unchanged failed DNS input created a duplicate step run: before=%s after=%s", dnsStepRunID, state.Steps["dns"].Run.ID)
	}
	if len(executor.dnsTargets) != 1 || executor.dnsTargets[0] != "https://authorized.example.test/" {
		t.Fatalf("DNS step did not receive prepared authorized targets: %#v", executor.dnsTargets)
	}
}

type parallelExecutor struct {
	started chan string
	release chan struct{}
	mu      sync.Mutex
	active  int
	maximum int
}

func (e *parallelExecutor) Execute(ctx context.Context, req capability.Request) (capability.Result, error) {
	var input struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(req.Action.Input, &input); err != nil {
		return capability.Result{}, err
	}
	e.mu.Lock()
	e.active++
	if e.active > e.maximum {
		e.maximum = e.active
	}
	e.mu.Unlock()
	select {
	case e.started <- input.Name:
	case <-ctx.Done():
		e.finish()
		return capability.Result{}, ctx.Err()
	}
	select {
	case <-e.release:
		e.finish()
		return capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Summary: input.Name, Output: json.RawMessage(`{"lines":[]}`)}}, nil
	case <-ctx.Done():
		e.finish()
		return capability.Result{}, ctx.Err()
	}
}

func (e *parallelExecutor) finish() {
	e.mu.Lock()
	e.active--
	e.mu.Unlock()
}

func (e *parallelExecutor) maxActive() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.maximum
}

func TestIndependentBranchesRunInParallelWithDeterministicCommits(t *testing.T) {
	calls := 0
	registry := registryFor(t, testCap{"x", &calls, false})
	executor := &parallelExecutor{started: make(chan string, 2), release: make(chan struct{})}
	engine := Engine{Registry: registry, Executor: executor, MaxParallel: 2, Policy: policy.Policy{AllowedCapabilities: []string{"x"}}, Scope: allScope{}}
	definition := Definition{ID: domain.NewID(), Name: "parallel", Version: "1", Steps: []Step{
		{ID: "a", Capability: "x", Input: json.RawMessage(`{"name":"a"}`)},
		{ID: "b", Capability: "x", Input: json.RawMessage(`{"name":"b"}`)},
	}}
	result := make(chan struct {
		state *State
		err   error
	}, 1)
	go func() {
		state, err := engine.Run(context.Background(), definition, nil, domain.Task{ID: domain.NewID(), ProgramID: domain.NewID()}, nil)
		result <- struct {
			state *State
			err   error
		}{state, err}
	}()
	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case name := <-executor.started:
			seen[name] = true
		case <-time.After(time.Second):
			t.Fatal("independent workflow branches did not start concurrently")
		}
	}
	close(executor.release)
	completed := <-result
	if completed.err != nil {
		t.Fatal(completed.err)
	}
	if executor.maxActive() != 2 {
		t.Fatalf("maximum active steps = %d, want 2", executor.maxActive())
	}
	var succeeded []string
	for _, event := range completed.state.Events {
		if event.Type == "step_succeeded" {
			succeeded = append(succeeded, event.StepID)
		}
	}
	if len(succeeded) != 2 || succeeded[0] != "a" || succeeded[1] != "b" {
		t.Fatalf("completion commits are not deterministic: %#v", succeeded)
	}
}

func TestWorkflowProviderBudgetBoundsParallelBranches(t *testing.T) {
	calls := 0
	registry := registryFor(t, testCap{"x", &calls, false})
	executor := &parallelExecutor{started: make(chan string, 2), release: make(chan struct{})}
	limiter := budget.NewLocal(budget.Limits{Program: 2, Provider: 1, Host: 2})
	engine := Engine{Registry: registry, Executor: executor, MaxParallel: 2, Budget: limiter, Policy: policy.Policy{AllowedCapabilities: []string{"x"}}, Scope: allScope{}}
	definition := Definition{ID: domain.NewID(), Name: "bounded", Version: "1", Steps: []Step{
		{ID: "a", Capability: "x", Provider: "shared", Input: json.RawMessage(`{"name":"a","target":"https://a.example.test"}`)},
		{ID: "b", Capability: "x", Provider: "shared", Input: json.RawMessage(`{"name":"b","target":"https://b.example.test"}`)},
	}}
	result := make(chan error, 1)
	go func() {
		_, err := engine.Run(context.Background(), definition, nil, domain.Task{ID: domain.NewID(), ProgramID: domain.NewID()}, nil)
		result <- err
	}()
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("first bounded step did not start")
	}
	select {
	case name := <-executor.started:
		t.Fatalf("provider budget allowed concurrent step %s", name)
	case <-time.After(30 * time.Millisecond):
	}
	executor.release <- struct{}{}
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("second bounded step did not start after release")
	}
	executor.release <- struct{}{}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if executor.maxActive() != 1 {
		t.Fatalf("maximum active provider steps = %d, want 1", executor.maxActive())
	}
}

type cancellationExecutor struct {
	started chan struct{}
}

func (e cancellationExecutor) Execute(ctx context.Context, _ capability.Request) (capability.Result, error) {
	close(e.started)
	<-ctx.Done()
	return capability.Result{}, ctx.Err()
}

type cancellationPersist struct {
	mu         sync.Mutex
	finalSaved bool
}

func (p *cancellationPersist) Save(ctx context.Context, state *State) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if state.Run.Status == domain.RunCancelled {
		p.finalSaved = true
	}
	return nil
}

func (p *cancellationPersist) savedFinalState() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.finalSaved
}

func TestControlCancellationStopsActivelyRunningStep(t *testing.T) {
	calls := 0
	registry := registryFor(t, testCap{"x", &calls, false})
	executor := cancellationExecutor{started: make(chan struct{})}
	persist := &cancellationPersist{}
	controls := &Controls{}
	engine := Engine{Registry: registry, Executor: executor, Persister: persist, MaxParallel: 2, Policy: policy.Policy{AllowedCapabilities: []string{"x"}}, Scope: allScope{}}
	definition := Definition{ID: domain.NewID(), Name: "cancel", Version: "1", Steps: []Step{{ID: "active", Capability: "x", Input: json.RawMessage(`{}`)}}}
	result := make(chan struct {
		state *State
		err   error
	}, 1)
	go func() {
		state, err := engine.Run(context.Background(), definition, nil, domain.Task{ID: domain.NewID()}, controls)
		result <- struct {
			state *State
			err   error
		}{state, err}
	}()
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("step did not start")
	}
	controls.Cancel()
	select {
	case completed := <-result:
		if completed.err != nil {
			t.Fatal(completed.err)
		}
		if completed.state.Run.Status != domain.RunCancelled || completed.state.Steps["active"].Run.Status != domain.StepCancelled {
			t.Fatalf("unexpected cancellation state: %#v", completed.state)
		}
		if !persist.savedFinalState() {
			t.Fatal("final cancellation state was not durably persisted")
		}
	case <-time.After(time.Second):
		t.Fatal("active step did not stop after cancellation")
	}
}

type defaultProviderCap struct{}

func (defaultProviderCap) Manifest() capability.Manifest {
	return capability.Manifest{Name: "implicit.provider", Version: "1", Risk: policy.Low, RetrySafe: true, Idempotent: true, SupportedProviders: []string{"default-provider"}}
}
func (defaultProviderCap) Validate(context.Context, capability.Request) error { return nil }
func (defaultProviderCap) Execute(context.Context, capability.Request) (capability.Result, error) {
	return capability.Result{}, nil
}

type providerCaptureExecutor struct {
	provider string
}

func (e *providerCaptureExecutor) Execute(_ context.Context, req capability.Request) (capability.Result, error) {
	e.provider = req.Provider
	return capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Summary: "ok", Output: json.RawMessage(`{"lines":[]}`)}}, nil
}

func TestExecuteStepUsesResolvedDefaultProvider(t *testing.T) {
	registry := registryFor(t, defaultProviderCap{})
	executor := &providerCaptureExecutor{}
	engine := Engine{Registry: registry, Executor: executor, Policy: policy.Policy{AllowedCapabilities: []string{"implicit.provider"}}, Scope: allScope{}}
	definition := Definition{ID: domain.NewID(), Name: "provider", Version: "1", Steps: []Step{{ID: "step", Capability: "implicit.provider", Input: json.RawMessage(`{}`)}}}
	if _, err := engine.Run(context.Background(), definition, nil, domain.Task{ID: domain.NewID(), ProgramID: domain.NewID()}, nil); err != nil {
		t.Fatal(err)
	}
	if executor.provider != "default-provider" {
		t.Fatalf("provider=%q", executor.provider)
	}
}

func TestApprovalPauseAllowsIndependentSafeBranchAndResumes(t *testing.T) {
	calls := 0
	registry := registryFor(t, testCap{"x", &calls, false})
	engine := Engine{Registry: registry, Executor: &testRegistryExecutor{registry: registry}, MaxParallel: 2, Policy: policy.Policy{AllowedCapabilities: []string{"x"}}, Scope: allScope{}}
	definition := Definition{ID: domain.NewID(), Name: "approval-branches", Version: "1", Steps: []Step{
		{ID: "gated", Capability: "x", ApprovalRequired: true, Input: json.RawMessage(`{}`)},
		{ID: "safe", Capability: "x", Input: json.RawMessage(`{}`)},
	}}
	task := domain.Task{ID: domain.NewID()}
	state, err := engine.Run(context.Background(), definition, nil, task, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.Run.Status != domain.RunPaused || state.Steps["gated"].Run.Status != domain.StepAwaitingApproval || state.Steps["safe"].Run.Status != domain.StepSucceeded {
		t.Fatalf("independent safe branch did not finish before approval pause: %#v", state)
	}
	if calls != 1 {
		t.Fatalf("calls before approval = %d, want 1", calls)
	}
	engine.Approval = func(context.Context, Step, policy.Risk) (bool, error) { return true, nil }
	state, err = engine.Run(context.Background(), definition, state, task, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.Run.Status != domain.RunCompleted || state.Steps["gated"].Run.Status != domain.StepSucceeded || calls != 2 {
		t.Fatalf("approval resume failed: calls=%d state=%#v", calls, state)
	}
}
