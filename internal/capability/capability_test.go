package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
)

type failingPreparedAllocator struct {
	capturedInvocations
	err error
}

type unresolvedAllocationError struct{}

func (*unresolvedAllocationError) Error() string              { return "allocation acknowledgement unresolved" }
func (*unresolvedAllocationError) CommitOutcomeUnknown() bool { return true }

func (f *failingPreparedAllocator) AllocateProviderInvocation(_ context.Context, record ProviderInvocationStartRecord, _ artifact.StoreIdentity) (ProviderInvocationAdmission, error) {
	f.starts = append(f.starts, record)
	return ProviderInvocationAdmission{}, f.err
}

type executionProbeCapability struct{ executed bool }

func (*executionProbeCapability) Manifest() Manifest {
	return Manifest{Name: "prepared.probe", Version: "1", Risk: policy.Low}
}
func (*executionProbeCapability) Validate(context.Context, Request) error { return nil }
func (c *executionProbeCapability) Execute(context.Context, Request) (Result, error) {
	c.executed = true
	return Result{Action: domain.ActionResult{Status: "succeeded"}}, nil
}

func TestPreparedAllocationFailurePreventsProviderInvocation(t *testing.T) {
	implementation := &executionProbeCapability{}
	registry := NewRegistry()
	if err := registry.Register(implementation); err != nil {
		t.Fatal(err)
	}
	cause := &unresolvedAllocationError{}
	allocator := &failingPreparedAllocator{err: cause}
	identity := artifact.StoreIdentity{ArtifactStoreID: domain.NewID(), IncarnationNonce: domain.NewID(), BackendKind: artifact.BackendKind, MarkerFormat: artifact.MarkerFormat, MarkerVersion: artifact.MarkerVersion}
	request := Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "prepared.probe", StepAttempt: 1}, ProgramID: domain.NewID(), Policy: policy.Policy{AllowedCapabilities: []string{"prepared.probe"}}, Scope: allowAllScope{}, DecisionRecorder: &capturedDecision{}, InvocationRecorder: allocator, PreparedStoreIdentity: &identity, RequirePreparedEvidence: true}
	_, err := registry.Execute(context.Background(), request)
	var unknown interface{ CommitOutcomeUnknown() bool }
	if !errors.Is(err, cause) || !errors.As(err, &unknown) || !unknown.CommitOutcomeUnknown() || implementation.executed || len(allocator.starts) != 1 {
		t.Fatalf("error=%v executed=%v allocations=%d", err, implementation.executed, len(allocator.starts))
	}
}

type guardedCapability struct {
	manifest Manifest
	called   bool
}

func (c *guardedCapability) Manifest() Manifest { return c.manifest }
func (c *guardedCapability) Validate(context.Context, Request) error {
	c.called = true
	return nil
}
func (c *guardedCapability) Execute(context.Context, Request) (Result, error) {
	c.called = true
	return Result{}, nil
}

type capturedDecision struct {
	records []PolicyDecisionRecord
	ids     []domain.ID
	err     error
}

func (c *capturedDecision) RecordPolicyDecision(_ context.Context, record PolicyDecisionRecord) (domain.ID, error) {
	c.records = append(c.records, record)
	if c.err != nil {
		return "", c.err
	}
	id := domain.NewID()
	c.ids = append(c.ids, id)
	return id, nil
}

type capturedInvocations struct {
	starts        []ProviderInvocationStartRecord
	startIDs      []domain.ID
	terminals     []ProviderInvocationTerminalRecord
	startErr      error
	terminalErr   error
	startRecorded bool
}

func (c *capturedInvocations) RecordProviderInvocationStarted(_ context.Context, record ProviderInvocationStartRecord) (domain.ID, error) {
	c.starts = append(c.starts, record)
	if c.startErr != nil {
		return "", c.startErr
	}
	id := domain.NewID()
	c.startIDs = append(c.startIDs, id)
	c.startRecorded = true
	return id, nil
}

func (c *capturedInvocations) RecordProviderInvocationTerminal(_ context.Context, record ProviderInvocationTerminalRecord) error {
	c.terminals = append(c.terminals, record)
	return c.terminalErr
}

func TestModeledPolicyRestrictionsDenyBeforeProviderAndAreAudited(t *testing.T) {
	tests := []struct {
		name         string
		requirements policy.Requirements
		configure    func(*policy.Policy)
		reason       string
	}{
		{"authentication", policy.Requirements{Authentication: true}, nil, "authentication usage"},
		{"directory fuzzing", policy.Requirements{DirectoryFuzzing: true}, nil, "directory fuzzing"},
		{"cross origin", policy.Requirements{CrossOrigin: true}, nil, "cross-origin"},
		{"intrusive checks", policy.Requirements{IntrusiveChecks: true}, nil, "intrusive checks"},
		{"scan window", policy.Requirements{}, func(p *policy.Policy) { p.ScanWindows = []string{"Mon 09:00-10:00 UTC"} }, "outside configured scan windows"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			implementation := &guardedCapability{manifest: Manifest{Name: "guarded", Version: "1", Risk: policy.Low, PolicyRequirements: test.requirements}}
			registry := NewRegistry()
			registry.now = func() time.Time { return time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC) }
			if err := registry.Register(implementation); err != nil {
				t.Fatal(err)
			}
			configured := policy.Policy{ID: "restricted", AllowedCapabilities: []string{"guarded"}}
			if test.configure != nil {
				test.configure(&configured)
			}
			audit := &capturedDecision{}
			invocations := &capturedInvocations{}
			_, err := registry.Execute(context.Background(), Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "guarded", Input: json.RawMessage(`{}`)}, Policy: configured, Scope: allowAllScope{}, DecisionRecorder: audit, InvocationRecorder: invocations})
			if err == nil || !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("error=%v", err)
			}
			if implementation.called {
				t.Fatal("provider validation or execution was reached")
			}
			if len(invocations.starts) != 0 {
				t.Fatalf("provider start was recorded after policy denial: %#v", invocations.starts)
			}
			if len(audit.records) != 1 || audit.records[0].Evaluation.Decision != policy.Deny || !strings.Contains(audit.records[0].Evaluation.Reason, test.reason) {
				t.Fatalf("audit=%#v", audit.records)
			}
		})
	}
}

func TestPolicyAuditFailureFailsClosedBeforeProvider(t *testing.T) {
	implementation := &guardedCapability{manifest: Manifest{Name: "guarded", Version: "1", Risk: policy.Low}}
	registry := NewRegistry()
	if err := registry.Register(implementation); err != nil {
		t.Fatal(err)
	}
	audit := &capturedDecision{err: errors.New("audit unavailable")}
	_, err := registry.Execute(context.Background(), Request{Action: domain.ActionRequest{Capability: "guarded", Input: json.RawMessage(`{}`)}, Policy: policy.Policy{AllowedCapabilities: []string{"guarded"}}, Scope: allowAllScope{}, DecisionRecorder: audit})
	if err == nil || implementation.called {
		t.Fatalf("error=%v provider_called=%v", err, implementation.called)
	}
}

func TestExplicitPolicyPermissionsAllowDeclaredBehavior(t *testing.T) {
	requirements := policy.Requirements{Authentication: true, DirectoryFuzzing: true, CrossOrigin: true, IntrusiveChecks: true}
	implementation := &guardedCapability{manifest: Manifest{Name: "guarded", Version: "1", Risk: policy.Low, PolicyRequirements: requirements}}
	registry := NewRegistry()
	if err := registry.Register(implementation); err != nil {
		t.Fatal(err)
	}
	audit := &capturedDecision{}
	invocations := &capturedInvocations{}
	configured := policy.Policy{AllowedCapabilities: []string{"guarded"}, AuthenticationUsage: true, DirectoryFuzzing: true, CrossOrigin: true, IntrusiveChecks: true}
	if _, err := registry.Execute(context.Background(), Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "guarded", Input: json.RawMessage(`{}`)}, Policy: configured, Scope: allowAllScope{}, DecisionRecorder: audit, InvocationRecorder: invocations}); err != nil {
		t.Fatal(err)
	}
	if !implementation.called || len(audit.records) != 1 || audit.records[0].Evaluation.Decision != policy.Allow || len(invocations.starts) != 1 || len(invocations.terminals) != 1 {
		t.Fatalf("provider_called=%v audit=%#v starts=%#v terminals=%#v", implementation.called, audit.records, invocations.starts, invocations.terminals)
	}
}

type boundaryCapability struct {
	validateErr error
	execute     func(context.Context) (Result, error)
	called      bool
}

type malformedProbeCapability struct{}

func (malformedProbeCapability) Manifest() Manifest {
	return Manifest{Name: "probe.http", Version: "4", Risk: policy.Low}
}
func (malformedProbeCapability) Validate(context.Context, Request) error { return nil }
func (malformedProbeCapability) Execute(context.Context, Request) (Result, error) {
	return Result{Action: domain.ActionResult{Status: "succeeded", Output: json.RawMessage(`{"authorized_records":[{"provider":"httpx","kind":"url","target":"not-a-url"}]}`)}}, nil
}

func (*boundaryCapability) Manifest() Manifest {
	return Manifest{Name: "boundary", Version: "1", Risk: policy.Low}
}
func (c *boundaryCapability) Validate(context.Context, Request) error { return c.validateErr }
func (c *boundaryCapability) Execute(ctx context.Context, _ Request) (Result, error) {
	c.called = true
	return c.execute(ctx)
}

type queueMutatingCapability struct {
	validateMutation domain.ID
	executeMutation  domain.ID
	validateCalled   bool
	executeCalled    bool
	validateSaw      *domain.ID
	executeSaw       *domain.ID
	validatePointer  *domain.ID
	executePointer   *domain.ID
}

func (*queueMutatingCapability) Manifest() Manifest {
	return Manifest{Name: "queue-mutator", Version: "1", Risk: policy.Low}
}

func (c *queueMutatingCapability) Validate(_ context.Context, req Request) error {
	c.validateCalled = true
	c.validatePointer = req.QueueJobID
	c.validateSaw = copyIDPointer(req.QueueJobID)
	if req.QueueJobID != nil {
		*req.QueueJobID = c.validateMutation
	}
	return nil
}

func (c *queueMutatingCapability) Execute(_ context.Context, req Request) (Result, error) {
	c.executeCalled = true
	c.executePointer = req.QueueJobID
	c.executeSaw = copyIDPointer(req.QueueJobID)
	if req.QueueJobID != nil {
		*req.QueueJobID = c.executeMutation
	}
	return Result{Action: domain.ActionResult{Status: "succeeded"}}, nil
}

func TestProviderInvocationBoundaryGatesAndPropagatesExactIDs(t *testing.T) {
	provider := &boundaryCapability{execute: func(context.Context) (Result, error) {
		return Result{Action: domain.ActionResult{Status: "succeeded"}}, nil
	}}
	registry := NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	decisions := &capturedDecision{}
	invocations := &capturedInvocations{}
	actionID := domain.NewID()
	result, err := registry.Execute(context.Background(), Request{
		Action: domain.ActionRequest{ID: actionID, Capability: "boundary", StepAttempt: 2, Input: json.RawMessage(`{}`)},
		Policy: policy.Policy{AllowedCapabilities: []string{"boundary"}}, Scope: allowAllScope{},
		DecisionRecorder: decisions, InvocationRecorder: invocations,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions.ids) != 1 || len(invocations.starts) != 1 || invocations.starts[0].ExecutionAuthorizationEventID != decisions.ids[0] {
		t.Fatalf("decisions=%#v starts=%#v", decisions.ids, invocations.starts)
	}
	if invocations.starts[0].ActionRequestID != actionID || invocations.starts[0].StepAttempt != 2 || invocations.starts[0].Provider != "boundary" {
		t.Fatalf("start=%#v", invocations.starts[0])
	}
	if result.ProviderAttemptID == nil || *result.ProviderAttemptID != invocations.startIDs[0] || len(invocations.terminals) != 1 || invocations.terminals[0].ProviderAttemptID != invocations.startIDs[0] || invocations.terminals[0].Outcome != ProviderInvocationSucceeded {
		t.Fatalf("result=%#v terminals=%#v", result, invocations.terminals)
	}
}

func TestMalformedProbeSourcePreservesResultAdmissionProvenanceAndDiagnostic(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register(malformedProbeCapability{}); err != nil {
		t.Fatal(err)
	}
	decisions := &capturedDecision{}
	invocations := &capturedInvocations{}
	result, err := registry.Execute(context.Background(), Request{
		ProgramID: domain.ID("00000000-0000-4000-8000-000000000001"),
		Action:    domain.ActionRequest{ID: domain.NewID(), Capability: "probe.http", Input: json.RawMessage(`{}`)},
		Policy:    policy.Policy{AllowedCapabilities: []string{"probe.http"}}, Scope: allowAllScope{},
		DecisionRecorder: decisions, InvocationRecorder: invocations,
	})
	if err == nil || result.Action.Error == nil || result.Action.Error.Classification != "source_contract" {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if result.ProviderAttemptID == nil || result.AdmissionProvenance == nil || *result.ProviderAttemptID != invocations.startIDs[0] || result.AdmissionProvenance.ProviderAttemptID != invocations.startIDs[0] {
		t.Fatalf("source contract failure lost result admission provenance: %#v", result)
	}
	if len(result.RawDiagnostic) == 0 {
		t.Fatalf("source contract failure lost its complete diagnostic: %#v", result)
	}
	if len(invocations.starts) != 1 || len(invocations.terminals) != 1 || invocations.terminals[0].Outcome != ProviderInvocationFailed {
		t.Fatalf("provider audit=%#v", invocations)
	}
}

func TestRegistrySnapshotsQueueJobIDAcrossProviderCallbacks(t *testing.T) {
	originalQueueJobID, validateMutation, executeMutation := domain.NewID(), domain.NewID(), domain.NewID()
	wantQueueJobID := originalQueueJobID
	provider := &queueMutatingCapability{validateMutation: validateMutation, executeMutation: executeMutation}
	registry := NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	decisions := &capturedDecision{}
	invocations := &capturedInvocations{}
	result, err := registry.Execute(context.Background(), Request{
		Action:             domain.ActionRequest{ID: domain.NewID(), Capability: "queue-mutator", Input: json.RawMessage(`{}`)},
		QueueJobID:         &originalQueueJobID,
		Policy:             policy.Policy{AllowedCapabilities: []string{"queue-mutator"}},
		Scope:              allowAllScope{},
		DecisionRecorder:   decisions,
		InvocationRecorder: invocations,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !provider.validateCalled || provider.validateSaw == nil || *provider.validateSaw != wantQueueJobID {
		t.Fatalf("Validate queue identity=%v want %s", provider.validateSaw, wantQueueJobID)
	}
	if !provider.executeCalled || provider.executeSaw == nil || *provider.executeSaw != wantQueueJobID {
		t.Fatalf("Execute queue identity=%v want %s", provider.executeSaw, wantQueueJobID)
	}
	if originalQueueJobID != wantQueueJobID {
		t.Fatalf("provider mutation escaped into caller-owned queue identity: got %s want %s", originalQueueJobID, wantQueueJobID)
	}
	if len(decisions.records) != 1 || decisions.records[0].QueueJobID == nil || *decisions.records[0].QueueJobID != wantQueueJobID {
		t.Fatalf("execution authorization queue identity=%#v want %s", decisions.records, wantQueueJobID)
	}
	if len(invocations.starts) != 1 || invocations.starts[0].QueueJobID == nil || *invocations.starts[0].QueueJobID != wantQueueJobID {
		t.Fatalf("provider start queue identity=%#v want %s", invocations.starts, wantQueueJobID)
	}
	if result.AdmissionProvenance == nil || result.AdmissionProvenance.QueueJobID == nil || *result.AdmissionProvenance.QueueJobID != wantQueueJobID {
		t.Fatalf("admission queue identity=%#v want %s", result.AdmissionProvenance, wantQueueJobID)
	}
	for name, authoritative := range map[string]*domain.ID{
		"execution authorization": decisions.records[0].QueueJobID,
		"provider start":          invocations.starts[0].QueueJobID,
		"admission":               result.AdmissionProvenance.QueueJobID,
	} {
		if authoritative == provider.validatePointer || authoritative == provider.executePointer {
			t.Fatalf("provider received pointer alias to %s queue identity", name)
		}
	}
	if provider.validatePointer == provider.executePointer {
		t.Fatal("Validate and Execute shared a queue identity pointer")
	}
}

func TestRegistryPreservesNilQueueJobIDAcrossProviderCallbacks(t *testing.T) {
	provider := &queueMutatingCapability{validateMutation: domain.NewID(), executeMutation: domain.NewID()}
	registry := NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	decisions := &capturedDecision{}
	invocations := &capturedInvocations{}
	result, err := registry.Execute(context.Background(), Request{
		Action:             domain.ActionRequest{ID: domain.NewID(), Capability: "queue-mutator", Input: json.RawMessage(`{}`)},
		Policy:             policy.Policy{AllowedCapabilities: []string{"queue-mutator"}},
		Scope:              allowAllScope{},
		DecisionRecorder:   decisions,
		InvocationRecorder: invocations,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !provider.validateCalled || !provider.executeCalled || provider.validatePointer != nil || provider.executePointer != nil || provider.validateSaw != nil || provider.executeSaw != nil {
		t.Fatalf("provider callbacks received synthesized queue identity: %#v", provider)
	}
	if len(decisions.records) != 1 || decisions.records[0].QueueJobID != nil {
		t.Fatalf("execution authorization synthesized queue identity: %#v", decisions.records)
	}
	if len(invocations.starts) != 1 || invocations.starts[0].QueueJobID != nil {
		t.Fatalf("provider start synthesized queue identity: %#v", invocations.starts)
	}
	if result.AdmissionProvenance == nil || result.AdmissionProvenance.QueueJobID != nil {
		t.Fatalf("admission queue identity=%#v want nil", result.AdmissionProvenance)
	}
}

func TestDispatchPolicyEventCannotAuthorizeProviderStart(t *testing.T) {
	provider := &boundaryCapability{execute: func(context.Context) (Result, error) { return Result{}, nil }}
	registry := NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	decisions := &capturedDecision{}
	invocations := &capturedInvocations{}
	req := Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "boundary", Input: json.RawMessage(`{}`)}, Policy: policy.Policy{AllowedCapabilities: []string{"boundary"}}, Scope: allowAllScope{}, PolicyPhase: "dispatch", DecisionRecorder: decisions}
	if err := registry.Validate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	dispatchID := decisions.ids[0]
	req.PolicyPhase = "execution"
	req.InvocationRecorder = invocations
	if _, err := registry.Execute(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(decisions.ids) != 2 || invocations.starts[0].ExecutionAuthorizationEventID == dispatchID || invocations.starts[0].ExecutionAuthorizationEventID != decisions.ids[1] {
		t.Fatalf("decision_ids=%#v start=%#v", decisions.ids, invocations.starts[0])
	}
}

func TestValidationAndStartFailuresPreventProviderCallback(t *testing.T) {
	for _, test := range []struct {
		name        string
		validateErr error
		startErr    error
	}{
		{name: "validation", validateErr: errors.New("invalid request")},
		{name: "start audit", startErr: errors.New("audit unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &boundaryCapability{validateErr: test.validateErr, execute: func(context.Context) (Result, error) { return Result{}, nil }}
			registry := NewRegistry()
			if err := registry.Register(provider); err != nil {
				t.Fatal(err)
			}
			invocations := &capturedInvocations{startErr: test.startErr}
			result, err := registry.Execute(context.Background(), Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "boundary", Input: json.RawMessage(`{}`)}, Policy: policy.Policy{AllowedCapabilities: []string{"boundary"}}, Scope: allowAllScope{}, DecisionRecorder: &capturedDecision{}, InvocationRecorder: invocations})
			if err == nil || provider.called {
				t.Fatalf("error=%v provider_called=%v", err, provider.called)
			}
			if result.ProviderAttemptID != nil || result.AdmissionProvenance != nil {
				t.Fatalf("pre-provider failure fabricated admission provenance: %#v", result)
			}
			if test.validateErr != nil && len(invocations.starts) != 0 {
				t.Fatalf("provider start was reached after validation failure: %#v", invocations.starts)
			}
		})
	}
}

func TestProviderStartCompletesBeforeCallbackAndEachCallbackIsUnique(t *testing.T) {
	invocations := &capturedInvocations{}
	provider := &boundaryCapability{execute: func(context.Context) (Result, error) {
		if !invocations.startRecorded {
			t.Fatal("provider callback ran before start recording completed")
		}
		return Result{Action: domain.ActionResult{Status: "succeeded"}}, nil
	}}
	registry := NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		invocations.startRecorded = false
		if _, err := registry.Execute(context.Background(), Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "boundary", Input: json.RawMessage(`{}`)}, Policy: policy.Policy{AllowedCapabilities: []string{"boundary"}}, Scope: allowAllScope{}, DecisionRecorder: &capturedDecision{}, InvocationRecorder: invocations}); err != nil {
			t.Fatal(err)
		}
	}
	if len(invocations.startIDs) != 2 || invocations.startIDs[0] == invocations.startIDs[1] {
		t.Fatalf("start ids=%#v", invocations.startIDs)
	}
}

func TestProviderTerminalClassificationPrecedence(t *testing.T) {
	tests := []struct {
		name    string
		execute func(context.Context) (Result, error)
		want    ProviderInvocationOutcome
	}{
		{name: "success", execute: func(context.Context) (Result, error) {
			return Result{Action: domain.ActionResult{Status: "succeeded"}}, nil
		}, want: ProviderInvocationSucceeded},
		{name: "failure", execute: func(context.Context) (Result, error) {
			return Result{Action: domain.ActionResult{Status: "failed", Error: &domain.StructuredError{Message: "failed"}}}, errors.New("failed")
		}, want: ProviderInvocationFailed},
		{name: "wrapped cancellation", execute: func(context.Context) (Result, error) {
			return Result{}, fmt.Errorf("provider stopped: %w", context.Canceled)
		}, want: ProviderInvocationCancelled},
		{name: "wrapped deadline", execute: func(context.Context) (Result, error) {
			return Result{}, fmt.Errorf("provider stopped: %w", context.DeadlineExceeded)
		}, want: ProviderInvocationTimedOut},
		{name: "provider local timeout", execute: func(context.Context) (Result, error) {
			return Result{Action: domain.ActionResult{Status: "failed", Error: &domain.StructuredError{Classification: "timeout", Message: "process exited"}}, ToolRun: &domain.ToolRun{TimedOut: true}}, errors.New("exit status 1")
		}, want: ProviderInvocationTimedOut},
		{name: "explicit cancellation status", execute: func(context.Context) (Result, error) {
			return Result{Action: domain.ActionResult{Status: "cancelled"}}, nil
		}, want: ProviderInvocationCancelled},
		{name: "explicit cancellation classification", execute: func(context.Context) (Result, error) {
			return Result{Action: domain.ActionResult{Status: "failed", Error: &domain.StructuredError{Classification: "canceled"}}}, errors.New("provider stopped")
		}, want: ProviderInvocationCancelled},
		{name: "explicit timeout status", execute: func(context.Context) (Result, error) {
			return Result{Action: domain.ActionResult{Status: "timeout"}}, nil
		}, want: ProviderInvocationTimedOut},
		{name: "late cancellation after ordinary failure", execute: func(ctx context.Context) (Result, error) {
			ctx.(interface{ cancel() }).cancel()
			return Result{Action: domain.ActionResult{Status: "failed", Error: &domain.StructuredError{Classification: "provider_error"}}}, errors.New("ordinary provider failure")
		}, want: ProviderInvocationFailed},
		{name: "late cancellation after success", execute: func(ctx context.Context) (Result, error) {
			ctx.(interface{ cancel() }).cancel()
			return Result{Action: domain.ActionResult{Status: "succeeded", Summary: "truth"}}, nil
		}, want: ProviderInvocationSucceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if strings.HasPrefix(test.name, "late cancellation") {
				cancelCtx, cancel := context.WithCancel(context.Background())
				ctx = cancellationTestContext{Context: cancelCtx, cancelFunc: cancel}
			}
			provider := &boundaryCapability{execute: test.execute}
			registry := NewRegistry()
			if err := registry.Register(provider); err != nil {
				t.Fatal(err)
			}
			invocations := &capturedInvocations{}
			result, providerErr := registry.Execute(ctx, Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "boundary", Input: json.RawMessage(`{}`)}, Policy: policy.Policy{AllowedCapabilities: []string{"boundary"}}, Scope: allowAllScope{}, DecisionRecorder: &capturedDecision{}, InvocationRecorder: invocations})
			if len(invocations.terminals) != 1 || invocations.terminals[0].Outcome != test.want {
				t.Fatalf("terminals=%#v want=%s", invocations.terminals, test.want)
			}
			if result.TerminalAuditError != nil || result.ProviderAttemptID == nil {
				t.Fatalf("result metadata=%#v", result)
			}
			if test.want == ProviderInvocationSucceeded && (providerErr != nil || result.Action.Status != "succeeded") {
				t.Fatalf("successful provider truth changed: result=%#v error=%v", result.Action, providerErr)
			}
		})
	}
}

type cancellationTestContext struct {
	context.Context
	cancelFunc context.CancelFunc
}

func (c cancellationTestContext) cancel() { c.cancelFunc() }

func TestRegistryOwnsProviderProvenanceMetadata(t *testing.T) {
	bogusAttemptID := domain.NewID()
	bogusRequestID := domain.NewID()
	bogusAuthorizationID := domain.NewID()
	bogusTerminalErr := errors.New("provider fabricated terminal degradation")
	provider := &boundaryCapability{execute: func(context.Context) (Result, error) {
		return Result{
			Action:            domain.ActionResult{RequestID: bogusRequestID, Status: "succeeded", Summary: "provider truth"},
			ToolRun:           &domain.ToolRun{Provider: "provider-controlled"},
			ProviderAttemptID: &bogusAttemptID,
			AdmissionProvenance: &ResultAdmissionProvenance{
				ProviderAttemptID:             bogusAttemptID,
				ActionRequestID:               bogusRequestID,
				ExecutionAuthorizationEventID: bogusAuthorizationID,
				Provider:                      "provider-controlled",
			},
			TerminalAuditError: bogusTerminalErr,
		}, nil
	}}
	registry := NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name        string
		terminalErr error
	}{
		{name: "successful terminal audit"},
		{name: "actual terminal audit failure", terminalErr: errors.New("actual terminal persistence failure")},
	} {
		t.Run(test.name, func(t *testing.T) {
			actionID, queueJobID := domain.NewID(), domain.NewID()
			decisions := &capturedDecision{}
			invocations := &capturedInvocations{terminalErr: test.terminalErr}
			result, err := registry.Execute(context.Background(), Request{Action: domain.ActionRequest{ID: actionID, Capability: "boundary", StepAttempt: 2, Input: json.RawMessage(`{}`)}, QueueJobID: &queueJobID, Policy: policy.Policy{AllowedCapabilities: []string{"boundary"}}, Scope: allowAllScope{}, DecisionRecorder: decisions, InvocationRecorder: invocations})
			if err != nil {
				t.Fatal(err)
			}
			if result.ProviderAttemptID == nil || *result.ProviderAttemptID != invocations.startIDs[0] || *result.ProviderAttemptID == bogusAttemptID {
				t.Fatalf("provider attempt metadata was not reclaimed: result=%#v starts=%#v", result, invocations.startIDs)
			}
			if result.Action.RequestID != actionID || result.Action.RequestID == bogusRequestID || result.Action.Status != "succeeded" || result.Action.Summary != "provider truth" {
				t.Fatalf("provider result truth changed: %#v", result.Action)
			}
			if result.ToolRun == nil || result.ToolRun.Provider != "boundary" {
				t.Fatalf("resolved provider metadata was not reclaimed: %#v", result.ToolRun)
			}
			if result.AdmissionProvenance == nil || result.AdmissionProvenance.ProviderAttemptID != invocations.startIDs[0] || result.AdmissionProvenance.ActionRequestID != actionID || result.AdmissionProvenance.StepAttempt != 2 || result.AdmissionProvenance.QueueJobID == nil || *result.AdmissionProvenance.QueueJobID != queueJobID || result.AdmissionProvenance.ExecutionAuthorizationEventID != decisions.ids[0] || result.AdmissionProvenance.Provider != "boundary" {
				t.Fatalf("trusted admission provenance was not reclaimed: result=%#v decisions=%#v starts=%#v", result.AdmissionProvenance, decisions.ids, invocations.startIDs)
			}
			if test.terminalErr == nil && result.TerminalAuditError != nil {
				t.Fatalf("provider-supplied terminal error survived: %v", result.TerminalAuditError)
			}
			if test.terminalErr != nil && (!errors.Is(result.TerminalAuditError, test.terminalErr) || errors.Is(result.TerminalAuditError, bogusTerminalErr)) {
				t.Fatalf("terminal error is not recorder-owned: %v", result.TerminalAuditError)
			}
		})
	}
}

func TestResultProvenanceMetadataIsNotSerialized(t *testing.T) {
	attemptID := domain.NewID()
	result := Result{
		Action:            domain.ActionResult{Status: "succeeded"},
		ProviderAttemptID: &attemptID,
		AdmissionProvenance: &ResultAdmissionProvenance{
			ProviderAttemptID: attemptID,
			Provider:          "internal-provider-secret",
		},
		TerminalAuditError: errors.New("internal database detail"),
	}
	serialized, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), string(attemptID)) || strings.Contains(string(serialized), "internal-provider-secret") || strings.Contains(string(serialized), "internal database detail") || strings.Contains(string(serialized), "ProviderAttemptID") || strings.Contains(string(serialized), "AdmissionProvenance") || strings.Contains(string(serialized), "TerminalAuditError") {
		t.Fatalf("Registry provenance metadata leaked into Result JSON: %s", serialized)
	}
}

type allowAllScope struct{}

func (allowAllScope) Allows(string) bool { return true }
