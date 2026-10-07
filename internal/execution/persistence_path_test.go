package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

func TestAdmittedLargeDiagnosticRemainsCompleteWhileWorkflowProjectionIsBounded(t *testing.T) {
	provider := &retryablePathProvider{diagnostic: strings.Repeat("complete diagnostic detail\n", 4096)}
	registry := capability.NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	store, artifacts := &capturedStore{}, &capturedArtifacts{}
	executor := Service{Registry: registry, Store: store, Artifacts: artifacts, ProgramID: domain.NewID()}
	checkpoints := &pathCheckpoint{}
	engine := workflow.Engine{Registry: registry, Executor: executor, Persister: checkpoints, Policy: policy.Policy{AllowedCapabilities: []string{"retryable.result"}}, Scope: allowedScope{}}
	def := workflow.Definition{ID: domain.NewID(), Name: "diagnostic projection", Version: "1", Steps: []workflow.Step{{ID: "a", Capability: "retryable.result", Input: json.RawMessage(`{}`), Retry: workflow.RetryPolicy{MaxAttempts: 1}}}}
	state, err := engine.Run(context.Background(), def, nil, domain.Task{ID: domain.NewID(), WorkflowDefinitionID: def.ID}, nil)
	if err == nil || domain.PersistenceUnresolved(err) || provider.calls != 1 || !store.persisted {
		t.Fatalf("calls=%d admitted=%v err=%v", provider.calls, store.persisted, err)
	}
	if len(err.Error()) > domain.SafeMessageMaxBytes || len(state.Steps["a"].Run.ErrorDetails) > domain.SafeMessageMaxBytes {
		t.Fatal("unbounded workflow diagnostic")
	}
	found := false
	for ordinal, entry := range artifacts.compiled.Artifacts {
		if entry.Reference.Role == domain.ArtifactRoleProviderDiagnostic {
			key, _ := domain.PreparedMemberKey(artifacts.compiled.PreparedSetID, ordinal)
			data := artifacts.prepared[key]
			if !bytes.Contains(data, []byte(provider.diagnostic)) || int64(len(data)) != entry.Reference.ContentSizeBytes {
				t.Fatal("admitted diagnostic was truncated")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("admitted diagnostic missing")
	}
	for _, raw := range checkpoints.snapshots {
		if bytes.Contains(raw, []byte(strings.Repeat("complete diagnostic detail", 100))) || len(raw) > 256<<10 {
			t.Fatal("diagnostic scaled checkpoint")
		}
	}
}

type retryablePathProvider struct {
	retryableResultCapability
	calls      int
	diagnostic string
}

func (p *retryablePathProvider) Execute(ctx context.Context, req capability.Request) (capability.Result, error) {
	p.calls++
	r, err := p.retryableResultCapability.Execute(ctx, req)
	if p.diagnostic != "" {
		r.Action.Summary = p.diagnostic
		r.Action.Error.Message = p.diagnostic
		r.RawDiagnostic = []byte(p.diagnostic)
		err = errors.New(p.diagnostic)
	}
	return r, err
}

type pathCheckpoint struct{ snapshots [][]byte }

func (p *pathCheckpoint) Save(_ context.Context, state *workflow.State) error {
	raw, err := json.Marshal(state)
	p.snapshots = append(p.snapshots, raw)
	return err
}

func TestRealProviderExecutionWorkflowPathNeverRetriesUnresolvedPersistence(t *testing.T) {
	unknown := &injectedCommitUnknown{operation: "path acknowledgement"}
	for _, boundary := range []string{"allocation", "prepared seal", "reservation", "publishing", "final seal", "adoption", "admission authority unavailable", "terminalization", "oversized rejection"} {
		t.Run(boundary, func(t *testing.T) {
			provider := &retryablePathProvider{diagnostic: strings.Repeat("provider diagnostic ", 2048)}
			registry := capability.NewRegistry()
			if err := registry.Register(provider); err != nil {
				t.Fatal(err)
			}
			store := &capturedStore{}
			switch boundary {
			case "allocation":
				store.startErr = unknown
			case "prepared seal":
				store.terminalErr = unknown
			case "reservation":
				store.err = unknown
			case "publishing":
				store.publishingErr = unknown
			case "final seal":
				store.sealErr = unknown
			case "adoption":
				store.adoptErrors = []error{unknown}
			case "admission authority unavailable":
				store.adoptErrors = []error{errors.New("live scheduler lease expired")}
			case "terminalization":
				store.publishingErr = errors.New("known transition failure")
				store.terminalizeErr = unknown
			case "oversized rejection":
				store.reservedCapacity = 1024
				store.rejectionErr = unknown
			}
			artifacts := &capturedArtifacts{}
			executor := Service{Registry: registry, Store: store, Artifacts: artifacts, ProgramID: domain.NewID()}
			checkpoints := &pathCheckpoint{}
			engine := workflow.Engine{Registry: registry, Executor: executor, Persister: checkpoints, Policy: policy.Policy{AllowedCapabilities: []string{"retryable.result"}}, Scope: allowedScope{}}
			def := workflow.Definition{ID: domain.NewID(), Name: "uncertain result", Version: "1", Steps: []workflow.Step{{ID: "a", Capability: "retryable.result", Input: json.RawMessage(`{}`), Retry: workflow.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond}}}}
			state, err := engine.Run(context.Background(), def, nil, domain.Task{ID: domain.NewID(), WorkflowDefinitionID: def.ID}, nil)
			wantCalls := 1
			if boundary == "allocation" {
				wantCalls = 0
			}
			if !domain.PersistenceUnresolved(err) || provider.calls != wantCalls {
				t.Fatalf("calls=%d want=%d err=%v", provider.calls, wantCalls, err)
			}
			step := state.Steps["a"].Run
			if step.AttemptCount > 1 || store.start.StepAttempt != 1 || store.effectiveSaves != 1 || step.CompletedAt != nil || step.Status == domain.StepFailed || step.Status == domain.StepCancelled || state.Run.Status == domain.RunFailed || state.Run.Status == domain.RunCancelled {
				t.Fatalf("contradictory state: %#v / %s", step, state.Run.Status)
			}
			if store.persisted || artifacts.deleteCalls != 0 {
				t.Fatal("unresolved result was finalized or cleaned")
			}
			for _, raw := range checkpoints.snapshots {
				if strings.Contains(string(raw), provider.diagnostic) {
					t.Fatal("full provider diagnostic leaked into checkpoint")
				}
			}
			if len(err.Error()) > domain.SafeMessageMaxBytes {
				t.Fatal("unbounded workflow error")
			}
		})
	}
}
