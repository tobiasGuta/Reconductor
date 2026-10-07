package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	commandprovider "github.com/tobiasGuta/Reconductor/internal/providers/command"
)

type countedOSRunner struct {
	commandprovider.OSRunner
	calls int
}

func (r *countedOSRunner) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int, error) {
	r.calls++
	return r.OSRunner.Run(ctx, name, args, stdin)
}

func TestProductionOutputLimitNeverRetriesAndRetainsUnknown(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "adopted", true: "commit_unknown"}[unknown], func(t *testing.T) {
			runner := &countedOSRunner{}
			registry := capability.NewRegistry()
			provider := commandprovider.New(commandprovider.Definition{Name: "resolve.dns", Provider: "helper", Executable: os.Args[0], Version: "1", Risk: policy.Low, Timeout: 5 * time.Second, BuildInvocation: func(commandprovider.Input, policy.Policy) (commandprovider.Invocation, error) {
				return commandprovider.Invocation{Args: []string{"-test.run=^TestLimitExecutionProcess$", "--", "limit-execution"}}, nil
			}}, runner, nil)
			if err := registry.Register(provider); err != nil {
				t.Fatal(err)
			}
			store, artifacts := &capturedStore{reservedCapacity: 64 << 10}, &capturedArtifacts{}
			if unknown {
				store.err = &injectedCommitUnknown{operation: "reservation"}
			}
			req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "resolve.dns", StepAttempt: 1, Input: json.RawMessage(`{"targets":["https://example.test/"]}`), IdempotencyKey: "output-limit"}, Policy: policy.Policy{AllowedCapabilities: []string{"resolve.dns"}}, Scope: allowedScope{}}
			result, err := (Service{Registry: registry, Store: store, Artifacts: artifacts, ProgramID: domain.NewID()}).Execute(context.Background(), req)
			if err == nil || runner.calls != 1 || result.Envelope == nil || result.Envelope.Error == nil || result.Envelope.Error.Code != "result_contract_limit" || result.Envelope.Error.Retryable || result.Envelope.ProviderOutcome != domain.ResultProviderFailed {
				t.Fatalf("calls=%d result=%#v err=%v", runner.calls, result.Envelope, err)
			}
			if domain.PersistenceUnresolved(err) != unknown {
				t.Fatalf("unresolved=%v want=%v: %v", domain.PersistenceUnresolved(err), unknown, err)
			}
			if unknown && (store.terminalized != 0 || len(artifacts.prepared) == 0 || len(store.cleanedSets) != 0) {
				t.Fatal("uncertain rejection result lost prepared ownership")
			}
			if !unknown && (!store.persisted || store.step.Status != domain.StepFailed) {
				t.Fatal("bounded rejection was not adopted as nonretryable failure")
			}
			for _, put := range artifacts.requests {
				if len(put.Data) > 64<<10 {
					t.Fatal("excess output retained")
				}
			}
		})
	}
}

func TestLimitExecutionProcess(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "limit-execution" {
		return
	}
	chunk := bytes.Repeat([]byte("x"), 8192)
	for range 8192 {
		if _, err := os.Stdout.Write(chunk); err != nil {
			time.Sleep(30 * time.Second)
			os.Exit(2)
		}
	}
	os.Exit(0)
}
