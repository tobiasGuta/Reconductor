package capability

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
)

func TestPredecodeAdmissionAllocationDoesNotScale(t *testing.T) {
	for _, size := range []int{1024, 1 << 20, 32 << 20} {
		payload := make(json.RawMessage, size)
		measured := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				r := Result{}
				r.Action.Output = payload
				if err := EnforceOutputBudget(&r, 256); err == nil || len(r.Action.Output) != 0 || r.OutputLimit == nil {
					b.Fatal("byte admission failed")
				}
			}
		})
		if measured.AllocedBytesPerOp() > 1024 {
			t.Fatalf("size=%d allocation=%d", size, measured.AllocedBytesPerOp())
		}
		t.Logf("rejected bytes=%d allocated bytes/op=%d allocations/op=%d", size, measured.AllocedBytesPerOp(), measured.AllocsPerOp())
	}
}

func TestRegistryByteAdmissionPrecedesStrictDecode(t *testing.T) {
	provider := &boundaryCapability{execute: func(context.Context) (Result, error) {
		return Result{Action: domain.ActionResult{Status: "succeeded", Output: json.RawMessage(strings.Repeat("[", domain.ResultEnvelopeMaxBytes+1))}}, nil
	}}
	registry := NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	invocations := &capturedInvocations{}
	result, err := registry.Execute(context.Background(), Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "boundary", Input: json.RawMessage(`{}`)}, Policy: policy.Policy{AllowedCapabilities: []string{"boundary"}}, Scope: allowAllScope{}, DecisionRecorder: &capturedDecision{}, InvocationRecorder: invocations})
	if err == nil || result.Action.Error == nil || result.Action.Error.Classification != "result_contract_limit" || result.Action.Error.Retryable || len(result.Action.Output) != 0 || len(invocations.starts) != 1 || len(invocations.terminals) != 1 || invocations.terminals[0].Outcome != ProviderInvocationFailed {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}
