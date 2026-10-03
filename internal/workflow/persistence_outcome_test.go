package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"testing"
	"time"
)

type uncertainExecutor struct {
	calls int
	err   error
}

func (e *uncertainExecutor) Execute(_ context.Context, req capability.Request) (capability.Result, error) {
	e.calls++
	return capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Error: &domain.StructuredError{Classification: "provider_error", Retryable: true}}}, e.err
}

func TestUnresolvedPersistenceNeverRetriesOrCompletesStep(t *testing.T) {
	for _, boundary := range []string{"allocation", "prepared seal", "reservation", "publishing", "final seal", "adoption", "terminalization", "oversized rejection"} {
		t.Run(boundary, func(t *testing.T) {
			calls := 0
			r := registryFor(t, testCap{"x", &calls, true})
			executor := &uncertainExecutor{err: errors.Join(context.Canceled, &domain.UnresolvedPersistenceError{Err: errors.New(boundary)})}
			engine := Engine{Registry: r, Executor: executor, Persister: &memoryPersist{}, Policy: policy.Policy{AllowedCapabilities: []string{"x"}}, Scope: allScope{}}
			def := Definition{ID: domain.NewID(), Name: "uncertain", Version: "1", Steps: []Step{{ID: "a", Capability: "x", Input: json.RawMessage(`{}`), Retry: RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond}}}}
			state, err := engine.Run(context.Background(), def, nil, domain.Task{ID: domain.NewID(), WorkflowDefinitionID: def.ID}, nil)
			if !domain.PersistenceUnresolved(err) || executor.calls != 1 {
				t.Fatalf("calls=%d err=%v", executor.calls, err)
			}
			step := state.Steps["a"].Run
			if step.CompletedAt != nil || step.Status == domain.StepFailed || step.Status == domain.StepCancelled || state.Run.Status == domain.RunFailed || state.Run.Status == domain.RunCancelled {
				t.Fatalf("uncertainty terminalized: step=%s workflow=%s", step.Status, state.Run.Status)
			}
		})
	}
}
