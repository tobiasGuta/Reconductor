package exactsandbox

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/exactexecution"
)

var constructorPanicRunnerCalls atomic.Int64

type constructorPanicRunner struct{}

func (r *constructorPanicRunner) Run(_ context.Context, input EncodedExecution) (EncodedResult, error) {
	constructorPanicRunnerCalls.Add(1)
	if r == nil {
		panic("nil Runner receiver reached")
	}
	return EncodeResult(input.Digest(), true)
}

type constructorMapRunner map[string]bool
type constructorSliceRunner []bool
type constructorFuncRunner func(context.Context, EncodedExecution) (EncodedResult, error)
type constructorChanRunner chan bool
type constructorValueRunner struct{}

func (constructorMapRunner) Run(_ context.Context, input EncodedExecution) (EncodedResult, error) {
	return EncodeResult(input.Digest(), true)
}
func (constructorSliceRunner) Run(_ context.Context, input EncodedExecution) (EncodedResult, error) {
	return EncodeResult(input.Digest(), true)
}
func (r constructorFuncRunner) Run(ctx context.Context, input EncodedExecution) (EncodedResult, error) {
	return r(ctx, input)
}
func (constructorChanRunner) Run(_ context.Context, input EncodedExecution) (EncodedResult, error) {
	return EncodeResult(input.Digest(), true)
}
func (constructorValueRunner) Run(_ context.Context, input EncodedExecution) (EncodedResult, error) {
	return EncodeResult(input.Digest(), true)
}

func TestNewExecutorRejectsNilRunners(t *testing.T) {
	var pointer *fakeRunner
	var panicPointer *constructorPanicRunner
	var wrapped Runner = pointer
	constructorPanicRunnerCalls.Store(0)
	for _, test := range []struct {
		name   string
		runner Runner
	}{
		{"literal nil", nil},
		{"pointer", pointer},
		{"panic receiver", panicPointer},
		{"wrapped interface", wrapped},
		{"map", constructorMapRunner(nil)},
		{"slice", constructorSliceRunner(nil)},
		{"func", constructorFuncRunner(nil)},
		{"chan", constructorChanRunner(nil)},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor, err := NewExecutor(test.runner)
			if !errors.Is(err, ErrProtocol) || executor != nil {
				t.Fatalf("nil Runner accepted: executor=%v err=%v", executor, err)
			}
		})
	}
	if calls := constructorPanicRunnerCalls.Load(); calls != 0 {
		t.Fatalf("constructor invoked Runner %d times", calls)
	}
}

func TestNewExecutorAcceptsNonNilRunners(t *testing.T) {
	for _, test := range []struct {
		name   string
		runner Runner
	}{
		{"pointer", &fakeRunner{}},
		{"value", constructorValueRunner{}},
		{"map", constructorMapRunner{}},
		{"slice", constructorSliceRunner{}},
		{"func", constructorFuncRunner(constructorValueRunner{}.Run)},
		{"chan", make(constructorChanRunner)},
	} {
		t.Run(test.name, func(t *testing.T) {
			executor, err := NewExecutor(test.runner)
			if err != nil || executor == nil {
				t.Fatalf("non-nil Runner rejected: %v", err)
			}
		})
	}
}

func TestSandboxExecutorInvalidHostInputs(t *testing.T) {
	if _, err := NewExecutor(nil); !errors.Is(err, ErrProtocol) {
		t.Fatal("nil runner accepted")
	}
	r := &fakeRunner{}
	s, _ := NewExecutor(r)
	if _, err := s.Execute(context.Background(), exactexecution.Execution{}); !errors.Is(err, ErrProtocol) || r.calls.Load() != 0 {
		t.Fatal("zero Execution reached runner")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Execute(ctx, exactexecution.Execution{}); !errors.Is(err, context.Canceled) || r.calls.Load() != 0 {
		t.Fatal("cancelled call reached runner")
	}
	for _, executor := range []*SandboxExecutor{nil, {}} {
		if _, err := executor.Execute(context.Background(), exactexecution.Execution{}); !errors.Is(err, ErrProtocol) {
			t.Fatal("invalid adapter accepted")
		}
	}
}
