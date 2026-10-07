package exactsandbox

import (
	"context"
	"fmt"
	"reflect"

	"github.com/tobiasGuta/Reconductor/internal/exactexecution"
)

// Runner is infrastructure for one fixed Reconductor-owned protocol runtime.
// It receives bounded execution bytes and their digest, never authority objects
// or an executable choice. This slice supplies no production implementation.
type Runner interface {
	Run(context.Context, EncodedExecution) (EncodedResult, error)
}

// SandboxExecutor is a library adapter only, with no production broker caller.
// The broker completes its authority handoff before invoking this adapter.
type SandboxExecutor struct{ runner Runner }

func NewExecutor(runner Runner) (*SandboxExecutor, error) {
	if isNilRunner(runner) {
		return nil, fmt.Errorf("%w: runner required", ErrProtocol)
	}
	return &SandboxExecutor{runner: runner}, nil
}

func isNilRunner(runner Runner) bool {
	if runner == nil {
		return true
	}
	value := reflect.ValueOf(runner)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (s *SandboxExecutor) Execute(ctx context.Context, e exactexecution.Execution) (exactexecution.Result, error) {
	if s == nil || s.runner == nil || ctx == nil {
		return exactexecution.Result{}, fmt.Errorf("%w: runner and context required", ErrProtocol)
	}
	if err := ctx.Err(); err != nil {
		return exactexecution.Result{}, err
	}
	encoded, err := FromExecution(e)
	if err != nil {
		return exactexecution.Result{}, err
	}
	// Caller context (including scheduler fence) is forwarded without detaching.
	output, err := s.runner.Run(ctx, encoded)
	if err != nil {
		return exactexecution.Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return exactexecution.Result{}, err
	}
	return DecodeResult(output, encoded.Digest())
}

var _ exactexecution.Executor = (*SandboxExecutor)(nil)
