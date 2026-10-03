package capability

import (
	"context"
	"fmt"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type outputBudgetKey struct{}

// Prepared executions use their already allocated database reservation. Legacy
// callers without prepared storage may produce only a control-envelope-sized
// result. This is a byte authority, not permission to retain rejected excess.
func WithOutputBudget(ctx context.Context, bytes int64) context.Context {
	return context.WithValue(ctx, outputBudgetKey{}, bytes)
}

func OutputBudget(ctx context.Context) int64 {
	if n, ok := ctx.Value(outputBudgetKey{}).(int64); ok {
		return n
	}
	return domain.ResultEnvelopeMaxBytes
}

type OutputLimitError struct{ Limit int64 }

func (e *OutputLimitError) Error() string {
	return fmt.Sprintf("provider output exceeds result byte authority (%d bytes)", e.Limit)
}
func (e *OutputLimitError) ResultContractLimit() domain.ResultContractLimitV1 {
	return domain.ResultContractLimitV1{Subject: domain.LimitPreparedEvidence, Unit: domain.LimitBytes, Limit: uint64(e.Limit), Observed: uint64(e.Limit) + 1}
}

// RejectOutput retains only deterministic bounded facts, never a truncated
// semantic value that could be mistaken for a successful result.
func RejectOutput(result *Result, limit int64) error {
	err := &OutputLimitError{Limit: limit}
	fact := err.ResultContractLimit()
	rejectResultLimit(result, fact, err.Error())
	return err
}

func RejectSemanticItems(result *Result) error {
	err := fmt.Errorf("provider output exceeds semantic item authority (%d items)", domain.InlineSemanticJSONMaxNodes)
	fact := domain.ResultContractLimitV1{Subject: domain.LimitSemanticOutput, Unit: domain.LimitItems, Limit: domain.InlineSemanticJSONMaxNodes, Observed: domain.InlineSemanticJSONMaxNodes + 1}
	rejectResultLimit(result, fact, err.Error())
	return err
}

func rejectResultLimit(result *Result, fact domain.ResultContractLimitV1, message string) {
	result.OutputLimit = &fact
	result.Action.Output = nil
	result.RawStdout, result.RawStderr, result.RawDiagnostic = nil, nil, nil
	result.Action.Status = "failed"
	result.Action.Summary = "provider output exceeded result contract"
	result.Action.Error = &domain.StructuredError{Classification: "result_contract_limit", Message: message, Retryable: false}
	result.ProviderOutcome = domain.ResultProviderFailed
}

// Check lengths before string conversions, redaction, copies, or JSON decoding.
func EnforceOutputBudget(result *Result, limit int64) error {
	// Direct/in-process callers must not bypass evidence admission through a
	// workflow-facing string before redaction or error-code normalization.
	if int64(len(result.Action.Summary)) > limit {
		return RejectOutput(result, limit)
	}
	if result.Action.Error != nil && (int64(len(result.Action.Error.Message)) > limit || int64(len(result.Action.Error.Classification)) > limit) {
		return RejectOutput(result, limit)
	}
	remaining := limit
	for _, n := range []int{len(result.Action.Output), len(result.RawStdout), len(result.RawStderr), len(result.RawDiagnostic)} {
		if int64(n) > remaining {
			return RejectOutput(result, limit)
		}
		remaining -= int64(n)
	}
	return nil
}
