package capability

import "testing"

func TestProviderInvocationOutcomeIsClosedAndIncludesTimeout(t *testing.T) {
	for _, outcome := range []ProviderInvocationOutcome{
		ProviderInvocationSucceeded,
		ProviderInvocationFailed,
		ProviderInvocationCancelled,
		ProviderInvocationTimedOut,
	} {
		if err := outcome.Validate(); err != nil {
			t.Fatalf("outcome %q rejected: %v", outcome, err)
		}
	}
	if err := ProviderInvocationOutcome("other").Validate(); err == nil {
		t.Fatal("unknown provider invocation outcome accepted")
	}
}
