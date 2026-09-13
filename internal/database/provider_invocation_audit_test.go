package database

import (
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/capability"
)

func TestProviderTerminalEventIncludesTimeout(t *testing.T) {
	event, message, err := providerTerminalEvent(capability.ProviderInvocationTimedOut)
	if err != nil {
		t.Fatal(err)
	}
	if event != "provider_invocation_timed_out" || message == "" {
		t.Fatalf("timeout mapping=(%q,%q)", event, message)
	}
	if _, _, err := providerTerminalEvent(capability.ProviderInvocationOutcome("other")); err == nil {
		t.Fatal("unknown provider terminal outcome was accepted")
	}
}
