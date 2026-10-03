//go:build !linux

package exactactivation

import (
	"errors"
	"testing"
)

func TestUnsupportedPlatform(t *testing.T) {
	owner, err := AcquireWorkerListener()
	if owner != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatal("non-Linux activation did not fail closed")
	}
	if !errors.Is(VerifyPeerCredentials(), ErrUnsupported) {
		t.Fatal("non-Linux credentials did not fail closed")
	}
}
