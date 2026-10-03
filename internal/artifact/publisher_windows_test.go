//go:build windows

package artifact

import (
	"context"
	"errors"
	"testing"
)

func TestLocalPublisherFailsClosedOnWindows(t *testing.T) {
	store := &Local{}
	guard, err := store.AcquirePublisher(context.Background(), StoreIdentity{})
	if guard != nil || !errors.Is(err, ErrPublisherLockUnsupported) {
		t.Fatalf("guard=%#v error=%v", guard, err)
	}
}

func TestPreparedRecoveryFailsClosedOnWindows(t *testing.T) {
	store := &Local{}
	guard, err := store.AcquirePreparedRecovery(context.Background(), StoreIdentity{})
	if guard != nil || !errors.Is(err, ErrPreparedStoreUnsupported) {
		t.Fatalf("guard=%#v error=%v", guard, err)
	}
}
