//go:build windows

package artifact

import (
	"context"
	"fmt"
)

func (l *Local) AcquirePublisher(context.Context, StoreIdentity) (PublisherGuard, error) {
	return nil, fmt.Errorf("%w: Windows cannot satisfy flock and directory durability", ErrPublisherLockUnsupported)
}

func (l *Local) AcquirePreparedRecovery(context.Context, StoreIdentity) (PreparedRecoveryGuard, error) {
	return nil, fmt.Errorf("%w: Windows cannot satisfy exclusive store locking and descriptor-relative no-follow traversal", ErrPreparedStoreUnsupported)
}
