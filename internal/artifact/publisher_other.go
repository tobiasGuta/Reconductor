//go:build !windows && !linux

package artifact

import (
	"context"
	"fmt"
)

func (l *Local) AcquirePublisher(context.Context, StoreIdentity) (PublisherGuard, error) {
	return nil, fmt.Errorf("%w: operating system is unsupported", ErrPublisherLockUnsupported)
}

func (l *Local) AcquirePreparedRecovery(context.Context, StoreIdentity) (PreparedRecoveryGuard, error) {
	return nil, fmt.Errorf("%w: operating system is unsupported", ErrPreparedStoreUnsupported)
}
