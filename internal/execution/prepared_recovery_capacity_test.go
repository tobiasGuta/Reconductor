package execution

import (
	"errors"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestPreparedRecoveryAuthorityBoundary(t *testing.T) {
	if err := validatePreparedRecoveryAuthority(domain.PreparedSetOutputAuthorityMaxBytes); err != nil {
		t.Fatalf("exact authority: %v", err)
	}
	for _, capacity := range []int64{0, domain.PreparedSetOutputAuthorityMaxBytes + 1} {
		err := validatePreparedRecoveryAuthority(capacity)
		var unresolved *domain.UnresolvedPersistenceError
		if !errors.As(err, &unresolved) {
			t.Fatalf("capacity=%d error=%v", capacity, err)
		}
	}
}
