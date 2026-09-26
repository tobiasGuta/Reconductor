package database

import (
	"errors"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestPreparedAdmissionRequiresExactCurrentAttemptAndState(t *testing.T) {
	for _, state := range []domain.StepStatus{domain.StepRunning, domain.StepRetryable, domain.StepFailed, domain.StepCancelled, domain.StepSucceeded, domain.StepPending} {
		for _, attempt := range []int{0, 1, 2, 3} {
			err := requireCurrentPreparedAttempt(lockedResultLineage{stepStatus: state, attemptCount: 2}, &capability.ResultAdmissionProvenance{StepAttempt: attempt})
			want := attempt == 2 && (state == domain.StepRunning || state == domain.StepRetryable)
			if (err == nil) != want {
				t.Fatalf("state=%s attempt=%d error=%v", state, attempt, err)
			}
		}
	}
}

func TestPreparedEvidenceStatusRequiresConfiguredAvailableCapacity(t *testing.T) {
	valid := PreparedEvidenceStatus{MaxOpenSets: 4, MaxSetBytes: 1024, MaxUnresolvedBytes: 4096, OpenSets: 3, UnresolvedBytes: 3072}
	if err := valid.RequireAdmissionCapacity(); err != nil {
		t.Fatalf("valid capacity: %v", err)
	}

	for name, status := range map[string]PreparedEvidenceStatus{
		"invalid limits":    {MaxOpenSets: 0, MaxSetBytes: 1024, MaxUnresolvedBytes: 4096},
		"invalid occupancy": {MaxOpenSets: 4, MaxSetBytes: 1024, MaxUnresolvedBytes: 4096, OpenSets: -1},
		"open sets":         {MaxOpenSets: 4, MaxSetBytes: 1024, MaxUnresolvedBytes: 8192, OpenSets: 4},
		"byte limit":        {MaxOpenSets: 8, MaxSetBytes: 1024, MaxUnresolvedBytes: 4096, UnresolvedBytes: 3073},
	} {
		t.Run(name, func(t *testing.T) {
			err := status.RequireAdmissionCapacity()
			if err == nil {
				t.Fatal("expected capacity rejection")
			}
			if name == "open sets" || name == "byte limit" {
				var limit *PreparedAdmissionLimitError
				if !errors.As(err, &limit) || !strings.Contains(err.Error(), "prepared-recover") {
					t.Fatalf("error=%v", err)
				}
			}
		})
	}
}
