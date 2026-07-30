//go:build operational

package operational

import (
	"context"
	"os"
	"os/signal"
	"testing"
	"time"
)

func TestApprovalLifecycle(t *testing.T) {
	operationalRunMu.Lock()
	t.Cleanup(operationalRunMu.Unlock)

	timeout := 7 * time.Minute
	if value := os.Getenv("RECONDUCTOR_E2E_TIMEOUT"); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed <= 0 {
			t.Fatalf("RECONDUCTOR_E2E_TIMEOUT=%q must be a positive duration", value)
		}
		timeout = parsed
	}
	timeoutCtx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	ctx, stop := signal.NotifyContext(timeoutCtx, os.Interrupt)
	t.Cleanup(stop)

	h := newHarness(t, ctx)
	h.preflight()
	h.prepare()
	h.startInfrastructure()
	h.buildBinaries()
	h.validateTemplate()
	h.migrate()
	h.startScheduler()

	rejected := h.runToApproval("reject")
	h.assertPreApproval(rejected)
	h.assertGuardScanCount(0)
	h.reject(rejected)
	h.assertRejected(rejected)
	h.assertGuardScanCount(0)

	approved := h.runToApproval("approve")
	h.assertPreApproval(approved)
	h.assertGuardScanCount(0)
	h.approveWithoutResume(approved)
	h.assertGuardScanCount(0)
	h.resumeAndComplete(approved)
	h.assertApprovedCompletion(approved)
}
