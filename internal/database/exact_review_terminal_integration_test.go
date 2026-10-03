package database

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
)

// The wrapper observes acquisition and can pause the real verified reader's
// Close. It never replaces the filesystem lock or digest verification.
type observedExactReader struct {
	local          *artifact.Local
	acquireEntered chan struct{}
	verifyEntered  chan struct{}
	releaseVerify  chan struct{}
	onGuardClose   func()
}

func (r *observedExactReader) OpenVerified(ctx context.Context, ref domain.ResultArtifactRefV1) (io.ReadCloser, error) {
	return r.local.OpenVerified(ctx, ref)
}

func (r *observedExactReader) AcquireVerifiedEvidence(ctx context.Context) (artifact.VerifiedEvidenceGuard, error) {
	if r.acquireEntered != nil {
		close(r.acquireEntered)
	}
	guard, err := r.local.AcquireVerifiedEvidence(ctx)
	if err != nil {
		return nil, err
	}
	return &observedExactGuard{VerifiedEvidenceGuard: guard, reader: r}, nil
}

type observedExactGuard struct {
	artifact.VerifiedEvidenceGuard
	reader *observedExactReader
}

func (g *observedExactGuard) OpenVerified(ctx context.Context, ref domain.ResultArtifactRefV1) (io.ReadCloser, error) {
	verified, err := g.VerifiedEvidenceGuard.OpenVerified(ctx, ref)
	if err != nil {
		return nil, err
	}
	return &observedExactCloser{ReadCloser: verified, ctx: ctx, reader: g.reader}, nil
}

func (g *observedExactGuard) Close() error {
	if g.reader.onGuardClose != nil {
		g.reader.onGuardClose()
	}
	return g.VerifiedEvidenceGuard.Close()
}

type observedExactCloser struct {
	io.ReadCloser
	ctx    context.Context
	reader *observedExactReader
}

func (r *observedExactCloser) Close() error {
	if r.reader.verifyEntered != nil {
		close(r.reader.verifyEntered)
		select {
		case <-r.reader.releaseVerify:
		case <-r.ctx.Done():
			return errors.Join(r.ReadCloser.Close(), r.ctx.Err())
		}
	}
	return r.ReadCloser.Close()
}

func waitExactSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("exact review did not reach the expected boundary")
	}
}

func assertExactWorkflowUnlocked(t *testing.T, store *Store, ctx context.Context, runID domain.ID) {
	t.Helper()
	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var id domain.ID
	if err := tx.QueryRow(ctx, `SELECT id FROM workflow_runs WHERE id=$1 FOR UPDATE NOWAIT`, runID).Scan(&id); err != nil {
		t.Fatalf("approval/preparation held workflow lock while waiting for store: %v", err)
	}
}

func constrainExactTestPool(t *testing.T, store *Store, ctx context.Context, maxConnections int32) {
	t.Helper()
	config := store.Pool.Config()
	config.MaxConns = maxConnections
	replacement, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := replacement.Ping(ctx); err != nil {
		replacement.Close()
		t.Fatal(err)
	}
	previous := store.Pool
	store.Pool = replacement
	previous.Close()
}

func blockExactWorkflow(t *testing.T, store *Store, ctx context.Context, workflowRunID domain.ID) (*pgx.Conn, pgx.Tx) {
	t.Helper()
	connection, err := pgx.ConnectConfig(ctx, store.Pool.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close(ctx) })
	tx, err := connection.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	var id domain.ID
	if err := tx.QueryRow(ctx, `SELECT id FROM workflow_runs WHERE id=$1 FOR UPDATE`, workflowRunID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return connection, tx
}

func waitExactPoolAcquired(t *testing.T, pool *pgxpool.Pool, expected int32) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		if pool.Stat().AcquiredConns() == expected {
			return
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			stats := pool.Stat()
			t.Fatalf("pool did not saturate: expected=%d acquired=%d total=%d idle=%d", expected, stats.AcquiredConns(), stats.TotalConns(), stats.IdleConns())
		}
	}
}

func exactCitedPreparationInput(t *testing.T, name string) (exactDispatchFixture, exactaction.ReviewContextV1, domain.ID) {
	t.Helper()
	f := pendingExactFixture(t, name)
	evidence := exactReviewEvidenceSet(t, f, 1)
	exactReviewLocalBytes(t, f, evidence)
	base, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	review := base.Review
	review.SupportingEvidence = []exactaction.Citation{{ArtifactID: evidence[0].ref.ArtifactID, ArtifactSHA256: evidence[0].ref.ContentSHA256, Locator: "line 1"}}
	x := recordScheduledProviderAdmission(t, f.result, exactFixtureContext(f.result), f.result.env.programID, scheduledProviderAction(f.result, 1), nil, "fixture")
	return f, review, x.ProviderAttemptID
}

func prepareExactCitedInput(ctx context.Context, f exactDispatchFixture, review exactaction.ReviewContextV1, providerAttemptID domain.ID) (domain.ID, error) {
	return f.result.env.store.PrepareExactActionApproval(ctx, f.result.env.programID, f.step, providerAttemptID,
		exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/allowed/review"},
		review, "reviewer", time.Now().Add(time.Hour))
}

func TestExactCitedOperationsUseOneConnection(t *testing.T) {
	t.Run("preparation", func(t *testing.T) {
		f, review, providerAttemptID := exactCitedPreparationInput(t, "exact-one-connection-preparation")
		store := f.result.env.store
		constrainExactTestPool(t, store, f.result.env.ctx, 1)
		ctx, cancel := context.WithTimeout(exactFixtureContext(f.result), 5*time.Second)
		defer cancel()
		if _, err := prepareExactCitedInput(ctx, f, review, providerAttemptID); err != nil {
			t.Fatalf("cited preparation required another pooled connection: %v", err)
		}
		if stats := store.Pool.Stat(); stats.MaxConns() != 1 || stats.AcquiredConns() != 0 {
			t.Fatalf("unexpected pool state after preparation: max=%d acquired=%d total=%d idle=%d", stats.MaxConns(), stats.AcquiredConns(), stats.TotalConns(), stats.IdleConns())
		}
	})

	t.Run("approve", func(t *testing.T) {
		f := pendingExactFixture(t, "exact-one-connection-approve")
		evidence := exactReviewEvidenceSet(t, f, 1)
		approvalID, local := exactReviewPrepareWithEvidence(t, f, evidence)
		store, ctx := f.result.env.store, f.result.env.ctx
		view, err := store.GetExactApprovalReview(ctx, approvalID)
		if err != nil {
			t.Fatal(err)
		}
		constrainExactTestPool(t, store, ctx, 1)
		decisionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := store.DecideExactApproval(decisionCtx, approvalID, view.ActionSHA256, view.ReviewContextSHA256, "approved", "reviewer"); err != nil {
			t.Fatalf("cited approval required another pooled connection: %v", err)
		}
		if stats := store.Pool.Stat(); stats.MaxConns() != 1 || stats.AcquiredConns() != 0 {
			t.Fatalf("unexpected pool state after approval: max=%d acquired=%d total=%d idle=%d", stats.MaxConns(), stats.AcquiredConns(), stats.TotalConns(), stats.IdleConns())
		}
		recoveryCtx, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		guard, err := local.AcquirePreparedRecovery(recoveryCtx, local.Identity())
		if err != nil {
			t.Fatalf("approval retained store authority from recovery: %v", err)
		}
		if err := guard.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestExactCitedOperationsDoNotDeadlockSaturatedPool(t *testing.T) {
	t.Run("approve", func(t *testing.T) {
		f := pendingExactFixture(t, "exact-two-connection-approve")
		evidence := exactReviewEvidenceSet(t, f, 1)
		approvalID, local := exactReviewPrepareWithEvidence(t, f, evidence)
		store, ctx := f.result.env.store, f.result.env.ctx
		view, err := store.GetExactApprovalReview(ctx, approvalID)
		if err != nil {
			t.Fatal(err)
		}
		constrainExactTestPool(t, store, ctx, 2)
		_, blocker := blockExactWorkflow(t, store, ctx, f.step.WorkflowRunID)
		operationCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		start := make(chan struct{})
		results := make(chan error, 2)
		for i := 0; i < 2; i++ {
			go func() {
				<-start
				results <- store.DecideExactApproval(operationCtx, approvalID, view.ActionSHA256, view.ReviewContextSHA256, "approved", "reviewer")
			}()
		}
		close(start)
		waitExactPoolAcquired(t, store.Pool, 2)
		if err := blocker.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		winners := 0
		for i := 0; i < 2; i++ {
			if err := <-results; err == nil {
				winners++
			} else if errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("concurrent cited approval deadlocked: %v", err)
			}
		}
		if winners != 1 {
			t.Fatalf("approval winners=%d", winners)
		}
		if stats := store.Pool.Stat(); stats.AcquiredConns() != 0 || stats.TotalConns() > 2 {
			t.Fatalf("approval leaked pool connection: acquired=%d total=%d", stats.AcquiredConns(), stats.TotalConns())
		}
		recoveryCtx, stop := context.WithTimeout(ctx, time.Second)
		defer stop()
		guard, err := local.AcquirePreparedRecovery(recoveryCtx, local.Identity())
		if err != nil {
			t.Fatalf("recovery remained blocked after concurrent approval: %v", err)
		}
		if err := guard.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("preparation", func(t *testing.T) {
		f, review, providerAttemptID := exactCitedPreparationInput(t, "exact-two-connection-preparation")
		store := f.result.env.store
		constrainExactTestPool(t, store, f.result.env.ctx, 2)
		_, blocker := blockExactWorkflow(t, store, f.result.env.ctx, f.step.WorkflowRunID)
		operationCtx, cancel := context.WithTimeout(exactFixtureContext(f.result), 5*time.Second)
		defer cancel()
		start := make(chan struct{})
		results := make(chan error, 2)
		for i := 0; i < 2; i++ {
			go func() {
				<-start
				_, err := prepareExactCitedInput(operationCtx, f, review, providerAttemptID)
				results <- err
			}()
		}
		close(start)
		waitExactPoolAcquired(t, store.Pool, 2)
		if err := blocker.Rollback(f.result.env.ctx); err != nil {
			t.Fatal(err)
		}
		winners := 0
		for i := 0; i < 2; i++ {
			if err := <-results; err == nil {
				winners++
			} else if errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("concurrent cited preparation deadlocked: %v", err)
			}
		}
		if winners != 1 {
			t.Fatalf("preparation winners=%d", winners)
		}
		if stats := store.Pool.Stat(); stats.AcquiredConns() != 0 || stats.TotalConns() > 2 {
			t.Fatalf("preparation leaked pool connection: acquired=%d total=%d", stats.AcquiredConns(), stats.TotalConns())
		}
	})
}

func TestExactTerminalApprovalExpiryBoundary(t *testing.T) {
	for i := 0; i < 3; i++ {
		f := pendingExactFixture(t, "exact-terminal-expiry-"+string(domain.NewID()))
		evidence := exactReviewEvidenceSet(t, f, 1)
		approvalID, local := exactReviewPrepareWithEvidence(t, f, evidence)
		store, ctx := f.result.env.store, f.result.env.ctx
		view, err := store.GetExactApprovalReview(ctx, approvalID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Pool.Exec(ctx, `UPDATE approvals SET expires_at=clock_timestamp()+interval '600 milliseconds' WHERE id=$1`, approvalID); err != nil {
			t.Fatal(err)
		}
		reader := &observedExactReader{local: local, verifyEntered: make(chan struct{}), releaseVerify: make(chan struct{})}
		store.ConfigureExactReviewEvidenceReader(reader)
		result := make(chan error, 1)
		go func() {
			result <- store.DecideExactApproval(ctx, approvalID, view.ActionSHA256, view.ReviewContextSHA256, "approved", "reviewer")
		}()
		waitExactSignal(t, reader.verifyEntered)
		var expired bool
		for !expired {
			if err := store.Pool.QueryRow(ctx, `SELECT clock_timestamp() >= expires_at FROM approvals WHERE id=$1`, approvalID).Scan(&expired); err != nil {
				t.Fatal(err)
			}
			if !expired {
				time.Sleep(10 * time.Millisecond)
			}
		}
		close(reader.releaseVerify)
		if err := <-result; !errors.Is(err, ErrExactApprovalDenied) {
			t.Fatalf("iteration %d: expired approval=%v", i, err)
		}
		var decision string
		var decidedAt *time.Time
		if err := store.Pool.QueryRow(ctx, `SELECT decision,decided_at FROM approvals WHERE id=$1`, approvalID).Scan(&decision, &decidedAt); err != nil || decision != "pending" || decidedAt != nil {
			t.Fatalf("iteration %d: decision=%s decided_at=%v err=%v", i, decision, decidedAt, err)
		}
		if permit, err := store.AdmitExactDispatch(exactFixtureContext(f.result), f.result.env.programID, f.step, view.ProviderAttemptID); permit != nil || err == nil {
			t.Fatalf("expired P dispatched: permit=%v err=%v", permit, err)
		}
	}

	// Run the same terminal UPDATE with a captured clock set exactly to P's
	// expiry. This tests the complete transition predicate at equality.
	f := pendingExactFixture(t, "exact-terminal-equality")
	const clockSource = "SELECT clock_timestamp() AS decided_at"
	if !strings.Contains(exactTerminalDecisionSQL, clockSource) {
		t.Fatal("terminal UPDATE clock source changed")
	}
	equalitySQL := strings.Replace(exactTerminalDecisionSQL, clockSource, "SELECT expires_at AS decided_at FROM approvals WHERE id=$1", 1)
	tag, err := f.result.env.store.Pool.Exec(f.result.env.ctx, equalitySQL, f.approvalID, "approved", "reviewer", f.attemptID)
	if err != nil || tag.RowsAffected() != 0 {
		t.Fatalf("equality transitioned P: rows=%d err=%v", tag.RowsAffected(), err)
	}
	var equalDecision string
	var equalDecidedAt *time.Time
	if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx, `SELECT decision,decided_at FROM approvals WHERE id=$1`, f.approvalID).Scan(&equalDecision, &equalDecidedAt); err != nil || equalDecision != "pending" || equalDecidedAt != nil {
		t.Fatalf("equality changed P: decision=%s decided_at=%v err=%v", equalDecision, equalDecidedAt, err)
	}

	// A terminal transition before expiry uses its one captured DB timestamp.
	valid := pendingExactFixture(t, "exact-terminal-before-expiry")
	view, err := valid.result.env.store.GetExactApprovalReview(valid.result.env.ctx, valid.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if err := valid.result.env.store.DecideExactApproval(valid.result.env.ctx, valid.approvalID, view.ActionSHA256, view.ReviewContextSHA256, "approved", "reviewer"); err != nil {
		t.Fatal(err)
	}
	var before bool
	if err := valid.result.env.store.Pool.QueryRow(valid.result.env.ctx, `SELECT decided_at < expires_at FROM approvals WHERE id=$1`, valid.approvalID).Scan(&before); err != nil || !before {
		t.Fatalf("valid decision clock=%v err=%v", before, err)
	}
}

func TestExactRejectRetainsExistingExpiryBoundary(t *testing.T) {
	f := pendingExactFixture(t, "exact-reject-expiry-boundary")
	store, ctx := f.result.env.store, f.result.env.ctx
	view, err := store.GetExactApprovalReview(ctx, f.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `UPDATE approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.approvalID); err != nil {
		t.Fatal(err)
	}
	if err := store.DecideExactApproval(ctx, f.approvalID, view.ActionSHA256, view.ReviewContextSHA256, "rejected", "reviewer"); !errors.Is(err, ErrExactApprovalDenied) {
		t.Fatalf("expired rejection changed established decision boundary: %v", err)
	}
	var decision string
	if err := store.Pool.QueryRow(ctx, `SELECT decision FROM approvals WHERE id=$1`, f.approvalID).Scan(&decision); err != nil || decision != "pending" {
		t.Fatalf("expired rejection changed P: %s %v", decision, err)
	}
}

func TestExactApprovalRecoveryStoreOrder(t *testing.T) {
	for i := 0; i < 3; i++ {
		f := pendingExactFixture(t, "exact-recovery-approval-"+string(domain.NewID()))
		evidence := exactReviewEvidenceSet(t, f, 1)
		approvalID, local := exactReviewPrepareWithEvidence(t, f, evidence)
		prepared := prepareDBFixture(t, f.result.env, f.result)
		store, ctx := f.result.env.store, f.result.env.ctx
		view, err := store.GetExactApprovalReview(ctx, approvalID)
		if err != nil {
			t.Fatal(err)
		}
		guard, err := local.AcquirePreparedRecovery(ctx, local.Identity())
		if err != nil {
			t.Fatal(err)
		}
		reader := &observedExactReader{local: local, acquireEntered: make(chan struct{})}
		store.ConfigureExactReviewEvidenceReader(reader)
		approvalCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		result := make(chan error, 1)
		go func() {
			result <- store.DecideExactApproval(approvalCtx, approvalID, view.ActionSHA256, view.ReviewContextSHA256, "approved", "reviewer")
		}()
		waitExactSignal(t, reader.acquireEntered)
		assertExactWorkflowUnlocked(t, store, ctx, f.step.WorkflowRunID)
		recoveryCtx, cancelRecovery := context.WithTimeout(prepared.recoveryContext(), 3*time.Second)
		if err := store.SealPreparedEvidence(recoveryCtx, prepared.seal); err != nil {
			t.Fatalf("recovery could not acquire workflow lineage: %v", err)
		}
		cancelRecovery()
		if err := guard.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != nil {
			t.Fatalf("approval after recovery: %v", err)
		}
		cancel()
	}
}

func TestExactPreparationRecoveryStoreOrder(t *testing.T) {
	for i := 0; i < 3; i++ {
		f := pendingExactFixture(t, "exact-recovery-prepare-"+string(domain.NewID()))
		evidence := exactReviewEvidenceSet(t, f, 1)
		local := exactReviewLocalBytes(t, f, evidence)
		store, ctx := f.result.env.store, f.result.env.ctx
		base, err := store.GetExactApprovalReview(ctx, f.approvalID)
		if err != nil {
			t.Fatal(err)
		}
		review := base.Review
		review.SupportingEvidence = []exactaction.Citation{{ArtifactID: evidence[0].ref.ArtifactID, ArtifactSHA256: evidence[0].ref.ContentSHA256, Locator: "line 1"}}
		x := recordScheduledProviderAdmission(t, f.result, exactFixtureContext(f.result), f.result.env.programID, scheduledProviderAction(f.result, 1), nil, "fixture")
		prepared := prepareDBFixture(t, f.result.env, f.result)
		guard, err := local.AcquirePreparedRecovery(ctx, local.Identity())
		if err != nil {
			t.Fatal(err)
		}
		reader := &observedExactReader{local: local, acquireEntered: make(chan struct{})}
		store.ConfigureExactReviewEvidenceReader(reader)
		prepareCtx, cancel := context.WithTimeout(exactFixtureContext(f.result), 5*time.Second)
		result := make(chan error, 1)
		go func() {
			_, err := store.PrepareExactActionApproval(prepareCtx, f.result.env.programID, f.step, x.ProviderAttemptID,
				exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/allowed/review"},
				review, "reviewer", time.Now().Add(time.Hour))
			result <- err
		}()
		waitExactSignal(t, reader.acquireEntered)
		assertExactWorkflowUnlocked(t, store, ctx, f.step.WorkflowRunID)
		recoveryCtx, cancelRecovery := context.WithTimeout(prepared.recoveryContext(), 3*time.Second)
		if err := store.SealPreparedEvidence(recoveryCtx, prepared.seal); err != nil {
			t.Fatalf("recovery could not acquire workflow lineage: %v", err)
		}
		cancelRecovery()
		if err := guard.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != nil {
			t.Fatalf("preparation after recovery: %v", err)
		}
		cancel()
	}
}

func TestExactUnavailableStoreAuthorityFailsBeforeLineageLock(t *testing.T) {
	f := pendingExactFixture(t, "exact-store-authority-unavailable")
	evidence := exactReviewEvidenceSet(t, f, 1)
	approvalID, local := exactReviewPrepareWithEvidence(t, f, evidence)
	store, ctx := f.result.env.store, f.result.env.ctx
	view, err := store.GetExactApprovalReview(ctx, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := local.AcquirePreparedRecovery(ctx, local.Identity())
	if err != nil {
		t.Fatal(err)
	}
	reader := &observedExactReader{local: local, acquireEntered: make(chan struct{})}
	store.ConfigureExactReviewEvidenceReader(reader)
	decisionCtx, cancel := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() {
		result <- store.DecideExactApproval(decisionCtx, approvalID, view.ActionSHA256, view.ReviewContextSHA256, "approved", "reviewer")
	}()
	waitExactSignal(t, reader.acquireEntered)
	assertExactWorkflowUnlocked(t, store, ctx, f.step.WorkflowRunID)
	cancel()
	if err := <-result; err == nil {
		t.Fatal("canceled store acquisition succeeded")
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	checkCtx, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	again, err := local.AcquirePreparedRecovery(checkCtx, local.Identity())
	if err != nil {
		t.Fatalf("canceled acquisition leaked store authority: %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
	var decision string
	if err := store.Pool.QueryRow(ctx, `SELECT decision FROM approvals WHERE id=$1`, approvalID).Scan(&decision); err != nil || decision != "pending" {
		t.Fatalf("canceled approval changed P: %s %v", decision, err)
	}
}

func TestExactCanceledVerificationReleasesStoreAuthority(t *testing.T) {
	f := pendingExactFixture(t, "exact-canceled-verification")
	evidence := exactReviewEvidenceSet(t, f, 1)
	approvalID, local := exactReviewPrepareWithEvidence(t, f, evidence)
	store, ctx := f.result.env.store, f.result.env.ctx
	view, err := store.GetExactApprovalReview(ctx, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	reader := &observedExactReader{local: local, verifyEntered: make(chan struct{}), releaseVerify: make(chan struct{})}
	store.ConfigureExactReviewEvidenceReader(reader)
	decisionCtx, cancel := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() {
		result <- store.DecideExactApproval(decisionCtx, approvalID, view.ActionSHA256, view.ReviewContextSHA256, "approved", "reviewer")
	}()
	waitExactSignal(t, reader.verifyEntered)
	cancel()
	if err := <-result; err == nil {
		t.Fatal("canceled verification approved")
	}
	assertExactWorkflowUnlocked(t, store, ctx, f.step.WorkflowRunID)
	checkCtx, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	guard, err := local.AcquirePreparedRecovery(checkCtx, local.Identity())
	if err != nil {
		t.Fatalf("canceled decision retained shared store authority: %v", err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	var decision string
	if err := store.Pool.QueryRow(ctx, `SELECT decision FROM approvals WHERE id=$1`, approvalID).Scan(&decision); err != nil || decision != "pending" {
		t.Fatalf("canceled decision changed P: %s %v", decision, err)
	}
}

func TestExactConcurrentTerminalAndPreparationIdentity(t *testing.T) {
	f := pendingExactFixture(t, "exact-concurrent-terminal")
	evidence := exactReviewEvidenceSet(t, f, 1)
	approvalID, _ := exactReviewPrepareWithEvidence(t, f, evidence)
	store, ctx := f.result.env.store, f.result.env.ctx
	view, err := store.GetExactApprovalReview(ctx, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, decision := range []string{"approved", "rejected"} {
		wg.Add(1)
		go func(decision string) {
			defer wg.Done()
			<-start
			results <- store.DecideExactApproval(ctx, approvalID, view.ActionSHA256, view.ReviewContextSHA256, decision, "reviewer")
		}(decision)
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("terminal winners=%d, want 1", winners)
	}
	var persisted string
	if err := store.Pool.QueryRow(ctx, `SELECT decision FROM approvals WHERE id=$1`, approvalID).Scan(&persisted); err != nil || (persisted != "approved" && persisted != "rejected") {
		t.Fatalf("terminal state=%q err=%v", persisted, err)
	}
}

func TestExactConcurrentApprovalAndDuplicatePreparation(t *testing.T) {
	t.Run("approve_twice", func(t *testing.T) {
		f := pendingExactFixture(t, "exact-concurrent-approval")
		evidence := exactReviewEvidenceSet(t, f, 1)
		approvalID, _ := exactReviewPrepareWithEvidence(t, f, evidence)
		store, ctx := f.result.env.store, f.result.env.ctx
		view, err := store.GetExactApprovalReview(ctx, approvalID)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		for i := 0; i < 2; i++ {
			go func() {
				<-start
				results <- store.DecideExactApproval(ctx, approvalID, view.ActionSHA256, view.ReviewContextSHA256, "approved", "reviewer")
			}()
		}
		close(start)
		winners := 0
		for i := 0; i < 2; i++ {
			if err := <-results; err == nil {
				winners++
			}
		}
		if winners != 1 {
			t.Fatalf("approval winners=%d", winners)
		}
	})

	t.Run("prepare_twice", func(t *testing.T) {
		f := pendingExactFixture(t, "exact-concurrent-preparation")
		evidence := exactReviewEvidenceSet(t, f, 1)
		exactReviewLocalBytes(t, f, evidence)
		store, ctx := f.result.env.store, f.result.env.ctx
		base, err := store.GetExactApprovalReview(ctx, f.approvalID)
		if err != nil {
			t.Fatal(err)
		}
		review := base.Review
		review.SupportingEvidence = []exactaction.Citation{{ArtifactID: evidence[0].ref.ArtifactID, ArtifactSHA256: evidence[0].ref.ContentSHA256, Locator: "line 1"}}
		x := recordScheduledProviderAdmission(t, f.result, exactFixtureContext(f.result), f.result.env.programID, scheduledProviderAction(f.result, 1), nil, "fixture")
		start := make(chan struct{})
		results := make(chan error, 2)
		for i := 0; i < 2; i++ {
			go func() {
				<-start
				_, err := store.PrepareExactActionApproval(exactFixtureContext(f.result), f.result.env.programID, f.step, x.ProviderAttemptID,
					exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/allowed/review"},
					review, "reviewer", time.Now().Add(time.Hour))
				results <- err
			}()
		}
		close(start)
		winners := 0
		for i := 0; i < 2; i++ {
			if err := <-results; err == nil {
				winners++
			}
		}
		var count int
		if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM exact_actions WHERE bound_provider_attempt_id=$1`, x.ProviderAttemptID).Scan(&count); err != nil || winners != 1 || count != 1 {
			t.Fatalf("preparation winners=%d frozen rows=%d err=%v", winners, count, err)
		}
	})
}

func TestExactEvidenceGuardCoversDecisionCommit(t *testing.T) {
	f := pendingExactFixture(t, "exact-guard-through-commit")
	evidence := exactReviewEvidenceSet(t, f, 1)
	approvalID, local := exactReviewPrepareWithEvidence(t, f, evidence)
	store, ctx := f.result.env.store, f.result.env.ctx
	view, err := store.GetExactApprovalReview(ctx, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan string, 1)
	store.ConfigureExactReviewEvidenceReader(&observedExactReader{local: local, onGuardClose: func() {
		var decision string
		if err := store.Pool.QueryRow(ctx, `SELECT decision FROM approvals WHERE id=$1`, approvalID).Scan(&decision); err != nil {
			observed <- "query failed"
			return
		}
		observed <- decision
	}})
	if err := store.DecideExactApproval(ctx, approvalID, view.ActionSHA256, view.ReviewContextSHA256, "approved", "reviewer"); err != nil {
		t.Fatal(err)
	}
	if decision := <-observed; decision != "approved" {
		t.Fatalf("store guard closed before decision commit: %s", decision)
	}
}

func TestExactMisconfiguredEvidenceGuardFailsClosed(t *testing.T) {
	for _, mode := range []string{"absent", "typed_nil", "uninitialized", "invalid_root"} {
		t.Run(mode, func(t *testing.T) {
			f := pendingExactFixture(t, "exact-guard-"+mode)
			evidence := exactReviewEvidenceSet(t, f, 1)
			approvalID, _ := exactReviewPrepareWithEvidence(t, f, evidence)
			store, ctx := f.result.env.store, f.result.env.ctx
			view, err := store.GetExactApprovalReview(ctx, approvalID)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "absent":
				store.ConfigureExactReviewEvidenceReader(nil)
			case "typed_nil":
				var local *artifact.Local
				store.ConfigureExactReviewEvidenceReader(local)
			case "uninitialized":
				store.ConfigureExactReviewEvidenceReader(&artifact.Local{})
			case "invalid_root":
				registration := ensureTestArtifactStore(t, ctx, store)
				root := t.TempDir()
				markerPath := filepath.Join(root, ".reconductor-artifact-store.json")
				marker, err := json.Marshal(map[string]any{
					"marker_format": registration.MarkerFormat, "marker_version": registration.MarkerVersion,
					"backend_kind": registration.BackendKind, "store_id": registration.ID,
					"incarnation_nonce": registration.IncarnationNonce,
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(markerPath, marker, 0600); err != nil {
					t.Fatal(err)
				}
				local, err := artifact.OpenLocal(ctx, root, registration.ID, store, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(markerPath); err != nil {
					t.Fatal(err)
				}
				store.ConfigureExactReviewEvidenceReader(local)
			}
			if err := store.DecideExactApproval(ctx, approvalID, view.ActionSHA256, view.ReviewContextSHA256, "approved", "reviewer"); !errors.Is(err, ErrExactApprovalDenied) {
				t.Fatalf("misconfigured reader granted approval: %v", err)
			}
			assertExactWorkflowUnlocked(t, store, ctx, f.step.WorkflowRunID)
			var decision string
			if err := store.Pool.QueryRow(ctx, `SELECT decision FROM approvals WHERE id=$1`, approvalID).Scan(&decision); err != nil || decision != "pending" {
				t.Fatalf("failed approval changed P: %s %v", decision, err)
			}
		})
	}
}
