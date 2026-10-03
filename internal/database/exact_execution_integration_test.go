package database

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
)

func TestExactExecutionLoaderAndTrustedClock(t *testing.T) {
	f := newDirectExactDispatchFixture(t, "exact-execution-loader")
	before, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.result.env.store.LoadExactDispatchAction(f.result.env.ctx, f.attemptID, before.ActionSHA256, f.authority.Epoch); !errors.Is(err, ErrExactDispatchDenied) {
		t.Fatal("loaded before intent")
	}
	permit, err := f.admit()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		action, err := f.result.env.store.LoadExactDispatchAction(f.result.env.ctx, f.attemptID, permit.ActionSHA256(), permit.AuthorityEpoch())
		if err != nil || !reflect.DeepEqual(action, before.Action) {
			t.Fatalf("loader fidelity: %+v %v", action, err)
		}
	}
	for _, bad := range []struct {
		id   domain.ID
		hash string
	}{{f.attemptID, strings.Repeat("f", 64)}, {domain.NewID(), permit.ActionSHA256()}, {"", permit.ActionSHA256()}, {f.attemptID, ""}} {
		if _, err := f.result.env.store.LoadExactDispatchAction(f.result.env.ctx, bad.id, bad.hash, permit.AuthorityEpoch()); !errors.Is(err, ErrExactDispatchDenied) {
			t.Fatalf("invalid execution binding: %v", err)
		}
	}
	for _, epoch := range []int64{-1, permit.AuthorityEpoch() + 1} {
		if _, err := f.result.env.store.LoadExactDispatchAction(f.result.env.ctx, f.attemptID, permit.ActionSHA256(), epoch); !errors.Is(err, ErrExactDispatchDenied) {
			t.Fatalf("invalid historical epoch accepted: epoch=%d err=%v", epoch, err)
		}
	}
	now, err := f.result.env.store.ExactDispatchTrustedTime(f.result.env.ctx)
	if err != nil || now.IsZero() || !permit.ConsumeAt(now) {
		t.Fatalf("trusted clock=%s error=%v", now, err)
	}
	cancelled, cancel := context.WithCancel(f.result.env.ctx)
	cancel()
	if _, err := f.result.env.store.ExactDispatchTrustedTime(cancelled); err == nil {
		t.Fatal("clock silently fell back after query failure")
	}
	after, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read modified frozen approval/review")
	}
	if state, audits := f.state(t); state != "DISPATCH_INTENT" || audits != 1 {
		t.Fatal("read modified dispatch")
	}
}

func TestExactExecutionLoaderUsesHistoricalIntentEpoch(t *testing.T) {
	f := newDirectExactDispatchFixture(t, "execution-historical-epoch")
	store, ctx := f.result.env.store, f.result.env.ctx
	p, err := f.admit()
	if err != nil {
		t.Fatal(err)
	}
	current, err := store.BeginLaunchAuthorityUpdate(ctx, f.result.env.programID, p.AuthorityEpoch(), "reviewer", "after intent")
	if err != nil || current != p.AuthorityEpoch()+1 {
		t.Fatalf("current epoch=%d err=%v", current, err)
	}
	if _, err = store.LoadExactDispatchAction(ctx, f.attemptID, p.ActionSHA256(), p.AuthorityEpoch()); err != nil {
		t.Fatalf("historical epoch rejected after current authority changed: %v", err)
	}
	if _, err = store.LoadExactDispatchAction(ctx, f.attemptID, p.ActionSHA256(), current); !errors.Is(err, ErrExactDispatchDenied) {
		t.Fatal("current epoch substituted for historical intent epoch")
	}
	if state, audits := f.state(t); state != "DISPATCH_INTENT" || audits != 1 {
		t.Fatal("loader changed historical intent")
	}
}

type forbiddenExecutionEvidenceReader struct{ calls atomic.Int64 }

func (r *forbiddenExecutionEvidenceReader) OpenVerified(context.Context, domain.ResultArtifactRefV1) (io.ReadCloser, error) {
	r.calls.Add(1)
	return nil, errors.New("execution must not inspect review evidence")
}

func TestExactExecutionLoaderDoesNotReopenCompletedEvidence(t *testing.T) {
	f := pendingExactFixture(t, "execution-no-review-evidence")
	evidence := exactReviewEvidenceSet(t, f, 1)
	p, _ := exactReviewPrepareWithEvidence(t, f, evidence)
	store, ctx := f.result.env.store, f.result.env.ctx
	view, err := store.GetExactApprovalReview(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.DecideExactApproval(ctx, p, view.ActionSHA256, view.ReviewContextSHA256, "approved", "reviewer"); err != nil {
		t.Fatal(err)
	}
	reader := &forbiddenExecutionEvidenceReader{}
	store.ConfigureExactReviewEvidenceReader(reader)
	artifactSnapshot := func() string {
		t.Helper()
		var snapshot string
		if err := store.Pool.QueryRow(ctx, `SELECT row_to_json(a)::text FROM artifacts a WHERE id=$1`, evidence[0].ref.ArtifactID).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	beforeArtifact := artifactSnapshot()
	permit, err := store.AdmitExactDispatch(exactFixtureContext(f.result), f.result.env.programID, f.step, view.ProviderAttemptID)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		a, err := store.LoadExactDispatchAction(ctx, view.ProviderAttemptID, permit.ActionSHA256(), permit.AuthorityEpoch())
		if err != nil || !reflect.DeepEqual(a, view.Action) {
			t.Fatalf("execution material=%+v %v", a, err)
		}
	}
	if reader.calls.Load() != 0 {
		t.Fatal("completed review evidence reopened")
	}
	if artifactSnapshot() != beforeArtifact {
		t.Fatal("execution loading changed evidence retention/access state")
	}
}

func TestExactExecutionLoaderRejectsTwoAdmittedActionsCrossBinding(t *testing.T) {
	f := newDirectExactDispatchFixture(t, "execution-cross-binding")
	store, ctx := f.result.env.store, f.result.env.ctx
	first, err := f.admit()
	if err != nil {
		t.Fatal(err)
	}
	actionID, authID, attemptID := domain.NewID(), domain.NewID(), domain.NewID()
	_, err = store.Pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,step_run_id,capability,action_request_id,step_attempt,safe_message,details) VALUES($1,'policy_allowed','test','test',$2,$3,$4,$5,'http.request',$6,1,'fixture','{"phase":"execution"}')`, authID, f.result.env.programID, f.result.lineage.task.ID, f.step.WorkflowRunID, f.step.ID, actionID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Pool.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,step_run_id,capability,action_request_id,step_attempt,execution_authorization_event_id,safe_message) VALUES($1,'provider_invocation_started','test','test',$2,$3,$4,$5,'http.request',$6,1,$7,'fixture')`, attemptID, f.result.env.programID, f.result.lineage.task.ID, f.step.WorkflowRunID, f.step.ID, actionID, authID)
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.GetExactApprovalReview(ctx, f.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	approvalID, err := store.PrepareExactActionApproval(ctx, f.result.env.programID, f.step, attemptID, exactaction.ProposedRequest{Method: "HEAD", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/allowed/second?id=1&id=2"}, original.Review, "reviewer", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	secondView, err := store.GetExactApprovalReview(ctx, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.DecideExactApproval(ctx, approvalID, secondView.ActionSHA256, secondView.ReviewContextSHA256, "approved", "reviewer"); err != nil {
		t.Fatal(err)
	}
	second, err := store.AdmitExactDispatch(ctx, f.result.env.programID, f.step, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range []struct {
		id   domain.ID
		hash string
	}{{first.ProviderAttemptID(), second.ActionSHA256()}, {second.ProviderAttemptID(), first.ActionSHA256()}} {
		if _, err := store.LoadExactDispatchAction(ctx, pair.id, pair.hash, first.AuthorityEpoch()); !errors.Is(err, ErrExactDispatchDenied) {
			t.Fatalf("cross-action execution material accepted: %v", err)
		}
	}
}
