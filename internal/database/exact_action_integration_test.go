package database

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
)

func pendingExactFixture(t *testing.T, name string) exactDispatchFixture {
	t.Helper()
	return buildExactDispatchFixtureDecision(t, newScheduledResultFixture(t, name, "http.request"), "https://example.test/allowed/one", false)
}

func TestExactPreparationDecisionAndFrozenRead(t *testing.T) {
	f := pendingExactFixture(t, "exact-pending-production")
	f.assertDeniedUnchanged(t)
	view, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Action.ActionID == "" || view.Action.Request.RequestTarget != "/allowed/one" || view.Action.Identity.Kind != "anonymous" || view.Action.Request.EffectivePort != 443 || view.Decision != "pending" || view.ProviderAttemptID != f.attemptID {
		t.Fatalf("review=%+v", view)
	}
	if err := f.result.env.store.DecideExactApproval(f.result.env.ctx, f.approvalID, "bad", view.ReviewContextSHA256, "approved", "operator"); !errors.Is(err, ErrExactApprovalDenied) {
		t.Fatalf("stale action=%v", err)
	}
	if err := f.result.env.store.DecideExactApproval(f.result.env.ctx, f.approvalID, view.ActionSHA256, "bad", "approved", "operator"); !errors.Is(err, ErrExactApprovalDenied) {
		t.Fatalf("stale review=%v", err)
	}
	if err := f.result.env.store.DecideExactApproval(f.result.env.ctx, f.approvalID, view.ActionSHA256, view.ReviewContextSHA256, "approved", "operator"); err != nil {
		t.Fatal(err)
	}
	if err := f.result.env.store.DecideExactApproval(f.result.env.ctx, f.approvalID, view.ActionSHA256, view.ReviewContextSHA256, "rejected", "operator"); !errors.Is(err, ErrExactApprovalDenied) {
		t.Fatalf("second decision=%v", err)
	}
	if _, err := f.admit(); err != nil {
		t.Fatal(err)
	}
	if state, audits := f.state(t); state != "DISPATCH_INTENT" || audits != 1 {
		t.Fatalf("state=%s audits=%d", state, audits)
	}
}

func TestExactRejectedApprovalNeverDispatches(t *testing.T) {
	f := pendingExactFixture(t, "exact-rejected-production")
	view, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.result.env.store.DecideExactApproval(f.result.env.ctx, f.approvalID, view.ActionSHA256, view.ReviewContextSHA256, "rejected", "operator"); err != nil {
		t.Fatal(err)
	}
	if err := f.result.env.store.DecideExactApproval(f.result.env.ctx, f.approvalID, view.ActionSHA256, view.ReviewContextSHA256, "approved", "operator"); !errors.Is(err, ErrExactApprovalDenied) {
		t.Fatalf("redecision=%v", err)
	}
	f.assertDeniedUnchanged(t)
}

func TestExactFrozenActionIgnoresStepInput(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-input-mutation")
	_, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE step_runs SET input='{"method":"HEAD","scheme":"https","hostname":"evil.test","effective_port":8443,"request_target":"/changed"}'::jsonb WHERE id=$1`, f.step.ID)
	if err != nil {
		t.Fatal(err)
	}
	view, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if view.Action.Request.Method != "GET" || view.Action.Request.Hostname != "example.test" || view.Action.Request.EffectivePort != 443 || view.Action.Request.RequestTarget != "/allowed/one" {
		t.Fatalf("mutated frozen action: %+v", view.Action.Request)
	}
	if _, err := f.admit(); err != nil {
		t.Fatal(err)
	}
}

func TestExactFrozenPersistenceAndDuplicatePreparation(t *testing.T) {
	f := pendingExactFixture(t, "exact-immutable")
	view, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE exact_actions SET canonical_contract='{}' WHERE action_request_id=$1`,
		`UPDATE exact_actions SET canonical_review_context='{}' WHERE action_request_id=$1`,
		`UPDATE exact_actions SET action_sha256=$2 WHERE action_request_id=$1`,
		`DELETE FROM exact_actions WHERE action_request_id=$1`,
	} {
		var err error
		if statement == `UPDATE exact_actions SET action_sha256=$2 WHERE action_request_id=$1` {
			_, err = f.result.env.store.Pool.Exec(f.result.env.ctx, statement, view.Action.ActionID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		} else {
			_, err = f.result.env.store.Pool.Exec(f.result.env.ctx, statement, view.Action.ActionID)
		}
		if err == nil {
			t.Fatalf("frozen mutation accepted: %s", statement)
		}
	}
	_, err = f.result.env.store.PrepareExactActionApproval(exactFixtureContext(f.result), f.result.env.programID, f.step, f.attemptID,
		exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/allowed/one"}, view.Review, "operator", time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("duplicate preparation accepted")
	}
}

func TestExactPreparationRollbackAndCitationReject(t *testing.T) {
	f := pendingExactFixture(t, "exact-preparation-rollback")
	action := scheduledProviderAction(f.result, 1)
	admission := recordScheduledProviderAdmission(t, f.result, exactFixtureContext(f.result), f.result.env.programID, action, nil, "fixture")
	view, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	proposal := exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/allowed/two"}
	badReview := view.Review
	badReview.SupportingEvidence = []exactaction.Citation{{ArtifactID: domain.NewID(), ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Locator: "line 1"}}
	if _, err := f.result.env.store.PrepareExactActionApproval(exactFixtureContext(f.result), f.result.env.programID, f.step, admission.ProviderAttemptID, proposal, badReview, "operator", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("missing artifact citation accepted")
	}
	sentinel := errors.New("abort preparation")
	if _, err := f.result.env.store.prepareExactActionApproval(exactFixtureContext(f.result), f.result.env.programID, f.step, admission.ProviderAttemptID, proposal, view.Review, "operator", time.Now().Add(time.Hour), func(pgx.Tx) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("rollback=%v", err)
	}
	var count int
	if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx, `SELECT (SELECT count(*) FROM exact_actions WHERE action_request_id=$1)+(SELECT count(*) FROM approvals WHERE bound_provider_attempt_id=$2)+(SELECT count(*) FROM exact_dispatch_attempts WHERE provider_attempt_id=$2)`, action.ID, admission.ProviderAttemptID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial preparation count=%d err=%v", count, err)
	}
}

func TestExactPreparationRejectsWrongXAndCapability(t *testing.T) {
	f := pendingExactFixture(t, "exact-wrong-x")
	other := pendingExactFixture(t, "exact-wrong-x-other")
	view, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	proposal := exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/allowed/one"}
	if _, err := f.result.env.store.PrepareExactActionApproval(exactFixtureContext(f.result), f.result.env.programID, f.step, other.attemptID, proposal, view.Review, "operator", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("foreign X accepted")
	}
	wrongStep := f.step
	wrongStep.Capability = "probe.http"
	if _, err := f.result.env.store.PrepareExactActionApproval(exactFixtureContext(f.result), f.result.env.programID, wrongStep, f.attemptID, proposal, view.Review, "operator", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("wrong capability accepted")
	}
}

func TestExactCitationOwnsImmutableArtifactIdentity(t *testing.T) {
	f := pendingExactFixture(t, "exact-cited-artifact")
	source, cited := adoptedEvidenceFixture(t, f.result.env, "exact-cited-source")
	artifactID, digest := cited.ArtifactID, cited.ContentSHA256
	exactReviewLocalBytes(t, f, []exactReviewEvidence{{source: source, ref: cited}})
	var err error
	view, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	action := scheduledProviderAction(f.result, 1)
	admission := recordScheduledProviderAdmission(t, f.result, exactFixtureContext(f.result), f.result.env.programID, action, nil, "fixture")
	review := view.Review
	review.SupportingEvidence = []exactaction.Citation{{ArtifactID: artifactID, ArtifactSHA256: digest, Locator: "line 1"}}
	proposal := exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/allowed/two"}
	approvalID, err := f.result.env.store.PrepareExactActionApproval(exactFixtureContext(f.result), f.result.env.programID, f.step, admission.ProviderAttemptID, proposal, review, "operator", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	newView, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, approvalID)
	if err != nil || len(newView.Review.SupportingEvidence) != 1 {
		t.Fatalf("read=%+v err=%v", newView, err)
	}
	other := newScheduledResultFixture(t, "exact-foreign-artifact", "http.request")
	_, foreignCited := adoptedEvidenceFixture(t, other.env, "exact-foreign-source")
	otherArtifactID := foreignCited.ArtifactID
	for _, statement := range []string{
		`UPDATE artifacts SET sha256=$2 WHERE id=$1`,
		`UPDATE artifacts SET task_id=$2 WHERE id=$1`,
		`UPDATE exact_action_citations SET artifact_sha256=$2 WHERE artifact_id=$1`,
		`DELETE FROM exact_action_citations WHERE artifact_id=$1`,
	} {
		var err error
		if strings.Contains(statement, "task_id") {
			_, err = f.result.env.store.Pool.Exec(f.result.env.ctx, statement, artifactID, other.lineage.task.ID)
		} else if strings.Contains(statement, "$2") {
			_, err = f.result.env.store.Pool.Exec(f.result.env.ctx, statement, artifactID, strings.Repeat("b", 64))
		} else {
			_, err = f.result.env.store.Pool.Exec(f.result.env.ctx, statement, artifactID)
		}
		if err == nil {
			t.Fatalf("citation identity mutation accepted: %s", statement)
		}
	}
	foreign := scheduledProviderAction(f.result, 1)
	foreignAdmission := recordScheduledProviderAdmission(t, f.result, exactFixtureContext(f.result), f.result.env.programID, foreign, nil, "fixture")
	review.SupportingEvidence = []exactaction.Citation{{ArtifactID: otherArtifactID, ArtifactSHA256: foreignCited.ContentSHA256, Locator: "line 1"}}
	if _, err := f.result.env.store.PrepareExactActionApproval(exactFixtureContext(f.result), f.result.env.programID, f.step, foreignAdmission.ProviderAttemptID, proposal, review, "operator", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("wrong-program artifact accepted")
	}
	review.SupportingEvidence = []exactaction.Citation{{ArtifactID: artifactID, ArtifactSHA256: strings.Repeat("b", 64), Locator: "line 1"}}
	if _, err := f.result.env.store.PrepareExactActionApproval(exactFixtureContext(f.result), f.result.env.programID, f.step, foreignAdmission.ProviderAttemptID, proposal, review, "operator", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("wrong artifact digest accepted")
	}
}

func TestExactDispatchRejectsMissingOrCorruptFrozenRows(t *testing.T) {
	for _, tc := range []struct {
		name            string
		row             bool
		wrongActionHash bool
		wrongReviewHash bool
		wrongAttempt    bool
	}{
		{name: "missing"},
		{name: "corrupt canonical", row: true},
		{name: "action hash mismatch", row: true, wrongActionHash: true},
		{name: "review hash mismatch", row: true, wrongReviewHash: true},
		{name: "wrong lineage", row: true, wrongAttempt: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newExactDispatchFixture(t, "exact-frozen-negative-"+strings.ReplaceAll(tc.name, " ", "-"))
			approvalID, attemptID := seedPendingExactApprovalAtWorkflowStep(t, f)
			var actionID domain.ID
			var actionSHA, reviewSHA string
			if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx, `SELECT action_request_id,action_sha256,review_context_sha256 FROM approvals WHERE id=$1`, approvalID).Scan(&actionID, &actionSHA, &reviewSHA); err != nil {
				t.Fatal(err)
			}
			if tc.row {
				if tc.wrongActionHash {
					actionSHA = strings.Repeat("c", 64)
				}
				if tc.wrongReviewHash {
					reviewSHA = strings.Repeat("d", 64)
				}
				stepAttempt := 1
				if tc.wrongAttempt {
					stepAttempt = 2
				}
				_, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `INSERT INTO exact_actions(action_request_id,bound_provider_attempt_id,program_id,task_id,workflow_run_id,step_run_id,step_attempt,contract_schema,capability_semantic_revision,canonical_contract,action_sha256,review_schema,canonical_review_context,review_context_sha256,created_by)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'{}',$10,$11,'{}',$12,'historical-test')`, actionID, attemptID, f.result.env.programID, f.result.lineage.task.ID, f.step.WorkflowRunID, f.step.ID, stepAttempt, exactaction.ContractVersion, exactaction.CapabilityRevision, actionSHA, exactaction.ReviewVersion, reviewSHA)
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE approvals SET decision='approved',decided_by='historical-test',decided_at=clock_timestamp() WHERE id=$1`, approvalID)
			if err != nil {
				t.Fatal(err)
			}
			permit, err := f.result.env.store.AdmitExactDispatch(exactFixtureContext(f.result), f.result.env.programID, f.step, attemptID)
			if permit != nil || !errors.Is(err, ErrExactDispatchDenied) {
				t.Fatalf("admission=%v err=%v", permit, err)
			}
		})
	}
}
