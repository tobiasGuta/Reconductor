package database

import (
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
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
)

type exactReviewEvidence struct {
	source preparedDBFixture
	ref    domain.ResultArtifactRefV1
}

func exactReviewEvidenceSet(t *testing.T, f exactDispatchFixture, count int) []exactReviewEvidence {
	t.Helper()
	result := make([]exactReviewEvidence, count)
	for i := range result {
		source, ref := adoptedEvidenceFixture(t, f.result.env, "exact-review-source-"+string(domain.NewID()))
		if _, err := f.result.env.store.AuthorizeEvidenceView(f.result.env.ctx, source.step.WorkflowRunID, ref.ArtifactID); err != nil {
			t.Fatalf("source evidence is not reviewable: %v", err)
		}
		result[i] = exactReviewEvidence{source: source, ref: ref}
	}
	return result
}

func exactReviewPrepareWithEvidence(t *testing.T, f exactDispatchFixture, evidence []exactReviewEvidence) (domain.ID, *artifact.Local) {
	t.Helper()
	local := exactReviewLocalBytes(t, f, evidence)
	base, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	review := base.Review
	for i, item := range evidence {
		citation := exactaction.Citation{ArtifactID: item.ref.ArtifactID, ArtifactSHA256: item.ref.ContentSHA256, Locator: "line 1"}
		if i%2 == 0 {
			review.SupportingEvidence = append(review.SupportingEvidence, citation)
		} else {
			review.ContradictoryEvidence = append(review.ContradictoryEvidence, citation)
		}
	}
	action := scheduledProviderAction(f.result, 1)
	admission := recordScheduledProviderAdmission(t, f.result, exactFixtureContext(f.result), f.result.env.programID, action, nil, "fixture")
	p, err := f.result.env.store.PrepareExactActionApproval(exactFixtureContext(f.result), f.result.env.programID, f.step, admission.ProviderAttemptID,
		exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/allowed/review"},
		review, "reviewer", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return p, local
}

// The compiled fixture has adopted publication metadata but no physical file.
// Materialize its exact content under a validated Local store so CleanupBatch
// exercises real byte removal, as in the original adversarial reproduction.
func exactReviewLocalBytes(t *testing.T, f exactDispatchFixture, items []exactReviewEvidence) *artifact.Local {
	t.Helper()
	root := t.TempDir()
	registration := ensureTestArtifactStore(t, f.result.env.ctx, f.result.env.store)
	marker, err := json.Marshal(map[string]any{
		"marker_format": registration.MarkerFormat, "marker_version": registration.MarkerVersion,
		"backend_kind": registration.BackendKind, "store_id": registration.ID,
		"incarnation_nonce": registration.IncarnationNonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".reconductor-artifact-store.json"), append(marker, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		for _, compiled := range item.source.compiled.Artifacts {
			if compiled.Reference.ArtifactID != item.ref.ArtifactID {
				continue
			}
			path := filepath.Join(root, item.ref.StorageKey)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			input, err := compiled.Source.Open()
			if err != nil {
				t.Fatal(err)
			}
			output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			_, copied := io.Copy(output, input)
			if err := errors.Join(copied, input.Close(), output.Close()); err != nil {
				t.Fatal(err)
			}
		}
	}
	local, err := artifact.OpenLocal(f.result.env.ctx, root, registration.ID, f.result.env.store, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		verified, err := local.OpenVerified(f.result.env.ctx, item.ref)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, verified)
		if err := errors.Join(readErr, verified.Close()); err != nil {
			t.Fatal(err)
		}
	}
	f.result.env.store.ConfigureExactReviewEvidenceReader(local)
	return local
}

func exactReviewExpireArtifact(t *testing.T, f exactDispatchFixture, id domain.ID) {
	t.Helper()
	if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE artifacts SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
}

func exactReviewDecide(t *testing.T, f exactDispatchFixture, p domain.ID, decision string) error {
	t.Helper()
	view, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	return f.result.env.store.DecideExactApproval(f.result.env.ctx, p, view.ActionSHA256, view.ReviewContextSHA256, decision, "reviewer")
}

func TestExactPendingReviewProtectsBytesAndTerminalReleases(t *testing.T) {
	for _, decision := range []string{"approved", "rejected"} {
		t.Run(decision, func(t *testing.T) {
			f := pendingExactFixture(t, "exact-protected-"+decision)
			evidence := exactReviewEvidenceSet(t, f, 1)
			p, local := exactReviewPrepareWithEvidence(t, f, evidence)
			exactReviewExpireArtifact(t, f, evidence[0].ref.ArtifactID)
			view, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, p)
			if err != nil || len(view.CitationAvailability) != 1 || view.CitationAvailability[0].Status != "available" {
				t.Fatalf("protected expired evidence view=%+v err=%v", view.CitationAvailability, err)
			}
			frozenReviewSHA := view.ReviewContextSHA256
			first, err := artifact.CleanupBatch(f.result.env.ctx, f.result.env.store, local, 10)
			if err != nil || first.Claimed != 0 {
				t.Fatalf("pending evidence was claimed: %+v %v", first, err)
			}
			if err := exactReviewDecide(t, f, p, decision); err != nil {
				t.Fatal(err)
			}
			second, err := artifact.CleanupBatch(f.result.env.ctx, f.result.env.store, local, 10)
			if err != nil || second.Removed != 1 {
				t.Fatalf("terminal evidence was not removed: %+v %v", second, err)
			}
			view, err = f.result.env.store.GetExactApprovalReview(f.result.env.ctx, p)
			if err != nil || view.CitationAvailability[0].Status != "unavailable" || view.ReviewContextSHA256 != frozenReviewSHA {
				t.Fatalf("deleted evidence view=%+v err=%v", view.CitationAvailability, err)
			}
		})
	}
}

func TestExactUnavailableOrRestrictedEvidenceBlocksApprovalButNotRejection(t *testing.T) {
	for _, restriction := range []string{"deleted", "missing_bytes", "sensitive"} {
		t.Run(restriction, func(t *testing.T) {
			f := pendingExactFixture(t, "exact-unavailable-"+restriction)
			evidence := exactReviewEvidenceSet(t, f, 1)
			p, local := exactReviewPrepareWithEvidence(t, f, evidence)
			id := evidence[0].ref.ArtifactID
			var err error
			if restriction == "deleted" {
				// A buggy claimant that bypasses the pending-review filter must
				// still leave approval unable to certify missing evidence.
				exactReviewExpireArtifact(t, f, id)
				var token domain.ID
				err = f.result.env.store.Pool.QueryRow(f.result.env.ctx,
					`UPDATE artifacts SET cleanup_claim_token=gen_random_uuid(),cleanup_claimed_at=clock_timestamp() WHERE id=$1 RETURNING cleanup_claim_token`, id).Scan(&token)
				if err == nil {
					_, err = local.DeleteContent(f.result.env.ctx, id, evidence[0].ref.StorageKey)
				}
				if err == nil {
					var finalized bool
					finalized, err = f.result.env.store.FinalizeArtifactCleanup(f.result.env.ctx, id, testArtifactStoreID, token, "removed")
					if err == nil && !finalized {
						t.Fatal("forced cleanup did not finalize")
					}
				}
			} else if restriction == "missing_bytes" {
				_, err = local.DeleteContent(f.result.env.ctx, id, evidence[0].ref.StorageKey)
			} else {
				_, err = f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE artifacts SET sensitive=true,redaction_state='sensitive-unredacted' WHERE id=$1`, id)
			}
			if err != nil {
				t.Fatal(err)
			}
			view, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, p)
			if err != nil || len(view.CitationAvailability) != 1 || view.CitationAvailability[0].Status != map[string]string{"deleted": "unavailable", "missing_bytes": "unavailable", "sensitive": "restricted"}[restriction] {
				t.Fatalf("unavailable evidence view=%+v err=%v", view.CitationAvailability, err)
			}
			if err := exactReviewDecide(t, f, p, "approved"); !errors.Is(err, ErrExactApprovalDenied) {
				t.Fatalf("approval=%v", err)
			}
			if err := exactReviewDecide(t, f, p, "rejected"); err != nil {
				t.Fatalf("rejection=%v", err)
			}
		})
	}
}

func TestExactReviewApprovalAndCleanupRace(t *testing.T) {
	for i := 0; i < 4; i++ {
		f := pendingExactFixture(t, "exact-cleanup-race-"+string(domain.NewID()))
		evidence := exactReviewEvidenceSet(t, f, 1)
		p, local := exactReviewPrepareWithEvidence(t, f, evidence)
		exactReviewExpireArtifact(t, f, evidence[0].ref.ArtifactID)
		view, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		var decisionErr, cleanupErr error
		var cleanup artifact.CleanupResult
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			decisionErr = f.result.env.store.DecideExactApproval(f.result.env.ctx, p, view.ActionSHA256, view.ReviewContextSHA256, "approved", "reviewer")
		}()
		go func() {
			defer wg.Done()
			<-start
			cleanup, cleanupErr = artifact.CleanupBatch(f.result.env.ctx, f.result.env.store, local, 10)
		}()
		close(start)
		wg.Wait()
		if decisionErr != nil || cleanupErr != nil {
			t.Fatalf("decision=%v cleanup=%v", decisionErr, cleanupErr)
		}
		var decidedAt, deletedAt time.Time
		if cleanup.Removed == 1 {
			if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx,
				`SELECT p.decided_at,a.content_deleted_at FROM approvals p JOIN exact_action_citations c ON c.action_request_id=p.action_request_id JOIN artifacts a ON a.id=c.artifact_id WHERE p.id=$1`, p).Scan(&decidedAt, &deletedAt); err != nil {
				t.Fatal(err)
			}
			if deletedAt.Before(decidedAt) {
				t.Fatalf("cleanup deleted evidence before successful approval: deleted=%v approved=%v", deletedAt, decidedAt)
			}
		}
	}
}

func TestExactReviewExpiryRevocationAndFailedPreparationRelease(t *testing.T) {
	for _, mode := range []string{"expired", "revoked", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			f := pendingExactFixture(t, "exact-release-"+mode)
			evidence := exactReviewEvidenceSet(t, f, 1)
			id := evidence[0].ref.ArtifactID
			var p domain.ID
			if mode == "rollback" {
				exactReviewLocalBytes(t, f, evidence)
				base, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
				if err != nil {
					t.Fatal(err)
				}
				review := base.Review
				review.SupportingEvidence = []exactaction.Citation{{ArtifactID: id, ArtifactSHA256: evidence[0].ref.ContentSHA256, Locator: "line 1"}}
				action := scheduledProviderAction(f.result, 1)
				x := recordScheduledProviderAdmission(t, f.result, exactFixtureContext(f.result), f.result.env.programID, action, nil, "fixture")
				sentinel := errors.New("rollback review preparation")
				_, err = f.result.env.store.prepareExactActionApproval(exactFixtureContext(f.result), f.result.env.programID, f.step, x.ProviderAttemptID,
					exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/allowed/review"},
					review, "reviewer", time.Now().Add(time.Hour), func(pgx.Tx) error { return sentinel })
				if !errors.Is(err, sentinel) {
					t.Fatal(err)
				}
			} else {
				p, _ = exactReviewPrepareWithEvidence(t, f, evidence)
			}
			exactReviewExpireArtifact(t, f, id)
			if mode == "expired" {
				if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, p); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "revoked" {
				if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE approvals SET revoked_at=clock_timestamp(),revoked_by='reviewer' WHERE id=$1`, p); err != nil {
					t.Fatal(err)
				}
			}
			claims, err := f.result.env.store.ClaimExpiredArtifacts(f.result.env.ctx, testArtifactStoreID, 10)
			if err != nil || len(claims) != 1 || claims[0].ID != id {
				t.Fatalf("stale review claim survived: mode=%s claims=%+v err=%v", mode, claims, err)
			}
		})
	}
}

func TestExactFrozenCitationSetAndDirectSQLMutations(t *testing.T) {
	for _, count := range []int{0, 1, 3} {
		f := pendingExactFixture(t, "exact-citation-count-"+string(domain.NewID()))
		evidence := exactReviewEvidenceSet(t, f, count)
		p, _ := exactReviewPrepareWithEvidence(t, f, evidence)
		view, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		var children int
		if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx, `SELECT count(*) FROM exact_action_citations WHERE action_request_id=$1`, view.Action.ActionID).Scan(&children); err != nil || children != count {
			t.Fatalf("committed child set=%d, want %d: %v", children, count, err)
		}
		if count != 3 {
			continue
		}
		if len(view.Review.SupportingEvidence) != 2 || len(view.Review.ContradictoryEvidence) != 1 {
			t.Fatal("supporting/contradictory classification changed")
		}
		unreferenced := exactReviewEvidenceSet(t, f, 1)[0]
		for _, query := range []struct {
			name string
			sql  string
			args []any
		}{
			{"extra", `INSERT INTO exact_action_citations(action_request_id,artifact_id,artifact_sha256) VALUES($1,$2,$3)`, []any{view.Action.ActionID, unreferenced.ref.ArtifactID, unreferenced.ref.ContentSHA256}},
			{"wrong_digest", `INSERT INTO exact_action_citations(action_request_id,artifact_id,artifact_sha256) VALUES($1,$2,$3)`, []any{view.Action.ActionID, evidence[0].ref.ArtifactID, strings.Repeat("f", 64)}},
			{"duplicate", `INSERT INTO exact_action_citations(action_request_id,artifact_id,artifact_sha256) VALUES($1,$2,$3)`, []any{view.Action.ActionID, evidence[0].ref.ArtifactID, evidence[0].ref.ContentSHA256}},
			{"update", `UPDATE exact_action_citations SET artifact_sha256=$3 WHERE action_request_id=$1 AND artifact_id=$2`, []any{view.Action.ActionID, evidence[0].ref.ArtifactID, strings.Repeat("f", 64)}},
			{"delete", `DELETE FROM exact_action_citations WHERE action_request_id=$1 AND artifact_id=$2`, []any{view.Action.ActionID, evidence[0].ref.ArtifactID}},
		} {
			if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, query.sql, query.args...); err == nil {
				t.Fatalf("%s mutation accepted", query.name)
			}
		}
		// A rejected extra member must not create a retention claim.
		exactReviewExpireArtifact(t, f, unreferenced.ref.ArtifactID)
		claims, err := f.result.env.store.ClaimExpiredArtifacts(f.result.env.ctx, testArtifactStoreID, 10)
		if err != nil || len(claims) != 1 || claims[0].ID != unreferenced.ref.ArtifactID {
			t.Fatalf("unreviewed artifact unexpectedly protected: %+v %v", claims, err)
		}
		// Reuse a valid frozen review in a new parent transaction, but omit its
		// third child. The deferred constraint must reject the commit itself.
		x := recordScheduledProviderAdmission(t, f.result, exactFixtureContext(f.result), f.result.env.programID, scheduledProviderAction(f.result, 1), nil, "fixture")
		tx, err := f.result.env.store.Pool.Begin(f.result.env.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(f.result.env.ctx, `INSERT INTO exact_actions(action_request_id,bound_provider_attempt_id,program_id,task_id,workflow_run_id,step_run_id,step_attempt,contract_schema,capability_semantic_revision,canonical_contract,action_sha256,review_schema,canonical_review_context,review_context_sha256,created_by)
			SELECT $1,$2,program_id,task_id,workflow_run_id,step_run_id,step_attempt,contract_schema,capability_semantic_revision,canonical_contract,action_sha256,review_schema,canonical_review_context,review_context_sha256,'test'
			FROM exact_actions WHERE action_request_id=$3`, x.ActionRequestID, x.ProviderAttemptID, view.Action.ActionID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(f.result.env.ctx, `INSERT INTO exact_action_citations(action_request_id,artifact_id,artifact_sha256) VALUES($1,$2,$3)`,
			x.ActionRequestID, evidence[0].ref.ArtifactID, strings.Repeat("f", 64)); err == nil || !strings.Contains(err.Error(), "absent from the frozen review") {
			_ = tx.Rollback(f.result.env.ctx)
			t.Fatalf("wrong canonical digest was not rejected by membership trigger: %v", err)
		}
		_ = tx.Rollback(f.result.env.ctx)

		tx, err = f.result.env.store.Pool.Begin(f.result.env.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(f.result.env.ctx, `INSERT INTO exact_actions(action_request_id,bound_provider_attempt_id,program_id,task_id,workflow_run_id,step_run_id,step_attempt,contract_schema,capability_semantic_revision,canonical_contract,action_sha256,review_schema,canonical_review_context,review_context_sha256,created_by)
			SELECT $1,$2,program_id,task_id,workflow_run_id,step_run_id,step_attempt,contract_schema,capability_semantic_revision,canonical_contract,action_sha256,review_schema,canonical_review_context,review_context_sha256,'test'
			FROM exact_actions WHERE action_request_id=$3`, x.ActionRequestID, x.ProviderAttemptID, view.Action.ActionID)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range evidence[:2] {
			if _, err := tx.Exec(f.result.env.ctx, `INSERT INTO exact_action_citations(action_request_id,artifact_id,artifact_sha256) VALUES($1,$2,$3)`,
				x.ActionRequestID, item.ref.ArtifactID, item.ref.ContentSHA256); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(f.result.env.ctx); err == nil {
			t.Fatal("incomplete frozen citation set committed")
		}
		var countAfter int
		if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx, `SELECT count(*) FROM exact_actions WHERE action_request_id=$1`, x.ActionRequestID).Scan(&countAfter); err != nil || countAfter != 0 {
			t.Fatalf("incomplete parent survived: count=%d err=%v", countAfter, err)
		}
	}
}

func TestExactReviewDuplicateCitationRejected(t *testing.T) {
	f := pendingExactFixture(t, "exact-duplicate-citation")
	evidence := exactReviewEvidenceSet(t, f, 1)
	base, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
	if err != nil {
		t.Fatal(err)
	}
	citation := exactaction.Citation{ArtifactID: evidence[0].ref.ArtifactID, ArtifactSHA256: evidence[0].ref.ContentSHA256, Locator: "line 1"}
	review := base.Review
	review.SupportingEvidence = []exactaction.Citation{citation}
	review.ContradictoryEvidence = []exactaction.Citation{citation}
	if _, _, err := review.Freeze(); err == nil {
		t.Fatal("duplicate supporting/contradictory citation accepted")
	}
}

func TestExactPreparationRequiresInspectableEvidence(t *testing.T) {
	for _, mode := range []string{"unconfigured_reader", "restricted"} {
		t.Run(mode, func(t *testing.T) {
			f := pendingExactFixture(t, "exact-preparation-"+mode)
			evidence := exactReviewEvidenceSet(t, f, 1)
			if mode == "restricted" {
				exactReviewLocalBytes(t, f, evidence)
				if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE artifacts SET sensitive=true WHERE id=$1`, evidence[0].ref.ArtifactID); err != nil {
					t.Fatal(err)
				}
			}
			base, err := f.result.env.store.GetExactApprovalReview(f.result.env.ctx, f.approvalID)
			if err != nil {
				t.Fatal(err)
			}
			review := base.Review
			review.SupportingEvidence = []exactaction.Citation{{ArtifactID: evidence[0].ref.ArtifactID, ArtifactSHA256: evidence[0].ref.ContentSHA256, Locator: "line 1"}}
			admission := recordScheduledProviderAdmission(t, f.result, exactFixtureContext(f.result), f.result.env.programID, scheduledProviderAction(f.result, 1), nil, "fixture")
			if _, err := f.result.env.store.PrepareExactActionApproval(exactFixtureContext(f.result), f.result.env.programID, f.step, admission.ProviderAttemptID,
				exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/allowed/review"},
				review, "reviewer", time.Now().Add(time.Hour)); !errors.Is(err, ErrExactApprovalDenied) {
				t.Fatalf("uninspectable evidence was prepared: %v", err)
			}
			var actions int
			if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx, `SELECT count(*) FROM exact_actions WHERE action_request_id=$1`, admission.ActionRequestID).Scan(&actions); err != nil || actions != 0 {
				t.Fatalf("failed preparation left a frozen action: count=%d err=%v", actions, err)
			}
		})
	}
}
