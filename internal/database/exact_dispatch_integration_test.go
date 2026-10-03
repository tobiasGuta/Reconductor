package database

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/scope"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

type exactDispatchFixture struct {
	result     scheduledResultFixture
	step       domain.StepRun
	attemptID  domain.ID
	approvalID domain.ID
	authority  ProgramLaunchAuthority
	include    []scope.Rule
	policy     policy.Policy
}

func newExactDispatchFixture(t *testing.T, name string) exactDispatchFixture {
	return newExactDispatchFixtureWithURL(t, name, "https://example.test/allowed/one")
}

func newExactDispatchFixtureWithURL(t *testing.T, name, targetURL string) exactDispatchFixture {
	t.Helper()
	result := newScheduledResultFixture(t, name, "http.request")
	return buildExactDispatchFixture(t, result, targetURL)
}

func newDirectExactDispatchFixture(t *testing.T, name string) exactDispatchFixture {
	t.Helper()
	env := newRecoveryTestEnvironment(t, name)
	task := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, name)
	runID, stepID := domain.NewID(), domain.NewID()
	now := time.Now().UTC()
	input := json.RawMessage(`{}`)
	key := name + "-provider"
	state := &workflow.State{Run: domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: env.definitionID,
		WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{"provider": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID,
			StepDefinitionID: "provider", Capability: "http.request", Status: domain.StepRunning, AttemptCount: 0,
			Input: input, StartedAt: &now, IdempotencyKey: key, ApprovalState: "not_required"}, InputHash: workflow.InputDigest(input)}}}
	materializeSyntheticWorkflowState(t, env.store, env.ctx, state)
	if err := env.store.SaveWorkflowState(env.ctx, state); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.Pool.Exec(env.ctx, `UPDATE step_runs SET attempt_count=1 WHERE id=$1`, stepID); err != nil {
		t.Fatal(err)
	}
	result := scheduledResultFixture{env: env, lineage: recoveryTestFixture{task: task, runID: runID}, stepID: stepID,
		idempotencyKey: key, capability: "http.request"}
	return buildExactDispatchFixture(t, result, "https://example.test/allowed/one")
}

func exactFixtureContext(result scheduledResultFixture) context.Context {
	if result.lineage.execution.ID == "" {
		return result.env.ctx
	}
	return result.context()
}

func buildExactDispatchFixture(t *testing.T, result scheduledResultFixture, targetURL string) exactDispatchFixture {
	return buildExactDispatchFixtureDecision(t, result, targetURL, true)
}

func buildExactDispatchFixtureDecision(t *testing.T, result scheduledResultFixture, targetURL string, approve bool) exactDispatchFixture {
	t.Helper()
	include := []scope.Rule{{Protocol: "https", Host: "example\\.test", Port: "443", File: "/allowed/.*", Enabled: true}}
	compiled, err := scope.Compile(include, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := result.env.store.Pool.Exec(result.env.ctx, `UPDATE programs SET scope_digest=$2 WHERE id=$1`, result.env.programID, compiled.Digest()); err != nil {
		t.Fatal(err)
	}
	pol := policy.Policy{ID: "fixture", AllowedCapabilities: []string{"http.request"}, AllowedHTTPMethods: []string{"GET", "HEAD"}}
	current, err := result.env.store.LaunchAuthority(result.env.ctx, result.env.programID)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := result.env.store.PublishLaunchAuthority(result.env.ctx, result.env.programID, current.Epoch, "integration-reviewer", include, nil, pol)
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(targetURL)
	if err != nil {
		t.Fatal(err)
	}
	action := scheduledProviderAction(result, 1)
	admission := recordScheduledProviderAdmission(t, result, exactFixtureContext(result), result.env.programID, action, nil, "fixture")
	step := domain.StepRun{ID: result.stepID, WorkflowRunID: result.lineage.runID, Capability: "http.request", IdempotencyKey: result.idempotencyKey}
	review := exactaction.ReviewContextV1{ReviewVersion: exactaction.ReviewVersion, ProposalSource: exactaction.ProposalSource{Kind: "integration"}, Purpose: "verify exact gate", ExpectedPositiveOutcome: "one dispatch intent", ExpectedNegativeOutcome: "scope or policy denial", Assumptions: []string{}, MissingEvidence: []string{}, SupportingEvidence: []exactaction.Citation{}, ContradictoryEvidence: []exactaction.Citation{}}
	approvalID, err := result.env.store.PrepareExactActionApproval(exactFixtureContext(result), result.env.programID, step, admission.ProviderAttemptID,
		exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: target.Hostname(), EffectivePort: 443, RequestTarget: target.RequestURI()}, review, "integration-reviewer", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := result.env.store.GetExactApprovalReview(result.env.ctx, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	if approve {
		if err := result.env.store.DecideExactApproval(result.env.ctx, approvalID, projection.ActionSHA256, projection.ReviewContextSHA256, "approved", "integration-reviewer"); err != nil {
			t.Fatal(err)
		}
	}
	return exactDispatchFixture{result: result, step: step, attemptID: admission.ProviderAttemptID, approvalID: approvalID, authority: authority, include: include, policy: pol}
}

func (f exactDispatchFixture) admit() (*ExactDispatchPermit, error) {
	return f.result.env.store.AdmitExactDispatch(exactFixtureContext(f.result), f.result.env.programID, f.step, f.attemptID)
}

func TestExactDispatchDirectAndScheduledUseSameGate(t *testing.T) {
	f := newDirectExactDispatchFixture(t, "exact-direct-path")
	p, err := f.admit()
	if err != nil || p == nil {
		t.Fatalf("direct admission=%v err=%v", p, err)
	}
	if state, audits := f.state(t); state != "DISPATCH_INTENT" || audits != 1 {
		t.Fatalf("state=%s audits=%d", state, audits)
	}
	f.assertSecondDenied(t)
}

func (f exactDispatchFixture) state(t *testing.T) (string, int) {
	t.Helper()
	var state string
	var audits int
	err := f.result.env.store.Pool.QueryRow(f.result.env.ctx, `SELECT state,
		(SELECT count(*) FROM audit_events WHERE provider_attempt_id=$1 AND event_type='exact_dispatch_intent')
		FROM exact_dispatch_attempts WHERE provider_attempt_id=$1`, f.attemptID).Scan(&state, &audits)
	if err != nil {
		t.Fatal(err)
	}
	return state, audits
}

func (f exactDispatchFixture) assertDeniedUnchanged(t *testing.T) {
	t.Helper()
	permit, err := f.admit()
	if err == nil || permit != nil {
		t.Fatalf("admitted invalid fixture permit=%v err=%v", permit, err)
	}
	if state, audits := f.state(t); state != "UNDISPATCHED" || audits != 0 {
		t.Fatalf("state=%s audits=%d", state, audits)
	}
}

func TestExactDispatchOneWinnerAndDurableProvenance(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-one-winner")
	const callers = 2
	start := make(chan struct{})
	results := make(chan *ExactDispatchPermit, callers)
	errorsOut := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; p, err := f.admit(); results <- p; errorsOut <- err }()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errorsOut)
	winners := 0
	for p := range results {
		if p != nil {
			winners++
			copyOfPermit := *p
			trustedNow := time.Now().UTC()
			if p.AuthorityEpoch() != f.authority.Epoch || !p.ConsumeAt(trustedNow) || copyOfPermit.ConsumeAt(trustedNow) || p.ConsumeAt(trustedNow) || p.Deadline() == nil {
				t.Fatalf("invalid permit %#v", p)
			}
		}
	}
	for err := range errorsOut {
		if err != nil && !errors.Is(err, ErrExactDispatchDenied) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("winners=%d", winners)
	}
	if state, audits := f.state(t); state != "DISPATCH_INTENT" || audits != 1 {
		t.Fatalf("state=%s audits=%d", state, audits)
	}
	f.assertSecondDenied(t)
	var epoch int64
	var scopeID, policyID domain.ID
	if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx, `SELECT authority_epoch,active_scope_id,active_policy_id
		FROM exact_dispatch_attempts WHERE provider_attempt_id=$1`, f.attemptID).Scan(&epoch, &scopeID, &policyID); err != nil {
		t.Fatal(err)
	}
	if epoch != f.authority.Epoch || scopeID != *f.authority.ActiveScopeID || policyID != *f.authority.ActivePolicyID {
		t.Fatalf("provenance epoch=%d scope=%s policy=%s", epoch, scopeID, policyID)
	}
	for _, statement := range []string{
		"UPDATE exact_dispatch_attempts SET state='UNDISPATCHED' WHERE provider_attempt_id=$1",
		"DELETE FROM exact_dispatch_attempts WHERE provider_attempt_id=$1",
	} {
		if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, statement, f.attemptID); err == nil {
			t.Fatalf("intent mutation succeeded: %s", statement)
		}
	}
	for _, statement := range []string{
		"UPDATE scopes SET definition='{}'::jsonb WHERE id=$1",
		"DELETE FROM scopes WHERE id=$1",
	} {
		if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, statement, scopeID); err == nil {
			t.Fatalf("scope material mutation succeeded: %s", statement)
		}
	}
}

func (f exactDispatchFixture) assertSecondDenied(t *testing.T) {
	t.Helper()
	if p, err := f.admit(); p != nil || !errors.Is(err, ErrExactDispatchDenied) {
		t.Fatalf("duplicate p=%v err=%v", p, err)
	}
}

func TestExactDispatchFailClosedAuthorityAndMaterial(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, f exactDispatchFixture)
	}{
		{"blocked", func(t *testing.T, f exactDispatchFixture) {
			_, err := f.result.env.store.BeginLaunchAuthorityUpdate(f.result.env.ctx, f.result.env.programID, f.authority.Epoch, "reviewer", "block")
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"missing scope material", func(t *testing.T, f exactDispatchFixture) { replaceExactScope(t, f, "null") }},
		{"missing policy material", func(t *testing.T, f exactDispatchFixture) { replaceExactPolicy(t, f, "null") }},
		{"wrong scope owner", func(t *testing.T, f exactDispatchFixture) {
			other, _ := createSchedulerIntegrationProgram(t, f.result.env.ctx, f.result.env.store, "exact-other-owner")
			id := domain.NewID()
			_, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `INSERT INTO scopes(id,program_id,version,definition,material_schema,evaluator_revision,canonical_material,material_sha256,scope_digest)
			SELECT $1,$2,1,definition,material_schema,evaluator_revision,canonical_material,material_sha256,scope_digest FROM scopes WHERE id=$3`, id, other, *f.authority.ActiveScopeID)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE program_launch_authority SET active_scope_id=$2,authority_epoch=authority_epoch+1 WHERE program_id=$1`, f.result.env.programID, id)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"scope digest mismatch", func(t *testing.T, f exactDispatchFixture) { replaceExactScope(t, f, "digest") }},
		{"scope malformed", func(t *testing.T, f exactDispatchFixture) { replaceExactScope(t, f, "malformed") }},
		{"scope schema", func(t *testing.T, f exactDispatchFixture) { replaceExactScope(t, f, "schema") }},
		{"scope evaluator", func(t *testing.T, f exactDispatchFixture) { replaceExactScope(t, f, "evaluator") }},
		{"policy digest mismatch", func(t *testing.T, f exactDispatchFixture) { replaceExactPolicy(t, f, "digest") }},
		{"policy schema", func(t *testing.T, f exactDispatchFixture) { replaceExactPolicy(t, f, "schema") }},
		{"policy evaluator", func(t *testing.T, f exactDispatchFixture) { replaceExactPolicy(t, f, "evaluator") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newExactDispatchFixture(t, "exact-deny-"+tc.name)
			tc.mutate(t, f)
			f.assertDeniedUnchanged(t)
		})
	}
}

func TestExactDispatchApprovalAndCurrentPolicy(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, f exactDispatchFixture)
	}{
		{"revoked", func(t *testing.T, f exactDispatchFixture) {
			_, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE approvals SET revoked_at=clock_timestamp(),revoked_by='reviewer' WHERE bound_provider_attempt_id=$1`, f.attemptID)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"expired", func(t *testing.T, f exactDispatchFixture) {
			_, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE bound_provider_attempt_id=$1`, f.attemptID)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"denied policy", func(t *testing.T, f exactDispatchFixture) {
			p := f.policy
			p.DeniedCapabilities = []string{"http.request"}
			a, err := f.result.env.store.PublishLaunchAuthority(f.result.env.ctx, f.result.env.programID, f.authority.Epoch, "reviewer", f.include, nil, p)
			if err != nil || a.Status != "READY" {
				t.Fatalf("publication=%v %v", a, err)
			}
		}},
		{"method restriction", func(t *testing.T, f exactDispatchFixture) {
			p := f.policy
			p.AllowedHTTPMethods = []string{"HEAD"}
			if _, err := f.result.env.store.PublishLaunchAuthority(f.result.env.ctx, f.result.env.programID, f.authority.Epoch, "reviewer", f.include, nil, p); err != nil {
				t.Fatal(err)
			}
		}},
		{"payload limit", func(t *testing.T, f exactDispatchFixture) {
			p := f.policy
			p.MaximumPayloadSize = 1
			if _, err := f.result.env.store.PublishLaunchAuthority(f.result.env.ctx, f.result.env.programID, f.authority.Epoch, "reviewer", f.include, nil, p); err != nil {
				t.Fatal(err)
			}
		}},
		{"outside scan window", func(t *testing.T, f exactDispatchFixture) {
			var now time.Time
			if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			p := f.policy
			p.ScanWindows = []string{now.UTC().AddDate(0, 0, 2).Weekday().String() + " 00:00-00:01 UTC"}
			if _, err := f.result.env.store.PublishLaunchAuthority(f.result.env.ctx, f.result.env.programID, f.authority.Epoch, "reviewer", f.include, nil, p); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newExactDispatchFixture(t, "exact-policy-"+tc.name)
			tc.mutate(t, f)
			f.assertDeniedUnchanged(t)
		})
	}
	t.Run("out of scope", func(t *testing.T) {
		f := newExactDispatchFixtureWithURL(t, "exact-out-of-scope", "https://example.test/other")
		f.assertDeniedUnchanged(t)
	})
}

func TestExactDispatchFaultBeforeCommitRollsBack(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-commit-fault")
	sentinel := errors.New("injected precommit failure")
	p, err := f.result.env.store.admitExactDispatch(f.result.context(), f.result.env.programID, f.step, f.attemptID, func(pgx.Tx) error { return sentinel })
	if p != nil || !errors.Is(err, sentinel) {
		t.Fatalf("p=%v err=%v", p, err)
	}
	if state, audits := f.state(t); state != "UNDISPATCHED" || audits != 0 {
		t.Fatalf("state=%s audits=%d", state, audits)
	}
	if p, err = f.admit(); err != nil || p == nil {
		t.Fatalf("retry p=%v err=%v", p, err)
	}
}

func TestExactAuthorityPublisherGenerationAndFailedCandidate(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-publisher-generation")
	if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, "UPDATE program_launch_authority SET authority_epoch=authority_epoch-1 WHERE program_id=$1", f.result.env.programID); err == nil {
		t.Fatal("authority epoch moved backwards")
	}
	blocked, err := f.result.env.store.BeginLaunchAuthorityUpdate(f.result.env.ctx, f.result.env.programID, f.authority.Epoch, "reviewer", "managed update")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.result.env.store.PublishLaunchAuthority(f.result.env.ctx, f.result.env.programID, f.authority.Epoch, "stale", f.include, nil, f.policy); !errors.Is(err, ErrLaunchAuthorityConflict) {
		t.Fatalf("stale publication=%v", err)
	}
	if _, err := f.result.env.store.activateLaunchPair(f.result.env.ctx, f.result.env.programID, blocked-1, "stale", *f.authority.ActiveScopeID, *f.authority.ActivePolicyID); !errors.Is(err, ErrLaunchAuthorityConflict) {
		t.Fatalf("stale activation=%v", err)
	}
	if _, err := f.result.env.store.PublishLaunchAuthority(f.result.env.ctx, f.result.env.programID, blocked, "reviewer", []scope.Rule{{Protocol: "[", Host: "x", Port: "443", File: "/", Enabled: true}}, nil, f.policy); err == nil {
		t.Fatal("malformed candidate published")
	}
	a, err := f.result.env.store.LaunchAuthority(f.result.env.ctx, f.result.env.programID)
	if err != nil || a.Status != "BLOCKED" || a.Epoch != blocked+1 {
		t.Fatalf("authority=%v err=%v", a, err)
	}
	f.assertDeniedUnchanged(t)
	restored, err := f.result.env.store.ActivateExistingLaunchAuthority(f.result.env.ctx, f.result.env.programID, a.Epoch, "reviewer", *f.authority.ActiveScopeID, *f.authority.ActivePolicyID)
	if err != nil || restored.Status != "READY" || restored.Epoch <= a.Epoch {
		t.Fatalf("restored=%v err=%v", restored, err)
	}
}

func TestExactDispatchWaitsForAuthorityUpdate(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-authority-wait")
	tx, err := f.result.env.store.Pool.Begin(f.result.env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.result.env.ctx)
	if _, err := tx.Exec(f.result.env.ctx, `UPDATE program_launch_authority SET status='BLOCKED',authority_epoch=authority_epoch+1 WHERE program_id=$1`, f.result.env.programID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.result.context(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := f.result.env.store.AdmitExactDispatch(ctx, f.result.env.programID, f.step, f.attemptID)
		done <- err
	}()
	// The blocked admission is observed through PostgreSQL's lock graph rather
	// than a timing guess. A committed tightening must win before admission.
	if err := waitForExactAuthorityBlocker(f.result.env.ctx, f.result.env.store, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.result.env.ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrExactDispatchDenied) {
		t.Fatalf("admission after block=%v", err)
	}
	if state, audits := f.state(t); state != "UNDISPATCHED" || audits != 0 {
		t.Fatalf("state=%s audits=%d", state, audits)
	}
}

func TestAuthorityPublicationWaitsForCommittedDispatch(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-publication-waits")
	gatePID := make(chan int, 1)
	release := make(chan struct{})
	gateDone := make(chan struct {
		permit *ExactDispatchPermit
		err    error
	}, 1)
	go func() {
		permit, err := f.result.env.store.admitExactDispatch(f.result.context(), f.result.env.programID, f.step, f.attemptID, func(tx pgx.Tx) error {
			var pid int
			if err := tx.QueryRow(f.result.env.ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				return err
			}
			gatePID <- pid
			<-release
			return nil
		})
		gateDone <- struct {
			permit *ExactDispatchPermit
			err    error
		}{permit, err}
	}()
	var pid int
	select {
	case pid = <-gatePID:
	case result := <-gateDone:
		t.Fatalf("gate failed before intent: %v", result.err)
	case <-time.After(10 * time.Second):
		t.Fatal("gate did not reach commit boundary")
	}
	publishDone := make(chan error, 1)
	go func() {
		_, err := f.result.env.store.BeginLaunchAuthorityUpdate(f.result.env.ctx, f.result.env.programID, f.authority.Epoch, "reviewer", "scope tightening")
		publishDone <- err
	}()
	if err := waitForExactBlockerPID(f.result.env.ctx, f.result.env.store, pid); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	gate := <-gateDone
	if gate.err != nil || gate.permit == nil || gate.permit.AuthorityEpoch() != f.authority.Epoch {
		t.Fatalf("gate=%v err=%v", gate.permit, gate.err)
	}
	if err := <-publishDone; err != nil {
		t.Fatal(err)
	}
	a, err := f.result.env.store.LaunchAuthority(f.result.env.ctx, f.result.env.programID)
	if err != nil || a.Status != "BLOCKED" || a.Epoch != f.authority.Epoch+1 {
		t.Fatalf("authority=%v err=%v", a, err)
	}
	if state, audits := f.state(t); state != "DISPATCH_INTENT" || audits != 1 {
		t.Fatalf("state=%s audits=%d", state, audits)
	}
}

func TestExactDispatchFreshDBClockAfterApprovalWait(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-approval-expiry-wait")
	tx, err := f.result.env.store.Pool.Begin(f.result.env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.result.env.ctx)
	if _, err := tx.Exec(f.result.env.ctx, `UPDATE approvals SET expires_at=clock_timestamp()-interval '1 second'
		WHERE bound_provider_attempt_id=$1`, f.attemptID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.result.context(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := f.result.env.store.AdmitExactDispatch(ctx, f.result.env.programID, f.step, f.attemptID)
		done <- err
	}()
	if err := waitForExactAuthorityBlocker(f.result.env.ctx, f.result.env.store, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.result.env.ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrExactDispatchDenied) {
		t.Fatalf("admission after expiry=%v", err)
	}
	if state, audits := f.state(t); state != "UNDISPATCHED" || audits != 0 {
		t.Fatalf("state=%s audits=%d", state, audits)
	}
}

func TestConcurrentScopeTighteningWinsBeforeDispatchIntent(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-concurrent-scope-tightening")
	tx, err := f.result.env.store.Pool.Begin(f.result.env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.result.env.ctx)
	if _, err := tx.Exec(f.result.env.ctx, "UPDATE programs SET scope_digest='tightened-before-intent' WHERE id=$1", f.result.env.programID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(f.result.context(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := f.result.env.store.AdmitExactDispatch(ctx, f.result.env.programID, f.step, f.attemptID)
		done <- err
	}()
	if err := waitForExactAuthorityBlocker(f.result.env.ctx, f.result.env.store, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(f.result.env.ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrExactDispatchDenied) {
		t.Fatalf("admission after tightening=%v", err)
	}
	a, err := f.result.env.store.LaunchAuthority(f.result.env.ctx, f.result.env.programID)
	if err != nil || a.Status != "BLOCKED" {
		t.Fatalf("authority=%v err=%v", a, err)
	}
	if state, audits := f.state(t); state != "UNDISPATCHED" || audits != 0 {
		t.Fatalf("state=%s audits=%d", state, audits)
	}
}

func TestExactScopeWritersInvalidateAndLocatorRepairPreservesAuthority(t *testing.T) {
	t.Run("semantic program update", func(t *testing.T) {
		f := newExactDispatchFixture(t, "exact-program-scope-writer")
		if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE programs SET scope_digest='new-semantic-digest' WHERE id=$1`, f.result.env.programID); err != nil {
			t.Fatal(err)
		}
		a, err := f.result.env.store.LaunchAuthority(f.result.env.ctx, f.result.env.programID)
		if err != nil || a.Status != "BLOCKED" || a.Epoch <= f.authority.Epoch {
			t.Fatalf("authority=%v err=%v", a, err)
		}
		f.assertDeniedUnchanged(t)
	})
	t.Run("pending expansion", func(t *testing.T) {
		f := newExactDispatchFixture(t, "exact-pending-expansion")
		snapshot := domain.ScopeSnapshot{ProgramID: f.result.env.programID, ScopeReference: "synthetic://new",
			ScopeDigest: "pending-scope", IncludeRuleDigests: []string{"new-include"}, ExcludeRuleDigests: []string{"new-exclusion"},
			TargetPlanDigest: "pending-plan", PlanningWarnings: json.RawMessage(`[]`), TargetPlan: json.RawMessage(`{}`)}
		change, err := f.result.env.store.CheckAndRecordScopeSnapshot(f.result.env.ctx, snapshot, false, "integration-reviewer")
		if err != nil || !change.Changed || change.Acknowledged {
			t.Fatalf("change=%v err=%v", change, err)
		}
		a, err := f.result.env.store.LaunchAuthority(f.result.env.ctx, f.result.env.programID)
		if err != nil || a.Status != "BLOCKED" {
			t.Fatalf("authority=%v err=%v", a, err)
		}
		f.assertDeniedUnchanged(t)
	})
	t.Run("locator repair", func(t *testing.T) {
		f := newExactDispatchFixture(t, "exact-locator-repair")
		var digest, plan string
		if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx, `SELECT scope_digest,target_plan_digest FROM programs WHERE id=$1`, f.result.env.programID).Scan(&digest, &plan); err != nil {
			t.Fatal(err)
		}
		if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE scope_versions SET scope_digest=$2 WHERE program_id=$1`, f.result.env.programID, digest); err != nil {
			t.Fatal(err)
		}
		if err := f.result.env.store.RepairProgramScopeReference(f.result.env.ctx, f.result.env.programID, "synthetic://repaired", digest, plan, "integration-reviewer"); err != nil {
			t.Fatal(err)
		}
		a, err := f.result.env.store.LaunchAuthority(f.result.env.ctx, f.result.env.programID)
		if err != nil || a.Status != "READY" || a.Epoch != f.authority.Epoch {
			t.Fatalf("authority=%v err=%v", a, err)
		}
		if p, err := f.admit(); err != nil || p == nil {
			t.Fatalf("admission=%v err=%v", p, err)
		}
	})
}

func TestExactDispatchStaleScheduledClaimDenied(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-stale-scheduler")
	stale := f.result.fence
	stale.LeaseOwner = "former-owner"
	p, err := f.result.env.store.AdmitExactDispatch(WithScheduledExecutionFence(f.result.env.ctx, stale), f.result.env.programID, f.step, f.attemptID)
	if p != nil || err == nil {
		t.Fatalf("stale admission=%v err=%v", p, err)
	}
	if state, audits := f.state(t); state != "UNDISPATCHED" || audits != 0 {
		t.Fatalf("state=%s audits=%d", state, audits)
	}
}

func TestExactDispatchCancelledTaskDenied(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-cancelled-task")
	if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, "UPDATE tasks SET status='cancelled' WHERE id=$1", f.result.lineage.task.ID); err != nil {
		t.Fatal(err)
	}
	f.assertDeniedUnchanged(t)
}

func TestScopeTighteningAfterIntentKeepsSingleHistoricalX(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-tighten-after-intent")
	p, err := f.admit()
	if err != nil || p == nil {
		t.Fatalf("admission=%v err=%v", p, err)
	}
	if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE programs SET scope_digest='tightened' WHERE id=$1`, f.result.env.programID); err != nil {
		t.Fatal(err)
	}
	a, err := f.result.env.store.LaunchAuthority(f.result.env.ctx, f.result.env.programID)
	if err != nil || a.Status != "BLOCKED" || a.Epoch <= p.AuthorityEpoch() {
		t.Fatalf("authority=%v err=%v", a, err)
	}
	f.assertSecondDenied(t)
	var storedEpoch int64
	if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx, `SELECT authority_epoch FROM exact_dispatch_attempts WHERE provider_attempt_id=$1`, f.attemptID).Scan(&storedEpoch); err != nil {
		t.Fatal(err)
	}
	if storedEpoch != p.AuthorityEpoch() {
		t.Fatalf("historical epoch=%d permit=%d", storedEpoch, p.AuthorityEpoch())
	}
}

func waitForExactAuthorityBlocker(ctx context.Context, store *Store, tx pgx.Tx) error {
	var blockerPID int
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		return err
	}
	return waitForExactBlockerPID(ctx, store, blockerPID)
}

func waitForExactBlockerPID(ctx context.Context, store *Store, blockerPID int) error {
	deadline, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		err := store.Pool.QueryRow(deadline, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a
			WHERE $1=ANY(pg_blocking_pids(a.pid)))`, blockerPID).Scan(&blocked)
		if err != nil {
			return err
		}
		if blocked {
			return nil
		}
		select {
		case <-ticker.C:
		case <-deadline.Done():
			return deadline.Err()
		}
	}
}

func replaceExactScope(t *testing.T, f exactDispatchFixture, mode string) {
	t.Helper()
	id := domain.NewID()
	materialExpr, hashExpr, schemaExpr, evalExpr, scopeDigestExpr := "canonical_material", "material_sha256", "material_schema", "evaluator_revision", "scope_digest"
	switch mode {
	case "null":
		materialExpr, hashExpr, schemaExpr, evalExpr, scopeDigestExpr = "NULL", "NULL", "NULL", "NULL", "NULL"
	case "digest":
		hashExpr = "repeat('0',64)"
	case "malformed":
		materialExpr = "'not-json'::bytea"
	case "schema":
		schemaExpr = "'unsupported'"
	case "evaluator":
		evalExpr = "'unsupported'"
	default:
		t.Fatal(mode)
	}
	query := `INSERT INTO scopes(id,program_id,version,definition,material_schema,evaluator_revision,canonical_material,material_sha256,scope_digest)
		SELECT $1,program_id,version+1,definition,` + schemaExpr + `,` + evalExpr + `,` + materialExpr + `,` + hashExpr + `,` + scopeDigestExpr + ` FROM scopes WHERE id=$2`
	if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, query, id, *f.authority.ActiveScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE program_launch_authority SET active_scope_id=$2,authority_epoch=authority_epoch+1 WHERE program_id=$1`, f.result.env.programID, id); err != nil {
		t.Fatal(err)
	}
}

func replaceExactPolicy(t *testing.T, f exactDispatchFixture, mode string) {
	t.Helper()
	id := domain.NewID()
	materialExpr, hashExpr, schemaExpr, evalExpr := "canonical_material", "material_sha256", "material_schema", "evaluator_revision"
	switch mode {
	case "null":
		materialExpr, hashExpr, schemaExpr, evalExpr = "NULL", "NULL", "NULL", "NULL"
	case "digest":
		hashExpr = "repeat('0',64)"
	case "schema":
		schemaExpr = "'unsupported'"
	case "evaluator":
		evalExpr = "'unsupported'"
	default:
		t.Fatal(mode)
	}
	query := `INSERT INTO policies(id,program_id,version,definition,material_schema,evaluator_revision,canonical_material,material_sha256)
		SELECT $1,program_id,version+1,definition,` + schemaExpr + `,` + evalExpr + `,` + materialExpr + `,` + hashExpr + ` FROM policies WHERE id=$2`
	if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, query, id, *f.authority.ActivePolicyID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `UPDATE program_launch_authority SET active_policy_id=$2,authority_epoch=authority_epoch+1 WHERE program_id=$1`, f.result.env.programID, id); err != nil {
		t.Fatal(err)
	}
}

func TestExactPendingTighterScopeCannotBeReactivated(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-pending-reactivation-regression")
	includes := append([]scope.Rule(nil), f.include...)
	includes = append(includes, scope.Rule{Protocol: "https", Host: "new\\.test", Port: "443", File: "/.*", Enabled: true})
	excludes := []scope.Rule{{Protocol: "https", Host: "example\\.test", Port: "443", File: "/allowed/.*", Enabled: true}}
	candidate, err := scope.Compile(includes, excludes)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := targeting.Plan(candidate, nil)
	if err != nil {
		t.Fatal(err)
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	warnings, err := json.Marshal(plan.Warnings)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := domain.ScopeSnapshot{ProgramID: f.result.env.programID, ScopeReference: "synthetic://pending-exclusion",
		ScopeDigest: candidate.Digest(), IncludeRuleDigests: candidate.IncludeDigests(), ExcludeRuleDigests: candidate.ExcludeDigests(),
		TargetPlanDigest: plan.Digest, PlanningWarnings: warnings, TargetPlan: planJSON}
	change, err := f.result.env.store.CheckAndRecordScopeSnapshot(f.result.env.ctx, snapshot, false, "reviewer")
	if err != nil || !change.Changed || !change.ExpandsScope || change.Acknowledged {
		t.Fatalf("pending candidate=%+v err=%v", change, err)
	}
	a, err := f.result.env.store.LaunchAuthority(f.result.env.ctx, f.result.env.programID)
	if err != nil || a.Status != "BLOCKED" {
		t.Fatalf("authority=%+v err=%v", a, err)
	}
	if _, err := f.result.env.store.ActivateExistingLaunchAuthority(f.result.env.ctx, f.result.env.programID,
		a.Epoch, "reviewer", *f.authority.ActiveScopeID, *f.authority.ActivePolicyID); !errors.Is(err, ErrLaunchAuthorityConflict) {
		t.Fatalf("old pair reactivation=%v", err)
	}
	a, err = f.result.env.store.LaunchAuthority(f.result.env.ctx, f.result.env.programID)
	if err != nil || a.Status != "BLOCKED" {
		t.Fatalf("authority after refusal=%+v err=%v", a, err)
	}
	f.assertDeniedUnchanged(t)
	// The gate also rejects an out-of-band READY pointer while the candidate is pending.
	if _, err := f.result.env.store.Pool.Exec(f.result.env.ctx,
		`UPDATE program_launch_authority SET status='READY',authority_epoch=authority_epoch+1 WHERE program_id=$1`, f.result.env.programID); err != nil {
		t.Fatal(err)
	}
	f.assertDeniedUnchanged(t)
	if err := f.result.env.store.AcknowledgeScopeVersion(f.result.env.ctx, change.ScopeVersionID, "reviewer"); err != nil {
		t.Fatal(err)
	}
	a, err = f.result.env.store.LaunchAuthority(f.result.env.ctx, f.result.env.programID)
	if err != nil || a.Status != "BLOCKED" {
		t.Fatalf("authority after acknowledgement=%+v err=%v", a, err)
	}
	published, err := f.result.env.store.PublishLaunchAuthority(f.result.env.ctx, f.result.env.programID,
		a.Epoch, "reviewer", includes, excludes, f.policy)
	if err != nil || published.Status != "READY" {
		t.Fatalf("resolved publication=%+v err=%v", published, err)
	}
	f.assertDeniedUnchanged(t) // The newly published exclusion still vetoes the old action.
}

func TestExactSchedulerLeaseExpiresDuringAuthorityWait(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-lease-wait-regression")
	ctx, cancel := context.WithTimeout(f.result.context(), 15*time.Second)
	defer cancel()
	if _, err := f.result.env.store.Pool.Exec(ctx,
		`UPDATE scheduled_executions SET lease_expires_at=clock_timestamp()+interval '2 seconds' WHERE id=$1`, f.result.lineage.execution.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := f.result.env.store.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, `SELECT program_id FROM program_launch_authority WHERE program_id=$1 FOR UPDATE`, f.result.env.programID); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		permit *ExactDispatchPermit
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		permit, err := f.result.env.store.AdmitExactDispatch(ctx, f.result.env.programID, f.step, f.attemptID)
		done <- outcome{permit, err}
	}()
	if err := waitForExactAuthorityBlocker(ctx, f.result.env.store, tx); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var expired bool
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()>=lease_expires_at FROM scheduled_executions WHERE id=$1`,
			f.result.lineage.execution.ID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.permit != nil || !errors.Is(result.err, ErrExactDispatchDenied) {
		t.Fatalf("expired scheduler admission permit=%v err=%v", result.permit, result.err)
	}
	if state, audits := f.state(t); state != "UNDISPATCHED" || audits != 0 {
		t.Fatalf("expired scheduler state=%s audits=%d", state, audits)
	}
}

func TestExactScheduledPermitDeadlineIncludesLease(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-lease-deadline-regression")
	var expires time.Time
	if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx,
		`UPDATE scheduled_executions SET lease_expires_at=clock_timestamp()+interval '30 seconds' WHERE id=$1 RETURNING lease_expires_at`,
		f.result.lineage.execution.ID).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	permit, err := f.admit()
	if err != nil || permit == nil {
		t.Fatalf("permit=%v err=%v", permit, err)
	}
	if permit.Deadline() == nil || !permit.Deadline().Equal(expires) {
		t.Fatalf("deadline=%v lease=%v", permit.Deadline(), expires)
	}
}

func TestExactPermitConsumeAtDeadline(t *testing.T) {
	deadline := time.Date(2026, time.September, 30, 12, 0, 0, 0, time.UTC)
	makePermit := func() *ExactDispatchPermit {
		return &ExactDispatchPermit{deadline: &deadline, used: new(atomic.Bool)}
	}
	before := deadline.Add(-time.Nanosecond)
	permit := makePermit()
	copyOfPermit := *permit
	if !permit.ConsumeAt(before) || copyOfPermit.ConsumeAt(before) || permit.ConsumeAt(before) {
		t.Fatal("copied or repeated permit consumed more than once")
	}
	for _, instant := range []time.Time{deadline, deadline.Add(time.Nanosecond)} {
		permit = makePermit()
		if permit.ConsumeAt(instant) || permit.used.Load() {
			t.Fatalf("permit consumed at or after deadline: %v", instant)
		}
	}
	if makePermit().ConsumeAt(time.Time{}) {
		t.Fatal("zero time consumed permit")
	}
}

func seedPendingExactApprovalAtWorkflowStep(t *testing.T, f exactDispatchFixture) (domain.ID, domain.ID) {
	t.Helper()
	action := scheduledProviderAction(f.result, 1)
	admission := recordScheduledProviderAdmission(t, f.result, exactFixtureContext(f.result),
		f.result.env.programID, action, nil, "fixture")
	approvalID := domain.NewID()
	_, err := f.result.env.store.Pool.Exec(f.result.env.ctx, `INSERT INTO approvals(
		id,request_id,task_id,action_request_id,requested_risk_level,reason,decision,expires_at,
		approval_kind,action_sha256,review_context_sha256,bound_provider_attempt_id)
		SELECT $1,$2,task_id,$3,requested_risk_level,'pending exact review','pending',expires_at,
		approval_kind,action_sha256,review_context_sha256,$4 FROM approvals WHERE bound_provider_attempt_id=$5`,
		approvalID, f.step.ID, action.ID, admission.ProviderAttemptID, f.attemptID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.result.env.store.Pool.Exec(f.result.env.ctx,
		`INSERT INTO exact_dispatch_attempts(provider_attempt_id,approval_id,program_id,action_request_id,action_sha256)
		 SELECT $1,$2,program_id,$3,action_sha256 FROM exact_dispatch_attempts WHERE provider_attempt_id=$4`,
		admission.ProviderAttemptID, approvalID, action.ID, f.attemptID)
	if err != nil {
		t.Fatal(err)
	}
	return approvalID, admission.ProviderAttemptID
}

func TestLegacyDecisionCannotApproveExactApproval(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-legacy-decision-regression")
	approvalID, attemptID := seedPendingExactApprovalAtWorkflowStep(t, f)
	if err := f.result.env.store.DecideApproval(f.result.env.ctx, approvalID, "approved", "workflow-reviewer"); err == nil {
		t.Fatal("legacy decision approved exact P")
	}
	var decision string
	if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx, `SELECT decision FROM approvals WHERE id=$1`, approvalID).Scan(&decision); err != nil || decision != "pending" {
		t.Fatalf("exact decision=%q err=%v", decision, err)
	}
	listed, err := f.result.env.store.ListApprovals(f.result.env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range listed {
		if item.ID == approvalID {
			t.Fatal("exact P appeared in legacy approval listing")
		}
	}
	if permit, err := f.result.env.store.AdmitExactDispatch(exactFixtureContext(f.result),
		f.result.env.programID, f.step, attemptID); permit != nil || !errors.Is(err, ErrExactDispatchDenied) {
		t.Fatalf("unreviewed exact P admitted permit=%v err=%v", permit, err)
	}
}

func TestWorkflowSaveCannotOverwriteExactApproval(t *testing.T) {
	f := newExactDispatchFixture(t, "exact-workflow-save-regression")
	approvalID, _ := seedPendingExactApprovalAtWorkflowStep(t, f)
	state, err := f.result.env.store.LoadWorkflowState(f.result.env.ctx, f.step.WorkflowRunID)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range state.Steps {
		if step.Run.ID == f.step.ID {
			step.Run.ApprovalState = "approved"
		}
	}
	if err := f.result.env.store.SaveWorkflowState(f.result.context(), state); err == nil || !strings.Contains(err.Error(), "workflow approval conflicts with exact approval") {
		t.Fatalf("workflow save collision=%v", err)
	}
	var decision string
	if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx, `SELECT decision FROM approvals WHERE id=$1`, approvalID).Scan(&decision); err != nil || decision != "pending" {
		t.Fatalf("exact P mutated decision=%q err=%v", decision, err)
	}
}

func TestWorkflowStepApprovalStillWorks(t *testing.T) {
	f := newDirectExactDispatchFixture(t, "exact-legacy-approval-compatibility")
	state, err := f.result.env.store.LoadWorkflowState(f.result.env.ctx, f.step.WorkflowRunID)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range state.Steps {
		if step.Run.ID == f.step.ID {
			step.Run.ApprovalState = "pending"
		}
	}
	if err := f.result.env.store.SaveWorkflowState(f.result.env.ctx, state); err != nil {
		t.Fatal(err)
	}
	var approvalID domain.ID
	if err := f.result.env.store.Pool.QueryRow(f.result.env.ctx,
		`SELECT id FROM approvals WHERE request_id=$1 AND approval_kind='workflow_step'`, f.step.ID).Scan(&approvalID); err != nil {
		t.Fatal(err)
	}
	if err := f.result.env.store.DecideExactApproval(f.result.env.ctx, approvalID, "", "", "approved", "exact-operator"); err == nil {
		t.Fatal("exact decision mutated legacy workflow approval")
	}
	if err := f.result.env.store.DecideApproval(f.result.env.ctx, approvalID, "approved", "workflow-reviewer"); err != nil {
		t.Fatal(err)
	}
	approved, err := f.result.env.store.StepApproved(f.result.env.ctx, f.step.ID)
	if err != nil || !approved {
		t.Fatalf("workflow-step approval=%v err=%v", approved, err)
	}
}
