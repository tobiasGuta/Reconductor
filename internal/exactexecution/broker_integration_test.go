package exactexecution

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/scope"
)

// Adapt the existing exact-action/console fixtures to an isolated schema. All
// provider events below are fixture provenance, never provider invocation.
type brokerFixture struct {
	store                                                    *database.Store
	ctx                                                      context.Context
	program, task, run, approval, attempt, action, execution domain.ID
	step                                                     domain.StepRun
	fence                                                    database.ScheduledExecutionFence
	authority                                                database.ProgramLaunchAuthority
	includes                                                 []scope.Rule
	policy                                                   policy.Policy
}

func newBrokerFixture(t *testing.T, scheduled, approve bool) brokerFixture {
	t.Helper()
	uri := os.Getenv("TEST_DATABASE_URL")
	if uri == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "broker_exact_" + strings.ReplaceAll(string(domain.NewID()), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	q.Set("search_path", schema)
	parsed.RawQuery = q.Encode()
	store, err := database.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if err = store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	f := brokerFixture{store: store, ctx: ctx, program: domain.NewID(), task: domain.NewID(), run: domain.NewID(), attempt: domain.NewID(), action: domain.NewID()}
	f.step = domain.StepRun{ID: domain.NewID(), WorkflowRunID: f.run, Capability: "http.request", IdempotencyKey: "fixture"}
	f.includes = []scope.Rule{{Protocol: "https", Host: "example\\.test", Port: "443", File: "/allowed/.*", Enabled: true}}
	f.policy = policy.Policy{ID: "fixture", AllowedCapabilities: []string{"http.request"}, AllowedHTTPMethods: []string{"GET", "HEAD"}}
	compiled, err := scope.Compile(f.includes, nil)
	if err != nil {
		t.Fatal(err)
	}
	definition, scopeID, auth := domain.NewID(), domain.NewID(), domain.NewID()
	f.exec(t, `INSERT INTO programs(id,name,platform,scope_reference,policy_reference,scope_digest) VALUES($1,$2,'test','synthetic','test',$3)`, f.program, "broker-"+string(f.program), compiled.Digest())
	f.exec(t, `INSERT INTO program_launch_authority(program_id) VALUES($1)`, f.program)
	f.exec(t, `INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,target_plan_digest,target_plan,acknowledged_at,acknowledged_by) VALUES($1,$2,'synthetic',$3,'plan','{}',clock_timestamp(),'fixture')`, scopeID, f.program, compiled.Digest())
	f.exec(t, `INSERT INTO workflow_definitions(id,name,version,definition) VALUES($1,'broker-fixture','1','{}')`, definition)
	f.exec(t, `INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES($1,$2,'test',$3,'running','test')`, f.task, f.program, definition)
	f.exec(t, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source,materialized_definition,materialization_digest,original_scope_version_id) VALUES($1,$2,$3,'1','running','test','{}',$4,$5)`, f.run, f.task, definition, strings.Repeat("a", 64), scopeID)
	f.exec(t, `INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,attempt_count,idempotency_key) VALUES($1,$2,'request','http.request','running',1,'fixture')`, f.step.ID, f.run)
	var scheduledID *domain.ID
	var schedulerAttempt *int
	if scheduled {
		schedule := domain.NewID()
		f.execution = domain.NewID()
		f.fence = database.ScheduledExecutionFence{ExecutionID: f.execution, LeaseOwner: "fixture-owner", Attempt: 1}
		scheduledID = &f.execution
		schedulerAttempt = &f.fence.Attempt
		f.exec(t, `INSERT INTO schedules(id,program_id,name,workflow_name,objective,cron_expression,timezone,created_by,next_run_at) VALUES($1,$2,'fixture','fixture','test','0 * * * *','UTC','fixture',clock_timestamp())`, schedule, f.program)
		f.exec(t, `INSERT INTO scheduled_executions(id,schedule_id,planned_at,trigger_source,status,task_id,workflow_run_id,scope_version_id,attempt_count,lease_owner,lease_expires_at,recovery_protocol_version) VALUES($1,$2,clock_timestamp(),'scheduled','running',$3,$4,$5,1,'fixture-owner',clock_timestamp()+interval '5 minutes',1)`, f.execution, schedule, f.task, f.run, scopeID)
		f.ctx = database.WithScheduledExecutionFence(ctx, f.fence)
	}
	f.exec(t, `INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,step_run_id,capability,action_request_id,step_attempt,scheduled_execution_id,scheduler_attempt,safe_message,details) VALUES($1,'policy_allowed','test','test',$2,$3,$4,$5,'http.request',$6,1,$7,$8,'fixture','{"phase":"execution"}')`, auth, f.program, f.task, f.run, f.step.ID, f.action, scheduledID, schedulerAttempt)
	f.exec(t, `INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,step_run_id,capability,action_request_id,step_attempt,scheduled_execution_id,scheduler_attempt,execution_authorization_event_id,safe_message) VALUES($1,'provider_invocation_started','test','test',$2,$3,$4,$5,'http.request',$6,1,$7,$8,$9,'fixture')`, f.attempt, f.program, f.task, f.run, f.step.ID, f.action, scheduledID, schedulerAttempt, auth)
	f.authority, err = store.PublishLaunchAuthority(ctx, f.program, 0, "fixture", f.includes, nil, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	review := exactaction.ReviewContextV1{ReviewVersion: exactaction.ReviewVersion, ProposalSource: exactaction.ProposalSource{Kind: "fixture"}, Purpose: "synthetic broker handoff", ExpectedPositiveOutcome: "one fake invocation", ExpectedNegativeOutcome: "denied", Assumptions: []string{}, MissingEvidence: []string{}, SupportingEvidence: []exactaction.Citation{}, ContradictoryEvidence: []exactaction.Citation{}}
	f.approval, err = store.PrepareExactActionApproval(f.ctx, f.program, f.step, f.attempt, exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/allowed/%2f?id=2&id=1?"}, review, "fixture-reviewer", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if approve {
		view, err := store.GetExactApprovalReview(ctx, f.approval)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.DecideExactApproval(ctx, f.approval, view.ActionSHA256, view.ReviewContextSHA256, "approved", "fixture-reviewer"); err != nil {
			t.Fatal(err)
		}
	}
	return f
}
func (f brokerFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := f.store.Pool.Exec(f.ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
}
func (f brokerFixture) assertState(t *testing.T, want string, audits int) {
	t.Helper()
	var state string
	var count int
	err := f.store.Pool.QueryRow(f.ctx, `SELECT state,(SELECT count(*) FROM audit_events WHERE event_type='exact_dispatch_intent' AND provider_attempt_id=$1) FROM exact_dispatch_attempts WHERE provider_attempt_id=$1`, f.attempt).Scan(&state, &count)
	if err != nil || state != want || count != audits {
		t.Fatalf("state=%s intents=%d err=%v", state, count, err)
	}
}
func (f brokerFixture) broker(t *testing.T, e Executor) *Broker {
	t.Helper()
	b, err := New(f.store, e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func (f brokerFixture) preserved(t *testing.T) string {
	t.Helper()
	var snapshot string
	err := f.store.Pool.QueryRow(f.ctx, `SELECT row_to_json(a)::text || row_to_json(e)::text || (SELECT md5(COALESCE(string_agg(row_to_json(v)::text,'|' ORDER BY v.id),'')) FROM artifacts v) FROM approvals a JOIN exact_actions e ON e.action_request_id=a.action_request_id WHERE a.id=$1`, f.approval).Scan(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
func TestBrokerIntegrationApprovedFrozenAndLoader(t *testing.T) {
	for _, scheduled := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "scheduled"}[scheduled], func(t *testing.T) {
			f := newBrokerFixture(t, scheduled, true)
			view, err := f.store.GetExactApprovalReview(f.ctx, f.approval)
			if err != nil {
				t.Fatal(err)
			}
			before := f.preserved(t)
			if _, err = f.store.LoadExactDispatchAction(f.ctx, f.attempt, view.ActionSHA256, f.authority.Epoch); err == nil {
				t.Fatal("material loaded before intent")
			}
			f.exec(t, `UPDATE step_runs SET input='{"request_target":"/mutable","authorization":"ignored"}' WHERE id=$1`, f.step.ID)
			step := f.step
			step.Input = json.RawMessage(`{"request_target":"/caller"}`)
			e := &countingExecutor{result: Result{Completed: true}}
			var admitted atomic.Pointer[database.ExactDispatchPermit]
			observed := &faultStore{Store: f.store, afterAdmit: func(p *database.ExactDispatchPermit) { admitted.Store(p) }}
			b, err := New(observed, e)
			if err != nil {
				t.Fatal(err)
			}
			e.onExecute = func(ctx context.Context, x Execution) {
				assertConsumedPermit(t, f, admitted.Load())
				if ctx != f.ctx || x.ProviderAttemptID() != f.attempt || x.ActionSHA256() != view.ActionSHA256 || x.AuthorityEpoch() != f.authority.Epoch || !reflect.DeepEqual(x.Action(), view.Action) {
					t.Fatal("executor did not receive frozen admitted material")
				}
				if scheduled {
					var lease time.Time
					if err := f.store.Pool.QueryRow(ctx, `SELECT lease_expires_at FROM scheduled_executions WHERE id=$1`, f.execution).Scan(&lease); err != nil {
						t.Fatal(err)
					}
					if x.Deadline() == nil || x.Deadline().After(lease) {
						t.Fatal("scheduled deadline not preserved")
					}
				}
			}
			if result, err := b.ExecuteApprovedExact(f.ctx, f.program, step, f.attempt); err != nil || !result.Completed || e.calls.Load() != 1 {
				t.Fatalf("result=%v err=%v", result, err)
			}
			f.assertState(t, "DISPATCH_INTENT", 1)
			for i := 0; i < 3; i++ {
				a, err := f.store.LoadExactDispatchAction(f.ctx, f.attempt, view.ActionSHA256, f.authority.Epoch)
				if err != nil || !reflect.DeepEqual(a, view.Action) {
					t.Fatalf("loader=%+v %v", a, err)
				}
			}
			for _, pair := range []struct {
				id domain.ID
				h  string
			}{{f.attempt, strings.Repeat("f", 64)}, {domain.NewID(), view.ActionSHA256}} {
				if _, err := f.store.LoadExactDispatchAction(f.ctx, pair.id, pair.h, f.authority.Epoch); err == nil {
					t.Fatal("loader cross-binding accepted")
				}
			}
			if _, err := b.ExecuteApprovedExact(f.ctx, f.program, step, f.attempt); err == nil || e.calls.Load() != 1 {
				t.Fatal("sequential execution replay")
			}
			if f.preserved(t) != before {
				t.Fatal("execution/read changed P/A/R/evidence")
			}
			f.assertState(t, "DISPATCH_INTENT", 1)
		})
	}
}
func TestBrokerIntegrationAdmissionVetoes(t *testing.T) {
	for _, name := range []string{"pending", "revoked", "expired", "blocked", "tightened scope", "denied method", "scope candidate", "missing action", "corrupt action", "wrong X", "missing scheduled claim", "expired scheduled lease", "wrong scheduled attempt"} {
		t.Run(name, func(t *testing.T) {
			scheduled := strings.Contains(name, "scheduled")
			f := newBrokerFixture(t, scheduled, name != "pending")
			ctx := f.ctx
			switch name {
			case "revoked":
				f.exec(t, `UPDATE approvals SET revoked_at=clock_timestamp(),revoked_by='fixture' WHERE id=$1`, f.approval)
			case "expired":
				f.exec(t, `UPDATE approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.approval)
			case "blocked":
				if _, err := f.store.BeginLaunchAuthorityUpdate(f.ctx, f.program, f.authority.Epoch, "fixture", "blocked"); err != nil {
					t.Fatal(err)
				}
			case "tightened scope":
				exclude := []scope.Rule{{Protocol: "https", Host: "example\\.test", Port: "443", File: "/allowed/.*", Enabled: true}}
				compiled, err := scope.Compile(f.includes, exclude)
				if err != nil {
					t.Fatal(err)
				}
				f.exec(t, `UPDATE programs SET scope_digest=$2 WHERE id=$1`, f.program, compiled.Digest())
				current, err := f.store.LaunchAuthority(f.ctx, f.program)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.PublishLaunchAuthority(f.ctx, f.program, current.Epoch, "fixture", f.includes, exclude, f.policy); err != nil {
					t.Fatal(err)
				}
			case "denied method":
				pol := f.policy
				pol.AllowedHTTPMethods = []string{"HEAD"}
				if _, err := f.store.PublishLaunchAuthority(f.ctx, f.program, f.authority.Epoch, "fixture", f.includes, nil, pol); err != nil {
					t.Fatal(err)
				}
			case "scope candidate":
				snapshot := domain.ScopeSnapshot{ProgramID: f.program, ScopeReference: "synthetic://candidate", ScopeDigest: "candidate", IncludeRuleDigests: []string{"extra"}, ExcludeRuleDigests: []string{}, TargetPlanDigest: "candidate-plan", PlanningWarnings: json.RawMessage(`[]`), TargetPlan: json.RawMessage(`{}`)}
				change, err := f.store.CheckAndRecordScopeSnapshot(f.ctx, snapshot, false, "fixture")
				if err != nil || !change.Changed || change.Acknowledged {
					t.Fatalf("candidate=%+v %v", change, err)
				}
				f.exec(t, `UPDATE program_launch_authority SET status='READY',authority_epoch=authority_epoch+1 WHERE program_id=$1`, f.program)
			case "missing action", "corrupt action":
				f.corruptAction(t, name == "missing action")
			case "wrong X":
				f.attempt = domain.NewID()
			case "missing scheduled claim":
				ctx = context.Background()
			case "expired scheduled lease":
				f.exec(t, `UPDATE scheduled_executions SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.execution)
			case "wrong scheduled attempt":
				fence := f.fence
				fence.Attempt++
				ctx = database.WithScheduledExecutionFence(context.Background(), fence)
			}
			e := &countingExecutor{}
			if _, err := f.broker(t, e).ExecuteApprovedExact(ctx, f.program, f.step, f.attempt); err == nil || e.calls.Load() != 0 {
				t.Fatalf("veto failed: %v calls=%d", err, e.calls.Load())
			}
			if name != "wrong X" {
				f.assertState(t, "UNDISPATCHED", 0)
			}
		})
	}
}

// Corruption is injected only inside this test's disposable schema. Migration
// definitions/production immutability remain untouched; the trigger is restored
// in the same transaction. This models corrupt historical persistence.
func (f brokerFixture) corruptAction(t *testing.T, missing bool) {
	t.Helper()
	tx, err := f.store.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err = tx.Exec(f.ctx, `ALTER TABLE exact_actions DISABLE TRIGGER exact_actions_immutable`); err != nil {
		t.Fatal(err)
	}
	query := `UPDATE exact_actions SET canonical_contract='{}'::bytea WHERE action_request_id=$1`
	if missing {
		query = `DELETE FROM exact_actions WHERE action_request_id=$1`
	}
	if _, err = tx.Exec(f.ctx, query, f.action); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, `ALTER TABLE exact_actions ENABLE TRIGGER exact_actions_immutable`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
}

type faultStore struct {
	*database.Store
	afterAdmit       func(*database.ExactDispatchPermit)
	loadErr, timeErr error
	admissionErr     error
	admissions       atomic.Int64
	clocks           atomic.Int64
	clockResult      func(context.Context, int64) (time.Time, error)
}

func (s *faultStore) AdmitExactDispatch(ctx context.Context, p domain.ID, step domain.StepRun, id domain.ID) (*database.ExactDispatchPermit, error) {
	s.admissions.Add(1)
	permit, err := s.Store.AdmitExactDispatch(ctx, p, step, id)
	if err == nil && s.afterAdmit != nil {
		s.afterAdmit(permit)
	}
	if err == nil && s.admissionErr != nil {
		// Simulate a lost commit response: durable intent exists, but the
		// caller receives only an error and never obtains the permit.
		return nil, s.admissionErr
	}
	return permit, err
}
func (s *faultStore) LoadExactDispatchAction(ctx context.Context, id domain.ID, h string, epoch int64) (exactaction.ActionContractV1, error) {
	if s.loadErr != nil {
		return exactaction.ActionContractV1{}, s.loadErr
	}
	return s.Store.LoadExactDispatchAction(ctx, id, h, epoch)
}
func (s *faultStore) ExactDispatchTrustedTime(ctx context.Context) (time.Time, error) {
	n := s.clocks.Add(1)
	if s.clockResult != nil {
		return s.clockResult(ctx, n)
	}
	if s.timeErr != nil {
		return time.Time{}, s.timeErr
	}
	return s.Store.ExactDispatchTrustedTime(ctx)
}
func TestBrokerIntegrationIntentFailuresNeverReplay(t *testing.T) {
	for _, name := range []string{"disappeared before consume", "admission commit ambiguity", "load error", "clock error", "corrupt after intent", "cancel after intent", "executor error", "executor panic"} {
		t.Run(name, func(t *testing.T) {
			f := newBrokerFixture(t, false, true)
			e := &countingExecutor{}
			sentinel := errors.New("injected broker failure")
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			store := &faultStore{Store: f.store}
			b, err := New(store, e)
			if err != nil {
				t.Fatal(err)
			}
			want := int64(0)
			switch name {
			case "admission commit ambiguity":
				store.admissionErr = sentinel
			case "disappeared before consume":
				if p, err := f.store.AdmitExactDispatch(f.ctx, f.program, f.step, f.attempt); err != nil || p == nil {
					t.Fatal(err)
				}
			case "load error":
				store.loadErr = sentinel
			case "clock error":
				store.timeErr = sentinel
			case "corrupt after intent":
				store.afterAdmit = func(*database.ExactDispatchPermit) { f.corruptAction(t, false) }
			case "cancel after intent":
				store.afterAdmit = func(*database.ExactDispatchPermit) { cancel() }
			case "executor error":
				e.err = sentinel
				want = 1
			case "executor panic":
				e.onExecute = func(context.Context, Execution) { panic(sentinel) }
				want = 1
			}
			if name == "executor panic" {
				func() {
					defer func() {
						if recover() != sentinel {
							t.Fatal("expected fake panic")
						}
					}()
					_, _ = b.ExecuteApprovedExact(ctx, f.program, f.step, f.attempt)
				}()
			} else {
				if _, err = b.ExecuteApprovedExact(ctx, f.program, f.step, f.attempt); err == nil {
					t.Fatal("injected failure accepted")
				}
			}
			if e.calls.Load() != want {
				t.Fatalf("calls=%d want=%d", e.calls.Load(), want)
			}
			f.assertState(t, "DISPATCH_INTENT", 1)
			fresh := f.broker(t, e)
			if _, err = fresh.ExecuteApprovedExact(f.ctx, f.program, f.step, f.attempt); err == nil || e.calls.Load() != want {
				t.Fatal("ambiguous intent replayed")
			}
			f.assertState(t, "DISPATCH_INTENT", 1)
		})
	}
}
func TestBrokerIntegration24Contenders(t *testing.T) {
	f := newBrokerFixture(t, false, true)
	e := &countingExecutor{result: Result{Completed: true}}
	var admitted atomic.Pointer[database.ExactDispatchPermit]
	observed := &faultStore{Store: f.store, afterAdmit: func(p *database.ExactDispatchPermit) { admitted.Store(p) }}
	b, err := New(observed, e)
	if err != nil {
		t.Fatal(err)
	}
	e.onExecute = func(context.Context, Execution) { assertConsumedPermit(t, f, admitted.Load()) }
	start := make(chan struct{})
	var wg sync.WaitGroup
	var winners atomic.Int64
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := b.ExecuteApprovedExact(f.ctx, f.program, f.step, f.attempt); err == nil {
				winners.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 || e.calls.Load() != 1 || observed.admissions.Load() != 24 {
		t.Fatalf("winners=%d executor=%d admissions=%d", winners.Load(), e.calls.Load(), observed.admissions.Load())
	}
	f.assertState(t, "DISPATCH_INTENT", 1)
}

func assertConsumedPermit(t *testing.T, f brokerFixture, permit *database.ExactDispatchPermit) {
	t.Helper()
	now, err := f.store.ExactDispatchTrustedTime(f.ctx)
	if err != nil || permit == nil || permit.Deadline() == nil || !now.Before(*permit.Deadline()) {
		t.Fatalf("could not observe a live consumed permit: %v", err)
	}
	if permit.ConsumeAt(now) {
		t.Fatal("executor was invoked before successful permit consumption")
	}
}

// This test-only adapter pauses at entry to ConsumeAt, after the broker fixed
// its argument. It delegates to the real, unchanged database permit afterward.
type pausedRealPermit struct {
	*database.ExactDispatchPermit
	beforeConsume func(time.Time)
	consumed      bool
}

func (p *pausedRealPermit) ConsumeAt(at time.Time) bool {
	p.beforeConsume(at)
	p.consumed = p.ExactDispatchPermit.ConsumeAt(at)
	return p.consumed
}

type pausedConsumptionBackend struct {
	storeBackend
	beforeConsume func(time.Time)
	permit        *pausedRealPermit
	clocks        int
}

func (s *pausedConsumptionBackend) admit(ctx context.Context, program domain.ID, step domain.StepRun, id domain.ID) (dispatchPermit, error) {
	p, err := s.Store.AdmitExactDispatch(ctx, program, step, id)
	if err != nil || p == nil {
		return nil, err
	}
	s.permit = &pausedRealPermit{ExactDispatchPermit: p, beforeConsume: s.beforeConsume}
	return s.permit, nil
}
func (s *pausedConsumptionBackend) trustedTime(ctx context.Context) (time.Time, error) {
	s.clocks++
	return s.Store.ExactDispatchTrustedTime(ctx)
}

func waitForBrokerDBDeadline(t *testing.T, ctx context.Context, store *database.Store, deadline time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		now, err := store.ExactDispatchTrustedTime(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !now.Before(deadline) {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func TestBrokerIntegrationStalePreConsumeSampleCannotExecute(t *testing.T) {
	f := newBrokerFixture(t, false, true)
	var deadline, preConsume time.Time
	if err := f.store.Pool.QueryRow(f.ctx, `UPDATE approvals SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1 RETURNING expires_at`, f.approval).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	s := &pausedConsumptionBackend{storeBackend: storeBackend{f.store}}
	s.beforeConsume = func(at time.Time) {
		preConsume = at
		if !at.Before(deadline) {
			t.Fatal("test did not capture a live pre-consume timestamp")
		}
		waitForBrokerDBDeadline(t, f.ctx, f.store, deadline)
	}
	e := &countingExecutor{}
	b := &Broker{backend: s, executor: e}
	if _, err := b.ExecuteApprovedExact(f.ctx, f.program, f.step, f.attempt); !errors.Is(err, ErrExecutionDenied) {
		t.Fatalf("stale pre-consume handoff err=%v", err)
	}
	if s.permit == nil || !s.permit.consumed || s.clocks != 2 || e.calls.Load() != 0 {
		t.Fatalf("clocks=%d calls=%d permit=%+v", s.clocks, e.calls.Load(), s.permit)
	}
	// The stale timestamp itself is still before D: rejection comes from the
	// fresh post-consumption guard, and the real permit remains spent.
	if s.permit.ExactDispatchPermit.ConsumeAt(preConsume) {
		t.Fatal("post-consume denial restored the real permit")
	}
	f.assertState(t, "DISPATCH_INTENT", 1)
	if _, err := f.broker(t, e).ExecuteApprovedExact(f.ctx, f.program, f.step, f.attempt); err == nil || e.calls.Load() != 0 {
		t.Fatal("stale-clock intent replayed")
	}
}

func TestBrokerIntegrationPostConsumeClockFailures(t *testing.T) {
	for _, name := range []string{"error", "zero", "cancellation", "delayed response"} {
		t.Run(name, func(t *testing.T) {
			f := newBrokerFixture(t, false, true)
			var deadline, preSample time.Time
			if name == "delayed response" {
				if err := f.store.Pool.QueryRow(f.ctx, `UPDATE approvals SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1 RETURNING expires_at`, f.approval).Scan(&deadline); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			var permit *database.ExactDispatchPermit
			sentinel := errors.New("post-consume database clock failure")
			s := &faultStore{Store: f.store, afterAdmit: func(p *database.ExactDispatchPermit) { permit = p }}
			s.clockResult = func(ctx context.Context, n int64) (time.Time, error) {
				if n == 1 {
					var err error
					preSample, err = f.store.ExactDispatchTrustedTime(ctx)
					return preSample, err
				}
				if n != 2 || permit.ConsumeAt(preSample) {
					t.Fatal("post-consume query without an already-spent real permit")
				}
				switch name {
				case "error":
					return time.Time{}, sentinel
				case "zero":
					return time.Time{}, nil
				case "cancellation":
					cancel()
					return f.store.ExactDispatchTrustedTime(ctx)
				case "delayed response":
					sampled, err := f.store.ExactDispatchTrustedTime(ctx)
					if err != nil || !sampled.Before(deadline) {
						t.Fatalf("second query did not sample before D: %v", err)
					}
					waitForBrokerDBDeadline(t, f.ctx, f.store, deadline)
					return sampled, nil
				default:
					panic("unknown clock fault")
				}
			}
			e := &countingExecutor{}
			b, err := New(s, e)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = b.ExecuteApprovedExact(ctx, f.program, f.step, f.attempt); err == nil || e.calls.Load() != 0 || s.clocks.Load() != 2 {
				t.Fatalf("post-consume fault err=%v calls=%d clocks=%d", err, e.calls.Load(), s.clocks.Load())
			}
			if name == "error" && !errors.Is(err, sentinel) {
				t.Fatal("clock failure was not propagated")
			}
			if name == "cancellation" && !errors.Is(err, context.Canceled) {
				t.Fatal("clock cancellation was not propagated")
			}
			if permit.ConsumeAt(preSample) {
				t.Fatal("failed second guard restored consumed permit")
			}
			f.assertState(t, "DISPATCH_INTENT", 1)
			if _, err := f.broker(t, e).ExecuteApprovedExact(f.ctx, f.program, f.step, f.attempt); err == nil || e.calls.Load() != 0 {
				t.Fatal("failed post-consume clock replayed")
			}
			f.assertState(t, "DISPATCH_INTENT", 1)
		})
	}
}

func (f brokerFixture) corruptIntentEpoch(t *testing.T, epoch int64) {
	t.Helper()
	tx, err := f.store.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err = tx.Exec(f.ctx, `ALTER TABLE exact_dispatch_attempts DISABLE TRIGGER exact_dispatch_intent_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, `UPDATE exact_dispatch_attempts SET authority_epoch=$2 WHERE provider_attempt_id=$1`, f.attempt, epoch); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, `ALTER TABLE exact_dispatch_attempts ENABLE TRIGGER exact_dispatch_intent_immutable`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBrokerIntegrationPersistedEpochMismatchDenied(t *testing.T) {
	for _, name := range []string{"different epoch", "negative epoch"} {
		t.Run(name, func(t *testing.T) {
			f := newBrokerFixture(t, false, true)
			s := &faultStore{Store: f.store, afterAdmit: func(p *database.ExactDispatchPermit) {
				epoch := p.AuthorityEpoch() + 1
				if name == "negative epoch" {
					epoch = -1
				}
				f.corruptIntentEpoch(t, epoch)
			}}
			e := &countingExecutor{}
			b, err := New(s, e)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = b.ExecuteApprovedExact(f.ctx, f.program, f.step, f.attempt); !errors.Is(err, database.ErrExactDispatchDenied) || e.calls.Load() != 0 || s.clocks.Load() != 0 {
				t.Fatalf("corrupt epoch err=%v calls=%d clocks=%d", err, e.calls.Load(), s.clocks.Load())
			}
			f.assertState(t, "DISPATCH_INTENT", 1)
			if _, err := f.broker(t, e).ExecuteApprovedExact(f.ctx, f.program, f.step, f.attempt); err == nil || e.calls.Load() != 0 {
				t.Fatal("corrupt historical epoch replayed")
			}
		})
	}
}

func TestBrokerIntegrationPostIntentAuthorityPreserved(t *testing.T) {
	for _, name := range []string{"revoked", "blocked epoch", "scope excluded", "policy denied", "scheduled cancelled"} {
		t.Run(name, func(t *testing.T) {
			f := newBrokerFixture(t, name == "scheduled cancelled", true)
			var permit *database.ExactDispatchPermit
			s := &faultStore{Store: f.store, afterAdmit: func(p *database.ExactDispatchPermit) {
				permit = p
				switch name {
				case "revoked":
					f.exec(t, `UPDATE approvals SET revoked_at=clock_timestamp(),revoked_by='fixture' WHERE id=$1`, f.approval)
				case "blocked epoch":
					current, err := f.store.BeginLaunchAuthorityUpdate(f.ctx, f.program, p.AuthorityEpoch(), "fixture", "after intent")
					if err != nil || current != p.AuthorityEpoch()+1 {
						t.Fatalf("current epoch=%d err=%v", current, err)
					}
				case "scope excluded":
					exclude := []scope.Rule{{Protocol: "https", Host: "example\\.test", Port: "443", File: "/allowed/.*", Enabled: true}}
					compiled, err := scope.Compile(f.includes, exclude)
					if err != nil {
						t.Fatal(err)
					}
					f.exec(t, `UPDATE programs SET scope_digest=$2 WHERE id=$1`, f.program, compiled.Digest())
					current, err := f.store.LaunchAuthority(f.ctx, f.program)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = f.store.PublishLaunchAuthority(f.ctx, f.program, current.Epoch, "fixture", f.includes, exclude, f.policy); err != nil {
						t.Fatal(err)
					}
				case "policy denied":
					pol := f.policy
					pol.AllowedHTTPMethods = []string{"HEAD"}
					if _, err := f.store.PublishLaunchAuthority(f.ctx, f.program, p.AuthorityEpoch(), "fixture", f.includes, nil, pol); err != nil {
						t.Fatal(err)
					}
				case "scheduled cancelled":
					f.exec(t, `UPDATE scheduled_executions SET status='cancelled',lease_owner='',lease_expires_at=NULL WHERE id=$1`, f.execution)
				}
			}}
			e := &countingExecutor{onExecute: func(_ context.Context, x Execution) {
				assertConsumedPermit(t, f, permit)
				var storedEpoch int64
				if err := f.store.Pool.QueryRow(f.ctx, `SELECT authority_epoch FROM exact_dispatch_attempts WHERE provider_attempt_id=$1`, f.attempt).Scan(&storedEpoch); err != nil {
					t.Fatal(err)
				}
				if storedEpoch != x.AuthorityEpoch() || storedEpoch != permit.AuthorityEpoch() {
					t.Fatal("historical epoch lost after current authority changed")
				}
			}}
			b, err := New(s, e)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = b.ExecuteApprovedExact(f.ctx, f.program, f.step, f.attempt); err != nil || e.calls.Load() != 1 || s.clocks.Load() != 2 {
				t.Fatalf("post-intent authority re-evaluated: err=%v calls=%d clocks=%d", err, e.calls.Load(), s.clocks.Load())
			}
			f.assertState(t, "DISPATCH_INTENT", 1)
			if _, err := f.broker(t, e).ExecuteApprovedExact(f.ctx, f.program, f.step, f.attempt); err == nil || e.calls.Load() != 1 {
				t.Fatal("historical permit replayed")
			}
		})
	}
}
