package exactsandbox

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
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
	"github.com/tobiasGuta/Reconductor/internal/exactexecution"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/scope"
)

// Disposable PostgreSQL fixtures produce real broker handoffs. No permit
// factory, unsafe reflection, production runner, or target invocation is used.
type sandboxFixture struct {
	store                                                    *database.Store
	ctx                                                      context.Context
	program, task, run, approval, attempt, action, execution domain.ID
	step                                                     domain.StepRun
	fence                                                    database.ScheduledExecutionFence
	authority                                                database.ProgramLaunchAuthority
	includes                                                 []scope.Rule
	policy                                                   policy.Policy
}

func newSandboxFixture(t *testing.T, scheduled, approve bool) sandboxFixture {
	return newSandboxTargetFixture(t, scheduled, approve, "/allowed/%2f?id=2&id=1?")
}
func newSandboxTargetFixture(t *testing.T, scheduled, approve bool, target string) sandboxFixture {
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
	f := sandboxFixture{store: store, ctx: ctx, program: domain.NewID(), task: domain.NewID(), run: domain.NewID(), attempt: domain.NewID(), action: domain.NewID()}
	f.step = domain.StepRun{ID: domain.NewID(), WorkflowRunID: f.run, Capability: "http.request", IdempotencyKey: "fixture"}
	f.includes = []scope.Rule{{Protocol: "https", Host: "example\\.test", Port: "443", File: "/.*", Enabled: true}}
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
	f.approval, err = store.PrepareExactActionApproval(f.ctx, f.program, f.step, f.attempt, exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: target}, review, "fixture-reviewer", time.Now().Add(5*time.Minute))
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
func (f sandboxFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := f.store.Pool.Exec(f.ctx, sql, args...); err != nil {
		t.Fatal(err)
	}
}

type captureExecutor struct{ execution exactexecution.Execution }

func (c *captureExecutor) Execute(_ context.Context, e exactexecution.Execution) (exactexecution.Result, error) {
	c.execution = e
	return exactexecution.Result{Completed: true}, nil
}

func executionFixture(t *testing.T, target string) (sandboxFixture, exactexecution.Execution) {
	t.Helper()
	f := newSandboxTargetFixture(t, false, true, target)
	e := &captureExecutor{}
	b, err := exactexecution.New(f.store, e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.ExecuteApprovedExact(f.ctx, f.program, f.step, f.attempt); err != nil {
		t.Fatal(err)
	}
	return f, e.execution
}

// Fake backend exists only in tests. Captured input is copied, while optional
// channels permit independent executions to remain concurrently in flight.
type fakeRunner struct {
	mu      sync.Mutex
	inputs  []EncodedExecution
	calls   atomic.Int64
	err     error
	output  func(context.Context, EncodedExecution) EncodedResult
	entered chan<- struct{}
	release <-chan struct{}
}

func (r *fakeRunner) Run(ctx context.Context, input EncodedExecution) (EncodedResult, error) {
	r.calls.Add(1)
	r.mu.Lock()
	r.inputs = append(r.inputs, input)
	r.mu.Unlock()
	if r.entered != nil {
		select {
		case r.entered <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if r.release != nil {
		select {
		case <-r.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	if r.output != nil {
		return r.output(ctx, input), nil
	}
	return EncodeResult(input.Digest(), true)
}

func TestFromExecutionLiteralTargets(t *testing.T) {
	for _, target := range []string{"/ordinary", "/item?id=1&id=2", "/item?b=2&a=1", "/item/%2F?x=%2f", "/item?"} {
		t.Run(target, func(t *testing.T) {
			_, e := executionFixture(t, target)
			encoded, err := FromExecution(e)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeExecution(encoded.Bytes(), encoded.Digest())
			if err != nil {
				t.Fatal(err)
			}
			if decoded.ProviderAttemptID() != e.ProviderAttemptID() || decoded.AuthorityEpoch() != e.AuthorityEpoch() || decoded.ActionSHA256() != e.ActionSHA256() || decoded.Action().Request.RequestTarget != target {
				t.Fatal("handoff identity or literal target changed")
			}
			for i := 0; i < 100; i++ {
				next, err := FromExecution(e)
				if err != nil {
					t.Fatal(err)
				}
				enc := next
				if string(enc.Bytes()) != string(encoded.Bytes()) || enc.Digest() != encoded.Digest() {
					t.Fatal("Execution conversion nondeterministic")
				}
			}
			var wire map[string]json.RawMessage
			if err = json.Unmarshal(encoded.Bytes(), &wire); err != nil {
				t.Fatal(err)
			}
			if len(wire) != 5 || wire["deadline"] != nil {
				t.Fatal("authority deadline or extra field serialized")
			}
		})
	}
}

func TestNewExecutorRejectsTypedNilBeforeBrokerHandoff(t *testing.T) {
	f := newSandboxFixture(t, true, true)
	var missing *fakeRunner
	adapter, err := NewExecutor(missing)
	if !errors.Is(err, ErrProtocol) || adapter != nil {
		t.Fatalf("typed-nil Runner produced a broker adapter: %v", err)
	}
	var intents int
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT count(*) FROM exact_dispatch_attempts WHERE provider_attempt_id=$1 AND state='DISPATCH_INTENT'`, f.attempt).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if intents != 0 {
		t.Fatal("constructor rejection consumed dispatch authority")
	}

	// The same approved fixture remains available for one valid handoff.
	runner := &fakeRunner{}
	adapter, err = NewExecutor(runner)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := exactexecution.New(f.store, adapter)
	if err != nil {
		t.Fatal(err)
	}
	result, err := broker.ExecuteApprovedExact(f.ctx, f.program, f.step, f.attempt)
	if err != nil || !result.Completed || runner.calls.Load() != 1 {
		t.Fatalf("valid handoff failed: result=%+v calls=%d err=%v", result, runner.calls.Load(), err)
	}
	if _, err := broker.ExecuteApprovedExact(f.ctx, f.program, f.step, f.attempt); err == nil || runner.calls.Load() != 1 {
		t.Fatal("valid handoff replayed")
	}
}

func TestSandboxExecutorBrokerHandoffAndNoReplay(t *testing.T) {
	for _, name := range []string{"success", "incomplete", "runner error", "wrong digest", "malformed", "unknown", "duplicate", "trailing", "oversized", "unsupported version", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			f := newSandboxFixture(t, true, true)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			r := &fakeRunner{}
			sentinel := errors.New("fake runner failed")
			if name == "runner error" {
				r.err = sentinel
			}
			r.output = func(got context.Context, in EncodedExecution) EncodedResult {
				if got != ctx {
					t.Fatal("context replaced")
				}
				c, err := DecodeExecution(in.Bytes(), in.Digest())
				if err != nil {
					t.Fatal(err)
				}
				if c.ProviderAttemptID() != f.attempt || c.AuthorityEpoch() != f.authority.Epoch {
					t.Fatal("execution binding lost")
				}
				var state string
				if err = f.store.Pool.QueryRow(f.ctx, `SELECT state FROM exact_dispatch_attempts WHERE provider_attempt_id=$1`, f.attempt).Scan(&state); err != nil || state != "DISPATCH_INTENT" {
					t.Fatal("runner before intent")
				}
				raw, _ := EncodeResult(in.Digest(), name != "incomplete")
				switch name {
				case "wrong digest":
					raw, _ = EncodeResult(strings.Repeat("f", 64), true)
				case "malformed":
					raw = []byte(`{`)
				case "unknown":
					raw = canonicalWire(t, map[string]any{"version": ResultVersion, "capsule_digest": in.Digest(), "completed": true, "retry": true})
				case "duplicate":
					raw = []byte(`{"capsule_digest":"` + in.Digest() + `","completed":false,"completed":true,"version":"` + ResultVersion + `"}`)
				case "trailing":
					raw = append(raw, []byte(`{}`)...)
				case "oversized":
					raw = []byte(strings.Repeat("x", MaxResultBytes+1))
				case "unsupported version":
					raw = canonicalWire(t, map[string]any{"version": "exact-sandbox-result/v2", "capsule_digest": in.Digest(), "completed": true})
				case "cancelled":
					cancel()
					if got.Err() != context.Canceled {
						t.Fatal("runner missed cancellation")
					}
				}
				return raw
			}
			s, err := NewExecutor(r)
			if err != nil {
				t.Fatal(err)
			}
			b, err := exactexecution.New(f.store, s)
			if err != nil {
				t.Fatal(err)
			}
			result, err := b.ExecuteApprovedExact(ctx, f.program, f.step, f.attempt)
			valid := name == "success" || name == "incomplete"
			if valid {
				if err != nil || result.Completed != (name == "success") {
					t.Fatalf("valid result=%+v err=%v", result, err)
				}
			} else if err == nil || result.Completed {
				t.Fatal("bad runner output accepted")
			}
			if name == "runner error" && !errors.Is(err, sentinel) {
				t.Fatal("runner error lost")
			}
			if name == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost")
			}
			if r.calls.Load() != 1 {
				t.Fatal("runner retried")
			}
			if _, err = b.ExecuteApprovedExact(f.ctx, f.program, f.step, f.attempt); err == nil || r.calls.Load() != 1 {
				t.Fatal("intent replay")
			}
		})
	}
}

func TestSandboxExecutorConcurrentBindings(t *testing.T) {
	_, one := executionFixture(t, "/one")
	_, two := executionFixture(t, "/two")
	c1, _ := FromExecution(one)
	c2, _ := FromExecution(two)
	s1 := c1.Digest()
	s2 := c2.Digest()
	if s1 == s2 || one.ProviderAttemptID() == two.ProviderAttemptID() || one.ActionSHA256() == two.ActionSHA256() {
		t.Fatal("fixtures not independent")
	}
	entered := make(chan struct{}, 24)
	release := make(chan struct{})
	r := &fakeRunner{entered: entered, release: release, output: func(_ context.Context, in EncodedExecution) EncodedResult {
		raw, _ := EncodeResult(in.Digest(), true)
		return raw
	}}
	s, _ := NewExecutor(r)
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for i := 0; i < 24; i++ {
		e := one
		if i%2 == 1 {
			e = two
		}
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Execute(context.Background(), e); errs <- err }()
	}
	for i := 0; i < 24; i++ {
		<-entered
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if r.calls.Load() != 24 {
		t.Fatal("wrong runner count")
	}
	// Concurrent deliberately crossed replies must both be denied.
	r.output = func(_ context.Context, in EncodedExecution) EncodedResult {
		other := s1
		if in.Digest() == s1 {
			other = s2
		}
		raw, _ := EncodeResult(other, true)
		return raw
	}
	for _, e := range []exactexecution.Execution{one, two} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Execute(context.Background(), e); !errors.Is(err, ErrProtocol) {
				t.Error("crossed result accepted")
			}
		}()
	}
	wg.Wait()
}

func TestSandboxExecutorBlockingCancellation(t *testing.T) {
	_, e := executionFixture(t, "/a")
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	r := &fakeRunner{entered: entered, release: release}
	s, _ := NewExecutor(r)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := s.Execute(ctx, e); done <- err }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || r.calls.Load() != 1 {
		t.Fatal("cancelled runner retried or context detached")
	}
}
