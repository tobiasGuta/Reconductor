package exactexecution

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
)

type fakePermit struct {
	id        domain.ID
	hash      string
	epoch     int64
	deadline  time.Time
	used      atomic.Bool
	consumes  atomic.Int64
	onConsume func()
}

func (p *fakePermit) ProviderAttemptID() domain.ID { return p.id }
func (p *fakePermit) ActionSHA256() string         { return p.hash }
func (p *fakePermit) AuthorityEpoch() int64        { return p.epoch }
func (p *fakePermit) Deadline() *time.Time         { v := p.deadline; return &v }
func (p *fakePermit) ConsumeAt(at time.Time) bool {
	if at.IsZero() || !at.Before(p.deadline) || !p.used.CompareAndSwap(false, true) {
		return false
	}
	p.consumes.Add(1)
	if p.onConsume != nil {
		p.onConsume()
	}
	return true
}

type fakeBackend struct {
	permit                     dispatchPermit
	action                     exactaction.ActionContractV1
	now                        time.Time
	epoch                      int64
	admitErr, loadErr, timeErr error
	admissions, loads, clocks  atomic.Int64
	oneAdmission               bool
	onAdmit, onLoad, onClock   func(context.Context)
}

func (f *fakeBackend) admit(ctx context.Context, _ domain.ID, _ domain.StepRun, _ domain.ID) (dispatchPermit, error) {
	n := f.admissions.Add(1)
	if f.onAdmit != nil {
		f.onAdmit(ctx)
	}
	if f.admitErr != nil {
		return nil, f.admitErr
	}
	if f.oneAdmission && n != 1 {
		return nil, ErrExecutionDenied
	}
	return f.permit, nil
}
func (f *fakeBackend) load(ctx context.Context, id domain.ID, h string, epoch int64) (exactaction.ActionContractV1, error) {
	f.loads.Add(1)
	if f.onLoad != nil {
		f.onLoad(ctx)
	}
	if id != f.permit.ProviderAttemptID() || h != f.permit.ActionSHA256() || epoch != f.epoch {
		return exactaction.ActionContractV1{}, ErrExecutionDenied
	}
	return f.action, f.loadErr
}
func (f *fakeBackend) trustedTime(ctx context.Context) (time.Time, error) {
	f.clocks.Add(1)
	if f.onClock != nil {
		f.onClock(ctx)
	}
	return f.now, f.timeErr
}

type countingExecutor struct {
	calls     atomic.Int64
	mu        sync.Mutex
	received  []Execution
	result    Result
	err       error
	onExecute func(context.Context, Execution)
}

func (f *countingExecutor) Execute(ctx context.Context, e Execution) (Result, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.received = append(f.received, e)
	f.mu.Unlock()
	if f.onExecute != nil {
		f.onExecute(ctx, e)
	}
	return f.result, f.err
}
func unitFixture(t *testing.T) (*Broker, *fakeBackend, *fakePermit, *countingExecutor, domain.StepRun) {
	t.Helper()
	a := exactaction.ActionContractV1{ContractVersion: exactaction.ContractVersion, ActionID: "action", Ownership: exactaction.Ownership{ProgramID: "program", TaskID: "task", WorkflowRunID: "run", StepRunID: "step", StepAttempt: 1}, Capability: exactaction.Capability{Name: "http.request", SemanticRevision: exactaction.CapabilityRevision}, Request: exactaction.Request{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/item/%2f?id=2&id=1?", Headers: []string{}}, Identity: exactaction.Identity{Kind: "anonymous"}, Limits: exactaction.Limits{MaxRequests: 1}}
	_, h, err := a.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	p := &fakePermit{id: "X", hash: h, epoch: 7, deadline: now.Add(time.Hour)}
	s := &fakeBackend{permit: p, action: a, now: now, epoch: p.epoch, oneAdmission: true}
	e := &countingExecutor{result: Result{Completed: true}}
	step := domain.StepRun{ID: "step", WorkflowRunID: "run", Capability: "http.request", IdempotencyKey: "key", Input: []byte(`{"request_target":"/caller-ignored"}`)}
	return &Broker{backend: s, executor: e}, s, p, e, step
}
func TestBrokerBindsAndConsumesBeforeInvocation(t *testing.T) {
	b, s, p, e, step := unitFixture(t)
	type contextKey struct{}
	key := contextKey{}
	ctx := context.WithValue(context.Background(), key, "fence")
	s.onAdmit = func(got context.Context) {
		if got != ctx {
			t.Fatal("context replaced")
		}
	}
	e.onExecute = func(got context.Context, execution Execution) {
		if !p.used.Load() || p.consumes.Load() != 1 {
			t.Fatal("executor before consumption")
		}
		if got != ctx {
			t.Fatal("executor context replaced")
		}
		if execution.ProviderAttemptID() != p.id || execution.ActionSHA256() != p.hash || execution.AuthorityEpoch() != 7 || !reflect.DeepEqual(execution.Action(), s.action) {
			t.Fatal("envelope not frozen permit-bound material")
		}
		copy := execution.Action()
		copy.Request.RequestTarget = "/edited"
		copy.Request.Headers = append(copy.Request.Headers, "forged")
		deadline := execution.Deadline()
		*deadline = time.Time{}
		if execution.Action().Request.RequestTarget == "/edited" || len(execution.Action().Request.Headers) != 0 || execution.Deadline().IsZero() {
			t.Fatal("mutable execution backing data exposed")
		}
	}
	result, err := b.ExecuteApprovedExact(ctx, "program", step, "X")
	if err != nil || !result.Completed || e.calls.Load() != 1 {
		t.Fatalf("result=%v err=%v", result, err)
	}
	if _, err = b.ExecuteApprovedExact(ctx, "program", step, "X"); err == nil || e.calls.Load() != 1 {
		t.Fatal("sequential replay")
	}
}
func TestBrokerFailClosedBoundaries(t *testing.T) {
	sentinel := errors.New("injected dependency failure")
	for _, name := range []string{"admission error", "ambiguous commit", "nil permit", "wrong X", "empty H", "negative epoch", "persisted epoch mismatch", "load error", "wrong action H", "wrong ownership", "invalid contract", "clock error", "zero clock", "consumed permit", "deadline equality", "after deadline"} {
		t.Run(name, func(t *testing.T) {
			b, s, p, e, step := unitFixture(t)
			switch name {
			case "admission error", "ambiguous commit":
				s.admitErr = sentinel
			case "nil permit":
				s.permit = nil
			case "wrong X":
				p.id = "other-X"
			case "empty H":
				p.hash = ""
			case "negative epoch":
				p.epoch = -1
			case "persisted epoch mismatch":
				p.epoch++
			case "load error":
				s.loadErr = sentinel
			case "wrong action H":
				s.action.Request.RequestTarget = "/different"
			case "wrong ownership":
				s.action.Ownership.ProgramID = "other"
				_, p.hash, _ = s.action.Freeze()
			case "invalid contract":
				s.action.Identity.Kind = "authenticated"
			case "clock error":
				s.timeErr = sentinel
			case "zero clock":
				s.now = time.Time{}
			case "consumed permit":
				p.used.Store(true)
			case "deadline equality":
				s.now = p.deadline
			case "after deadline":
				s.now = p.deadline.Add(time.Nanosecond)
			}
			if _, err := b.ExecuteApprovedExact(context.Background(), "program", step, "X"); err == nil {
				t.Fatal("unsafe execution succeeded")
			}
			if e.calls.Load() != 0 || p.consumes.Load() != 0 {
				t.Fatal("failure reached consume/executor")
			}
			if s.admissions.Load() != 1 {
				t.Fatal("admission retried")
			}
		})
	}
}
func TestBrokerDeadlineBeforeAndDelayedClock(t *testing.T) {
	b, s, p, e, step := unitFixture(t)
	s.now = p.deadline.Add(-time.Second)
	if _, err := b.ExecuteApprovedExact(context.Background(), "program", step, "X"); err != nil || e.calls.Load() != 1 {
		t.Fatal("safe pre-deadline clock failed")
	}
	b, s, p, e, step = unitFixture(t)
	s.now = p.deadline.Add(-time.Millisecond)
	s.onClock = func(context.Context) { <-time.After(10 * time.Millisecond) }
	if _, err := b.ExecuteApprovedExact(context.Background(), "program", step, "X"); err == nil || e.calls.Load() != 0 {
		t.Fatal("stale clock response revived deadline")
	}
}

func TestBrokerPostConsumptionTrustedGuard(t *testing.T) {
	for _, name := range []string{"before deadline", "clock error", "zero time", "deadline equality", "after deadline", "delayed response"} {
		t.Run(name, func(t *testing.T) {
			b, s, p, e, step := unitFixture(t)
			sentinel := errors.New("post-consume clock failure")
			s.onClock = func(context.Context) {
				if s.clocks.Load() != 2 {
					return
				}
				if !p.used.Load() || p.consumes.Load() != 1 {
					t.Fatal("second clock queried before consumption")
				}
				switch name {
				case "before deadline":
					s.now = p.deadline.Add(-time.Second)
				case "clock error":
					s.timeErr = sentinel
				case "zero time":
					s.now = time.Time{}
				case "deadline equality":
					s.now = p.deadline
				case "after deadline":
					s.now = p.deadline.Add(time.Nanosecond)
				case "delayed response":
					s.now = p.deadline.Add(-time.Millisecond)
					<-time.After(10 * time.Millisecond)
				}
			}
			_, err := b.ExecuteApprovedExact(context.Background(), "program", step, "X")
			want := int64(0)
			if name == "before deadline" {
				want = 1
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("failed post-consume guard executed")
			}
			if name == "clock error" && !errors.Is(err, sentinel) {
				t.Fatal("post-consume clock error lost")
			}
			if e.calls.Load() != want || p.consumes.Load() != 1 || s.clocks.Load() != 2 || !p.used.Load() {
				t.Fatalf("calls=%d consumes=%d clocks=%d", e.calls.Load(), p.consumes.Load(), s.clocks.Load())
			}
			fresh := &Broker{backend: s, executor: e}
			if _, err := fresh.ExecuteApprovedExact(context.Background(), "program", step, "X"); err == nil || e.calls.Load() != want || p.consumes.Load() != 1 {
				t.Fatal("post-consumption handoff replayed")
			}
		})
	}
}
func TestBrokerExecutorFailureNeverRetries(t *testing.T) {
	b, s, p, e, step := unitFixture(t)
	sentinel := errors.New("executor failed")
	e.err = sentinel
	if _, err := b.ExecuteApprovedExact(context.Background(), "program", step, "X"); !errors.Is(err, sentinel) {
		t.Fatal("executor error lost")
	}
	if _, err := b.ExecuteApprovedExact(context.Background(), "program", step, "X"); err == nil {
		t.Fatal("executor replay")
	}
	if e.calls.Load() != 1 || p.consumes.Load() != 1 || s.admissions.Load() != 2 {
		t.Fatal("retry/reset occurred")
	}
}
func TestBrokerConcurrentAndFaultyPermitReuse(t *testing.T) {
	for _, faulty := range []bool{false, true} {
		t.Run(map[bool]string{false: "single admission", true: "same permit reused"}[faulty], func(t *testing.T) {
			b, s, p, e, step := unitFixture(t)
			s.oneAdmission = !faulty
			start := make(chan struct{})
			var wg sync.WaitGroup
			var successes atomic.Int64
			for i := 0; i < 24; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if _, err := b.ExecuteApprovedExact(context.Background(), "program", step, "X"); err == nil {
						successes.Add(1)
					}
				}()
			}
			close(start)
			wg.Wait()
			if successes.Load() != 1 || e.calls.Load() != 1 || p.consumes.Load() != 1 {
				t.Fatalf("successes=%d invokes=%d consumes=%d", successes.Load(), e.calls.Load(), p.consumes.Load())
			}
			if _, err := b.ExecuteApprovedExact(context.Background(), "program", step, "X"); err == nil || e.calls.Load() != 1 {
				t.Fatal("faulty sequential permit reuse")
			}
		})
	}
}
func TestBrokerCancellationBoundaries(t *testing.T) {
	for _, boundary := range []string{"before admission", "after admission", "after load", "after clock", "after consumption", "during post-consume clock", "executor entry"} {
		t.Run(boundary, func(t *testing.T) {
			b, s, p, e, step := unitFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch boundary {
			case "before admission":
				cancel()
			case "after admission":
				s.onAdmit = func(context.Context) { cancel() }
			case "after load":
				s.onLoad = func(context.Context) { cancel() }
			case "after clock":
				s.onClock = func(context.Context) { cancel() }
			case "after consumption":
				p.onConsume = cancel
			case "during post-consume clock":
				s.onClock = func(context.Context) {
					if s.clocks.Load() == 2 {
						cancel()
					}
				}
			case "executor entry":
				e.onExecute = func(ctx context.Context, _ Execution) {
					cancel()
					if ctx.Err() == nil {
						t.Fatal("cancelled context lost")
					}
				}
				e.err = context.Canceled
			}
			if _, err := b.ExecuteApprovedExact(ctx, "program", step, "X"); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel error=%v", err)
			}
			invocations, consumes := int64(0), int64(0)
			if boundary == "after consumption" || boundary == "during post-consume clock" || boundary == "executor entry" {
				consumes = 1
			}
			if boundary == "executor entry" {
				invocations = 1
			}
			if e.calls.Load() != invocations || p.consumes.Load() != consumes {
				t.Fatal("cancellation crossed wrong boundary")
			}
			if boundary == "before admission" && s.admissions.Load() != 0 {
				t.Fatal("already cancelled admission")
			}
			if boundary != "before admission" {
				if _, err := b.ExecuteApprovedExact(context.Background(), "program", step, "X"); err == nil || e.calls.Load() != invocations {
					t.Fatal("cancelled intent replay")
				}
			}
		})
	}
}
func TestBrokerIncompleteLineageAndZeroValue(t *testing.T) {
	b, s, _, e, step := unitFixture(t)
	for _, bad := range []domain.StepRun{{}, {ID: step.ID, WorkflowRunID: step.WorkflowRunID, Capability: "other", IdempotencyKey: "key"}} {
		if _, err := b.ExecuteApprovedExact(context.Background(), "program", bad, "X"); err == nil {
			t.Fatal("invalid lineage")
		}
	}
	if _, err := b.ExecuteApprovedExact(context.Background(), "", step, "X"); err == nil {
		t.Fatal("empty program")
	}
	if _, err := b.ExecuteApprovedExact(context.Background(), "program", step, ""); err == nil {
		t.Fatal("empty X")
	}
	if s.admissions.Load() != 0 || e.calls.Load() != 0 {
		t.Fatal("incomplete identity reached dependencies")
	}
	var zero Broker
	if _, err := zero.ExecuteApprovedExact(context.Background(), "program", step, "X"); err == nil {
		t.Fatal("zero broker")
	}
	if _, err := New(nil, e); err == nil {
		t.Fatal("nil store")
	}
}

func TestBrokerUsedPermitCannotEnterWhileExecutorBlocked(t *testing.T) {
	b, s, p, e, step := unitFixture(t)
	s.oneAdmission = false
	entered, release := make(chan struct{}), make(chan struct{})
	e.onExecute = func(context.Context, Execution) { close(entered); <-release }
	done := make(chan error, 1)
	go func() { _, err := b.ExecuteApprovedExact(context.Background(), "program", step, "X"); done <- err }()
	<-entered
	if _, err := b.ExecuteApprovedExact(context.Background(), "program", step, "X"); err == nil || e.calls.Load() != 1 || p.consumes.Load() != 1 {
		t.Fatal("used permit entered blocked executor again")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
