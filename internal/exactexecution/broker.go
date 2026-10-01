// Package exactexecution consumes admitted exact launch authority. It has no
// transport implementation and no production caller in this foundation slice.
package exactexecution

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
)

var ErrExecutionDenied = errors.New("exact execution denied")

// Store contains only upstream admission and read-only execution dependencies.
// In particular it exposes no approval, evidence, reset, or recovery operation.
type Store interface {
	AdmitExactDispatch(context.Context, domain.ID, domain.StepRun, domain.ID) (*database.ExactDispatchPermit, error)
	LoadExactDispatchAction(context.Context, domain.ID, string, int64) (exactaction.ActionContractV1, error)
	ExactDispatchTrustedTime(context.Context) (time.Time, error)
}

type Executor interface {
	Execute(context.Context, Execution) (Result, error)
}

// Result is deliberately bounded and carries no transport/evidence payload.
type Result struct{ Completed bool }

// Execution is an immutable value. Accessors never expose mutable backing data
// or permit authority. Only the broker can construct a nonzero envelope.
type Execution struct {
	providerAttemptID domain.ID
	actionSHA256      string
	authorityEpoch    int64
	action            exactaction.ActionContractV1
	deadline          *time.Time
}

func (e Execution) ProviderAttemptID() domain.ID { return e.providerAttemptID }
func (e Execution) ActionSHA256() string         { return e.actionSHA256 }
func (e Execution) AuthorityEpoch() int64        { return e.authorityEpoch }
func (e Execution) Action() exactaction.ActionContractV1 {
	action := e.action
	action.Request.Headers = append([]string{}, action.Request.Headers...)
	return action
}
func (e Execution) Deadline() *time.Time {
	if e.deadline == nil {
		return nil
	}
	copy := *e.deadline
	return &copy
}

// The private ports allow fault/one-use tests without publishing a permit
// factory or changing the frozen database permit API.
type dispatchPermit interface {
	ProviderAttemptID() domain.ID
	ActionSHA256() string
	AuthorityEpoch() int64
	Deadline() *time.Time
	ConsumeAt(time.Time) bool
}
type backend interface {
	admit(context.Context, domain.ID, domain.StepRun, domain.ID) (dispatchPermit, error)
	load(context.Context, domain.ID, string, int64) (exactaction.ActionContractV1, error)
	trustedTime(context.Context) (time.Time, error)
}
type storeBackend struct{ Store }

func (s storeBackend) admit(ctx context.Context, programID domain.ID, step domain.StepRun, id domain.ID) (dispatchPermit, error) {
	permit, err := s.AdmitExactDispatch(ctx, programID, step, id)
	if err != nil || permit == nil {
		return nil, err
	}
	return permit, nil
}
func (s storeBackend) load(ctx context.Context, id domain.ID, hash string, epoch int64) (exactaction.ActionContractV1, error) {
	return s.LoadExactDispatchAction(ctx, id, hash, epoch)
}
func (s storeBackend) trustedTime(ctx context.Context) (time.Time, error) {
	return s.ExactDispatchTrustedTime(ctx)
}

type Broker struct {
	backend  backend
	executor Executor
}

func New(store Store, executor Executor) (*Broker, error) {
	if store == nil || executor == nil {
		return nil, fmt.Errorf("%w: store and executor are required", ErrExecutionDenied)
	}
	return &Broker{backend: storeBackend{store}, executor: executor}, nil
}

// ExecuteApprovedExact admits once, binds frozen material, consumes once, and
// calls the executor once. It never retries, resets intent, or alters approval.
// The original context, including any scheduler fence, reaches admission.
// Successful consumption plus a successful post-consumption trusted deadline
// guard authorize the handoff. With a captured deadline, the fresh successful
// guard proves consumption occurred before it. A later pause before executor
// entry does not re-evaluate authority; the deadline bounds this handoff, not
// that instruction.
func (b *Broker) ExecuteApprovedExact(ctx context.Context, programID domain.ID, step domain.StepRun, providerAttemptID domain.ID) (Result, error) {
	if b == nil || b.backend == nil || b.executor == nil || ctx == nil || programID == "" || step.ID == "" || step.WorkflowRunID == "" || step.IdempotencyKey == "" || step.Capability != "http.request" || providerAttemptID == "" {
		return Result{}, fmt.Errorf("%w: incomplete execution lineage", ErrExecutionDenied)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	permit, err := b.backend.admit(ctx, programID, step, providerAttemptID)
	if err != nil {
		return Result{}, err // Includes commit ambiguity: never retry admission.
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if permit == nil || permit.ProviderAttemptID() != providerAttemptID || permit.ActionSHA256() == "" || permit.AuthorityEpoch() < 0 {
		return Result{}, fmt.Errorf("%w: invalid admitted permit identity", ErrExecutionDenied)
	}
	action, err := b.backend.load(ctx, permit.ProviderAttemptID(), permit.ActionSHA256(), permit.AuthorityEpoch())
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	// This binds the returned value to H; authorization stays in admission.
	_, hash, err := action.Freeze()
	if err != nil || hash != permit.ActionSHA256() || action.Ownership.ProgramID != programID || action.Ownership.WorkflowRunID != step.WorkflowRunID || action.Ownership.StepRunID != step.ID {
		return Result{}, fmt.Errorf("%w: frozen execution binding mismatch", ErrExecutionDenied)
	}
	deadline := permit.Deadline()
	preConsume, err := b.trustedNow(ctx)
	if err != nil {
		return Result{}, err
	}
	if deadline != nil && !preConsume.Before(*deadline) {
		return Result{}, fmt.Errorf("%w: permit expired before consumption", ErrExecutionDenied)
	}
	if !permit.ConsumeAt(preConsume) {
		return Result{}, fmt.Errorf("%w: permit unavailable or expired", ErrExecutionDenied)
	}
	// This new sample is taken after consumption. It catches a pause between
	// fixing preConsume and consuming, without reviving the spent permission.
	postConsume, err := b.trustedNow(ctx)
	if err != nil {
		return Result{}, err
	}
	if deadline != nil && !postConsume.Before(*deadline) {
		return Result{}, fmt.Errorf("%w: permit expired at execution handoff", ErrExecutionDenied)
	}
	action.Request.Headers = append([]string{}, action.Request.Headers...)
	envelope := Execution{providerAttemptID: permit.ProviderAttemptID(), actionSHA256: permit.ActionSHA256(), authorityEpoch: permit.AuthorityEpoch(), action: action, deadline: deadline}
	return b.executor.Execute(ctx, envelope)
}

// trustedNow keeps PostgreSQL as the authority clock, advancing each fresh
// sample by the entire monotonic query round trip. Both consumption guards use
// this independently; there is no caller time or local wall-clock fallback.
func (b *Broker) trustedNow(ctx context.Context) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	started := time.Now()
	now, err := b.backend.trustedTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if now.IsZero() {
		return time.Time{}, fmt.Errorf("%w: trusted execution clock unavailable", ErrExecutionDenied)
	}
	return now.Add(time.Since(started)), nil
}

var _ Store = (*database.Store)(nil)
