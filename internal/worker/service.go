package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/budget"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/execution"
	"github.com/tobiasGuta/Reconductor/internal/queue"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
)

type ResultStore interface {
	execution.ResultStore
	AlreadySucceeded(context.Context, string) (bool, error)
}

type WorkQueue interface {
	EnsureGroup(context.Context) error
	PumpRetries(context.Context, int64) (int, error)
	ClaimStale(context.Context, time.Duration, int64) ([]queue.Delivery, error)
	Read(context.Context, time.Duration, int64) ([]queue.Delivery, error)
	Touch(context.Context, string) error
	Ack(context.Context, string, any) error
	Fail(context.Context, string, queue.Job, string, bool) error
}

var ErrDeliveryLeaseLost = errors.New("queue delivery lease lost")

type Service struct {
	Queue                   WorkQueue
	Registry                *capability.Registry
	Artifacts               artifact.Storage
	Results                 ResultStore
	PoolSize                int
	ReadBlock, LeaseTimeout time.Duration
	Logger                  *slog.Logger
	Budget                  budget.Limiter
	PolicyAuditor           capability.PolicyDecisionRecorder
}

func (s *Service) Run(ctx context.Context) error {
	if s.PoolSize < 1 {
		return fmt.Errorf("worker pool size must be positive")
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	if s.Artifacts == nil {
		return fmt.Errorf("artifact storage is required")
	}
	if err := s.Queue.EnsureGroup(ctx); err != nil {
		return err
	}
	var wg sync.WaitGroup
	errCh := make(chan error, s.PoolSize+1)
	for i := 0; i < s.PoolSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.consume(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		retryTicker := time.NewTicker(time.Second)
		defer retryTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-retryTicker.C:
				if _, err := s.Queue.PumpRetries(ctx, 100); err != nil {
					s.Logger.Error("retry pump failed", "error", err)
				}
			}
		}
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-ctx.Done():
		<-done
		return nil
	case err := <-errCh:
		return err
	case <-done:
		return nil
	}
}
func (s *Service) consume(ctx context.Context) error {
	lastClaim := time.Time{}
	for {
		if lastClaim.IsZero() || time.Since(lastClaim) >= s.LeaseTimeout/2 {
			stale, err := s.Queue.ClaimStale(ctx, s.LeaseTimeout, 10)
			if err != nil {
				return err
			}
			for _, d := range stale {
				if err := s.handle(ctx, d); err != nil {
					s.Logger.Error("stale delivery failed", "error", err)
				}
			}
			lastClaim = time.Now()
		}
		deliveries, err := s.Queue.Read(ctx, s.ReadBlock, 1)
		if err != nil {
			return err
		}
		for _, d := range deliveries {
			if err := s.handle(ctx, d); err != nil {
				s.Logger.Error("delivery failed", "message_id", d.MessageID, "error", err)
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}
func (s *Service) handle(ctx context.Context, d queue.Delivery) error {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	jobCtx, cancelJob := context.WithCancelCause(ctx)
	leaseDone := make(chan struct{})
	go func() {
		defer close(leaseDone)
		interval := s.LeaseTimeout / 3
		if interval <= 0 {
			interval = time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-jobCtx.Done():
				return
			case <-ticker.C:
				if err := s.Queue.Touch(jobCtx, d.MessageID); err != nil {
					if jobCtx.Err() != nil {
						return
					}
					logger.Warn("job lease refresh failed", "message_id", d.MessageID, "error", err)
					cancelJob(fmt.Errorf("%w: %v", ErrDeliveryLeaseLost, err))
					return
				}
			}
		}
	}()
	defer func() {
		cancelJob(context.Canceled)
		<-leaseDone
	}()
	done, err := s.Results.AlreadySucceeded(jobCtx, d.Job.Action.IdempotencyKey)
	if err != nil {
		if leaseErr := deliveryLeaseError(jobCtx); leaseErr != nil {
			return leaseErr
		}
		return err
	}
	if err := deliveryLeaseError(jobCtx); err != nil {
		return err
	}
	if done {
		return s.Queue.Ack(jobCtx, d.MessageID, domain.QueueResultV1{Version: "queue-result/v1", ActionRequestID: d.Job.Action.ID, Status: "succeeded", Summary: "duplicate delivery already completed"})
	}
	sc, err := platformscope.Compile(d.Job.ScopeIncludes, d.Job.ScopeExcludes)
	if err != nil {
		if leaseErr := deliveryLeaseError(jobCtx); leaseErr != nil {
			return leaseErr
		}
		return s.Queue.Fail(jobCtx, d.MessageID, d.Job, "invalid_scope: "+err.Error(), false)
	}
	provider := s.resolveProvider(d.Job)
	if s.Budget != nil {
		release, acquireErr := s.Budget.Acquire(jobCtx, budget.Request{ProgramID: d.Job.ProgramID, Provider: provider, Hosts: budget.HostsFromInput(d.Job.Action.Input)})
		if acquireErr != nil {
			if leaseErr := deliveryLeaseError(jobCtx); leaseErr != nil {
				return leaseErr
			}
			return acquireErr
		}
		defer release()
	}
	auditor := s.PolicyAuditor
	if auditor == nil {
		if recorder, ok := s.Results.(capability.PolicyDecisionRecorder); ok {
			auditor = recorder
		}
	}
	result, runErr := s.executeJob(jobCtx, d, provider, sc, auditor)
	if leaseErr := deliveryLeaseError(jobCtx); leaseErr != nil {
		// A delivery whose ownership can no longer be proven must remain pending.
		// A subsequent owner will either observe the durable result or resume the
		// prepared-result lifecycle without replaying an unknown provider outcome.
		return leaseErr
	}
	if domain.PersistenceUnresolved(runErr) {
		// Leave the delivery pending. Neither retry nor dead-letter is a known
		// outcome while the original result may still be committed.
		return runErr
	}
	if runErr != nil {
		retryable := result.Action.Error != nil && result.Action.Error.Retryable
		return s.Queue.Fail(jobCtx, d.MessageID, d.Job, runErr.Error(), retryable)
	}
	if result.Envelope == nil {
		return fmt.Errorf("worker result has no admitted bounded envelope")
	}
	return s.Queue.Ack(jobCtx, d.MessageID, *result.Envelope)
}

func deliveryLeaseError(ctx context.Context) error {
	cause := context.Cause(ctx)
	if errors.Is(cause, ErrDeliveryLeaseLost) {
		return cause
	}
	return nil
}

func (s *Service) resolveProvider(job queue.Job) string {
	return s.Registry.ProviderName(job.Action.Capability, job.Provider)
}

func (s *Service) executeJob(ctx context.Context, d queue.Delivery, provider string, sc capability.Scope, auditor capability.PolicyDecisionRecorder) (capability.Result, error) {
	var queueJobID *domain.ID
	if d.Job.ID != "" {
		id := d.Job.ID
		queueJobID = &id
	}
	return (execution.Service{Registry: s.Registry, Store: s.Results, Artifacts: s.Artifacts, ProgramID: d.Job.ProgramID, PolicyAuditor: auditor}).Execute(ctx, capability.Request{Action: d.Job.Action, Provider: provider, Approved: d.Job.Approved, Policy: d.Job.Policy, Scope: sc, QueueJobID: queueJobID})
}
