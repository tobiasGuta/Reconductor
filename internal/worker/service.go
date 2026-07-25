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
type Service struct {
	Queue                   *queue.Streams
	Registry                *capability.Registry
	Artifacts               artifact.Storage
	Results                 ResultStore
	PoolSize                int
	ReadBlock, LeaseTimeout time.Duration
	Logger                  *slog.Logger
	Budget                  budget.Limiter
	PolicyAuditor           capability.PolicyDecisionRecorder
	Retention               artifact.RetentionStore
	RetentionEvery          time.Duration
}

func (s *Service) Run(ctx context.Context) error {
	if s.PoolSize < 1 {
		return fmt.Errorf("worker pool size must be positive")
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	if s.RetentionEvery <= 0 {
		s.RetentionEvery = time.Minute
	}
	if err := s.purgeExpired(ctx); err != nil {
		return err
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
		retentionTicker := time.NewTicker(s.RetentionEvery)
		defer retryTicker.Stop()
		defer retentionTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-retryTicker.C:
				if _, err := s.Queue.PumpRetries(ctx, 100); err != nil {
					s.Logger.Error("retry pump failed", "error", err)
				}
			case <-retentionTicker.C:
				if err := s.purgeExpired(ctx); err != nil {
					s.Logger.Error("artifact retention purge failed", "error", err)
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
	leaseCtx, stopLease := context.WithCancel(ctx)
	defer stopLease()
	go func() {
		interval := s.LeaseTimeout / 3
		if interval <= 0 {
			interval = time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-leaseCtx.Done():
				return
			case <-ticker.C:
				if err := s.Queue.Touch(leaseCtx, d.MessageID); err != nil {
					s.Logger.Warn("job lease refresh failed", "message_id", d.MessageID, "error", err)
				}
			}
		}
	}()
	done, err := s.Results.AlreadySucceeded(ctx, d.Job.Action.IdempotencyKey)
	if err != nil {
		return err
	}
	if done {
		return s.Queue.Ack(ctx, d.MessageID, domain.ActionResult{RequestID: d.Job.Action.ID, Status: "succeeded", Summary: "duplicate delivery already completed"})
	}
	sc, err := platformscope.Compile(d.Job.ScopeIncludes, d.Job.ScopeExcludes)
	if err != nil {
		return s.Queue.Fail(ctx, d.MessageID, d.Job, "invalid_scope: "+err.Error(), false)
	}
	provider := d.Job.Provider
	if provider == "" {
		if implementation, ok := s.Registry.Get(d.Job.Action.Capability); ok {
			manifest := implementation.Manifest()
			if len(manifest.SupportedProviders) > 0 {
				provider = manifest.SupportedProviders[0]
			}
		}
	}
	if provider == "" {
		provider = d.Job.Action.Capability
	}
	if s.Budget != nil {
		release, acquireErr := s.Budget.Acquire(ctx, budget.Request{ProgramID: d.Job.ProgramID, Provider: provider, Hosts: budget.HostsFromInput(d.Job.Action.Input)})
		if acquireErr != nil {
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
	result, runErr := s.executeJob(ctx, d, provider, sc, auditor)
	if runErr != nil {
		retryable := result.Action.Error != nil && result.Action.Error.Retryable
		return s.Queue.Fail(ctx, d.MessageID, d.Job, runErr.Error(), retryable)
	}
	return s.Queue.Ack(ctx, d.MessageID, result.Action)
}

func (s *Service) executeJob(ctx context.Context, d queue.Delivery, provider string, sc capability.Scope, auditor capability.PolicyDecisionRecorder) (capability.Result, error) {
	return (execution.Service{Registry: s.Registry, Store: s.Results, Artifacts: s.Artifacts, ProgramID: d.Job.ProgramID, PolicyAuditor: auditor}).Execute(ctx, capability.Request{Action: d.Job.Action, Provider: provider, Approved: d.Job.Approved, Policy: d.Job.Policy, Scope: sc})
}

func (s *Service) purgeExpired(ctx context.Context) error {
	if s.Retention == nil {
		return nil
	}
	deleter, ok := s.Artifacts.(artifact.Deleter)
	if !ok {
		return fmt.Errorf("artifact storage does not support retention deletion")
	}
	_, err := artifact.PurgeExpired(ctx, s.Retention, deleter, 1000)
	return err
}
