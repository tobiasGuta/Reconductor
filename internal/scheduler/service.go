package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/orchestration"
)

type Store interface {
	ListSchedules(context.Context, domain.ID) ([]domain.Schedule, error)
	MaterializeDueSchedule(context.Context, domain.ID, time.Time, time.Time) ([]domain.ScheduledExecution, error)
	ClaimPendingScheduledExecution(context.Context, string, time.Duration) (domain.ScheduledExecution, domain.Schedule, bool, error)
	HeartbeatScheduledExecution(context.Context, domain.ID, string, time.Duration) error
	MarkScheduledExecutionRunning(context.Context, domain.ID, domain.ID, domain.ID, *domain.ID, string) error
	MarkScheduledExecutionPaused(context.Context, domain.ID, string) error
	MarkScheduledExecutionCompleted(context.Context, domain.ID, string) error
	MarkScheduledExecutionFailed(context.Context, domain.ID, string, string, string) error
	MarkScheduledExecutionBlocked(context.Context, domain.ID, domain.ID, string) error
}

type Service struct {
	Store        Store
	Orchestrator *orchestration.Service
	Config       config.Scheduler
	Owner        string
	Logger       *slog.Logger
}

func New(store *database.Store, orchestrator *orchestration.Service, cfg config.Scheduler) *Service {
	owner, _ := os.Hostname()
	if owner == "" {
		owner = "scheduler"
	}
	return &Service{Store: store, Orchestrator: orchestrator, Config: cfg, Owner: owner, Logger: slog.Default()}
}

func (s *Service) Tick(ctx context.Context) error {
	if err := s.Materialize(ctx); err != nil {
		return err
	}
	return s.Dispatch(ctx)
}

func (s *Service) Materialize(ctx context.Context) error {
	schedules, err := s.Store.ListSchedules(ctx, "")
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, schedule := range schedules {
		if !schedule.Enabled {
			continue
		}
		due, ok, err := DueOccurrence(schedule.CronExpression, schedule.Timezone, schedule.NextRunAt, now)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		// Limit one schedule per transaction so next_run_at is calculated in the
		// cron package and only one missed occurrence is materialized.
		if _, err := s.Store.MaterializeDueSchedule(ctx, schedule.ID, now, due.NextRunAt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Dispatch(ctx context.Context) error {
	max := s.Config.MaxConcurrentRuns
	if max < 1 {
		max = 1
	}
	var wg sync.WaitGroup
	errs := make(chan error, max)
	for i := 0; i < max; i++ {
		exec, schedule, ok, err := s.Store.ClaimPendingScheduledExecution(ctx, s.Owner, s.Config.LeaseTimeout)
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.execute(ctx, exec, schedule); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	var joined error
	for err := range errs {
		joined = errors.Join(joined, err)
	}
	return joined
}

func (s *Service) execute(ctx context.Context, exec domain.ScheduledExecution, schedule domain.Schedule) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopHeartbeat := make(chan struct{})
	go func() {
		ticker := time.NewTicker(maxDuration(time.Second, s.Config.LeaseTimeout/3))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = s.Store.HeartbeatScheduledExecution(context.WithoutCancel(ctx), exec.ID, s.Owner, s.Config.LeaseTimeout)
			case <-stopHeartbeat:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	defer close(stopHeartbeat)

	request := orchestration.WorkflowRequest{
		ProgramID:         schedule.ProgramID,
		WorkflowName:      schedule.WorkflowName,
		Objective:         schedule.Objective,
		RequestedBy:       exec.TriggerSource,
		ScheduleReference: stringPtr(string(schedule.ID)),
		Headless:          schedule.Headless,
	}
	if exec.TaskID != nil {
		request.ExistingTaskID = *exec.TaskID
	}
	if exec.WorkflowRunID != nil {
		request.ResumeRunID = *exec.WorkflowRunID
	}
	result, err := s.Orchestrator.Run(runCtx, request)
	if errors.Is(err, orchestration.ErrScopeExpansion) {
		return s.Store.MarkScheduledExecutionBlocked(context.WithoutCancel(ctx), exec.ID, result.ScopeChange.ScopeVersionID, s.Owner)
	}
	if result.State != nil {
		var scopeVersion *domain.ID
		if result.ScopeChange.ScopeVersionID != "" {
			scopeVersion = &result.ScopeChange.ScopeVersionID
		}
		_ = s.Store.MarkScheduledExecutionRunning(context.WithoutCancel(ctx), exec.ID, result.Task.ID, result.State.Run.ID, scopeVersion, s.Owner)
	}
	if err != nil {
		return s.Store.MarkScheduledExecutionFailed(context.WithoutCancel(ctx), exec.ID, s.Owner, "execution", err.Error())
	}
	if result.State == nil {
		return s.Store.MarkScheduledExecutionFailed(context.WithoutCancel(ctx), exec.ID, s.Owner, "execution", "workflow did not return state")
	}
	switch result.State.Run.Status {
	case domain.RunCompleted:
		return s.Store.MarkScheduledExecutionCompleted(context.WithoutCancel(ctx), exec.ID, s.Owner)
	case domain.RunPaused:
		return s.Store.MarkScheduledExecutionPaused(context.WithoutCancel(ctx), exec.ID, s.Owner)
	case domain.RunCancelled:
		return s.Store.MarkScheduledExecutionFailed(context.WithoutCancel(ctx), exec.ID, s.Owner, "cancelled", "workflow was cancelled")
	default:
		return s.Store.MarkScheduledExecutionFailed(context.WithoutCancel(ctx), exec.ID, s.Owner, "execution", fmt.Sprintf("workflow ended as %s", result.State.Run.Status))
	}
}

func (s *Service) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.Config.PollInterval)
	defer ticker.Stop()
	for {
		if err := s.Tick(ctx); err != nil && s.Logger != nil {
			s.Logger.Warn("scheduler tick failed", "error", err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func stringPtr(value string) *string { return &value }

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
