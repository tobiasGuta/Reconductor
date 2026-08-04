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
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

type Store interface {
	ListSchedules(context.Context, domain.ID) ([]domain.Schedule, error)
	MaterializeDueSchedule(context.Context, domain.ID, time.Time, time.Time) ([]domain.ScheduledExecution, error)
	ClaimPendingScheduledExecution(context.Context, string, time.Duration) (domain.ScheduledExecution, domain.Schedule, bool, error)
	HeartbeatScheduledExecution(context.Context, domain.ID, string, int, time.Duration) error
	MarkScheduledExecutionTaskCreated(context.Context, domain.ID, domain.ID, string, int) error
	MarkScheduledExecutionRunning(context.Context, domain.ID, domain.ID, domain.ID, *domain.ID, string, int) error
	MarkScheduledExecutionPaused(context.Context, domain.ID, string, int) error
	MarkScheduledExecutionPausedForApproval(context.Context, domain.ID, string, int) error
	MarkScheduledExecutionCompleted(context.Context, domain.ID, string, int) error
	MarkScheduledExecutionFailed(context.Context, domain.ID, string, int, string, string) error
	MarkScheduledExecutionCancelled(context.Context, domain.ID, string, int) error
	MarkScheduledExecutionBlocked(context.Context, domain.ID, domain.ID, string, int) error
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
	runCtx, cancelRun := context.WithCancelCause(ctx)
	runCtx = database.WithScheduledExecutionFence(runCtx, database.ScheduledExecutionFence{ExecutionID: exec.ID, LeaseOwner: s.Owner, Attempt: exec.AttemptCount})
	defer cancelRun(nil)

	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(maxDuration(time.Second, s.Config.LeaseTimeout/3))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				err := s.Store.HeartbeatScheduledExecution(heartbeatCtx, exec.ID, s.Owner, exec.AttemptCount, s.Config.LeaseTimeout)
				if errors.Is(err, database.ErrLostScheduledExecutionLease) {
					cancelRun(err)
					return
				}
			case <-heartbeatCtx.Done():
				return
			}
		}
	}()
	defer func() {
		cancelHeartbeat()
		<-heartbeatDone
	}()

	request := orchestration.WorkflowRequest{
		ProgramID:         schedule.ProgramID,
		WorkflowName:      schedule.WorkflowName,
		Objective:         schedule.Objective,
		RequestedBy:       exec.TriggerSource,
		ScheduleReference: stringPtr(string(schedule.ID)),
		Headless:          schedule.Headless,
		Lifecycle:         scheduledExecutionLifecycle{Store: s.Store, ExecutionID: exec.ID, Owner: s.Owner, Attempt: exec.AttemptCount},
	}
	if exec.TaskID != nil {
		request.ExistingTaskID = *exec.TaskID
	}
	if exec.WorkflowRunID != nil {
		request.ResumeRunID = *exec.WorkflowRunID
	}
	result, err := s.Orchestrator.Run(runCtx, request)
	if database.IsScheduledExecutionFenceError(err) {
		return err
	}
	if errors.Is(err, orchestration.ErrScopeExpansion) {
		return s.Store.MarkScheduledExecutionBlocked(context.WithoutCancel(ctx), exec.ID, result.ScopeChange.ScopeVersionID, s.Owner, exec.AttemptCount)
	}
	if result.State != nil && result.State.Run.Status == domain.RunCancelled {
		return s.Store.MarkScheduledExecutionCancelled(context.WithoutCancel(ctx), exec.ID, s.Owner, exec.AttemptCount)
	}
	if errors.Is(err, context.Canceled) {
		return s.Store.MarkScheduledExecutionCancelled(context.WithoutCancel(ctx), exec.ID, s.Owner, exec.AttemptCount)
	}
	if err != nil {
		return s.Store.MarkScheduledExecutionFailed(context.WithoutCancel(ctx), exec.ID, s.Owner, exec.AttemptCount, "execution", err.Error())
	}
	if result.State == nil {
		return s.Store.MarkScheduledExecutionFailed(context.WithoutCancel(ctx), exec.ID, s.Owner, exec.AttemptCount, "execution", "workflow did not return state")
	}
	switch result.State.Run.Status {
	case domain.RunCompleted:
		return s.Store.MarkScheduledExecutionCompleted(context.WithoutCancel(ctx), exec.ID, s.Owner, exec.AttemptCount)
	case domain.RunPaused:
		if runAwaitingApproval(result.State) {
			return s.Store.MarkScheduledExecutionPausedForApproval(context.WithoutCancel(ctx), exec.ID, s.Owner, exec.AttemptCount)
		}
		return s.Store.MarkScheduledExecutionPaused(context.WithoutCancel(ctx), exec.ID, s.Owner, exec.AttemptCount)
	case domain.RunCancelled:
		return s.Store.MarkScheduledExecutionCancelled(context.WithoutCancel(ctx), exec.ID, s.Owner, exec.AttemptCount)
	default:
		return s.Store.MarkScheduledExecutionFailed(context.WithoutCancel(ctx), exec.ID, s.Owner, exec.AttemptCount, "execution", fmt.Sprintf("workflow ended as %s", result.State.Run.Status))
	}
}

type scheduledExecutionLifecycle struct {
	Store       Store
	ExecutionID domain.ID
	Owner       string
	Attempt     int
}

func (l scheduledExecutionLifecycle) TaskCreated(ctx context.Context, task domain.Task) error {
	return l.Store.MarkScheduledExecutionTaskCreated(ctx, l.ExecutionID, task.ID, l.Owner, l.Attempt)
}

func (l scheduledExecutionLifecycle) WorkflowCreated(ctx context.Context, task domain.Task, run domain.WorkflowRun, scopeVersionID domain.ID) error {
	var scopeVersion *domain.ID
	if scopeVersionID != "" {
		scopeVersion = &scopeVersionID
	}
	return l.Store.MarkScheduledExecutionRunning(ctx, l.ExecutionID, task.ID, run.ID, scopeVersion, l.Owner, l.Attempt)
}

func runAwaitingApproval(state *workflow.State) bool {
	for _, step := range state.Steps {
		if step.Run.Status == domain.StepAwaitingApproval {
			return true
		}
	}
	return false
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
