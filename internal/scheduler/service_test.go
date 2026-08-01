package scheduler

import (
	"context"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type lifecycleStore struct {
	Store
	taskExecution domain.ID
	taskID        domain.ID
	taskOwner     string
	taskAttempt   int
	runExecution  domain.ID
	runTaskID     domain.ID
	runID         domain.ID
	runOwner      string
	runAttempt    int
}

func (s *lifecycleStore) MarkScheduledExecutionTaskCreated(_ context.Context, executionID, taskID domain.ID, owner string, attempt int) error {
	s.taskExecution, s.taskID, s.taskOwner, s.taskAttempt = executionID, taskID, owner, attempt
	return nil
}

func (s *lifecycleStore) MarkScheduledExecutionRunning(_ context.Context, executionID, taskID, runID domain.ID, _ *domain.ID, owner string, attempt int) error {
	s.runExecution, s.runTaskID, s.runID, s.runOwner, s.runAttempt = executionID, taskID, runID, owner, attempt
	return nil
}

func TestScheduledExecutionLifecycleForwardsClaimAttempt(t *testing.T) {
	store := &lifecycleStore{}
	executionID, taskID, runID := domain.NewID(), domain.NewID(), domain.NewID()
	lifecycle := scheduledExecutionLifecycle{Store: store, ExecutionID: executionID, Owner: "owner", Attempt: 7}
	task := domain.Task{ID: taskID}
	if err := lifecycle.TaskCreated(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if store.taskExecution != executionID || store.taskID != taskID || store.taskOwner != "owner" || store.taskAttempt != 7 {
		t.Fatalf("task callback execution=%s task=%s owner=%q attempt=%d", store.taskExecution, store.taskID, store.taskOwner, store.taskAttempt)
	}
	if err := lifecycle.WorkflowCreated(context.Background(), task, domain.WorkflowRun{ID: runID}, ""); err != nil {
		t.Fatal(err)
	}
	if store.runExecution != executionID || store.runTaskID != taskID || store.runID != runID || store.runOwner != "owner" || store.runAttempt != 7 {
		t.Fatalf("workflow callback execution=%s task=%s run=%s owner=%q attempt=%d", store.runExecution, store.runTaskID, store.runID, store.runOwner, store.runAttempt)
	}
}
