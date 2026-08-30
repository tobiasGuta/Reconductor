package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

func TestReconcileCheckpointReconstructsOnlyMissingInitialCheckpoint(t *testing.T) {
	state := modernCheckpointState(t)
	root := t.TempDir()
	store := workflow.FileStore{Root: root}

	got, err := reconcileCheckpoint(context.Background(), store, state)
	if err != nil {
		t.Fatal(err)
	}
	if got.Run.ID != state.Run.ID || len(got.Steps) != 0 || len(got.Events) != 1 || got.Events[0].Type != "workflow_started" || !got.Events[0].At.Equal(*state.Run.StartedAt) {
		t.Fatalf("reconstructed state=%#v", got)
	}
	reloaded, err := store.Load(string(state.Run.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCheckpointIdentity(state, reloaded); err != nil {
		t.Fatalf("reconstructed checkpoint identity: %v", err)
	}
}

func TestReconcileCheckpointFailsClosed(t *testing.T) {
	t.Run("missing checkpoint with StepRuns", func(t *testing.T) {
		state := modernCheckpointState(t)
		state.Steps["existing"] = &workflow.StepState{Run: domain.StepRun{ID: domain.NewID(), WorkflowRunID: state.Run.ID, StepDefinitionID: "existing", Capability: "test", Status: domain.StepRunning}}
		_, err := reconcileCheckpoint(context.Background(), workflow.FileStore{Root: t.TempDir()}, state)
		if !errors.Is(err, workflow.ErrWorkflowCheckpointUnavailable) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("terminal run", func(t *testing.T) {
		state := modernCheckpointState(t)
		state.Run.Status = domain.RunCompleted
		_, err := reconcileCheckpoint(context.Background(), workflow.FileStore{Root: t.TempDir()}, state)
		if !errors.Is(err, workflow.ErrWorkflowCheckpointUnavailable) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("malformed checkpoint", func(t *testing.T) {
		state := modernCheckpointState(t)
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, string(state.Run.ID)+".json"), []byte(`{"run":`), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := reconcileCheckpoint(context.Background(), workflow.FileStore{Root: root}, state)
		if !errors.Is(err, workflow.ErrWorkflowCheckpointConflict) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("type-corrupt checkpoint", func(t *testing.T) {
		state := modernCheckpointState(t)
		root := t.TempDir()
		path := filepath.Join(root, string(state.Run.ID)+".json")
		content := []byte(`{"run":{"id":17}}`)
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		_, err := reconcileCheckpoint(context.Background(), workflow.FileStore{Root: root}, state)
		if !errors.Is(err, workflow.ErrWorkflowCheckpointConflict) {
			t.Fatalf("error=%v", err)
		}
		preserved, readErr := os.ReadFile(path)
		if readErr != nil || string(preserved) != string(content) {
			t.Fatalf("malformed checkpoint was overwritten: error=%v content=%q", readErr, preserved)
		}
	})

	t.Run("conflicting checkpoint", func(t *testing.T) {
		state := modernCheckpointState(t)
		root := t.TempDir()
		checkpoint := cloneWorkflowState(t, state)
		checkpoint.Run.TaskID = domain.NewID()
		if err := (workflow.FileStore{Root: root}).Save(context.Background(), checkpoint); err != nil {
			t.Fatal(err)
		}
		_, err := reconcileCheckpoint(context.Background(), workflow.FileStore{Root: root}, state)
		if !errors.Is(err, workflow.ErrWorkflowCheckpointConflict) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("incomplete existing checkpoint", func(t *testing.T) {
		state := modernCheckpointState(t)
		state.Steps["started"] = &workflow.StepState{Run: domain.StepRun{ID: domain.NewID(), WorkflowRunID: state.Run.ID, StepDefinitionID: "started", Capability: "test", Status: domain.StepRunning, IdempotencyKey: "started-key"}}
		root := t.TempDir()
		checkpoint := cloneWorkflowState(t, state)
		checkpoint.Steps = map[string]*workflow.StepState{}
		if err := (workflow.FileStore{Root: root}).Save(context.Background(), checkpoint); err != nil {
			t.Fatal(err)
		}
		_, err := reconcileCheckpoint(context.Background(), workflow.FileStore{Root: root}, state)
		if !errors.Is(err, workflow.ErrWorkflowCheckpointConflict) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("legacy materialization", func(t *testing.T) {
		state := modernCheckpointState(t)
		state.Run.MaterializedDefinition = nil
		state.Run.MaterializationDigest = ""
		state.Run.OriginalScopeVersionID = nil
		_, err := reconcileCheckpoint(context.Background(), workflow.FileStore{Root: t.TempDir()}, state)
		if !errors.Is(err, workflow.ErrWorkflowResumeUnavailable) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("materialization digest mismatch", func(t *testing.T) {
		state := modernCheckpointState(t)
		state.Run.MaterializationDigest = "0000000000000000000000000000000000000000000000000000000000000000"
		_, err := reconcileCheckpoint(context.Background(), workflow.FileStore{Root: t.TempDir()}, state)
		if !errors.Is(err, workflow.ErrWorkflowCheckpointConflict) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestReconcileCheckpointKeepsDatabaseAuthoritative(t *testing.T) {
	state := modernCheckpointState(t)
	root := t.TempDir()
	checkpoint := cloneWorkflowState(t, state)
	checkpoint.Run.Status = domain.RunPaused
	checkpoint.Events = []workflow.Event{{At: *state.Run.StartedAt, Type: "workflow_started", Message: "from checkpoint"}}
	if err := (workflow.FileStore{Root: root}).Save(context.Background(), checkpoint); err != nil {
		t.Fatal(err)
	}
	got, err := reconcileCheckpoint(context.Background(), workflow.FileStore{Root: root}, state)
	if err != nil {
		t.Fatal(err)
	}
	if got.Run.Status != domain.RunRunning || len(got.Events) != 1 || got.Events[0].Message != "from checkpoint" {
		t.Fatalf("reconciled state=%#v", got)
	}
}

type corruptAfterReconstructionStore struct {
	loads   int
	saves   int
	content []byte
}

func (s *corruptAfterReconstructionStore) Load(string) (*workflow.State, error) {
	s.loads++
	if s.loads == 1 {
		return nil, os.ErrNotExist
	}
	return nil, &workflow.CheckpointDecodeError{Err: errors.New("synthetic type-corrupt checkpoint")}
}

func (s *corruptAfterReconstructionStore) Save(context.Context, *workflow.State) error {
	s.saves++
	s.content = []byte(`{"run":{"id":17}}`)
	return nil
}

func TestReconcileCheckpointClassifiesSecondLoadCorruptionAsConflict(t *testing.T) {
	state := modernCheckpointState(t)
	store := &corruptAfterReconstructionStore{}
	_, err := reconcileCheckpoint(context.Background(), store, state)
	if !errors.Is(err, workflow.ErrWorkflowCheckpointConflict) || !strings.Contains(err.Error(), "malformed checkpoint") {
		t.Fatalf("error=%v", err)
	}
	if store.loads != 2 || store.saves != 1 || string(store.content) != `{"run":{"id":17}}` {
		t.Fatalf("loads=%d saves=%d content=%q", store.loads, store.saves, store.content)
	}
}

func modernCheckpointState(t *testing.T) *workflow.State {
	t.Helper()
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	definition := workflow.Definition{ID: domain.NewID(), Name: "checkpoint-test", Version: "1", Materializer: "web-recon/v1", Description: "test", Steps: []workflow.Step{}, DefaultPolicyRequirements: json.RawMessage(`{}`), CreatedAt: now}
	materialized, digest, err := workflow.Materialize(definition)
	if err != nil {
		t.Fatal(err)
	}
	scopeVersionID := domain.NewID()
	return &workflow.State{Run: domain.WorkflowRun{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowDefinitionID: definition.ID, WorkflowVersion: definition.Version, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "test", Summary: json.RawMessage(`{}`), MaterializedDefinition: materialized, MaterializationDigest: digest, OriginalScopeVersionID: &scopeVersionID}, Steps: map[string]*workflow.StepState{}}
}

func cloneWorkflowState(t *testing.T, state *workflow.State) *workflow.State {
	t.Helper()
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var clone workflow.State
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return &clone
}
