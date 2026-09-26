package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

type approvalDecisionStub struct {
	decisions map[domain.ID]string
	err       error
}

func (s approvalDecisionStub) StepApprovalDecision(context.Context, domain.ID) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return "", errors.New("unexpected approval lookup")
}

type mappedApprovalDecisionStub map[domain.ID]string

func (s mappedApprovalDecisionStub) StepApprovalDecision(_ context.Context, id domain.ID) (string, error) {
	decision, ok := s[id]
	if !ok {
		return "", errors.New("approval not found")
	}
	return decision, nil
}

func TestApprovalForResumeIsScopedToApprovedStep(t *testing.T) {
	firstRunID, secondRunID := domain.NewID(), domain.NewID()
	state := &workflow.State{Steps: map[string]*workflow.StepState{
		"first":  {Run: domain.StepRun{ID: firstRunID, StepDefinitionID: "first", Status: domain.StepAwaitingApproval}},
		"second": {Run: domain.StepRun{ID: secondRunID, StepDefinitionID: "second", Status: domain.StepAwaitingApproval}},
	}}
	approval, err := approvalForResume(context.Background(), mappedApprovalDecisionStub{firstRunID: "approved", secondRunID: "pending"}, state, false)
	if err != nil {
		t.Fatal(err)
	}
	if approved, err := approval(context.Background(), workflow.Step{ID: "first"}, policy.Moderate); err != nil || !approved {
		t.Fatalf("approved step denied: approved=%v err=%v", approved, err)
	}
	if approved, err := approval(context.Background(), workflow.Step{ID: "second"}, policy.Moderate); approved || !errors.Is(err, workflow.ErrApprovalRequired) {
		t.Fatalf("pending step inherited approval: approved=%v err=%v", approved, err)
	}
}

func TestApprovalForResumeRejectsAndHonorsCancellation(t *testing.T) {
	stepRunID := domain.NewID()
	state := &workflow.State{Steps: map[string]*workflow.StepState{"gated": {Run: domain.StepRun{ID: stepRunID, StepDefinitionID: "gated", Status: domain.StepAwaitingApproval}}}}
	if _, err := approvalForResume(context.Background(), mappedApprovalDecisionStub{stepRunID: "rejected"}, state, false); err == nil {
		t.Fatal("rejected approval was accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := approvalForResume(cancelled, approvalDecisionStub{err: context.Canceled}, state, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}

func TestInlineModerateApprovalIsSingleUseAndCannotApproveHighRisk(t *testing.T) {
	approval, err := approvalForResume(context.Background(), mappedApprovalDecisionStub{}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if approved, err := approval(context.Background(), workflow.Step{ID: "high"}, policy.High); approved || !errors.Is(err, workflow.ErrApprovalRequired) {
		t.Fatalf("high-risk step was inline-approved: approved=%v err=%v", approved, err)
	}
	if approved, err := approval(context.Background(), workflow.Step{ID: "first"}, policy.Moderate); err != nil || !approved {
		t.Fatalf("moderate inline approval failed: approved=%v err=%v", approved, err)
	}
	if approved, err := approval(context.Background(), workflow.Step{ID: "second"}, policy.Moderate); approved || !errors.Is(err, workflow.ErrApprovalRequired) {
		t.Fatalf("inline approval was reused: approved=%v err=%v", approved, err)
	}
}

func TestTaskRunningResumesInMemoryControls(t *testing.T) {
	controls := &workflow.Controls{}
	if stopped := applyTaskStatus(domain.TaskPaused, controls); stopped {
		t.Fatal("pause stopped the watcher")
	}
	if stopped := applyTaskStatus(domain.TaskRunning, controls); stopped {
		t.Fatal("resume stopped the watcher")
	}
	calls := 0
	registry := capability.NewRegistry()
	if err := registry.Register(controlTestCapability{calls: &calls}); err != nil {
		t.Fatal(err)
	}
	engine := workflow.Engine{Registry: registry, Executor: controlTestExecutor{registry: registry}, Policy: policy.Policy{AllowedCapabilities: []string{"control.test"}}, Scope: engineLivenessScope{}}
	definition := workflow.Definition{ID: domain.NewID(), Name: "control", Version: "1", Steps: []workflow.Step{{ID: "step", Capability: "control.test", Input: json.RawMessage(`{}`)}}}
	state, err := engine.Run(context.Background(), definition, nil, domain.Task{ID: domain.NewID()}, controls)
	if err != nil {
		t.Fatal(err)
	}
	if state.Run.Status != domain.RunCompleted || calls != 1 {
		t.Fatalf("resume left workflow paused: calls=%d state=%#v", calls, state)
	}
}

type controlTestCapability struct{ calls *int }

func (controlTestCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "control.test", Version: "1", Risk: policy.Low, RetrySafe: true, Idempotent: true}
}
func (controlTestCapability) Validate(context.Context, capability.Request) error { return nil }
func (c controlTestCapability) Execute(_ context.Context, request capability.Request) (capability.Result, error) {
	*c.calls++
	return capability.Result{Action: domain.ActionResult{RequestID: request.Action.ID, Status: "succeeded", Summary: "ok", Output: json.RawMessage(`{}`)}}, nil
}

type controlTestExecutor struct{ registry *capability.Registry }

func (e controlTestExecutor) Execute(ctx context.Context, request capability.Request) (capability.Result, error) {
	recorder := controlTestRecorder{}
	request.DecisionRecorder = recorder
	request.InvocationRecorder = recorder
	return e.registry.Execute(ctx, request)
}

type controlTestRecorder struct{}

func (controlTestRecorder) RecordPolicyDecision(context.Context, capability.PolicyDecisionRecord) (domain.ID, error) {
	return domain.NewID(), nil
}
func (controlTestRecorder) RecordProviderInvocationStarted(context.Context, capability.ProviderInvocationStartRecord) (domain.ID, error) {
	return domain.NewID(), nil
}
func (controlTestRecorder) RecordProviderInvocationTerminal(context.Context, capability.ProviderInvocationTerminalRecord) error {
	return nil
}

func TestEngineConstructsWithInjectedModernStorageWithoutRetentionPrerequisite(t *testing.T) {
	storage := engineLivenessArtifacts{}
	service := Service{
		Config:    config.Config{Policy: config.Policy{DefaultRateLimit: 1, DefaultConcurrency: 1, DefaultProviderConcurrency: 1, DefaultHostConcurrency: 1}},
		Store:     &database.Store{},
		Registry:  capability.NewRegistry(),
		Artifacts: storage,
	}
	engine, err := service.engine(context.Background(), domain.Task{ProgramID: domain.NewID()}, engineLivenessScope{}, false, 2, workflow.FileStore{Root: t.TempDir()}, nil, domain.NewID())
	if err != nil {
		t.Fatalf("engine construction error=%v", err)
	}
	if engine.Executor == nil {
		t.Fatal("engine did not construct an executor from injected modern artifact storage")
	}
	if engine.OperatorAttemptCeiling != 2 {
		t.Fatalf("operator attempt ceiling=%d", engine.OperatorAttemptCeiling)
	}
}

type engineLivenessScope struct{}

func (engineLivenessScope) Allows(string) bool { return true }

type engineLivenessArtifacts struct{}

func (engineLivenessArtifacts) Put(_ context.Context, request artifact.PutRequest) (domain.Artifact, error) {
	id := domain.NewID()
	key, err := artifact.StorageKeyFor(id)
	if err != nil {
		return domain.Artifact{}, err
	}
	storeID := domain.ID("00000000-0000-4000-8000-000000009007")
	return domain.Artifact{ID: id, TaskID: request.TaskID, WorkflowRunID: request.WorkflowRunID, StepRunID: request.StepRunID, ToolRunID: request.ToolRunID, Type: request.Type, ContentType: request.ContentType, Size: int64(len(request.Data)), AddressingVersion: 1, ArtifactStoreID: &storeID, StorageKey: &key}, nil
}
