package worker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/execution"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/queue"
)

type workerCaptureCapability struct {
	input json.RawMessage
}

func (*workerCaptureCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "classify.endpoint", Version: "3", Risk: policy.Passive, RetrySafe: true, Idempotent: true}
}
func (*workerCaptureCapability) Validate(context.Context, capability.Request) error { return nil }
func (c *workerCaptureCapability) Execute(_ context.Context, req capability.Request) (capability.Result, error) {
	c.input = append(json.RawMessage(nil), req.Action.Input...)
	return capability.Result{
		Action:    domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Summary: "classified", Output: json.RawMessage(`{"endpoints":[],"classifications":[],"interesting_endpoints":[],"relationships":[]}`)},
		RawStdout: []byte("raw provider stdout\n"),
		RawStderr: []byte("raw provider stderr\n"),
	}, nil
}

type workerStore struct {
	previous  []string
	loadedFor string
	step      domain.StepRun
	tool      *domain.ToolRun
	artifacts []domain.Artifact
	result    domain.ActionResult
}

func (*workerStore) AlreadySucceeded(context.Context, string) (bool, error) { return false, nil }
func (s *workerStore) PreviousObservationValues(_ context.Context, _ domain.ID, _ domain.ID, capabilityName string) ([]string, error) {
	s.loadedFor = capabilityName
	return append([]string(nil), s.previous...), nil
}
func (s *workerStore) PersistResult(_ context.Context, _ domain.ID, step domain.StepRun, tool *domain.ToolRun, artifacts []domain.Artifact, result domain.ActionResult) error {
	s.step = step
	s.tool = tool
	s.artifacts = append([]domain.Artifact(nil), artifacts...)
	s.result = result
	return nil
}

type workerArtifacts struct {
	puts []artifact.PutRequest
}

func (s *workerArtifacts) Put(_ context.Context, req artifact.PutRequest) (domain.Artifact, error) {
	s.puts = append(s.puts, req)
	return domain.Artifact{ID: domain.NewID(), TaskID: req.TaskID, WorkflowRunID: req.WorkflowRunID, StepRunID: req.StepRunID, ToolRunID: req.ToolRunID, Type: req.Type, ContentType: req.ContentType, Size: int64(len(req.Data)), StorageLocation: "memory://" + req.Name, CreatedAt: time.Now().UTC()}, nil
}

type workerScope struct{}

func (workerScope) Allows(string) bool { return true }

type parityCapability struct {
	fail bool
}

func (parityCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "parity.cap", Version: "1", Risk: policy.Low, RetrySafe: true, Idempotent: true}
}
func (parityCapability) Validate(context.Context, capability.Request) error { return nil }
func (c parityCapability) Execute(_ context.Context, req capability.Request) (capability.Result, error) {
	now := time.Now().UTC()
	exitCode := 0
	tool := &domain.ToolRun{ID: domain.NewID(), StepRunID: req.Action.StepRunID, Capability: req.Action.Capability, Provider: req.Provider, ToolVersion: "test", SanitizedArguments: json.RawMessage(`{"safe":true}`), ExecutionEnvironment: json.RawMessage(`{"kind":"test"}`), StartedAt: now, CompletedAt: &now, ExitCode: &exitCode}
	result := capability.Result{
		Action:    domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Summary: "parity ok", Output: json.RawMessage(`{"lines":["https://x.test/"]}`)},
		ToolRun:   tool,
		RawStdout: []byte("raw stdout\n"),
		RawStderr: []byte("raw stderr\n"),
	}
	if c.fail {
		result.Action.Status = "failed"
		result.Action.Summary = "parity failed"
		result.Action.Error = &domain.StructuredError{Classification: "provider_error", Message: "temporary parity failure", Retryable: true}
		return result, errors.New("temporary parity failure")
	}
	return result, nil
}

func TestWorkerExecutionUsesSharedPipelineForHistoryAndArtifacts(t *testing.T) {
	registry := capability.NewRegistry()
	classifier := &workerCaptureCapability{}
	if err := registry.Register(classifier); err != nil {
		t.Fatal(err)
	}
	store := &workerStore{previous: []string{`{"provider":"httpx","kind":"url","target":"https://x.test/api","status_code":401}`}}
	artifacts := &workerArtifacts{}
	programID, taskID, runID, stepID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	input := json.RawMessage(`{"active":[],"passive":[],"http_observations":[],"crawl_observations":[],"passive_observations":[],"historical_observations":[],"api_schema_endpoints":[],"target_plan_digest":"plan"}`)
	service := &Service{Registry: registry, Results: store, Artifacts: artifacts}
	delivery := queue.Delivery{Job: queue.Job{ProgramID: programID, Action: domain.ActionRequest{ID: domain.NewID(), TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, Capability: "classify.endpoint", Input: input, IdempotencyKey: "job"}, Policy: policy.Policy{AllowedCapabilities: []string{"classify.endpoint"}, ArtifactRetention: time.Hour}}}

	result, err := service.executeJob(context.Background(), delivery, "platform", workerScope{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action.Status != "succeeded" || store.step.Status != domain.StepSucceeded {
		t.Fatalf("result=%#v step=%#v", result.Action, store.step)
	}
	var captured struct {
		History []map[string]any `json:"historical_observations"`
	}
	if err := json.Unmarshal(classifier.input, &captured); err != nil {
		t.Fatal(err)
	}
	if store.loadedFor != "probe.http" || len(captured.History) != 1 || captured.History[0]["status_code"] != float64(401) {
		t.Fatalf("historical evidence was not injected: loaded_for=%q input=%s", store.loadedFor, classifier.input)
	}
	if store.tool == nil || store.tool.StdoutArtifactID == nil || store.tool.StderrArtifactID == nil {
		t.Fatalf("raw artifact IDs were not attached to the tool run: %#v", store.tool)
	}
	var stdoutID, stderrID, resultID domain.ID
	for _, artifact := range store.artifacts {
		switch artifact.StorageLocation {
		case "memory://stdout.jsonl":
			stdoutID = artifact.ID
			if artifact.Type != "raw-provider-output" || artifact.ContentType != "application/x-ndjson" {
				t.Fatalf("stdout artifact mismatch: %#v", artifact)
			}
		case "memory://stderr.txt":
			stderrID = artifact.ID
			if artifact.Type != "raw-provider-output" || artifact.ContentType != "text/plain" {
				t.Fatalf("stderr artifact mismatch: %#v", artifact)
			}
		case "memory://result.json":
			resultID = artifact.ID
			if artifact.Type != "normalized-result" || artifact.ContentType != "application/json" {
				t.Fatalf("result artifact mismatch: %#v", artifact)
			}
		}
	}
	if stdoutID == "" || stderrID == "" || resultID == "" {
		t.Fatalf("expected stdout, stderr, and result artifacts, got %#v", store.artifacts)
	}
	if *store.tool.StdoutArtifactID != stdoutID || *store.tool.StderrArtifactID != stderrID {
		t.Fatalf("tool raw artifact pointers are wrong: tool=%#v stdout=%s stderr=%s", store.tool, stdoutID, stderrID)
	}
	for _, id := range store.result.ArtifactIDs {
		if id == stdoutID {
			t.Fatalf("raw stdout artifact leaked into normalized action artifact IDs: %#v", store.result.ArtifactIDs)
		}
	}
}

func TestLocalAndWorkerExecutionPipelineParityForSuccessAndRetryableFailure(t *testing.T) {
	for _, test := range []struct {
		name       string
		fail       bool
		wantStatus domain.StepStatus
	}{
		{name: "success", wantStatus: domain.StepSucceeded},
		{name: "retryable-failure", fail: true, wantStatus: domain.StepRetryable},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry := capability.NewRegistry()
			if err := registry.Register(parityCapability{fail: test.fail}); err != nil {
				t.Fatal(err)
			}
			programID, taskID, runID := domain.NewID(), domain.NewID(), domain.NewID()
			localStore, localArtifacts := &workerStore{}, &workerArtifacts{}
			workerStore, workerArtifacts := &workerStore{}, &workerArtifacts{}
			localReq := capability.Request{Action: parityAction(taskID, runID, domain.NewID()), Provider: "resolved-provider", Policy: policy.Policy{AllowedCapabilities: []string{"parity.cap"}, ArtifactRetention: time.Hour}, Scope: workerScope{}}
			localResult, localErr := (execution.Service{Registry: registry, Store: localStore, Artifacts: localArtifacts, ProgramID: programID}).Execute(context.Background(), localReq)
			workerDelivery := queue.Delivery{Job: queue.Job{ProgramID: programID, Action: parityAction(taskID, runID, domain.NewID()), Policy: policy.Policy{AllowedCapabilities: []string{"parity.cap"}, ArtifactRetention: time.Hour}}}
			workerResult, workerErr := (&Service{Registry: registry, Results: workerStore, Artifacts: workerArtifacts}).executeJob(context.Background(), workerDelivery, "resolved-provider", workerScope{}, nil)
			if (localErr == nil) != (workerErr == nil) {
				t.Fatalf("local err=%v worker err=%v", localErr, workerErr)
			}
			if localResult.Action.Status != workerResult.Action.Status || localResult.Action.Summary != workerResult.Action.Summary {
				t.Fatalf("action mismatch local=%#v worker=%#v", localResult.Action, workerResult.Action)
			}
			if localStore.step.Status != test.wantStatus || workerStore.step.Status != test.wantStatus {
				t.Fatalf("step status local=%s worker=%s want=%s", localStore.step.Status, workerStore.step.Status, test.wantStatus)
			}
			if localStore.tool.Provider != "resolved-provider" || workerStore.tool.Provider != "resolved-provider" {
				t.Fatalf("provider attribution local=%#v worker=%#v", localStore.tool, workerStore.tool)
			}
			assertArtifactRoles(t, "local", localStore, localArtifacts)
			assertArtifactRoles(t, "worker", workerStore, workerArtifacts)
		})
	}
}

func parityAction(taskID, runID, stepID domain.ID) domain.ActionRequest {
	return domain.ActionRequest{ID: domain.NewID(), TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, Capability: "parity.cap", Input: json.RawMessage(`{"ok":true}`), IdempotencyKey: string(stepID)}
}

func assertArtifactRoles(t *testing.T, name string, store *workerStore, artifacts *workerArtifacts) {
	t.Helper()
	if len(artifacts.puts) != 3 || len(store.artifacts) != 3 {
		t.Fatalf("%s artifact count puts=%d persisted=%d", name, len(artifacts.puts), len(store.artifacts))
	}
	roles := map[string]string{}
	for _, put := range artifacts.puts {
		roles[put.Name] = put.Type + "|" + put.ContentType
	}
	if roles["stdout.jsonl"] != "raw-provider-output|application/x-ndjson" || roles["stderr.txt"] != "raw-provider-output|text/plain" || roles["result.json"] != "normalized-result|application/json" {
		t.Fatalf("%s artifact roles=%#v", name, roles)
	}
	for _, artifact := range store.artifacts {
		if artifact.StorageLocation == "memory://stdout.jsonl" && (store.tool.StdoutArtifactID == nil || *store.tool.StdoutArtifactID != artifact.ID) {
			t.Fatalf("%s stdout pointer mismatch", name)
		}
		if artifact.StorageLocation == "memory://stderr.txt" && (store.tool.StderrArtifactID == nil || *store.tool.StderrArtifactID != artifact.ID) {
			t.Fatalf("%s stderr pointer mismatch", name)
		}
		if artifact.StorageLocation == "memory://result.json" {
			for _, id := range store.result.ArtifactIDs {
				if id == artifact.ID {
					return
				}
			}
			t.Fatalf("%s normalized result artifact not attached to action result", name)
		}
	}
}
