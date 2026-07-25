package worker

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
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
