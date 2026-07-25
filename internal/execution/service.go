package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type Service struct {
	Registry      *capability.Registry
	Store         ResultStore
	Artifacts     artifact.Storage
	ProgramID     domain.ID
	PolicyAuditor capability.PolicyDecisionRecorder
}
type ResultStore interface {
	PreviousObservationValues(context.Context, domain.ID, domain.ID, string) ([]string, error)
	PersistResult(context.Context, domain.ID, domain.StepRun, *domain.ToolRun, []domain.Artifact, domain.ActionResult) error
}

func (s Service) Execute(ctx context.Context, req capability.Request) (capability.Result, error) {
	req.ProgramID = s.ProgramID
	req.PolicyPhase = "execution"
	req.DecisionRecorder = s.PolicyAuditor
	if req.DecisionRecorder == nil {
		if recorder, ok := s.Store.(capability.PolicyDecisionRecorder); ok {
			req.DecisionRecorder = recorder
		}
	}
	if req.Action.Capability == "compare.assets" {
		if s.Store == nil {
			return capability.Result{}, fmt.Errorf("result store is required")
		}
		var input map[string]any
		if json.Unmarshal(req.Action.Input, &input) == nil {
			if previous, ok := input["previous"].([]any); !ok || len(previous) == 0 {
				values, loadErr := s.Store.PreviousObservationValues(ctx, s.ProgramID, req.Action.WorkflowRunID, "probe.http")
				if loadErr != nil {
					return capability.Result{}, loadErr
				}
				input["previous"] = values
				req.Action.Input, _ = json.Marshal(input)
			}
		}
	}
	if req.Action.Capability == "classify.endpoint" {
		if s.Store == nil {
			return capability.Result{}, fmt.Errorf("result store is required")
		}
		var input map[string]any
		if err := json.Unmarshal(req.Action.Input, &input); err == nil {
			if previous, ok := input["historical_observations"].([]any); !ok || len(previous) == 0 {
				values, loadErr := s.Store.PreviousObservationValues(ctx, s.ProgramID, req.Action.WorkflowRunID, "probe.http")
				if loadErr != nil {
					return capability.Result{}, loadErr
				}
				history, historyErr := historicalRecords(values)
				if historyErr != nil {
					return capability.Result{}, historyErr
				}
				input["historical_observations"] = history
				req.Action.Input, _ = json.Marshal(input)
			}
		}
	}
	result, executionErr := s.Registry.Execute(ctx, req)
	if executionErr != nil && result.Action.Error == nil {
		result.Action = domain.ActionResult{RequestID: req.Action.ID, Status: "failed", Summary: "capability execution failed", Error: &domain.StructuredError{Classification: "execution", Message: executionErr.Error(), Retryable: false}}
	}
	tool := result.ToolRun
	if tool == nil {
		now := time.Now().UTC()
		version := "1"
		if implementation, ok := s.Registry.Get(req.Action.Capability); ok {
			version = implementation.Manifest().Version
		}
		tool = &domain.ToolRun{ID: domain.NewID(), StepRunID: req.Action.StepRunID, Capability: req.Action.Capability, Provider: "platform", ToolVersion: version, SanitizedArguments: json.RawMessage(`{}`), ExecutionEnvironment: json.RawMessage(`{"kind":"in-process"}`), StartedAt: now, CompletedAt: &now}
	}
	var artifacts []domain.Artifact
	var persistenceErr error
	persistCtx := ctx
	persistCancel := func() {}
	if ctx.Err() != nil {
		persistCtx, persistCancel = context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	}
	defer persistCancel()
	for _, raw := range []struct {
		name, contentType string
		data              []byte
	}{{"stdout.jsonl", "application/x-ndjson", result.RawStdout}, {"stderr.txt", "text/plain", result.RawStderr}} {
		if len(raw.data) == 0 {
			continue
		}
		if s.Artifacts == nil {
			persistenceErr = errors.Join(persistenceErr, fmt.Errorf("persist %s: artifact storage is required", raw.name))
			continue
		}
		a, putErr := s.Artifacts.Put(persistCtx, artifact.PutRequest{ProgramID: s.ProgramID, TaskID: req.Action.TaskID, WorkflowRunID: req.Action.WorkflowRunID, StepRunID: req.Action.StepRunID, ToolRunID: tool.ID, Type: "raw-provider-output", ContentType: raw.contentType, Name: raw.name, Retention: req.Policy.ArtifactRetention, Data: raw.data})
		if putErr != nil {
			persistenceErr = errors.Join(persistenceErr, fmt.Errorf("persist %s: %w", raw.name, putErr))
			continue
		}
		artifacts = append(artifacts, a)
		tool.ArtifactIDs = append(tool.ArtifactIDs, a.ID)
		if raw.name == "stdout.jsonl" {
			tool.StdoutArtifactID = &a.ID
		}
		if raw.name == "stderr.txt" {
			tool.StderrArtifactID = &a.ID
		}
	}
	if len(result.Action.Output) > 0 {
		if s.Artifacts == nil {
			persistenceErr = errors.Join(persistenceErr, fmt.Errorf("persist result.json: artifact storage is required"))
		} else {
			a, putErr := s.Artifacts.Put(persistCtx, artifact.PutRequest{ProgramID: s.ProgramID, TaskID: req.Action.TaskID, WorkflowRunID: req.Action.WorkflowRunID, StepRunID: req.Action.StepRunID, ToolRunID: tool.ID, Type: "normalized-result", ContentType: "application/json", Name: "result.json", Retention: req.Policy.ArtifactRetention, Data: result.Action.Output})
			if putErr != nil {
				persistenceErr = errors.Join(persistenceErr, fmt.Errorf("persist result.json: %w", putErr))
			} else {
				artifacts = append(artifacts, a)
				tool.ArtifactIDs = append(tool.ArtifactIDs, a.ID)
				result.Action.ArtifactIDs = append(result.Action.ArtifactIDs, a.ID)
			}
		}
	}
	now := time.Now().UTC()
	step := domain.StepRun{ID: req.Action.StepRunID, WorkflowRunID: req.Action.WorkflowRunID, Capability: req.Action.Capability, Status: domain.StepSucceeded, Output: result.Action.Output, CompletedAt: &now, IdempotencyKey: req.Action.IdempotencyKey}
	if executionErr != nil {
		step.Status = domain.StepFailed
		if result.Action.Error != nil {
			step.ErrorClassification = result.Action.Error.Classification
			step.ErrorDetails = result.Action.Error.Message
			if result.Action.Error.Retryable {
				step.Status = domain.StepRetryable
			}
		}
	}
	if s.Store == nil {
		persistenceErr = errors.Join(persistenceErr, fmt.Errorf("result store is required"))
	} else if err := s.Store.PersistResult(persistCtx, s.ProgramID, step, tool, artifacts, result.Action); err != nil {
		persistenceErr = errors.Join(persistenceErr, err)
	}
	if persistenceErr != nil {
		return result, errors.Join(executionErr, fmt.Errorf("persist execution result: %w", persistenceErr))
	}
	return result, executionErr
}

func historicalRecords(values []string) ([]any, error) {
	out := make([]any, 0, len(values))
	for index, value := range values {
		var item map[string]any
		if err := json.Unmarshal([]byte(value), &item); err != nil {
			return nil, fmt.Errorf("historical observation %d: %w", index, err)
		}
		if target, _ := item["target"].(string); target != "" {
			if provider, _ := item["provider"].(string); provider == "" {
				item["provider"] = "httpx"
			}
			if kind, _ := item["kind"].(string); kind == "" {
				item["kind"] = "url"
			}
			out = append(out, item)
			continue
		}
		legacy := firstHistoricalString(item, "value", "url", "input")
		if legacy == "" {
			return nil, fmt.Errorf("historical observation %d has no target", index)
		}
		upgraded := map[string]any{"provider": "httpx", "kind": "url", "target": legacy, "fields": item}
		if status, ok := item["status_code"]; ok {
			upgraded["status_code"] = status
		}
		if technologies, ok := item["technologies"]; ok {
			upgraded["technologies"] = technologies
		} else if technologies, ok := item["tech"]; ok {
			upgraded["technologies"] = technologies
		}
		out = append(out, upgraded)
	}
	return out, nil
}

func firstHistoricalString(item map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := item[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}
