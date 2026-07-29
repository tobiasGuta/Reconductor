package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/normalize"
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
		record, err := historicalRecord(value)
		if err != nil {
			return nil, fmt.Errorf("historical observation %d: %w", index, err)
		}
		out = append(out, record)
	}
	return out, nil
}

func historicalRecord(raw string) (map[string]any, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("empty observation")
	}
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		target, err := historicalHTTPURL(trimmed)
		if err != nil {
			return nil, err
		}
		return map[string]any{"provider": "httpx", "kind": "url", "target": target, "fields": map[string]any{"value": trimmed}}, nil
	}
	var item map[string]any
	if err := json.Unmarshal([]byte(trimmed), &item); err != nil {
		return nil, err
	}
	if target, _ := item["target"].(string); target != "" {
		normalizedTarget, err := historicalHTTPURL(target)
		if err != nil {
			return nil, err
		}
		item["target"] = normalizedTarget
		if provider, _ := item["provider"].(string); provider == "" {
			item["provider"] = "httpx"
		}
		if kind, _ := item["kind"].(string); kind == "" {
			item["kind"] = "url"
		} else if kind != "url" {
			return nil, fmt.Errorf("record kind %q is not a URL", kind)
		}
		return item, nil
	}
	legacy := firstHistoricalString(item, "value", "url", "input")
	if legacy == "" {
		legacy = historicalHostCandidate(item)
	}
	if legacy == "" {
		return nil, fmt.Errorf("has no target")
	}
	target, err := historicalHTTPURL(legacy)
	if err != nil {
		return nil, err
	}
	upgraded := map[string]any{"provider": "httpx", "kind": "url", "target": target, "fields": item}
	if status, ok := item["status_code"]; ok {
		upgraded["status_code"] = status
	}
	if technologies, ok := item["technologies"]; ok {
		upgraded["technologies"] = technologies
	} else if technologies, ok := item["tech"]; ok {
		upgraded["technologies"] = technologies
	}
	return upgraded, nil
}

func historicalHTTPURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	if parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", fmt.Errorf("record target must be an absolute HTTP URL")
	}
	return normalize.URL(trimmed)
}

func historicalHostCandidate(item map[string]any) string {
	host := firstHistoricalString(item, "host")
	if host == "" || strings.Contains(host, "://") {
		return host
	}
	scheme := firstHistoricalString(item, "scheme")
	if scheme == "" {
		return ""
	}
	return scheme + "://" + host
}

func firstHistoricalString(item map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := item[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}
