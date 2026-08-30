package execution

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/normalize"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	commandprovider "github.com/tobiasGuta/Reconductor/internal/providers/command"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
)

var errFakeExit = errors.New("exit status 1")

type failingRunner struct{}

func (failingRunner) Run(context.Context, string, []string, []byte) ([]byte, []byte, int, error) {
	return []byte(`{"partial":true}` + "\n"), []byte("password=sensitive-test-value\nresolver configuration failed\n"), 1, errFakeExit
}
func (failingRunner) Version(context.Context, string, []string) (string, error) { return "test-1", nil }

type capturedStore struct {
	called         bool
	step           domain.StepRun
	tool           *domain.ToolRun
	artifacts      []domain.Artifact
	result         domain.ActionResult
	admission      *capability.ResultAdmissionProvenance
	err            error
	previous       []string
	loadedFor      string
	historyLoads   int
	effective      json.RawMessage
	effectiveFound bool
	effectiveErr   error
	effectiveLoads int
	effectiveSaves int
	policyID       domain.ID
	startID        domain.ID
	start          capability.ProviderInvocationStartRecord
	terminal       capability.ProviderInvocationTerminalRecord
	startErr       error
	terminalErr    error
}

func (s *capturedStore) RecordPolicyDecision(context.Context, capability.PolicyDecisionRecord) (domain.ID, error) {
	if s.policyID == "" {
		s.policyID = domain.NewID()
	}
	return s.policyID, nil
}

func (s *capturedStore) RecordProviderInvocationStarted(_ context.Context, record capability.ProviderInvocationStartRecord) (domain.ID, error) {
	s.start = record
	if s.startErr != nil {
		return "", s.startErr
	}
	if s.startID == "" {
		s.startID = domain.NewID()
	}
	return s.startID, nil
}

func (s *capturedStore) RecordProviderInvocationTerminal(_ context.Context, record capability.ProviderInvocationTerminalRecord) error {
	s.terminal = record
	return s.terminalErr
}

func (s *capturedStore) PreviousObservationValues(_ context.Context, _ domain.ID, _ domain.ID, capabilityName string) ([]string, error) {
	s.loadedFor = capabilityName
	s.historyLoads++
	return append([]string(nil), s.previous...), nil
}

func (s *capturedStore) LoadEffectiveStepInput(context.Context, domain.ID, domain.ActionRequest) (json.RawMessage, bool, error) {
	s.effectiveLoads++
	return append(json.RawMessage(nil), s.effective...), s.effectiveFound, s.effectiveErr
}

func (s *capturedStore) PersistEffectiveStepInput(_ context.Context, _ domain.ID, _ domain.ActionRequest, input json.RawMessage) (json.RawMessage, error) {
	if s.effectiveErr != nil {
		return nil, s.effectiveErr
	}
	s.effectiveSaves++
	s.effective = append(json.RawMessage(nil), input...)
	s.effectiveFound = true
	return append(json.RawMessage(nil), input...), nil
}

func TestHistoricalRecordsPreserveStructuredEvidenceAndUpgradeLegacyValues(t *testing.T) {
	records, err := historicalRecords([]string{
		`https://x.test/plain-https`,
		`http://x.test/plain-http`,
		`{"provider":"httpx","kind":"url","target":"https://x.test/api","status_code":200,"fields":{"tech":["go"]}}`,
		`{"value":"https://x.test/legacy"}`,
		`{"url":"https://x.test/old-httpx","status_code":403,"tech":["Go"]}`,
		`{"input":"https://x.test/input","status_code":204}`,
		`{"host":"x.test","scheme":"https","status_code":302}`,
	})
	if err != nil || len(records) != 7 {
		t.Fatalf("records=%#v err=%v", records, err)
	}
	plainHTTPS := records[0].(map[string]any)
	if plainHTTPS["provider"] != "httpx" || plainHTTPS["kind"] != "url" || plainHTTPS["target"] != "https://x.test/plain-https" {
		t.Fatalf("plain HTTPS observation was not upgraded: %#v", plainHTTPS)
	}
	plainHTTP := records[1].(map[string]any)
	if plainHTTP["target"] != "http://x.test/plain-http" {
		t.Fatalf("plain HTTP observation was not upgraded: %#v", plainHTTP)
	}
	structured := records[2].(map[string]any)
	if structured["provider"] != "httpx" || structured["status_code"] != json.Number("200") {
		t.Fatalf("structured evidence was lost: %#v", structured)
	}
	legacy := records[3].(map[string]any)
	if legacy["provider"] != "httpx" || legacy["target"] != "https://x.test/legacy" {
		t.Fatalf("legacy observation was not upgraded: %#v", legacy)
	}
	oldHTTPX := records[4].(map[string]any)
	if oldHTTPX["target"] != "https://x.test/old-httpx" || oldHTTPX["status_code"] != json.Number("403") {
		t.Fatalf("legacy HTTPX evidence was not upgraded: %#v", oldHTTPX)
	}
	input := records[5].(map[string]any)
	if input["target"] != "https://x.test/input" || input["status_code"] != json.Number("204") {
		t.Fatalf("legacy input evidence was not upgraded: %#v", input)
	}
	host := records[6].(map[string]any)
	if host["target"] != "https://x.test/" || host["status_code"] != json.Number("302") {
		t.Fatalf("legacy host evidence was not upgraded: %#v", host)
	}
}

func TestHistoricalRecordsPreserveNormalizedTargetRecords(t *testing.T) {
	records, err := historicalRecords([]string{`{"provider":"httpx","kind":"url","target":"HTTPS://X.Test:443/path/../api?b=2&a=1","host":"x.test","status_code":201,"technologies":["Go"],"fields":{"content_type":"application/json"}}`})
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%#v err=%v", records, err)
	}
	record := records[0].(map[string]any)
	if record["provider"] != "httpx" || record["kind"] != "url" || record["target"] != "https://x.test/api?a=1&b=2" || record["status_code"] != json.Number("201") {
		t.Fatalf("normalized record evidence was not preserved: %#v", record)
	}
}

func TestHistoricalRecordsRejectMalformedInputs(t *testing.T) {
	tests := []string{
		`not a url`,
		`ftp://x.test/`,
		`{"unexpected":true}`,
		`{"value":"not a url"}`,
		`{"target":"https://x.test/","kind":"host"}`,
		`{"url":`,
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if _, err := historicalRecords([]string{raw}); err == nil {
				t.Fatal("invalid historical observation was accepted")
			}
		})
	}
}

type inputCaptureCapability struct {
	input json.RawMessage
}

func (*inputCaptureCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "classify.endpoint", Version: "3", Risk: policy.Passive, RetrySafe: true, Idempotent: true}
}
func (*inputCaptureCapability) Validate(context.Context, capability.Request) error { return nil }
func (c *inputCaptureCapability) Execute(_ context.Context, req capability.Request) (capability.Result, error) {
	c.input = append(json.RawMessage(nil), req.Action.Input...)
	return capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Output: json.RawMessage(`{"endpoints":[],"classifications":[],"interesting_endpoints":[],"relationships":[]}`)}}, nil
}

type spoofedToolProvenanceCapability struct{ bogusAttemptID domain.ID }

func (*spoofedToolProvenanceCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "test.spoofed-tool-provenance", Version: "1", Risk: policy.Low}
}
func (*spoofedToolProvenanceCapability) Validate(context.Context, capability.Request) error {
	return nil
}
func (c *spoofedToolProvenanceCapability) Execute(_ context.Context, req capability.Request) (capability.Result, error) {
	now := time.Now().UTC()
	return capability.Result{
		Action: domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded"},
		ToolRun: &domain.ToolRun{
			ID:                domain.NewID(),
			StepRunID:         req.Action.StepRunID,
			Capability:        req.Action.Capability,
			Provider:          "spoofing-provider",
			StartedAt:         now,
			ProviderAttemptID: &c.bogusAttemptID,
		},
	}, nil
}

func TestExecutionOverwritesProviderSuppliedToolRunAttemptIdentity(t *testing.T) {
	registry := capability.NewRegistry()
	bogusAttemptID := domain.NewID()
	provider := &spoofedToolProvenanceCapability{bogusAttemptID: bogusAttemptID}
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	store := &capturedStore{}
	req := capability.Request{
		Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: provider.Manifest().Name, Input: json.RawMessage(`{}`)},
		Policy: policy.Policy{AllowedCapabilities: []string{provider.Manifest().Name}},
		Scope:  allowedScope{},
	}
	result, err := (Service{Registry: registry, Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderAttemptID == nil || store.tool == nil || store.tool.ProviderAttemptID == nil || *store.tool.ProviderAttemptID != *result.ProviderAttemptID || *store.tool.ProviderAttemptID != store.startID || *store.tool.ProviderAttemptID == bogusAttemptID {
		t.Fatalf("tool provenance was not reclaimed: result=%#v tool=%#v start=%s bogus=%s", result, store.tool, store.startID, bogusAttemptID)
	}
	if store.admission == nil || store.admission.ProviderAttemptID != store.startID || store.admission.ActionRequestID != req.Action.ID || store.admission.ExecutionAuthorizationEventID != store.policyID || store.admission.Provider != provider.Manifest().Name || store.tool.Provider != provider.Manifest().Name || store.result.RequestID != req.Action.ID {
		t.Fatalf("exact admission metadata was not delivered to Store: admission=%#v tool=%#v result=%#v", store.admission, store.tool, store.result)
	}
}

func TestClassifyExecutionLoadsPriorProbeEvidence(t *testing.T) {
	registry := capability.NewRegistry()
	classifier := &inputCaptureCapability{}
	if err := registry.Register(classifier); err != nil {
		t.Fatal(err)
	}
	store := &capturedStore{previous: []string{
		`{"provider":"httpx","kind":"url","target":"https://x.test/api","status_code":401,"fields":{"content_type":"application/json"}}`,
	}}
	input := json.RawMessage(`{"active":[],"passive":[],"http_observations":[],"crawl_observations":[],"passive_observations":[],"historical_observations":[],"api_schema_endpoints":[],"target_plan_digest":"plan"}`)
	req := capability.Request{
		Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "classify.endpoint", Input: input},
		Policy: policy.Policy{AllowedCapabilities: []string{"classify.endpoint"}},
		Scope:  allowedScope{},
	}
	result, err := (Service{Registry: registry, Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var captured struct {
		History []map[string]any `json:"historical_observations"`
	}
	if err := json.Unmarshal(classifier.input, &captured); err != nil {
		t.Fatal(err)
	}
	if store.loadedFor != "probe.http" || len(captured.History) != 1 || captured.History[0]["status_code"] != float64(401) {
		t.Fatalf("loaded_for=%q input=%s", store.loadedFor, classifier.input)
	}
	if store.effectiveSaves != 1 || string(store.effective) != string(classifier.input) || string(result.EffectiveInput) != string(classifier.input) {
		t.Fatalf("effective input was not frozen before execution: saves=%d persisted=%s provider=%s result=%s", store.effectiveSaves, store.effective, classifier.input, result.EffectiveInput)
	}
	if store.tool == nil || store.tool.ProviderAttemptID == nil || *store.tool.ProviderAttemptID != store.startID || store.tool.Provider != "classify.endpoint" || store.admission == nil || store.admission.Provider != "classify.endpoint" {
		t.Fatalf("platform-synthesized provider ToolRun lost attempt identity: tool=%#v start=%s", store.tool, store.startID)
	}
}

func TestClassifyExecutionReusesFrozenHistoricalEnrichmentAcrossRetry(t *testing.T) {
	registry := capability.NewRegistry()
	classifier := &inputCaptureCapability{}
	if err := registry.Register(classifier); err != nil {
		t.Fatal(err)
	}
	store := &capturedStore{previous: []string{`{"provider":"httpx","kind":"url","target":"https://first.test/","status_code":200}`}}
	programID, taskID, runID, stepID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	input := json.RawMessage(`{"active":[],"passive":[],"http_observations":[],"crawl_observations":[],"passive_observations":[],"historical_observations":[],"api_schema_endpoints":[],"target_plan_digest":"plan"}`)
	request := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, Capability: "classify.endpoint", Input: input, IdempotencyKey: "frozen-history", StepAttempt: 1}, Policy: policy.Policy{AllowedCapabilities: []string{"classify.endpoint"}}, Scope: allowedScope{}}
	service := Service{Registry: registry, Store: store, Artifacts: &capturedArtifacts{}, ProgramID: programID}
	if _, err := service.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	first := append(json.RawMessage(nil), classifier.input...)
	if store.historyLoads != 1 || store.effectiveSaves != 1 {
		t.Fatalf("first attempt history_loads=%d effective_saves=%d", store.historyLoads, store.effectiveSaves)
	}

	store.previous = []string{`{"provider":"httpx","kind":"url","target":"https://newer.test/","status_code":500}`}
	request.Action.ID = domain.NewID()
	request.Action.StepAttempt = 2
	request.Action.Input = input
	if _, err := service.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if store.historyLoads != 1 || store.effectiveSaves != 2 || string(classifier.input) != string(first) {
		t.Fatalf("retry rematerialized history: history_loads=%d effective_saves=%d first=%s retry=%s", store.historyLoads, store.effectiveSaves, first, classifier.input)
	}
}

func TestClassifyExecutionPreservesExactSourceNumbersThroughEnrichment(t *testing.T) {
	cfg, err := config.LoadWith(func(key string) string {
		if key == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	programID := domain.NewID()
	attemptID := domain.NewID()
	store := &capturedStore{startID: attemptID}
	batch := provideroutput.Parse("httpx", []string{`{"url":"https://exact.example.test/api/users/123","status_code":200,"meta":{"large":9007199254740993,"decimal":0.10000000000000001}}`})
	if len(batch.Records) != 1 || len(batch.Warnings) != 0 {
		t.Fatalf("provider records=%#v warnings=%#v", batch.Records, batch.Warnings)
	}
	sources, err := normalize.BuildProbeHTTPSourceRecords(string(programID), string(attemptID), batch.Records, normalize.RequestSemantics{
		Method:      normalize.ValueSemantics{State: normalize.ValueDefaulted, Value: executionString("GET")},
		ContentType: normalize.ValueSemantics{State: normalize.ValueUnknown},
	})
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string]any{
		"active":                  []string{},
		"passive":                 []string{},
		"http_observations":       batch.Records,
		"http_source_records":     sources,
		"crawl_observations":      []provideroutput.Record{},
		"passive_observations":    []provideroutput.Record{},
		"historical_observations": []provideroutput.Record{},
		"api_schema_endpoints":    []string{},
		"target_plan_digest":      "plan",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := capability.Request{
		Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "classify.endpoint", Input: input},
		Policy: policy.Policy{AllowedCapabilities: []string{"classify.endpoint"}},
		Scope:  allowedScope{},
	}
	result, err := (Service{Registry: providers.Registry(cfg), Store: store, Artifacts: &capturedArtifacts{}, ProgramID: programID}).Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var output struct {
		SourceDerivations []normalize.SourceDerivation `json:"source_derivations"`
	}
	if err := json.Unmarshal(result.Action.Output, &output); err != nil {
		t.Fatal(err)
	}
	if len(output.SourceDerivations) != 1 || output.SourceDerivations[0].SourceLocator != sources[0].SourceLocator {
		t.Fatalf("source verification did not survive production enrichment: output=%s", result.Action.Output)
	}
}

func executionString(value string) *string { return &value }

func TestClassifyExecutionConvertsMixedPriorProbeValues(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &capturedStore{previous: []string{
		`https://x.test/plain`,
		`http://x.test/plain-http`,
		`{"value":"https://x.test/legacy"}`,
		`{"url":"https://x.test/old-httpx","status_code":403,"tech":["Go"]}`,
		`{"provider":"httpx","kind":"url","target":"https://x.test/api","status_code":401,"fields":{"content_type":"application/json"}}`,
	}}
	input := json.RawMessage(`{"active":[],"passive":[],"http_observations":[],"crawl_observations":[],"passive_observations":[],"historical_observations":[],"api_schema_endpoints":[],"target_plan_digest":"plan"}`)
	req := capability.Request{
		Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "classify.endpoint", Input: input},
		Policy: policy.Policy{AllowedCapabilities: []string{"classify.endpoint"}},
		Scope:  allowedScope{},
	}
	result, err := (Service{Registry: providers.Registry(cfg), Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if store.loadedFor != "probe.http" || result.Action.Status != "succeeded" {
		t.Fatalf("historical probe values were not injected successfully: loaded_for=%q result=%#v", store.loadedFor, result.Action)
	}
}

func TestCompareAssetsExecutionLoadsPriorProbeValues(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &capturedStore{previous: []string{`{"value":"https://example.test/"}`}}
	input := json.RawMessage(`{"current":["https://example.test/"],"previous":[],"coverage_complete":true,"target_plan_digest":"plan"}`)
	req := capability.Request{
		Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "compare.assets", Input: input},
		Policy: policy.Policy{AllowedCapabilities: []string{"compare.assets"}},
		Scope:  allowedScope{},
	}
	result, err := (Service{Registry: providers.Registry(cfg), Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if store.loadedFor != "probe.http" {
		t.Fatalf("historical probe values were not loaded: %q", store.loadedFor)
	}
	var output struct {
		NewOrChanged []string `json:"new_or_changed"`
		Removed      []string `json:"removed"`
	}
	if err := json.Unmarshal(result.Action.Output, &output); err != nil {
		t.Fatal(err)
	}
	if len(output.NewOrChanged) != 0 || len(output.Removed) != 0 {
		t.Fatalf("loaded historical value did not match current asset: %s", result.Action.Output)
	}
}

func TestCompareAssetsExecutionEstablishesFirstRunBaseline(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &capturedStore{}
	const target = "http://127.0.0.1:33000/"
	input := json.RawMessage(`{"current":[{"provider":"httpx","kind":"url","target":"http://127.0.0.1:33000/","host":"127.0.0.1","port":33000,"status_code":200}],"previous":[],"coverage_complete":true,"target_plan_digest":"plan"}`)
	req := capability.Request{
		Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "compare.assets", Input: input},
		Policy: policy.Policy{AllowedCapabilities: []string{"compare.assets"}},
		Scope:  allowedScope{},
	}
	result, err := (Service{Registry: providers.Registry(cfg), Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if store.loadedFor != "probe.http" {
		t.Fatalf("historical probe values were not loaded: %q", store.loadedFor)
	}
	var output struct {
		NewOrChanged []string `json:"new_or_changed"`
		ScanTargets  []string `json:"scan_targets"`
		Removed      []string `json:"removed"`
	}
	if err := json.Unmarshal(result.Action.Output, &output); err != nil {
		t.Fatal(err)
	}
	if len(output.NewOrChanged) != 1 || output.NewOrChanged[0] != target {
		t.Fatalf("first-run asset was not new: %s", result.Action.Output)
	}
	if len(output.ScanTargets) != 1 || output.ScanTargets[0] != target {
		t.Fatalf("first-run scan targets=%q want=%q", output.ScanTargets, target)
	}
	if len(output.Removed) != 0 {
		t.Fatalf("first-run baseline fabricated removals: %s", result.Action.Output)
	}
}

func TestCompareAssetsExecutionDoesNotReplaceInvalidPreviousInput(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"missing", `{"current":[],"coverage_complete":true,"target_plan_digest":"plan"}`, `field "previous" is required and cannot be null`},
		{"null", `{"current":[],"previous":null,"coverage_complete":true,"target_plan_digest":"plan"}`, `field "previous" is required and cannot be null`},
		{"malformed non-null", `{"current":[],"previous":[42],"coverage_complete":true,"target_plan_digest":"plan"}`, "cannot unmarshal number"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &capturedStore{previous: []string{"https://history.example.test/"}}
			req := capability.Request{
				Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "compare.assets", Input: json.RawMessage(test.raw)},
				Policy: policy.Policy{AllowedCapabilities: []string{"compare.assets"}},
				Scope:  allowedScope{},
			}
			_, err := (Service{Registry: providers.Registry(cfg), Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(context.Background(), req)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v want containing %q", err, test.want)
			}
			if store.loadedFor != "" {
				t.Fatalf("invalid previous input was silently replaced from %q history", store.loadedFor)
			}
		})
	}
}

func (s *capturedStore) PersistResult(_ context.Context, _ domain.ID, step domain.StepRun, tool *domain.ToolRun, artifacts []domain.Artifact, result domain.ActionResult, admission *capability.ResultAdmissionProvenance) error {
	s.called, s.step, s.tool, s.artifacts, s.result = true, step, tool, append([]domain.Artifact(nil), artifacts...), result
	s.admission = admission
	return s.err
}

func TestFailedProviderAndPersistenceErrorsAreBothPreserved(t *testing.T) {
	registry := capability.NewRegistry()
	provider := commandprovider.New(commandprovider.Definition{Name: "probe.http", Provider: "fake-httpx", Executable: "fake-httpx", Version: "1", Risk: policy.Low, BuildArgs: func(i commandprovider.Input, _ policy.Policy) ([]string, error) {
		return []string{"-u", i.Targets[0]}, nil
	}}, failingRunner{}, redaction.New())
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	persistCause := errors.New("database unavailable")
	store := &capturedStore{err: persistCause}
	input, _ := json.Marshal(commandprovider.Input{Targets: []string{"https://local.example.test/"}})
	req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "probe.http", Input: input}, Policy: policy.Policy{AllowedCapabilities: []string{"probe.http"}}, Scope: allowedScope{}}
	_, err := (Service{Registry: registry, Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(context.Background(), req)
	if !errors.Is(err, errFakeExit) || !errors.Is(err, persistCause) {
		t.Fatalf("execution and persistence causes were not preserved: %v", err)
	}
}

type capturedArtifacts struct{ requests []artifact.PutRequest }

func (s *capturedArtifacts) Put(_ context.Context, req artifact.PutRequest) (domain.Artifact, error) {
	s.requests = append(s.requests, req)
	return domain.Artifact{ID: domain.NewID(), TaskID: req.TaskID, WorkflowRunID: req.WorkflowRunID, StepRunID: req.StepRunID, ToolRunID: req.ToolRunID, Type: req.Type, ContentType: req.ContentType, Size: int64(len(req.Data)), CreatedAt: time.Now().UTC()}, nil
}

type allowedScope struct{}

func (allowedScope) Allows(string) bool { return true }

func TestFailedProviderAttemptPersistsToolStepArtifactsAndOriginalError(t *testing.T) {
	registry := capability.NewRegistry()
	provider := commandprovider.New(commandprovider.Definition{Name: "probe.http", Provider: "fake-httpx", Executable: "fake-httpx", Version: "1", Risk: policy.Low, BuildArgs: func(i commandprovider.Input, _ policy.Policy) ([]string, error) {
		return []string{"-u", i.Targets[0]}, nil
	}}, failingRunner{}, redaction.New())
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	store, artifacts := &capturedStore{}, &capturedArtifacts{}
	programID, taskID, runID, stepID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	input, _ := json.Marshal(commandprovider.Input{Targets: []string{"https://local.example.test/"}})
	req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, Capability: "probe.http", Input: input, IdempotencyKey: "failure-test"}, Policy: policy.Policy{AllowedCapabilities: []string{"probe.http"}, ArtifactRetention: 24 * time.Hour}, Scope: allowedScope{}}
	result, err := (Service{Registry: registry, Store: store, Artifacts: artifacts, ProgramID: programID}).Execute(context.Background(), req)
	if err == nil || !errors.Is(err, errFakeExit) {
		t.Fatalf("original error was not preserved: %v", err)
	}
	if !strings.Contains(err.Error(), "resolver configuration failed") {
		t.Fatalf("diagnostic missing: %v", err)
	}
	if !store.called || store.step.Status != domain.StepFailed || store.step.ErrorClassification == "" {
		t.Fatalf("failed step not persisted: %#v", store.step)
	}
	if store.tool == nil || store.tool.ExitCode == nil || *store.tool.ExitCode != 1 || store.tool.StepRunID != stepID {
		t.Fatalf("failed tool not persisted: %#v", store.tool)
	}
	if store.tool.ProviderAttemptID == nil || *store.tool.ProviderAttemptID != store.startID {
		t.Fatalf("provider-supplied ToolRun lost attempt identity: tool=%#v start=%s", store.tool, store.startID)
	}
	if store.result.Status != "failed" || result.Action.Error == nil {
		t.Fatalf("failed action result not persisted: %#v", store.result)
	}
	var stderrSeen, normalizedSeen bool
	for _, req := range artifacts.requests {
		if req.ProgramID != programID || req.TaskID != taskID || req.WorkflowRunID != runID || req.StepRunID != stepID || req.ToolRunID != store.tool.ID {
			t.Fatalf("incomplete artifact lineage: %#v", req)
		}
		if req.Retention != 24*time.Hour {
			t.Fatalf("artifact retention=%s", req.Retention)
		}
		switch req.Name {
		case "stderr.txt":
			stderrSeen = true
			if strings.Contains(string(req.Data), "sensitive-test-value") || !strings.Contains(string(req.Data), "<redacted>") {
				t.Fatalf("stderr was not redacted: %q", req.Data)
			}
		case "result.json":
			normalizedSeen = true
		}
	}
	if !stderrSeen || !normalizedSeen || len(store.artifacts) < 2 {
		t.Fatalf("failure artifacts missing: requests=%#v persisted=%#v", artifacts.requests, store.artifacts)
	}
}

type contextErrorCapability struct {
	err            error
	waitForContext bool
	started        chan struct{}
	calls          int
}

func (*contextErrorCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "context.error", Version: "1", Risk: policy.Low}
}

func (*contextErrorCapability) Validate(context.Context, capability.Request) error { return nil }

func (c *contextErrorCapability) Execute(ctx context.Context, _ capability.Request) (capability.Result, error) {
	c.calls++
	if c.started != nil {
		close(c.started)
	}
	if c.waitForContext {
		<-ctx.Done()
		return capability.Result{}, ctx.Err()
	}
	return capability.Result{}, c.err
}

func executionContextErrorRequest() capability.Request {
	return capability.Request{
		Action: domain.ActionRequest{
			ID:             domain.NewID(),
			TaskID:         domain.NewID(),
			WorkflowRunID:  domain.NewID(),
			StepRunID:      domain.NewID(),
			Capability:     "context.error",
			Input:          json.RawMessage(`{}`),
			IdempotencyKey: "context-error",
			StepAttempt:    1,
		},
		Policy: policy.Policy{AllowedCapabilities: []string{"context.error"}},
		Scope:  allowedScope{},
	}
}

func TestOwningContextCancellationPersistsCancelledResult(t *testing.T) {
	registry := capability.NewRegistry()
	provider := &contextErrorCapability{waitForContext: true, started: make(chan struct{})}
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	store := &capturedStore{}
	service := Service{Registry: registry, Store: store, ProgramID: domain.NewID()}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	type executionOutcome struct {
		result capability.Result
		err    error
	}
	completed := make(chan executionOutcome, 1)
	go func() {
		result, err := service.Execute(ctx, executionContextErrorRequest())
		completed <- executionOutcome{result: result, err: err}
	}()
	<-provider.started
	cancel()
	outcome := <-completed

	if !errors.Is(outcome.err, context.Canceled) || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("execution error=%v context error=%v", outcome.err, ctx.Err())
	}
	if provider.calls != 1 || !store.called || store.step.Status != domain.StepCancelled || store.step.CompletedAt == nil {
		t.Fatalf("provider calls=%d persisted step=%#v", provider.calls, store.step)
	}
	if outcome.result.Action.Status != "cancelled" || outcome.result.Action.Error == nil || outcome.result.Action.Error.Classification != "cancelled" || store.result.Status != "cancelled" || store.step.ErrorClassification != "cancelled" {
		t.Fatalf("result=%#v persisted_result=%#v step=%#v", outcome.result.Action, store.result, store.step)
	}
	if store.terminal.Outcome != capability.ProviderInvocationCancelled || store.admission == nil || store.admission.StepAttempt != 1 || store.admission.ProviderAttemptID != store.startID || store.tool == nil || store.tool.ProviderAttemptID == nil || *store.tool.ProviderAttemptID != store.startID {
		t.Fatalf("terminal=%#v admission=%#v tool=%#v start=%s", store.terminal, store.admission, store.tool, store.startID)
	}
}

func TestProviderOriginatedContextCanceledWithActiveCallerRemainsFailure(t *testing.T) {
	registry := capability.NewRegistry()
	provider := &contextErrorCapability{err: context.Canceled}
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	store := &capturedStore{}
	ctx := context.Background()
	result, err := (Service{Registry: registry, Store: store, ProgramID: domain.NewID()}).Execute(ctx, executionContextErrorRequest())
	if !errors.Is(err, context.Canceled) || ctx.Err() != nil {
		t.Fatalf("provider error=%v caller error=%v", err, ctx.Err())
	}
	if provider.calls != 1 || store.step.Status != domain.StepFailed || store.step.CompletedAt == nil || result.Action.Status != "failed" || result.Action.Error == nil || result.Action.Error.Classification != "execution" {
		t.Fatalf("provider calls=%d result=%#v step=%#v", provider.calls, result.Action, store.step)
	}
	if store.terminal.Outcome != capability.ProviderInvocationCancelled {
		t.Fatalf("provider terminal outcome=%s", store.terminal.Outcome)
	}
}

func TestExecutionDeadlineExceededRemainsFailure(t *testing.T) {
	registry := capability.NewRegistry()
	provider := &contextErrorCapability{waitForContext: true}
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	store := &capturedStore{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	result, err := (Service{Registry: registry, Store: store, ProgramID: domain.NewID()}).Execute(ctx, executionContextErrorRequest())
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("execution error=%v context error=%v", err, ctx.Err())
	}
	if provider.calls != 1 || store.step.Status != domain.StepFailed || store.step.CompletedAt == nil || result.Action.Status != "failed" || result.Action.Error == nil || result.Action.Error.Classification != "execution" {
		t.Fatalf("provider calls=%d result=%#v step=%#v", provider.calls, result.Action, store.step)
	}
}

type retryableResultCapability struct{}

func (retryableResultCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "retryable.result", Version: "1", Risk: policy.Low, RetrySafe: true, Idempotent: true}
}

func (retryableResultCapability) Validate(context.Context, capability.Request) error { return nil }

func (retryableResultCapability) Execute(_ context.Context, req capability.Request) (capability.Result, error) {
	return capability.Result{Action: domain.ActionResult{
		RequestID: req.Action.ID,
		Status:    "failed",
		Summary:   "temporary provider failure",
		Error:     &domain.StructuredError{Classification: "provider_error", Message: "retry later", Retryable: true},
	}}, errors.New("temporary provider failure")
}

func TestRetryableServiceResultIsNotCompleted(t *testing.T) {
	registry := capability.NewRegistry()
	if err := registry.Register(retryableResultCapability{}); err != nil {
		t.Fatal(err)
	}
	store := &capturedStore{}
	req := capability.Request{
		Action: domain.ActionRequest{
			ID:             domain.NewID(),
			TaskID:         domain.NewID(),
			WorkflowRunID:  domain.NewID(),
			StepRunID:      domain.NewID(),
			Capability:     "retryable.result",
			Input:          json.RawMessage(`{}`),
			IdempotencyKey: "retryable-result",
			StepAttempt:    2,
		},
		Policy: policy.Policy{AllowedCapabilities: []string{"retryable.result"}},
		Scope:  allowedScope{},
	}
	if _, err := (Service{Registry: registry, Store: store, ProgramID: domain.NewID()}).Execute(context.Background(), req); err == nil {
		t.Fatal("retryable provider failure was not returned")
	}
	if !store.called || store.step.Status != domain.StepRetryable || store.step.CompletedAt != nil {
		t.Fatalf("retryable step=%#v", store.step)
	}
	if store.admission == nil || store.admission.StepAttempt != 2 {
		t.Fatalf("retryable admission=%#v", store.admission)
	}
}

func TestNoProviderStartFailurePersistsPlatformToolWithoutAttempt(t *testing.T) {
	registry := capability.NewRegistry()
	provider := &inputCaptureCapability{}
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	startCause := errors.New("provider start unavailable")
	store := &capturedStore{startErr: startCause}
	req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "classify.endpoint", Input: json.RawMessage(`{"historical_observations":[]}`)}, Policy: policy.Policy{AllowedCapabilities: []string{"classify.endpoint"}}, Scope: allowedScope{}}
	result, err := (Service{Registry: registry, Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(context.Background(), req)
	if !errors.Is(err, startCause) {
		t.Fatalf("start failure not returned: %v", err)
	}
	if provider.input != nil {
		t.Fatalf("provider callback ran with input %s", provider.input)
	}
	if result.ProviderAttemptID != nil || result.AdmissionProvenance != nil || store.admission != nil || store.tool == nil || store.tool.ProviderAttemptID != nil || store.tool.Provider != "platform" || store.step.Status != domain.StepFailed {
		t.Fatalf("no-provider persistence result=%#v tool=%#v step=%#v", result, store.tool, store.step)
	}
}

func TestTerminalAuditDegradationDoesNotChangePersistedProviderSuccess(t *testing.T) {
	registry := capability.NewRegistry()
	provider := &inputCaptureCapability{}
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	terminalCause := errors.New("terminal audit unavailable")
	store := &capturedStore{terminalErr: terminalCause}
	req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "classify.endpoint", Input: json.RawMessage(`{"historical_observations":[]}`)}, Policy: policy.Policy{AllowedCapabilities: []string{"classify.endpoint"}}, Scope: allowedScope{}}
	result, err := (Service{Registry: registry, Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("terminal audit degradation changed provider success: %v", err)
	}
	if !errors.Is(result.TerminalAuditError, terminalCause) || result.ProviderAttemptID == nil || result.AdmissionProvenance == nil || store.admission == nil || store.admission.ProviderAttemptID != *result.ProviderAttemptID || store.step.Status != domain.StepSucceeded || store.result.Status != "succeeded" || store.tool.ProviderAttemptID == nil || *store.tool.ProviderAttemptID != *result.ProviderAttemptID {
		t.Fatalf("degraded result=%#v step=%#v persisted=%#v tool=%#v", result, store.step, store.result, store.tool)
	}
}

func TestOSRunnerAcceptanceDeliversDNSHostsAndPersistsFailedStderr(t *testing.T) {
	registry := capability.NewRegistry()
	provider := commandprovider.New(commandprovider.Definition{
		Name:       "resolve.dns",
		Provider:   "fake-dnsx",
		Executable: os.Args[0],
		Version:    "1",
		Risk:       policy.Low,
		BuildInvocation: func(commandprovider.Input, policy.Policy) (commandprovider.Invocation, error) {
			return commandprovider.Invocation{
				Args:  []string{"-test.run=^TestExecutionFakeExecutable$", "--", "dns-failure"},
				Stdin: []byte("one.example.test\ntwo.example.test\n"),
			}, nil
		},
	}, commandprovider.OSRunner{}, redaction.New())
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}

	store, artifacts := &capturedStore{}, &capturedArtifacts{}
	programID, taskID, runID, stepID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	input, _ := json.Marshal(commandprovider.Input{Targets: []string{"https://one.example.test/", "https://two.example.test/path"}})
	req := capability.Request{
		Action: domain.ActionRequest{
			ID:             domain.NewID(),
			TaskID:         taskID,
			WorkflowRunID:  runID,
			StepRunID:      stepID,
			Capability:     "resolve.dns",
			Input:          input,
			IdempotencyKey: "fake-executable-failure",
		},
		Policy: policy.Policy{AllowedCapabilities: []string{"resolve.dns"}},
		Scope:  allowedScope{},
	}

	_, err := (Service{Registry: registry, Store: store, Artifacts: artifacts, ProgramID: programID}).Execute(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "fake DNS failure") {
		t.Fatalf("expected fake executable failure diagnostic, got %v", err)
	}
	if store.tool == nil || store.tool.ExitCode == nil || *store.tool.ExitCode != 9 {
		t.Fatalf("fake executable exit was not persisted: %#v", store.tool)
	}

	for _, put := range artifacts.requests {
		if put.Name != "stderr.txt" {
			continue
		}
		stderr := string(put.Data)
		if !strings.Contains(stderr, "received=one.example.test,two.example.test") {
			t.Fatalf("newline-delimited stdin did not reach fake executable: %q", stderr)
		}
		if strings.Contains(stderr, "acceptance-secret") || !strings.Contains(stderr, "<redacted>") {
			t.Fatalf("persisted stderr was not redacted: %q", stderr)
		}
		return
	}
	t.Fatal("stderr.txt was not persisted")
}

func TestExecutionFakeExecutable(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "dns-failure" {
		return
	}
	stdin, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(2)
	}
	hosts := strings.TrimSuffix(string(stdin), "\n")
	if hosts != "one.example.test\ntwo.example.test" {
		_, _ = os.Stderr.WriteString("unexpected stdin=" + hosts + "\n")
		os.Exit(3)
	}
	_, _ = os.Stdout.WriteString("{\"partial\":true}\n")
	_, _ = os.Stderr.WriteString("password=acceptance-secret\nreceived=" + strings.ReplaceAll(hosts, "\n", ",") + "\nfake DNS failure\n")
	os.Exit(9)
}
