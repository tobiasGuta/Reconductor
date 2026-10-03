package execution

import (
	"bytes"
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
	"github.com/tobiasGuta/Reconductor/internal/resultadmission"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

var errFakeExit = errors.New("exit status 1")

type failingRunner struct{}

func (failingRunner) Run(context.Context, string, []string, []byte) ([]byte, []byte, int, error) {
	return []byte(`{"partial":true}` + "\n"), []byte("password=sensitive-test-value\nresolver configuration failed\n"), 1, errFakeExit
}
func (failingRunner) Version(context.Context, string, []string) (string, error) { return "test-1", nil }

type capturedStore struct {
	reservedCapacity   int64
	rejections         int
	rejectionErr       error
	rejectedOccurrence domain.ID
	called             bool
	persisted          bool
	publications       int
	step               domain.StepRun
	tool               *domain.ToolRun
	artifacts          []domain.Artifact
	result             domain.ActionResult
	admission          *capability.ResultAdmissionProvenance
	err                error
	previous           []string
	loadedFor          string
	historyLoads       int
	effective          json.RawMessage
	effectiveFound     bool
	effectiveErr       error
	effectiveLoads     int
	effectiveSaves     int
	policyID           domain.ID
	startID            domain.ID
	start              capability.ProviderInvocationStartRecord
	terminal           capability.ProviderInvocationTerminalRecord
	terminalEvents     int
	startErr           error
	terminalErr        error
	publishingErr      error
	publishingAt       int
	sealErr            error
	sealAt             int
	adoptErrors        []error
	adoptCalls         int
	terminalized       int
	terminalState      domain.PublicationState
	terminalizeErr     error
	recoveryRecords    []domain.PreparedSetRecord
	recoveryStates     []domain.PublicationState
	cleanedSets        []domain.ID
	cleanErrors        []error
}

func (s *capturedStore) AllocateProviderInvocation(_ context.Context, record capability.ProviderInvocationStartRecord, _ artifact.StoreIdentity) (capability.ProviderInvocationAdmission, error) {
	s.start = record
	if s.startErr != nil {
		return capability.ProviderInvocationAdmission{}, s.startErr
	}
	if s.startID == "" {
		s.startID = domain.NewID()
	}
	capacity := s.reservedCapacity
	if capacity == 0 {
		capacity = domain.PreparedSetOutputAuthorityMaxBytes
	}
	return capability.ProviderInvocationAdmission{ProviderAttemptID: s.startID, PreparedSetID: domain.NewID(), ManifestID: domain.NewID(), ReservedCapacityBytes: capacity}, nil
}

func (s *capturedStore) RejectPreparedEvidence(_ context.Context, _ domain.ID, _ domain.StepRun, compiled resultadmission.CompiledResult, admission capability.ResultAdmissionProvenance, request artifact.PreparedStageRequest, limit domain.ResultContractLimitV1) error {
	s.rejections++
	s.rejectedOccurrence = compiled.ResultOccurrenceID
	if compiled.PreparedSetID != admission.PreparedSetID || request.SetID != compiled.PreparedSetID || limit.Limit != uint64(admission.ReservedCapacityBytes) {
		return errors.New("rejection identity contradiction")
	}
	return s.rejectionErr
}

func TestOversizedEvidenceIsKnownNonadmissionBeforeStaging(t *testing.T) {
	store, artifacts := &capturedStore{reservedCapacity: 1024}, &capturedArtifacts{}
	result, err := executePublicationPipeline(t, store, artifacts, bytes.Repeat([]byte("x"), 8192))
	var capacity *artifact.PreparedCapacityError
	if !errors.As(err, &capacity) || domain.PersistenceUnresolved(err) {
		t.Fatalf("classification=%v", err)
	}
	if store.rejections != 1 || store.rejectedOccurrence != artifacts.compiled.ResultOccurrenceID || result.Envelope != nil || result.Action.Error == nil || result.Action.Error.Classification != "result_contract_limit" || result.Action.Error.Retryable {
		t.Fatalf("rejections=%d result=%#v", store.rejections, result.Action)
	}
	if len(artifacts.prepared) != 0 || len(artifacts.requests) != 0 || store.persisted || store.adoptCalls != 0 || store.publications != 0 {
		t.Fatal("oversized result staged or published")
	}
}

func TestOversizedRejectionFailureRemainsUnresolvedWithSameIdentity(t *testing.T) {
	for _, failure := range []error{errors.New("database unavailable"), &injectedCommitUnknown{operation: "nonadmission"}} {
		store, artifacts := &capturedStore{reservedCapacity: 1024, rejectionErr: failure}, &capturedArtifacts{}
		_, err := executePublicationPipeline(t, store, artifacts, bytes.Repeat([]byte("x"), 8192))
		if !domain.PersistenceUnresolved(err) || !errors.Is(err, failure) || store.rejections != 1 || store.rejectedOccurrence != artifacts.compiled.ResultOccurrenceID || artifacts.deleteCalls != 0 || store.adoptCalls != 0 {
			t.Fatalf("error=%v rejections=%d", err, store.rejections)
		}
	}
}

func (s *capturedStore) SealPreparedEvidence(_ context.Context, record resultadmission.PreparedSealRecord) error {
	s.terminalEvents++
	s.terminal = capability.ProviderInvocationTerminalRecord{ProviderAttemptID: record.Admission.ProviderAttemptID, Outcome: record.Outcome}
	return s.terminalErr
}

func (s *capturedStore) QuarantinePreparedEvidence(context.Context, domain.ID, string) error {
	return nil
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
	s.terminalEvents++
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

func (s *capturedStore) PersistResultWithArtifactPublication(ctx context.Context, _ domain.ID, step domain.StepRun, tool *domain.ToolRun, result *domain.ActionResult, admission *capability.ResultAdmissionProvenance, publish func(context.Context) ([]domain.Artifact, error)) error {
	s.called = true
	if s.err != nil {
		return s.err
	}
	var artifacts []domain.Artifact
	if publish != nil {
		s.publications++
		var err error
		artifacts, err = publish(ctx)
		if err != nil {
			return err
		}
	}
	s.persisted, s.step, s.tool, s.artifacts, s.result = true, step, tool, append([]domain.Artifact(nil), artifacts...), *result
	s.admission = admission
	return nil
}

func (s *capturedStore) PersistPreProviderFailure(_ context.Context, _ domain.ID, step domain.StepRun, summary string) error {
	s.called = true
	if s.err != nil {
		return s.err
	}
	s.persisted, s.step, s.tool = true, step, nil
	s.result = domain.ActionResult{Status: string(step.Status), Summary: summary, Error: &domain.StructuredError{Classification: step.ErrorClassification, Message: step.ErrorDetails}}
	return nil
}

func (s *capturedStore) ReserveCompiledResult(_ context.Context, _ domain.ID, _ domain.StepRun, _ resultadmission.CompiledResult, _ *capability.ResultAdmissionProvenance, _ artifact.StoreIdentity) error {
	s.called = true
	if s.err != nil {
		return s.err
	}
	s.publications++
	return nil
}

func (s *capturedStore) MarkCompiledArtifactPublishing(_ context.Context, _ resultadmission.CompiledResult, ordinal int) error {
	if s.publishingErr != nil && ordinal == s.publishingAt {
		return s.publishingErr
	}
	return nil
}
func (s *capturedStore) SealCompiledArtifact(_ context.Context, _ resultadmission.CompiledResult, ordinal int) error {
	if s.sealErr != nil && ordinal == s.sealAt {
		return s.sealErr
	}
	return nil
}
func (s *capturedStore) TerminalizeCompiledResult(_ context.Context, _ resultadmission.CompiledResult, state domain.PublicationState, _ string) error {
	s.terminalized++
	s.terminalState = state
	return s.terminalizeErr
}
func (s *capturedStore) AdoptCompiledResult(_ context.Context, _ domain.ID, step domain.StepRun, compiled resultadmission.CompiledResult, admission *capability.ResultAdmissionProvenance, _ time.Duration) error {
	s.adoptCalls++
	if len(s.adoptErrors) >= s.adoptCalls && s.adoptErrors[s.adoptCalls-1] != nil {
		return s.adoptErrors[s.adoptCalls-1]
	}
	step.Output = append(json.RawMessage(nil), compiled.EnvelopeJSON...)
	artifacts := make([]domain.Artifact, 0, len(compiled.Artifacts))
	for _, item := range compiled.Artifacts {
		storeID, key := item.Reference.ArtifactStoreID, item.Reference.StorageKey
		artifacts = append(artifacts, domain.Artifact{ID: item.Reference.ArtifactID, TaskID: s.start.TaskID, WorkflowRunID: step.WorkflowRunID, StepRunID: step.ID, ToolRunID: compiled.ToolRun.ID, Type: item.ArtifactType, ContentType: item.Reference.ContentType, Size: item.Reference.ContentSizeBytes, SHA256: item.Reference.ContentSHA256, AddressingVersion: 1, ArtifactStoreID: &storeID, StorageKey: &key})
	}
	semanticIDs := []domain.ID{compiled.Envelope.SemanticOutput.ArtifactID}
	s.persisted, s.step, s.artifacts, s.result = true, step, artifacts, domain.ActionResult{RequestID: compiled.Envelope.ActionRequestID, Status: string(compiled.Envelope.Status), Summary: compiled.Envelope.Summary, Output: compiled.EnvelopeJSON, ArtifactIDs: semanticIDs}
	tool := compiled.ToolRun
	s.tool = &tool
	s.admission = admission
	return nil
}

func (s *capturedStore) ListPreparedEvidence(context.Context, domain.ID, domain.ID, int) ([]domain.PreparedSetRecord, error) {
	return append([]domain.PreparedSetRecord(nil), s.recoveryRecords...), nil
}
func (s *capturedStore) MarkPreparedEvidenceCleaned(_ context.Context, setID domain.ID) error {
	s.cleanedSets = append(s.cleanedSets, setID)
	if len(s.cleanErrors) >= len(s.cleanedSets) {
		return s.cleanErrors[len(s.cleanedSets)-1]
	}
	return nil
}
func (s *capturedStore) CompiledPublicationStates(context.Context, resultadmission.CompiledResult) ([]domain.PublicationState, error) {
	return append([]domain.PublicationState(nil), s.recoveryStates...), nil
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
	artifacts := &capturedArtifacts{}
	input, _ := json.Marshal(commandprovider.Input{Targets: []string{"https://local.example.test/"}})
	req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "probe.http", Input: input}, Policy: policy.Policy{AllowedCapabilities: []string{"probe.http"}}, Scope: allowedScope{}}
	_, err := (Service{Registry: registry, Store: store, Artifacts: artifacts, ProgramID: domain.NewID()}).Execute(context.Background(), req)
	if !errors.Is(err, errFakeExit) || !errors.Is(err, persistCause) {
		t.Fatalf("execution and persistence causes were not preserved: %v", err)
	}
	if len(artifacts.requests) != 0 || store.persisted || store.publications != 0 {
		t.Fatalf("result-store denial published artifacts: puts=%d persisted=%v publications=%d", len(artifacts.requests), store.persisted, store.publications)
	}
}

func TestArtifactPublicationFailurePreventsResultAcceptance(t *testing.T) {
	registry := capability.NewRegistry()
	provider := commandprovider.New(commandprovider.Definition{Name: "probe.http", Provider: "fake-httpx", Executable: "fake-httpx", Version: "1", Risk: policy.Low, BuildArgs: func(i commandprovider.Input, _ policy.Policy) ([]string, error) {
		return []string{"-u", i.Targets[0]}, nil
	}}, failingRunner{}, redaction.New())
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	publicationCause := errors.New("artifact device unavailable")
	store := &capturedStore{}
	artifacts := &capturedArtifacts{err: publicationCause}
	input, _ := json.Marshal(commandprovider.Input{Targets: []string{"https://local.example.test/"}})
	req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "probe.http", Input: input}, Policy: policy.Policy{AllowedCapabilities: []string{"probe.http"}}, Scope: allowedScope{}}
	_, err := (Service{Registry: registry, Store: store, Artifacts: artifacts, ProgramID: domain.NewID()}).Execute(context.Background(), req)
	if !errors.Is(err, errFakeExit) || !errors.Is(err, publicationCause) {
		t.Fatalf("execution and publication causes were not preserved: %v", err)
	}
	if !store.called || store.persisted || store.publications != 1 || len(artifacts.requests) != 1 {
		t.Fatalf("publication failure was accepted: called=%v persisted=%v publications=%d puts=%d", store.called, store.persisted, store.publications, len(artifacts.requests))
	}
}

type capturedArtifacts struct {
	requests    []artifact.PutRequest
	err         error
	req         capability.Request
	compiled    resultadmission.CompiledResult
	undurable   bool
	sizeDelta   int64
	badDigest   bool
	closeErr    error
	failAfter   int
	prepared    map[string][]byte
	deleteCalls int
}

var capturedPublisherIdentity = artifact.StoreIdentity{ArtifactStoreID: "00000000-0000-4000-8000-000000009002", IncarnationNonce: "00000000-0000-4000-8000-000000009003", BackendKind: artifact.BackendKind, MarkerFormat: artifact.MarkerFormat, MarkerVersion: artifact.MarkerVersion}

func (s *capturedArtifacts) Identity() artifact.StoreIdentity { return capturedPublisherIdentity }
func (s *capturedArtifacts) CaptureCompiledPublication(req capability.Request, compiled resultadmission.CompiledResult) {
	s.req, s.compiled = req, compiled
}
func (s *capturedArtifacts) AcquirePublisher(_ context.Context, expected artifact.StoreIdentity) (artifact.PublisherGuard, error) {
	if expected != capturedPublisherIdentity {
		return nil, errors.New("identity mismatch")
	}
	return &capturedPublisherGuard{owner: s}, nil
}
func (s *capturedArtifacts) AcquirePreparedRecovery(_ context.Context, expected artifact.StoreIdentity) (artifact.PreparedRecoveryGuard, error) {
	if expected != capturedPublisherIdentity {
		return nil, errors.New("identity mismatch")
	}
	return &capturedRecoveryGuard{capturedPublisherGuard: capturedPublisherGuard{owner: s}}, nil
}

type capturedRecoveryGuard struct{ capturedPublisherGuard }

func (g *capturedRecoveryGuard) InspectPrepared(_ context.Context, setID domain.ID) (artifact.PreparedInspection, error) {
	manifestKey, _ := domain.PreparedManifestKey(setID)
	manifestJSON, ok := g.owner.prepared[manifestKey]
	if !ok {
		return artifact.PreparedInspection{}, os.ErrNotExist
	}
	manifest, err := domain.DecodePreparedManifestV1(manifestJSON)
	if err != nil {
		return artifact.PreparedInspection{}, err
	}
	controlJSON := g.owner.prepared[manifest.Control.StorageKey]
	control, err := domain.DecodePreparedControlV1(controlJSON)
	if err != nil {
		return artifact.PreparedInspection{}, err
	}
	return artifact.PreparedInspection{Manifest: manifest, ManifestJSON: append([]byte(nil), manifestJSON...), Control: control, ControlJSON: append([]byte(nil), controlJSON...), Durable: true}, nil
}
func (*capturedRecoveryGuard) VerifyReserved(context.Context, artifact.ReservedArtifactV1) (artifact.PublishedArtifactV1, bool, error) {
	return artifact.PublishedArtifactV1{}, false, nil
}
func (g *capturedRecoveryGuard) DeleteResolvedPrepared(context.Context, domain.PreparedSetRecord) (artifact.PreparedDeletionOutcome, error) {
	g.owner.deleteCalls++
	if g.owner.deleteCalls > 1 {
		return artifact.PreparedContentAlreadyAbsent, nil
	}
	return artifact.PreparedContentRemoved, nil
}

type capturedPublisherGuard struct {
	owner  *capturedArtifacts
	closed bool
}

func (g *capturedPublisherGuard) Identity() artifact.StoreIdentity { return capturedPublisherIdentity }
func (g *capturedPublisherGuard) StagePrepared(_ context.Context, request artifact.PreparedStageRequest) (artifact.PreparedStageReceipt, error) {
	if g.owner.prepared == nil {
		g.owner.prepared = map[string][]byte{}
	}
	contentBytes := int64(0)
	for _, object := range append([]artifact.PreparedStageObject{request.Control}, request.Members...) {
		reader, err := object.Source.Open()
		if err != nil {
			return artifact.PreparedStageReceipt{}, err
		}
		data, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || int64(len(data)) != object.ExpectedSize || artifact.DigestBytes(data) != object.ExpectedSHA256 {
			return artifact.PreparedStageReceipt{}, errors.Join(readErr, closeErr, errors.New("invalid prepared stage object"))
		}
		g.owner.prepared[object.StorageKey] = data
		contentBytes += int64(len(data))
	}
	g.owner.prepared[request.ManifestKey] = append([]byte(nil), request.ManifestJSON...)
	return artifact.PreparedStageReceipt{ManifestSize: int64(len(request.ManifestJSON)), ManifestSHA256: artifact.DigestBytes(request.ManifestJSON), MemberCount: len(request.Members), ContentBytes: contentBytes, Durable: true}, nil
}
func (g *capturedPublisherGuard) OpenPrepared(_ context.Context, key string, size int64, digest [32]byte) (io.ReadCloser, error) {
	data, ok := g.owner.prepared[key]
	if !ok || int64(len(data)) != size || artifact.DigestBytes(data) != digest {
		return nil, errors.New("prepared object unavailable")
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}
func (g *capturedPublisherGuard) PublishReserved(_ context.Context, reserved artifact.ReservedArtifactV1, reader io.Reader) (artifact.PublishedArtifactV1, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return artifact.PublishedArtifactV1{}, err
	}
	var item resultadmission.PreparedArtifact
	for _, candidate := range g.owner.compiled.Artifacts {
		if candidate.Reference.ArtifactID == reserved.ArtifactID {
			item = candidate
			break
		}
	}
	name := map[domain.ResultArtifactRoleV1]string{domain.ArtifactRoleProviderStdout: "stdout.jsonl", domain.ArtifactRoleProviderStderr: "stderr.txt", domain.ArtifactRoleProviderDiagnostic: "diagnostic.bin", domain.ArtifactRoleSemanticResult: "result.json"}[item.Reference.Role]
	g.owner.requests = append(g.owner.requests, artifact.PutRequest{ProgramID: g.owner.req.ProgramID, TaskID: g.owner.req.Action.TaskID, WorkflowRunID: g.owner.req.Action.WorkflowRunID, StepRunID: g.owner.req.Action.StepRunID, ToolRunID: g.owner.compiled.ToolRun.ID, Type: item.ArtifactType, ContentType: item.Reference.ContentType, Name: name, Retention: g.owner.req.Policy.ArtifactRetention, Data: data})
	if g.owner.err != nil {
		return artifact.PublishedArtifactV1{}, g.owner.err
	}
	if g.owner.failAfter > 0 && len(g.owner.requests) >= g.owner.failAfter {
		return artifact.PublishedArtifactV1{}, errors.New("injected physical write failure")
	}
	digest := reserved.ExpectedSHA256
	if g.owner.badDigest {
		digest[0] ^= 1
	}
	return artifact.PublishedArtifactV1{SizeBytes: int64(len(data)) + g.owner.sizeDelta, SHA256: digest, Durable: !g.owner.undurable}, nil
}
func (g *capturedPublisherGuard) Close() error { g.closed = true; return g.owner.closeErr }

func (s *capturedArtifacts) Put(_ context.Context, req artifact.PutRequest) (domain.Artifact, error) {
	s.requests = append(s.requests, req)
	if s.err != nil {
		return domain.Artifact{}, s.err
	}
	id := domain.NewID()
	key, err := artifact.StorageKeyFor(id)
	if err != nil {
		return domain.Artifact{}, err
	}
	storeID := domain.ID("00000000-0000-4000-8000-000000009002")
	return domain.Artifact{ID: id, TaskID: req.TaskID, WorkflowRunID: req.WorkflowRunID, StepRunID: req.StepRunID, ToolRunID: req.ToolRunID, Type: req.Type, ContentType: req.ContentType, Size: int64(len(req.Data)), AddressingVersion: 1, ArtifactStoreID: &storeID, StorageKey: &key, CreatedAt: time.Now().UTC()}, nil
}

type allowedScope struct{}

func (allowedScope) Allows(string) bool { return true }

type publicationPipelineCapability struct {
	stdout []byte
	output json.RawMessage
}

func (c publicationPipelineCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "compare.assets", Version: "2", Risk: policy.Low, RetrySafe: true, Idempotent: true, OutputSchema: json.RawMessage(`{"type":"object"}`)}
}
func (publicationPipelineCapability) Validate(context.Context, capability.Request) error { return nil }
func (c publicationPipelineCapability) Execute(_ context.Context, request capability.Request) (capability.Result, error) {
	output := c.output
	if len(output) == 0 {
		output = json.RawMessage(`{}`)
	}
	return capability.Result{Action: domain.ActionResult{RequestID: request.Action.ID, Status: "succeeded", Summary: "pipeline", Output: append(json.RawMessage(nil), output...)}, RawStdout: append([]byte(nil), c.stdout...)}, nil
}

type confidentialityFailureCapability struct {
	calls  int
	detail string
}

func (c *confidentialityFailureCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "review.failure", Version: "1", Risk: policy.Low, RetrySafe: false, Idempotent: true, OutputSchema: json.RawMessage(`{}`)}
}
func (*confidentialityFailureCapability) Validate(context.Context, capability.Request) error {
	return nil
}
func (c *confidentialityFailureCapability) Execute(_ context.Context, request capability.Request) (capability.Result, error) {
	c.calls++
	message := "provider failure " + c.detail
	return capability.Result{
		Action: domain.ActionResult{
			RequestID: request.Action.ID,
			Status:    "failed",
			Summary:   message,
			Error:     &domain.StructuredError{Classification: "provider_error", Message: message, Retryable: false},
		},
		RawDiagnostic: []byte("provider diagnostic " + c.detail),
	}, errors.New(message)
}

func TestProviderErrorConfidentialitySurvivesAdoptionAndPreparedRecovery(t *testing.T) {
	const secret = "token=assignment-ten-synthetic"
	provider := &confidentialityFailureCapability{detail: secret + " " + strings.Repeat("x", domain.SafeMessageMaxBytes)}
	registry := capability.NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	store, artifacts := &capturedStore{}, &capturedArtifacts{}
	request := capability.Request{
		Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "review.failure", Input: json.RawMessage(`{}`), IdempotencyKey: "confidentiality-review", StepAttempt: 1},
		Policy: policy.Policy{AllowedCapabilities: []string{"review.failure"}},
		Scope:  allowedScope{},
	}
	result, err := (Service{Registry: registry, Store: store, Artifacts: artifacts, ProgramID: domain.NewID()}).Execute(context.Background(), request)
	if err == nil || result.Envelope == nil || result.Envelope.Error == nil || result.Action.Error == nil || !store.persisted {
		t.Fatal("failed provider result did not reach the admitted failure path")
	}
	if result.Envelope.Error.Code != "provider_error" || result.Envelope.Error.Retryable || store.step.ErrorClassification != "provider_error" || store.terminal.Outcome != capability.ProviderInvocationFailed {
		t.Fatal("failure classification or retryability changed")
	}
	envelopeJSON, marshalErr := result.Envelope.CanonicalJSON()
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for name, value := range map[string]string{"returned error": err.Error(), "returned action error": result.Action.Error.Message, "adopted step": store.step.ErrorDetails} {
		if strings.Contains(value, "assignment-ten-synthetic") || !strings.Contains(value, "<redacted>") {
			t.Fatalf("%s crossed the operator-safe boundary", name)
		}
	}
	if bytes.Contains(envelopeJSON, []byte("assignment-ten-synthetic")) {
		t.Fatal("compiled envelope retained the synthetic sentinel")
	}
	if len(result.Envelope.Error.Message) > domain.SafeMessageMaxBytes || len(store.step.ErrorDetails) > domain.SafeMessageMaxBytes {
		t.Fatal("post-redaction error message exceeded the safe bound")
	}
	for _, data := range artifacts.prepared {
		if bytes.Contains(data, []byte("assignment-ten-synthetic")) {
			t.Fatal("prepared evidence retained the synthetic sentinel")
		}
	}
	for _, published := range artifacts.requests {
		if bytes.Contains(published.Data, []byte("assignment-ten-synthetic")) {
			t.Fatal("published evidence retained the synthetic sentinel")
		}
	}

	compiled := artifacts.compiled
	manifestKey, _ := domain.PreparedManifestKey(compiled.PreparedSetID)
	manifestJSON := artifacts.prepared[manifestKey]
	manifest, decodeErr := domain.DecodePreparedManifestV1(manifestJSON)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	controlJSON := artifacts.prepared[manifest.Control.StorageKey]
	contentBytes := int64(len(manifestJSON) + len(controlJSON))
	for _, member := range manifest.Members {
		contentBytes += member.ContentSizeBytes
	}
	manifestSize := int64(len(manifestJSON))
	manifestDigest := artifact.DigestString(artifact.DigestBytes(manifestJSON))
	memberCount := len(manifest.Members)
	occurrence := manifest.ResultOccurrenceID
	recoveryStore := &capturedStore{recoveryRecords: []domain.PreparedSetRecord{{ID: manifest.SetID, ManifestID: manifest.ManifestID, ProviderAttemptID: manifest.ProviderAttemptID, ProgramID: artifacts.req.ProgramID, TaskID: artifacts.req.Action.TaskID, WorkflowRunID: artifacts.req.Action.WorkflowRunID, StepRunID: artifacts.req.Action.StepRunID, ActionRequestID: artifacts.req.Action.ID, StepAttempt: artifacts.req.Action.StepAttempt, ArtifactStoreID: capturedPublisherIdentity.ArtifactStoreID, StoreIncarnationNonce: capturedPublisherIdentity.IncarnationNonce, State: domain.PreparedSealed, ReservedCapacityBytes: contentBytes, ResultOccurrenceID: &occurrence, ProviderTerminalEventID: &compiled.ProviderTerminalEventID, ManifestStorageKey: &manifestKey, ManifestSizeBytes: &manifestSize, ManifestSHA256: &manifestDigest, MemberCount: &memberCount, ContentSizeBytes: &contentBytes}}}
	recoveryStore.recoveryStates = make([]domain.PublicationState, len(compiled.Artifacts))
	for index := range recoveryStore.recoveryStates {
		recoveryStore.recoveryStates[index] = domain.PublicationSealed
	}
	if recoveryErr := (Service{Store: recoveryStore, Artifacts: artifacts}).RecoverPreparedEvidence(context.Background(), 10); recoveryErr != nil {
		t.Fatal(recoveryErr)
	}
	if provider.calls != 1 || store.terminalEvents != 1 || recoveryStore.terminalEvents != 0 || store.adoptCalls != 1 || recoveryStore.adoptCalls != 1 || recoveryStore.tool == nil || store.tool == nil || recoveryStore.tool.ID != store.tool.ID || recoveryStore.admission == nil || recoveryStore.admission.ProviderAttemptID != compiled.Envelope.ProviderAttemptID || recoveryStore.admission.PreparedSetID != compiled.PreparedSetID || recoveryStore.result.RequestID != compiled.Envelope.ActionRequestID {
		t.Fatal("prepared recovery replayed the provider or replaced result identity")
	}
	if strings.Contains(recoveryStore.step.ErrorDetails, "assignment-ten-synthetic") || !strings.Contains(recoveryStore.step.ErrorDetails, "<redacted>") {
		t.Fatal("prepared recovery reintroduced the synthetic sentinel")
	}
}

type injectedProjectionLimit struct{ limit domain.ResultContractLimitV1 }

func (e *injectedProjectionLimit) Error() string { return "injected projection limit" }
func (e *injectedProjectionLimit) ResultContractLimit() domain.ResultContractLimitV1 {
	return e.limit
}

type injectedCommitUnknown struct{ operation string }

func (e *injectedCommitUnknown) Error() string              { return e.operation + " commit failed" }
func (e *injectedCommitUnknown) CommitOutcomeUnknown() bool { return true }

func executePublicationPipeline(t *testing.T, store *capturedStore, artifacts *capturedArtifacts, stdout []byte) (capability.Result, error) {
	return executePublicationPipelineResult(t, store, artifacts, stdout, nil)
}

func executePublicationPipelineResult(t *testing.T, store *capturedStore, artifacts *capturedArtifacts, stdout []byte, output json.RawMessage) (capability.Result, error) {
	t.Helper()
	registry := capability.NewRegistry()
	if err := registry.Register(publicationPipelineCapability{stdout: stdout, output: output}); err != nil {
		t.Fatal(err)
	}
	request := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "compare.assets", Input: json.RawMessage(`{}`), IdempotencyKey: "publication-pipeline", StepAttempt: 1}, Policy: policy.Policy{AllowedCapabilities: []string{"compare.assets"}}, Scope: allowedScope{}}
	return (Service{Registry: registry, Store: store, Artifacts: artifacts, ProgramID: domain.NewID()}).Execute(context.Background(), request)
}

func TestLargePublicationPipelineKeepsEveryControlProjectionBounded(t *testing.T) {
	stdout := []byte(strings.Repeat("stdout evidence\n", 20_000))
	semantic := json.RawMessage(`{"value":"` + strings.Repeat("x", 300_000) + `"}`)
	store, artifacts := &capturedStore{}, &capturedArtifacts{}
	result, err := executePublicationPipelineResult(t, store, artifacts, stdout, semantic)
	if err != nil {
		t.Fatal(err)
	}
	if result.Envelope == nil || result.Envelope.SemanticOutput.Mode != domain.SemanticModeArtifactJSON || !store.persisted || store.tool == nil {
		t.Fatalf("envelope=%#v persisted=%v tool=%#v", result.Envelope, store.persisted, store.tool)
	}
	if len(store.step.Output) > domain.ResultEnvelopeMaxBytes || bytes.Contains(store.step.Output, semantic[10:110]) || bytes.Contains(store.step.Output, stdout[:100]) {
		t.Fatalf("StepRun.Output bytes=%d scaled with evidence", len(store.step.Output))
	}
	audit, err := json.Marshal(domain.ResultAuditProjectionV1{Version: 1, ActionRequestID: result.Envelope.ActionRequestID, ResultOccurrenceID: result.Envelope.ResultOccurrenceID, ProviderAttemptID: result.Envelope.ProviderAttemptID, Status: result.Envelope.Status, SemanticMode: result.Envelope.SemanticOutput.Mode, SemanticArtifactID: result.Envelope.SemanticOutput.ArtifactID, ArtifactCount: len(result.Envelope.Artifacts), EnvelopeSHA256: artifacts.compiled.EnvelopeSHA256})
	if err != nil || len(audit) > domain.DiagnosticMaxBytes || bytes.Contains(audit, semantic[10:110]) {
		t.Fatalf("audit bytes=%d error=%v", len(audit), err)
	}
	if len(artifacts.requests) != 2 {
		t.Fatalf("physical artifacts=%d", len(artifacts.requests))
	}
	if len(artifacts.requests[0].Data) != len(stdout) || len(artifacts.requests[1].Data) != len(semantic) {
		t.Fatalf("physical stdout=%d semantic=%d", len(artifacts.requests[0].Data), len(artifacts.requests[1].Data))
	}
	if len(store.tool.ArtifactIDs) != 2 || store.result.Output == nil || len(store.result.Output) > domain.ResultEnvelopeMaxBytes {
		t.Fatalf("tool artifacts=%d bounded result=%d", len(store.tool.ArtifactIDs), len(store.result.Output))
	}
	t.Logf("stdout_evidence=%d semantic_evidence=%d envelope=%d audit=%d artifacts=%d", len(stdout), len(semantic), len(store.step.Output), len(audit), len(store.tool.ArtifactIDs))
}

func TestPublicationStagesSmallMemoryBackedMemberBeforeReservation(t *testing.T) {
	store, artifacts := &capturedStore{}, &capturedArtifacts{}
	result, err := executePublicationPipeline(t, store, artifacts, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Envelope == nil || len(artifacts.compiled.Artifacts) != 1 {
		t.Fatalf("compiled result=%#v members=%d", result.Envelope, len(artifacts.compiled.Artifacts))
	}
	memberKey, _ := domain.PreparedMemberKey(artifacts.compiled.PreparedSetID, 0)
	member, ok := artifacts.prepared[memberKey]
	if !ok || len(member) > 64*1024 || string(member) != "{}" {
		t.Fatalf("small prepared member present=%v bytes=%d value=%q", ok, len(member), member)
	}
	manifestKey, _ := domain.PreparedManifestKey(artifacts.compiled.PreparedSetID)
	if _, ok := artifacts.prepared[manifestKey]; !ok {
		t.Fatal("prepared manifest was not staged")
	}
	if !store.persisted {
		t.Fatal("small prepared member was not adopted")
	}
}

func TestPreparedRecoveryReusesExactIdentitiesWithoutProviderReplay(t *testing.T) {
	store, artifacts := &capturedStore{}, &capturedArtifacts{}
	if _, err := executePublicationPipeline(t, store, artifacts, []byte("durable evidence\n")); err != nil {
		t.Fatal(err)
	}
	compiled := artifacts.compiled
	manifestKey, _ := domain.PreparedManifestKey(compiled.PreparedSetID)
	manifestJSON := artifacts.prepared[manifestKey]
	manifest, err := domain.DecodePreparedManifestV1(manifestJSON)
	if err != nil {
		t.Fatal(err)
	}
	controlJSON := artifacts.prepared[manifest.Control.StorageKey]
	contentBytes := int64(len(manifestJSON) + len(controlJSON))
	for _, member := range manifest.Members {
		contentBytes += member.ContentSizeBytes
	}
	manifestSize, manifestDigest, memberCount, occurrence := int64(len(manifestJSON)), artifact.DigestString(artifact.DigestBytes(manifestJSON)), len(manifest.Members), manifest.ResultOccurrenceID
	store.recoveryRecords = []domain.PreparedSetRecord{{ID: manifest.SetID, ManifestID: manifest.ManifestID, ProviderAttemptID: manifest.ProviderAttemptID, ProgramID: artifacts.req.ProgramID, TaskID: artifacts.req.Action.TaskID, WorkflowRunID: artifacts.req.Action.WorkflowRunID, StepRunID: artifacts.req.Action.StepRunID, ActionRequestID: artifacts.req.Action.ID, StepAttempt: artifacts.req.Action.StepAttempt, ArtifactStoreID: capturedPublisherIdentity.ArtifactStoreID, StoreIncarnationNonce: capturedPublisherIdentity.IncarnationNonce, State: domain.PreparedSealed, ReservedCapacityBytes: contentBytes, ResultOccurrenceID: &occurrence, ProviderTerminalEventID: &compiled.ProviderTerminalEventID, ManifestStorageKey: &manifestKey, ManifestSizeBytes: &manifestSize, ManifestSHA256: &manifestDigest, MemberCount: &memberCount, ContentSizeBytes: &contentBytes}}
	store.recoveryStates = make([]domain.PublicationState, len(compiled.Artifacts))
	for index := range store.recoveryStates {
		store.recoveryStates[index] = domain.PublicationSealed
	}
	beforeAdopts := store.adoptCalls
	store.persisted = false
	if err := (Service{Store: store, Artifacts: artifacts}).RecoverPreparedEvidence(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	if store.adoptCalls != beforeAdopts+1 || !store.persisted || store.admission == nil || store.admission.PreparedSetID != compiled.PreparedSetID || store.admission.ProviderAttemptID != compiled.Envelope.ProviderAttemptID || store.result.RequestID != compiled.Envelope.ActionRequestID {
		t.Fatalf("recovery adopts=%d persisted=%v admission=%#v result=%#v", store.adoptCalls, store.persisted, store.admission, store.result)
	}
	for _, boundary := range []string{"before prepared seal", "before reservation", "reserved", "publishing", "sealed", "adoption acknowledgement", "authority unavailable"} {
		t.Run(boundary, func(t *testing.T) {
			record := store.recoveryRecords[0]
			candidate := &capturedStore{recoveryRecords: []domain.PreparedSetRecord{record}}
			state := domain.PublicationSealed
			switch boundary {
			case "before prepared seal":
				candidate.recoveryRecords[0].State = domain.PreparedAllocated
			case "reserved":
				state = domain.PublicationReserved
			case "publishing":
				state = domain.PublicationPublishing
			case "adoption acknowledgement":
				candidate.adoptErrors = []error{&injectedCommitUnknown{operation: "recovery adoption"}}
			case "authority unavailable":
				candidate.adoptErrors = []error{errors.New("exact recovery authority unavailable")}
			}
			if boundary != "before prepared seal" && boundary != "before reservation" {
				candidate.recoveryStates = make([]domain.PublicationState, len(compiled.Artifacts))
				for i := range candidate.recoveryStates {
					candidate.recoveryStates[i] = state
				}
			}
			err := (Service{Store: candidate, Artifacts: artifacts}).RecoverPreparedEvidence(context.Background(), 10)
			unresolved := boundary == "adoption acknowledgement" || boundary == "authority unavailable"
			if unresolved != domain.PersistenceUnresolved(err) || (!unresolved && err != nil) {
				t.Fatalf("recovery error=%v", err)
			}
			if candidate.terminalized != 0 || len(candidate.cleanedSets) != 0 || candidate.startID != "" {
				t.Fatal("recovery abandoned, cleaned or invoked provider")
			}
			if !unresolved && (candidate.admission == nil || candidate.admission.ProviderAttemptID != compiled.Envelope.ProviderAttemptID || candidate.admission.PreparedSetID != compiled.PreparedSetID || candidate.result.RequestID != compiled.Envelope.ActionRequestID) {
				t.Fatal("recovery replaced result identities")
			}
		})
	}
}

func TestResolvedPreparedCleanupRetriesAfterPhysicalDeletion(t *testing.T) {
	setID := domain.NewID()
	store := &capturedStore{recoveryRecords: []domain.PreparedSetRecord{{ID: setID, ArtifactStoreID: capturedPublisherIdentity.ArtifactStoreID, StoreIncarnationNonce: capturedPublisherIdentity.IncarnationNonce, State: domain.PreparedResolvedAdopted, ReservedCapacityBytes: domain.PreparedSetOutputAuthorityMaxBytes}}, cleanErrors: []error{&injectedCommitUnknown{operation: "cleanup"}, nil}}
	artifacts := &capturedArtifacts{}
	service := Service{Store: store, Artifacts: artifacts}
	if err := service.RecoverPreparedEvidence(context.Background(), 10); !commitOutcomeUnknown(err) {
		t.Fatalf("first cleanup error=%v", err)
	}
	if err := service.RecoverPreparedEvidence(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	if artifacts.deleteCalls != 2 || len(store.cleanedSets) != 2 {
		t.Fatalf("delete calls=%d cleaned transitions=%d", artifacts.deleteCalls, len(store.cleanedSets))
	}
}

func TestPreparedRecoveryRetainsQuarantine(t *testing.T) {
	record := domain.PreparedSetRecord{ID: domain.NewID(), ArtifactStoreID: capturedPublisherIdentity.ArtifactStoreID, StoreIncarnationNonce: capturedPublisherIdentity.IncarnationNonce, State: domain.PreparedQuarantined, ReservedCapacityBytes: domain.PreparedSetOutputAuthorityMaxBytes}
	store, artifacts := &capturedStore{recoveryRecords: []domain.PreparedSetRecord{record}}, &capturedArtifacts{}
	if err := (Service{Store: store, Artifacts: artifacts}).RecoverPreparedEvidence(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	if artifacts.deleteCalls != 0 || len(store.cleanedSets) != 0 {
		t.Fatalf("quarantine delete calls=%d cleaned=%d", artifacts.deleteCalls, len(store.cleanedSets))
	}
}

func TestPublicationPipelineFailureInjectionPreservesAtomicVisibility(t *testing.T) {
	failure := errors.New("injected failure")
	tests := []struct {
		name           string
		configure      func(*capturedStore, *capturedArtifacts)
		stdout         []byte
		wantPhysical   int
		wantTerminal   domain.PublicationState
		wantUnresolved bool
	}{
		{"reservation transaction", func(store *capturedStore, _ *capturedArtifacts) { store.err = failure }, nil, 0, "", true},
		{"publishing transition", func(store *capturedStore, _ *capturedArtifacts) { store.publishingErr = failure }, nil, 0, "", true},
		{"physical write", func(_ *capturedStore, artifacts *capturedArtifacts) { artifacts.err = failure }, nil, 1, domain.PublicationQuarantined, true},
		{"size mismatch", func(_ *capturedStore, artifacts *capturedArtifacts) { artifacts.sizeDelta = 1 }, nil, 1, domain.PublicationQuarantined, true},
		{"digest mismatch", func(_ *capturedStore, artifacts *capturedArtifacts) { artifacts.badDigest = true }, nil, 1, domain.PublicationQuarantined, true},
		{"durability failure", func(_ *capturedStore, artifacts *capturedArtifacts) { artifacts.undurable = true }, nil, 1, domain.PublicationQuarantined, true},
		{"seal transition", func(store *capturedStore, _ *capturedArtifacts) { store.sealErr = failure }, nil, 1, "", true},
		{"partial multi artifact", func(_ *capturedStore, artifacts *capturedArtifacts) { artifacts.failAfter = 2 }, []byte("stdout"), 2, domain.PublicationQuarantined, true},
		{"adoption precommit", func(store *capturedStore, _ *capturedArtifacts) { store.adoptErrors = []error{failure} }, nil, 1, "", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, artifacts := &capturedStore{}, &capturedArtifacts{}
			test.configure(store, artifacts)
			_, err := executePublicationPipeline(t, store, artifacts, test.stdout)
			if err == nil {
				t.Fatal("injected failure was not returned")
			}
			if domain.PersistenceUnresolved(err) != test.wantUnresolved {
				t.Fatalf("unresolved=%v want=%v error=%v", domain.PersistenceUnresolved(err), test.wantUnresolved, err)
			}
			if len(artifacts.requests) != test.wantPhysical || store.persisted || store.tool != nil || len(store.artifacts) != 0 {
				t.Fatalf("physical=%d persisted=%v tool=%#v artifacts=%d", len(artifacts.requests), store.persisted, store.tool, len(store.artifacts))
			}
			if (store.terminalized > 0) != (test.wantTerminal != "") {
				t.Fatalf("terminalized=%d want=%s", store.terminalized, test.wantTerminal)
			}
			if store.terminalized > 0 && store.terminalState != test.wantTerminal {
				t.Fatalf("terminal state=%s want=%s", store.terminalState, test.wantTerminal)
			}
		})
	}
}

func TestProjectionLimitRollsBackThenAdoptsFailedEnvelopeAgainstSealedSet(t *testing.T) {
	limit := domain.ResultContractLimitV1{Subject: domain.LimitProjectionItem, Unit: domain.LimitBytes, Limit: domain.ResultEnvelopeMaxBytes, Observed: domain.ResultEnvelopeMaxBytes + 1}
	store := &capturedStore{adoptErrors: []error{&injectedProjectionLimit{limit: limit}, nil}}
	result, err := executePublicationPipeline(t, store, &capturedArtifacts{}, nil)
	if err == nil || !strings.Contains(err.Error(), "result_contract_limit") {
		t.Fatalf("failed-result admission error=%v", err)
	}
	if store.adoptCalls != 2 || !store.persisted || store.terminalized != 0 || result.Envelope == nil || result.Envelope.Status != domain.ResultStatusFailed || result.Envelope.ProviderOutcome != domain.ResultProviderSucceeded || result.Envelope.Error == nil || result.Envelope.Error.Code != "result_contract_limit" || result.Envelope.SemanticOutput.ProjectionState != domain.ProjectionRejected {
		t.Fatalf("adopts=%d persisted=%v terminalized=%d envelope=%#v", store.adoptCalls, store.persisted, store.terminalized, result.Envelope)
	}
}

func TestCommitUnknownNeverTerminalizesOrReplays(t *testing.T) {
	t.Run("reservation", func(t *testing.T) {
		store := &capturedStore{err: &injectedCommitUnknown{operation: "reservation"}}
		_, err := executePublicationPipeline(t, store, &capturedArtifacts{}, nil)
		if err == nil || store.terminalized != 0 || store.adoptCalls != 0 {
			t.Fatalf("error=%v terminalized=%d adopts=%d", err, store.terminalized, store.adoptCalls)
		}
	})
	t.Run("adoption", func(t *testing.T) {
		store := &capturedStore{adoptErrors: []error{&injectedCommitUnknown{operation: "adoption"}}}
		_, err := executePublicationPipeline(t, store, &capturedArtifacts{}, nil)
		if err == nil || store.terminalized != 0 || store.adoptCalls != 1 || store.persisted {
			t.Fatalf("error=%v terminalized=%d adopts=%d persisted=%v", err, store.terminalized, store.adoptCalls, store.persisted)
		}
	})
}

func TestCommitUnknownAtEveryPreparedPublicationBoundaryRetainsEvidence(t *testing.T) {
	unknown := &injectedCommitUnknown{operation: "injected"}
	tests := []struct {
		name      string
		configure func(*capturedStore, *capturedArtifacts)
	}{
		{"prepared sealing", func(store *capturedStore, _ *capturedArtifacts) { store.terminalErr = unknown }},
		{"publishing transition", func(store *capturedStore, _ *capturedArtifacts) { store.publishingErr = unknown }},
		{"final sealing transition", func(store *capturedStore, _ *capturedArtifacts) { store.sealErr = unknown }},
		{"terminalization", func(store *capturedStore, artifacts *capturedArtifacts) {
			artifacts.err = errors.New("known publication failure")
			store.terminalizeErr = unknown
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, artifacts := &capturedStore{}, &capturedArtifacts{}
			test.configure(store, artifacts)
			_, err := executePublicationPipeline(t, store, artifacts, []byte("evidence\n"))
			if !commitOutcomeUnknown(err) {
				t.Fatalf("error=%v does not retain unresolved commit outcome", err)
			}
			if len(artifacts.prepared) == 0 || store.persisted {
				t.Fatalf("prepared=%d persisted=%v", len(artifacts.prepared), store.persisted)
			}
			if test.name != "terminalization" && store.terminalized != 0 {
				t.Fatalf("unresolved %s was terminalized", test.name)
			}
		})
	}
}

func TestPublisherCloseFailureIsSecondaryAfterCommittedAdoption(t *testing.T) {
	closeCause := errors.New("injected lock release failure")
	store := &capturedStore{}
	result, err := executePublicationPipeline(t, store, &capturedArtifacts{closeErr: closeCause}, nil)
	if err != nil || !store.persisted || store.terminalized != 0 || result.Envelope == nil || result.Envelope.Status != domain.ResultStatusSucceeded {
		t.Fatalf("error=%v persisted=%v terminalized=%d envelope=%#v", err, store.persisted, store.terminalized, result.Envelope)
	}
}

func TestPublisherCloseFailureDoesNotReverseWorkflowSuccess(t *testing.T) {
	registry := capability.NewRegistry()
	if err := registry.Register(publicationPipelineCapability{}); err != nil {
		t.Fatal(err)
	}
	store := &capturedStore{}
	artifacts := &capturedArtifacts{closeErr: errors.New("injected lock release failure")}
	executor := Service{Registry: registry, Store: store, Artifacts: artifacts, ProgramID: domain.NewID()}
	engine := workflow.Engine{Registry: registry, Executor: executor, Policy: policy.Policy{AllowedCapabilities: []string{"compare.assets"}}, Scope: allowedScope{}}
	definition := workflow.Definition{ID: domain.NewID(), Name: "publisher-close", Version: "1", Steps: []workflow.Step{{ID: "step", Capability: "compare.assets", Input: json.RawMessage(`{}`)}}}
	state, err := engine.Run(context.Background(), definition, nil, domain.Task{ID: domain.NewID(), ProgramID: domain.NewID()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.Run.Status != domain.RunCompleted || state.Steps["step"].Run.Status != domain.StepSucceeded || !store.persisted {
		t.Fatalf("committed success was reversed: state=%#v persisted=%v", state, store.persisted)
	}
}

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
	if !store.called || !store.persisted || store.publications != 1 || store.step.Status != domain.StepFailed || store.step.ErrorClassification == "" {
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
	rawStdout      []byte
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
		return capability.Result{RawStdout: append([]byte(nil), c.rawStdout...)}, ctx.Err()
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
	provider := &contextErrorCapability{waitForContext: true, started: make(chan struct{}), rawStdout: []byte("cancelled output must not publish\n")}
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	store := &capturedStore{}
	artifacts := &capturedArtifacts{}
	service := Service{Registry: registry, Store: store, Artifacts: artifacts, ProgramID: domain.NewID()}
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
	if len(artifacts.requests) != 3 || store.publications != 1 {
		t.Fatalf("cancelled execution did not preserve stdout, diagnostic, and canonical-null evidence: puts=%d publications=%d", len(artifacts.requests), store.publications)
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
	result, err := (Service{Registry: registry, Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(ctx, executionContextErrorRequest())
	if !errors.Is(err, context.Canceled) || ctx.Err() != nil {
		t.Fatalf("provider error=%v caller error=%v", err, ctx.Err())
	}
	if provider.calls != 1 || store.step.Status != domain.StepCancelled || store.step.CompletedAt == nil || result.Action.Status != "failed" || result.Action.Error == nil || result.Action.Error.Classification != "execution" {
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
	result, err := (Service{Registry: registry, Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(ctx, executionContextErrorRequest())
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
	if _, err := (Service{Registry: registry, Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(context.Background(), req); err == nil {
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
	if result.ProviderAttemptID != nil || result.AdmissionProvenance != nil || store.admission != nil || store.tool != nil || store.step.Status != domain.StepFailed || len(store.step.Output) != 0 {
		t.Fatalf("no-provider persistence result=%#v tool=%#v step=%#v", result, store.tool, store.step)
	}
}

func TestPreparedSealFailurePreventsProviderSuccessAdoption(t *testing.T) {
	registry := capability.NewRegistry()
	provider := &inputCaptureCapability{}
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	terminalCause := errors.New("terminal audit unavailable")
	store := &capturedStore{terminalErr: terminalCause}
	req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), Capability: "classify.endpoint", Input: json.RawMessage(`{"historical_observations":[]}`)}, Policy: policy.Policy{AllowedCapabilities: []string{"classify.endpoint"}}, Scope: allowedScope{}}
	result, err := (Service{Registry: registry, Store: store, Artifacts: &capturedArtifacts{}, ProgramID: domain.NewID()}).Execute(context.Background(), req)
	if !errors.Is(err, terminalCause) {
		t.Fatalf("prepared seal failure was not returned: %v", err)
	}
	if result.ProviderAttemptID == nil || result.AdmissionProvenance == nil || store.persisted || store.admission != nil {
		t.Fatalf("seal failure result=%#v persisted=%v admission=%#v", result, store.persisted, store.admission)
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
		t.Fatalf("fake executable exit was not persisted: tool=%#v error=%v", store.tool, err)
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
