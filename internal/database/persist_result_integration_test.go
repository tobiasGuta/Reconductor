package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/execution"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

type postgresProvenanceCapability struct {
	calls          int
	store          *Store
	startID        *domain.ID
	cancel         context.CancelFunc
	startVisible   bool
	observationErr error
}

func (*postgresProvenanceCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "test.provenance", Version: "1", Risk: policy.Low}
}
func (*postgresProvenanceCapability) Validate(context.Context, capability.Request) error { return nil }
func (c *postgresProvenanceCapability) Execute(ctx context.Context, req capability.Request) (capability.Result, error) {
	c.calls++
	if c.store != nil && c.startID != nil {
		var count int
		c.observationErr = c.store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE id=$1 AND event_type='provider_invocation_started'`, *c.startID).Scan(&count)
		c.startVisible = c.observationErr == nil && count == 1
	}
	if c.cancel != nil {
		c.cancel()
	}
	return capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Summary: "provider returned"}}, nil
}

type observingPostgresRecorder struct {
	store   *Store
	startID *domain.ID
}

func (r observingPostgresRecorder) RecordProviderInvocationStarted(ctx context.Context, record capability.ProviderInvocationStartRecord) (domain.ID, error) {
	id, err := r.store.RecordProviderInvocationStarted(ctx, record)
	if err == nil {
		*r.startID = id
	}
	return id, err
}
func (r observingPostgresRecorder) RecordProviderInvocationTerminal(ctx context.Context, record capability.ProviderInvocationTerminalRecord) error {
	return r.store.RecordProviderInvocationTerminal(ctx, record)
}

type invalidPostgresStartRecorder struct{ store *Store }

func (r invalidPostgresStartRecorder) RecordProviderInvocationStarted(ctx context.Context, record capability.ProviderInvocationStartRecord) (domain.ID, error) {
	record.ExecutionAuthorizationEventID = domain.NewID()
	return r.store.RecordProviderInvocationStarted(ctx, record)
}
func (r invalidPostgresStartRecorder) RecordProviderInvocationTerminal(ctx context.Context, record capability.ProviderInvocationTerminalRecord) error {
	return r.store.RecordProviderInvocationTerminal(ctx, record)
}

type integrationAllowScope struct{}

func (integrationAllowScope) Allows(string) bool { return true }

type postgresWorkflowRetryCapability struct {
	calls             int
	store             *Store
	persistedInputs   []json.RawMessage
	persistedAttempts []int
}

func (*postgresWorkflowRetryCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "test.workflow-retry", Version: "1", Risk: policy.Low, RetrySafe: true, Idempotent: true, SupportedProviders: []string{"retry-provider"}}
}

func (*postgresWorkflowRetryCapability) Validate(context.Context, capability.Request) error {
	return nil
}

func (c *postgresWorkflowRetryCapability) Execute(ctx context.Context, req capability.Request) (capability.Result, error) {
	c.calls++
	if c.store != nil {
		var input json.RawMessage
		var attempt int
		if err := c.store.Pool.QueryRow(ctx, `SELECT input,attempt_count FROM step_runs WHERE id=$1`, req.Action.StepRunID).Scan(&input, &attempt); err != nil {
			return capability.Result{}, err
		}
		c.persistedInputs = append(c.persistedInputs, append(json.RawMessage(nil), input...))
		c.persistedAttempts = append(c.persistedAttempts, attempt)
	}
	now := time.Now().UTC()
	exitCode := 0
	tool := &domain.ToolRun{ID: domain.NewID(), StepRunID: req.Action.StepRunID, Capability: req.Action.Capability, Provider: req.Provider, ToolVersion: "1", SanitizedArguments: json.RawMessage(`{}`), ExecutionEnvironment: json.RawMessage(`{"kind":"integration"}`), StartedAt: now, CompletedAt: &now, ExitCode: &exitCode}
	result := capability.Result{
		Action:    domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Summary: "provider succeeded"},
		ToolRun:   tool,
		RawStdout: []byte("provider attempt output\n"),
	}
	if c.calls == 1 {
		result.Action.Status = "failed"
		result.Action.Summary = "provider retryable failure"
		result.Action.Error = &domain.StructuredError{Classification: "provider_error", Message: "temporary failure", Retryable: true}
		return result, errors.New("temporary failure")
	}
	return result, nil
}

type postgresWorkflowRetryArtifacts struct {
	acquireErr error
	guard      artifact.PublisherGuard
}

func (postgresWorkflowRetryArtifacts) Identity() artifact.StoreIdentity {
	return artifact.StoreIdentity{ArtifactStoreID: testArtifactStoreID, IncarnationNonce: testArtifactStoreNonce, BackendKind: artifact.BackendKind, MarkerFormat: artifact.MarkerFormat, MarkerVersion: artifact.MarkerVersion}
}

func (s postgresWorkflowRetryArtifacts) AcquirePublisher(_ context.Context, expected artifact.StoreIdentity) (artifact.PublisherGuard, error) {
	if expected != s.Identity() {
		return nil, fmt.Errorf("test publisher identity mismatch")
	}
	if s.acquireErr != nil {
		return nil, s.acquireErr
	}
	if s.guard != nil {
		return s.guard, nil
	}
	return &postgresWorkflowRetryPublisher{identity: expected, prepared: make(map[string][]byte)}, nil
}

type postgresWorkflowRetryPublisher struct {
	identity artifact.StoreIdentity
	prepared map[string][]byte
}

func (p *postgresWorkflowRetryPublisher) Identity() artifact.StoreIdentity { return p.identity }

func (p *postgresWorkflowRetryPublisher) StagePrepared(_ context.Context, request artifact.PreparedStageRequest) (artifact.PreparedStageReceipt, error) {
	if err := request.ValidateCapacity(); err != nil {
		return artifact.PreparedStageReceipt{}, err
	}
	manifest, err := domain.DecodePreparedManifestV1(request.ManifestJSON)
	if err != nil {
		return artifact.PreparedStageReceipt{}, err
	}
	manifestKey, _ := domain.PreparedManifestKey(request.SetID)
	if manifest.SetID != request.SetID || manifest.ManifestID != request.ManifestID || manifest.ArtifactStoreID != p.identity.ArtifactStoreID || manifest.StoreIncarnationNonce != p.identity.IncarnationNonce || manifest.StoreBackendKind != p.identity.BackendKind || manifest.StoreMarkerFormat != p.identity.MarkerFormat || manifest.StoreMarkerVersion != p.identity.MarkerVersion || request.ManifestKey != manifestKey || request.Control.StorageKey != manifest.Control.StorageKey || request.Control.ExpectedSize != manifest.Control.ContentSizeBytes || artifact.DigestString(request.Control.ExpectedSHA256) != manifest.Control.ContentSHA256 || len(request.Members) != len(manifest.Members) {
		return artifact.PreparedStageReceipt{}, fmt.Errorf("test prepared manifest mismatch")
	}
	contentBytes := int64(0)
	objects := append([]artifact.PreparedStageObject{request.Control}, request.Members...)
	for index, object := range objects {
		if object.Source == nil {
			return artifact.PreparedStageReceipt{}, fmt.Errorf("test prepared source %d is nil", index)
		}
		if index > 0 {
			member := manifest.Members[index-1]
			if object.StorageKey != member.PreparedKey || object.ExpectedSize != member.ContentSizeBytes || artifact.DigestString(object.ExpectedSHA256) != member.ContentSHA256 {
				return artifact.PreparedStageReceipt{}, fmt.Errorf("test prepared member %d mismatch", index-1)
			}
		}
		reader, err := object.Source.Open()
		if err != nil {
			return artifact.PreparedStageReceipt{}, err
		}
		data, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || int64(len(data)) != object.ExpectedSize || artifact.DigestBytes(data) != object.ExpectedSHA256 {
			return artifact.PreparedStageReceipt{}, errors.Join(readErr, closeErr, fmt.Errorf("test prepared source %d mismatch", index))
		}
		p.prepared[object.StorageKey] = data
		contentBytes += int64(len(data))
	}
	p.prepared[request.ManifestKey] = append([]byte(nil), request.ManifestJSON...)
	return artifact.PreparedStageReceipt{ManifestSize: int64(len(request.ManifestJSON)), ManifestSHA256: artifact.DigestBytes(request.ManifestJSON), MemberCount: len(request.Members), ContentBytes: contentBytes, Durable: true}, nil
}

func (p *postgresWorkflowRetryPublisher) OpenPrepared(_ context.Context, key string, size int64, digest [32]byte) (io.ReadCloser, error) {
	data, ok := p.prepared[key]
	if !ok || int64(len(data)) != size || artifact.DigestBytes(data) != digest {
		return nil, fmt.Errorf("test prepared object mismatch")
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (p *postgresWorkflowRetryPublisher) PublishReserved(_ context.Context, reserved artifact.ReservedArtifactV1, source io.Reader) (artifact.PublishedArtifactV1, error) {
	if reserved.ArtifactStoreID != p.identity.ArtifactStoreID {
		return artifact.PublishedArtifactV1{}, fmt.Errorf("test publication store mismatch")
	}
	data, err := io.ReadAll(source)
	if err != nil {
		return artifact.PublishedArtifactV1{}, err
	}
	if int64(len(data)) != reserved.ExpectedSize || artifact.DigestBytes(data) != reserved.ExpectedSHA256 {
		return artifact.PublishedArtifactV1{}, fmt.Errorf("test publication content mismatch")
	}
	return artifact.PublishedArtifactV1{SizeBytes: int64(len(data)), SHA256: reserved.ExpectedSHA256, Durable: true}, nil
}

func (*postgresWorkflowRetryPublisher) Close() error { return nil }

type postgresInvalidPublisherGuard struct{ closeCalls int }

func (postgresInvalidPublisherGuard) Identity() artifact.StoreIdentity {
	return postgresWorkflowRetryArtifacts{}.Identity()
}
func (postgresInvalidPublisherGuard) PublishReserved(context.Context, artifact.ReservedArtifactV1, io.Reader) (artifact.PublishedArtifactV1, error) {
	return artifact.PublishedArtifactV1{}, errors.New("invalid publisher guard must not publish")
}
func (g *postgresInvalidPublisherGuard) Close() error {
	g.closeCalls++
	return nil
}

func (postgresWorkflowRetryArtifacts) Put(_ context.Context, req artifact.PutRequest) (domain.Artifact, error) {
	item := domain.Artifact{ID: domain.NewID(), TaskID: req.TaskID, WorkflowRunID: req.WorkflowRunID, StepRunID: req.StepRunID, ToolRunID: req.ToolRunID, Type: req.Type, ContentType: req.ContentType, Size: int64(len(req.Data)), SHA256: strings.Repeat("a", 64), CreatedAt: time.Now().UTC(), RedactionState: "redacted"}
	key, err := artifact.StorageKeyFor(item.ID)
	if err != nil {
		return domain.Artifact{}, err
	}
	storeID := testArtifactStoreID
	item.AddressingVersion, item.ArtifactStoreID, item.StorageKey = 1, &storeID, &key
	return item, nil
}

type postgresClassifyResumeCapability struct {
	calls             int
	store             *Store
	persistedInputs   []json.RawMessage
	persistedAttempts []int
}

func (*postgresClassifyResumeCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "classify.endpoint", Version: "5", Risk: policy.Low, RetrySafe: true, Idempotent: true, SupportedProviders: []string{"classifier"}}
}
func (*postgresClassifyResumeCapability) Validate(context.Context, capability.Request) error {
	return nil
}
func (c *postgresClassifyResumeCapability) Execute(ctx context.Context, req capability.Request) (capability.Result, error) {
	c.calls++
	var input json.RawMessage
	var attempt int
	if err := c.store.Pool.QueryRow(ctx, `SELECT input,attempt_count FROM step_runs WHERE id=$1`, req.Action.StepRunID).Scan(&input, &attempt); err != nil {
		return capability.Result{}, err
	}
	c.persistedInputs = append(c.persistedInputs, append(json.RawMessage(nil), input...))
	c.persistedAttempts = append(c.persistedAttempts, attempt)
	now := time.Now().UTC()
	exitCode := 0
	result := capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Summary: "classifier succeeded", Output: json.RawMessage(`{"endpoints":[],"classifications":[],"interesting_endpoints":[],"relationships":[],"source_derivations":[]}`)}, ToolRun: &domain.ToolRun{ID: domain.NewID(), StepRunID: req.Action.StepRunID, Capability: req.Action.Capability, Provider: req.Provider, ToolVersion: "5", SanitizedArguments: json.RawMessage(`{}`), ExecutionEnvironment: json.RawMessage(`{"kind":"integration"}`), StartedAt: now, CompletedAt: &now, ExitCode: &exitCode}}
	if c.calls == 1 {
		result.Action.Status = "failed"
		result.Action.Summary = "retryable classifier failure"
		result.Action.Error = &domain.StructuredError{Classification: "provider_error", Message: "temporary classifier failure", Retryable: true}
		return result, errors.New("temporary classifier failure")
	}
	return result, nil
}

type countingHistoricalStore struct {
	*Store
	historyLoads int
}

type concurrentEffectiveInputStore struct {
	*Store
	loads      atomic.Int32
	bothLoaded chan struct{}
}

func (s *concurrentEffectiveInputStore) LoadEffectiveStepInput(ctx context.Context, programID domain.ID, action domain.ActionRequest) (json.RawMessage, bool, error) {
	input, found, err := s.Store.LoadEffectiveStepInput(ctx, programID, action)
	if err != nil {
		return nil, false, err
	}
	if s.loads.Add(1) == 2 {
		close(s.bothLoaded)
	}
	<-s.bothLoaded
	return input, found, nil
}

type blockingAttemptCapability struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (*blockingAttemptCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "test.concurrent-attempt", Version: "1", Risk: policy.Low, RetrySafe: true, Idempotent: true}
}
func (*blockingAttemptCapability) Validate(context.Context, capability.Request) error { return nil }
func (c *blockingAttemptCapability) Execute(_ context.Context, req capability.Request) (capability.Result, error) {
	c.calls.Add(1)
	c.entered <- struct{}{}
	<-c.release
	return capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Summary: "claimed attempt executed"}}, nil
}

func (s *countingHistoricalStore) PreviousObservationValues(ctx context.Context, programID, runID domain.ID, capabilityName string) ([]string, error) {
	s.historyLoads++
	return s.Store.PreviousObservationValues(ctx, programID, runID, capabilityName)
}

func TestWorkflowResumePreservesHistoricalEffectiveInputAndAttemptProvenance(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "workflow-resume-effective-input")
	firstHistory := `{"provider":"httpx","kind":"url","target":"https://first-history.test/","status_code":200}`
	newerHistory := `{"provider":"httpx","kind":"url","target":"https://newer-history.test/","status_code":503}`
	insertCompletedHistoricalObservation(t, env, firstHistory, time.Now().UTC().Add(-time.Hour))

	now := time.Now().UTC().Truncate(time.Microsecond)
	task := domain.Task{ID: domain.NewID(), ProgramID: env.programID, Objective: "resume frozen historical input", WorkflowDefinitionID: env.definitionID, Status: domain.TaskRunning, RequestedBy: "integration-test", CreatedAt: now, UpdatedAt: now}
	if err := env.store.CreateTask(env.ctx, task); err != nil {
		t.Fatal(err)
	}
	baseInput := json.RawMessage(`{"active":[],"passive":[],"http_observations":[],"crawl_observations":[],"passive_observations":[],"historical_observations":[],"api_schema_endpoints":[],"target_plan_digest":"plan"}`)
	definition, scopeVersionID := syntheticWorkflowDefinition(t, env.store, env.ctx, task.ID)
	definition.Steps = []workflow.Step{{ID: "classify", Capability: "classify.endpoint", Provider: "classifier", Input: baseInput, Retry: workflow.RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond}}}
	materialized, digest, err := workflow.Materialize(definition)
	if err != nil {
		t.Fatal(err)
	}
	runID, stepID := domain.NewID(), domain.NewID()
	baseHash := workflow.InputDigest(baseInput)
	keySum := sha256.Sum256([]byte(string(runID) + "\x00classify\x00" + baseHash))
	state := &workflow.State{Run: domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: definition.ID, WorkflowVersion: definition.Version, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration-test", Summary: json.RawMessage(`{}`), MaterializedDefinition: materialized, MaterializationDigest: digest, OriginalScopeVersionID: &scopeVersionID}, Steps: map[string]*workflow.StepState{"classify": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "classify", Capability: "classify.endpoint", Status: domain.StepRunning, Input: baseInput, IdempotencyKey: hex.EncodeToString(keySum[:]), ApprovalState: "not_required"}, InputHash: baseHash}}}
	if err := env.store.SaveWorkflowState(env.ctx, state); err != nil {
		t.Fatal(err)
	}

	provider := &postgresClassifyResumeCapability{store: env.store}
	registry := capability.NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	countingStore := &countingHistoricalStore{Store: env.store}
	executor := execution.Service{Registry: registry, Store: countingStore, Artifacts: postgresWorkflowRetryArtifacts{}, ProgramID: env.programID}
	firstAction := domain.ActionRequest{ID: domain.NewID(), TaskID: task.ID, WorkflowRunID: runID, StepRunID: stepID, RequestedBy: "workflow", Capability: "classify.endpoint", Reason: "first durable attempt", Input: baseInput, IdempotencyKey: state.Steps["classify"].Run.IdempotencyKey, StepAttempt: 1}
	firstResult, firstErr := executor.Execute(env.ctx, capability.Request{Action: firstAction, Provider: "classifier", Policy: policy.Policy{AllowedCapabilities: []string{"classify.endpoint"}}, Scope: integrationAllowScope{}})
	if firstErr == nil || firstResult.Action.Error == nil || !firstResult.Action.Error.Retryable {
		t.Fatalf("first result=%#v error=%v", firstResult, firstErr)
	}
	frozenInput := append(json.RawMessage(nil), firstResult.EffectiveInput...)
	if countingStore.historyLoads != 1 || len(frozenInput) == 0 || strings.Contains(string(frozenInput), "newer-history") || !strings.Contains(string(frozenInput), "first-history") {
		t.Fatalf("history_loads=%d frozen_input=%s", countingStore.historyLoads, frozenInput)
	}

	insertCompletedHistoricalObservation(t, env, newerHistory, time.Now().UTC())
	resumedState, err := env.store.LoadWorkflowState(env.ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	engine := workflow.Engine{Registry: registry, Executor: executor, Persister: WorkflowPersister{Store: env.store, File: workflow.FileStore{Root: t.TempDir()}}, Policy: policy.Policy{AllowedCapabilities: []string{"classify.endpoint"}}, Scope: integrationAllowScope{}, OriginalScopeVersionID: scopeVersionID}
	resumedState, err = engine.Run(env.ctx, definition, resumedState, task, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resumedState.Run.Status != domain.RunCompleted || provider.calls != 2 || countingStore.historyLoads != 1 || len(provider.persistedAttempts) != 2 || provider.persistedAttempts[0] != 1 || provider.persistedAttempts[1] != 2 {
		t.Fatalf("status=%s calls=%d history_loads=%d attempts=%v", resumedState.Run.Status, provider.calls, countingStore.historyLoads, provider.persistedAttempts)
	}
	for index, input := range provider.persistedInputs {
		var equal bool
		if err := env.store.Pool.QueryRow(env.ctx, `SELECT $1::jsonb=$2::jsonb`, input, frozenInput).Scan(&equal); err != nil || !equal {
			t.Fatalf("provider input[%d]=%s frozen=%s equal=%v error=%v", index, input, frozenInput, equal, err)
		}
	}
	var attemptCount, acceptedAttemptTwo int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT attempt_count FROM step_runs WHERE id=$1`, stepID).Scan(&attemptCount); err != nil {
		t.Fatal(err)
	}
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT count(*) FROM audit_events accepted JOIN audit_events started ON started.id=accepted.provider_attempt_id WHERE accepted.event_type='provider_result_accepted' AND accepted.step_run_id=$1 AND started.event_type='provider_invocation_started' AND started.step_attempt=2 AND accepted.action_request_id=started.action_request_id`, stepID).Scan(&acceptedAttemptTwo); err != nil {
		t.Fatal(err)
	}
	if attemptCount != 2 || acceptedAttemptTwo != 1 {
		t.Fatalf("durable attempt_count=%d accepted_attempt_two=%d", attemptCount, acceptedAttemptTwo)
	}
}

func insertCompletedHistoricalObservation(t *testing.T, env recoveryTestEnvironment, raw string, completedAt time.Time) {
	t.Helper()
	task := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "historical-observation")
	state := &workflow.State{Run: domain.WorkflowRun{ID: domain.NewID(), TaskID: task.ID, Status: domain.RunCompleted, StartedAt: &completedAt, CompletedAt: &completedAt, TriggerSource: "integration", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{}}
	materializeSyntheticWorkflowState(t, env.store, env.ctx, state)
	if err := env.store.SaveWorkflowState(env.ctx, state); err != nil {
		t.Fatal(err)
	}
	assetID := domain.NewID()
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO assets(id,program_id,type,canonical_value) VALUES($1,$2,'url',$3)`, assetID, env.programID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.Pool.Exec(env.ctx, `INSERT INTO asset_observations(id,asset_id,workflow_run_id,source_capability,observed_value,metadata,first_seen_at,observed_at,confidence) VALUES($1,$2,$3,'probe.http',$4,$5,$6,$6,1)`, domain.NewID(), assetID, state.Run.ID, raw, json.RawMessage(raw), completedAt); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowRetryPersistsEveryProviderAttempt(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "workflow-provider-retry")
	now := time.Now().UTC()
	task := domain.Task{ID: domain.NewID(), ProgramID: env.programID, Objective: "workflow provider retry", WorkflowDefinitionID: env.definitionID, Status: domain.TaskRunning, RequestedBy: "integration-test", CreatedAt: now, UpdatedAt: now}
	if err := env.store.CreateTask(env.ctx, task); err != nil {
		t.Fatal(err)
	}
	provider := &postgresWorkflowRetryCapability{store: env.store}
	registry := capability.NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	definition, scopeVersionID := syntheticWorkflowDefinition(t, env.store, env.ctx, task.ID)
	definition.Steps = []workflow.Step{{ID: "retry", Capability: "test.workflow-retry", Input: json.RawMessage(`{}`), Retry: workflow.RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond}}}
	engine := workflow.Engine{
		Registry:               registry,
		Executor:               execution.Service{Registry: registry, Store: env.store, Artifacts: postgresWorkflowRetryArtifacts{}, ProgramID: env.programID},
		Persister:              WorkflowPersister{Store: env.store, File: workflow.FileStore{Root: t.TempDir()}},
		Policy:                 policy.Policy{AllowedCapabilities: []string{"test.workflow-retry"}},
		Scope:                  integrationAllowScope{},
		OriginalScopeVersionID: scopeVersionID,
	}
	state, err := engine.Run(env.ctx, definition, nil, task, nil)
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 2 || state.Run.Status != domain.RunCompleted || state.Steps["retry"].Run.Status != domain.StepSucceeded {
		t.Fatalf("calls=%d state=%#v", provider.calls, state)
	}
	if len(provider.persistedInputs) != 2 || string(provider.persistedInputs[0]) != `{}` || string(provider.persistedInputs[1]) != `{}` || len(provider.persistedAttempts) != 2 || provider.persistedAttempts[0] != 1 || provider.persistedAttempts[1] != 2 {
		t.Fatalf("provider observed inputs=%q attempts=%v", provider.persistedInputs, provider.persistedAttempts)
	}
	stepID := state.Steps["retry"].Run.ID
	var status domain.StepStatus
	var attemptCount, stepCount, toolCount, providerAttemptCount, artifactCount, artifactToolCount, toolExecutionCount, acceptedDecisionCount int
	var failedStdoutCount, failedDiagnosticCount, failedSemanticCount int
	var succeededStdoutCount, succeededDiagnosticCount, succeededSemanticCount int
	var failedPublicationCount, failedMinimumOrdinal, failedMaximumOrdinal int
	var succeededPublicationCount, succeededMinimumOrdinal, succeededMaximumOrdinal int
	var completedAt *time.Time
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT status,attempt_count,completed_at FROM step_runs WHERE id=$1`, stepID).Scan(&status, &attemptCount, &completedAt); err != nil {
		t.Fatal(err)
	}
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT
		(SELECT count(*) FROM step_runs WHERE workflow_run_id=$1 AND step_definition_id='retry'),
		(SELECT count(*) FROM tool_runs WHERE step_run_id=$2),
		(SELECT count(DISTINCT provider_attempt_id) FROM tool_runs WHERE step_run_id=$2),
		(SELECT count(*) FROM artifacts WHERE step_run_id=$2),
		(SELECT count(DISTINCT tool_run_id) FROM artifacts WHERE step_run_id=$2),
		(SELECT count(*) FROM audit_events WHERE step_run_id=$2 AND event_type='tool_execution'),
		(SELECT count(*) FROM audit_events WHERE step_run_id=$2 AND event_type='provider_result_accepted')`, state.Run.ID, stepID).Scan(&stepCount, &toolCount, &providerAttemptCount, &artifactCount, &artifactToolCount, &toolExecutionCount, &acceptedDecisionCount); err != nil {
		t.Fatal(err)
	}
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT
		count(*) FILTER (WHERE started.step_attempt=1 AND artifacts.type='raw-provider-output' AND artifacts.content_type='application/x-ndjson'),
		count(*) FILTER (WHERE started.step_attempt=1 AND artifacts.type='provider-diagnostic'),
		count(*) FILTER (WHERE started.step_attempt=1 AND artifacts.type='normalized-result' AND artifacts.content_type='application/json'),
		count(*) FILTER (WHERE started.step_attempt=2 AND artifacts.type='raw-provider-output' AND artifacts.content_type='application/x-ndjson'),
		count(*) FILTER (WHERE started.step_attempt=2 AND artifacts.type='provider-diagnostic'),
		count(*) FILTER (WHERE started.step_attempt=2 AND artifacts.type='normalized-result' AND artifacts.content_type='application/json'),
		count(*) FILTER (WHERE started.step_attempt=1),
		COALESCE(min(publications.publication_ordinal) FILTER (WHERE started.step_attempt=1),-1),
		COALESCE(max(publications.publication_ordinal) FILTER (WHERE started.step_attempt=1),-1),
		count(*) FILTER (WHERE started.step_attempt=2),
		COALESCE(min(publications.publication_ordinal) FILTER (WHERE started.step_attempt=2),-1),
		COALESCE(max(publications.publication_ordinal) FILTER (WHERE started.step_attempt=2),-1)
		FROM artifacts
		JOIN tool_runs tools ON tools.id=artifacts.tool_run_id
		JOIN audit_events started ON started.id=tools.provider_attempt_id AND started.event_type='provider_invocation_started'
		JOIN artifact_publications publications ON publications.artifact_id=artifacts.id
		WHERE artifacts.step_run_id=$1`, stepID).Scan(
		&failedStdoutCount, &failedDiagnosticCount, &failedSemanticCount,
		&succeededStdoutCount, &succeededDiagnosticCount, &succeededSemanticCount,
		&failedPublicationCount, &failedMinimumOrdinal, &failedMaximumOrdinal,
		&succeededPublicationCount, &succeededMinimumOrdinal, &succeededMaximumOrdinal,
	); err != nil {
		t.Fatal(err)
	}
	if status != domain.StepSucceeded || attemptCount != 2 || completedAt == nil || stepCount != 1 || toolCount != 2 || providerAttemptCount != 2 || artifactCount != 5 || artifactToolCount != 2 || toolExecutionCount != 2 || acceptedDecisionCount != 2 {
		t.Fatalf("status=%s attempt=%d completed=%v steps=%d tools=%d provider_attempts=%d artifacts=%d artifact_tools=%d tool_executions=%d accepted_decisions=%d", status, attemptCount, completedAt, stepCount, toolCount, providerAttemptCount, artifactCount, artifactToolCount, toolExecutionCount, acceptedDecisionCount)
	}
	if failedStdoutCount != 1 || failedDiagnosticCount != 1 || failedSemanticCount != 1 || failedPublicationCount != 3 || failedMinimumOrdinal != 0 || failedMaximumOrdinal != 2 {
		t.Fatalf("failed attempt evidence stdout=%d diagnostic=%d semantic=%d publications=%d ordinals=%d..%d", failedStdoutCount, failedDiagnosticCount, failedSemanticCount, failedPublicationCount, failedMinimumOrdinal, failedMaximumOrdinal)
	}
	if succeededStdoutCount != 1 || succeededDiagnosticCount != 0 || succeededSemanticCount != 1 || succeededPublicationCount != 2 || succeededMinimumOrdinal != 0 || succeededMaximumOrdinal != 1 {
		t.Fatalf("successful attempt evidence stdout=%d diagnostic=%d semantic=%d publications=%d ordinals=%d..%d", succeededStdoutCount, succeededDiagnosticCount, succeededSemanticCount, succeededPublicationCount, succeededMinimumOrdinal, succeededMaximumOrdinal)
	}
}

type effectiveInputCaptureStore struct {
	*Store
	proposed json.RawMessage
}

func (s *effectiveInputCaptureStore) PersistEffectiveStepInput(ctx context.Context, programID domain.ID, action domain.ActionRequest, proposed json.RawMessage) (json.RawMessage, error) {
	s.proposed = append(json.RawMessage(nil), proposed...)
	return s.Store.PersistEffectiveStepInput(ctx, programID, action, proposed)
}

func TestWorkflowPublisherAcquisitionFailurePersistsAuthoritativeEffectiveInput(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "publisher-acquisition-effective-input")
	now := time.Now().UTC()
	task := domain.Task{ID: domain.NewID(), ProgramID: env.programID, Objective: "publisher acquisition failure", WorkflowDefinitionID: env.definitionID, Status: domain.TaskRunning, RequestedBy: "integration-test", CreatedAt: now, UpdatedAt: now}
	if err := env.store.CreateTask(env.ctx, task); err != nil {
		t.Fatal(err)
	}
	provider := &postgresWorkflowRetryCapability{}
	registry := capability.NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	callerInput := json.RawMessage(`{"b":2,"a":1}`)
	definition, scopeVersionID := syntheticWorkflowDefinition(t, env.store, env.ctx, task.ID)
	definition.Steps = []workflow.Step{{ID: "publisher", Capability: "test.workflow-retry", Input: callerInput, Retry: workflow.RetryPolicy{MaxAttempts: 1}}}
	publisherErr := errors.New("publisher authority unavailable")
	capturingStore := &effectiveInputCaptureStore{Store: env.store}
	engine := workflow.Engine{
		Registry:               registry,
		Executor:               execution.Service{Registry: registry, Store: capturingStore, Artifacts: postgresWorkflowRetryArtifacts{acquireErr: publisherErr}, ProgramID: env.programID},
		Persister:              WorkflowPersister{Store: env.store, File: workflow.FileStore{Root: t.TempDir()}},
		Policy:                 policy.Policy{AllowedCapabilities: []string{"test.workflow-retry"}},
		Scope:                  integrationAllowScope{},
		OriginalScopeVersionID: scopeVersionID,
	}
	state, err := engine.Run(env.ctx, definition, nil, task, nil)
	if !errors.Is(err, publisherErr) || errors.Is(err, workflow.ErrEffectiveStepInputConflict) {
		t.Fatalf("workflow error=%v", err)
	}
	if state == nil || state.Run.Status != domain.RunFailed || state.Steps["publisher"] == nil || state.Steps["publisher"].Run.Status != domain.StepFailed {
		t.Fatalf("workflow state=%#v", state)
	}

	stepID := state.Steps["publisher"].Run.ID
	var runStatus domain.RunStatus
	var runCompleted, stepCompleted *time.Time
	var stepStatus domain.StepStatus
	var attemptCount int
	var classification, details string
	var persistedInput json.RawMessage
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT wr.status,wr.completed_at,sr.status,sr.attempt_count,sr.completed_at,sr.error_classification,sr.error_details,sr.input
		FROM workflow_runs wr JOIN step_runs sr ON sr.workflow_run_id=wr.id WHERE wr.id=$1 AND sr.id=$2`, state.Run.ID, stepID).Scan(&runStatus, &runCompleted, &stepStatus, &attemptCount, &stepCompleted, &classification, &details, &persistedInput); err != nil {
		t.Fatal(err)
	}
	if runStatus != domain.RunFailed || runCompleted == nil || stepStatus != domain.StepFailed || attemptCount != 1 || stepCompleted == nil || classification != "execution" || !strings.Contains(details, publisherErr.Error()) {
		t.Fatalf("run=%s completed=%v step=%s attempts=%d step_completed=%v classification=%q details=%q", runStatus, runCompleted, stepStatus, attemptCount, stepCompleted, classification, details)
	}
	if len(capturingStore.proposed) == 0 || bytes.Equal(capturingStore.proposed, persistedInput) || bytes.Equal(callerInput, persistedInput) {
		t.Fatalf("effective input was not PostgreSQL-authoritative: caller=%s proposed=%s persisted=%s", callerInput, capturingStore.proposed, persistedInput)
	}
	var semanticallyEqual bool
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT $1::jsonb=$2::jsonb`, capturingStore.proposed, persistedInput).Scan(&semanticallyEqual); err != nil || !semanticallyEqual {
		t.Fatalf("effective inputs are not semantically equal: proposed=%s persisted=%s equal=%v err=%v", capturingStore.proposed, persistedInput, semanticallyEqual, err)
	}

	var stepRows, providerCalls, toolRuns, artifacts, preparedSets, publications, secondAttempts int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT
		(SELECT count(*) FROM step_runs WHERE workflow_run_id=$1),
		(SELECT count(*) FROM audit_events WHERE workflow_run_id=$1 AND event_type='provider_invocation_started'),
		(SELECT count(*) FROM tool_runs WHERE step_run_id=$2),
		(SELECT count(*) FROM artifacts WHERE workflow_run_id=$1),
		(SELECT count(*) FROM prepared_evidence_sets WHERE workflow_run_id=$1),
		(SELECT count(*) FROM artifact_publications publications JOIN audit_events attempts ON attempts.id=publications.provider_attempt_id WHERE attempts.workflow_run_id=$1),
		(SELECT count(*) FROM audit_events WHERE step_run_id=$2 AND event_type='provider_invocation_started' AND step_attempt=2)`, state.Run.ID, stepID).Scan(&stepRows, &providerCalls, &toolRuns, &artifacts, &preparedSets, &publications, &secondAttempts); err != nil {
		t.Fatal(err)
	}
	if provider.calls != 0 || stepRows != 1 || providerCalls != 0 || toolRuns != 0 || artifacts != 0 || preparedSets != 0 || publications != 0 || secondAttempts != 0 {
		t.Fatalf("provider_calls=%d step_rows=%d provider_audits=%d tool_runs=%d artifacts=%d prepared_sets=%d publications=%d second_attempts=%d", provider.calls, stepRows, providerCalls, toolRuns, artifacts, preparedSets, publications, secondAttempts)
	}
}

func TestWorkflowPublisherGuardMismatchPersistsAuthoritativeEffectiveInput(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "publisher-guard-mismatch-effective-input")
	now := time.Now().UTC()
	task := domain.Task{ID: domain.NewID(), ProgramID: env.programID, Objective: "publisher guard mismatch", WorkflowDefinitionID: env.definitionID, Status: domain.TaskRunning, RequestedBy: "integration-test", CreatedAt: now, UpdatedAt: now}
	if err := env.store.CreateTask(env.ctx, task); err != nil {
		t.Fatal(err)
	}
	provider := &postgresWorkflowRetryCapability{}
	registry := capability.NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	callerInput := json.RawMessage(`{"b":2,"a":1}`)
	definition, scopeVersionID := syntheticWorkflowDefinition(t, env.store, env.ctx, task.ID)
	definition.Steps = []workflow.Step{{ID: "publisher", Capability: "test.workflow-retry", Input: callerInput, Retry: workflow.RetryPolicy{MaxAttempts: 1}}}
	guard := &postgresInvalidPublisherGuard{}
	capturingStore := &effectiveInputCaptureStore{Store: env.store}
	engine := workflow.Engine{
		Registry:               registry,
		Executor:               execution.Service{Registry: registry, Store: capturingStore, Artifacts: postgresWorkflowRetryArtifacts{guard: guard}, ProgramID: env.programID},
		Persister:              WorkflowPersister{Store: env.store, File: workflow.FileStore{Root: t.TempDir()}},
		Policy:                 policy.Policy{AllowedCapabilities: []string{"test.workflow-retry"}},
		Scope:                  integrationAllowScope{},
		OriginalScopeVersionID: scopeVersionID,
	}
	state, err := engine.Run(env.ctx, definition, nil, task, nil)
	if err == nil || errors.Is(err, workflow.ErrEffectiveStepInputConflict) || !strings.Contains(err.Error(), "artifact publisher lacks prepared-evidence capability") {
		t.Fatalf("workflow error=%v", err)
	}
	if guard.closeCalls != 1 || state == nil || state.Run.Status != domain.RunFailed || state.Steps["publisher"] == nil || state.Steps["publisher"].Run.Status != domain.StepFailed {
		t.Fatalf("guard_closes=%d workflow_state=%#v", guard.closeCalls, state)
	}

	stepID := state.Steps["publisher"].Run.ID
	var runStatus domain.RunStatus
	var runCompleted, stepCompleted *time.Time
	var stepStatus domain.StepStatus
	var attemptCount int
	var classification, details string
	var persistedInput json.RawMessage
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT wr.status,wr.completed_at,sr.status,sr.attempt_count,sr.completed_at,sr.error_classification,sr.error_details,sr.input
		FROM workflow_runs wr JOIN step_runs sr ON sr.workflow_run_id=wr.id WHERE wr.id=$1 AND sr.id=$2`, state.Run.ID, stepID).Scan(&runStatus, &runCompleted, &stepStatus, &attemptCount, &stepCompleted, &classification, &details, &persistedInput); err != nil {
		t.Fatal(err)
	}
	if runStatus != domain.RunFailed || runCompleted == nil || stepStatus != domain.StepFailed || attemptCount != 1 || stepCompleted == nil || classification != "execution" || !strings.Contains(details, "artifact publisher lacks prepared-evidence capability") {
		t.Fatalf("run=%s completed=%v step=%s attempts=%d step_completed=%v classification=%q details=%q", runStatus, runCompleted, stepStatus, attemptCount, stepCompleted, classification, details)
	}
	if len(capturingStore.proposed) == 0 || bytes.Equal(capturingStore.proposed, persistedInput) || bytes.Equal(callerInput, persistedInput) {
		t.Fatalf("effective input was not PostgreSQL-authoritative: caller=%s proposed=%s persisted=%s", callerInput, capturingStore.proposed, persistedInput)
	}
	var semanticallyEqual bool
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT $1::jsonb=$2::jsonb`, capturingStore.proposed, persistedInput).Scan(&semanticallyEqual); err != nil || !semanticallyEqual {
		t.Fatalf("effective inputs are not semantically equal: proposed=%s persisted=%s equal=%v err=%v", capturingStore.proposed, persistedInput, semanticallyEqual, err)
	}

	var stepRows, providerCalls, toolRuns, artifacts, preparedSets, publications, secondAttempts int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT
		(SELECT count(*) FROM step_runs WHERE workflow_run_id=$1),
		(SELECT count(*) FROM audit_events WHERE workflow_run_id=$1 AND event_type='provider_invocation_started'),
		(SELECT count(*) FROM tool_runs WHERE step_run_id=$2),
		(SELECT count(*) FROM artifacts WHERE workflow_run_id=$1),
		(SELECT count(*) FROM prepared_evidence_sets WHERE workflow_run_id=$1),
		(SELECT count(*) FROM artifact_publications publications JOIN audit_events attempts ON attempts.id=publications.provider_attempt_id WHERE attempts.workflow_run_id=$1),
		(SELECT count(*) FROM audit_events WHERE step_run_id=$2 AND event_type='provider_invocation_started' AND step_attempt=2)`, state.Run.ID, stepID).Scan(&stepRows, &providerCalls, &toolRuns, &artifacts, &preparedSets, &publications, &secondAttempts); err != nil {
		t.Fatal(err)
	}
	if provider.calls != 0 || stepRows != 1 || providerCalls != 0 || toolRuns != 0 || artifacts != 0 || preparedSets != 0 || publications != 0 || secondAttempts != 0 {
		t.Fatalf("provider_calls=%d step_rows=%d provider_audits=%d tool_runs=%d artifacts=%d prepared_sets=%d publications=%d second_attempts=%d", provider.calls, stepRows, providerCalls, toolRuns, artifacts, preparedSets, publications, secondAttempts)
	}
}

func TestEffectiveStepInputPersistenceConflictsBeforeProviderAdmission(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "effective-input-conflict")
	now := time.Now().UTC()
	task := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "effective-input-conflict")
	runID, stepID := domain.NewID(), domain.NewID()
	state := &workflow.State{
		Run:   domain.WorkflowRun{ID: runID, TaskID: task.ID, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{"classify": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "classify", Capability: "classify.endpoint", Status: domain.StepRunning, Input: json.RawMessage(`{"historical_observations":[]}`), IdempotencyKey: "effective-input-conflict", ApprovalState: "not_required"}}},
	}
	materializeSyntheticWorkflowState(t, env.store, env.ctx, state)
	if err := env.store.SaveWorkflowState(env.ctx, state); err != nil {
		t.Fatal(err)
	}
	action := domain.ActionRequest{ID: domain.NewID(), TaskID: task.ID, WorkflowRunID: runID, StepRunID: stepID, Capability: "classify.endpoint", IdempotencyKey: "effective-input-conflict", StepAttempt: 1}
	first := json.RawMessage(`{"historical_observations":[{"target":"https://first.test/"}]}`)
	persisted, err := env.store.PersistEffectiveStepInput(env.ctx, env.programID, action, first)
	if err != nil {
		t.Fatal(err)
	}
	var persistedEqual bool
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT $1::jsonb=$2::jsonb`, persisted, first).Scan(&persistedEqual); err != nil || !persistedEqual {
		t.Fatalf("first effective input=%s equal=%v err=%v", persisted, persistedEqual, err)
	}
	if _, err := env.store.PersistEffectiveStepInput(env.ctx, env.programID, action, json.RawMessage(`{"historical_observations":[{"target":"https://other.test/"}]}`)); !errors.Is(err, workflow.ErrEffectiveStepInputConflict) {
		t.Fatalf("different same-attempt input error=%v", err)
	}
	action.StepAttempt = 2
	loaded, found, err := env.store.LoadEffectiveStepInput(env.ctx, env.programID, action)
	if err != nil || !found {
		t.Fatalf("loaded effective input=%s found=%v err=%v", loaded, found, err)
	}
	var loadedEqual bool
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT $1::jsonb=$2::jsonb`, loaded, first).Scan(&loadedEqual); err != nil || !loadedEqual {
		t.Fatalf("loaded effective input=%s equal=%v err=%v", loaded, loadedEqual, err)
	}
	var attempt int
	var stored json.RawMessage
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT input,attempt_count FROM step_runs WHERE id=$1`, stepID).Scan(&stored, &attempt); err != nil || attempt != 1 {
		t.Fatalf("stored input=%s attempt=%d err=%v", stored, attempt, err)
	}
	var storedEqual bool
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT $1::jsonb=$2::jsonb`, stored, first).Scan(&storedEqual); err != nil || !storedEqual {
		t.Fatalf("stored effective input=%s equal=%v err=%v", stored, storedEqual, err)
	}
}

func TestConcurrentEffectiveStepAttemptIsOneShotBeforeProviderExecution(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "concurrent-effective-input-claim")
	now := time.Now().UTC()
	task := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "concurrent-effective-input-claim")
	runID, stepID := domain.NewID(), domain.NewID()
	frozen := json.RawMessage(`{"targets":["https://one.example.test/"]}`)
	state := &workflow.State{
		Run:   domain.WorkflowRun{ID: runID, TaskID: task.ID, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{"attempt": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "attempt", Capability: "test.concurrent-attempt", Status: domain.StepRunning, Input: frozen, IdempotencyKey: "concurrent-attempt", ApprovalState: "not_required"}, InputHash: workflow.InputDigest(frozen)}},
	}
	materializeSyntheticWorkflowState(t, env.store, env.ctx, state)
	if err := env.store.SaveWorkflowState(env.ctx, state); err != nil {
		t.Fatal(err)
	}
	first := domain.ActionRequest{ID: domain.NewID(), TaskID: task.ID, WorkflowRunID: runID, StepRunID: stepID, RequestedBy: "integration", Capability: "test.concurrent-attempt", Input: frozen, IdempotencyKey: "concurrent-attempt", StepAttempt: 1}
	if _, err := env.store.PersistEffectiveStepInput(env.ctx, env.programID, first, frozen); err != nil {
		t.Fatal(err)
	}

	provider := &blockingAttemptCapability{entered: make(chan struct{}, 1), release: make(chan struct{})}
	registry := capability.NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	barrierStore := &concurrentEffectiveInputStore{Store: env.store, bothLoaded: make(chan struct{})}
	service := execution.Service{Registry: registry, Store: barrierStore, Artifacts: postgresWorkflowRetryArtifacts{}, ProgramID: env.programID}
	type outcome struct{ err error }
	results := make(chan outcome, 2)
	for range 2 {
		action := first
		action.ID = domain.NewID()
		action.StepAttempt = 2
		go func() {
			_, err := service.Execute(env.ctx, capability.Request{Action: action, Policy: policy.Policy{ID: "concurrent-attempt", AllowedCapabilities: []string{"test.concurrent-attempt"}}, Scope: integrationAllowScope{}})
			results <- outcome{err: err}
		}()
	}
	select {
	case <-provider.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("provider did not receive the winning attempt")
	}
	var loser outcome
	select {
	case loser = <-results:
	case <-time.After(5 * time.Second):
		t.Fatal("duplicate attempt did not fail while the winning provider was blocked")
	}
	if !errors.Is(loser.err, workflow.ErrStepAttemptOwnershipLost) || !errors.Is(loser.err, workflow.ErrEffectiveStepInputConflict) {
		t.Fatalf("duplicate attempt error=%v", loser.err)
	}
	close(provider.release)
	select {
	case winner := <-results:
		if winner.err != nil {
			t.Fatalf("winning attempt error=%v", winner.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("winning attempt did not finish")
	}
	var attemptCount, attemptTwoStarts int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT attempt_count FROM step_runs WHERE id=$1`, stepID).Scan(&attemptCount); err != nil {
		t.Fatal(err)
	}
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type='provider_invocation_started' AND step_attempt=2`, stepID).Scan(&attemptTwoStarts); err != nil {
		t.Fatal(err)
	}
	if provider.calls.Load() != 1 || attemptTwoStarts != 1 || attemptCount != 2 {
		t.Fatalf("provider calls=%d provider starts=%d durable attempt=%d", provider.calls.Load(), attemptTwoStarts, attemptCount)
	}
}

func TestTwoCompleteEnginesCannotLetLosingAttemptClaimOverwriteWinnerLifecycle(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "two-engine-attempt-ownership")
	now := time.Now().UTC().Truncate(time.Microsecond)
	task := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "two-engine-attempt-ownership")
	definition, scopeVersionID := syntheticWorkflowDefinition(t, env.store, env.ctx, task.ID)
	definition.Steps = []workflow.Step{{ID: "attempt", Capability: "test.concurrent-attempt", Input: json.RawMessage(`{"targets":["https://one.example.test/"]}`), Retry: workflow.RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond}}}
	materialized, digest, err := workflow.Materialize(definition)
	if err != nil {
		t.Fatal(err)
	}
	runID, stepID := domain.NewID(), domain.NewID()
	input := append(json.RawMessage(nil), definition.Steps[0].Input...)
	inputHash := workflow.InputDigest(input)
	keySum := sha256.Sum256([]byte(string(runID) + "\x00attempt\x00" + inputHash))
	idempotencyKey := hex.EncodeToString(keySum[:])
	initial := &workflow.State{
		Run:   domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: definition.ID, WorkflowVersion: definition.Version, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration", Summary: json.RawMessage(`{}`), MaterializedDefinition: materialized, MaterializationDigest: digest, OriginalScopeVersionID: &scopeVersionID},
		Steps: map[string]*workflow.StepState{"attempt": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "attempt", Capability: "test.concurrent-attempt", Status: domain.StepRunning, Input: input, StartedAt: &now, IdempotencyKey: idempotencyKey, ApprovalState: "not_required"}, InputHash: inputHash}},
	}
	if err := env.store.SaveWorkflowState(env.ctx, initial); err != nil {
		t.Fatal(err)
	}
	firstAction := domain.ActionRequest{ID: domain.NewID(), TaskID: task.ID, WorkflowRunID: runID, StepRunID: stepID, RequestedBy: "workflow", Capability: "test.concurrent-attempt", Input: input, IdempotencyKey: idempotencyKey, StepAttempt: 1}
	if _, err := env.store.PersistEffectiveStepInput(env.ctx, env.programID, firstAction, input); err != nil {
		t.Fatal(err)
	}
	retryable := domain.StepRun{ID: stepID, WorkflowRunID: runID, Capability: "test.concurrent-attempt", Status: domain.StepRetryable, ErrorClassification: "provider_error", ErrorDetails: "first attempt is retryable", IdempotencyKey: idempotencyKey}
	retryableResult := domain.ActionResult{RequestID: firstAction.ID, Status: "failed", Summary: "retryable setup result", Error: &domain.StructuredError{Classification: "provider_error", Message: "first attempt is retryable", Retryable: true}}
	if err := env.store.PersistResult(env.ctx, env.programID, retryable, nil, nil, retryableResult, nil); err != nil {
		t.Fatal(err)
	}
	stateA, err := env.store.LoadWorkflowState(env.ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	stateB, err := env.store.LoadWorkflowState(env.ctx, runID)
	if err != nil {
		t.Fatal(err)
	}

	provider := &blockingAttemptCapability{entered: make(chan struct{}, 1), release: make(chan struct{})}
	registry := capability.NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	barrierStore := &concurrentEffectiveInputStore{Store: env.store, bothLoaded: make(chan struct{})}
	type engineOutcome struct {
		state *workflow.State
		err   error
	}
	results := make(chan engineOutcome, 2)
	states := []*workflow.State{stateA, stateB}
	for index, candidate := range states {
		candidate := candidate
		root := t.TempDir()
		engine := workflow.Engine{
			Registry:  registry,
			Executor:  execution.Service{Registry: registry, Store: barrierStore, Artifacts: postgresWorkflowRetryArtifacts{}, ProgramID: env.programID},
			Persister: WorkflowPersister{Store: env.store, File: workflow.FileStore{Root: root}},
			Policy:    policy.Policy{ID: "two-engine-attempt", AllowedCapabilities: []string{"test.concurrent-attempt"}},
			Scope:     integrationAllowScope{}, OriginalScopeVersionID: scopeVersionID,
		}
		engineCtx, cancel := context.WithTimeout(env.ctx, 10*time.Second)
		defer cancel()
		go func(label int) {
			completed, runErr := engine.Run(engineCtx, definition, candidate, task, nil)
			results <- engineOutcome{state: completed, err: runErr}
		}(index)
	}
	select {
	case <-provider.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("winning engine did not enter provider execution")
	}
	var loser engineOutcome
	select {
	case loser = <-results:
	case <-time.After(5 * time.Second):
		t.Fatal("losing engine did not terminate while winner was blocked")
	}
	if !errors.Is(loser.err, workflow.ErrStepAttemptOwnershipLost) || loser.state == nil || loser.state.Run.Status == domain.RunFailed || loser.state.Steps["attempt"].Run.Status == domain.StepFailed {
		t.Fatalf("loser state=%#v error=%v", loser.state, loser.err)
	}
	var blockedRunStatus domain.RunStatus
	var blockedStepStatus domain.StepStatus
	var blockedAttempt, blockedFailedRuns, blockedFailedSteps int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT wr.status,sr.status,sr.attempt_count,(SELECT count(*) FROM workflow_runs WHERE id=$1 AND status='failed'),(SELECT count(*) FROM step_runs WHERE id=$2 AND status='failed') FROM workflow_runs wr JOIN step_runs sr ON sr.workflow_run_id=wr.id WHERE wr.id=$1 AND sr.id=$2`, runID, stepID).Scan(&blockedRunStatus, &blockedStepStatus, &blockedAttempt, &blockedFailedRuns, &blockedFailedSteps); err != nil {
		t.Fatal(err)
	}
	if blockedRunStatus != domain.RunRunning || blockedStepStatus != domain.StepRetryable || blockedAttempt != 2 || blockedFailedRuns != 0 || blockedFailedSteps != 0 || provider.calls.Load() != 1 {
		t.Fatalf("blocked lifecycle run=%s step=%s attempt=%d failed_runs=%d failed_steps=%d provider_calls=%d", blockedRunStatus, blockedStepStatus, blockedAttempt, blockedFailedRuns, blockedFailedSteps, provider.calls.Load())
	}
	close(provider.release)
	var winner engineOutcome
	select {
	case winner = <-results:
	case <-time.After(5 * time.Second):
		t.Fatal("winning engine did not finish")
	}
	if winner.err != nil || winner.state == nil || winner.state.Run.Status != domain.RunCompleted || winner.state.Steps["attempt"].Run.Status != domain.StepSucceeded {
		t.Fatalf("winner state=%#v error=%v", winner.state, winner.err)
	}
	var finalRunStatus domain.RunStatus
	var finalStepStatus domain.StepStatus
	var attemptTwoStarts, acceptedAttemptTwo int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT wr.status,sr.status,(SELECT count(*) FROM audit_events WHERE step_run_id=$2 AND event_type='provider_invocation_started' AND step_attempt=2),(SELECT count(*) FROM audit_events accepted JOIN audit_events started ON started.id=accepted.provider_attempt_id WHERE accepted.event_type='provider_result_accepted' AND accepted.step_run_id=$2 AND started.event_type='provider_invocation_started' AND started.step_attempt=2 AND accepted.action_request_id=started.action_request_id) FROM workflow_runs wr JOIN step_runs sr ON sr.workflow_run_id=wr.id WHERE wr.id=$1 AND sr.id=$2`, runID, stepID).Scan(&finalRunStatus, &finalStepStatus, &attemptTwoStarts, &acceptedAttemptTwo); err != nil {
		t.Fatal(err)
	}
	if finalRunStatus != domain.RunCompleted || finalStepStatus != domain.StepSucceeded || attemptTwoStarts != 1 || acceptedAttemptTwo != 1 || provider.calls.Load() != 1 {
		t.Fatalf("final lifecycle run=%s step=%s starts=%d accepted=%d provider_calls=%d", finalRunStatus, finalStepStatus, attemptTwoStarts, acceptedAttemptTwo, provider.calls.Load())
	}
}

func TestStaleWorkflowSaveCannotRegressEffectiveInputOrAttempt(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "stale-effective-input-save")
	now := time.Now().UTC()
	task := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "stale-effective-input-save")
	runID, stepID := domain.NewID(), domain.NewID()
	earlier := json.RawMessage(`{"targets":[]}`)
	frozen := json.RawMessage(`{"targets":["https://frozen.example.test/"]}`)
	stale := &workflow.State{
		Run:   domain.WorkflowRun{ID: runID, TaskID: task.ID, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{"attempt": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "attempt", Capability: "test.concurrent-attempt", Status: domain.StepRunning, Input: earlier, IdempotencyKey: "stale-attempt", ApprovalState: "not_required"}, InputHash: workflow.InputDigest(earlier)}},
	}
	materializeSyntheticWorkflowState(t, env.store, env.ctx, stale)
	if err := env.store.SaveWorkflowState(env.ctx, stale); err != nil {
		t.Fatal(err)
	}
	action := domain.ActionRequest{ID: domain.NewID(), TaskID: task.ID, WorkflowRunID: runID, StepRunID: stepID, Capability: "test.concurrent-attempt", IdempotencyKey: "stale-attempt", StepAttempt: 1}
	if _, err := env.store.PersistEffectiveStepInput(env.ctx, env.programID, action, frozen); err != nil {
		t.Fatal(err)
	}
	action.ID = domain.NewID()
	action.StepAttempt = 2
	if _, err := env.store.PersistEffectiveStepInput(env.ctx, env.programID, action, frozen); err != nil {
		t.Fatal(err)
	}
	if err := env.store.SaveWorkflowState(env.ctx, stale); !errors.Is(err, workflow.ErrEffectiveStepInputConflict) {
		t.Fatalf("stale count/input save error=%v", err)
	}
	authoritative, err := env.store.LoadWorkflowState(env.ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	step := authoritative.Steps["attempt"]
	if step.Run.AttemptCount != 2 || step.InputHash != workflow.InputDigest(step.Run.Input) || !strings.Contains(string(step.Run.Input), "frozen.example.test") {
		t.Fatalf("authoritative step=%#v", step)
	}
	step.InputHash = strings.Repeat("0", 64)
	if err := env.store.SaveWorkflowState(env.ctx, authoritative); !errors.Is(err, workflow.ErrEffectiveStepInputConflict) {
		t.Fatalf("alternate input hash save error=%v", err)
	}
	step.InputHash = workflow.InputDigest(step.Run.Input)
	step.Run.Input = json.RawMessage(`{"targets":["https://alternate.example.test/"]}`)
	step.InputHash = workflow.InputDigest(step.Run.Input)
	if err := env.store.SaveWorkflowState(env.ctx, authoritative); !errors.Is(err, workflow.ErrEffectiveStepInputConflict) {
		t.Fatalf("alternate frozen input save error=%v", err)
	}
	reloaded, err := env.store.LoadWorkflowState(env.ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Steps["attempt"].Run.AttemptCount != 2 || !strings.Contains(string(reloaded.Steps["attempt"].Run.Input), "frozen.example.test") {
		t.Fatalf("regressed durable step=%#v", reloaded.Steps["attempt"])
	}
}

func TestCrashAfterAttemptAllocationConsumesAttempt(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "crash-after-attempt-allocation")
	now := time.Now().UTC()
	task := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "crash-after-attempt-allocation")
	runID, stepID := domain.NewID(), domain.NewID()
	frozen := json.RawMessage(`{"targets":["https://resume.example.test/"]}`)
	state := &workflow.State{
		Run:   domain.WorkflowRun{ID: runID, TaskID: task.ID, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{"attempt": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "attempt", Capability: "test.concurrent-attempt", Status: domain.StepRunning, Input: frozen, IdempotencyKey: "crash-attempt", ApprovalState: "not_required"}, InputHash: workflow.InputDigest(frozen)}},
	}
	materializeSyntheticWorkflowState(t, env.store, env.ctx, state)
	if err := env.store.SaveWorkflowState(env.ctx, state); err != nil {
		t.Fatal(err)
	}
	action := domain.ActionRequest{ID: domain.NewID(), TaskID: task.ID, WorkflowRunID: runID, StepRunID: stepID, Capability: "test.concurrent-attempt", Input: frozen, IdempotencyKey: "crash-attempt", StepAttempt: 1}
	if _, err := env.store.PersistEffectiveStepInput(env.ctx, env.programID, action, frozen); err != nil {
		t.Fatal(err)
	}
	resumed, err := env.store.LoadWorkflowState(env.ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.Steps["attempt"].Run.AttemptCount != 1 {
		t.Fatalf("resumed attempt=%d", resumed.Steps["attempt"].Run.AttemptCount)
	}
	if _, err := env.store.PersistEffectiveStepInput(env.ctx, env.programID, action, frozen); !errors.Is(err, workflow.ErrEffectiveStepInputConflict) {
		t.Fatalf("reused consumed attempt error=%v", err)
	}
	action.ID = domain.NewID()
	action.StepAttempt = resumed.Steps["attempt"].Run.AttemptCount + 1
	if _, err := env.store.PersistEffectiveStepInput(env.ctx, env.programID, action, frozen); err != nil {
		t.Fatalf("next bounded attempt %d: %v", action.StepAttempt, err)
	}
	var attemptCount int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT attempt_count FROM step_runs WHERE id=$1`, stepID).Scan(&attemptCount); err != nil || attemptCount != 2 {
		t.Fatalf("durable attempt=%d err=%v", attemptCount, err)
	}
}

func TestPostgresPersistsFailedExecutionLineage(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	schema := "persist_result_" + strings.ReplaceAll(string(domain.NewID()), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop integration schema: %v", err)
		}
	}()

	u, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	store, err := Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	ensureTestArtifactStore(t, ctx, store)

	now := time.Now().UTC()
	programID, definitionID, taskID := domain.NewID(), domain.NewID(), domain.NewID()
	program := domain.Program{
		ID: programID, Name: "persistence-" + string(programID), Platform: "integration", Description: "synthetic local integration data",
		ScopeReference: "synthetic://local", PolicyReference: "integration", ScopeDigest: "scope", IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{},
		TargetPlanDigest: "plan", ScopePlanWarnings: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now,
	}
	snapshot := domain.ScopeSnapshot{ScopeReference: program.ScopeReference, ScopeDigest: program.ScopeDigest, IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: program.TargetPlanDigest, PlanningWarnings: json.RawMessage(`[]`), TargetPlan: json.RawMessage(`{}`), CreatedAt: now}
	if err := store.CreateProgram(ctx, program, snapshot); err != nil {
		t.Fatal(err)
	}
	ensureSyntheticWorkflowTemplate(t, store, ctx, definitionID, "persistence-"+string(definitionID))
	task := domain.Task{ID: taskID, ProgramID: programID, Objective: "verify failure persistence", WorkflowDefinitionID: definitionID, Status: domain.TaskRunning, RequestedBy: "integration-test", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateTask(ctx, task); err != nil {
		t.Fatal(err)
	}

	runID, stepID, toolID, artifactID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	state := &workflow.State{
		Run:   domain.WorkflowRun{ID: runID, TaskID: taskID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration-test", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{"dns": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "dns", Capability: "resolve.dns", Status: domain.StepRunning, Input: json.RawMessage(`{"targets":["https://local.example.test/"]}`), IdempotencyKey: string(domain.NewID()), ApprovalState: "not_required"}}},
	}
	materializeSyntheticWorkflowState(t, store, ctx, state)
	if err := store.SaveWorkflowState(ctx, state); err != nil {
		t.Fatal(err)
	}
	altProgramID, altTaskID, altRunID, altStepID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	altProgram := program
	altProgram.ID = altProgramID
	altProgram.Name = "persistence-alt-" + string(altProgramID)
	if err := store.CreateProgram(ctx, altProgram, snapshot); err != nil {
		t.Fatal(err)
	}
	altTask := task
	altTask.ID = altTaskID
	altTask.Objective = "alternate valid terminal lineage"
	if err := store.CreateTask(ctx, altTask); err != nil {
		t.Fatal(err)
	}
	altState := &workflow.State{
		Run:   domain.WorkflowRun{ID: altRunID, TaskID: altTaskID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration-test", Summary: json.RawMessage(`{}`)},
		Steps: map[string]*workflow.StepState{"alternate": {Run: domain.StepRun{ID: altStepID, WorkflowRunID: altRunID, StepDefinitionID: "alternate", Capability: "alternate.capability", Status: domain.StepRunning, Input: json.RawMessage(`{}`), IdempotencyKey: string(domain.NewID()), ApprovalState: "not_required"}}},
	}
	materializeSyntheticWorkflowState(t, store, ctx, altState)
	if err := store.SaveWorkflowState(ctx, altState); err != nil {
		t.Fatal(err)
	}
	actionRequest := domain.ActionRequest{ID: domain.NewID(), TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, RequestedBy: "integration-test", Capability: "resolve.dns", Reason: "must not persist in provider provenance", Input: json.RawMessage(`{"target":"must-not-persist.example.test","token":"secret"}`), IdempotencyKey: state.Steps["dns"].Run.IdempotencyKey, StepAttempt: 1}
	dispatchAuthorizationID, err := store.RecordPolicyDecision(ctx, capability.PolicyDecisionRecord{ProgramID: programID, Action: actionRequest, Provider: "dnsx", PolicyID: "restricted", Phase: "dispatch", Evaluation: policy.Evaluation{Decision: policy.Allow, Reason: "synthetic dispatch allow"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordProviderInvocationStarted(ctx, capability.ProviderInvocationStartRecord{ProgramID: programID, TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, ActionRequestID: actionRequest.ID, StepAttempt: actionRequest.StepAttempt, ExecutionAuthorizationEventID: dispatchAuthorizationID, Capability: actionRequest.Capability, Provider: "dnsx", Actor: actionRequest.RequestedBy}); err == nil {
		t.Fatal("dispatch-phase ALLOW authorized a provider start")
	}
	var dispatchStarts int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event_type='provider_invocation_started' AND execution_authorization_event_id=$1`, dispatchAuthorizationID).Scan(&dispatchStarts); err != nil || dispatchStarts != 0 {
		t.Fatalf("dispatch authorization provider starts=%d err=%v", dispatchStarts, err)
	}
	authorizationID, err := store.RecordPolicyDecision(ctx, capability.PolicyDecisionRecord{ProgramID: programID, Action: actionRequest, Provider: "dnsx", PolicyID: "restricted", Phase: "execution", Evaluation: policy.Evaluation{Decision: policy.Allow, Reason: "synthetic allow"}})
	if err != nil {
		t.Fatal(err)
	}
	validStart := capability.ProviderInvocationStartRecord{ProgramID: programID, TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, ActionRequestID: actionRequest.ID, StepAttempt: actionRequest.StepAttempt, ExecutionAuthorizationEventID: authorizationID, Capability: actionRequest.Capability, Provider: "dnsx", Actor: actionRequest.RequestedBy}
	altQueueID := domain.NewID()
	for _, test := range []struct {
		name   string
		mutate func(*capability.ProviderInvocationStartRecord)
	}{
		{name: "program", mutate: func(record *capability.ProviderInvocationStartRecord) { record.ProgramID = altProgramID }},
		{name: "task", mutate: func(record *capability.ProviderInvocationStartRecord) { record.TaskID = altTaskID }},
		{name: "workflow", mutate: func(record *capability.ProviderInvocationStartRecord) { record.WorkflowRunID = altRunID }},
		{name: "step", mutate: func(record *capability.ProviderInvocationStartRecord) { record.StepRunID = altStepID }},
		{name: "action", mutate: func(record *capability.ProviderInvocationStartRecord) { record.ActionRequestID = domain.NewID() }},
		{name: "step attempt", mutate: func(record *capability.ProviderInvocationStartRecord) { record.StepAttempt++ }},
		{name: "queue job", mutate: func(record *capability.ProviderInvocationStartRecord) { record.QueueJobID = &altQueueID }},
		{name: "authorization", mutate: func(record *capability.ProviderInvocationStartRecord) {
			record.ExecutionAuthorizationEventID = dispatchAuthorizationID
		}},
		{name: "capability", mutate: func(record *capability.ProviderInvocationStartRecord) { record.Capability = "alternate.capability" }},
		{name: "provider", mutate: func(record *capability.ProviderInvocationStartRecord) { record.Provider = "alternate-provider" }},
	} {
		t.Run("provider start rejects mismatched "+test.name, func(t *testing.T) {
			record := validStart
			test.mutate(&record)
			if _, err := store.RecordProviderInvocationStarted(ctx, record); err == nil {
				t.Fatalf("provider start accepted mismatched %s", test.name)
			}
		})
	}
	providerAttemptID, err := store.RecordProviderInvocationStarted(ctx, validStart)
	if err != nil {
		t.Fatal(err)
	}
	var committedStart int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE id=$1 AND event_type='provider_invocation_started'`, providerAttemptID).Scan(&committedStart); err != nil || committedStart != 1 {
		t.Fatalf("provider start was not committed before callback boundary: count=%d err=%v", committedStart, err)
	}
	validTerminal := capability.ProviderInvocationTerminalRecord{ProviderAttemptID: providerAttemptID, ProgramID: programID, TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, Capability: actionRequest.Capability, Provider: "dnsx", Actor: actionRequest.RequestedBy, Outcome: capability.ProviderInvocationFailed}
	for _, test := range []struct {
		name   string
		mutate func(*capability.ProviderInvocationTerminalRecord)
	}{
		{name: "program", mutate: func(record *capability.ProviderInvocationTerminalRecord) { record.ProgramID = altProgramID }},
		{name: "task", mutate: func(record *capability.ProviderInvocationTerminalRecord) { record.TaskID = altTaskID }},
		{name: "workflow", mutate: func(record *capability.ProviderInvocationTerminalRecord) { record.WorkflowRunID = altRunID }},
		{name: "step", mutate: func(record *capability.ProviderInvocationTerminalRecord) { record.StepRunID = altStepID }},
		{name: "capability", mutate: func(record *capability.ProviderInvocationTerminalRecord) { record.Capability = "alternate.capability" }},
		{name: "provider", mutate: func(record *capability.ProviderInvocationTerminalRecord) { record.Provider = "alternate-provider" }},
	} {
		t.Run("terminal rejects mismatched "+test.name, func(t *testing.T) {
			record := validTerminal
			test.mutate(&record)
			if err := store.RecordProviderInvocationTerminal(ctx, record); err == nil {
				t.Fatalf("terminal accepted mismatched %s", test.name)
			}
			var terminals int
			if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE provider_attempt_id=$1 AND event_type IN ('provider_invocation_succeeded','provider_invocation_failed','provider_invocation_cancelled')`, providerAttemptID).Scan(&terminals); err != nil || terminals != 0 {
				t.Fatalf("mismatched terminal rows=%d err=%v", terminals, err)
			}
		})
	}
	if err := store.RecordProviderInvocationTerminal(ctx, validTerminal); err != nil {
		t.Fatal(err)
	}
	var terminalActor, terminalCapability, terminalProvider string
	var terminalTask, terminalProgram, terminalRun, terminalStep, terminalAttempt domain.ID
	var terminalScheduled *domain.ID
	var terminalSchedulerAttempt *int
	if err := store.Pool.QueryRow(ctx, `SELECT actor,task_id,program_id,workflow_run_id,step_run_id,scheduled_execution_id,scheduler_attempt,provider_attempt_id,capability,provider FROM audit_events WHERE provider_attempt_id=$1 AND event_type='provider_invocation_failed'`, providerAttemptID).Scan(&terminalActor, &terminalTask, &terminalProgram, &terminalRun, &terminalStep, &terminalScheduled, &terminalSchedulerAttempt, &terminalAttempt, &terminalCapability, &terminalProvider); err != nil {
		t.Fatal(err)
	}
	if terminalActor != actionRequest.RequestedBy || terminalTask != taskID || terminalProgram != programID || terminalRun != runID || terminalStep != stepID || terminalScheduled != nil || terminalSchedulerAttempt != nil || terminalAttempt != providerAttemptID || terminalCapability != actionRequest.Capability || terminalProvider != "dnsx" {
		t.Fatalf("terminal lineage actor=%q task=%s program=%s run=%s step=%s scheduled=%v scheduler_attempt=%v attempt=%s capability=%q provider=%q", terminalActor, terminalTask, terminalProgram, terminalRun, terminalStep, terminalScheduled, terminalSchedulerAttempt, terminalAttempt, terminalCapability, terminalProvider)
	}

	exitCode := 1
	completed := now.Add(time.Second)
	tool := &domain.ToolRun{ID: toolID, StepRunID: stepID, Capability: "resolve.dns", Provider: "dnsx", ToolVersion: "test", SanitizedArguments: json.RawMessage(`{"stdin_bytes":19}`), ExecutionEnvironment: json.RawMessage(`{"kind":"local-process","shell":false}`), StartedAt: now, CompletedAt: &completed, ExitCode: &exitCode, StderrArtifactID: &artifactID, ProviderAttemptID: &providerAttemptID}
	expires := now.Add(-time.Minute)
	artifact := withTestArtifactAddress(domain.Artifact{ID: artifactID, TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, ToolRunID: toolID, Type: "raw-provider-output", ContentType: "text/plain", Size: 24, SHA256: strings.Repeat("a", 64), CreatedAt: completed, ExpiresAt: &expires, RedactionState: "redacted"})
	step := domain.StepRun{ID: stepID, WorkflowRunID: runID, Capability: "resolve.dns", Status: domain.StepFailed, Output: json.RawMessage(`{"lines":[],"authorized":[],"filtered":[]}`), ErrorClassification: "provider_error", ErrorDetails: "exit status 1: fake DNS failure", CompletedAt: &completed, IdempotencyKey: state.Steps["dns"].Run.IdempotencyKey}
	action := domain.ActionResult{RequestID: actionRequest.ID, Status: "failed", Summary: "dnsx execution failed", Output: step.Output, Error: &domain.StructuredError{Classification: "provider_error", Message: step.ErrorDetails}}
	admission := &capability.ResultAdmissionProvenance{ProviderAttemptID: providerAttemptID, ActionRequestID: actionRequest.ID, StepAttempt: actionRequest.StepAttempt, ExecutionAuthorizationEventID: authorizationID, Provider: "dnsx"}
	wrongTool := *tool
	wrongTool.ProviderAttemptID = &authorizationID
	if err := store.PersistResult(ctx, programID, step, &wrongTool, []domain.Artifact{artifact}, action, admission); !errors.Is(err, ErrWorkflowResultConflict) {
		t.Fatalf("non-start provider attempt link error=%v", err)
	}
	if err := store.PersistResult(ctx, programID, step, tool, []domain.Artifact{artifact}, action, nil); !errors.Is(err, ErrWorkflowResultConflict) {
		t.Fatalf("provider-attempt ToolRun without trusted admission provenance error=%v", err)
	}
	if err := store.PersistResult(ctx, programID, step, tool, []domain.Artifact{artifact}, action, admission); err != nil {
		t.Fatal(err)
	}
	var acceptedDecisions, rejectedDecisions int
	if err := store.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM audit_events WHERE event_type='provider_result_accepted' AND provider_attempt_id=$1),
		(SELECT count(*) FROM audit_events WHERE event_type='provider_result_rejected' AND provider_attempt_id=$1 AND details->>'reason_code'='provider_provenance_mismatch')`, providerAttemptID).Scan(&acceptedDecisions, &rejectedDecisions); err != nil {
		t.Fatal(err)
	}
	if acceptedDecisions != 1 || rejectedDecisions != 1 {
		t.Fatalf("provider result decisions accepted=%d rejected=%d", acceptedDecisions, rejectedDecisions)
	}

	var status domain.StepStatus
	var classification, details string
	if err := store.Pool.QueryRow(ctx, `SELECT status,error_classification,error_details FROM step_runs WHERE id=$1`, stepID).Scan(&status, &classification, &details); err != nil {
		t.Fatal(err)
	}
	if status != domain.StepFailed || classification != step.ErrorClassification || details != step.ErrorDetails {
		t.Fatalf("failed step mismatch: status=%s classification=%q details=%q", status, classification, details)
	}
	var storedExit int
	var stderrID, storedProviderAttempt domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT exit_code,stderr_artifact_id,provider_attempt_id FROM tool_runs WHERE id=$1`, toolID).Scan(&storedExit, &stderrID, &storedProviderAttempt); err != nil {
		t.Fatal(err)
	}
	if storedExit != exitCode || stderrID != artifactID || storedProviderAttempt != providerAttemptID {
		t.Fatalf("failed tool mismatch: exit=%d stderr=%s provider_attempt=%s", storedExit, stderrID, storedProviderAttempt)
	}
	var startAuthorization, startAction domain.ID
	var startAttempt int
	var startProvider *domain.ID
	var startDetails string
	if err := store.Pool.QueryRow(ctx, `SELECT execution_authorization_event_id,action_request_id,step_attempt,provider_attempt_id,details::text FROM audit_events WHERE id=$1`, providerAttemptID).Scan(&startAuthorization, &startAction, &startAttempt, &startProvider, &startDetails); err != nil {
		t.Fatal(err)
	}
	if startAuthorization != authorizationID || startAction != actionRequest.ID || startAttempt != 1 || startProvider != nil || startDetails != "{}" {
		t.Fatalf("start provenance authorization=%s action=%s attempt=%d provider=%v details=%s", startAuthorization, startAction, startAttempt, startProvider, startDetails)
	}
	var executionProvider, executionAction domain.ID
	var executionAttempt int
	var executionQueue *domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT provider_attempt_id,action_request_id,step_attempt,queue_job_id FROM audit_events WHERE event_type='tool_execution' AND tool_run_id=$1`, toolID).Scan(&executionProvider, &executionAction, &executionAttempt, &executionQueue); err != nil {
		t.Fatal(err)
	}
	if executionProvider != providerAttemptID || executionAction != actionRequest.ID || executionAttempt != 1 || executionQueue != nil {
		t.Fatalf("tool_execution provenance provider=%s action=%s attempt=%d queue=%v", executionProvider, executionAction, executionAttempt, executionQueue)
	}
	var storedTask, storedRun, storedStep, storedTool domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT task_id,workflow_run_id,step_run_id,tool_run_id FROM artifacts WHERE id=$1`, artifactID).Scan(&storedTask, &storedRun, &storedStep, &storedTool); err != nil {
		t.Fatal(err)
	}
	if storedTask != taskID || storedRun != runID || storedStep != stepID || storedTool != toolID {
		t.Fatalf("artifact lineage mismatch: task=%s run=%s step=%s tool=%s", storedTask, storedRun, storedStep, storedTool)
	}
	if _, err := store.RecordPolicyDecision(ctx, capability.PolicyDecisionRecord{ProgramID: programID, Action: domain.ActionRequest{TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, Capability: "resolve.dns", RequestedBy: "integration-test"}, Provider: "dnsx", PolicyID: "restricted", Phase: "execution", Evaluation: policy.Evaluation{Decision: policy.Deny, Reason: "synthetic denial"}}); err != nil {
		t.Fatal(err)
	}
	var policyEvents int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type='policy_denied'`, stepID).Scan(&policyEvents); err != nil || policyEvents != 1 {
		t.Fatalf("policy audit count=%d err=%v", policyEvents, err)
	}

	provenanceStepID := domain.NewID()
	provenanceKey := string(domain.NewID())
	if _, err := store.Pool.Exec(ctx, `INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,input,idempotency_key) VALUES($1,$2,'provider-provenance','test.provenance','running','{}',$3)`, provenanceStepID, runID, provenanceKey); err != nil {
		t.Fatal(err)
	}
	registry := capability.NewRegistry()
	provider := &postgresProvenanceCapability{}
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	rejectedAction := domain.ActionRequest{ID: domain.NewID(), TaskID: taskID, WorkflowRunID: runID, StepRunID: provenanceStepID, RequestedBy: "integration-test", Capability: "test.provenance", Input: json.RawMessage(`{}`), IdempotencyKey: provenanceKey, StepAttempt: 1}
	if _, err := registry.Execute(ctx, capability.Request{Action: rejectedAction, ProgramID: programID, Policy: policy.Policy{AllowedCapabilities: []string{"test.provenance"}}, Scope: integrationAllowScope{}, DecisionRecorder: store, InvocationRecorder: invalidPostgresStartRecorder{store: store}}); err == nil {
		t.Fatal("invalid provider start audit unexpectedly succeeded")
	}
	if provider.calls != 0 {
		t.Fatalf("provider callback ran after rejected start: calls=%d", provider.calls)
	}

	observedStartID := domain.ID("")
	detachedCtx, cancelDetached := context.WithCancel(ctx)
	observingProvider := &postgresProvenanceCapability{store: store, startID: &observedStartID, cancel: cancelDetached}
	observingRegistry := capability.NewRegistry()
	if err := observingRegistry.Register(observingProvider); err != nil {
		t.Fatal(err)
	}
	observingAction := rejectedAction
	observingAction.ID = domain.NewID()
	observedResult, err := observingRegistry.Execute(detachedCtx, capability.Request{Action: observingAction, ProgramID: programID, Policy: policy.Policy{AllowedCapabilities: []string{"test.provenance"}}, Scope: integrationAllowScope{}, DecisionRecorder: store, InvocationRecorder: observingPostgresRecorder{store: store, startID: &observedStartID}})
	if err != nil {
		t.Fatalf("cancelled caller context prevented detached terminal persistence: %v", err)
	}
	if !observingProvider.startVisible || observingProvider.observationErr != nil || observedResult.ProviderAttemptID == nil || *observedResult.ProviderAttemptID != observedStartID {
		t.Fatalf("provider did not observe committed start: visible=%v observation_err=%v result=%#v start=%s", observingProvider.startVisible, observingProvider.observationErr, observedResult, observedStartID)
	}
	var detachedTerminals int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE provider_attempt_id=$1 AND event_type='provider_invocation_succeeded'`, observedStartID).Scan(&detachedTerminals); err != nil || detachedTerminals != 1 {
		t.Fatalf("detached terminal rows=%d err=%v", detachedTerminals, err)
	}

	// Prepared-result execution no longer calls RecordProviderInvocationTerminal:
	// SealPreparedEvidence inserts terminal provenance and seals the prepared set
	// in one PostgreSQL transaction. Service tests cover seal failure and unknown
	// acknowledgement without adoption or replay, but this integration suite has
	// no test-only injection point inside that exact PostgreSQL transaction.

	if _, err := store.Pool.Exec(ctx, `DELETE FROM artifacts WHERE id=$1`, artifactID); err == nil || !strings.Contains(err.Error(), "metadata deletion is prohibited") {
		t.Fatalf("artifact delete error=%v", err)
	}
	var artifactRows, expiryEvents int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM artifacts WHERE id=$1`, artifactID).Scan(&artifactRows); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type='artifact_expired'`, stepID).Scan(&expiryEvents); err != nil {
		t.Fatal(err)
	}
	if artifactRows != 1 || expiryEvents != 0 {
		t.Fatalf("artifact rows=%d expiry audits=%d", artifactRows, expiryEvents)
	}

	state.Steps["dns"].Run.Status = domain.StepRunning
	state.Steps["dns"].Run.Output = nil
	state.Steps["dns"].Run.ErrorClassification = ""
	state.Steps["dns"].Run.ErrorDetails = ""
	state.Steps["dns"].Run.CompletedAt = nil
	if err := store.SaveWorkflowState(ctx, state); !errors.Is(err, workflow.ErrEffectiveStepInputConflict) {
		t.Fatalf("stale attempt-0 save error=%v", err)
	}
	authoritative, err := store.LoadWorkflowState(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	authoritativeStep := authoritative.Steps["dns"]
	if authoritativeStep == nil || authoritativeStep.Run.Status != domain.StepFailed || authoritativeStep.Run.AttemptCount != 1 {
		t.Fatalf("authoritative failed step=%#v", authoritativeStep)
	}
	var authoritativeInput struct {
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal(authoritativeStep.Run.Input, &authoritativeInput); err != nil || len(authoritativeInput.Targets) != 1 || authoritativeInput.Targets[0] != "https://local.example.test/" || authoritativeStep.InputHash != workflow.InputDigest(authoritativeStep.Run.Input) {
		t.Fatalf("authoritative input=%s hash=%q", authoritativeStep.Run.Input, authoritativeStep.InputHash)
	}
	if authoritativeStep.Run.ErrorClassification != step.ErrorClassification || authoritativeStep.Run.ErrorDetails != step.ErrorDetails || authoritativeStep.Run.CompletedAt == nil || !authoritativeStep.Run.CompletedAt.Equal(completed.Truncate(time.Microsecond)) {
		t.Fatalf("authoritative terminal fields classification=%q details=%q completed=%v", authoritativeStep.Run.ErrorClassification, authoritativeStep.Run.ErrorDetails, authoritativeStep.Run.CompletedAt)
	}
	var stepCount, acceptedAfter, rejectedAfter, terminalAfter int
	var providerAttemptAfter domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM step_runs WHERE workflow_run_id=$1 AND step_definition_id='dns' AND idempotency_key=$2),
		(SELECT count(*) FROM audit_events WHERE event_type='provider_result_accepted' AND provider_attempt_id=$3),
		(SELECT count(*) FROM audit_events WHERE event_type='provider_result_rejected' AND provider_attempt_id=$3),
		(SELECT count(*) FROM audit_events WHERE event_type='provider_invocation_failed' AND provider_attempt_id=$3),
		(SELECT provider_attempt_id FROM tool_runs WHERE id=$4)`, runID, state.Steps["dns"].Run.IdempotencyKey, providerAttemptID, toolID).Scan(&stepCount, &acceptedAfter, &rejectedAfter, &terminalAfter, &providerAttemptAfter); err != nil {
		t.Fatal(err)
	}
	if stepCount != 1 {
		t.Fatalf("stale save left %d step rows, want 1", stepCount)
	}
	if acceptedAfter != 1 || rejectedAfter != 1 || terminalAfter != 1 || providerAttemptAfter != providerAttemptID {
		t.Fatalf("provenance after stale save accepted=%d rejected=%d terminal=%d tool_attempt=%s want=%s", acceptedAfter, rejectedAfter, terminalAfter, providerAttemptAfter, providerAttemptID)
	}
}
