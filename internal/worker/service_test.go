package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/execution"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/queue"
	"github.com/tobiasGuta/Reconductor/internal/resultadmission"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
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

func TestWorkerUsesMultiConfiguredDefaultProvider(t *testing.T) {
	multi, err := capability.NewMulti("z-default", map[string]capability.Capability{
		"a-alphabetical": workerProviderStub{name: "multi.worker"},
		"z-default":      workerProviderStub{name: "multi.worker"},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := capability.NewRegistry()
	if err := registry.Register(multi); err != nil {
		t.Fatal(err)
	}
	service := Service{Registry: registry}
	job := queue.Job{Action: domain.ActionRequest{Capability: "multi.worker"}}
	if provider := service.resolveProvider(job); provider != "z-default" {
		t.Fatalf("omitted provider resolved to %q", provider)
	}
	job.Provider = "a-alphabetical"
	if provider := service.resolveProvider(job); provider != "a-alphabetical" {
		t.Fatalf("explicit provider resolved to %q", provider)
	}
}

type leaseFailureQueue struct {
	touches atomic.Int32
	acks    atomic.Int32
	fails   atomic.Int32
}

func (*leaseFailureQueue) EnsureGroup(context.Context) error { return nil }
func (*leaseFailureQueue) PumpRetries(context.Context, int64) (int, error) {
	return 0, nil
}
func (*leaseFailureQueue) ClaimStale(context.Context, time.Duration, int64) ([]queue.Delivery, error) {
	return nil, nil
}
func (*leaseFailureQueue) Read(context.Context, time.Duration, int64) ([]queue.Delivery, error) {
	return nil, nil
}
func (q *leaseFailureQueue) Touch(context.Context, string) error {
	q.touches.Add(1)
	return errors.New("synthetic lease refresh failure")
}
func (q *leaseFailureQueue) Ack(context.Context, string, any) error {
	q.acks.Add(1)
	return nil
}
func (q *leaseFailureQueue) Fail(context.Context, string, queue.Job, string, bool) error {
	q.fails.Add(1)
	return nil
}

type leaseBlockingStore struct{ *workerStore }

func (*leaseBlockingStore) AlreadySucceeded(ctx context.Context, _ string) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

func TestWorkerLeaseRefreshFailureCancelsWorkWithoutQueueFinalization(t *testing.T) {
	workQueue := &leaseFailureQueue{}
	service := Service{
		Queue:        workQueue,
		Results:      &leaseBlockingStore{workerStore: &workerStore{}},
		LeaseTimeout: 3 * time.Millisecond,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	err := service.handle(context.Background(), queue.Delivery{MessageID: "lease-loss", Job: queue.Job{Action: domain.ActionRequest{IdempotencyKey: "lease-loss"}}})
	if !errors.Is(err, ErrDeliveryLeaseLost) {
		t.Fatalf("error=%v want delivery lease loss", err)
	}
	if workQueue.touches.Load() != 1 || workQueue.acks.Load() != 0 || workQueue.fails.Load() != 0 {
		t.Fatalf("touches=%d acks=%d fails=%d", workQueue.touches.Load(), workQueue.acks.Load(), workQueue.fails.Load())
	}
}

type workerProviderStub struct{ name string }

func (c workerProviderStub) Manifest() capability.Manifest {
	return capability.Manifest{Name: c.name, Version: "1", Risk: policy.Low, RetrySafe: true, Idempotent: true}
}
func (workerProviderStub) Validate(context.Context, capability.Request) error { return nil }
func (workerProviderStub) Execute(context.Context, capability.Request) (capability.Result, error) {
	return capability.Result{}, nil
}

type workerStore struct {
	previous          []string
	loadedFor         string
	step              domain.StepRun
	tool              *domain.ToolRun
	artifacts         []domain.Artifact
	result            domain.ActionResult
	admission         *capability.ResultAdmissionProvenance
	admissions        []*capability.ResultAdmissionProvenance
	policyID          domain.ID
	startID           domain.ID
	startIDs          []domain.ID
	start             capability.ProviderInvocationStartRecord
	terminal          capability.ProviderInvocationTerminalRecord
	terminalErr       error
	effectiveInputs   map[domain.ID]json.RawMessage
	effectiveAttempts map[domain.ID]int
}

func (s *workerStore) AllocateProviderInvocation(_ context.Context, record capability.ProviderInvocationStartRecord, _ artifact.StoreIdentity) (capability.ProviderInvocationAdmission, error) {
	s.start = record
	s.startID = domain.NewID()
	s.startIDs = append(s.startIDs, s.startID)
	return capability.ProviderInvocationAdmission{ProviderAttemptID: s.startID, PreparedSetID: domain.NewID(), ManifestID: domain.NewID(), ReservedCapacityBytes: domain.PreparedSetOutputAuthorityMaxBytes}, nil
}

func (s *workerStore) SealPreparedEvidence(_ context.Context, record resultadmission.PreparedSealRecord) error {
	s.terminal = capability.ProviderInvocationTerminalRecord{ProviderAttemptID: record.Admission.ProviderAttemptID, Outcome: record.Outcome}
	return s.terminalErr
}

func (*workerStore) QuarantinePreparedEvidence(context.Context, domain.ID, string) error { return nil }

func (s *workerStore) RecordPolicyDecision(context.Context, capability.PolicyDecisionRecord) (domain.ID, error) {
	if s.policyID == "" {
		s.policyID = domain.NewID()
	}
	return s.policyID, nil
}
func (s *workerStore) RecordProviderInvocationStarted(_ context.Context, record capability.ProviderInvocationStartRecord) (domain.ID, error) {
	s.start = record
	s.startID = domain.NewID()
	s.startIDs = append(s.startIDs, s.startID)
	return s.startID, nil
}
func (s *workerStore) RecordProviderInvocationTerminal(_ context.Context, record capability.ProviderInvocationTerminalRecord) error {
	s.terminal = record
	return s.terminalErr
}

func (*workerStore) AlreadySucceeded(context.Context, string) (bool, error) { return false, nil }
func (s *workerStore) PreviousObservationValues(_ context.Context, _ domain.ID, _ domain.ID, capabilityName string) ([]string, error) {
	s.loadedFor = capabilityName
	return append([]string(nil), s.previous...), nil
}
func (s *workerStore) LoadEffectiveStepInput(_ context.Context, _ domain.ID, action domain.ActionRequest) (json.RawMessage, bool, error) {
	persisted, found := s.effectiveInputs[action.StepRunID]
	if !found {
		return nil, false, nil
	}
	authoritativeAttempt := s.effectiveAttempts[action.StepRunID]
	if action.StepAttempt < authoritativeAttempt {
		return nil, false, &workflow.StepAttemptOwnershipError{StepRunID: action.StepRunID, RequestedAttempt: action.StepAttempt, AuthoritativeAttempt: authoritativeAttempt}
	}
	return append(json.RawMessage(nil), persisted...), true, nil
}
func (s *workerStore) PersistEffectiveStepInput(_ context.Context, _ domain.ID, action domain.ActionRequest, proposed json.RawMessage) (json.RawMessage, error) {
	if action.StepAttempt < 1 || len(proposed) == 0 || !json.Valid(proposed) {
		return nil, fmt.Errorf("%w: effective input or attempt is invalid", workflow.ErrEffectiveStepInputConflict)
	}
	if s.effectiveInputs == nil {
		s.effectiveInputs = map[domain.ID]json.RawMessage{}
		s.effectiveAttempts = map[domain.ID]int{}
	}
	persisted, found := s.effectiveInputs[action.StepRunID]
	if found {
		authoritativeAttempt := s.effectiveAttempts[action.StepRunID]
		if action.StepAttempt <= authoritativeAttempt {
			return nil, &workflow.StepAttemptOwnershipError{StepRunID: action.StepRunID, RequestedAttempt: action.StepAttempt, AuthoritativeAttempt: authoritativeAttempt}
		}
		if action.StepAttempt != authoritativeAttempt+1 || !bytes.Equal(persisted, proposed) {
			return nil, fmt.Errorf("%w: StepRun %s already has authoritative attempt %d input", workflow.ErrEffectiveStepInputConflict, action.StepRunID, authoritativeAttempt)
		}
		s.effectiveAttempts[action.StepRunID] = action.StepAttempt
		return append(json.RawMessage(nil), persisted...), nil
	}
	if action.StepAttempt != 1 {
		return nil, fmt.Errorf("%w: first durable attempt for StepRun %s must be 1, got %d", workflow.ErrEffectiveStepInputConflict, action.StepRunID, action.StepAttempt)
	}
	frozen := append(json.RawMessage(nil), proposed...)
	s.effectiveInputs[action.StepRunID] = frozen
	s.effectiveAttempts[action.StepRunID] = action.StepAttempt
	return append(json.RawMessage(nil), frozen...), nil
}
func (s *workerStore) PersistResultWithArtifactPublication(ctx context.Context, _ domain.ID, step domain.StepRun, tool *domain.ToolRun, result *domain.ActionResult, admission *capability.ResultAdmissionProvenance, publish func(context.Context) ([]domain.Artifact, error)) error {
	var artifacts []domain.Artifact
	if publish != nil {
		var err error
		artifacts, err = publish(ctx)
		if err != nil {
			return err
		}
	}
	s.step = step
	s.tool = tool
	s.artifacts = append([]domain.Artifact(nil), artifacts...)
	s.result = *result
	s.admission = admission
	s.admissions = append(s.admissions, admission)
	return nil
}

func (s *workerStore) PersistPreProviderFailure(_ context.Context, _ domain.ID, step domain.StepRun, summary string) error {
	s.step = step
	s.tool = nil
	s.result = domain.ActionResult{Status: string(step.Status), Summary: summary, Error: &domain.StructuredError{Classification: step.ErrorClassification, Message: step.ErrorDetails}}
	return nil
}

func (s *workerStore) ReserveCompiledResult(context.Context, domain.ID, domain.StepRun, resultadmission.CompiledResult, *capability.ResultAdmissionProvenance, artifact.StoreIdentity) error {
	return nil
}
func (*workerStore) MarkCompiledArtifactPublishing(context.Context, resultadmission.CompiledResult, int) error {
	return nil
}
func (*workerStore) SealCompiledArtifact(context.Context, resultadmission.CompiledResult, int) error {
	return nil
}
func (*workerStore) TerminalizeCompiledResult(context.Context, resultadmission.CompiledResult, domain.PublicationState, string) error {
	return nil
}
func (s *workerStore) AdoptCompiledResult(_ context.Context, _ domain.ID, step domain.StepRun, compiled resultadmission.CompiledResult, admission *capability.ResultAdmissionProvenance, _ time.Duration) error {
	step.Output = append(json.RawMessage(nil), compiled.EnvelopeJSON...)
	artifacts := make([]domain.Artifact, 0, len(compiled.Artifacts))
	for _, item := range compiled.Artifacts {
		storeID, key := item.Reference.ArtifactStoreID, item.Reference.StorageKey
		artifacts = append(artifacts, domain.Artifact{ID: item.Reference.ArtifactID, TaskID: s.start.TaskID, WorkflowRunID: step.WorkflowRunID, StepRunID: step.ID, ToolRunID: compiled.ToolRun.ID, Type: item.ArtifactType, ContentType: item.Reference.ContentType, Size: item.Reference.ContentSizeBytes, SHA256: item.Reference.ContentSHA256, AddressingVersion: 1, ArtifactStoreID: &storeID, StorageKey: &key})
	}
	semanticIDs := []domain.ID{compiled.Envelope.SemanticOutput.ArtifactID}
	tool := compiled.ToolRun
	s.step, s.tool, s.artifacts, s.result, s.admission = step, &tool, artifacts, domain.ActionResult{RequestID: compiled.Envelope.ActionRequestID, Status: string(compiled.Envelope.Status), Summary: compiled.Envelope.Summary, Output: compiled.EnvelopeJSON, ArtifactIDs: semanticIDs}, admission
	s.admissions = append(s.admissions, admission)
	return nil
}

type workerArtifacts struct {
	puts     []artifact.PutRequest
	req      capability.Request
	compiled resultadmission.CompiledResult
	prepared map[string][]byte
}

var workerPublisherIdentity = artifact.StoreIdentity{ArtifactStoreID: "00000000-0000-4000-8000-000000009001", IncarnationNonce: "00000000-0000-4000-8000-000000009004", BackendKind: artifact.BackendKind, MarkerFormat: artifact.MarkerFormat, MarkerVersion: artifact.MarkerVersion}

func (s *workerArtifacts) Identity() artifact.StoreIdentity { return workerPublisherIdentity }
func (s *workerArtifacts) CaptureCompiledPublication(req capability.Request, compiled resultadmission.CompiledResult) {
	s.req, s.compiled = req, compiled
}
func (s *workerArtifacts) AcquirePublisher(_ context.Context, expected artifact.StoreIdentity) (artifact.PublisherGuard, error) {
	if expected != workerPublisherIdentity {
		return nil, errors.New("identity mismatch")
	}
	return &workerPublisherGuard{owner: s}, nil
}

type workerPublisherGuard struct{ owner *workerArtifacts }

func (g *workerPublisherGuard) Identity() artifact.StoreIdentity { return workerPublisherIdentity }
func (g *workerPublisherGuard) StagePrepared(_ context.Context, request artifact.PreparedStageRequest) (artifact.PreparedStageReceipt, error) {
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
func (g *workerPublisherGuard) OpenPrepared(_ context.Context, key string, size int64, digest [32]byte) (io.ReadCloser, error) {
	data, ok := g.owner.prepared[key]
	if !ok || int64(len(data)) != size || artifact.DigestBytes(data) != digest {
		return nil, errors.New("prepared object unavailable")
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}
func (g *workerPublisherGuard) PublishReserved(_ context.Context, reserved artifact.ReservedArtifactV1, reader io.Reader) (artifact.PublishedArtifactV1, error) {
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
	g.owner.puts = append(g.owner.puts, artifact.PutRequest{ProgramID: g.owner.req.ProgramID, TaskID: g.owner.req.Action.TaskID, WorkflowRunID: g.owner.req.Action.WorkflowRunID, StepRunID: g.owner.req.Action.StepRunID, ToolRunID: g.owner.compiled.ToolRun.ID, Type: item.ArtifactType, ContentType: item.Reference.ContentType, Name: name, Retention: g.owner.req.Policy.ArtifactRetention, Data: data})
	return artifact.PublishedArtifactV1{SizeBytes: int64(len(data)), SHA256: reserved.ExpectedSHA256, Durable: true}, nil
}
func (g *workerPublisherGuard) Close() error { return nil }

func (s *workerArtifacts) Put(_ context.Context, req artifact.PutRequest) (domain.Artifact, error) {
	s.puts = append(s.puts, req)
	id := domain.NewID()
	key, err := artifact.StorageKeyFor(id)
	if err != nil {
		return domain.Artifact{}, err
	}
	storeID := domain.ID("00000000-0000-4000-8000-000000009001")
	return domain.Artifact{ID: id, TaskID: req.TaskID, WorkflowRunID: req.WorkflowRunID, StepRunID: req.StepRunID, ToolRunID: req.ToolRunID, Type: req.Type, ContentType: req.ContentType, Size: int64(len(req.Data)), AddressingVersion: 1, ArtifactStoreID: &storeID, StorageKey: &key, CreatedAt: time.Now().UTC()}, nil
}

type workerScope struct{}

func (workerScope) Allows(string) bool { return true }

type parityCapability struct {
	fail             bool
	claimedAttemptID *domain.ID
}

func (parityCapability) Manifest() capability.Manifest {
	return capability.Manifest{Name: "parity.cap", Version: "1", Risk: policy.Low, RetrySafe: true, Idempotent: true}
}
func (parityCapability) Validate(context.Context, capability.Request) error { return nil }
func (c parityCapability) Execute(_ context.Context, req capability.Request) (capability.Result, error) {
	now := time.Now().UTC()
	exitCode := 0
	tool := &domain.ToolRun{ID: domain.NewID(), StepRunID: req.Action.StepRunID, Capability: req.Action.Capability, Provider: req.Provider, ToolVersion: "test", SanitizedArguments: json.RawMessage(`{"safe":true}`), ExecutionEnvironment: json.RawMessage(`{"kind":"test"}`), StartedAt: now, CompletedAt: &now, ExitCode: &exitCode}
	if c.claimedAttemptID != nil {
		claimed := *c.claimedAttemptID
		tool.ProviderAttemptID = &claimed
	}
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
	jobID, actionID := domain.NewID(), domain.NewID()
	delivery := queue.Delivery{MessageID: "redis-message-1", Job: queue.Job{ID: jobID, ProgramID: programID, Action: domain.ActionRequest{ID: actionID, TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, Capability: "classify.endpoint", Input: input, IdempotencyKey: "job", StepAttempt: 1}, Policy: policy.Policy{AllowedCapabilities: []string{"classify.endpoint"}, ArtifactRetention: time.Hour}}}

	result, err := service.executeJob(context.Background(), delivery, "platform", workerScope{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Action.Status != "succeeded" || store.step.Status != domain.StepSucceeded {
		t.Fatalf("result=%#v step=%#v", result.Action, store.step)
	}
	if store.start.QueueJobID == nil || *store.start.QueueJobID != jobID || store.start.ActionRequestID != actionID || string(jobID) == delivery.MessageID {
		t.Fatalf("queued provenance start=%#v message_id=%q", store.start, delivery.MessageID)
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
		switch {
		case store.tool.StdoutArtifactID != nil && artifact.ID == *store.tool.StdoutArtifactID:
			stdoutID = artifact.ID
			if artifact.Type != "raw-provider-output" || artifact.ContentType != "application/x-ndjson" {
				t.Fatalf("stdout artifact mismatch: %#v", artifact)
			}
		case store.tool.StderrArtifactID != nil && artifact.ID == *store.tool.StderrArtifactID:
			stderrID = artifact.ID
			if artifact.Type != "raw-provider-output" || artifact.ContentType != "text/plain" {
				t.Fatalf("stderr artifact mismatch: %#v", artifact)
			}
		default:
			for _, id := range store.result.ArtifactIDs {
				if id == artifact.ID {
					resultID = artifact.ID
					if artifact.Type != "normalized-result" || artifact.ContentType != "application/json" {
						t.Fatalf("result artifact mismatch: %#v", artifact)
					}
				}
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
			workerDelivery := queue.Delivery{Job: queue.Job{ID: domain.NewID(), ProgramID: programID, Action: parityAction(taskID, runID, domain.NewID()), Policy: policy.Policy{AllowedCapabilities: []string{"parity.cap"}, ArtifactRetention: time.Hour}}}
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
			if localStore.start.QueueJobID != nil || workerStore.start.QueueJobID == nil || *workerStore.start.QueueJobID != workerDelivery.Job.ID {
				t.Fatalf("queue provenance local=%#v worker=%#v", localStore.start.QueueJobID, workerStore.start.QueueJobID)
			}
			assertArtifactRoles(t, "local", localStore, localArtifacts)
			assertArtifactRoles(t, "worker", workerStore, workerArtifacts)
		})
	}
}

func TestWorkerRedeliveryRetainsJobAndActionButCreatesNewProviderAttempt(t *testing.T) {
	registry := capability.NewRegistry()
	provider := &parityCapability{}
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	store := &workerStore{}
	jobID, actionID := domain.NewID(), domain.NewID()
	delivery := queue.Delivery{MessageID: "redis-delivery-a", Job: queue.Job{ID: jobID, ProgramID: domain.NewID(), Action: parityAction(domain.NewID(), domain.NewID(), domain.NewID()), Policy: policy.Policy{AllowedCapabilities: []string{"parity.cap"}}}}
	delivery.Job.Action.ID = actionID
	service := &Service{Registry: registry, Results: store, Artifacts: &workerArtifacts{}}
	first, err := service.executeJob(context.Background(), delivery, "resolved-provider", workerScope{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	provider.claimedAttemptID = first.ProviderAttemptID
	delivery.MessageID = "redis-delivery-b"
	delivery.Job.Action.StepAttempt = 2
	delivery.Job.Action.Input = json.RawMessage(`{"ok":false}`)
	second, err := service.executeJob(context.Background(), delivery, "resolved-provider", workerScope{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.ProviderAttemptID == nil || second.ProviderAttemptID == nil || *first.ProviderAttemptID == *second.ProviderAttemptID {
		t.Fatalf("provider attempts first=%v second=%v", first.ProviderAttemptID, second.ProviderAttemptID)
	}
	if len(store.startIDs) != 2 || store.start.QueueJobID == nil || *store.start.QueueJobID != jobID || store.start.ActionRequestID != actionID {
		t.Fatalf("redelivery provenance starts=%#v last=%#v", store.startIDs, store.start)
	}
	if len(store.admissions) != 2 || store.admissions[0] == nil || store.admissions[1] == nil || store.admissions[0].ProviderAttemptID != *first.ProviderAttemptID || store.admissions[1].ProviderAttemptID != *second.ProviderAttemptID || store.admissions[0].ActionRequestID != actionID || store.admissions[1].ActionRequestID != actionID || store.admissions[0].QueueJobID == nil || store.admissions[1].QueueJobID == nil || *store.admissions[0].QueueJobID != jobID || *store.admissions[1].QueueJobID != jobID {
		t.Fatalf("redelivery admissions=%#v first=%#v second=%#v", store.admissions, first.ProviderAttemptID, second.ProviderAttemptID)
	}
	if store.tool == nil || store.tool.ProviderAttemptID == nil || *store.tool.ProviderAttemptID != *second.ProviderAttemptID || *store.tool.ProviderAttemptID == *first.ProviderAttemptID {
		t.Fatalf("P1 was not displaced by exact redelivery P2: tool=%#v first=%v second=%v", store.tool, first.ProviderAttemptID, second.ProviderAttemptID)
	}
	if store.effectiveAttempts[delivery.Job.Action.StepRunID] != 2 || !bytes.Equal(store.effectiveInputs[delivery.Job.Action.StepRunID], json.RawMessage(`{"ok":true}`)) {
		t.Fatalf("redelivery did not retain frozen input across attempts: attempts=%#v inputs=%#v", store.effectiveAttempts, store.effectiveInputs)
	}
}

func TestWorkerPreparedSealFailureDoesNotAdoptOrLogInternalError(t *testing.T) {
	const internalMarker = "SECRET_INTERNAL_DATABASE_DETAIL"
	registry := capability.NewRegistry()
	if err := registry.Register(parityCapability{fail: true}); err != nil {
		t.Fatal(err)
	}
	store := &workerStore{terminalErr: errors.New(internalMarker)}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	var queueCalls atomic.Int32
	client := redis.NewClient(&redis.Options{
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			queueCalls.Add(1)
			return nil, errors.New("synthetic queue unavailable")
		},
		MaxRetries: -1,
	})
	t.Cleanup(func() { _ = client.Close() })
	delivery := queue.Delivery{
		MessageID: "terminal-audit-log-test",
		Job: queue.Job{
			ID:            domain.NewID(),
			ProgramID:     domain.NewID(),
			Action:        parityAction(domain.NewID(), domain.NewID(), domain.NewID()),
			Policy:        policy.Policy{AllowedCapabilities: []string{"parity.cap"}},
			ScopeIncludes: []platformscope.Rule{{Protocol: "^https$", Host: `^x\.test$`, Port: "^443$", File: "^/.*", Enabled: true}},
		},
	}
	service := &Service{
		Queue:        queue.New(client, "terminal-audit-log-test", "worker", 0, time.Millisecond),
		Registry:     registry,
		Results:      store,
		Artifacts:    &workerArtifacts{},
		Logger:       logger,
		LeaseTimeout: time.Hour,
	}
	if err := service.handle(context.Background(), delivery); !domain.PersistenceUnresolved(err) {
		t.Fatalf("prepared uncertainty lost before worker queue handling: %v", err)
	}
	if queueCalls.Load() != 0 || len(store.startIDs) != 1 {
		t.Fatalf("worker retried/finalized unresolved result: queue calls=%d provider attempts=%d", queueCalls.Load(), len(store.startIDs))
	}
	output := logs.String()
	if strings.Contains(output, internalMarker) || strings.Contains(output, store.terminalErr.Error()) {
		t.Fatalf("prepared seal error leaked into worker log: %s", output)
	}
	if store.startID == "" || store.step.Status != "" || store.result.Status != "" {
		t.Fatalf("prepared seal failure was adopted: start=%s step=%#v result=%#v", store.startID, store.step, store.result)
	}
}

func TestWorkerStartupReachesQueueConsumerWithoutRetentionPrerequisite(t *testing.T) {
	spy := newRedisCommandSpy(t)
	client := redis.NewClient(&redis.Options{Addr: spy.listener.Addr().String(), Protocol: 2, DisableIdentity: true, MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	service := &Service{
		Queue:        queue.New(client, "worker-startup-liveness", "worker", 0, time.Millisecond),
		Registry:     capability.NewRegistry(),
		Results:      &workerStore{},
		Artifacts:    &workerArtifacts{},
		PoolSize:     1,
		ReadBlock:    10 * time.Millisecond,
		LeaseTimeout: time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.Run(ctx) }()
	for _, command := range []string{"XGROUP", "XAUTOCLAIM", "XREADGROUP"} {
		spy.waitFor(t, command, time.Second)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("worker shutdown error=%v", err)
	}
}

func TestWorkerPeriodicRetryLifecycleNeedsNoRetentionMaintenance(t *testing.T) {
	spy := newRedisCommandSpy(t)
	client := redis.NewClient(&redis.Options{Addr: spy.listener.Addr().String(), Protocol: 2, DisableIdentity: true, MaxRetries: -1})
	t.Cleanup(func() { _ = client.Close() })
	service := &Service{
		Queue:        queue.New(client, "worker-periodic-liveness", "worker", 0, time.Millisecond),
		Registry:     capability.NewRegistry(),
		Results:      &workerStore{},
		Artifacts:    &workerArtifacts{},
		PoolSize:     1,
		ReadBlock:    10 * time.Millisecond,
		LeaseTimeout: time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.Run(ctx) }()
	spy.waitFor(t, "XREADGROUP", time.Second)
	spy.waitFor(t, "EVAL", 2*time.Second)
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("worker shutdown error=%v", err)
	}
}

type redisCommandSpy struct {
	listener net.Listener
	mu       sync.Mutex
	commands []string
	seen     chan string
}

func newRedisCommandSpy(t *testing.T) *redisCommandSpy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	spy := &redisCommandSpy{listener: listener, seen: make(chan string, 64)}
	t.Cleanup(func() { _ = listener.Close() })
	go spy.accept()
	return spy
}

func (s *redisCommandSpy) accept() {
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.serve(connection)
	}
}

func (s *redisCommandSpy) serve(connection net.Conn) {
	defer connection.Close()
	reader := bufio.NewReader(connection)
	for {
		command, err := readRedisCommand(reader)
		if err != nil {
			return
		}
		s.record(command[0])
		var response string
		switch command[0] {
		case "HELLO":
			response = "-ERR unknown command 'hello'\r\n"
		case "XGROUP":
			response = "+OK\r\n"
		case "XAUTOCLAIM":
			response = "*3\r\n$3\r\n0-0\r\n*0\r\n*0\r\n"
		case "XREADGROUP":
			response = "*-1\r\n"
		case "ZRANGEBYSCORE":
			response = "*0\r\n"
		case "EVAL":
			response = ":0\r\n"
		default:
			response = "+OK\r\n"
		}
		if _, err := io.WriteString(connection, response); err != nil {
			return
		}
	}
}

func (s *redisCommandSpy) record(command string) {
	s.mu.Lock()
	s.commands = append(s.commands, command)
	s.mu.Unlock()
	select {
	case s.seen <- command:
	default:
	}
}

func (s *redisCommandSpy) waitFor(t *testing.T, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		s.mu.Lock()
		for _, command := range s.commands {
			if command == want {
				s.mu.Unlock()
				return
			}
		}
		s.mu.Unlock()
		select {
		case <-s.seen:
		case <-deadline.C:
			t.Fatalf("Redis command %s was not observed; commands=%v", want, s.commands)
		}
	}
}

func readRedisCommand(reader *bufio.Reader) ([]string, error) {
	prefix, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if prefix != '*' {
		return nil, fmt.Errorf("RESP command prefix=%q", prefix)
	}
	count, err := readRESPInteger(reader)
	if err != nil {
		return nil, err
	}
	command := make([]string, count)
	for index := range command {
		prefix, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		if prefix != '$' {
			return nil, fmt.Errorf("RESP bulk prefix=%q", prefix)
		}
		size, err := readRESPInteger(reader)
		if err != nil {
			return nil, err
		}
		value := make([]byte, size)
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, err
		}
		if tail, err := reader.ReadString('\n'); err != nil || tail != "\r\n" {
			return nil, fmt.Errorf("RESP bulk terminator=%q error=%v", tail, err)
		}
		command[index] = string(value)
	}
	command[0] = strings.ToUpper(command[0])
	return command, nil
}

func readRESPInteger(reader *bufio.Reader) (int, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
}

func parityAction(taskID, runID, stepID domain.ID) domain.ActionRequest {
	return domain.ActionRequest{ID: domain.NewID(), TaskID: taskID, WorkflowRunID: runID, StepRunID: stepID, Capability: "parity.cap", Input: json.RawMessage(`{"ok":true}`), IdempotencyKey: string(stepID), StepAttempt: 1}
}

func assertArtifactRoles(t *testing.T, name string, store *workerStore, artifacts *workerArtifacts) {
	t.Helper()
	wantCount := 3
	if store.step.Status != domain.StepSucceeded {
		wantCount = 4
	}
	if len(artifacts.puts) != wantCount || len(store.artifacts) != wantCount {
		t.Fatalf("%s artifact count puts=%d persisted=%d", name, len(artifacts.puts), len(store.artifacts))
	}
	roles := map[string]string{}
	for _, put := range artifacts.puts {
		roles[put.Name] = put.Type + "|" + put.ContentType
	}
	if roles["stdout.jsonl"] != "raw-provider-output|application/x-ndjson" || roles["stderr.txt"] != "raw-provider-output|text/plain" || roles["result.json"] != "normalized-result|application/json" {
		t.Fatalf("%s artifact roles=%#v", name, roles)
	}
	if wantCount == 4 && roles["diagnostic.bin"] != "provider-diagnostic|application/vnd.reconductor.provider-diagnostic-v1" {
		t.Fatalf("%s diagnostic role=%#v", name, roles)
	}
	for _, artifact := range store.artifacts {
		if artifact.Type == "normalized-result" {
			for _, id := range store.result.ArtifactIDs {
				if id == artifact.ID {
					return
				}
			}
			t.Fatalf("%s normalized result artifact not attached to action result", name)
		}
	}
}
