package database

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/evidence"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/resultadmission"
)

func TestEvidenceCLIToServiceWithAdoptedLocalArtifact(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("authoritative local artifact publication is Linux-only")
	}
	env := newRecoveryTestEnvironment(t, "evidence-cli")
	root := t.TempDir()
	storeID := domain.NewID()
	if _, err := artifact.InitializeLocal(env.ctx, root, storeID, env.store, artifact.InitializationOptions{}); err != nil {
		t.Fatal(err)
	}
	local, err := artifact.OpenLocal(env.ctx, root, storeID, env.store, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture, stdoutReference := publishLocalEvidenceFixture(t, env, local)
	service := evidence.Service{Authorizer: env.store, Lister: env.store, Store: local}
	before := evidenceMutationCounts(t, env)
	stateBefore := captureEvidenceReadState(t, env, fixture)

	var listed bytes.Buffer
	if err := evidence.Execute(env.ctx, service, []string{string(fixture.step.WorkflowRunID)}, &listed); err != nil {
		t.Fatal(err)
	}
	var items []evidence.Metadata
	for _, candidate := range fixture.compiled.Artifacts {
		if _, authorizeErr := env.store.AuthorizeEvidenceView(env.ctx, fixture.step.WorkflowRunID, candidate.Reference.ArtifactID); authorizeErr != nil {
			t.Fatalf("authorize role=%s artifact=%s: %v", candidate.Reference.Role, candidate.Reference.ArtifactID, authorizeErr)
		}
	}
	if err := json.Unmarshal(listed.Bytes(), &items); err != nil {
		t.Fatalf("decode list: %v\n%s", err, listed.String())
	}
	found := false
	for _, item := range items {
		found = found || item.ArtifactID == stdoutReference.ArtifactID
	}
	if !found || strings.Contains(listed.String(), stdoutReference.StorageKey) || strings.Contains(listed.String(), "storage_key") {
		t.Fatalf("unsafe or incomplete list: %s", listed.String())
	}

	var shown bytes.Buffer
	if err := evidence.Execute(env.ctx, service, []string{string(fixture.step.WorkflowRunID), string(stdoutReference.ArtifactID)}, &shown); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shown.String(), "integrity_status: verified") || !strings.Contains(shown.String(), "| synthetic observation") || strings.Contains(shown.String(), stdoutReference.StorageKey) {
		t.Fatalf("unexpected evidence display: %s", shown.String())
	}

	var crossRun bytes.Buffer
	if err := evidence.Execute(env.ctx, service, []string{string(domain.NewID()), string(stdoutReference.ArtifactID)}, &crossRun); !errors.Is(err, artifact.ErrEvidenceUnavailable) || crossRun.Len() != 0 {
		t.Fatalf("cross-run output=%q error=%v", crossRun.String(), err)
	}
	if after := evidenceMutationCounts(t, env); after != before {
		t.Fatalf("CLI evidence reads mutated state: before=%v after=%v", before, after)
	}
	if stateAfter := captureEvidenceReadState(t, env, fixture); stateAfter != stateBefore {
		t.Fatalf("CLI evidence reads changed authoritative rows")
	}
}

func publishLocalEvidenceFixture(t *testing.T, env recoveryTestEnvironment, local *artifact.Local) (preparedDBFixture, domain.ResultArtifactRefV1) {
	t.Helper()
	scheduled := newScheduledResultFixtureInEnvironment(t, env, "evidence-cli-adopted", "compare.assets")
	identity := local.Identity()
	if err := env.store.ConfigurePreparedEvidenceLimits(env.ctx, identity.ArtifactStoreID, 128, 1<<20, 128<<20); err != nil {
		t.Fatal(err)
	}
	action := scheduledProviderAction(scheduled, 1)
	authorizationID, err := env.store.RecordPolicyDecision(scheduled.context(), capability.PolicyDecisionRecord{ProgramID: env.programID, Action: action, Provider: "fixture", PolicyID: "test", Phase: "execution", Evaluation: policy.Evaluation{Decision: policy.Allow, Reason: "local fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	allocated, err := env.store.AllocateProviderInvocation(scheduled.context(), capability.ProviderInvocationStartRecord{ProgramID: env.programID, TaskID: action.TaskID, WorkflowRunID: action.WorkflowRunID, StepRunID: action.StepRunID, ActionRequestID: action.ID, StepAttempt: 1, ExecutionAuthorizationEventID: authorizationID, Capability: action.Capability, Provider: "fixture", Actor: "test"}, identity)
	if err != nil {
		t.Fatal(err)
	}
	admission := capability.ResultAdmissionProvenance{ProviderAttemptID: allocated.ProviderAttemptID, PreparedSetID: allocated.PreparedSetID, ManifestID: allocated.ManifestID, ReservedCapacityBytes: allocated.ReservedCapacityBytes, ActionRequestID: action.ID, StepAttempt: 1, ExecutionAuthorizationEventID: authorizationID, Provider: "fixture", ProviderTerminalEventID: domain.NewID()}
	now := time.Now().UTC()
	tool := domain.ToolRun{ID: domain.NewID(), StepRunID: action.StepRunID, Capability: action.Capability, Provider: "fixture", ToolVersion: "2", StartedAt: now, CompletedAt: &now, ProviderAttemptID: &admission.ProviderAttemptID, SanitizedArguments: json.RawMessage(`{}`), ExecutionEnvironment: json.RawMessage(`{}`)}
	result := capability.Result{Action: domain.ActionResult{RequestID: action.ID, Status: "succeeded", Summary: "synthetic fixture", Output: json.RawMessage(`{"status":"observed"}`)}, RawStdout: []byte("synthetic observation\nsecond line"), ProviderAttemptID: &admission.ProviderAttemptID, AdmissionProvenance: &admission, ProviderOutcome: domain.ResultProviderSucceeded}
	compiled, err := resultadmission.Compile(resultadmission.CompileRequest{ProgramID: env.programID, Action: action, Manifest: capability.Manifest{Name: action.Capability, Version: "2", OutputSchema: json.RawMessage(`{}`)}, StoreIdentity: identity, Result: result, ToolRun: tool, RequirePreparedEvidence: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = compiled.Close() })
	step := domain.StepRun{ID: action.StepRunID, WorkflowRunID: action.WorkflowRunID, Capability: action.Capability, IdempotencyKey: action.IdempotencyKey, Status: domain.StepSucceeded, CompletedAt: &now}
	stageRequest, manifest, err := compiled.PreparedStageRequest(identity, step, admission, capability.ProviderInvocationSucceeded, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := local.AcquirePublisher(env.ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	preparedGuard, ok := guard.(artifact.PreparedPublisherGuard)
	if !ok {
		_ = guard.Close()
		t.Fatal("local publisher does not support prepared evidence")
	}
	receipt, err := preparedGuard.StagePrepared(env.ctx, stageRequest)
	if err != nil {
		_ = guard.Close()
		t.Fatal(err)
	}
	seal := resultadmission.PreparedSealRecord{Admission: admission, StoreIdentity: identity, Manifest: manifest, ManifestSize: receipt.ManifestSize, ManifestSHA256: artifact.DigestString(receipt.ManifestSHA256), ContentBytes: receipt.ContentBytes + receipt.ManifestSize, Outcome: capability.ProviderInvocationSucceeded}
	if err := env.store.SealPreparedEvidence(scheduled.context(), seal); err != nil {
		_ = guard.Close()
		t.Fatal(err)
	}
	if err := compiled.TransferPreparedSources(preparedGuard, manifest); err != nil {
		_ = guard.Close()
		t.Fatal(err)
	}
	if err := env.store.ReserveCompiledResult(scheduled.context(), env.programID, step, compiled, &admission, identity); err != nil {
		_ = guard.Close()
		t.Fatal(err)
	}
	for ordinal, item := range compiled.Artifacts {
		if err := env.store.MarkCompiledArtifactPublishing(scheduled.context(), compiled, ordinal); err != nil {
			_ = guard.Close()
			t.Fatal(err)
		}
		reader, err := item.Source.Open()
		if err != nil {
			_ = guard.Close()
			t.Fatal(err)
		}
		digestBytes, err := hex.DecodeString(item.Reference.ContentSHA256)
		if err != nil {
			_ = reader.Close()
			_ = guard.Close()
			t.Fatal(err)
		}
		var digest [32]byte
		copy(digest[:], digestBytes)
		publication, publishErr := guard.PublishReserved(env.ctx, artifact.ReservedArtifactV1{PublicationID: item.PublicationID, ArtifactID: item.Reference.ArtifactID, ArtifactStoreID: item.Reference.ArtifactStoreID, StorageKey: item.Reference.StorageKey, ExpectedSize: item.Reference.ContentSizeBytes, ExpectedSHA256: digest}, reader)
		closeErr := reader.Close()
		if publishErr != nil || closeErr != nil || !publication.Durable {
			_ = guard.Close()
			t.Fatalf("publication=%#v publish=%v close=%v", publication, publishErr, closeErr)
		}
		if err := env.store.SealCompiledArtifact(scheduled.context(), compiled, ordinal); err != nil {
			_ = guard.Close()
			t.Fatal(err)
		}
	}
	if err := env.store.AdoptCompiledResult(scheduled.context(), env.programID, step, compiled, &admission, time.Hour); err != nil {
		_ = guard.Close()
		t.Fatal(err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}

	fixture := preparedDBFixture{scheduledResultFixture: scheduled, identity: identity, action: action, admission: admission, compiled: compiled, seal: seal, step: step}
	for _, item := range compiled.Artifacts {
		if item.Reference.Role == domain.ArtifactRoleProviderStdout {
			return fixture, item.Reference
		}
	}
	t.Fatal("fixture has no stdout artifact")
	return preparedDBFixture{}, domain.ResultArtifactRefV1{}
}
