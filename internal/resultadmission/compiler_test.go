package resultadmission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

var testStoreIdentity = artifact.StoreIdentity{ArtifactStoreID: "00000000-0000-4000-8000-000000000101", IncarnationNonce: "00000000-0000-4000-8000-000000000102", BackendKind: artifact.BackendKind, MarkerFormat: artifact.MarkerFormat, MarkerVersion: artifact.MarkerVersion}

func compileTestResult(t *testing.T, result capability.Result, schema string, reservation ...int64) CompiledResult {
	t.Helper()
	compiled, err := Compile(compileTestRequest(result, schema, reservation...))
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

func compileTestRequest(result capability.Result, schema string, reservation ...int64) CompileRequest {
	actionID, attemptID := domain.NewID(), domain.NewID()
	result.ProviderAttemptID = &attemptID
	result.AdmissionProvenance = &capability.ResultAdmissionProvenance{ProviderAttemptID: attemptID, ActionRequestID: actionID, StepAttempt: 1, Provider: "test", ReservedCapacityBytes: 1 << 20}
	if len(reservation) > 0 {
		result.AdmissionProvenance.ReservedCapacityBytes = reservation[0]
	}
	if result.ProviderOutcome == "" {
		result.ProviderOutcome = domain.ResultProviderSucceeded
	}
	now := time.Now().UTC()
	stepID := domain.NewID()
	return CompileRequest{
		ProgramID:     domain.NewID(),
		Action:        domain.ActionRequest{ID: actionID, TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: stepID, Capability: "test.result", StepAttempt: 1},
		Manifest:      capability.Manifest{Name: "test.result", Version: "1", OutputSchema: json.RawMessage(schema)},
		StoreIdentity: testStoreIdentity,
		Result:        result,
		ToolRun:       domain.ToolRun{ID: domain.NewID(), StepRunID: stepID, Capability: "test.result", Provider: "test", ToolVersion: "1", StartedAt: now, CompletedAt: &now, ProviderAttemptID: &attemptID},
	}
}

func preparedByRole(t *testing.T, compiled CompiledResult, role domain.ResultArtifactRoleV1) PreparedArtifact {
	t.Helper()
	for _, item := range compiled.Artifacts {
		if item.Reference.Role == role {
			return item
		}
	}
	t.Fatalf("role %s not found", role)
	return PreparedArtifact{}
}

func TestCompileLargeResultKeepsControlPlaneBoundedAndUsesReplayableSources(t *testing.T) {
	stdout := []byte(strings.Repeat("stdout evidence\n", 8_000))
	semantic := json.RawMessage(`{"value":"` + strings.Repeat("x", 80_000) + `"}`)
	compiled := compileTestResult(t, capability.Result{Action: domain.ActionResult{Status: "succeeded", Summary: "large", Output: semantic}, RawStdout: stdout}, `{"type":"object","required":["value"],"properties":{"value":{"type":"string"}},"additionalProperties":false}`)
	stdoutSource := preparedByRole(t, compiled, domain.ArtifactRoleProviderStdout).Source
	defer compiled.Close()
	if compiled.Envelope.SemanticOutput.Mode != domain.SemanticModeArtifactJSON || len(compiled.Envelope.SemanticOutput.InlineJSON) != 0 {
		t.Fatalf("semantic output was not artifact-backed: %#v", compiled.Envelope.SemanticOutput)
	}
	if len(compiled.EnvelopeJSON) > domain.ResultEnvelopeMaxBytes || bytes.Contains(compiled.EnvelopeJSON, []byte(strings.Repeat("x", 100))) || bytes.Contains(compiled.EnvelopeJSON, stdout[:100]) {
		t.Fatalf("control envelope scaled with evidence: bytes=%d", len(compiled.EnvelopeJSON))
	}
	reader, err := stdoutSource.Open()
	if err != nil {
		t.Fatal(err)
	}
	written, err := io.Copy(io.Discard, reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil || written != int64(len(stdout)) {
		t.Fatalf("replay bytes=%d error=%v close=%v", written, err, closeErr)
	}
	if err := compiled.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := stdoutSource.Open(); err == nil {
		t.Fatal("temporary prepared source survived compiled-result cleanup")
	}
}

func TestCompileInvalidSemanticOutputPublishesExactBundleAndCanonicalNull(t *testing.T) {
	invalid := json.RawMessage(`{"a":1,"a":2}`)
	compiled := compileTestResult(t, capability.Result{Action: domain.ActionResult{Status: "succeeded", Output: invalid}}, `{}`)
	defer compiled.Close()
	if compiled.Envelope.Status != domain.ResultStatusFailed || compiled.Envelope.ProviderOutcome != domain.ResultProviderFailed || compiled.Envelope.Error == nil || compiled.Envelope.Error.Code != "provider_contract_invalid" || compiled.Envelope.Error.Message != "provider returned invalid semantic output" || compiled.Envelope.SemanticOutput.Mode != domain.SemanticModeNone {
		t.Fatalf("invalid semantic envelope=%#v", compiled.Envelope)
	}
	semantic := preparedByRole(t, compiled, domain.ArtifactRoleSemanticResult)
	reader, _ := semantic.Source.Open()
	raw, _ := io.ReadAll(reader)
	_ = reader.Close()
	wantDigest := sha256.Sum256([]byte("null"))
	if string(raw) != "null" || semantic.Reference.ContentSizeBytes != 4 || semantic.Reference.ContentSHA256 != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("canonical null=%q ref=%#v", raw, semantic.Reference)
	}
	diagnostic := preparedByRole(t, compiled, domain.ArtifactRoleProviderDiagnostic)
	reader, _ = diagnostic.Source.Open()
	if err := VerifyDiagnosticBundle(reader, diagnostic.Reference.ContentSizeBytes); err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	if diagnostic.Reference.ContentSizeBytes != int64(50+len(invalid)) || compiled.Envelope.Error.DiagnosticArtifactID == nil || *compiled.Envelope.Error.DiagnosticArtifactID != diagnostic.Reference.ArtifactID {
		t.Fatalf("diagnostic bundle ref=%#v error=%#v", diagnostic.Reference, compiled.Envelope.Error)
	}
}

func TestCompilePreservesOversizedDiagnosticWithoutControlPlaneGrowth(t *testing.T) {
	diagnostic := []byte(strings.Repeat("complete failure detail\n", 12_000))
	compiled := compileTestResult(t, capability.Result{Action: domain.ActionResult{Status: "failed", Summary: "failed", Error: &domain.StructuredError{Classification: "provider_error", Message: strings.Repeat("m", 5_000)}}, RawDiagnostic: diagnostic, ProviderOutcome: domain.ResultProviderFailed}, `{}`)
	defer compiled.Close()
	bundle := preparedByRole(t, compiled, domain.ArtifactRoleProviderDiagnostic)
	if bundle.Reference.ContentSizeBytes != int64(50+len(diagnostic)) || len(compiled.EnvelopeJSON) > domain.ResultEnvelopeMaxBytes || len(compiled.Envelope.Error.Message) != domain.SafeMessageMaxBytes {
		t.Fatalf("bundle=%d envelope=%d error=%d", bundle.Reference.ContentSizeBytes, len(compiled.EnvelopeJSON), len(compiled.Envelope.Error.Message))
	}
	reader, _ := bundle.Source.Open()
	defer reader.Close()
	if err := VerifyDiagnosticBundle(reader, bundle.Reference.ContentSizeBytes); err != nil {
		t.Fatal(err)
	}
}

func TestCompileRejectsProviderArtifactIdentityAndSchemaInvalidOutput(t *testing.T) {
	t.Run("provider artifact ids", func(t *testing.T) {
		compiled := compileTestResult(t, capability.Result{Action: domain.ActionResult{Status: "succeeded", Output: json.RawMessage(`{}`), ArtifactIDs: []domain.ID{domain.NewID()}}}, `{}`)
		defer compiled.Close()
		if compiled.Envelope.Status != domain.ResultStatusFailed || compiled.Envelope.Error == nil || compiled.Envelope.Error.Code != "provider_contract_invalid" {
			t.Fatalf("envelope=%#v", compiled.Envelope)
		}
	})
	t.Run("schema rejection", func(t *testing.T) {
		compiled := compileTestResult(t, capability.Result{Action: domain.ActionResult{Status: "succeeded", Output: json.RawMessage(`{"ok":"wrong"}`)}}, `{"type":"object","required":["ok"],"properties":{"ok":{"type":"boolean"}},"additionalProperties":false}`)
		defer compiled.Close()
		if compiled.Envelope.ProviderOutcome != domain.ResultProviderFailed || compiled.Envelope.Error == nil || compiled.Envelope.Error.Code != "provider_contract_invalid" {
			t.Fatalf("envelope=%#v", compiled.Envelope)
		}
	})
}

func TestDiagnosticBundleVerifierRejectsDigestAndTrailingData(t *testing.T) {
	source, err := NewDiagnosticBundleSource([]DiagnosticSection{{Kind: CompleteDiagnostic, Source: newByteSource([]byte("diagnostic"))}, {Kind: InvalidSemanticOutput, Source: newByteSource([]byte("invalid"))}})
	if err != nil {
		t.Fatal(err)
	}
	reader, _ := source.Open()
	raw, _ := io.ReadAll(reader)
	_ = reader.Close()
	if len(raw) != 91+len("diagnostic")+len("invalid") {
		t.Fatalf("two-section overhead=%d", len(raw)-len("diagnostic")-len("invalid"))
	}
	if err := VerifyDiagnosticBundle(bytes.NewReader(raw), int64(len(raw))); err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), raw...)
	corrupt[len(corrupt)-1] ^= 1
	if err := VerifyDiagnosticBundle(bytes.NewReader(corrupt), int64(len(corrupt))); err == nil {
		t.Fatal("corrupt section digest was accepted")
	}
	trailing := append(append([]byte(nil), raw...), 0)
	if err := VerifyDiagnosticBundle(bytes.NewReader(trailing), int64(len(trailing))); err == nil {
		t.Fatal("trailing diagnostic data was accepted")
	}
}
