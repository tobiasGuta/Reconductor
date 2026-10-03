package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
)

type semanticResolverFake struct {
	raw     []byte
	request domain.SemanticBindingResolutionV1
}

func (r *semanticResolverFake) ResolveSemanticBinding(_ context.Context, request domain.SemanticBindingResolutionV1) (io.ReadCloser, error) {
	r.request = request
	return io.NopCloser(strings.NewReader(string(r.raw))), nil
}

type bindingCapability struct{ manifest capability.Manifest }

func (c bindingCapability) Manifest() capability.Manifest                    { return c.manifest }
func (bindingCapability) Validate(context.Context, capability.Request) error { return nil }
func (bindingCapability) Execute(context.Context, capability.Request) (capability.Result, error) {
	return capability.Result{}, nil
}

func artifactEnvelope(t *testing.T, semantic []byte, capabilityName, version string) json.RawMessage {
	t.Helper()
	artifactID, storeID := domain.NewID(), domain.NewID()
	key, err := artifact.StorageKeyFor(artifactID)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(semantic)
	schemaSum := sha256.Sum256([]byte(`{}`))
	reference := domain.ResultArtifactRefV1{ArtifactID: artifactID, ArtifactStoreID: storeID, StorageKey: key, Role: domain.ArtifactRoleSemanticResult, ContentType: "application/json", ContentSizeBytes: int64(len(semantic)), ContentSHA256: hex.EncodeToString(sum[:])}
	envelope := domain.ResultEnvelopeV1{Version: domain.ResultEnvelopeVersionV1, ActionRequestID: domain.NewID(), ResultOccurrenceID: domain.NewID(), ProviderAttemptID: domain.NewID(), CapabilityName: capabilityName, CapabilityVersion: version, Status: domain.ResultStatusSucceeded, ProviderOutcome: domain.ResultProviderSucceeded, Summary: "ok", PublicationComplete: true, SemanticOutput: domain.SemanticOutputV1{Version: domain.SemanticOutputVersionV1, Mode: domain.SemanticModeArtifactJSON, Completeness: domain.SemanticComplete, Canonicalization: domain.CanonicalJSONVersionV1, ArtifactID: artifactID, ContentSHA256: reference.ContentSHA256, ContentSizeBytes: reference.ContentSizeBytes, OutputSchemaSHA256: hex.EncodeToString(schemaSum[:]), NodeCount: 8, MaximumDepth: 3, ProjectionState: domain.ProjectionNotRequired}, Artifacts: []domain.ResultArtifactRefV1{reference}}
	raw, err := envelope.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestArtifactBackedBindingUsesAuthoritativeResolverAndCompatibleArrayMapping(t *testing.T) {
	semantic := []byte(`{"huge":"` + strings.Repeat("x", 80_000) + `","records":[{"name":"one"},"{\"name\":\"two\"}",{"other":true},7]}`)
	resolver := &semanticResolverFake{raw: semantic}
	registry := capability.NewRegistry()
	for _, manifest := range []capability.Manifest{{Name: "source", Version: "1", Risk: policy.Low}, {Name: "sink", Version: "1", Risk: policy.Low}} {
		if err := registry.Register(bindingCapability{manifest: manifest}); err != nil {
			t.Fatal(err)
		}
	}
	programID, runID := domain.NewID(), domain.NewID()
	sourceRunID := domain.NewID()
	state := &State{Steps: map[string]*StepState{"source-step": {Run: domain.StepRun{ID: sourceRunID, WorkflowRunID: runID, StepDefinitionID: "source-step", Capability: "source", Status: domain.StepSucceeded, Output: artifactEnvelope(t, semantic, "source", "1")}}}}
	resolved, err := resolveInput(context.Background(), &Engine{Registry: registry, BindingResolver: resolver}, programID, runID, Step{ID: "sink-step", Capability: "sink", Input: json.RawMessage(`{"names":[]}`), Bindings: map[string]string{"names": "source-step.output.records.name"}}, state)
	if err != nil {
		t.Fatal(err)
	}
	if string(resolved) != `{"names":["one","two"]}` {
		t.Fatalf("resolved=%s", resolved)
	}
	if resolver.request.ConsumerProgramID != programID || resolver.request.ConsumerWorkflowRunID != runID || resolver.request.ConsumerStepDefinition != "sink-step" || resolver.request.SourceStepDefinition != "source-step" || resolver.request.Reference.Selector != "records.name" || resolver.request.Reference.SourceStepRunID != sourceRunID {
		t.Fatalf("authority request=%#v", resolver.request)
	}
}

func TestArtifactBindingLimitRequiresBothManifestAndClosedSchemaBranch(t *testing.T) {
	semantic := []byte(`{"value":"` + strings.Repeat("x", domain.InlineSemanticJSONMaxBytes+1) + `"}`)
	referenceBranch := `{"oneOf":[{"type":"string"},` + exactReferenceSchemaBranch() + `]}`
	manifest := capability.Manifest{Name: "sink", Version: "1", SupportsSemanticBindingReferences: true, InputSchema: json.RawMessage(referenceBranch)}
	if !supportsSemanticBindingReferences(manifest) {
		t.Fatal("exact closed reference branch was not recognized")
	}
	manifest.SupportsSemanticBindingReferences = false
	if supportsSemanticBindingReferences(manifest) {
		t.Fatal("schema branch enabled references without manifest declaration")
	}
	manifest.SupportsSemanticBindingReferences = true
	manifest.InputSchema = json.RawMessage(`{"type":"object"}`)
	if supportsSemanticBindingReferences(manifest) {
		t.Fatal("generic object schema enabled references")
	}
	_, err := selectSemanticJSON(strings.NewReader(string(semantic)), []string{"value"})
	if _, ok := err.(*bindingMaterializationLimitError); !ok {
		t.Fatalf("large selection error=%T %v", err, err)
	}
}

func exactReferenceSchemaBranch() string {
	return `{"type":"object","additionalProperties":false,"required":["schema_id","version","source_program_id","source_workflow_run_id","source_step_run_id","source_action_request_id","source_result_occurrence_id","source_provider_attempt_id","source_artifact_id","artifact_store_id","storage_key","selector","content_sha256","content_size_bytes","output_schema_sha256"],"properties":{"schema_id":{"const":"` + domain.SemanticBindingReferenceSchemaV1 + `"},"version":{"const":"` + domain.SemanticBindingReferenceVersionV1 + `"},"source_program_id":{"type":"string"},"source_workflow_run_id":{"type":"string"},"source_step_run_id":{"type":"string"},"source_action_request_id":{"type":"string"},"source_result_occurrence_id":{"type":"string"},"source_provider_attempt_id":{"type":"string"},"source_artifact_id":{"type":"string"},"artifact_store_id":{"type":"string"},"storage_key":{"type":"string"},"selector":{"type":"string"},"content_sha256":{"type":"string"},"content_size_bytes":{"type":"integer"},"output_schema_sha256":{"type":"string"}}}`
}

func TestReferenceSupportRejectsStructurallySimilarBranch(t *testing.T) {
	manifest := capability.Manifest{Name: "sink", Version: "1", SupportsSemanticBindingReferences: true, InputSchema: json.RawMessage(`{"oneOf":[{"type":"object","additionalProperties":false,"required":["schema_id"],"properties":{"schema_id":{"const":"` + domain.SemanticBindingReferenceSchemaV1 + `"}}}]}`)}
	if supportsSemanticBindingReferences(manifest) {
		t.Fatal("structurally similar reference branch enabled consumption")
	}
}

func TestStoredResultEnvelopeDetectionNeverFallsBack(t *testing.T) {
	semantic := []byte(`{"value":true}`)
	valid := artifactEnvelope(t, semantic, "source", "1")
	unknown := []byte(strings.Replace(string(valid), domain.ResultEnvelopeVersionV1, "result-envelope/v9", 1))
	if _, _, err := decodeStoredResult(unknown); err == nil || !strings.Contains(err.Error(), "result_contract_version_unsupported") {
		t.Fatalf("unknown version error=%v", err)
	}
	invalid := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"unexpected":true}`)...)
	if _, _, err := decodeStoredResult(invalid); err == nil || !strings.Contains(err.Error(), "invalid result envelope") {
		t.Fatalf("invalid v1 error=%v", err)
	}
	legacy := json.RawMessage(`{"value":"` + strings.Repeat("x", domain.InlineSemanticJSONMaxBytes) + `"}`)
	if _, _, err := resolveBindingValue(context.Background(), &Engine{}, "", "", "sink", "source", domain.StepRun{Output: legacy}, "value"); err == nil || !strings.Contains(err.Error(), "result_contract_legacy_unavailable") {
		t.Fatalf("oversized legacy error=%v", err)
	}
}

func TestSelectorRejectsContinuationThroughNullAndAcceptsTerminalNull(t *testing.T) {
	value := map[string]any{"terminal": nil}
	selected, err := applySelector(value, []string{"terminal"}, false)
	if err != nil || selected != nil {
		t.Fatalf("terminal null=%#v error=%v", selected, err)
	}
	if _, err := applySelector(value, []string{"terminal", "next"}, false); err == nil {
		t.Fatal("continued through null")
	}
}
