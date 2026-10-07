package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func preparedFixture(t *testing.T, memberCount int) (PreparedManifestV1, PreparedControlV1) {
	t.Helper()
	setID, manifestID, storeID, incarnation := NewID(), NewID(), NewID(), NewID()
	attemptID, occurrenceID := NewID(), NewID()
	now := time.Now().UTC().Truncate(time.Microsecond)
	members := make([]PreparedMemberV1, memberCount)
	refs := make([]ResultArtifactRefV1, memberCount)
	roles := []ResultArtifactRoleV1{ArtifactRoleProviderStdout, ArtifactRoleProviderStderr, ArtifactRoleProviderDiagnostic, ArtifactRoleSemanticResult}
	for i := range members {
		artifactID, publicationID := NewID(), NewID()
		preparedKey, _ := PreparedMemberKey(setID, i)
		value := string(artifactID)
		role := roles[4-memberCount+i]
		members[i] = PreparedMemberV1{Ordinal: i, PublicationID: publicationID, ArtifactID: artifactID, PreparedKey: preparedKey, FinalKey: "v1/" + value[:2] + "/" + value, Role: role, ContentType: "application/" + strings.Repeat("x", 243), ArtifactType: strings.Repeat("a", 64), ContentSizeBytes: 922337203685477580, ContentSHA256: strings.Repeat("a", 64)}
		refs[i] = ResultArtifactRefV1{ArtifactID: artifactID, ArtifactStoreID: storeID, StorageKey: members[i].FinalKey, Role: role, ContentType: members[i].ContentType, ContentSizeBytes: members[i].ContentSizeBytes, ContentSHA256: members[i].ContentSHA256}
	}
	semantic := refs[len(refs)-1]
	diagnosticID := refs[len(refs)-2].ArtifactID
	capabilityName, capabilityVersion := strings.Repeat("c", 128), strings.Repeat("v", 64)
	provider, toolVersion := strings.Repeat("p", DiagnosticMaxBytes), strings.Repeat("t", DiagnosticMaxBytes)
	maxObject := json.RawMessage(`{"x":"` + strings.Repeat("s", DiagnosticMaxBytes-8) + `"}`)
	envelope := ResultEnvelopeV1{Version: ResultEnvelopeVersionV1, ActionRequestID: NewID(), ResultOccurrenceID: occurrenceID, ProviderAttemptID: attemptID, CapabilityName: capabilityName, CapabilityVersion: capabilityVersion, Status: ResultStatusFailed, ProviderOutcome: ResultProviderFailed, Summary: strings.Repeat("s", SafeMessageMaxBytes), PublicationComplete: true, SemanticOutput: SemanticOutputV1{Version: SemanticOutputVersionV1, Mode: SemanticModeArtifactJSON, Completeness: SemanticComplete, Canonicalization: CanonicalJSONVersionV1, ArtifactID: semantic.ArtifactID, ContentSHA256: semantic.ContentSHA256, ContentSizeBytes: semantic.ContentSizeBytes, OutputSchemaSHA256: strings.Repeat("b", 64), NodeCount: 1, MaximumDepth: 1, ProjectionState: ProjectionNotRequired}, Artifacts: refs, Error: &ResultErrorV1{Code: "provider_error", Message: strings.Repeat("e", SafeMessageMaxBytes), DiagnosticArtifactID: &diagnosticID}}
	envelopeJSON, err := envelope.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	envelopeSum := sha256.Sum256(envelopeJSON)
	terminalID, acceptedID, stepID, runID, authID := NewID(), NewID(), NewID(), NewID(), NewID()
	control := PreparedControlV1{Version: PreparedControlVersionV1, SetID: setID, ManifestID: manifestID, ProviderTerminalEventID: terminalID, AcceptedEventID: acceptedID, ProviderOutcome: ResultProviderFailed, Envelope: envelope, EnvelopeSHA256: hex.EncodeToString(envelopeSum[:]), ToolRun: ToolRun{ID: NewID(), StepRunID: stepID, Capability: capabilityName, Provider: provider, ToolVersion: toolVersion, SanitizedArguments: maxObject, ExecutionEnvironment: maxObject, StartedAt: now, CompletedAt: &now, ArtifactIDs: memberArtifactIDs(members), ProviderAttemptID: &attemptID}, Step: PreparedStepV1{ID: stepID, WorkflowRunID: runID, Capability: capabilityName, Status: ResultStatusFailed, ErrorClassification: "provider_error", ErrorDetails: strings.Repeat("e", SafeMessageMaxBytes), CompletedAt: &now, IdempotencyKey: strings.Repeat("i", DiagnosticMaxBytes)}, Admission: PreparedAdmissionV1{ProviderAttemptID: attemptID, PreparedSetID: setID, ActionRequestID: envelope.ActionRequestID, StepAttempt: 2147483647, ExecutionAuthorizationEventID: authID, Provider: provider}, ArtifactRetentionNanos: int64(365 * 24 * time.Hour)}
	controlJSON, err := control.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	controlSum := sha256.Sum256(controlJSON)
	controlKey, _ := PreparedControlKey(setID)
	manifest := PreparedManifestV1{Version: PreparedManifestVersionV1, SetID: setID, ManifestID: manifestID, ArtifactStoreID: storeID, StoreIncarnationNonce: incarnation, StoreBackendKind: "local-v1", StoreMarkerFormat: "reconductor-artifact-store", StoreMarkerVersion: 1, ProviderAttemptID: &attemptID, ResultOccurrenceID: occurrenceID, Control: PreparedObjectRefV1{StorageKey: controlKey, ContentSizeBytes: int64(len(controlJSON)), ContentSHA256: hex.EncodeToString(controlSum[:])}, Members: members}
	return manifest, control
}

func memberArtifactIDs(members []PreparedMemberV1) []ID {
	ids := make([]ID, len(members))
	for i := range members {
		ids[i] = members[i].ArtifactID
	}
	return ids
}

func TestPreparedManifestMaximumPopulationFitsBound(t *testing.T) {
	manifest, control := preparedFixture(t, ResultArtifactReferenceMaxCount)
	manifestJSON, err := manifest.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	controlJSON, err := control.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifestJSON) > PreparedManifestMaxBytes || len(controlJSON) > PreparedControlMaxBytes {
		t.Fatalf("prepared bounds manifest=%d/%d control=%d/%d", len(manifestJSON), PreparedManifestMaxBytes, len(controlJSON), PreparedControlMaxBytes)
	}
	t.Logf("maximum-population prepared bounds manifest=%d/%d control=%d/%d", len(manifestJSON), PreparedManifestMaxBytes, len(controlJSON), PreparedControlMaxBytes)
	if _, err := DecodePreparedManifestV1(manifestJSON); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePreparedControlV1(controlJSON); err != nil {
		t.Fatal(err)
	}
}

func TestPreparedKeysAndLifecycleAreClosed(t *testing.T) {
	setID := NewID()
	prefix, _ := PreparedSetPrefix(setID)
	manifest, _ := PreparedManifestKey(setID)
	control, _ := PreparedControlKey(setID)
	member, _ := PreparedMemberKey(setID, 3)
	if !strings.HasPrefix(manifest, prefix) || !strings.HasPrefix(control, prefix) || !strings.HasPrefix(member, prefix) {
		t.Fatalf("prepared keys escaped set prefix %q: %q %q %q", prefix, manifest, control, member)
	}
	for _, state := range []PreparedEvidenceState{PreparedAllocated, PreparedSealed, PreparedResolvedAdopted, PreparedResolvedAbandoned, PreparedQuarantined, PreparedCleaned} {
		if err := state.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if err := PreparedEvidenceState("reserved").Validate(); err == nil {
		t.Fatal("publication state entered prepared lifecycle")
	}
}
