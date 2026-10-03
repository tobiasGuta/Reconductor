package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func validResultEnvelopeForMatrix(t *testing.T) ResultEnvelopeV1 {
	t.Helper()
	artifactID, storeID := NewID(), NewID()
	semantic := []byte("null")
	content := sha256.Sum256(semantic)
	schema := sha256.Sum256([]byte("{}"))
	reference := ResultArtifactRefV1{
		ArtifactID:       artifactID,
		ArtifactStoreID:  storeID,
		StorageKey:       "v1/" + string(artifactID)[:2] + "/" + string(artifactID),
		Role:             ArtifactRoleSemanticResult,
		ContentType:      "application/json",
		ContentSizeBytes: int64(len(semantic)),
		ContentSHA256:    hex.EncodeToString(content[:]),
	}
	return ResultEnvelopeV1{
		Version:             ResultEnvelopeVersionV1,
		ActionRequestID:     NewID(),
		ResultOccurrenceID:  NewID(),
		ProviderAttemptID:   NewID(),
		CapabilityName:      "test.result",
		CapabilityVersion:   "1",
		Status:              ResultStatusSucceeded,
		ProviderOutcome:     ResultProviderSucceeded,
		Summary:             "ok",
		PublicationComplete: true,
		SemanticOutput: SemanticOutputV1{
			Version:            SemanticOutputVersionV1,
			Mode:               SemanticModeNone,
			Completeness:       SemanticNotProduced,
			Canonicalization:   CanonicalJSONVersionV1,
			ArtifactID:         artifactID,
			ContentSHA256:      reference.ContentSHA256,
			ContentSizeBytes:   reference.ContentSizeBytes,
			OutputSchemaSHA256: hex.EncodeToString(schema[:]),
			NodeCount:          1,
			MaximumDepth:       1,
			ProjectionState:    ProjectionNotRequired,
		},
		Artifacts: []ResultArtifactRefV1{reference},
	}
}

func TestResultEnvelopeExactProviderStatusMatrix(t *testing.T) {
	tests := []struct {
		name      string
		status    ResultEnvelopeStatusV1
		outcome   ResultProviderOutcomeV1
		retryable bool
		code      string
	}{
		{"succeeded", ResultStatusSucceeded, ResultProviderSucceeded, false, ""},
		{"failed", ResultStatusFailed, ResultProviderFailed, false, "provider_error"},
		{"retryable", ResultStatusRetryable, ResultProviderFailed, true, "provider_error"},
		{"timeout failed", ResultStatusFailed, ResultProviderTimeout, false, "timeout"},
		{"timeout retryable", ResultStatusRetryable, ResultProviderTimeout, true, "timeout"},
		{"cancelled", ResultStatusCancelled, ResultProviderCancelled, false, "cancelled"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := validResultEnvelopeForMatrix(t)
			envelope.Status, envelope.ProviderOutcome = test.status, test.outcome
			if test.code != "" {
				envelope.Error = &ResultErrorV1{Code: test.code, Message: "bounded", Retryable: test.retryable}
			}
			if err := envelope.Validate(); err != nil {
				t.Fatalf("valid matrix entry rejected: %v", err)
			}
		})
	}
}

func TestResultEnvelopeRejectsUnlistedMatrixAndAllowsPostProviderLimit(t *testing.T) {
	for name, mutate := range map[string]func(*ResultEnvelopeV1){
		"success with error": func(e *ResultEnvelopeV1) { e.Error = &ResultErrorV1{Code: "provider_error", Message: "bad"} },
		"failed success": func(e *ResultEnvelopeV1) {
			e.Status = ResultStatusFailed
			e.Error = &ResultErrorV1{Code: "provider_error", Message: "bad"}
		},
		"retry cancelled": func(e *ResultEnvelopeV1) {
			e.Status, e.ProviderOutcome = ResultStatusRetryable, ResultProviderCancelled
			e.Error = &ResultErrorV1{Code: "cancelled", Message: "bad", Retryable: true}
		},
	} {
		t.Run(name, func(t *testing.T) {
			envelope := validResultEnvelopeForMatrix(t)
			mutate(&envelope)
			if err := envelope.Validate(); err == nil {
				t.Fatal("unlisted matrix entry accepted")
			}
		})
	}
	for _, outcome := range []ResultProviderOutcomeV1{ResultProviderSucceeded, ResultProviderFailed, ResultProviderTimeout, ResultProviderCancelled} {
		envelope := validResultEnvelopeForMatrix(t)
		envelope.Status, envelope.ProviderOutcome = ResultStatusFailed, outcome
		envelope.SemanticOutput.Mode = SemanticModeArtifactJSON
		envelope.SemanticOutput.Completeness = SemanticComplete
		envelope.SemanticOutput.ProjectionState = ProjectionRejected
		envelope.Error = &ResultErrorV1{Code: "result_contract_limit", Message: "bounded", Limit: &ResultContractLimitV1{Subject: LimitProjectionItem, Unit: LimitBytes, Limit: 65_536, Observed: 65_537}}
		if err := envelope.Validate(); err != nil {
			t.Fatalf("post-provider limit rejected for %s: %v", outcome, err)
		}
	}
}
