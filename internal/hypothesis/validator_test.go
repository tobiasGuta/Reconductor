package hypothesis

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/scope"
)

type testCapability struct {
	manifest capability.Manifest
}

func (t testCapability) Manifest() capability.Manifest                      { return t.manifest }
func (t testCapability) Validate(context.Context, capability.Request) error { return nil }
func (t testCapability) Execute(context.Context, capability.Request) (capability.Result, error) {
	return capability.Result{}, nil
}

type testRegistry struct {
	caps map[string]capability.Capability
}

func (r testRegistry) Get(name string) (capability.Capability, bool) {
	c, ok := r.caps[name]
	return c, ok
}

func (r testRegistry) ValidateDefinitionInput(name string, raw json.RawMessage) error {
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	if name == "probe.http" {
		if _, ok := parsed["targets"]; !ok {
			return fmt.Errorf("probe.http requires targets")
		}
	}
	return nil
}

type testScope struct {
	allowedPrefix string
}

func (s testScope) Allows(target string) bool {
	return len(s.allowedPrefix) > 0 && len(target) >= len(s.allowedPrefix) && target[:len(s.allowedPrefix)] == s.allowedPrefix
}

func setupTestValidator() *Validator {
	reg := testRegistry{
		caps: map[string]capability.Capability{
			"probe.http": testCapability{
				manifest: capability.Manifest{
					Name:             "probe.http",
					Version:          "4",
					Risk:             policy.Low,
					ApprovalRequired: false,
				},
			},
			"scan.nuclei": testCapability{
				manifest: capability.Manifest{
					Name:             "scan.nuclei",
					Version:          "2",
					Risk:             policy.Moderate,
					ApprovalRequired: true,
				},
			},
		},
	}
	sc := testScope{allowedPrefix: "https://api.target.com"}
	return NewValidator(reg, sc)
}

func TestValidator_AdmitValidCandidate(t *testing.T) {
	val := setupTestValidator()
	ctx := SafeContext{
		Evidence: []SafeEvidenceRef{
			{
				ArtifactID: "art-1",
				Locators:   []string{"https://api.target.com/actuator/env"},
			},
		},
	}

	cand := CandidateHypothesis{
		CandidateType: "exposed_actuator_interface",
		Statement:     "Actuator exposed",
		Rationale:     "HTTP 200 observed",
		SupportingEvidence: []EvidenceCitation{
			{ArtifactID: "art-1", Locator: "https://api.target.com/actuator/env"},
		},
		ProposedAction: &ProposedAction{
			Capability: "probe.http",
			TargetURL:  "https://api.target.com/actuator/env",
			Parameters: json.RawMessage(`{"targets":["https://api.target.com/actuator/env"],"method":"GET"}`),
		},
	}

	admitted := val.Validate(ctx, cand)
	if admitted.ValidationStatus != "admitted" {
		t.Fatalf("expected admitted, got %s (reasons: %v)", admitted.ValidationStatus, admitted.RejectionReasons)
	}
	if admitted.AuthoritativeRisk != policy.Low {
		t.Errorf("expected AuthoritativeRisk Low, got %s", admitted.AuthoritativeRisk)
	}
	if admitted.ApprovalRequired != false {
		t.Errorf("expected ApprovalRequired false, got %v", admitted.ApprovalRequired)
	}
	if admitted.DeterministicID == "" || admitted.DeterministicID == "admitted-error" {
		t.Errorf("invalid deterministic ID: %s", admitted.DeterministicID)
	}
}

func TestValidator_DeterministicIDCanonicalEquivalence(t *testing.T) {
	// Candidate 1: action params with key ordering A: targets, method
	cand1 := CandidateHypothesis{
		CandidateType: "exposed_actuator_interface",
		Statement:     "Actuator exposed",
		Rationale:     "HTTP 200 observed",
		SupportingEvidence: []EvidenceCitation{
			{ArtifactID: "art-1", Locator: "https://api.target.com/actuator/env"},
			{ArtifactID: "art-2", Locator: "https://api.target.com/actuator/health"},
		},
		Assumptions: []string{"beta", "alpha"},
		ProposedAction: &ProposedAction{
			Capability: "probe.http",
			TargetURL:  "https://api.target.com/actuator/env",
			Parameters: json.RawMessage(`{"targets":["https://api.target.com/actuator/env"],"method":"GET"}`),
		},
	}

	// Candidate 2: action params with reversed key ordering, whitespace differences, and reversed citations/assumptions
	cand2 := CandidateHypothesis{
		CandidateType: "exposed_actuator_interface",
		Statement:     "Actuator exposed",
		Rationale:     "HTTP 200 observed",
		SupportingEvidence: []EvidenceCitation{
			{ArtifactID: "art-2", Locator: "https://api.target.com/actuator/health"},
			{ArtifactID: "art-1", Locator: "https://api.target.com/actuator/env"},
		},
		Assumptions: []string{"alpha", "beta"},
		ProposedAction: &ProposedAction{
			Capability: "probe.http",
			TargetURL:  "https://api.target.com/actuator/env",
			Parameters: json.RawMessage(`{  "method":  "GET" ,  "targets": [ "https://api.target.com/actuator/env" ]  }`),
		},
	}

	id1, err1 := ComputeDeterministicID(cand1)
	if err1 != nil {
		t.Fatalf("cand1 ID error: %v", err1)
	}
	id2, err2 := ComputeDeterministicID(cand2)
	if err2 != nil {
		t.Fatalf("cand2 ID error: %v", err2)
	}

	if id1 != id2 {
		t.Errorf("expected identical deterministic IDs for semantically identical candidates:\nid1: %s\nid2: %s", id1, id2)
	}
}

func TestValidator_DeterministicID_CitationsReorderingEquivalence(t *testing.T) {
	// Candidate A: SupportingEvidence in order [art-1, art-2]
	candA := CandidateHypothesis{
		CandidateType: "exposed_actuator_interface",
		Statement:     "Actuator exposed",
		Rationale:     "HTTP 200 observed",
		SupportingEvidence: []EvidenceCitation{
			{ArtifactID: "art-1", Locator: "https://api.target.com/actuator/env"},
			{ArtifactID: "art-2", Locator: "https://api.target.com/actuator/health"},
		},
		ProposedAction: &ProposedAction{
			Capability: "probe.http",
			TargetURL:  "https://api.target.com/actuator/env",
			Parameters: json.RawMessage(`{"method":"GET","targets":["https://api.target.com/actuator/env"]}`),
		},
	}

	// Candidate B: SupportingEvidence in opposite order [art-2, art-1]
	candB := CandidateHypothesis{
		CandidateType: "exposed_actuator_interface",
		Statement:     "Actuator exposed",
		Rationale:     "HTTP 200 observed",
		SupportingEvidence: []EvidenceCitation{
			{ArtifactID: "art-2", Locator: "https://api.target.com/actuator/health"},
			{ArtifactID: "art-1", Locator: "https://api.target.com/actuator/env"},
		},
		ProposedAction: &ProposedAction{
			Capability: "probe.http",
			TargetURL:  "https://api.target.com/actuator/env",
			Parameters: json.RawMessage(`{"method":"GET","targets":["https://api.target.com/actuator/env"]}`),
		},
	}

	idA, errA := ComputeDeterministicID(candA)
	if errA != nil {
		t.Fatalf("candA ID error: %v", errA)
	}
	idB, errB := ComputeDeterministicID(candB)
	if errB != nil {
		t.Fatalf("candB ID error: %v", errB)
	}

	if idA != idB {
		t.Errorf("expected ComputeDeterministicID(candidateA) == ComputeDeterministicID(candidateB), got %s != %s", idA, idB)
	}
}

func TestValidator_FabricatedLocatorMismatchWithValidActionTarget(t *testing.T) {
	val := setupTestValidator()
	// Artifact A legitimately observes Endpoint A.
	ctx := SafeContext{
		Evidence: []SafeEvidenceRef{
			{
				ArtifactID: "art-A",
				Locators:   []string{"https://api.target.com/endpoint-A"},
			},
		},
	}

	// Candidate action legitimately targets Endpoint A.
	// But candidate cites Artifact A and supplies Endpoint B as the citation Locator.
	cand := CandidateHypothesis{
		CandidateType: "exposed_endpoint",
		Statement:     "Endpoint A is vulnerable",
		Rationale:     "Citing Artifact A for Endpoint A",
		SupportingEvidence: []EvidenceCitation{
			{ArtifactID: "art-A", Locator: "https://api.target.com/endpoint-B"},
		},
		ProposedAction: &ProposedAction{
			Capability: "probe.http",
			TargetURL:  "https://api.target.com/endpoint-A",
			Parameters: json.RawMessage(`{"targets":["https://api.target.com/endpoint-A"]}`),
		},
	}

	admitted := val.Validate(ctx, cand)
	if admitted.ValidationStatus != "rejected" {
		t.Fatalf("expected rejected, got %s", admitted.ValidationStatus)
	}
	hasMismatch := false
	for _, r := range admitted.RejectionReasons {
		if r == ReasonEvidenceMismatch {
			hasMismatch = true
		}
	}
	if !hasMismatch {
		t.Errorf("expected ReasonEvidenceMismatch in %v", admitted.RejectionReasons)
	}
}

func TestValidator_EvidenceMismatchRejection(t *testing.T) {
	val := setupTestValidator()
	// Artifact 1 belongs to endpoint A
	ctx := SafeContext{
		Evidence: []SafeEvidenceRef{
			{
				ArtifactID: "art-1",
				Locators:   []string{"https://api.target.com/endpoint-A"},
			},
		},
	}

	// Candidate cites Artifact 1 for endpoint B
	cand := CandidateHypothesis{
		CandidateType: "exposed_actuator_interface",
		Statement:     "Endpoint B is vulnerable",
		Rationale:     "Citing Artifact 1",
		SupportingEvidence: []EvidenceCitation{
			{ArtifactID: "art-1", Locator: "https://api.target.com/endpoint-B"},
		},
	}

	admitted := val.Validate(ctx, cand)
	if admitted.ValidationStatus != "rejected" {
		t.Fatalf("expected rejected for evidence locator mismatch, got %s", admitted.ValidationStatus)
	}

	hasMismatch := false
	for _, r := range admitted.RejectionReasons {
		if r == ReasonEvidenceMismatch {
			hasMismatch = true
		}
	}
	if !hasMismatch {
		t.Errorf("expected ReasonEvidenceMismatch in rejection reasons, got %v", admitted.RejectionReasons)
	}
}

func TestValidator_UnknownEvidenceRefRejection(t *testing.T) {
	val := setupTestValidator()
	ctx := SafeContext{
		Evidence: []SafeEvidenceRef{
			{
				ArtifactID: "art-real",
				Locators:   []string{"https://api.target.com/real"},
			},
		},
	}

	cand := CandidateHypothesis{
		CandidateType: "exposed_actuator_interface",
		Statement:     "Test statement",
		Rationale:     "Test rationale",
		SupportingEvidence: []EvidenceCitation{
			{ArtifactID: "art-fabricated-999", Locator: "https://api.target.com/real"},
		},
	}

	admitted := val.Validate(ctx, cand)
	if admitted.ValidationStatus != "rejected" {
		t.Fatalf("expected rejection for unknown evidence ref, got %s", admitted.ValidationStatus)
	}

	hasUnknownRef := false
	for _, r := range admitted.RejectionReasons {
		if r == ReasonUnknownEvidenceRef {
			hasUnknownRef = true
		}
	}
	if !hasUnknownRef {
		t.Errorf("expected ReasonUnknownEvidenceRef in %v", admitted.RejectionReasons)
	}
}

func TestValidator_TargetOutOfScopeRejection(t *testing.T) {
	val := setupTestValidator()
	ctx := SafeContext{}

	cand := CandidateHypothesis{
		CandidateType: "out_of_scope_action",
		Statement:     "Testing external domain",
		Rationale:     "Model suggested scanning external site",
		ProposedAction: &ProposedAction{
			Capability: "probe.http",
			TargetURL:  "https://evil-unauthorized.com/test",
			Parameters: json.RawMessage(`{"targets":["https://evil-unauthorized.com/test"]}`),
		},
	}

	admitted := val.Validate(ctx, cand)
	if admitted.ValidationStatus != "rejected" {
		t.Fatalf("expected rejection for out-of-scope target, got %s", admitted.ValidationStatus)
	}

	hasScopeRejection := false
	for _, r := range admitted.RejectionReasons {
		if r == ReasonTargetOutOfScope {
			hasScopeRejection = true
		}
	}
	if !hasScopeRejection {
		t.Errorf("expected ReasonTargetOutOfScope in %v", admitted.RejectionReasons)
	}
}

func TestValidator_UnknownCapabilityRejection(t *testing.T) {
	val := setupTestValidator()
	ctx := SafeContext{}

	cand := CandidateHypothesis{
		CandidateType: "invalid_action",
		Statement:     "Attempting shell or fake capability",
		Rationale:     "Model suggested fake exploit capability",
		ProposedAction: &ProposedAction{
			Capability: "exploit.rce",
			TargetURL:  "https://api.target.com/test",
			Parameters: json.RawMessage(`{}`),
		},
	}

	admitted := val.Validate(ctx, cand)
	if admitted.ValidationStatus != "rejected" {
		t.Fatalf("expected rejection for unknown capability, got %s", admitted.ValidationStatus)
	}

	hasCapRejection := false
	for _, r := range admitted.RejectionReasons {
		if r == ReasonUnknownCapability {
			hasCapRejection = true
		}
	}
	if !hasCapRejection {
		t.Errorf("expected ReasonUnknownCapability in %v", admitted.RejectionReasons)
	}
}

func TestValidator_RealReconductorScopeIntegration(t *testing.T) {
	// Verify real scope.Compile works with Validator
	realScope, err := scope.Compile([]scope.Rule{
		{Protocol: "https", Host: "api.target.com", Port: "443", File: ".*", Enabled: true},
	}, nil)
	if err != nil {
		t.Fatalf("scope compile failed: %v", err)
	}

	val := NewValidator(testRegistry{}, realScope)

	// In-scope action
	admittedIn := val.Validate(SafeContext{}, CandidateHypothesis{
		CandidateType: "test",
		Statement:     "test",
		Rationale:     "test",
		ProposedAction: &ProposedAction{
			Capability: "probe.http",
			TargetURL:  "https://api.target.com/v1/users",
			Parameters: json.RawMessage(`{}`),
		},
	})
	for _, r := range admittedIn.RejectionReasons {
		if r == ReasonTargetOutOfScope {
			t.Errorf("target should be in scope")
		}
	}

	// Out-of-scope action
	admittedOut := val.Validate(SafeContext{}, CandidateHypothesis{
		CandidateType: "test",
		Statement:     "test",
		Rationale:     "test",
		ProposedAction: &ProposedAction{
			Capability: "probe.http",
			TargetURL:  "https://other.com/v1/users",
			Parameters: json.RawMessage(`{}`),
		},
	})
	hasScopeOut := false
	for _, r := range admittedOut.RejectionReasons {
		if r == ReasonTargetOutOfScope {
			hasScopeOut = true
		}
	}
	if !hasScopeOut {
		t.Errorf("target should be rejected as out-of-scope")
	}
}
