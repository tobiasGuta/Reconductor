package hypothesis

import (
	"encoding/json"
	"strings"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/policy"
)

// CapabilityRegistry is the interface required for capability admission, matching capability.Registry.
type CapabilityRegistry interface {
	Get(name string) (capability.Capability, bool)
	ValidateDefinitionInput(name string, raw json.RawMessage) error
}

// ScopeValidator is the interface required for scope authorization, matching scope.Scope.
type ScopeValidator interface {
	Allows(target string) bool
}

// Validator enforces deterministic admission rules on candidate hypotheses.
type Validator struct {
	Registry CapabilityRegistry
	Scope    ScopeValidator
}

// NewValidator constructs an admission validator using Reconductor's real registry and scope.
func NewValidator(registry CapabilityRegistry, scope ScopeValidator) *Validator {
	return &Validator{
		Registry: registry,
		Scope:    scope,
	}
}

// Validate validates an untrusted candidate against safe context, capability registry, and scope.
func (v *Validator) Validate(ctx SafeContext, rawCandidate CandidateHypothesis) AdmittedHypothesis {
	var reasons []ReasonCode

	// 1. Structural Candidate Validation
	if strings.TrimSpace(rawCandidate.Statement) == "" ||
		strings.TrimSpace(rawCandidate.Rationale) == "" ||
		strings.TrimSpace(rawCandidate.CandidateType) == "" {
		reasons = append(reasons, ReasonMalformedCandidate)
	}

	// Build authoritative evidence lookup table: ArtifactID -> map[Locator]bool
	evidenceUniverse := make(map[string]map[string]bool)
	for _, ev := range ctx.Evidence {
		locMap := make(map[string]bool)
		for _, loc := range ev.Locators {
			locMap[loc] = true
		}
		evidenceUniverse[ev.ArtifactID] = locMap
	}

	// 2. Validate Evidence Citations
	allCitations := append([]EvidenceCitation{}, rawCandidate.SupportingEvidence...)
	allCitations = append(allCitations, rawCandidate.ContradictoryEvidence...)

	for _, cit := range allCitations {
		locMap, found := evidenceUniverse[cit.ArtifactID]
		if !found {
			reasons = append(reasons, ReasonUnknownEvidenceRef)
			continue
		}
		// Invariant: The cited locator must be non-empty and authoritatively observed in that artifact
		normLoc := sanitizeLocator(cit.Locator)
		if cit.Locator == "" || (!locMap[cit.Locator] && !locMap[normLoc]) {
			reasons = append(reasons, ReasonEvidenceMismatch)
		}
	}

	// 3. Validate Proposed Action (if present)
	var authoritativeRisk policy.Risk = policy.Passive
	var approvalRequired bool = false
	policyStatus := "not_evaluated"

	if rawCandidate.ProposedAction != nil {
		action := rawCandidate.ProposedAction
		capName := strings.TrimSpace(action.Capability)

		if capName == "" {
			reasons = append(reasons, ReasonUnknownCapability)
		} else if v.Registry != nil {
			capInstance, ok := v.Registry.Get(capName)
			if !ok {
				reasons = append(reasons, ReasonUnknownCapability)
			} else {
				manifest := capInstance.Manifest()
				authoritativeRisk = manifest.Risk
				approvalRequired = manifest.ApprovalRequired

				// Validate arguments against real capability schema / validator
				if err := v.Registry.ValidateDefinitionInput(capName, action.Parameters); err != nil {
					reasons = append(reasons, ReasonInvalidActionArgs)
				}
			}
		}

		// Validate target against real scope
		targetURL := strings.TrimSpace(action.TargetURL)
		if targetURL == "" {
			reasons = append(reasons, ReasonTargetOutOfScope)
		} else if v.Scope != nil {
			if !v.Scope.Allows(targetURL) {
				reasons = append(reasons, ReasonTargetOutOfScope)
			}
		}
	}

	// Normalize candidate (sorts citations, assumptions, canonicalizes parameters)
	normCandidate, err := NormalizeCandidate(rawCandidate)
	if err != nil {
		reasons = append(reasons, ReasonInvalidActionArgs)
		normCandidate = rawCandidate
	}

	detID, err := ComputeDeterministicID(normCandidate)
	if err != nil {
		detID = "admitted-error"
	}

	// Deduplicate reason codes
	uniqueReasons := dedupReasons(reasons)

	status := "admitted"
	if len(uniqueReasons) > 0 {
		status = "rejected"
	}

	return AdmittedHypothesis{
		DeterministicID:        detID,
		Candidate:              normCandidate,
		ValidationStatus:       status,
		RejectionReasons:       uniqueReasons,
		AuthoritativeRisk:      authoritativeRisk,
		ApprovalRequired:       approvalRequired,
		PolicyEvaluationStatus: policyStatus,
		AdmittedAt:             FixedTestAdmittedEpoch,
	}
}

func dedupReasons(in []ReasonCode) []ReasonCode {
	if len(in) == 0 {
		return []ReasonCode{}
	}
	seen := make(map[ReasonCode]bool, len(in))
	out := make([]ReasonCode, 0, len(in))
	for _, r := range in {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}
