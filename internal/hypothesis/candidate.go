package hypothesis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/policy"
)

type ReasonCode string

const (
	ReasonUnknownEvidenceRef ReasonCode = "unknown_evidence_reference"
	ReasonEvidenceMismatch   ReasonCode = "evidence_locator_mismatch"
	ReasonTargetOutOfScope   ReasonCode = "target_out_of_scope"
	ReasonUnknownCapability  ReasonCode = "unknown_capability"
	ReasonInvalidActionArgs  ReasonCode = "invalid_action_arguments"
	ReasonMalformedCandidate ReasonCode = "malformed_candidate"
)

const FixedTestAdmittedEpoch = "2026-09-28T00:00:00Z"

// EvidenceCitation represents an untrusted candidate citation.
type EvidenceCitation struct {
	ArtifactID   string `json:"artifact_id"`
	Locator      string `json:"locator"`
	AdvisoryText string `json:"advisory_text,omitempty"`
}

// ProposedAction represents an untrusted action proposal mapping to a Reconductor capability.
type ProposedAction struct {
	Capability  string          `json:"capability"`
	TargetURL   string          `json:"target_url"`
	Parameters  json.RawMessage `json:"parameters"`
	Description string          `json:"description"`
}

// CandidateHypothesis is the untrusted advisory candidate DTO.
// Notice there are NO fields for finding_state, confirmed_finding, severity, or execution tokens.
type CandidateHypothesis struct {
	CandidateType         string             `json:"candidate_type"`
	Statement             string             `json:"statement"`
	Rationale             string             `json:"rationale"`
	SupportingEvidence    []EvidenceCitation `json:"supporting_evidence"`
	ContradictoryEvidence []EvidenceCitation `json:"contradictory_evidence"`
	Assumptions           []string           `json:"assumptions"`
	MissingEvidence       []string           `json:"missing_evidence"`
	ProposedAction        *ProposedAction    `json:"proposed_action,omitempty"`
	ExpectedOutcome       string             `json:"expected_outcome"`
}

// AdmittedHypothesis is the system-derived, deterministic wrapper around an admitted or rejected candidate.
type AdmittedHypothesis struct {
	DeterministicID        string              `json:"deterministic_id"`
	Candidate              CandidateHypothesis `json:"candidate"`
	ValidationStatus       string              `json:"validation_status"`
	RejectionReasons       []ReasonCode        `json:"rejection_reasons"`
	AuthoritativeRisk      policy.Risk         `json:"authoritative_risk"`
	ApprovalRequired       bool                `json:"approval_required"`
	PolicyEvaluationStatus string              `json:"policy_evaluation_status"`
	AdmittedAt             string              `json:"admitted_at"`
}

// NormalizeCandidate ensures all set-like nested collections are deterministically ordered and action parameters are canonicalized.
func NormalizeCandidate(c CandidateHypothesis) (CandidateHypothesis, error) {
	norm := c
	norm.CandidateType = strings.TrimSpace(c.CandidateType)
	norm.Statement = strings.TrimSpace(c.Statement)
	norm.Rationale = strings.TrimSpace(c.Rationale)
	norm.ExpectedOutcome = strings.TrimSpace(c.ExpectedOutcome)

	norm.SupportingEvidence = normalizeCitations(c.SupportingEvidence)
	norm.ContradictoryEvidence = normalizeCitations(c.ContradictoryEvidence)
	norm.Assumptions = dedupSortStrings(c.Assumptions)
	norm.MissingEvidence = dedupSortStrings(c.MissingEvidence)

	if c.ProposedAction != nil {
		action := *c.ProposedAction
		action.Capability = strings.TrimSpace(action.Capability)
		action.TargetURL = strings.TrimSpace(action.TargetURL)
		action.Description = strings.TrimSpace(action.Description)

		if len(action.Parameters) > 0 {
			// Canonicalize parameters using existing canonicaljson
			_, canonicalParams, _, _, err := canonicaljson.ParseStrict(action.Parameters)
			if err != nil {
				return CandidateHypothesis{}, err
			}
			action.Parameters = canonicalParams
		} else {
			action.Parameters = json.RawMessage(`{}`)
		}
		norm.ProposedAction = &action
	}

	return norm, nil
}

func normalizeCitations(in []EvidenceCitation) []EvidenceCitation {
	if len(in) == 0 {
		return []EvidenceCitation{}
	}
	// Sort by ArtifactID ASC, then Locator ASC
	sorted := make([]EvidenceCitation, len(in))
	copy(sorted, in)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ArtifactID != sorted[j].ArtifactID {
			return sorted[i].ArtifactID < sorted[j].ArtifactID
		}
		return sorted[i].Locator < sorted[j].Locator
	})

	// Deduplicate identical citations
	out := make([]EvidenceCitation, 0, len(sorted))
	seen := make(map[string]bool)
	for _, cit := range sorted {
		key := cit.ArtifactID + "\x00" + cit.Locator
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, cit)
	}
	return out
}

// ComputeDeterministicID computes a deterministic identity hash from a normalized candidate.
func ComputeDeterministicID(c CandidateHypothesis) (string, error) {
	norm, err := NormalizeCandidate(c)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(norm)
	if err != nil {
		return "", err
	}
	_, canonical, _, _, err := canonicaljson.ParseStrict(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "admitted-" + hex.EncodeToString(sum[:8]), nil
}
