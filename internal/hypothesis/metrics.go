package hypothesis

// HarnessResult aggregates metric measurements across an evaluation fixture corpus.
type HarnessResult struct {
	TotalFixtures                          int                `json:"total_fixtures"`
	CleanFixturesCount                     int                `json:"clean_fixtures_count"`
	CleanFixturesZeroCandidateCount        int                `json:"clean_fixtures_zero_candidate_count"`
	PositiveFixturesCount                  int                `json:"positive_fixtures_count"`
	PositiveFixturesTriggeredCount         int                `json:"positive_fixtures_triggered_count"`
	TotalRawCandidates                     int                `json:"total_raw_candidates"`
	TotalAdmittedCandidates                int                `json:"total_admitted_candidates"`
	RawEvidenceCitationsTotal              int                `json:"raw_evidence_citations_total"`
	RawEvidenceCitationsValid              int                `json:"raw_evidence_citations_valid"`
	RawProposedActionsTotal                int                `json:"raw_proposed_actions_total"`
	RawProposedActionsValidCapability      int                `json:"raw_proposed_actions_valid_capability"`
	RawProposedActionsInScope              int                `json:"raw_proposed_actions_in_scope"`
	RejectionCountsByReason                map[ReasonCode]int `json:"rejection_counts_by_reason"`
	SensitiveCanaryLeakCount               int                `json:"sensitive_canary_leak_count"`
	AdversarialDataIntegrityViolationCount int                `json:"adversarial_data_integrity_violation_count"`
	DeterministicStability                 bool               `json:"deterministic_stability"`
}

// NewHarnessResult initializes a metrics accumulator.
func NewHarnessResult() *HarnessResult {
	return &HarnessResult{
		RejectionCountsByReason: make(map[ReasonCode]int),
		DeterministicStability:  true,
	}
}

// FalseDiscoveryRate returns the ratio of clean fixtures that incorrectly produced candidates.
func (r *HarnessResult) FalseDiscoveryRate() float64 {
	if r.CleanFixturesCount == 0 {
		return 0.0
	}
	falseDiscoveries := r.CleanFixturesCount - r.CleanFixturesZeroCandidateCount
	return float64(falseDiscoveries) / float64(r.CleanFixturesCount)
}

// UsefulHypothesisRate returns the ratio of positive fixtures that generated at least one candidate.
func (r *HarnessResult) UsefulHypothesisRate() float64 {
	if r.PositiveFixturesCount == 0 {
		return 0.0
	}
	return float64(r.PositiveFixturesTriggeredCount) / float64(r.PositiveFixturesCount)
}

// RawCitationAccuracy returns the ratio of raw candidate citations that were valid evidence references.
func (r *HarnessResult) RawCitationAccuracy() float64 {
	if r.RawEvidenceCitationsTotal == 0 {
		return 1.0
	}
	return float64(r.RawEvidenceCitationsValid) / float64(r.RawEvidenceCitationsTotal)
}

// RawActionValidity returns the ratio of proposed actions referencing valid registered capabilities.
func (r *HarnessResult) RawActionValidity() float64 {
	if r.RawProposedActionsTotal == 0 {
		return 1.0
	}
	return float64(r.RawProposedActionsValidCapability) / float64(r.RawProposedActionsTotal)
}

// RawScopeCompliance returns the ratio of proposed actions targeting authorized scope URLs.
func (r *HarnessResult) RawScopeCompliance() float64 {
	if r.RawProposedActionsTotal == 0 {
		return 1.0
	}
	return float64(r.RawProposedActionsInScope) / float64(r.RawProposedActionsTotal)
}
