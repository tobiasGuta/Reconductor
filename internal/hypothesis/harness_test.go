package hypothesis

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	"github.com/tobiasGuta/Reconductor/internal/scope"
)

type SyntheticFixture struct {
	FixtureID   string             `json:"fixture_id"`
	Category    string             `json:"category"`
	Description string             `json:"description"`
	Input       RawEvaluationInput `json:"input"`
	Expected    struct {
		CandidateCount int      `json:"candidate_count"`
		CandidateTypes []string `json:"candidate_types"`
		ShouldAdmitAll bool     `json:"should_admit_all"`
	} `json:"expected"`
}

func loadFixtures(t *testing.T) []SyntheticFixture {
	matches, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatalf("failed to glob fixtures: %v", err)
	}
	if len(matches) < 17 {
		t.Fatalf("expected at least 17 fixtures, found %d", len(matches))
	}

	fixtures := make([]SyntheticFixture, 0, len(matches))
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", path, err)
		}

		// Verify zero trailing whitespace in fixture file
		lines := strings.Split(string(data), "\n")
		for lineIdx, line := range lines {
			if strings.HasSuffix(line, " ") || strings.HasSuffix(line, "\t") || strings.HasSuffix(line, "\r") {
				t.Errorf("fixture %s has trailing whitespace on line %d", path, lineIdx+1)
			}
		}

		var f SyntheticFixture
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&f); err != nil {
			t.Fatalf("failed to parse fixture %s: %v", path, err)
		}
		fixtures = append(fixtures, f)
	}
	return fixtures
}

func TestSyntheticFixturesHarness(t *testing.T) {
	fixtures := loadFixtures(t)
	metrics := NewHarnessResult()
	metrics.TotalFixtures = len(fixtures)

	// Initialize real Reconductor capability registry
	realRegistry := providers.Registry(config.Config{
		Tools: config.Tools{
			HTTPX:     "httpx",
			Katana:    "katana",
			Nuclei:    "nuclei",
			Subfinder: "subfinder",
			DNSx:      "dnsx",
			Naabu:     "naabu",
			GAU:       "gau",
		},
	})

	// Initialize real permissive test scope for target.com domains
	realScope, err := scope.Compile([]scope.Rule{
		{Protocol: "https", Host: ".*\\.target\\.com", Port: ".*", File: ".*", Enabled: true},
		{Protocol: "https", Host: "target\\.com", Port: ".*", File: ".*", Enabled: true},
		{Protocol: "http", Host: "target\\.com", Port: ".*", File: ".*", Enabled: true},
	}, nil)
	if err != nil {
		t.Fatalf("failed to compile scope: %v", err)
	}

	validator := NewValidator(realRegistry, realScope)

	canaries := []string{
		"SECRET_BEARER_CANARY",
		"SECRET_API_KEY_CANARY",
		"SECRET_PASSWORD_CANARY",
		"SECRET_CHANGE_QUERY_CANARY",
		"SECRET_TITLE_PASSWORD_CANARY",
		"SECRET_SESSION_CANARY",
		"SECRET_LOCATOR_CANARY",
		"SECRET_UNREDACTED_CANARY",
	}

	for _, f := range fixtures {
		t.Run(f.FixtureID, func(t *testing.T) {
			// 1. Safe context assembly
			ctx, err := AssembleSafeContext(f.Input)
			if err != nil {
				t.Fatalf("AssembleSafeContext failed: %v", err)
			}

			// Verify context size bound
			rawCtx, err := json.Marshal(ctx)
			if err != nil {
				t.Fatalf("marshal safe context failed: %v", err)
			}
			if len(rawCtx) > MaxContextBytes {
				t.Errorf("safe context exceeds 16 KiB limit: %d bytes", len(rawCtx))
			}

			// Check for sensitive canary leaks
			ctxStr := string(rawCtx)
			for _, canary := range canaries {
				if strings.Contains(ctxStr, canary) {
					metrics.SensitiveCanaryLeakCount++
					t.Errorf("fixture %s leaked canary %s into SafeContext", f.FixtureID, canary)
				}
			}

			// 2. Generate deterministic baseline candidates
			candidates := GenerateBaseline(ctx)
			metrics.TotalRawCandidates += len(candidates)

			// Track category metrics
			switch f.Category {
			case "clean":
				metrics.CleanFixturesCount++
				if len(candidates) == 0 {
					metrics.CleanFixturesZeroCandidateCount++
				} else {
					t.Errorf("clean fixture %s produced %d candidates (expected 0)", f.FixtureID, len(candidates))
				}
			case "positive":
				metrics.PositiveFixturesCount++
				if len(candidates) > 0 {
					metrics.PositiveFixturesTriggeredCount++
				} else {
					t.Errorf("positive fixture %s produced 0 candidates (expected > 0)", f.FixtureID)
				}
			case "semantic_control":
				// Deliberate gap: baseline should produce 0 false confirmed findings
				if len(candidates) != f.Expected.CandidateCount {
					t.Errorf("semantic control fixture %s produced %d candidates (expected %d)", f.FixtureID, len(candidates), f.Expected.CandidateCount)
				}
			case "adversarial":
				// Verify adversarial strings did not compromise control flow or inject capabilities
				for _, c := range candidates {
					if strings.Contains(c.Statement, "rm -rf") || strings.Contains(c.CandidateType, "exploit") {
						metrics.AdversarialDataIntegrityViolationCount++
						t.Errorf("adversarial instruction altered candidate: %v", c)
					}
				}
				for _, capName := range ctx.AllowedCapabilities {
					if capName == "exploit.rce" {
						metrics.AdversarialDataIntegrityViolationCount++
						t.Errorf("adversarial data registered fake capability: %s", capName)
					}
				}
			}

			// Verify expected candidate count
			if len(candidates) != f.Expected.CandidateCount {
				t.Errorf("expected %d candidates, got %d", f.Expected.CandidateCount, len(candidates))
			}

			// 3. Validate each candidate
			for _, cand := range candidates {
				// Metrics tracking
				metrics.RawEvidenceCitationsTotal += len(cand.SupportingEvidence) + len(cand.ContradictoryEvidence)
				for _, cit := range cand.SupportingEvidence {
					for _, ev := range ctx.Evidence {
						if ev.ArtifactID == cit.ArtifactID {
							metrics.RawEvidenceCitationsValid++
							break
						}
					}
				}

				if cand.ProposedAction != nil {
					metrics.RawProposedActionsTotal++
					if _, ok := realRegistry.Get(cand.ProposedAction.Capability); ok {
						metrics.RawProposedActionsValidCapability++
					}
					if realScope.Allows(cand.ProposedAction.TargetURL) {
						metrics.RawProposedActionsInScope++
					}
				}

				admitted := validator.Validate(ctx, cand)
				if admitted.ValidationStatus == "admitted" {
					metrics.TotalAdmittedCandidates++
				} else {
					for _, r := range admitted.RejectionReasons {
						metrics.RejectionCountsByReason[r]++
					}
					if f.Expected.ShouldAdmitAll {
						t.Errorf("fixture %s: expected candidate to be admitted, was rejected with reasons: %v", f.FixtureID, admitted.RejectionReasons)
					}
				}

				// Assert authoritative policy metadata is populated
				if admitted.ValidationStatus == "admitted" && cand.ProposedAction != nil {
					if capInst, ok := realRegistry.Get(cand.ProposedAction.Capability); ok {
						if admitted.AuthoritativeRisk != capInst.Manifest().Risk {
							t.Errorf("AuthoritativeRisk %s != manifest risk %s", admitted.AuthoritativeRisk, capInst.Manifest().Risk)
						}
					}
				}
			}

			// 4. Test Deterministic Stability across repeated runs
			ctxSecond, _ := AssembleSafeContext(f.Input)
			rawSecond, _ := json.Marshal(ctxSecond)
			if !bytes.Equal(rawCtx, rawSecond) {
				metrics.DeterministicStability = false
				t.Errorf("fixture %s produced non-deterministic SafeContext", f.FixtureID)
			}
		})
	}

	// Harness overall quality assertions
	if metrics.CleanFixturesCount == 0 || metrics.CleanFixturesZeroCandidateCount != metrics.CleanFixturesCount {
		t.Errorf("Clean fixtures false discovery rate: %.2f (expected 0.00)", metrics.FalseDiscoveryRate())
	}
	if metrics.PositiveFixturesCount == 0 || metrics.PositiveFixturesTriggeredCount != metrics.PositiveFixturesCount {
		t.Errorf("Positive fixtures useful hypothesis rate: %.2f (expected 1.00)", metrics.UsefulHypothesisRate())
	}
	if metrics.SensitiveCanaryLeakCount != 0 {
		t.Errorf("SensitiveCanaryLeakCount: %d (expected 0)", metrics.SensitiveCanaryLeakCount)
	}
	if metrics.AdversarialDataIntegrityViolationCount != 0 {
		t.Errorf("AdversarialDataIntegrityViolationCount: %d (expected 0)", metrics.AdversarialDataIntegrityViolationCount)
	}
	if !metrics.DeterministicStability {
		t.Errorf("DeterministicStability failed")
	}

	t.Logf("=== Harness Evaluation Summary ===")
	t.Logf("Total Fixtures: %d", metrics.TotalFixtures)
	t.Logf("Clean Fixtures: %d (Zero candidate count: %d, False Discovery Rate: %.2f%%)",
		metrics.CleanFixturesCount, metrics.CleanFixturesZeroCandidateCount, metrics.FalseDiscoveryRate()*100)
	t.Logf("Positive Fixtures: %d (Triggered: %d, Useful Hypothesis Rate: %.2f%%)",
		metrics.PositiveFixturesCount, metrics.PositiveFixturesTriggeredCount, metrics.UsefulHypothesisRate()*100)
	t.Logf("Raw Candidates Generated: %d, Admitted: %d", metrics.TotalRawCandidates, metrics.TotalAdmittedCandidates)
	t.Logf("Raw Citation Accuracy: %.2f%% (%d/%d)",
		metrics.RawCitationAccuracy()*100, metrics.RawEvidenceCitationsValid, metrics.RawEvidenceCitationsTotal)
	t.Logf("Raw Action Capability Validity: %.2f%% (%d/%d)",
		metrics.RawActionValidity()*100, metrics.RawProposedActionsValidCapability, metrics.RawProposedActionsTotal)
	t.Logf("Raw Action Scope Compliance: %.2f%% (%d/%d)",
		metrics.RawScopeCompliance()*100, metrics.RawProposedActionsInScope, metrics.RawProposedActionsTotal)
	t.Logf("Sensitive Canary Leaks: %d", metrics.SensitiveCanaryLeakCount)
	t.Logf("Adversarial Integrity Violations: %d", metrics.AdversarialDataIntegrityViolationCount)
	t.Logf("Deterministic Stability: %v", metrics.DeterministicStability)
}
