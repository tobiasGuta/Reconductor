package hypothesis

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GenerateBaseline generates deterministic candidate hypotheses from safe context observations.
// Returns an empty slice (null output) when no deterministic triggers match.
func GenerateBaseline(ctx SafeContext) []CandidateHypothesis {
	var candidates []CandidateHypothesis

	// 1. Check endpoints for deterministic patterns
	for _, ep := range ctx.Endpoints {
		locator := ep.Origin + ep.RouteSignature

		// Helper to build citations from ep.EvidenceArtifactIDs
		citations := make([]EvidenceCitation, 0, len(ep.EvidenceArtifactIDs))
		for _, artID := range ep.EvidenceArtifactIDs {
			citations = append(citations, EvidenceCitation{
				ArtifactID:   artID,
				Locator:      locator,
				AdvisoryText: "Verified observation of endpoint at " + locator,
			})
		}

		// A. Exposed Admin / Debug / Actuator
		if hasStatusCode(ep.StatusCodes, 200) && (hasLabel(ep.Labels, "admin", "debug", "actuator", "pprof") ||
			containsAny(ep.RouteSignature, "/actuator", "/debug/pprof", "/env", "/admin")) {

			candidateType := "exposed_administrative_interface"
			if hasLabel(ep.Labels, "actuator") || strings.HasPrefix(ep.RouteSignature, "/actuator") {
				candidateType = "exposed_actuator_management_interface"
			} else if strings.Contains(ep.RouteSignature, "/debug") {
				candidateType = "exposed_debug_interface"
			}

			actionParams, _ := json.Marshal(map[string]any{
				"targets": []string{locator},
				"method":  "GET",
			})

			candidates = append(candidates, CandidateHypothesis{
				CandidateType:      candidateType,
				Statement:          fmt.Sprintf("Sensitive management or diagnostic interface exposed at %s", locator),
				Rationale:          fmt.Sprintf("Observed HTTP 200 on route %s matching diagnostic/administrative signatures.", ep.RouteSignature),
				SupportingEvidence: citations,
				Assumptions: []string{
					"Route is served by backend application rather than a generic static mock.",
				},
				MissingEvidence: []string{
					"No authenticated probe recorded verifying access control or credential masking.",
				},
				ProposedAction: &ProposedAction{
					Capability:  "probe.http",
					TargetURL:   locator,
					Parameters:  actionParams,
					Description: fmt.Sprintf("Perform a safe GET probe to verify response body and headers at %s", locator),
				},
				ExpectedOutcome: "Confirm whether sensitive administrative or diagnostic controls are exposed without authentication.",
			})
			continue
		}

		// B. Swagger / OpenAPI Documentation
		if hasStatusCode(ep.StatusCodes, 200) && (hasLabel(ep.Labels, "swagger", "openapi") ||
			containsAny(ep.RouteSignature, "/swagger", "/openapi", "/api-docs")) {

			actionParams, _ := json.Marshal(map[string]any{
				"targets": []string{locator},
				"method":  "GET",
			})

			candidates = append(candidates, CandidateHypothesis{
				CandidateType:      "exposed_api_documentation",
				Statement:          fmt.Sprintf("Interactive API documentation or schema exposed at %s", locator),
				Rationale:          fmt.Sprintf("Endpoint %s returned HTTP 200 with OpenAPI/Swagger labels.", locator),
				SupportingEvidence: citations,
				Assumptions: []string{
					"Documentation contains active API schema specifications.",
				},
				MissingEvidence: []string{
					"Discovered schema endpoints have not been enumerated for undocumented administrative routes.",
				},
				ProposedAction: &ProposedAction{
					Capability:  "probe.http",
					TargetURL:   locator,
					Parameters:  actionParams,
					Description: fmt.Sprintf("Perform a safe GET probe to retrieve API documentation specification at %s", locator),
				},
				ExpectedOutcome: "Retrieve schema definition to catalog authorized endpoints.",
			})
			continue
		}

		// C. Redirect Parameter Investigation Signal
		if isRedirectStatus(ep.StatusCodes) && hasAnyParam(ep.QueryParamNames, "redirect", "url", "next", "return_to", "dest", "target") {
			actionParams, _ := json.Marshal(map[string]any{
				"targets": []string{locator},
				"method":  "GET",
			})

			candidates = append(candidates, CandidateHypothesis{
				CandidateType:      "parameter_reflection_anomaly",
				Statement:          fmt.Sprintf("Endpoint at %s accepts navigation parameter that warrants validation against open redirection.", locator),
				Rationale:          fmt.Sprintf("Endpoint returned HTTP redirection status with navigation parameter name %v.", ep.QueryParamNames),
				SupportingEvidence: citations,
				Assumptions: []string{
					"Parameter value influences downstream HTTP Location response header.",
				},
				MissingEvidence: []string{
					"Response Location destination has not been tested against external domains to determine if open redirection is permitted.",
				},
				ProposedAction: &ProposedAction{
					Capability:  "probe.http",
					TargetURL:   locator,
					Parameters:  actionParams,
					Description: fmt.Sprintf("Perform a safe GET probe with diagnostic parameter value to inspect Location header behavior at %s", locator),
				},
				ExpectedOutcome: "Determine whether navigation parameter enforces domain allowlisting or permits arbitrary redirect.",
			})
			continue
		}

		// Control case: BOLA / Semantic Authorization
		// If route has multiple route parameters e.g. /api/v1/tenants/... but no cross-tenant test,
		// do NOT invent a confirmed BOLA finding. Baseline emits nothing for BOLA (intentional gap for Slice 2).
	}

	// 2. Check Changes for high-priority attack surface changes
	for _, ch := range ctx.Changes {
		if strings.EqualFold(ch.Priority, "high") || strings.EqualFold(ch.Priority, "critical") || ch.Kind == "endpoint_interesting" {
			targetURL := ch.EntityKey
			if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
				// If entity key is a path, combine with first endpoint origin if available
				if len(ctx.Endpoints) > 0 && strings.HasPrefix(targetURL, "/") {
					targetURL = ctx.Endpoints[0].Origin + targetURL
				} else {
					targetURL = "https://" + targetURL
				}
			}

			citations := make([]EvidenceCitation, 0, len(ch.EvidenceArtifactIDs))
			for _, artID := range ch.EvidenceArtifactIDs {
				citations = append(citations, EvidenceCitation{
					ArtifactID:   artID,
					Locator:      ch.EntityKey,
					AdvisoryText: "Change item observation for " + ch.EntityKey,
				})
			}

			actionParams, _ := json.Marshal(map[string]any{
				"targets": []string{targetURL},
				"method":  "GET",
			})

			candidates = append(candidates, CandidateHypothesis{
				CandidateType:      "new_endpoint_investigation",
				Statement:          fmt.Sprintf("High-priority attack surface change detected on %s", ch.EntityKey),
				Rationale:          fmt.Sprintf("Change detection reported %s with priority %s (reasons: %v).", ch.Kind, ch.Priority, ch.Reasons),
				SupportingEvidence: citations,
				Assumptions: []string{
					"Newly appeared or modified resource represents intended deployment change.",
				},
				MissingEvidence: []string{
					"Detailed baseline diff has not been inspected for unexpected endpoint exposure.",
				},
				ProposedAction: &ProposedAction{
					Capability:  "probe.http",
					TargetURL:   targetURL,
					Parameters:  actionParams,
					Description: fmt.Sprintf("Probe new or modified target %s", targetURL),
				},
				ExpectedOutcome: "Establish baseline response headers and status for newly discovered surface.",
			})
		}
	}

	return candidates
}

func hasStatusCode(codes []int, target int) bool {
	for _, c := range codes {
		if c == target {
			return true
		}
	}
	return false
}

func isRedirectStatus(codes []int) bool {
	for _, c := range codes {
		if c == 301 || c == 302 || c == 303 || c == 307 || c == 308 {
			return true
		}
	}
	return false
}

func hasLabel(labels []string, targets ...string) bool {
	for _, l := range labels {
		for _, t := range targets {
			if strings.EqualFold(l, t) {
				return true
			}
		}
	}
	return false
}

func hasAnyParam(params []string, targets ...string) bool {
	for _, p := range params {
		for _, t := range targets {
			if strings.EqualFold(p, t) {
				return true
			}
		}
	}
	return false
}

func containsAny(s string, sub ...string) bool {
	for _, item := range sub {
		if strings.Contains(s, item) {
			return true
		}
	}
	return false
}
