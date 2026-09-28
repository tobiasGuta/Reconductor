package hypothesis

import (
	"testing"
)

func TestGenerateBaseline_CleanNullOutput(t *testing.T) {
	ctx := SafeContext{
		Endpoints: []SafeEndpoint{
			{
				Origin:         "https://target.com",
				RouteSignature: "/",
				Method:         "GET",
				StatusCodes:    []int{200},
				Labels:         []string{"public"},
			},
			{
				Origin:         "https://target.com",
				RouteSignature: "/about",
				Method:         "GET",
				StatusCodes:    []int{200},
				Labels:         []string{"public"},
			},
		},
	}

	candidates := GenerateBaseline(ctx)
	if len(candidates) != 0 {
		t.Errorf("expected 0 candidates on clean context, got %d", len(candidates))
	}
}

func TestGenerateBaseline_ExposedActuator(t *testing.T) {
	ctx := SafeContext{
		Endpoints: []SafeEndpoint{
			{
				Origin:              "https://api.target.com",
				RouteSignature:      "/actuator/env",
				Method:              "GET",
				StatusCodes:         []int{200},
				Labels:              []string{"actuator", "admin"},
				Technologies:        []string{"Spring Boot"},
				EvidenceArtifactIDs: []string{"art-act-1"},
			},
		},
		Evidence: []SafeEvidenceRef{
			{
				ArtifactID: "art-act-1",
				Locators:   []string{"https://api.target.com/actuator/env"},
			},
		},
	}

	candidates := GenerateBaseline(ctx)
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate for exposed actuator, got %d", len(candidates))
	}

	c := candidates[0]
	if c.CandidateType != "exposed_actuator_management_interface" {
		t.Errorf("unexpected candidate type: %s", c.CandidateType)
	}
	if c.ProposedAction == nil {
		t.Fatalf("expected proposed action, got nil")
	}
	if c.ProposedAction.Capability != "probe.http" {
		t.Errorf("expected probe.http capability, got %s", c.ProposedAction.Capability)
	}
	if c.ProposedAction.TargetURL != "https://api.target.com/actuator/env" {
		t.Errorf("unexpected target URL: %s", c.ProposedAction.TargetURL)
	}
}

func TestGenerateBaseline_ExposedSwagger(t *testing.T) {
	ctx := SafeContext{
		Endpoints: []SafeEndpoint{
			{
				Origin:              "https://api.target.com",
				RouteSignature:      "/swagger-ui/index.html",
				Method:              "GET",
				StatusCodes:         []int{200},
				Labels:              []string{"swagger", "api"},
				EvidenceArtifactIDs: []string{"art-swag-1"},
			},
		},
		Evidence: []SafeEvidenceRef{
			{
				ArtifactID: "art-swag-1",
				Locators:   []string{"https://api.target.com/swagger-ui/index.html"},
			},
		},
	}

	candidates := GenerateBaseline(ctx)
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate for swagger UI, got %d", len(candidates))
	}
	if candidates[0].CandidateType != "exposed_api_documentation" {
		t.Errorf("unexpected candidate type: %s", candidates[0].CandidateType)
	}
}

func TestGenerateBaseline_RedirectSignal(t *testing.T) {
	ctx := SafeContext{
		Endpoints: []SafeEndpoint{
			{
				Origin:              "https://auth.target.com",
				RouteSignature:      "/oauth/authorize",
				Method:              "GET",
				StatusCodes:         []int{302},
				QueryParamNames:     []string{"client_id", "redirect"},
				Labels:              []string{"auth", "redirect"},
				EvidenceArtifactIDs: []string{"art-redir-1"},
			},
		},
		Evidence: []SafeEvidenceRef{
			{
				ArtifactID: "art-redir-1",
				Locators:   []string{"https://auth.target.com/oauth/authorize"},
			},
		},
	}

	candidates := GenerateBaseline(ctx)
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate for redirect signal, got %d", len(candidates))
	}
	if candidates[0].CandidateType != "parameter_reflection_anomaly" {
		t.Errorf("unexpected candidate type: %s", candidates[0].CandidateType)
	}
}

func TestGenerateBaseline_BOLAControlGap(t *testing.T) {
	// Semantic BOLA control scenario: multi-tenant parameters observed in crawl, but no cross-account test
	ctx := SafeContext{
		Endpoints: []SafeEndpoint{
			{
				Origin:              "https://api.target.com",
				RouteSignature:      "/api/v1/tenants/{param}/users/{param}",
				Method:              "GET",
				StatusCodes:         []int{200},
				Labels:              []string{"api"},
				EvidenceArtifactIDs: []string{"art-bola-1"},
			},
		},
		Evidence: []SafeEvidenceRef{
			{
				ArtifactID: "art-bola-1",
				Locators:   []string{"https://api.target.com/api/v1/tenants/{param}/users/{param}"},
			},
		},
	}

	candidates := GenerateBaseline(ctx)
	// Must emit 0 candidates (no false confirmed BOLA findings)
	if len(candidates) != 0 {
		t.Errorf("expected 0 baseline candidates for unverified BOLA (intentional gap for Slice 2), got %d", len(candidates))
	}
}

func TestGenerateBaseline_ContradictoryAuthStatus(t *testing.T) {
	// Admin keyword present, but status code is 401 Unauthorized (access control enforced)
	ctx := SafeContext{
		Endpoints: []SafeEndpoint{
			{
				Origin:              "https://api.target.com",
				RouteSignature:      "/admin/dashboard",
				Method:              "GET",
				StatusCodes:         []int{401},
				Labels:              []string{"admin", "auth"},
				EvidenceArtifactIDs: []string{"art-contra-1"},
			},
		},
		Evidence: []SafeEvidenceRef{
			{
				ArtifactID: "art-contra-1",
				Locators:   []string{"https://api.target.com/admin/dashboard"},
			},
		},
	}

	candidates := GenerateBaseline(ctx)
	if len(candidates) != 0 {
		t.Errorf("expected 0 candidates when admin endpoint is 401 Unauthorized, got %d", len(candidates))
	}
}
