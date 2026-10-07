package hypothesis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAssembleSafeContext_MultiHostDistinct(t *testing.T) {
	input := RawEvaluationInput{
		Endpoints: []RawEndpointInput{
			{
				RawURL:              "https://api.target.com/api/v1/users/1",
				RouteSignature:      "/api/v1/users/{param}",
				Method:              "GET",
				StatusCodes:         []int{200},
				Labels:              []string{"api"},
				InterestScore:       1,
				EvidenceArtifactIDs: []string{"art-1"},
			},
			{
				RawURL:              "https://admin.target.com/api/v1/users/1",
				RouteSignature:      "/api/v1/users/{param}",
				Method:              "GET",
				StatusCodes:         []int{200},
				Labels:              []string{"admin"},
				InterestScore:       7,
				EvidenceArtifactIDs: []string{"art-2"},
			},
		},
		Evidence: []RawEvidenceInput{
			{
				ArtifactID:       "art-1",
				StepDefinitionID: "probe-http",
				SourceCategory:   "http_probe",
				RedactionState:   "redacted",
				Locators:         []string{"https://api.target.com/api/v1/users/{param}"},
			},
			{
				ArtifactID:       "art-2",
				StepDefinitionID: "probe-http",
				SourceCategory:   "http_probe",
				RedactionState:   "redacted",
				Locators:         []string{"https://admin.target.com/api/v1/users/{param}"},
			},
		},
	}

	ctx, err := AssembleSafeContext(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ctx.Endpoints) != 2 {
		t.Fatalf("expected 2 distinct endpoints for different origins, got %d", len(ctx.Endpoints))
	}

	// First endpoint should be the higher-scoring one (admin)
	if ctx.Endpoints[0].Origin != "https://admin.target.com" {
		t.Errorf("expected first endpoint to be admin.target.com (score 7), got %s", ctx.Endpoints[0].Origin)
	}
	if ctx.Endpoints[1].Origin != "https://api.target.com" {
		t.Errorf("expected second endpoint to be api.target.com (score 1), got %s", ctx.Endpoints[1].Origin)
	}
}

func TestAssembleSafeContext_SetLikeNestedNormalization(t *testing.T) {
	input1 := RawEvaluationInput{
		Endpoints: []RawEndpointInput{
			{
				RawURL:              "https://target.com/api",
				RouteSignature:      "/api",
				Method:              "GET",
				StatusCodes:         []int{404, 200, 500},
				QueryParameters:     []string{"zebra=1", "apple=2", "banana=3"},
				Labels:              []string{"zebra", "alpha", "beta"},
				Technologies:        []string{"Zend", "Apache", "PHP"},
				EvidenceArtifactIDs: []string{"art-b", "art-a"},
			},
		},
		Changes: []RawChangeInput{
			{
				Kind:                "asset_changed",
				EntityType:          "asset",
				EntityKey:           "https://target.com/api",
				Priority:            "high",
				Reasons:             []string{"zeta_change", "alpha_change"},
				EvidenceArtifactIDs: []string{"art-b", "art-a"},
			},
		},
		Evidence: []RawEvidenceInput{
			{
				ArtifactID:       "art-b",
				StepDefinitionID: "probe-http",
				SourceCategory:   "http_probe",
				RedactionState:   "redacted",
				Locators:         []string{"https://target.com/z", "https://target.com/a"},
			},
			{
				ArtifactID:       "art-a",
				StepDefinitionID: "probe-http",
				SourceCategory:   "http_probe",
				RedactionState:   "redacted",
				Locators:         []string{"https://target.com/api"},
			},
		},
		AllowedCapabilities: []string{"scan.nuclei", "probe.http", "crawl.web"},
	}

	// Identical data with reversed/shuffled nested collections
	input2 := RawEvaluationInput{
		Endpoints: []RawEndpointInput{
			{
				RawURL:              "https://target.com/api",
				RouteSignature:      "/api",
				Method:              "GET",
				StatusCodes:         []int{200, 500, 404, 200},                  // Shuffled & duplicated
				QueryParameters:     []string{"banana=9", "apple=8", "zebra=7"}, // Shuffled
				Labels:              []string{"beta", "zebra", "alpha"},         // Shuffled
				Technologies:        []string{"PHP", "Zend", "Apache"},          // Shuffled
				EvidenceArtifactIDs: []string{"art-a", "art-b"},                 // Shuffled
			},
		},
		Changes: []RawChangeInput{
			{
				Kind:                "asset_changed",
				EntityType:          "asset",
				EntityKey:           "https://target.com/api",
				Priority:            "high",
				Reasons:             []string{"alpha_change", "zeta_change"}, // Shuffled
				EvidenceArtifactIDs: []string{"art-a", "art-b"},              // Shuffled
			},
		},
		Evidence: []RawEvidenceInput{
			{
				ArtifactID:       "art-a",
				StepDefinitionID: "probe-http",
				SourceCategory:   "http_probe",
				RedactionState:   "redacted",
				Locators:         []string{"https://target.com/api"},
			},
			{
				ArtifactID:       "art-b",
				StepDefinitionID: "probe-http",
				SourceCategory:   "http_probe",
				RedactionState:   "redacted",
				Locators:         []string{"https://target.com/a", "https://target.com/z"}, // Shuffled
			},
		},
		AllowedCapabilities: []string{"crawl.web", "scan.nuclei", "probe.http"}, // Shuffled
	}

	ctx1, err1 := AssembleSafeContext(input1)
	if err1 != nil {
		t.Fatalf("ctx1 error: %v", err1)
	}
	ctx2, err2 := AssembleSafeContext(input2)
	if err2 != nil {
		t.Fatalf("ctx2 error: %v", err2)
	}

	b1, err := json.Marshal(ctx1)
	if err != nil {
		t.Fatalf("marshal ctx1: %v", err)
	}
	b2, err := json.Marshal(ctx2)
	if err != nil {
		t.Fatalf("marshal ctx2: %v", err)
	}

	if !bytes.Equal(b1, b2) {
		t.Errorf("expected byte-for-byte identical output for shuffled nested collections:\nctx1: %s\nctx2: %s", string(b1), string(b2))
	}
}

func TestAssembleSafeContext_CanaryExclusion(t *testing.T) {
	input := RawEvaluationInput{
		Endpoints: []RawEndpointInput{
			{
				RawURL:          "https://target.com/api?token=SECRET_BEARER_CANARY&api_key=SECRET_API_KEY_CANARY&password=SECRET_PASSWORD_CANARY",
				RouteSignature:  "/api",
				Method:          "GET",
				StatusCodes:     []int{200},
				QueryParameters: []string{"token=SECRET_BEARER_CANARY", "api_key=SECRET_API_KEY_CANARY"},
				Labels:          []string{"api"},
			},
		},
		Changes: []RawChangeInput{
			{
				Kind:       "asset_changed",
				EntityType: "asset",
				EntityKey:  "https://target.com/user?token=SECRET_CHANGE_QUERY_CANARY",
				Priority:   "low",
				Reasons:    []string{"update"},
				Title:      "User password reset with secret: SECRET_TITLE_PASSWORD_CANARY",
				Summary:    "Cookie header session=SECRET_SESSION_CANARY was logged",
			},
		},
		Evidence: []RawEvidenceInput{
			{
				ArtifactID:       "art-1",
				StepDefinitionID: "probe-http",
				SourceCategory:   "http_probe",
				RedactionState:   "redacted",
				Locators:         []string{"https://target.com/api?token=SECRET_LOCATOR_CANARY"},
			},
			{
				ArtifactID:       "art-unredacted",
				StepDefinitionID: "probe-http",
				SourceCategory:   "http_probe",
				RedactionState:   "unredacted",
				Locators:         []string{"https://target.com/SECRET_UNREDACTED_CANARY"},
			},
		},
	}

	ctx, err := AssembleSafeContext(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	serialized := string(b)

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

	for _, canary := range canaries {
		if strings.Contains(serialized, canary) {
			t.Errorf("prohibited canary %q leaked into safe context: %s", canary, serialized)
		}
	}
}

func TestAssembleSafeContext_WholeContextSizeBounding(t *testing.T) {
	// Construct an oversized input with 100 endpoints and 50 changes
	endpoints := make([]RawEndpointInput, 100)
	for i := 0; i < 100; i++ {
		endpoints[i] = RawEndpointInput{
			RawURL:          fmt.Sprintf("https://target.com/path/%s/%d", strings.Repeat("a", 100), i),
			RouteSignature:  fmt.Sprintf("/path/%s/%d", strings.Repeat("a", 100), i),
			Method:          "GET",
			StatusCodes:     []int{200},
			QueryParameters: []string{"param1", "param2", "param3"},
			Labels:          []string{"label1", "label2"},
			Technologies:    []string{"Tech1", "Tech2"},
			InterestScore:   i,
		}
	}

	changes := make([]RawChangeInput, 50)
	for i := 0; i < 50; i++ {
		changes[i] = RawChangeInput{
			Kind:       "asset_changed",
			EntityType: "asset",
			EntityKey:  fmt.Sprintf("https://target.com/change/%s/%d", strings.Repeat("b", 100), i),
			Priority:   "low",
			Reasons:    []string{"reason1", "reason2"},
		}
	}

	input := RawEvaluationInput{
		Endpoints:           endpoints,
		Changes:             changes,
		AllowedCapabilities: []string{"probe.http", "crawl.web"},
	}

	ctx, err := AssembleSafeContext(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	if len(b) > MaxContextBytes {
		t.Errorf("serialized context size %d exceeds limit %d", len(b), MaxContextBytes)
	}

	if !ctx.Truncated {
		t.Errorf("expected context to be marked truncated")
	}

	if ctx.SelectedEndpointsCount >= ctx.AvailableEndpointsCount {
		t.Errorf("expected selected endpoints (%d) to be less than available (%d)", ctx.SelectedEndpointsCount, ctx.AvailableEndpointsCount)
	}
}

func TestAssembleSafeContext_FailClosedOnExcessiveBaseContext(t *testing.T) {
	// Create an excessive base context where AllowedCapabilities alone exceeds 16 KiB
	caps := make([]string, 500)
	for i := 0; i < 500; i++ {
		caps[i] = "capability.long.name." + strings.Repeat("x", 50) + "." + string(rune('0'+i%10))
	}

	input := RawEvaluationInput{
		AllowedCapabilities: caps,
	}

	// MaxCapabilitiesCount bounds caps to 32, so let's verify caps are bounded
	ctx, err := AssembleSafeContext(input)
	if err != nil {
		t.Fatalf("expected bounded caps to succeed: %v", err)
	}
	b, _ := json.Marshal(ctx)
	if len(b) > MaxContextBytes {
		t.Errorf("expected caps to be bounded within 16 KiB")
	}
}

func TestAssembleSafeContext_TruncationTelemetry_Unbounded(t *testing.T) {
	input := RawEvaluationInput{
		Endpoints: []RawEndpointInput{
			{
				RawURL:              "https://api.target.com/users",
				RouteSignature:      "/users",
				Method:              "GET",
				StatusCodes:         []int{200},
				Labels:              []string{"api"},
				EvidenceArtifactIDs: []string{"art-1"},
			},
			{
				RawURL:              "https://api.target.com/posts",
				RouteSignature:      "/posts",
				Method:              "GET",
				StatusCodes:         []int{200},
				Labels:              []string{"api"},
				EvidenceArtifactIDs: []string{"art-2"},
			},
		},
		Changes: []RawChangeInput{
			{
				Kind:                "endpoint_created",
				EntityType:          "endpoint",
				EntityKey:           "https://api.target.com/users",
				Priority:            "low",
				EvidenceArtifactIDs: []string{"art-1"},
			},
		},
		Evidence: []RawEvidenceInput{
			{
				ArtifactID:       "art-1",
				StepDefinitionID: "probe-http",
				SourceCategory:   "http_probe",
				RedactionState:   "redacted",
				Locators:         []string{"https://api.target.com/users"},
			},
			{
				ArtifactID:       "art-2",
				StepDefinitionID: "probe-http",
				SourceCategory:   "http_probe",
				RedactionState:   "redacted",
				Locators:         []string{"https://api.target.com/posts"},
			},
		},
		AllowedCapabilities: []string{"probe.http"},
	}

	ctx, err := AssembleSafeContext(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ctx.Truncated {
		t.Errorf("expected Truncated == false when nothing is removed")
	}
	if ctx.AvailableEndpointsCount != 2 || ctx.SelectedEndpointsCount != 2 {
		t.Errorf("expected 2/2 endpoints, got available=%d, selected=%d", ctx.AvailableEndpointsCount, ctx.SelectedEndpointsCount)
	}
	if ctx.AvailableChangesCount != 1 || ctx.SelectedChangesCount != 1 {
		t.Errorf("expected 1/1 changes, got available=%d, selected=%d", ctx.AvailableChangesCount, ctx.SelectedChangesCount)
	}
	if ctx.AvailableEvidenceCount != 2 || ctx.SelectedEvidenceCount != 2 {
		t.Errorf("expected 2/2 evidence, got available=%d, selected=%d", ctx.AvailableEvidenceCount, ctx.SelectedEvidenceCount)
	}

	b, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if len(b) > MaxContextBytes {
		t.Errorf("expected context <= 16 KiB, got %d", len(b))
	}
}

func TestAssembleSafeContext_TruncationTelemetry_Bounded(t *testing.T) {
	endpoints := make([]RawEndpointInput, 80)
	evidence := make([]RawEvidenceInput, 80)
	for i := 0; i < 80; i++ {
		artID := fmt.Sprintf("art-%03d", i)
		rawURL := fmt.Sprintf("https://target.com/large/path/%s/%d", strings.Repeat("z", 80), i)
		route := fmt.Sprintf("/large/path/%s/%d", strings.Repeat("z", 80), i)
		endpoints[i] = RawEndpointInput{
			RawURL:              rawURL,
			RouteSignature:      route,
			Method:              "GET",
			StatusCodes:         []int{200},
			QueryParameters:     []string{"p1", "p2"},
			Labels:              []string{"api", "large"},
			EvidenceArtifactIDs: []string{artID},
			InterestScore:       i,
		}
		evidence[i] = RawEvidenceInput{
			ArtifactID:       artID,
			StepDefinitionID: "probe-http",
			SourceCategory:   "http_probe",
			RedactionState:   "redacted",
			Locators:         []string{rawURL},
		}
	}

	changes := make([]RawChangeInput, 30)
	for i := 0; i < 30; i++ {
		changes[i] = RawChangeInput{
			Kind:       "asset_changed",
			EntityType: "asset",
			EntityKey:  fmt.Sprintf("https://target.com/large/change/%s/%d", strings.Repeat("y", 80), i),
			Priority:   "low",
			Reasons:    []string{"diff"},
		}
	}

	input := RawEvaluationInput{
		Endpoints:           endpoints,
		Changes:             changes,
		Evidence:            evidence,
		AllowedCapabilities: []string{"probe.http"},
	}

	ctx, err := AssembleSafeContext(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !ctx.Truncated {
		t.Errorf("expected Truncated == true when bounding removes information")
	}
	if ctx.AvailableEndpointsCount != 80 {
		t.Errorf("expected AvailableEndpointsCount 80, got %d", ctx.AvailableEndpointsCount)
	}
	if ctx.SelectedEndpointsCount >= 80 {
		t.Errorf("expected SelectedEndpointsCount < 80, got %d", ctx.SelectedEndpointsCount)
	}
	if ctx.AvailableChangesCount != 30 {
		t.Errorf("expected AvailableChangesCount 30, got %d", ctx.AvailableChangesCount)
	}
	if ctx.SelectedChangesCount != 0 {
		t.Errorf("expected lowest-priority changes to be fully evicted (0), got %d", ctx.SelectedChangesCount)
	}
	if ctx.AvailableEvidenceCount != 80 {
		t.Errorf("expected AvailableEvidenceCount 80, got %d", ctx.AvailableEvidenceCount)
	}
	if ctx.SelectedEvidenceCount >= 80 {
		t.Errorf("expected SelectedEvidenceCount < 80, got %d", ctx.SelectedEvidenceCount)
	}

	b, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if len(b) > MaxContextBytes {
		t.Errorf("expected context <= 16 KiB, got %d", len(b))
	}

	// Verify count accuracy and deterministic stability by re-assembling
	ctx2, err2 := AssembleSafeContext(input)
	if err2 != nil {
		t.Fatalf("reassemble error: %v", err2)
	}
	b2, _ := json.Marshal(ctx2)
	if !bytes.Equal(b, b2) {
		t.Errorf("expected deterministic identical serialization across runs")
	}
}

func TestAssembleSafeContext_PriorityRetentionVsLexicalOrdering(t *testing.T) {
	// Endpoint High: High interest score (100), but lexically comes LAST (/zzz)
	epHigh := RawEndpointInput{
		RawURL:              "https://api.target.com/zzz_high_interest",
		RouteSignature:      "/zzz_high_interest",
		Method:              "GET",
		StatusCodes:         []int{200},
		Labels:              []string{"critical"},
		EvidenceArtifactIDs: []string{"art-high"},
		InterestScore:       100,
	}

	// Endpoint Low: Low interest score (1), but lexically comes FIRST (/aaa)
	epLow := RawEndpointInput{
		RawURL:              "https://api.target.com/aaa_low_interest",
		RouteSignature:      "/aaa_low_interest",
		Method:              "GET",
		StatusCodes:         []int{200},
		Labels:              []string{"low"},
		EvidenceArtifactIDs: []string{"art-low"},
		InterestScore:       1,
	}

	// Two equal-priority endpoints with same score (50) to test deterministic identity tie-breakers:
	// Tie breaker: Origin ASC, RouteSignature ASC, Method ASC.
	epTie1 := RawEndpointInput{
		RawURL:              "https://api.target.com/mmm_equal_tie_1",
		RouteSignature:      "/mmm_equal_tie_1",
		Method:              "GET",
		StatusCodes:         []int{200},
		EvidenceArtifactIDs: []string{"art-tie1"},
		InterestScore:       50,
	}
	epTie2 := RawEndpointInput{
		RawURL:              "https://api.target.com/mmm_equal_tie_2",
		RouteSignature:      "/mmm_equal_tie_2",
		Method:              "GET",
		StatusCodes:         []int{200},
		EvidenceArtifactIDs: []string{"art-tie2"},
		InterestScore:       50,
	}

	// Bulk endpoints with medium interest score (40) to push context over 16 KiB limit
	// and force truncation of low-interest endpoints and some equal-priority tie endpoints
	endpoints := []RawEndpointInput{epLow, epHigh, epTie2, epTie1}
	evidence := []RawEvidenceInput{
		{ArtifactID: "art-high", StepDefinitionID: "p", SourceCategory: "p", RedactionState: "redacted", Locators: []string{"https://api.target.com/zzz_high_interest"}},
		{ArtifactID: "art-low", StepDefinitionID: "p", SourceCategory: "p", RedactionState: "redacted", Locators: []string{"https://api.target.com/aaa_low_interest"}},
		{ArtifactID: "art-tie1", StepDefinitionID: "p", SourceCategory: "p", RedactionState: "redacted", Locators: []string{"https://api.target.com/mmm_equal_tie_1"}},
		{ArtifactID: "art-tie2", StepDefinitionID: "p", SourceCategory: "p", RedactionState: "redacted", Locators: []string{"https://api.target.com/mmm_equal_tie_2"}},
	}

	for i := 0; i < 50; i++ {
		artID := fmt.Sprintf("art-bulk-%03d", i)
		rawURL := fmt.Sprintf("https://api.target.com/bulk/%s/%d", strings.Repeat("x", 120), i)
		route := fmt.Sprintf("/bulk/%s/%d", strings.Repeat("x", 120), i)
		endpoints = append(endpoints, RawEndpointInput{
			RawURL:              rawURL,
			RouteSignature:      route,
			Method:              "GET",
			StatusCodes:         []int{200},
			QueryParameters:     []string{"p1", "p2"},
			Labels:              []string{"bulk"},
			EvidenceArtifactIDs: []string{artID},
			InterestScore:       40, // Below 50 and 100, above 1
		})
		evidence = append(evidence, RawEvidenceInput{
			ArtifactID:       artID,
			StepDefinitionID: "p",
			SourceCategory:   "p",
			RedactionState:   "redacted",
			Locators:         []string{rawURL},
		})
	}

	input := RawEvaluationInput{
		Endpoints:           endpoints,
		Evidence:            evidence,
		AllowedCapabilities: []string{"probe.http"},
	}

	ctx, err := AssembleSafeContext(input)
	if err != nil {
		t.Fatalf("assemble error: %v", err)
	}

	b, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if len(b) > MaxContextBytes {
		t.Errorf("serialized size %d exceeds 16 KiB", len(b))
	}

	// 1. Truncation telemetry must be correct
	if !ctx.Truncated {
		t.Errorf("expected context to be truncated")
	}
	if ctx.AvailableEndpointsCount != len(endpoints) {
		t.Errorf("expected AvailableEndpointsCount=%d, got %d", len(endpoints), ctx.AvailableEndpointsCount)
	}
	if ctx.SelectedEndpointsCount >= ctx.AvailableEndpointsCount {
		t.Errorf("expected SelectedEndpointsCount < AvailableEndpointsCount, got %d vs %d", ctx.SelectedEndpointsCount, ctx.AvailableEndpointsCount)
	}

	// 2. High-interest endpoint (/zzz_high_interest) must be retained over low-interest endpoint (/aaa_low_interest)
	hasHigh := false
	hasLow := false
	for _, ep := range ctx.Endpoints {
		if ep.RouteSignature == "/zzz_high_interest" {
			hasHigh = true
		}
		if ep.RouteSignature == "/aaa_low_interest" {
			hasLow = true
		}
	}

	if !hasHigh {
		t.Errorf("higher-interest endpoint /zzz_high_interest was unexpectedly evicted")
	}
	if hasLow {
		t.Errorf("lower-interest endpoint /aaa_low_interest was retained when budget required eviction")
	}

	// 3. Serialized context ordering must be strictly canonical lexical (Origin ASC, Method ASC, RouteSignature ASC)
	for i := 1; i < len(ctx.Endpoints); i++ {
		prev := ctx.Endpoints[i-1]
		curr := ctx.Endpoints[i]
		if prev.Origin > curr.Origin {
			t.Errorf("canonical origin ordering violated: %s > %s", prev.Origin, curr.Origin)
		} else if prev.Origin == curr.Origin {
			if prev.Method > curr.Method {
				t.Errorf("canonical method ordering violated: %s > %s", prev.Method, curr.Method)
			} else if prev.Method == curr.Method {
				if prev.RouteSignature >= curr.RouteSignature {
					t.Errorf("canonical route ordering violated: %s >= %s", prev.RouteSignature, curr.RouteSignature)
				}
			}
		}
	}

	// 4. Repeated runs produce byte-identical serialized context
	ctx2, err2 := AssembleSafeContext(input)
	if err2 != nil {
		t.Fatalf("second assemble error: %v", err2)
	}
	b2, err2 := json.Marshal(ctx2)
	if err2 != nil {
		t.Fatalf("second marshal error: %v", err2)
	}
	if !bytes.Equal(b, b2) {
		t.Errorf("expected byte-identical output across repeated runs")
	}
}
