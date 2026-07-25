package intelligence

import (
	"reflect"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
)

func TestClassifyCombinesResponseRequestSchemaJavaScriptAndHistoryEvidence(t *testing.T) {
	target := "https://api.example.test/v1/users/123?token=redacted"
	input := Input{
		HTTPObservations: []provideroutput.Record{{
			Provider: "httpx", Kind: provideroutput.URLRecord, Target: target,
			StatusCode: 401, Technologies: []string{"Go", "React"},
			Fields: map[string]any{
				"method":                "POST",
				"request_content_type":  "application/json",
				"response_content_type": "application/json",
				"final_url":             "https://api.example.test/login",
				"headers":               map[string]any{"www-authenticate": "Bearer"},
			},
		}},
		CrawlObservations: []provideroutput.Record{{
			Provider: "katana", Kind: provideroutput.URLRecord, Target: target,
			Fields: map[string]any{
				"method":               "POST",
				"request_content_type": "application/json",
				"source_url":           "https://api.example.test/assets/app.js",
			},
		}},
		HistoricalObservations: []provideroutput.Record{{
			Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://api.example.test/v1/users/456?token=old",
			StatusCode: 200, Technologies: []string{"PHP"},
			Fields: map[string]any{"method": "POST", "request_content_type": "application/json", "response_content_type": "application/json"},
		}},
		APISchemaEndpoints: []string{target},
	}

	output, err := Classify(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Classifications) != 1 || len(output.InterestingEndpoints) != 1 {
		t.Fatalf("classification=%#v", output)
	}
	got := output.Classifications[0]
	for _, label := range []string{"api_schema_member", "authentication_required", "javascript_discovered", "non_read_method", "parameterized_path", "query_parameters", "status_changed", "technology_changed", "multi_source"} {
		if !contains(got.Labels, label) {
			t.Errorf("missing label %q in %v", label, got.Labels)
		}
	}
	if got.Endpoint.Method != "POST" || got.Endpoint.ContentType != "application/json" {
		t.Fatalf("request semantics were lost: %#v", got.Endpoint)
	}
	if got.Confidence < 0.95 || got.InterestScore < 10 {
		t.Fatalf("score/confidence not evidence-derived: %#v", got)
	}
	if !got.Historical.SeenBefore || !got.Historical.StatusChanged || !got.Historical.TechnologyChanged {
		t.Fatalf("historical behavior=%#v", got.Historical)
	}
	if len(got.Relationships) != 1 || got.Relationships[0].Kind != "javascript_reference" {
		t.Fatalf("relationships=%#v", got.Relationships)
	}
	if !reflect.DeepEqual(got.StatusCodes, []int{401}) || !contains(got.Technologies, "go") || !contains(got.Technologies, "react") {
		t.Fatalf("response evidence missing: statuses=%v technologies=%v", got.StatusCodes, got.Technologies)
	}

	repeated, err := Classify(input)
	if err != nil || !reflect.DeepEqual(output, repeated) {
		t.Fatalf("classification is not deterministic: err=%v\nfirst=%#v\nsecond=%#v", err, output, repeated)
	}

	reordered := input
	reordered.HTTPObservations, reordered.CrawlObservations = input.CrawlObservations, input.HTTPObservations
	permuted, err := Classify(reordered)
	if err != nil || !reflect.DeepEqual(output, permuted) {
		t.Fatalf("classification depends on observation order: err=%v\nfirst=%#v\npermuted=%#v", err, output, permuted)
	}
}

func TestClassifyAvoidsSubstringKeywordNoise(t *testing.T) {
	output, err := Classify(Input{CrawlObservations: []provideroutput.Record{
		{Provider: "katana", Kind: provideroutput.URLRecord, Target: "https://example.test/capistrano/administrator-guide", Fields: map[string]any{}},
		{Provider: "katana", Kind: provideroutput.URLRecord, Target: "https://example.test/assets/main.css", Fields: map[string]any{}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Classifications) != 2 || len(output.InterestingEndpoints) != 0 {
		t.Fatalf("benign corpus was promoted: %#v", output)
	}
	for _, item := range output.Classifications {
		if len(item.MatchedKeywords) != 0 {
			t.Fatalf("substring keyword false positive: %#v", item)
		}
	}
}

func TestClassifyRejectsMalformedOrNonURLRecords(t *testing.T) {
	tests := []provideroutput.Record{
		{Provider: "katana", Kind: provideroutput.URLRecord, Target: "not-a-url"},
		{Provider: "httpx", Kind: provideroutput.HostRecord, Target: "example.test"},
	}
	for _, record := range tests {
		if _, err := Classify(Input{CrawlObservations: []provideroutput.Record{record}}); err == nil {
			t.Fatalf("invalid record was accepted: %#v", record)
		}
	}
}

func contains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
