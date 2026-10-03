package changes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/normalize"
)

func TestFromReportRawSuppressesUnchangedInterestingEndpoint(t *testing.T) {
	items, err := FromReportRaw(reportWithEndpoint(t, historical{SeenBefore: true}), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("unchanged endpoint produced change items: %#v", items)
	}
}

func TestFromReportRawPrioritizesNewAndChangedEndpoints(t *testing.T) {
	newItems, err := FromReportRaw(reportWithEndpoint(t, historical{}), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(newItems) != 1 || newItems[0].Priority != "high" {
		t.Fatalf("new state-changing endpoint priority = %#v", newItems)
	}
	ordinaryItems, err := FromReportRaw(reportEndpoint(t, historical{}, "GET", []string{"api"}), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(ordinaryItems) != 1 || ordinaryItems[0].Priority != "medium" {
		t.Fatalf("new ordinary endpoint priority = %#v", ordinaryItems)
	}

	changedItems, err := FromReportRaw(reportWithEndpoint(t, historical{SeenBefore: true, StatusChanged: true}), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(changedItems) != 1 || changedItems[0].Priority != "medium" {
		t.Fatalf("changed existing endpoint priority = %#v", changedItems)
	}
}

func TestFromReportRawPreservesStructuredAssetEvidence(t *testing.T) {
	raw := json.RawMessage(`{
		"changes":[{
			"kind":"new_or_changed",
			"value":"https://app.example.test/",
			"previous":{"status_code":200,"technologies":["old"]},
			"current":{"status_code":401,"technologies":["new"]},
			"reasons":["HTTP status changed","technology changed"]
		}],
		"endpoints":[],
		"candidate_matches":[],
		"target_plan_digest":"plan"
	}`)
	items, err := FromReportRaw(raw, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %#v", items)
	}
	if !strings.Contains(string(items[0].Previous), `"status_code":200`) || !strings.Contains(string(items[0].Current), `"status_code":401`) {
		t.Fatalf("structured evidence was not preserved: previous=%s current=%s", items[0].Previous, items[0].Current)
	}
}

func TestFromReportItemMatchesWholeReportDerivation(t *testing.T) {
	observedAt := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	raw := json.RawMessage(`{"kind":"new_or_changed","value":"https://app.example.test/","reasons":["changed"]}`)
	streamed, ok, err := FromReportItem("changes", raw, observedAt)
	if err != nil || !ok {
		t.Fatalf("streamed item unavailable: ok=%v err=%v", ok, err)
	}
	whole, err := FromReportRaw(json.RawMessage(`{"changes":[`+string(raw)+`],"endpoints":[],"candidate_matches":[],"target_plan_digest":"plan"}`), observedAt)
	if err != nil || len(whole) != 1 {
		t.Fatalf("whole report items=%#v err=%v", whole, err)
	}
	left, _ := json.Marshal(streamed)
	right, _ := json.Marshal(whole[0])
	if string(left) != string(right) {
		t.Fatalf("streamed=%s whole=%s", left, right)
	}
}

func TestEndpointChangeEntityKeyUsesCorrectedEndpointDigest(t *testing.T) {
	key, _, err := normalize.CanonicalEndpoint("https://app.example.test/api/users/123?x=1", "GET", "application/json")
	if err != nil {
		t.Fatal(err)
	}
	items, err := FromReportRaw(reportWithCanonicalEndpoint(t, key), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].EntityKey != key.Digest {
		t.Fatalf("change items=%#v digest=%q", items, key.Digest)
	}
}

func TestEndpointChangeEntityKeysPreserveCorrectedIdentityBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		leftURL   string
		rightURL  string
		wantEqual bool
	}{
		{name: "different origins", leftURL: "https://a.example/api/users/123?x=1", rightURL: "https://b.example/api/users/456?x=2"},
		{name: "query values excluded", leftURL: "https://a.example/api/users/123?x=1", rightURL: "https://a.example/api/users/456?x=2", wantEqual: true},
		{name: "parameter framing", leftURL: "https://a.example/api/users/123?a%2Cb=1&c=1", rightURL: "https://a.example/api/users/456?a=1&b%2Cc=1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			left, _, err := normalize.CanonicalEndpoint(test.leftURL, "GET", "")
			if err != nil {
				t.Fatal(err)
			}
			right, _, err := normalize.CanonicalEndpoint(test.rightURL, "GET", "")
			if err != nil {
				t.Fatal(err)
			}
			leftItems, err := FromReportRaw(reportWithCanonicalEndpoint(t, left), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			rightItems, err := FromReportRaw(reportWithCanonicalEndpoint(t, right), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if len(leftItems) != 1 || len(rightItems) != 1 {
				t.Fatalf("left=%#v right=%#v", leftItems, rightItems)
			}
			gotEqual := leftItems[0].EntityKey == rightItems[0].EntityKey
			if gotEqual != test.wantEqual {
				t.Fatalf("entity keys equal=%t want=%t left=%q right=%q", gotEqual, test.wantEqual, leftItems[0].EntityKey, rightItems[0].EntityKey)
			}
		})
	}
}

func reportWithEndpoint(t *testing.T, history historical) json.RawMessage {
	return reportEndpoint(t, history, "POST", []string{"admin"})
}

func reportEndpoint(t *testing.T, history historical, method string, labels []string) json.RawMessage {
	t.Helper()
	payload := reportPayload{
		Changes:          []AssetChange{},
		CandidateMatches: []string{},
		TargetPlanDigest: "plan",
		Endpoints: []endpointClassification{{
			Endpoint: endpoint{
				ExactURL:        "https://app.example.test/admin",
				RouteSignature:  "/admin",
				Method:          method,
				QueryParameters: []string{},
				Digest:          "endpoint-1",
			},
			Labels:          labels,
			Signals:         []signal{},
			Sources:         []string{"crawl"},
			Technologies:    []string{},
			StatusCodes:     []int{200},
			MatchedKeywords: []string{},
			Historical:      history,
		}},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func reportWithCanonicalEndpoint(t *testing.T, key normalize.EndpointKey) json.RawMessage {
	t.Helper()
	payload := reportPayload{
		Changes:          []AssetChange{},
		CandidateMatches: []string{},
		TargetPlanDigest: "plan",
		Endpoints: []endpointClassification{{
			Endpoint: endpoint{
				ExactURL:        key.ExactURL,
				RouteSignature:  key.RouteSignature,
				Method:          key.Method,
				ContentType:     key.ContentType,
				QueryParameters: append([]string(nil), key.QueryParameters...),
				Digest:          key.Digest,
			},
			Labels:          []string{"api"},
			Signals:         []signal{},
			Sources:         []string{"classify.endpoint"},
			Technologies:    []string{},
			StatusCodes:     []int{200},
			MatchedKeywords: []string{},
			Historical:      historical{},
		}},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
