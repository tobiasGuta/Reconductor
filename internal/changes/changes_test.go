package changes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
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
