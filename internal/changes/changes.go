package changes

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type Item struct {
	Kind                string          `json:"kind"`
	EntityType          string          `json:"entity_type"`
	EntityKey           string          `json:"entity_key"`
	Priority            string          `json:"priority"`
	Title               string          `json:"title"`
	Summary             string          `json:"summary"`
	Reasons             []string        `json:"reasons"`
	Previous            json.RawMessage `json:"previous,omitempty"`
	Current             json.RawMessage `json:"current,omitempty"`
	SourceCapabilities  []string        `json:"source_capabilities"`
	EvidenceArtifactIDs []domain.ID     `json:"evidence_artifact_ids,omitempty"`
	ObservedAt          time.Time       `json:"observed_at"`
}

type reportPayload struct {
	Changes          []AssetChange            `json:"changes"`
	Endpoints        []endpointClassification `json:"endpoints"`
	CandidateMatches []string                 `json:"candidate_matches"`
	TargetPlanDigest string                   `json:"target_plan_digest"`
}

type AssetChange struct {
	Kind     string          `json:"kind"`
	Value    string          `json:"value"`
	Previous json.RawMessage `json:"previous,omitempty"`
	Current  json.RawMessage `json:"current,omitempty"`
	Reasons  []string        `json:"reasons"`
}

type endpointClassification struct {
	Endpoint             endpoint   `json:"endpoint"`
	Labels               []string   `json:"labels"`
	MatchedKeywords      []string   `json:"matched_keywords"`
	Signals              []signal   `json:"signals"`
	InterestScore        int        `json:"interest_score"`
	Confidence           float64    `json:"confidence"`
	Sources              []string   `json:"sources"`
	Technologies         []string   `json:"technologies"`
	StatusCodes          []int      `json:"status_codes"`
	RedirectDestinations []string   `json:"redirect_destinations"`
	Historical           historical `json:"historical"`
}

type endpoint struct {
	ExactURL        string   `json:"exact_url"`
	RouteSignature  string   `json:"route_signature"`
	Method          string   `json:"method"`
	ContentType     string   `json:"content_type"`
	QueryParameters []string `json:"query_parameters"`
	Digest          string   `json:"digest"`
}

type signal struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Weight int    `json:"weight"`
	Source string `json:"source"`
}

type historical struct {
	SeenBefore        bool `json:"seen_before"`
	StatusChanged     bool `json:"status_changed"`
	TechnologyChanged bool `json:"technology_changed"`
}

func FromReportRaw(raw json.RawMessage, observedAt time.Time) ([]Item, error) {
	var payload reportPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	items := make([]Item, 0, len(payload.Changes)+len(payload.Endpoints)+len(payload.CandidateMatches))
	for _, change := range payload.Changes {
		if strings.TrimSpace(change.Value) != "" {
			items = append(items, assetItem(change, observedAt))
		}
	}
	for _, endpoint := range payload.Endpoints {
		if strings.TrimSpace(endpoint.Endpoint.ExactURL) != "" {
			if item, ok := endpointItem(endpoint, observedAt); ok {
				items = append(items, item)
			}
		}
	}
	for _, line := range payload.CandidateMatches {
		if item, ok := CandidateFromLine(line, nil, observedAt); ok {
			items = append(items, item)
		}
	}
	return dedupe(items), nil
}

func CandidateFromLine(line string, evidence []domain.ID, observedAt time.Time) (Item, bool) {
	var match map[string]any
	if json.Unmarshal([]byte(line), &match) != nil {
		return Item{}, false
	}
	templateID := stringField(match, "template-id", "templateID", "template")
	target := stringField(match, "matched-at", "matched", "host", "url")
	if templateID == "" || target == "" {
		return Item{}, false
	}
	title := "New candidate finding"
	if info, ok := match["info"].(map[string]any); ok {
		if name := stringField(info, "name"); name != "" {
			title = "New candidate finding: " + name
		}
	}
	current, _ := json.Marshal(match)
	return Item{
		Kind:                "candidate_finding",
		EntityType:          "candidate_finding",
		EntityKey:           target + "#" + templateID,
		Priority:            "high",
		Title:               title,
		Summary:             fmt.Sprintf("Nuclei reported candidate %s on %s", templateID, target),
		Reasons:             []string{"new candidate finding", "scanner matches remain unverified until observed evidence and impact are confirmed"},
		Current:             current,
		SourceCapabilities:  []string{"scan.nuclei"},
		EvidenceArtifactIDs: append([]domain.ID(nil), evidence...),
		ObservedAt:          observedAt,
	}, true
}

func assetItem(change AssetChange, observedAt time.Time) Item {
	kind := strings.TrimSpace(change.Kind)
	value := strings.TrimSpace(change.Value)
	priority := "medium"
	reasons := append([]string(nil), change.Reasons...)
	if len(reasons) == 0 {
		reasons = []string{"HTTP asset was new or changed"}
	}
	title := "HTTP asset changed"
	if kind == "removed" {
		priority = "low"
		if len(change.Reasons) == 0 {
			reasons = []string{"asset was absent from a complete current comparison"}
		}
		title = "HTTP asset removed"
	}
	if hostSignal(value) && kind != "removed" {
		priority = "high"
		reasons = append(reasons, "new authorized hostname or HTTP service")
	}
	return Item{Kind: kind, EntityType: "http_asset", EntityKey: value, Priority: priority, Title: title, Summary: value, Reasons: unique(reasons), Previous: change.Previous, Current: change.Current, SourceCapabilities: []string{"compare.assets"}, ObservedAt: observedAt}
}

func endpointItem(value endpointClassification, observedAt time.Time) (Item, bool) {
	isNew := !value.Historical.SeenBefore
	statusChanged := value.Historical.StatusChanged
	technologyChanged := value.Historical.TechnologyChanged
	if !isNew && !statusChanged && !technologyChanged {
		return Item{}, false
	}
	method := strings.ToUpper(strings.TrimSpace(value.Endpoint.Method))
	reasons := []string{"endpoint classifier marked route interesting"}
	priority := "medium"
	if isNew {
		reasons = append(reasons, "endpoint is newly observed")
	}
	if isNew && method != "" && method != "GET" && method != "HEAD" && method != "OPTIONS" {
		priority = "high"
		reasons = append(reasons, "method is "+method)
	}
	for _, label := range append(append([]string{}, value.Labels...), value.MatchedKeywords...) {
		normalized := strings.ToLower(label)
		if isNew && (strings.Contains(normalized, "admin") || strings.Contains(normalized, "auth") || strings.Contains(normalized, "internal")) {
			priority = "high"
			reasons = append(reasons, "classifier reported "+label+" signal")
			break
		}
	}
	if value.Historical.StatusChanged {
		reasons = append(reasons, "HTTP status changed")
	}
	if value.Historical.TechnologyChanged {
		reasons = append(reasons, "technology changed")
	}
	sort.Strings(value.Sources)
	current, _ := json.Marshal(value)
	title := strings.TrimSpace(method + " " + value.Endpoint.RouteSignature)
	if title == "" {
		title = "Interesting endpoint"
	}
	key := value.Endpoint.Digest
	if key == "" {
		key = value.Endpoint.ExactURL
	}
	return Item{Kind: "endpoint", EntityType: "endpoint", EntityKey: key, Priority: priority, Title: title, Summary: value.Endpoint.ExactURL, Reasons: unique(reasons), Current: current, SourceCapabilities: value.Sources, ObservedAt: observedAt}, true
}

func hostSignal(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Hostname() != ""
}

func stringField(v map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := v[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func dedupe(items []Item) []Item {
	seen := map[string]bool{}
	out := make([]Item, 0, len(items))
	for _, item := range items {
		key := item.Kind + "\x00" + item.EntityType + "\x00" + item.EntityKey
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	return out
}

func unique(items []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}
