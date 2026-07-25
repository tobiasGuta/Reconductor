package intelligence

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/tobiasGuta/Reconductor/internal/normalize"
	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
)

type Input struct {
	HTTPObservations       []provideroutput.Record
	CrawlObservations      []provideroutput.Record
	PassiveObservations    []provideroutput.Record
	HistoricalObservations []provideroutput.Record
	APISchemaEndpoints     []string
}

type Signal struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Weight int    `json:"weight"`
	Source string `json:"source"`
}

type Relationship struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
}

type HistoricalBehavior struct {
	SeenBefore        bool `json:"seen_before"`
	StatusChanged     bool `json:"status_changed"`
	TechnologyChanged bool `json:"technology_changed"`
}

type EndpointClassification struct {
	Endpoint             normalize.EndpointKey `json:"endpoint"`
	Labels               []string              `json:"labels"`
	MatchedKeywords      []string              `json:"matched_keywords"`
	Signals              []Signal              `json:"signals"`
	InterestScore        int                   `json:"interest_score"`
	Confidence           float64               `json:"confidence"`
	Sources              []string              `json:"sources"`
	Technologies         []string              `json:"technologies"`
	StatusCodes          []int                 `json:"status_codes"`
	RedirectDestinations []string              `json:"redirect_destinations"`
	Relationships        []Relationship        `json:"relationships"`
	Historical           HistoricalBehavior    `json:"historical"`
}

type Output struct {
	Endpoints            []normalize.EndpointKey  `json:"endpoints"`
	Classifications      []EndpointClassification `json:"classifications"`
	InterestingEndpoints []EndpointClassification `json:"interesting_endpoints"`
	Relationships        []Relationship           `json:"relationships"`
}

type observation struct {
	record provideroutput.Record
	source string
}

type parsedObservation struct {
	observation
	key     normalize.EndpointKey
	details recordDetails
}

type aggregate struct {
	classification  EndpointClassification
	signalSet       map[string]bool
	labelSet        map[string]bool
	keywordSet      map[string]bool
	sourceSet       map[string]bool
	technologySet   map[string]bool
	statusSet       map[int]bool
	redirectSet     map[string]bool
	relationshipSet map[string]bool
	maxConfidence   float64
}

var interestingKeywords = map[string]bool{
	"admin": true, "api": true, "swagger": true, "openapi": true,
	"graphql": true, "oauth": true, "debug": true, "upload": true,
}

var authenticationKeywords = map[string]bool{
	"auth": true, "login": true, "signin": true, "oauth": true,
	"sso": true, "token": true, "session": true,
}

func Classify(input Input) (Output, error) {
	current := appendRecords(nil, input.HTTPObservations, "http")
	current = appendRecords(current, input.CrawlObservations, "crawl")
	current = appendRecords(current, input.PassiveObservations, "passive")
	apiExact, apiRoutes, err := schemaMembership(input.APISchemaEndpoints)
	if err != nil {
		return Output{}, err
	}
	history, err := historicalIndex(input.HistoricalObservations)
	if err != nil {
		return Output{}, err
	}
	parsed := make([]parsedObservation, 0, len(current))
	for index, item := range current {
		key, details, err := endpointFromRecord(item.record)
		if err != nil {
			return Output{}, fmt.Errorf("%s observation %d: %w", item.source, index, err)
		}
		parsed = append(parsed, parsedObservation{observation: item, key: key, details: details})
	}
	sort.Slice(parsed, func(i, j int) bool {
		left, right := parsed[i], parsed[j]
		leftKey := left.key.Digest + "\x00" + left.key.ExactURL + "\x00" + left.source + "\x00" + left.record.Provider
		rightKey := right.key.Digest + "\x00" + right.key.ExactURL + "\x00" + right.source + "\x00" + right.record.Provider
		return leftKey < rightKey
	})
	aggregates := map[string]*aggregate{}
	for _, item := range parsed {
		key, details := item.key, item.details
		entry := aggregates[key.Digest]
		if entry == nil {
			entry = newAggregate(key)
			aggregates[key.Digest] = entry
		}
		applyObservation(entry, item.observation, details)
		if apiExact[key.ExactURL] || apiRoutes[key.RouteSignature] {
			entry.addLabel("api_schema_member")
			entry.addSignal("api_schema_membership", key.RouteSignature, 3, "api_schema")
		}
		if previous := history[historyKey(key)]; len(previous) > 0 {
			entry.classification.Historical.SeenBefore = true
			entry.addLabel("historically_observed")
			entry.addSignal("historically_observed", key.ExactURL, 0, "history")
			applyHistoricalComparison(entry, details, previous)
		} else if len(input.HistoricalObservations) > 0 {
			entry.addLabel("new_endpoint")
			entry.addSignal("new_endpoint", key.ExactURL, 1, "history")
		}
	}
	keys := make([]string, 0, len(aggregates))
	for key := range aggregates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	output := Output{Endpoints: []normalize.EndpointKey{}, Classifications: []EndpointClassification{}, InterestingEndpoints: []EndpointClassification{}, Relationships: []Relationship{}}
	globalRelationships := map[string]bool{}
	for _, digest := range keys {
		entry := aggregates[digest]
		finalize(entry)
		classification := entry.classification
		output.Endpoints = append(output.Endpoints, classification.Endpoint)
		output.Classifications = append(output.Classifications, classification)
		if classification.InterestScore >= 2 {
			output.InterestingEndpoints = append(output.InterestingEndpoints, classification)
		}
		for _, relationship := range classification.Relationships {
			key := relationship.Source + "\x00" + relationship.Target + "\x00" + relationship.Kind
			if !globalRelationships[key] {
				globalRelationships[key] = true
				output.Relationships = append(output.Relationships, relationship)
			}
		}
	}
	sort.Slice(output.Relationships, func(i, j int) bool {
		left, right := output.Relationships[i], output.Relationships[j]
		return left.Source+"\x00"+left.Target+"\x00"+left.Kind < right.Source+"\x00"+right.Target+"\x00"+right.Kind
	})
	return output, nil
}

type recordDetails struct {
	method, requestContentType, responseContentType string
	redirect, sourceURL                             string
	status                                          int
	technologies                                    []string
}

func endpointFromRecord(record provideroutput.Record) (normalize.EndpointKey, recordDetails, error) {
	if strings.TrimSpace(record.Provider) == "" {
		return normalize.EndpointKey{}, recordDetails{}, fmt.Errorf("record provider is required")
	}
	if record.Kind != provideroutput.URLRecord {
		return normalize.EndpointKey{}, recordDetails{}, fmt.Errorf("record kind %q is not a URL", record.Kind)
	}
	if record.StatusCode < 0 || record.StatusCode > 599 {
		return normalize.EndpointKey{}, recordDetails{}, fmt.Errorf("record status code %d is outside 0-599", record.StatusCode)
	}
	parsedTarget, err := url.Parse(strings.TrimSpace(record.Target))
	if err != nil || parsedTarget.Hostname() == "" || (parsedTarget.Scheme != "http" && parsedTarget.Scheme != "https") {
		return normalize.EndpointKey{}, recordDetails{}, fmt.Errorf("record target must be an absolute HTTP URL")
	}
	requestFields := nestedObject(record.Fields, "request")
	responseFields := nestedObject(record.Fields, "response")
	requestContentType := directString(record.Fields, "request_content_type", "request-content-type")
	if requestContentType == "" {
		requestContentType = firstNestedString(requestFields, "content_type", "content-type")
	}
	responseContentType := directString(record.Fields, "response_content_type", "response-content-type")
	if responseContentType == "" {
		responseContentType = firstNestedString(responseFields, "content_type", "content-type")
	}
	if responseContentType == "" {
		responseContentType = directString(record.Fields, "content_type", "content-type", "mime_type", "mime-type")
	}
	method := firstNestedString(requestFields, "method")
	if method == "" {
		method = directString(record.Fields, "method")
	}
	details := recordDetails{
		method:              strings.ToUpper(method),
		requestContentType:  requestContentType,
		responseContentType: responseContentType,
		redirect:            firstNestedString(record.Fields, "final-url", "final_url", "redirect", "location"),
		sourceURL:           firstNestedString(record.Fields, "source_url", "source", "referer", "referrer"),
		status:              record.StatusCode,
		technologies:        append([]string{}, record.Technologies...),
	}
	if details.method == "" {
		details.method = "GET"
	}
	if details.status == 0 {
		details.status = firstNestedInt(record.Fields, "status_code", "status-code", "status")
	}
	details.technologies = append(details.technologies, firstNestedStrings(record.Fields, "tech", "technologies")...)
	key, err := normalize.Endpoint(record.Target, details.method, details.requestContentType)
	if err != nil {
		return normalize.EndpointKey{}, recordDetails{}, err
	}
	details.redirect = normalizedOptionalURL(details.redirect)
	details.sourceURL = normalizedOptionalURL(details.sourceURL)
	details.technologies = normalizedStrings(details.technologies)
	return key, details, nil
}

func applyObservation(entry *aggregate, item observation, details recordDetails) {
	source := strings.ToLower(strings.TrimSpace(item.record.Provider))
	if source == "" {
		source = item.source
	}
	entry.sourceSet[source] = true
	confidence := sourceConfidence(source)
	if value, ok := nestedFloat(item.record.Fields, "confidence"); ok && value >= 0 && value <= 1 {
		confidence = value
	}
	if confidence > entry.maxConfidence {
		entry.maxConfidence = confidence
	}
	for _, technology := range details.technologies {
		entry.technologySet[technology] = true
		entry.addSignal("technology", technology, 0, source)
	}
	if details.status > 0 {
		entry.statusSet[details.status] = true
		entry.addSignal("response_status", strconv.Itoa(details.status), 0, source)
		switch {
		case details.status == 401 || details.status == 403:
			entry.addLabel("authentication_required")
			entry.addSignal("authentication_status", strconv.Itoa(details.status), 3, source)
		case details.status >= 300 && details.status <= 399:
			entry.addLabel("redirect")
			entry.addSignal("redirect_status", strconv.Itoa(details.status), 1, source)
		case details.status >= 500:
			entry.addLabel("server_error")
			entry.addSignal("server_error_status", strconv.Itoa(details.status), 1, source)
		}
	}
	if details.redirect != "" {
		entry.redirectSet[details.redirect] = true
		entry.addSignal("redirect_destination", details.redirect, 1, source)
	}
	applyURLSignals(entry, entry.classification.Endpoint, source)
	if details.method != "GET" && details.method != "HEAD" && details.method != "OPTIONS" {
		entry.addLabel("non_read_method")
		entry.addSignal("http_method", details.method, 2, source)
	}
	contentType := strings.ToLower(details.responseContentType)
	if contentType == "" {
		contentType = strings.ToLower(details.requestContentType)
	}
	if strings.Contains(contentType, "json") || strings.Contains(contentType, "graphql") {
		entry.addLabel("api_content")
		entry.addSignal("content_type", contentType, 1, source)
	}
	if strings.Contains(strings.ToLower(details.sourceURL), ".js") {
		relationship := Relationship{Source: details.sourceURL, Target: entry.classification.Endpoint.ExactURL, Kind: "javascript_reference"}
		entry.addRelationship(relationship)
		entry.addLabel("javascript_discovered")
		entry.addSignal("javascript_source", details.sourceURL, 2, source)
	}
	if strings.HasSuffix(strings.ToLower(pathOf(entry.classification.Endpoint.ExactURL)), ".js") {
		entry.addLabel("javascript_asset")
		entry.addSignal("javascript_asset", entry.classification.Endpoint.ExactURL, 1, source)
	}
	if hasAuthenticationHeader(item.record.Fields) {
		entry.addLabel("authentication_required")
		entry.addSignal("authentication_header", "www-authenticate", 3, source)
	}
}

func applyURLSignals(entry *aggregate, endpoint normalize.EndpointKey, source string) {
	parsed, _ := url.Parse(endpoint.ExactURL)
	for token := range urlTokens(parsed) {
		if interestingKeywords[token] {
			entry.keywordSet[token] = true
			entry.addLabel("keyword:" + token)
			entry.addSignal("url_keyword", token, 2, source)
		}
		if authenticationKeywords[token] {
			entry.addLabel("authentication_indicator")
			entry.addSignal("authentication_keyword", token, 2, source)
		}
	}
	if len(endpoint.QueryParameters) > 0 {
		entry.addLabel("query_parameters")
		entry.addSignal("query_parameters", strings.Join(endpoint.QueryParameters, ","), 1, source)
	}
	if strings.Contains(endpoint.RouteSignature, "{id}") {
		entry.addLabel("parameterized_path")
		entry.addSignal("path_parameter", endpoint.RouteSignature, 2, source)
	}
	lowerPath := strings.ToLower(parsed.Path)
	if strings.HasSuffix(lowerPath, "/openapi.json") || strings.HasSuffix(lowerPath, "/swagger.json") || strings.HasSuffix(lowerPath, "/openapi.yaml") || strings.HasSuffix(lowerPath, "/openapi.yml") {
		entry.addLabel("api_schema_document")
		entry.addSignal("api_schema_document", endpoint.ExactURL, 3, source)
	}
}

func historicalIndex(records []provideroutput.Record) (map[string][]recordDetails, error) {
	out := map[string][]recordDetails{}
	for index, record := range records {
		key, details, err := endpointFromRecord(record)
		if err != nil {
			return nil, fmt.Errorf("historical observation %d: %w", index, err)
		}
		out[historyKey(key)] = append(out[historyKey(key)], details)
	}
	return out, nil
}

func applyHistoricalComparison(entry *aggregate, current recordDetails, previous []recordDetails) {
	currentTech := stringSet(current.technologies)
	for _, old := range previous {
		if current.status > 0 && old.status > 0 && current.status != old.status {
			entry.classification.Historical.StatusChanged = true
		}
		if len(currentTech) > 0 && len(old.technologies) > 0 && !sameSet(currentTech, stringSet(old.technologies)) {
			entry.classification.Historical.TechnologyChanged = true
		}
	}
	if entry.classification.Historical.StatusChanged {
		entry.addLabel("status_changed")
		entry.addSignal("historical_status_change", "changed", 2, "history")
	}
	if entry.classification.Historical.TechnologyChanged {
		entry.addLabel("technology_changed")
		entry.addSignal("historical_technology_change", "changed", 1, "history")
	}
}

func finalize(entry *aggregate) {
	classification := &entry.classification
	classification.Labels = sortedKeys(entry.labelSet)
	classification.MatchedKeywords = sortedKeys(entry.keywordSet)
	classification.Sources = sortedKeys(entry.sourceSet)
	classification.Technologies = sortedKeys(entry.technologySet)
	classification.StatusCodes = sortedInts(entry.statusSet)
	classification.RedirectDestinations = sortedKeys(entry.redirectSet)
	sort.Slice(classification.Signals, func(i, j int) bool {
		left, right := classification.Signals[i], classification.Signals[j]
		return left.Type+"\x00"+left.Value+"\x00"+left.Source < right.Type+"\x00"+right.Value+"\x00"+right.Source
	})
	sort.Slice(classification.Relationships, func(i, j int) bool {
		left, right := classification.Relationships[i], classification.Relationships[j]
		return left.Source+"\x00"+left.Target+"\x00"+left.Kind < right.Source+"\x00"+right.Target+"\x00"+right.Kind
	})
	score, positiveSignals := 0, 0
	for _, signal := range classification.Signals {
		score += signal.Weight
		if signal.Weight > 0 {
			positiveSignals++
		}
	}
	if len(classification.Sources) > 1 {
		score++
		classification.Labels = appendUniqueSorted(classification.Labels, "multi_source")
	}
	classification.InterestScore = score
	confidence := entry.maxConfidence + float64(max(0, len(classification.Sources)-1))*0.05 + float64(positiveSignals)*0.03
	classification.Confidence = math.Round(math.Min(0.99, confidence)*100) / 100
}

func newAggregate(key normalize.EndpointKey) *aggregate {
	return &aggregate{
		classification: EndpointClassification{Endpoint: key, Labels: []string{}, MatchedKeywords: []string{}, Signals: []Signal{}, Sources: []string{}, Technologies: []string{}, StatusCodes: []int{}, RedirectDestinations: []string{}, Relationships: []Relationship{}},
		signalSet:      map[string]bool{}, labelSet: map[string]bool{}, keywordSet: map[string]bool{}, sourceSet: map[string]bool{}, technologySet: map[string]bool{}, statusSet: map[int]bool{}, redirectSet: map[string]bool{}, relationshipSet: map[string]bool{},
	}
}

func (a *aggregate) addSignal(kind, value string, weight int, source string) {
	key := kind + "\x00" + value + "\x00" + source
	if a.signalSet[key] {
		return
	}
	a.signalSet[key] = true
	a.classification.Signals = append(a.classification.Signals, Signal{Type: kind, Value: value, Weight: weight, Source: source})
}

func (a *aggregate) addLabel(value string) { a.labelSet[value] = true }

func (a *aggregate) addRelationship(value Relationship) {
	key := value.Source + "\x00" + value.Target + "\x00" + value.Kind
	if a.relationshipSet[key] {
		return
	}
	a.relationshipSet[key] = true
	a.classification.Relationships = append(a.classification.Relationships, value)
}

func appendRecords(out []observation, records []provideroutput.Record, source string) []observation {
	for _, record := range records {
		out = append(out, observation{record: record, source: source})
	}
	return out
}

func schemaMembership(items []string) (map[string]bool, map[string]bool, error) {
	exact, routes := map[string]bool{}, map[string]bool{}
	for index, raw := range items {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, nil, fmt.Errorf("api schema endpoint %d must be an absolute HTTP URL", index)
		}
		key, err := normalize.Endpoint(raw, "GET", "")
		if err != nil {
			return nil, nil, fmt.Errorf("api schema endpoint %d: %w", index, err)
		}
		exact[key.ExactURL], routes[key.RouteSignature] = true, true
	}
	return exact, routes, nil
}

func historyKey(key normalize.EndpointKey) string { return key.Digest }

func sourceConfidence(source string) float64 {
	switch source {
	case "httpx":
		return 0.95
	case "katana":
		return 0.85
	case "gau":
		return 0.55
	case "historical":
		return 0.65
	default:
		return 0.5
	}
}

func urlTokens(value *url.URL) map[string]bool {
	out := map[string]bool{}
	add := func(raw string) {
		for _, token := range strings.FieldsFunc(strings.ToLower(raw), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
			if token != "" {
				out[token] = true
			}
		}
	}
	add(value.Path)
	for key := range value.Query() {
		add(key)
	}
	return out
}

func pathOf(raw string) string {
	parsed, _ := url.Parse(raw)
	return parsed.Path
}

func normalizedOptionalURL(raw string) string {
	if raw == "" {
		return ""
	}
	normalized, err := normalize.URL(raw)
	if err != nil {
		return ""
	}
	return normalized
}

func firstNestedString(fields map[string]any, keys ...string) string {
	for _, value := range nestedValues(fields, keys...) {
		if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
			return strings.TrimSpace(text)
		}
	}
	return ""
}

func directString(fields map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := fields[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func nestedObject(fields map[string]any, key string) map[string]any {
	if value, ok := fields[key].(map[string]any); ok {
		return value
	}
	return map[string]any{}
}

func firstNestedInt(fields map[string]any, keys ...string) int {
	for _, value := range nestedValues(fields, keys...) {
		switch number := value.(type) {
		case float64:
			return int(number)
		case int:
			return number
		case string:
			parsed, _ := strconv.Atoi(number)
			if parsed > 0 {
				return parsed
			}
		}
	}
	return 0
}

func firstNestedStrings(fields map[string]any, keys ...string) []string {
	for _, value := range nestedValues(fields, keys...) {
		switch items := value.(type) {
		case []any:
			out := []string{}
			for _, item := range items {
				if text, ok := item.(string); ok {
					out = append(out, text)
				}
			}
			return out
		case []string:
			return items
		}
	}
	return nil
}

func nestedValues(fields map[string]any, keys ...string) []any {
	wanted := map[string]bool{}
	for _, key := range keys {
		wanted[strings.ToLower(key)] = true
	}
	out := []any{}
	var walk func(any)
	walk = func(value any) {
		switch current := value.(type) {
		case map[string]any:
			ordered := make([]string, 0, len(current))
			for key := range current {
				ordered = append(ordered, key)
			}
			sort.Strings(ordered)
			for _, key := range ordered {
				if wanted[strings.ToLower(key)] {
					out = append(out, current[key])
				}
				walk(current[key])
			}
		case []any:
			for _, item := range current {
				walk(item)
			}
		}
	}
	walk(fields)
	return out
}

func nestedFloat(fields map[string]any, key string) (float64, bool) {
	for _, value := range nestedValues(fields, key) {
		if number, ok := value.(float64); ok {
			return number, true
		}
	}
	return 0, false
}

func hasAuthenticationHeader(fields map[string]any) bool {
	for _, value := range nestedValues(fields, "www-authenticate") {
		if text, ok := value.(string); ok && text != "" {
			return true
		}
	}
	return false
}

func normalizedStrings(items []string) []string {
	set := map[string]bool{}
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		if item != "" {
			set[item] = true
		}
	}
	return sortedKeys(set)
}

func stringSet(items []string) map[string]bool {
	out := map[string]bool{}
	for _, item := range normalizedStrings(items) {
		out[item] = true
	}
	return out
}

func sameSet(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if !right[value] {
			return false
		}
	}
	return true
}

func sortedKeys[T ~string](items map[T]bool) []T {
	out := make([]T, 0, len(items))
	for item := range items {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedInts(items map[int]bool) []int {
	out := make([]int, 0, len(items))
	for item := range items {
		out = append(out, item)
	}
	sort.Ints(out)
	return out
}

func appendUniqueSorted(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	items = append(items, value)
	sort.Strings(items)
	return items
}
