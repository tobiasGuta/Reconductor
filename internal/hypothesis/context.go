package hypothesis

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
)

const (
	MaxContextBytes       = 16_384 // 16 KiB authoritative bound (matches InlineSemanticJSONMaxBytes)
	MaxOriginBytes        = 128
	MaxRouteBytes         = 256
	MaxLocatorBytes       = 384
	MaxParamNameBytes     = 64
	MaxReasonBytes        = 64
	MaxCapabilityBytes    = 64
	MaxEntityKeyBytes     = 256
	MaxLocatorsPerRef     = 8
	MaxArtifactIDsPerItem = 8
	MaxParamsPerEndpoint  = 16
	MaxLabelsPerEndpoint  = 8
	MaxTechsPerEndpoint   = 8
	MaxStatusCodes        = 8
	MaxReasonsPerChange   = 8
	MaxCapabilitiesCount  = 32
)

var (
	ErrContextLimitExceeded = errors.New("safe context exceeds 16 KiB size limit after maximum truncation")
	ErrInvalidOrigin        = errors.New("invalid endpoint origin")
	ErrUnredactedEvidence   = errors.New("unredacted evidence rejected from safe context")
)

// SafeEndpoint represents a normalized, provenance-aware endpoint observation.
// Strictly no query parameter values, URL userinfo, or credentials.
type SafeEndpoint struct {
	Origin              string   `json:"origin"`
	RouteSignature      string   `json:"route_signature"`
	Method              string   `json:"method"`
	StatusCodes         []int    `json:"status_codes"`
	QueryParamNames     []string `json:"query_param_names"`
	Labels              []string `json:"labels"`
	Technologies        []string `json:"technologies"`
	EvidenceArtifactIDs []string `json:"evidence_artifact_ids"`
}

// SafeChange represents a normalized change item with query values and target titles omitted.
type SafeChange struct {
	Kind                string   `json:"kind"`
	EntityType          string   `json:"entity_type"`
	EntityKey           string   `json:"entity_key"`
	Priority            string   `json:"priority"`
	Reasons             []string `json:"reasons"`
	EvidenceArtifactIDs []string `json:"evidence_artifact_ids"`
}

// SafeEvidenceRef represents an authoritative link between a verified artifact and its observed locators.
type SafeEvidenceRef struct {
	ArtifactID       string   `json:"artifact_id"`
	StepDefinitionID string   `json:"step_definition_id"`
	SourceCategory   string   `json:"source_category"`
	Locators         []string `json:"locators"`
}

// SafeContext is the strongly typed allowlist-by-construction DTO eligible for model egress.
type SafeContext struct {
	Endpoints               []SafeEndpoint    `json:"endpoints"`
	Changes                 []SafeChange      `json:"changes"`
	Evidence                []SafeEvidenceRef `json:"evidence"`
	AllowedCapabilities     []string          `json:"allowed_capabilities"`
	Truncated               bool              `json:"truncated"`
	AvailableEndpointsCount int               `json:"available_endpoints_count"`
	SelectedEndpointsCount  int               `json:"selected_endpoints_count"`
	AvailableChangesCount   int               `json:"available_changes_count"`
	SelectedChangesCount    int               `json:"selected_changes_count"`
	AvailableEvidenceCount  int               `json:"available_evidence_count"`
	SelectedEvidenceCount   int               `json:"selected_evidence_count"`
}

// RawEndpointInput is an input structure for assembler ingestion.
type RawEndpointInput struct {
	RawURL              string   `json:"raw_url"`
	RouteSignature      string   `json:"route_signature"`
	Method              string   `json:"method"`
	StatusCodes         []int    `json:"status_codes"`
	QueryParameters     []string `json:"query_parameters"` // Can be names or "name=val", assembler extracts names only
	Labels              []string `json:"labels"`
	Technologies        []string `json:"technologies"`
	InterestScore       int      `json:"interest_score"`
	EvidenceArtifactIDs []string `json:"evidence_artifact_ids"`
}

// RawChangeInput is an input structure for assembler ingestion.
type RawChangeInput struct {
	Kind                string   `json:"kind"`
	EntityType          string   `json:"entity_type"`
	EntityKey           string   `json:"entity_key"`
	Priority            string   `json:"priority"`
	Reasons             []string `json:"reasons"`
	EvidenceArtifactIDs []string `json:"evidence_artifact_ids"`
	Title               string   `json:"title,omitempty"`   // Prohibited from SafeContext egress
	Summary             string   `json:"summary,omitempty"` // Prohibited from SafeContext egress
}

// RawEvidenceInput is an input structure for assembler ingestion.
type RawEvidenceInput struct {
	ArtifactID       string   `json:"artifact_id"`
	StepDefinitionID string   `json:"step_definition_id"`
	SourceCategory   string   `json:"source_category"`
	RedactionState   string   `json:"redaction_state"`
	Locators         []string `json:"locators"`
}

// RawEvaluationInput bundles raw normalized observations for a run.
type RawEvaluationInput struct {
	Endpoints           []RawEndpointInput `json:"endpoints"`
	Changes             []RawChangeInput   `json:"changes"`
	Evidence            []RawEvidenceInput `json:"evidence"`
	AllowedCapabilities []string           `json:"allowed_capabilities"`
}

// AssembleSafeContext constructs a deterministic, provenance-aware, bounded SafeContext.
func AssembleSafeContext(raw RawEvaluationInput) (SafeContext, error) {
	// 1. Process and normalize AllowedCapabilities
	caps := dedupSortStrings(raw.AllowedCapabilities)
	if len(caps) > MaxCapabilitiesCount {
		caps = caps[:MaxCapabilitiesCount]
	}
	for i := range caps {
		caps[i] = boundString(caps[i], MaxCapabilityBytes)
	}
	caps = dedupSortStrings(caps)

	// 2. Process and validate Evidence
	validEvidenceMap := make(map[string]SafeEvidenceRef)
	for _, e := range raw.Evidence {
		if strings.TrimSpace(e.ArtifactID) == "" {
			continue
		}
		// Ingestion eligibility check: unredacted evidence is rejected fail-closed
		if e.RedactionState != "redacted" {
			continue
		}
		locs := make([]string, 0, len(e.Locators))
		for _, loc := range e.Locators {
			normLoc := sanitizeLocator(loc)
			if normLoc != "" {
				locs = append(locs, boundString(normLoc, MaxLocatorBytes))
			}
		}
		locs = dedupSortStrings(locs)
		if len(locs) > MaxLocatorsPerRef {
			locs = locs[:MaxLocatorsPerRef]
		}
		validEvidenceMap[e.ArtifactID] = SafeEvidenceRef{
			ArtifactID:       boundString(strings.TrimSpace(e.ArtifactID), 64),
			StepDefinitionID: boundString(strings.TrimSpace(e.StepDefinitionID), 64),
			SourceCategory:   boundString(strings.TrimSpace(e.SourceCategory), 32),
			Locators:         locs,
		}
	}

	// 3. Process Endpoints
	type rankedEndpoint struct {
		endpoint      SafeEndpoint
		interestScore int
		origin        string
		route         string
		method        string
	}
	endpointsList := make([]rankedEndpoint, 0, len(raw.Endpoints))
	for _, ep := range raw.Endpoints {
		origin, err := extractNormalizedOrigin(ep.RawURL)
		if err != nil {
			continue
		}
		route := sanitizeRoute(ep.RouteSignature)
		if route == "" {
			route = "/"
		}
		route = boundString(route, MaxRouteBytes)
		method := strings.ToUpper(strings.TrimSpace(ep.Method))
		if method == "" {
			method = "GET"
		}
		method = boundString(method, 16)

		// Parameter names only - strictly strip any parameter values
		paramNames := make([]string, 0, len(ep.QueryParameters))
		for _, p := range ep.QueryParameters {
			name := sanitizeParamName(p)
			if name != "" {
				paramNames = append(paramNames, boundString(name, MaxParamNameBytes))
			}
		}
		paramNames = dedupSortStrings(paramNames)
		if len(paramNames) > MaxParamsPerEndpoint {
			paramNames = paramNames[:MaxParamsPerEndpoint]
		}

		statusCodes := dedupSortInts(ep.StatusCodes)
		if len(statusCodes) > MaxStatusCodes {
			statusCodes = statusCodes[:MaxStatusCodes]
		}

		labels := make([]string, 0, len(ep.Labels))
		for _, l := range ep.Labels {
			clean := strings.ToLower(strings.TrimSpace(l))
			if clean != "" {
				labels = append(labels, boundString(clean, 32))
			}
		}
		labels = dedupSortStrings(labels)
		if len(labels) > MaxLabelsPerEndpoint {
			labels = labels[:MaxLabelsPerEndpoint]
		}

		techs := make([]string, 0, len(ep.Technologies))
		for _, t := range ep.Technologies {
			clean := strings.TrimSpace(t)
			if clean != "" {
				techs = append(techs, boundString(clean, 64))
			}
		}
		techs = dedupSortStrings(techs)
		if len(techs) > MaxTechsPerEndpoint {
			techs = techs[:MaxTechsPerEndpoint]
		}

		// Filter evidence IDs to those in validEvidenceMap
		artIDs := make([]string, 0, len(ep.EvidenceArtifactIDs))
		for _, id := range ep.EvidenceArtifactIDs {
			trimmed := strings.TrimSpace(id)
			if _, ok := validEvidenceMap[trimmed]; ok {
				artIDs = append(artIDs, trimmed)
			}
		}
		artIDs = dedupSortStrings(artIDs)
		if len(artIDs) > MaxArtifactIDsPerItem {
			artIDs = artIDs[:MaxArtifactIDsPerItem]
		}

		safeEp := SafeEndpoint{
			Origin:              origin,
			RouteSignature:      route,
			Method:              method,
			StatusCodes:         statusCodes,
			QueryParamNames:     paramNames,
			Labels:              labels,
			Technologies:        techs,
			EvidenceArtifactIDs: artIDs,
		}

		endpointsList = append(endpointsList, rankedEndpoint{
			endpoint:      safeEp,
			interestScore: ep.InterestScore,
			origin:        origin,
			route:         route,
			method:        method,
		})
	}

	// Priority ranking: InterestScore DESC, tie-breaking by deterministic identity ASC
	sort.Slice(endpointsList, func(i, j int) bool {
		if endpointsList[i].interestScore != endpointsList[j].interestScore {
			return endpointsList[i].interestScore > endpointsList[j].interestScore
		}
		if endpointsList[i].origin != endpointsList[j].origin {
			return endpointsList[i].origin < endpointsList[j].origin
		}
		if endpointsList[i].route != endpointsList[j].route {
			return endpointsList[i].route < endpointsList[j].route
		}
		return endpointsList[i].method < endpointsList[j].method
	})

	// Deduplicate identical endpoints keeping highest interest score
	rankedEndpoints := make([]rankedEndpoint, 0, len(endpointsList))
	seenEpKeys := make(map[string]bool)
	for _, item := range endpointsList {
		key := fmt.Sprintf("%s\x00%s\x00%s", item.origin, item.route, item.method)
		if seenEpKeys[key] {
			continue
		}
		seenEpKeys[key] = true
		rankedEndpoints = append(rankedEndpoints, item)
	}

	// 4. Process Changes
	type rankedChange struct {
		change       SafeChange
		priorityRank int
		kind         string
		entityKey    string
	}
	changesList := make([]rankedChange, 0, len(raw.Changes))
	for _, ch := range raw.Changes {
		kind := boundString(strings.TrimSpace(ch.Kind), 32)
		entType := boundString(strings.TrimSpace(ch.EntityType), 32)
		entKey := boundString(sanitizeEntityKey(ch.EntityKey), MaxEntityKeyBytes)
		priority := strings.ToLower(strings.TrimSpace(ch.Priority))
		if priority == "" {
			priority = "low"
		}
		priority = boundString(priority, 16)

		reasons := make([]string, 0, len(ch.Reasons))
		for _, r := range ch.Reasons {
			clean := strings.TrimSpace(r)
			if clean != "" {
				reasons = append(reasons, boundString(clean, MaxReasonBytes))
			}
		}
		reasons = dedupSortStrings(reasons)
		if len(reasons) > MaxReasonsPerChange {
			reasons = reasons[:MaxReasonsPerChange]
		}

		artIDs := make([]string, 0, len(ch.EvidenceArtifactIDs))
		for _, id := range ch.EvidenceArtifactIDs {
			trimmed := strings.TrimSpace(id)
			if _, ok := validEvidenceMap[trimmed]; ok {
				artIDs = append(artIDs, trimmed)
			}
		}
		artIDs = dedupSortStrings(artIDs)
		if len(artIDs) > MaxArtifactIDsPerItem {
			artIDs = artIDs[:MaxArtifactIDsPerItem]
		}

		safeCh := SafeChange{
			Kind:                kind,
			EntityType:          entType,
			EntityKey:           entKey,
			Priority:            priority,
			Reasons:             reasons,
			EvidenceArtifactIDs: artIDs,
		}

		pRank := priorityRank(priority)
		changesList = append(changesList, rankedChange{
			change:       safeCh,
			priorityRank: pRank,
			kind:         kind,
			entityKey:    entKey,
		})
	}

	// Sort changes by priority rank ASC (Critical=1 first), tie-breaking by lexical key
	sort.Slice(changesList, func(i, j int) bool {
		if changesList[i].priorityRank != changesList[j].priorityRank {
			return changesList[i].priorityRank < changesList[j].priorityRank
		}
		if changesList[i].kind != changesList[j].kind {
			return changesList[i].kind < changesList[j].kind
		}
		return changesList[i].entityKey < changesList[j].entityKey
	})

	rankedChanges := make([]rankedChange, 0, len(changesList))
	seenChKeys := make(map[string]bool)
	for _, item := range changesList {
		key := fmt.Sprintf("%s\x00%s\x00%s", item.change.Kind, item.change.EntityType, item.change.EntityKey)
		if seenChKeys[key] {
			continue
		}
		seenChKeys[key] = true
		rankedChanges = append(rankedChanges, item)
	}

	// 5. Gather evidence list sorted by ArtifactID ASC
	evidenceList := make([]SafeEvidenceRef, 0, len(validEvidenceMap))
	for _, e := range validEvidenceMap {
		evidenceList = append(evidenceList, e)
	}
	sort.Slice(evidenceList, func(i, j int) bool {
		return evidenceList[i].ArtifactID < evidenceList[j].ArtifactID
	})

	totalEndpoints := len(rankedEndpoints)
	totalChanges := len(rankedChanges)
	totalEvidence := len(evidenceList)
	truncated := false

	// Progressive whole-context bounding loop
	selectedEndpoints := make([]rankedEndpoint, len(rankedEndpoints))
	copy(selectedEndpoints, rankedEndpoints)
	selectedChanges := make([]rankedChange, len(rankedChanges))
	copy(selectedChanges, rankedChanges)

	for {
		// Stage 2: Canonical lexical sorting for serialization
		canonEndpoints := make([]SafeEndpoint, len(selectedEndpoints))
		for i, re := range selectedEndpoints {
			canonEndpoints[i] = re.endpoint
		}
		sort.Slice(canonEndpoints, func(i, j int) bool {
			if canonEndpoints[i].Origin != canonEndpoints[j].Origin {
				return canonEndpoints[i].Origin < canonEndpoints[j].Origin
			}
			if canonEndpoints[i].Method != canonEndpoints[j].Method {
				return canonEndpoints[i].Method < canonEndpoints[j].Method
			}
			return canonEndpoints[i].RouteSignature < canonEndpoints[j].RouteSignature
		})

		canonChanges := make([]SafeChange, len(selectedChanges))
		for i, rc := range selectedChanges {
			canonChanges[i] = rc.change
		}
		sort.Slice(canonChanges, func(i, j int) bool {
			if canonChanges[i].Kind != canonChanges[j].Kind {
				return canonChanges[i].Kind < canonChanges[j].Kind
			}
			if canonChanges[i].EntityType != canonChanges[j].EntityType {
				return canonChanges[i].EntityType < canonChanges[j].EntityType
			}
			return canonChanges[i].EntityKey < canonChanges[j].EntityKey
		})

		// Prune evidence to only those referenced by selected endpoints or changes
		referencedArtifacts := make(map[string]bool)
		for _, ep := range canonEndpoints {
			for _, id := range ep.EvidenceArtifactIDs {
				referencedArtifacts[id] = true
			}
		}
		for _, ch := range canonChanges {
			for _, id := range ch.EvidenceArtifactIDs {
				referencedArtifacts[id] = true
			}
		}

		keptEvidence := make([]SafeEvidenceRef, 0, len(evidenceList))
		for _, ev := range evidenceList {
			if referencedArtifacts[ev.ArtifactID] {
				keptEvidence = append(keptEvidence, ev)
			}
		}

		isTruncated := truncated ||
			len(selectedEndpoints) < totalEndpoints ||
			len(selectedChanges) < totalChanges ||
			len(keptEvidence) < totalEvidence

		candidateCtx := SafeContext{
			Endpoints:               canonEndpoints,
			Changes:                 canonChanges,
			Evidence:                keptEvidence,
			AllowedCapabilities:     caps,
			Truncated:               isTruncated,
			AvailableEndpointsCount: totalEndpoints,
			SelectedEndpointsCount:  len(canonEndpoints),
			AvailableChangesCount:   totalChanges,
			SelectedChangesCount:    len(canonChanges),
			AvailableEvidenceCount:  totalEvidence,
			SelectedEvidenceCount:   len(keptEvidence),
		}

		b, err := json.Marshal(candidateCtx)
		if err != nil {
			return SafeContext{}, err
		}

		if len(b) <= MaxContextBytes {
			return candidateCtx, nil
		}

		// Stage 1 Eviction: Drop lowest-priority items from tail of ranked collections
		truncated = true
		if len(selectedChanges) > 0 {
			// Drop lowest-priority change first
			selectedChanges = selectedChanges[:len(selectedChanges)-1]
			continue
		}
		if len(selectedEndpoints) > 0 {
			// Drop lowest-scoring endpoint
			selectedEndpoints = selectedEndpoints[:len(selectedEndpoints)-1]
			continue
		}

		// Even with 0 changes and 0 endpoints, context still exceeds 16 KiB!
		// Fail closed.
		return SafeContext{}, ErrContextLimitExceeded
	}
}

func priorityRank(p string) int {
	switch strings.ToLower(p) {
	case "critical":
		return 1
	case "high":
		return 2
	case "medium":
		return 3
	case "low":
		return 4
	default:
		return 5
	}
}

func sanitizeParamName(p string) string {
	clean := strings.TrimSpace(p)
	if idx := strings.IndexByte(clean, '='); idx >= 0 {
		clean = clean[:idx]
	}
	clean = strings.TrimSpace(clean)
	return clean
}

func sanitizeRoute(sig string) string {
	clean := strings.TrimSpace(sig)
	if idx := strings.IndexByte(clean, '?'); idx >= 0 {
		clean = clean[:idx]
	}
	if !strings.HasPrefix(clean, "/") && clean != "" {
		clean = "/" + clean
	}
	return path.Clean(clean)
}

func sanitizeEntityKey(key string) string {
	clean := strings.TrimSpace(key)
	if idx := strings.IndexByte(clean, '?'); idx >= 0 {
		clean = clean[:idx]
	}
	return clean
}

func sanitizeLocator(loc string) string {
	clean := strings.TrimSpace(loc)
	if idx := strings.IndexByte(clean, '?'); idx >= 0 {
		clean = clean[:idx]
	}
	return clean
}

func extractNormalizedOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ErrInvalidOrigin
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + strings.TrimPrefix(raw, "//")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", ErrInvalidOrigin
	}
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return "", ErrInvalidOrigin
	}

	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}

	authority := hostname
	if port != "" {
		authority = net.JoinHostPort(hostname, port)
	}

	origin := fmt.Sprintf("%s://%s", scheme, authority)
	return boundString(origin, MaxOriginBytes), nil
}

func boundString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func dedupSortStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] && s != "" {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func dedupSortInts(in []int) []int {
	if len(in) == 0 {
		return []int{}
	}
	seen := make(map[int]bool, len(in))
	out := make([]int, 0, len(in))
	for _, n := range in {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

// CanonicalJSONSafeContext serializes SafeContext into strictly formatted canonical JSON.
func CanonicalJSONSafeContext(ctx SafeContext) ([]byte, error) {
	raw, err := json.Marshal(ctx)
	if err != nil {
		return nil, err
	}
	_, canonical, _, _, err := canonicaljson.ParseStrict(raw)
	return canonical, err
}
