package targeting

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
)

type DetailedScope interface {
	Evaluate(string) platformscope.Evaluation
	IncludeRules() []platformscope.NormalizedRule
	ExcludeRules() []platformscope.NormalizedRule
}

type PassiveDiscoveryScope interface {
	DetailedScope
	AllowsDiscoveryRoot(string) bool
}

type PlannedScope struct {
	DetailedScope
	discoveryRoots        map[string]DiscoveryRoot
	currentDiscoveryRoots map[string]DiscoveryRoot
}

func WithDiscoveryRoots(sc DetailedScope, pinnedRoots, currentRoots []DiscoveryRoot) PlannedScope {
	bound := PlannedScope{DetailedScope: sc, discoveryRoots: make(map[string]DiscoveryRoot, len(pinnedRoots)), currentDiscoveryRoots: make(map[string]DiscoveryRoot, len(currentRoots))}
	for _, pinned := range pinnedRoots {
		if root, err := normalizeHostname(pinned.Domain); err == nil {
			pinned.Domain = root
			pinned.SourceRuleIDs = append([]string(nil), pinned.SourceRuleIDs...)
			bound.discoveryRoots[root] = pinned
		}
	}
	for _, current := range currentRoots {
		if root, err := normalizeHostname(current.Domain); err == nil {
			current.Domain = root
			current.SourceRuleIDs = append([]string(nil), current.SourceRuleIDs...)
			bound.currentDiscoveryRoots[root] = current
		}
	}
	return bound
}

func (s PlannedScope) Allows(target string) bool { return s.Evaluate(target).Allowed }

func (s PlannedScope) AllowsDiscoveryRoot(raw string) bool {
	root, err := normalizeHostname(raw)
	if err != nil {
		return false
	}
	pinned, pinnedToOriginalPlan := s.discoveryRoots[root]
	if !pinnedToOriginalPlan {
		return false
	}
	current, presentInCurrentPlan := s.currentDiscoveryRoots[root]
	if !presentInCurrentPlan {
		return false
	}
	for _, sourceRuleID := range pinned.SourceRuleIDs {
		if !containsString(current.SourceRuleIDs, sourceRuleID) {
			continue
		}
		if discoverySourceBasisAllowed(s.DetailedScope, root, sourceRuleID) {
			return true
		}
		if pinned.Source == "manual" && current.Source == "manual" {
			return true
		}
	}
	return false
}

func containsString(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func discoverySourceBasisAllowed(sc DetailedScope, root, sourceRuleID string) bool {
	var source platformscope.NormalizedRule
	found := false
	for _, include := range sc.IncludeRules() {
		if include.ID == sourceRuleID {
			source, found = include, true
			break
		}
	}
	if !found {
		return false
	}
	base, ok := narrowWildcardBase(source.Host)
	if !ok || base != root {
		return false
	}
	protocols, protocolsOK := finiteProtocols(source.Protocol)
	ports, portsOK := finitePorts(source.Port)
	path, pathOK := initialPath(source.File)
	if !protocolsOK || !portsOK || !pathOK {
		return false
	}
	for _, protocol := range protocols {
		for _, port := range ports {
			if discoveryCombinationAllowed(sc.ExcludeRules(), source, root, protocol, port, path) {
				return true
			}
		}
	}
	return false
}

func discoveryCombinationAllowed(exclusions []platformscope.NormalizedRule, source platformscope.NormalizedRule, root, protocol string, port int, path string) bool {
	portValue := strconv.Itoa(port)
	for _, exclusion := range exclusions {
		if !rulePatternMatches(exclusion.Protocol, protocol) || !rulePatternMatches(exclusion.Port, portValue) || !rulePatternMatches(exclusion.File, path) {
			continue
		}
		covers, provable := exclusionCoversDiscoveryHosts(exclusion.Host, source.Host, root)
		if !provable || covers {
			return false
		}
	}
	return true
}

func rulePatternMatches(pattern, value string) bool {
	compiled, err := regexp.Compile(pattern)
	return err == nil && full(compiled, value)
}

func exclusionCoversDiscoveryHosts(exclusionPattern, sourcePattern, sourceRoot string) (bool, bool) {
	if exclusionPattern == sourcePattern || exclusionPattern == ".*" || exclusionPattern == "^.*$" {
		return true, true
	}
	if _, exact := exactHost(exclusionPattern); exact {
		return false, true
	}
	if exclusionRoot, wildcard := narrowWildcardBase(exclusionPattern); wildcard {
		return sourceRoot == exclusionRoot || strings.HasSuffix(sourceRoot, "."+exclusionRoot), true
	}
	if exclusionRoot, optional := optionalWildcardBase(exclusionPattern); optional {
		return sourceRoot == exclusionRoot || strings.HasSuffix(sourceRoot, "."+exclusionRoot), true
	}
	return false, false
}

func optionalWildcardBase(pattern string) (string, bool) {
	body := strings.TrimPrefix(strings.TrimSuffix(pattern, "$"), "^")
	for _, prefix := range []string{`(?:.*\.)?`, `(?:[^.]+\.)?`} {
		if strings.HasPrefix(body, prefix) {
			return exactHost("^" + strings.TrimPrefix(body, prefix) + "$")
		}
	}
	return "", false
}

type FilterDecision struct {
	Target         string               `json:"target"`
	Accepted       bool                 `json:"accepted"`
	Reason         platformscope.Reason `json:"reason"`
	AuthorizedURLs []string             `json:"authorized_urls,omitempty"`
	SourceRuleIDs  []string             `json:"source_rule_ids,omitempty"`
}

type FilterResult struct {
	Authorized     []string         `json:"authorized"`
	AuthorizedURLs []string         `json:"authorized_urls"`
	Filtered       []FilterDecision `json:"filtered"`
	Decisions      []FilterDecision `json:"decisions"`
	AcceptedCount  int              `json:"accepted_count"`
	FilteredCount  int              `json:"filtered_count"`
}

func FilterDiscoveredHosts(sc DetailedScope, hosts []string) FilterResult {
	result := FilterResult{Authorized: []string{}, AuthorizedURLs: []string{}, Filtered: []FilterDecision{}, Decisions: []FilterDecision{}}
	seen := map[string]bool{}
	for _, raw := range hosts {
		host, err := normalizeHostname(raw)
		if err != nil {
			d := FilterDecision{Target: raw, Reason: platformscope.ReasonInvalidHostname}
			result.Filtered = append(result.Filtered, d)
			result.Decisions = append(result.Decisions, d)
			continue
		}
		if seen[host] {
			continue
		}
		seen[host] = true
		d := authorizeHost(sc, host)
		result.Decisions = append(result.Decisions, d)
		if d.Accepted {
			result.Authorized = append(result.Authorized, host)
			result.AuthorizedURLs = append(result.AuthorizedURLs, d.AuthorizedURLs...)
		} else {
			result.Filtered = append(result.Filtered, d)
		}
	}
	result.Authorized = uniqueStrings(result.Authorized)
	result.AuthorizedURLs = uniqueStrings(result.AuthorizedURLs)
	result.AcceptedCount, result.FilteredCount = len(result.Authorized), len(result.Filtered)
	return result
}

func FilterURLs(sc DetailedScope, targets []string) FilterResult {
	result := FilterResult{Authorized: []string{}, AuthorizedURLs: []string{}, Filtered: []FilterDecision{}, Decisions: []FilterDecision{}}
	seen := map[string]bool{}
	for _, raw := range targets {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			d := FilterDecision{Target: raw, Reason: platformscope.ReasonInvalidTarget}
			result.Filtered = append(result.Filtered, d)
			result.Decisions = append(result.Decisions, d)
			continue
		}
		normalized := u.String()
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		e := sc.Evaluate(normalized)
		d := FilterDecision{Target: normalized, Accepted: e.Allowed, Reason: e.Reason, SourceRuleIDs: e.MatchedIncludeIDs}
		result.Decisions = append(result.Decisions, d)
		if d.Accepted {
			result.Authorized = append(result.Authorized, normalized)
			result.AuthorizedURLs = append(result.AuthorizedURLs, normalized)
		} else {
			result.Filtered = append(result.Filtered, d)
		}
	}
	result.Authorized = uniqueStrings(result.Authorized)
	result.AuthorizedURLs = uniqueStrings(result.AuthorizedURLs)
	result.AcceptedCount, result.FilteredCount = len(result.Authorized), len(result.Filtered)
	return result
}

func authorizeHost(sc DetailedScope, host string) FilterDecision {
	d := FilterDecision{Target: host, Reason: platformscope.ReasonNoInclude}
	matchedHost := false
	matchedExclusion := false
	for _, r := range sc.IncludeRules() {
		hostRE, err := regexp.Compile(r.Host)
		if err != nil || !full(hostRE, host) {
			continue
		}
		matchedHost = true
		protocols, pok := finiteProtocols(r.Protocol)
		ports, ook := finitePorts(r.Port)
		path, pathOK := initialPath(r.File)
		if !pok || !ook || !pathOK {
			continue
		}
		for _, protocol := range protocols {
			for _, port := range ports {
				raw := endpointURL(protocol, host, port, path)
				e := sc.Evaluate(raw)
				if e.Allowed {
					d.AuthorizedURLs = appendUnique(d.AuthorizedURLs, raw)
					d.SourceRuleIDs = append(d.SourceRuleIDs, e.MatchedIncludeIDs...)
				} else if e.Reason == platformscope.ReasonExcluded {
					matchedExclusion = true
				}
			}
		}
	}
	if len(d.AuthorizedURLs) > 0 {
		d.Accepted = true
		d.Reason = platformscope.ReasonAllowed
		d.AuthorizedURLs = uniqueStrings(d.AuthorizedURLs)
		d.SourceRuleIDs = uniqueStrings(d.SourceRuleIDs)
		return d
	}
	if matchedExclusion {
		d.Reason = platformscope.ReasonExcluded
	} else if !matchedHost {
		d.Reason = platformscope.ReasonNoInclude
	}
	return d
}

func IsIPHost(raw string) bool { return net.ParseIP(strings.Trim(raw, "[]")) != nil }
func SortedUnique(items []string) []string {
	out := uniqueStrings(items)
	sort.Strings(out)
	return out
}
