package workflows

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

const (
	ContinuousName = "continuous-web-recon"
	BaselineName   = "authorized-web-baseline"
)

func Build(name string, plan targeting.TargetPlan, headless bool) (workflow.Definition, error) {
	switch name {
	case "", ContinuousName:
		if !plan.HasExecutableTargets() {
			return workflow.Definition{}, fmt.Errorf("target plan has no executable authorized targets")
		}
		return ContinuousWebRecon(plan, headless), nil
	case BaselineName:
		if len(plan.ExactActiveSeeds) == 0 {
			return workflow.Definition{}, fmt.Errorf("authorized-web-baseline requires at least one exact active seed")
		}
		return AuthorizedWebBaseline(plan, headless), nil
	default:
		return workflow.Definition{}, fmt.Errorf("unknown workflow %q", name)
	}
}

func ContinuousWebRecon(plan targeting.TargetPlan, headless bool) workflow.Definition {
	return webReconDefinition(domain.ID("d0e5e6a3-bd8a-4b4b-a76b-f6452c30179a"), ContinuousName, "2.2.0", "Scope-driven continuous web reconnaissance with preliminary briefs and optional scanner enrichment", plan, headless, true)
}

func AuthorizedWebBaseline(plan targeting.TargetPlan, headless bool) workflow.Definition {
	return webReconDefinition(domain.ID("c9479711-b203-4fe1-8528-718888e5a5d2"), BaselineName, "1.2.0", "Scope-derived exact-seed authorized web baseline with preliminary briefs and optional scanner enrichment", plan, headless, false)
}

func webReconDefinition(id domain.ID, name, version, description string, plan targeting.TargetPlan, headless, allowDiscovery bool) workflow.Definition {
	policyRequirements := json.RawMessage(`{"forbid":["dos","bruteforce","credential-stuffing","state-changing"],"moderate_requires_approval":true}`)
	steps := []workflow.Step{}
	prepare := workflow.Step{ID: "prepare-authorized-targets", Capability: "targeting.prepare", Input: raw(map[string]any{"exact_urls": plan.InitialURLs(), "discovered_urls": []string{}, "ports": commonPorts(plan), "target_plan_digest": plan.Digest}), Retry: retry(), Timeout: time.Minute}
	if allowDiscovery && len(plan.DiscoveryRoots) > 0 {
		steps = append(steps, workflow.Step{ID: "discover-subdomains", Capability: "discover.subdomains", Provider: "subfinder", Input: raw(map[string]any{"domains": plan.DiscoveryDomains(), "target_plan_digest": plan.Digest}), Retry: retry(), Timeout: 15 * time.Minute})
		prepare.DependsOn = []string{"discover-subdomains"}
		prepare.Bindings = map[string]string{"discovered_urls": "discover-subdomains.output.authorized_urls"}
	}
	steps = append(steps, prepare)
	steps = append(steps, workflow.Step{ID: "resolve-dns", Capability: "resolve.dns", Provider: "dnsx", DependsOn: []string{prepare.ID}, Input: raw(map[string]any{"targets": []string{}, "target_plan_digest": plan.Digest}), Bindings: map[string]string{"targets": prepare.ID + ".output.urls"}, Retry: retry(), Timeout: 10 * time.Minute})
	probeDeps := []string{"resolve-dns"}
	ports := commonPorts(plan)
	if len(ports) > 0 {
		steps = append(steps, workflow.Step{ID: "scan-ports", Capability: "scan.ports", Provider: "naabu", DependsOn: []string{"resolve-dns"}, Condition: "nonempty:" + prepare.ID + ".output.port_targets", Input: raw(map[string]any{"targets": []string{}, "ports": joinPorts(ports), "target_plan_digest": plan.Digest}), Bindings: map[string]string{"targets": prepare.ID + ".output.port_targets"}, Retry: retry(), Timeout: 20 * time.Minute})
		probeDeps = append(probeDeps, "scan-ports")
	}
	steps = append(steps,
		workflow.Step{ID: "probe-http", Capability: "probe.http", Provider: "httpx", DependsOn: probeDeps, Input: raw(map[string]any{"targets": []string{}, "target_plan_digest": plan.Digest}), Bindings: map[string]string{"targets": prepare.ID + ".output.urls"}, Retry: retry(), Timeout: 15 * time.Minute},
		workflow.Step{ID: "compare-assets", Capability: "compare.assets", DependsOn: []string{"probe-http"}, Input: raw(map[string]any{"current": []string{}, "previous": []string{}, "coverage_complete": true, "target_plan_digest": plan.Digest}), Bindings: map[string]string{"current": "probe-http.output.authorized_records"}, Retry: retry(), Timeout: time.Minute},
		workflow.Step{ID: "crawl-new-or-changed-web-assets", Capability: "crawl.web", Provider: "katana", DependsOn: []string{"compare-assets"}, Condition: "nonempty:compare-assets.output.crawl_targets", Input: raw(map[string]any{"targets": []string{}, "headless": headless, "target_plan_digest": plan.Digest}), Bindings: map[string]string{"targets": "compare-assets.output.crawl_targets"}, Retry: retry(), Timeout: 30 * time.Minute},
	)
	classifyDeps := []string{"crawl-new-or-changed-web-assets"}
	classifyBindings := map[string]string{
		"http_observations":  "probe-http.output.authorized_records",
		"crawl_observations": "crawl-new-or-changed-web-assets.output.authorized_records",
	}
	if allowDiscovery && len(plan.DiscoveryRoots) > 0 {
		steps = append(steps, workflow.Step{ID: "discover-archive-urls", Capability: "discover.archive_urls", Provider: "gau", DependsOn: []string{"prepare-authorized-targets"}, Input: raw(map[string]any{"domains": plan.DiscoveryDomains(), "target_plan_digest": plan.Digest}), Retry: retry(), Timeout: 15 * time.Minute})
		classifyDeps = append(classifyDeps, "discover-archive-urls")
		classifyBindings["passive_observations"] = "discover-archive-urls.output.authorized_records"
	}
	steps = append(steps,
		workflow.Step{ID: "classify-interesting-endpoints", Capability: "classify.endpoint", DependsOn: classifyDeps, Input: raw(map[string]any{"active": []string{}, "passive": []string{}, "http_observations": []any{}, "crawl_observations": []any{}, "passive_observations": []any{}, "historical_observations": []any{}, "api_schema_endpoints": []string{}, "target_plan_digest": plan.Digest}), Bindings: classifyBindings, Retry: retry(), Timeout: time.Minute},
		workflow.Step{ID: "generate-recon-brief", Capability: "report.changes", DependsOn: []string{"classify-interesting-endpoints"}, Input: raw(map[string]any{"changes": []any{}, "endpoints": []any{}, "candidate_matches": []any{}, "target_plan_digest": plan.Digest}), Bindings: map[string]string{"changes": "compare-assets.output.changes", "endpoints": "classify-interesting-endpoints.output.interesting_endpoints"}, Retry: retry(), Timeout: time.Minute},
		workflow.Step{ID: "run-safe-nuclei-profile", Capability: "scan.nuclei", Provider: "nuclei", DependsOn: []string{"classify-interesting-endpoints"}, Condition: "nonempty:compare-assets.output.scan_targets", Input: raw(map[string]any{"targets": []string{}, "target_plan_digest": plan.Digest}), Bindings: map[string]string{"targets": "compare-assets.output.scan_targets"}, Retry: workflow.RetryPolicy{MaxAttempts: 2, BaseDelay: 5 * time.Second}, Timeout: 45 * time.Minute, ApprovalRequired: true},
		workflow.Step{ID: "enrich-recon-brief", Capability: "report.changes", DependsOn: []string{"generate-recon-brief", "run-safe-nuclei-profile"}, Input: raw(map[string]any{"changes": []any{}, "endpoints": []any{}, "candidate_matches": []any{}, "target_plan_digest": plan.Digest}), Bindings: map[string]string{"changes": "compare-assets.output.changes", "endpoints": "classify-interesting-endpoints.output.interesting_endpoints", "candidate_matches": "run-safe-nuclei-profile.output.lines"}, Retry: retry(), Timeout: time.Minute},
	)
	return workflow.Definition{ID: id, Name: name, Version: version, Description: description, DefaultPolicyRequirements: policyRequirements, CreatedAt: time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC), Steps: steps}
}

func commonPorts(plan targeting.TargetPlan) []int {
	groups := [][]int{}
	for _, seed := range plan.ExactActiveSeeds {
		ports := []int{}
		for _, endpoint := range seed.Endpoints {
			if !containsPort(ports, endpoint.Port) {
				ports = append(ports, endpoint.Port)
			}
		}
		if len(ports) > 0 {
			groups = append(groups, ports)
		}
	}
	wildcardGroups := map[string][]int{}
	for _, rule := range plan.WildcardRules {
		key := rule.HostPattern + "\x00" + rule.PathPattern
		for _, port := range rule.Ports {
			if !containsPort(wildcardGroups[key], port) {
				wildcardGroups[key] = append(wildcardGroups[key], port)
			}
		}
	}
	for _, ports := range wildcardGroups {
		if len(ports) > 0 {
			groups = append(groups, ports)
		}
	}
	if len(groups) == 0 {
		return nil
	}
	result := append([]int{}, groups[0]...)
	for _, group := range groups[1:] {
		kept := result[:0]
		for _, port := range result {
			if containsPort(group, port) {
				kept = append(kept, port)
			}
		}
		result = kept
	}
	sort.Ints(result)
	return result
}
func containsPort(items []int, value int) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
func joinPorts(ports []int) string {
	values := make([]string, len(ports))
	for i, port := range ports {
		values[i] = strconv.Itoa(port)
	}
	return strings.Join(values, ",")
}
func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func retry() workflow.RetryPolicy {
	return workflow.RetryPolicy{MaxAttempts: 3, BaseDelay: 2 * time.Second}
}
