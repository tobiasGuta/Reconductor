package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	commandprovider "github.com/tobiasGuta/Reconductor/internal/providers/command"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
)

type testScope struct{}

func (testScope) Allows(string) bool { return true }
func TestCompareAssetsStatusRouting(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	r := Registry(cfg)
	input := json.RawMessage(`{"current":["{\"url\":\"https://x.test/ok\",\"status_code\":200}","{\"url\":\"https://x.test/login\",\"status_code\":403}","{\"url\":\"https://x.test/missing\",\"status_code\":404}"],"previous":[],"coverage_complete":true,"target_plan_digest":"test-plan"}`)
	result, err := r.Execute(context.Background(), capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "compare.assets", Input: input}, Policy: policy.Policy{AllowedCapabilities: []string{"compare.assets"}}, Scope: testScope{}})
	if err != nil {
		t.Fatal(err)
	}
	var output struct {
		Crawl  []string            `json:"crawl_targets"`
		Scan   []string            `json:"scan_targets"`
		Routes map[string][]string `json:"status_routes"`
	}
	if err := json.Unmarshal(result.Action.Output, &output); err != nil {
		t.Fatal(err)
	}
	if len(output.Crawl) != 1 || len(output.Scan) != 2 || len(output.Routes["ignored"]) != 1 {
		t.Fatalf("unexpected routes: %s", result.Action.Output)
	}
}

func TestCompareAssetsPreservesHistoricalPlainWrappedAndStructuredObservations(t *testing.T) {
	tests := []struct {
		name     string
		current  []string
		previous []string
	}{
		{"plain URL", []string{"https://example.test/"}, []string{"https://example.test/"}},
		{"legacy value wrapper", []string{"https://example.test/"}, []string{`{"value":"https://example.test/"}`}},
		{"structured HTTPX JSON", []string{`{"url":"https://example.test/","status_code":200,"tech":["Go"]}`}, []string{`{"url":"https://example.test/","status_code":200,"tech":["Go"]}`}},
		{"normalized HTTPX record", []string{`{"provider":"httpx","kind":"url","target":"https://example.test/path","host":"example.test","status_code":200,"technologies":["Go"]}`}, []string{`{"provider":"httpx","kind":"url","target":"https://example.test/path","host":"example.test","status_code":200,"technologies":["Go"]}`}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, _ := json.Marshal(CompareAssetsInput{Current: test.current, Previous: test.previous, CoverageComplete: true, TargetPlanDigest: "plan"})
			result, _, err := executeCompareAssets(input)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.NewOrChanged) != 0 || len(result.Removed) != 0 || len(result.Changes) != 0 {
				t.Fatalf("unchanged observations were reported as changed: %#v", result)
			}
		})
	}
}

func TestCompareAssetsRejectsMalformedHistoricalValueWrappers(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(CompareAssetsInput{Current: []string{}, Previous: []string{`{"value":"not a url"}`}, CoverageComplete: true, TargetPlanDigest: "plan"})
	_, err = Registry(cfg).Execute(context.Background(), capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "compare.assets", Input: input}, Policy: policy.Policy{AllowedCapabilities: []string{"compare.assets"}}, Scope: testScope{}})
	if err == nil || !strings.Contains(err.Error(), "does not contain a valid HTTP URL") {
		t.Fatalf("malformed value wrapper was not rejected: %v", err)
	}
}

func TestInternalCapabilitiesPublishConcreteStrictSchemas(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := Registry(cfg)
	for _, name := range []string{"targeting.prepare", "compare.assets", "classify.endpoint", "report.changes"} {
		implementation, ok := registry.Get(name)
		if !ok {
			t.Fatalf("capability %s missing", name)
		}
		manifest := implementation.Manifest()
		for kind, raw := range map[string]json.RawMessage{"input": manifest.InputSchema, "output": manifest.OutputSchema} {
			if !json.Valid(raw) {
				t.Fatalf("%s %s schema is invalid JSON: %s", name, kind, raw)
			}
			var schema struct {
				AdditionalProperties *bool          `json:"additionalProperties"`
				Required             []string       `json:"required"`
				Properties           map[string]any `json:"properties"`
			}
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatal(err)
			}
			if schema.AdditionalProperties == nil || *schema.AdditionalProperties || len(schema.Required) == 0 || len(schema.Properties) == 0 {
				t.Fatalf("%s %s schema is not concrete and closed: %s", name, kind, raw)
			}
		}
	}
}

func TestInternalCapabilitiesRejectMalformedMissingAndUnexpectedInput(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := Registry(cfg)
	tests := []struct {
		name string
		raw  string
	}{
		{"targeting.prepare", `{"exact_urls":[],"discovered_urls":[],"ports":[],"target_plan_digest":"plan","command":"whoami"}`},
		{"targeting.prepare", `{"exact_urls":[],"discovered_urls":[],"ports":[70000],"target_plan_digest":"plan"}`},
		{"compare.assets", `{"current":"https://x.test","previous":[],"coverage_complete":true,"target_plan_digest":"plan"}`},
		{"compare.assets", `{"current":[],"previous":[],"coverage_complete":true}`},
		{"classify.endpoint", `{"active":[],"passive":[],"http_observations":[],"crawl_observations":[],"passive_observations":[],"historical_observations":[],"api_schema_endpoints":[],"target_plan_digest":"plan","command":"whoami"}`},
		{"classify.endpoint", `{"active":["not a url"],"passive":[],"http_observations":[],"crawl_observations":[],"passive_observations":[],"historical_observations":[],"api_schema_endpoints":[],"target_plan_digest":"plan"}`},
		{"report.changes", `{"changes":[{"kind":"new_or_changed"}],"endpoints":[],"candidate_matches":[],"target_plan_digest":"plan"}`},
		{"report.changes", `{"changes":[{"kind":"invented","value":"https://x.test/"}],"endpoints":[],"candidate_matches":[],"target_plan_digest":"plan"}`},
		{"report.changes", `{"changes":[],"endpoints":[{"endpoint":{"exact_url":"https://x.test/"},"matched_keywords":["api"]}],"candidate_matches":[],"target_plan_digest":"plan"}`},
		{"report.changes", `{"changes":[],"endpoints":[],"candidate_matches":[{}],"target_plan_digest":"plan"}`},
	}
	for _, test := range tests {
		t.Run(test.name+"/"+test.raw, func(t *testing.T) {
			if err := registry.ValidateDefinitionInput(test.name, json.RawMessage(test.raw)); err == nil {
				t.Fatal("invalid input was accepted")
			}
		})
	}
}

func TestInternalCapabilityValidDefinitionContracts(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := Registry(cfg)
	valid := map[string]string{
		"targeting.prepare": `{"exact_urls":[],"discovered_urls":[],"ports":[],"target_plan_digest":"plan"}`,
		"compare.assets":    `{"current":[],"previous":[],"coverage_complete":false,"target_plan_digest":"plan"}`,
		"classify.endpoint": `{"active":[],"passive":[],"http_observations":[],"crawl_observations":[],"passive_observations":[],"historical_observations":[],"api_schema_endpoints":[],"target_plan_digest":"plan"}`,
		"report.changes":    `{"changes":[],"endpoints":[],"candidate_matches":[],"target_plan_digest":"plan"}`,
	}
	for name, raw := range valid {
		if err := registry.ValidateDefinitionInput(name, json.RawMessage(raw)); err != nil {
			t.Fatalf("%s valid input rejected: %v", name, err)
		}
	}
}

func TestInternalCapabilitiesEmitTypedNonNullOutputs(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := Registry(cfg)
	scope, err := platformscope.Compile([]platformscope.Rule{{Protocol: `^https$`, Host: `^x\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		input string
		out   any
	}{
		{"targeting.prepare", `{"exact_urls":["https://x.test/"],"discovered_urls":[],"ports":[443],"target_plan_digest":"plan"}`, &TargetingPrepareOutput{}},
		{"compare.assets", `{"current":["{\"url\":\"https://x.test/\",\"status_code\":200}"],"previous":[],"coverage_complete":true,"target_plan_digest":"plan"}`, &CompareAssetsOutput{}},
		{"classify.endpoint", `{"active":["https://x.test/api/1"],"passive":[],"http_observations":[],"crawl_observations":[],"passive_observations":[],"historical_observations":[],"api_schema_endpoints":[],"target_plan_digest":"plan"}`, &ClassifyEndpointOutput{}},
		{"report.changes", `{"changes":[],"endpoints":[],"candidate_matches":[],"target_plan_digest":"plan"}`, &ReportChangesOutput{}},
	}
	for _, test := range tests {
		result, err := registry.Execute(context.Background(), capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: test.name, Input: json.RawMessage(test.input)}, Policy: policy.Policy{AllowedCapabilities: []string{test.name}}, Scope: scope})
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if strings.Contains(string(result.Action.Output), ":null") {
			t.Fatalf("%s emitted null collection: %s", test.name, result.Action.Output)
		}
		if err := json.Unmarshal(result.Action.Output, test.out); err != nil {
			t.Fatalf("%s output contract: %v", test.name, err)
		}
	}
}

func TestDNSxInvocationUsesSortedDeduplicatedHostnameStdin(t *testing.T) {
	invocation, err := dnsxInvocation(commandprovider.Input{Targets: []string{"https://Z.Example.Test./path?q=1#fragment", "http://a.example.test:8080/other", "https://A.EXAMPLE.TEST/", "http://192.0.2.1/path", "https://[2001:db8::1]/v1"}}, policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(invocation.Args, " "), "-silent"; got != want {
		t.Fatalf("args=%q", got)
	}
	if strings.Contains(strings.Join(invocation.Args, " "), "-d") {
		t.Fatalf("dnsx received brute-force flag: %v", invocation.Args)
	}
	if got, want := string(invocation.Stdin), "192.0.2.1\n2001:db8::1\na.example.test\nz.example.test\n"; got != want {
		t.Fatalf("stdin=%q want=%q", got, want)
	}
}

func TestAuditedProviderFlagMatrix(t *testing.T) {
	input := commandprovider.Input{Domains: []string{"example.test"}, Targets: []string{"https://app.example.test/path"}, Ports: "80,443", Headless: true}
	recon := config.Recon{RateLimit: 75, Concurrency: 20}
	pol := policy.Policy{RateLimit: 20, Concurrency: 5}
	nuclei := config.Nuclei{RateLimit: 50, HostConcurrency: 10, TemplateConcurrency: 10, HeadlessConcurrency: 2, Severity: []string{"low", "medium", "high", "critical"}, IncludeTags: []string{"cve", "exposure", "misconfig"}, ExcludeTags: []string{"dos", "fuzz", "bruteforce", "intrusive"}, TemplateDirectory: `C:\nuclei-templates`}
	tests := []struct {
		name  string
		want  string
		build func() ([]string, error)
	}{
		{"subfinder", "-d example.test -silent", func() ([]string, error) { return subfinderArgs(input, pol) }},
		{"chaos", "-d example.test -silent", func() ([]string, error) { return chaosArgs(input, "configured") }},
		{"naabu", "-host app.example.test -silent -rate 20 -p 80,443", func() ([]string, error) { return naabuArgs(input, pol, recon) }},
		{"katana", "-u https://app.example.test/path -silent -jsonl -fs fqdn -rate-limit 20 -concurrency 5 -headless", func() ([]string, error) { return katanaArgs(input, pol, recon) }},
		{"gau", "--json example.test", func() ([]string, error) { return gauArgs(input) }},
		{"nuclei", `-u https://app.example.test/path -jsonl -silent -dr -rl 20 -c 5 -bulk-size 5 -headc 2 -severity low,medium,high,critical -tags cve,exposure,misconfig -etags dos,fuzz,bruteforce,intrusive -t C:\nuclei-templates`, func() ([]string, error) { return nucleiArgs(input, pol, nuclei) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args, err := test.build()
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(args, " "); got != test.want {
				t.Fatalf("args=%q want=%q", got, test.want)
			}
		})
	}
	httpx, err := httpxInvocation(input, pol, recon)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(httpx.Args, " "), "-silent -json -status-code -content-type -location -tech-detect -threads 5"; got != want {
		t.Fatalf("httpx args=%q want=%q", got, want)
	}
	if got, want := string(httpx.Stdin), "https://app.example.test/path\n"; got != want {
		t.Fatalf("httpx stdin=%q want=%q", got, want)
	}
	invocation, err := dnsxInvocation(input, pol)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(invocation.Args, " "); got != "-silent" || string(invocation.Stdin) != "app.example.test\n" {
		t.Fatalf("dnsx args=%q stdin=%q", got, invocation.Stdin)
	}
}

func TestHTTPXInvocationUsesNewlineDelimitedTargetStdin(t *testing.T) {
	targets := []string{
		"https://app.example.test/path?view=full",
		"http://api.example.test:8080/v1/items?id=42",
		"https://[2001:db8::1]:8443/a/b?x=1&y=2",
	}
	invocation, err := httpxInvocation(commandprovider.Input{Targets: targets}, policy.Policy{Concurrency: 5}, config.Recon{Concurrency: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range invocation.Args {
		if arg == "-u" {
			t.Fatalf("HTTPX target flag appeared in args: %v", invocation.Args)
		}
	}
	wantStdin := strings.Join(targets, "\n") + "\n"
	if got := string(invocation.Stdin); got != wantStdin {
		t.Fatalf("stdin=%q want=%q", got, wantStdin)
	}
	if !strings.HasSuffix(string(invocation.Stdin), "\n") {
		t.Fatalf("stdin does not end in a newline: %q", invocation.Stdin)
	}
	lines := strings.Split(strings.TrimSuffix(string(invocation.Stdin), "\n"), "\n")
	if len(lines) != len(targets) {
		t.Fatalf("stdin lines=%d want=%d", len(lines), len(targets))
	}
	for i, target := range targets {
		if lines[i] != target {
			t.Fatalf("stdin line %d=%q want=%q", i, lines[i], target)
		}
	}
}

func TestHTTPXInvocationKeepsLargeTargetListsOffCommandLine(t *testing.T) {
	targets := make([]string, 5000)
	for i := range targets {
		targets[i] = fmt.Sprintf("https://host-%04d.example.test:8443/path/%d?source=regression", i, i)
	}
	invocation, err := httpxInvocation(commandprovider.Input{Targets: targets}, policy.Policy{Concurrency: 5}, config.Recon{Concurrency: 20})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(invocation.Args), 8; got != want {
		t.Fatalf("args=%d want=%d", got, want)
	}
	if len(invocation.Stdin) == 0 {
		t.Fatal("HTTPX stdin is empty")
	}
	if got, want := string(invocation.Stdin), strings.Join(targets, "\n")+"\n"; got != want {
		t.Fatalf("HTTPX stdin did not contain the complete target list: bytes=%d want=%d", len(got), len(want))
	}
}

func TestHTTPXInvocationRejectsEmptyTargets(t *testing.T) {
	_, err := httpxInvocation(commandprovider.Input{}, policy.Policy{}, config.Recon{})
	if err == nil || err.Error() != "targets are required" {
		t.Fatalf("err=%v want=%q", err, "targets are required")
	}
}

func TestHostConcurrencyBudgetReachesHostAwareProviders(t *testing.T) {
	input := commandprovider.Input{Targets: []string{"https://app.example.test/path"}}
	recon := config.Recon{RateLimit: 75, Concurrency: 20}
	pol := policy.Policy{RateLimit: 20, Concurrency: 8, HostConcurrency: 2}
	nuclei := config.Nuclei{RateLimit: 50, HostConcurrency: 10, TemplateConcurrency: 10, HeadlessConcurrency: 2, Severity: []string{"low"}, IncludeTags: []string{"cve"}, ExcludeTags: []string{"dos"}}
	katana, err := katanaArgs(input, pol, recon)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(katana, " "); !strings.Contains(got, "-concurrency 2") {
		t.Fatalf("Katana did not receive host budget: %s", got)
	}
	nucleiFlags, err := nucleiArgs(input, pol, nuclei)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(nucleiFlags, " "); !strings.Contains(got, "-bulk-size 2") {
		t.Fatalf("Nuclei did not receive host budget: %s", got)
	}
}

func TestDNSxInvocationRejectsInvalidURLAndKeepsLargeListsOffCommandLine(t *testing.T) {
	if _, err := dnsxInvocation(commandprovider.Input{Targets: []string{"not-a-url"}}, policy.Policy{}); err == nil {
		t.Fatal("invalid URL accepted")
	}
	targets := make([]string, 5000)
	for i := range targets {
		targets[i] = fmt.Sprintf("https://host-%04d.example.test/path", i)
	}
	invocation, err := dnsxInvocation(commandprovider.Input{Targets: targets}, policy.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if len(invocation.Args) != 1 || len(invocation.Stdin) < 100000 {
		t.Fatalf("large list was not transported through stdin: args=%d stdin=%d", len(invocation.Args), len(invocation.Stdin))
	}
}

type denyScope struct{}

func (denyScope) Allows(string) bool { return false }

func TestDNSxValidationStillRejectsOutOfScopeURLs(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	capabilityImpl, ok := Registry(cfg).Get("resolve.dns")
	if !ok {
		t.Fatal("resolve.dns missing")
	}
	raw, _ := json.Marshal(commandprovider.Input{Targets: []string{"https://outside.example.test/"}})
	req := capability.Request{Action: domain.ActionRequest{Capability: "resolve.dns", Input: raw}, Policy: policy.Policy{AllowedCapabilities: []string{"resolve.dns"}}, Scope: denyScope{}}
	if err := capabilityImpl.Validate(context.Background(), req); err == nil {
		t.Fatal("out-of-scope DNS target accepted")
	}
}
