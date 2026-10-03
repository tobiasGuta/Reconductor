package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	commandprovider "github.com/tobiasGuta/Reconductor/internal/providers/command"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
)

type testScope struct{}

func (testScope) Allows(string) bool { return true }

type providerTestProvenanceRecorder struct{}

func (providerTestProvenanceRecorder) RecordPolicyDecision(context.Context, capability.PolicyDecisionRecord) (domain.ID, error) {
	return domain.NewID(), nil
}
func (providerTestProvenanceRecorder) RecordProviderInvocationStarted(context.Context, capability.ProviderInvocationStartRecord) (domain.ID, error) {
	return domain.NewID(), nil
}
func (providerTestProvenanceRecorder) RecordProviderInvocationTerminal(context.Context, capability.ProviderInvocationTerminalRecord) error {
	return nil
}

func executeProviderTest(registry *capability.Registry, req capability.Request) (capability.Result, error) {
	recorder := providerTestProvenanceRecorder{}
	req.DecisionRecorder = recorder
	req.InvocationRecorder = recorder
	return registry.Execute(context.Background(), req)
}

type passiveAdmissionRecorder struct{ starts int }

func (*passiveAdmissionRecorder) RecordPolicyDecision(context.Context, capability.PolicyDecisionRecord) (domain.ID, error) {
	return domain.NewID(), nil
}
func (r *passiveAdmissionRecorder) RecordProviderInvocationStarted(context.Context, capability.ProviderInvocationStartRecord) (domain.ID, error) {
	r.starts++
	return domain.NewID(), nil
}
func (*passiveAdmissionRecorder) RecordProviderInvocationTerminal(context.Context, capability.ProviderInvocationTerminalRecord) error {
	return nil
}

type passiveCommandRunner struct {
	calls  int
	args   []string
	stdout string
}

func (r *passiveCommandRunner) Run(_ context.Context, _ string, args []string, _ []byte) ([]byte, []byte, int, error) {
	r.calls++
	r.args = append([]string(nil), args...)
	return []byte(r.stdout), nil, 0, nil
}
func (*passiveCommandRunner) Version(context.Context, string, []string) (string, error) {
	return "2.0.0", nil
}

func TestPassiveDiscoveryAdmissionUsesCurrentExclusionAwareScopeForSubfinderAndGAU(t *testing.T) {
	wildcardA := platformscope.Rule{Protocol: `^https$`, Host: `^.*\.example\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}
	wildcardB := platformscope.Rule{Protocol: `^https$`, Host: `^[^.]+\.example\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}
	unrelatedExact := platformscope.Rule{Protocol: `^https$`, Host: `^example\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}
	tests := []struct {
		name             string
		originalIncludes []platformscope.Rule
		currentIncludes  []platformscope.Rule
		currentExcludes  []platformscope.Rule
		originalManual   []targeting.ManualDiscoveryRoot
		currentManual    []targeting.ManualDiscoveryRoot
		wantRun          bool
	}{
		{name: "original generating rule remains", originalIncludes: []platformscope.Rule{wildcardA}, currentIncludes: []platformscope.Rule{wildcardA}, wantRun: true},
		{name: "original generating rule removed", originalIncludes: []platformscope.Rule{wildcardA}, currentIncludes: []platformscope.Rule{{Protocol: `^https$`, Host: `^api\.other\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}}},
		{name: "original generating rule fully excluded", originalIncludes: []platformscope.Rule{wildcardA}, currentIncludes: []platformscope.Rule{wildcardA}, currentExcludes: []platformscope.Rule{wildcardA}},
		{name: "broader exclusion fully vetoes original basis", originalIncludes: []platformscope.Rule{wildcardA}, currentIncludes: []platformscope.Rule{wildcardA}, currentExcludes: []platformscope.Rule{{Protocol: `^https$`, Host: `^.*\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}}},
		{name: "unrelated exact include cannot launder vetoed basis", originalIncludes: []platformscope.Rule{wildcardA}, currentIncludes: []platformscope.Rule{wildcardA, unrelatedExact}, currentExcludes: []platformscope.Rule{wildcardA}},
		{name: "unrelated wildcard cannot launder vetoed basis", originalIncludes: []platformscope.Rule{wildcardA}, currentIncludes: []platformscope.Rule{wildcardA, wildcardB}, currentExcludes: []platformscope.Rule{wildcardA}},
		{name: "current only same-root rule cannot substitute authority", originalIncludes: []platformscope.Rule{wildcardA}, currentIncludes: []platformscope.Rule{wildcardB}},
		{name: "partial exclusion leaves original basis provable", originalIncludes: []platformscope.Rule{wildcardA}, currentIncludes: []platformscope.Rule{wildcardA}, currentExcludes: []platformscope.Rule{{Protocol: `^https$`, Host: `^blocked\.example\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}}, wantRun: true},
		{name: "synthetic-label-only exclusion does not veto original basis", originalIncludes: []platformscope.Rule{wildcardA}, currentIncludes: []platformscope.Rule{wildcardA}, currentExcludes: []platformscope.Rule{{Protocol: `^https$`, Host: `^reconductor-discovery-probe\.example\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}}, wantRun: true},
		{name: "one of multiple original source rules remains", originalIncludes: []platformscope.Rule{wildcardA, wildcardB}, currentIncludes: []platformscope.Rule{wildcardB}, wantRun: true},
		{name: "finite path basis remains constrained", originalIncludes: []platformscope.Rule{{Protocol: `^https$`, Host: wildcardA.Host, Port: `^443$`, File: `^/admin$`, Enabled: true}}, currentIncludes: []platformscope.Rule{{Protocol: `^https$`, Host: wildcardA.Host, Port: `^443$`, File: `^/admin$`, Enabled: true}}, wantRun: true},
		{name: "non-enumerable path basis fails closed", originalIncludes: []platformscope.Rule{{Protocol: `^https$`, Host: wildcardA.Host, Port: `^443$`, File: `^/admin/.*`, Enabled: true}}, currentIncludes: []platformscope.Rule{{Protocol: `^https$`, Host: wildcardA.Host, Port: `^443$`, File: `^/admin/.*`, Enabled: true}}},
		{name: "manual semantic basis remains", originalIncludes: []platformscope.Rule{unrelatedExact}, currentIncludes: []platformscope.Rule{unrelatedExact}, originalManual: []targeting.ManualDiscoveryRoot{{Domain: "example.test", Reason: "authorized passive root"}}, currentManual: []targeting.ManualDiscoveryRoot{{Domain: "example.test", Reason: "authorized passive root"}}, wantRun: true},
		{name: "changed manual reason cannot substitute basis", originalIncludes: []platformscope.Rule{unrelatedExact}, currentIncludes: []platformscope.Rule{unrelatedExact}, originalManual: []targeting.ManualDiscoveryRoot{{Domain: "example.test", Reason: "authorized passive root"}}, currentManual: []targeting.ManualDiscoveryRoot{{Domain: "example.test", Reason: "different authority"}}},
	}
	providers := []struct {
		name        string
		provider    string
		adapter     string
		stdout      string
		build       func(commandprovider.Input, policy.Policy) ([]string, error)
		wantArgs    []string
		wrapAsMulti bool
	}{
		{name: "subfinder", provider: "subfinder", adapter: "subfinder", stdout: "www.example.test\n", build: subfinderArgs, wantArgs: []string{"-d", "example.test", "-silent"}, wrapAsMulti: true},
		{name: "gau", provider: "gau", adapter: "gau", stdout: "https://www.example.test/\n", build: func(input commandprovider.Input, _ policy.Policy) ([]string, error) { return gauArgs(input) }, wantArgs: []string{"--json", "example.test"}},
	}
	for _, providerTest := range providers {
		providerTest := providerTest
		for _, test := range tests {
			t.Run(providerTest.name+"/"+test.name, func(t *testing.T) {
				originalScope, err := platformscope.Compile(test.originalIncludes, nil)
				if err != nil {
					t.Fatal(err)
				}
				originalPlan, err := targeting.Plan(originalScope, test.originalManual)
				if err != nil {
					t.Fatal(err)
				}
				currentScope, err := platformscope.Compile(test.currentIncludes, test.currentExcludes)
				if err != nil {
					t.Fatal(err)
				}
				currentPlan, err := targeting.Plan(currentScope, test.currentManual)
				if err != nil {
					t.Fatal(err)
				}
				runner := &passiveCommandRunner{stdout: providerTest.stdout}
				implementation := commandprovider.New(commandprovider.Definition{Name: map[bool]string{true: "discover.subdomains", false: "discover.archive_urls"}[providerTest.wrapAsMulti], Provider: providerTest.provider, Executable: providerTest.provider, Version: "2", Risk: policy.Passive, ScopeType: "discovery-root", RetrySafe: true, Idempotent: true, PassiveInput: true, OutputAdapter: providerTest.adapter, BuildArgs: providerTest.build}, runner, nil)
				var registered capability.Capability = implementation
				if providerTest.wrapAsMulti {
					registered, err = capability.NewMulti("subfinder", map[string]capability.Capability{"subfinder": implementation})
					if err != nil {
						t.Fatal(err)
					}
				}
				registry := capability.NewRegistry()
				if err := registry.Register(registered); err != nil {
					t.Fatal(err)
				}
				capabilityName := registered.Manifest().Name
				raw, err := json.Marshal(commandprovider.Input{Domains: []string{"example.test"}})
				if err != nil {
					t.Fatal(err)
				}
				recorder := &passiveAdmissionRecorder{}
				_, executeErr := registry.Execute(context.Background(), capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), RequestedBy: "test", Capability: capabilityName, Input: raw, StepAttempt: 1}, Provider: providerTest.provider, Policy: policy.Policy{ID: "passive-admission", AllowedCapabilities: []string{capabilityName}}, Scope: targeting.WithDiscoveryRoots(currentScope, originalPlan.DiscoveryRoots, currentPlan.DiscoveryRoots), DecisionRecorder: recorder, InvocationRecorder: recorder})
				if !test.wantRun {
					if executeErr == nil || recorder.starts != 0 || runner.calls != 0 || len(runner.args) != 0 {
						t.Fatalf("error=%v provider_starts=%d runner_calls=%d args=%v", executeErr, recorder.starts, runner.calls, runner.args)
					}
					return
				}
				if executeErr != nil || recorder.starts != 1 || runner.calls != 1 || !slices.Equal(runner.args, providerTest.wantArgs) {
					t.Fatalf("error=%v provider_starts=%d runner_calls=%d args=%v want=%v", executeErr, recorder.starts, runner.calls, runner.args, providerTest.wantArgs)
				}
			})
		}
	}
}

func TestEndpointClassifierVersionAndStableSchemas(t *testing.T) {
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
	classifier, ok := registry.Get("classify.endpoint")
	if !ok {
		t.Fatal("classify.endpoint capability is missing")
	}
	classifierManifest := classifier.Manifest()
	if classifierManifest.Version != "5" {
		t.Fatalf("classify.endpoint version=%q want=5", classifierManifest.Version)
	}
	if strings.Contains(string(classifierManifest.OutputSchema), "origin_scheme") || strings.Contains(string(classifierManifest.OutputSchema), "origin_host") || strings.Contains(string(classifierManifest.OutputSchema), "origin_effective_port") {
		t.Fatalf("classify.endpoint serialized origin fields changed: %s", classifierManifest.OutputSchema)
	}
	reporter, ok := registry.Get("report.changes")
	if !ok {
		t.Fatal("report.changes capability is missing")
	}
	if got := reporter.Manifest().Version; got != "3" {
		t.Fatalf("report.changes version=%q want=3", got)
	}
}

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
	input := json.RawMessage(`{
		"current":[
			{"provider":"httpx","kind":"url","target":"http://127.0.0.1:33000/","host":"127.0.0.1","port":33000,"status_code":200},
			{"provider":"httpx","kind":"url","target":"https://x.test/moved","status_code":302},
			{"provider":"httpx","kind":"url","target":"https://x.test/login","status_code":401},
			{"provider":"httpx","kind":"url","target":"https://x.test/missing","status_code":404}
		],
		"previous":[],
		"coverage_complete":true,
		"target_plan_digest":"test-plan"
	}`)
	result, err := executeProviderTest(r, capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "compare.assets", Input: input}, Policy: policy.Policy{AllowedCapabilities: []string{"compare.assets"}}, Scope: testScope{}})
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
	if got, want := strings.Join(output.Routes["active"], ","), "http://127.0.0.1:33000/"; got != want {
		t.Fatalf("active=%q want=%q", got, want)
	}
	if got, want := strings.Join(output.Routes["redirects"], ","), "https://x.test/moved"; got != want {
		t.Fatalf("redirects=%q want=%q", got, want)
	}
	if got, want := strings.Join(output.Routes["authentication"], ","), "https://x.test/login"; got != want {
		t.Fatalf("authentication=%q want=%q", got, want)
	}
	if got, want := strings.Join(output.Routes["ignored"], ","), "https://x.test/missing"; got != want {
		t.Fatalf("ignored=%q want=%q", got, want)
	}
	if got, want := strings.Join(output.Crawl, ","), "http://127.0.0.1:33000/"; got != want {
		t.Fatalf("crawl_targets=%q want=%q", got, want)
	}
	if got, want := strings.Join(output.Scan, ","), "http://127.0.0.1:33000/,https://x.test/moved,https://x.test/login"; got != want {
		t.Fatalf("scan_targets=%q want=%q", got, want)
	}
}

func TestInternalProviderOverBudgetIsRejectedByRegistry(t *testing.T) {
	cfg, err := config.LoadWith(func(k string) string {
		if k == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := platformscope.Compile([]platformscope.Rule{{Protocol: `^http$`, Host: `^127\.0\.0\.1$`, Port: `^8080$`, File: `^/.*`, Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	urls := make([]string, 500)
	for i := range urls {
		urls[i] = fmt.Sprintf("http://127.0.0.1:8080/resource/%06d/%s", i, strings.Repeat("x", 64))
	}
	input, err := json.Marshal(TargetingPrepareInput{ExactURLs: urls, DiscoveredURLs: []string{}, Ports: []int{8080}, TargetPlanDigest: "internal-output-limit"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := executeProviderTest(Registry(cfg), capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "targeting.prepare", Input: input}, Policy: policy.Policy{AllowedCapabilities: []string{"targeting.prepare"}}, Scope: sc})
	if err == nil || result.Action.Error == nil || result.Action.Error.Classification != "result_contract_limit" || result.Action.Error.Retryable || len(result.Action.Output) != 0 || result.OutputLimit == nil || result.OutputLimit.Limit != domain.ResultEnvelopeMaxBytes {
		t.Fatalf("result=%#v error=%v input_bytes=%d", result, err, len(input))
	}
}

func TestCompareAssetsRejectsMalformedStructuredCurrentObservations(t *testing.T) {
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
	tests := []string{
		`{"current":[{"provider":"httpx","kind":"url","target":"not a URL","status_code":200}],"previous":[],"coverage_complete":true,"target_plan_digest":"plan"}`,
		`{"current":[{"provider":"httpx","kind":"host","target":"https://x.test/","status_code":200}],"previous":[],"coverage_complete":true,"target_plan_digest":"plan"}`,
		`{"current":[{"provider":"httpx","kind":"url","target":"https://x.test/","status_code":"200"}],"previous":[],"coverage_complete":true,"target_plan_digest":"plan"}`,
		`{"current":[{"provider":"httpx","kind":"url","target":"https://x.test/","status_code":200,"unexpected":true}],"previous":[],"coverage_complete":true,"target_plan_digest":"plan"}`,
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if err := registry.ValidateDefinitionInput("compare.assets", json.RawMessage(raw)); err == nil {
				t.Fatal("malformed structured observation was accepted")
			}
		})
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

func TestCompareAssetsStructuredCurrentMatchesPersistedHistory(t *testing.T) {
	input := json.RawMessage(`{
		"current":[{"provider":"httpx","kind":"url","target":"http://127.0.0.1:33000/","host":"127.0.0.1","port":33000,"status_code":200}],
		"previous":["{\"provider\":\"httpx\",\"kind\":\"url\",\"target\":\"http://127.0.0.1:33000/\",\"host\":\"127.0.0.1\",\"port\":33000,\"status_code\":200}"],
		"coverage_complete":true,
		"target_plan_digest":"plan"
	}`)
	result, _, err := executeCompareAssets(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.NewOrChanged) != 0 || len(result.ScanTargets) != 0 || len(result.Changes) != 0 {
		t.Fatalf("unchanged persisted observation was reported as changed: %#v", result)
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
	_, err = executeProviderTest(Registry(cfg), capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "compare.assets", Input: input}, Policy: policy.Policy{AllowedCapabilities: []string{"compare.assets"}}, Scope: testScope{}})
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
		{"compare.assets", `{"current":[],"coverage_complete":true,"target_plan_digest":"plan"}`},
		{"compare.assets", `{"current":[],"previous":null,"coverage_complete":true,"target_plan_digest":"plan"}`},
		{"compare.assets", `{"current":[],"previous":[42],"coverage_complete":true,"target_plan_digest":"plan"}`},
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
		result, err := executeProviderTest(registry, capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: test.name, Input: json.RawMessage(test.input)}, Policy: policy.Policy{AllowedCapabilities: []string{test.name}}, Scope: scope})
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

func TestTargetingPrepareNarrowsPinnedURLsToCurrentScope(t *testing.T) {
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
	input := json.RawMessage(`{"exact_urls":["https://keep.test/","https://removed.test/"],"discovered_urls":[],"ports":[443],"target_plan_digest":"pinned-plan"}`)

	narrowed, err := platformscope.Compile([]platformscope.Rule{{Protocol: `^https$`, Host: `^keep\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := executeProviderTest(registry, capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "targeting.prepare", Input: input}, Policy: policy.Policy{AllowedCapabilities: []string{"targeting.prepare"}}, Scope: narrowed})
	if err != nil {
		t.Fatal(err)
	}
	var output TargetingPrepareOutput
	if err := json.Unmarshal(result.Action.Output, &output); err != nil {
		t.Fatal(err)
	}
	if len(output.URLs) != 1 || output.URLs[0] != "https://keep.test/" || output.AcceptedCount != 1 || output.FilteredCount != 1 {
		t.Fatalf("narrowed output=%#v", output)
	}

	veto, err := platformscope.Compile([]platformscope.Rule{{Protocol: `^https$`, Host: `^other\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = executeProviderTest(registry, capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "targeting.prepare", Input: input}, Policy: policy.Policy{AllowedCapabilities: []string{"targeting.prepare"}}, Scope: veto})
	if err == nil || !strings.Contains(err.Error(), "no executable authorized targets") {
		t.Fatalf("current-scope veto error=%v", err)
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
	if got, want := strings.Join(httpx.Args, " "), "-silent -json -nfs -status-code -content-type -location -tech-detect -threads 5"; got != want {
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

func TestProviderUpdateArgs(t *testing.T) {
	original := []string{"-silent"}
	disabled := providerUpdateArgs(append([]string(nil), original...), false)
	if got := strings.Join(disabled, " "); got != "-silent -duc" {
		t.Fatalf("disabled provider updates args=%q", got)
	}
	enabled := providerUpdateArgs(append([]string(nil), original...), true)
	if got := strings.Join(enabled, " "); got != "-silent" {
		t.Fatalf("enabled provider updates args=%q", got)
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
	if got, want := len(invocation.Args), 9; got != want {
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

type unsupportedHTTPXOptionRunner struct {
	args  []string
	stdin []byte
}

func (r *unsupportedHTTPXOptionRunner) Run(_ context.Context, _ string, args []string, stdin []byte) ([]byte, []byte, int, error) {
	r.args = append([]string(nil), args...)
	r.stdin = append([]byte(nil), stdin...)
	return nil, []byte("unknown flag: -nfs"), 2, errors.New("exit status 2")
}

func (*unsupportedHTTPXOptionRunner) Version(context.Context, string, []string) (string, error) {
	return "httpx version 1.12.0", nil
}

func TestHTTPXUnsupportedNoFallbackSchemeFailsVisibly(t *testing.T) {
	runner := &unsupportedHTTPXOptionRunner{}
	provider := commandprovider.New(commandprovider.Definition{
		Name: "probe.http", Provider: "httpx", Executable: "httpx", Version: "4", Risk: policy.Low, ScopeType: "url", OutputAdapter: "httpx",
		BuildInvocation: func(input commandprovider.Input, pol policy.Policy) (commandprovider.Invocation, error) {
			return httpxInvocation(input, pol, config.Recon{Concurrency: 1})
		},
	}, runner, nil)
	registry := capability.NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	target := "http://127.0.0.1:8080/"
	sc, err := platformscope.Compile([]platformscope.Rule{{Protocol: `^http$`, Host: `^127\.0\.0\.1$`, Port: `^8080$`, File: `^/.*`, Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(commandprovider.Input{Targets: []string{target}, PlanDigest: "unsupported-option"})
	if err != nil {
		t.Fatal(err)
	}
	result, executeErr := executeProviderTest(registry, capability.Request{ProgramID: domain.NewID(), Action: domain.ActionRequest{ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), RequestedBy: "test", Capability: "probe.http", Input: input, StepAttempt: 1}, Provider: "httpx", Policy: policy.Policy{AllowedCapabilities: []string{"probe.http"}, Concurrency: 1}, Scope: sc})
	if executeErr == nil || result.Action.Status != "failed" || result.Action.Error == nil || result.Action.Error.Classification != "provider_error" || !strings.Contains(result.Action.Error.Message, "unknown flag: -nfs") {
		t.Fatalf("result=%#v err=%v, want visible unsupported-option provider failure", result, executeErr)
	}
	if !slices.Contains(runner.args, "-nfs") || string(runner.stdin) != target+"\n" {
		t.Fatalf("args=%v stdin=%q, want -nfs and exact target", runner.args, runner.stdin)
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
