package workflows

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

type e2eCap struct{ name string }

func (c e2eCap) Manifest() capability.Manifest {
	return capability.Manifest{Name: c.name, Version: "1", Risk: map[bool]policy.Risk{true: policy.Moderate, false: policy.Low}[c.name == "scan.nuclei"], ApprovalRequired: c.name == "scan.nuclei", Idempotent: true, RetrySafe: true}
}

func TestBuiltInWorkflowSatisfiesRegisteredCapabilitySchemas(t *testing.T) {
	cfg, err := config.LoadPlanning()
	if err != nil {
		t.Fatal(err)
	}
	plan := targeting.TargetPlan{
		Digest:           "schema-plan",
		DiscoveryRoots:   []targeting.DiscoveryRoot{{Domain: "x.test", Source: "test"}},
		ExactActiveSeeds: []targeting.ActiveSeed{{Host: "x.test", Endpoints: []targeting.Endpoint{{Protocol: "https", Port: 443, URL: "https://x.test/"}}}},
	}
	definition := ContinuousWebRecon(plan, false)
	if err := workflow.Validate(definition, providers.Registry(cfg)); err != nil {
		t.Fatal(err)
	}
	var classifier *workflow.Step
	for index := range definition.Steps {
		if definition.Steps[index].Capability == "classify.endpoint" {
			classifier = &definition.Steps[index]
			break
		}
	}
	if classifier == nil {
		t.Fatal("classifier step missing")
	}
	want := map[string]string{
		"http_observations":    "probe-http.output.authorized_records",
		"crawl_observations":   "crawl-new-or-changed-web-assets.output.authorized_records",
		"passive_observations": "discover-archive-urls.output.authorized_records",
	}
	for field, binding := range want {
		if classifier.Bindings[field] != binding {
			t.Fatalf("classifier binding %s=%q want %q", field, classifier.Bindings[field], binding)
		}
	}
}

func TestWebReconDefinitionsUseEmptyPreviousObservationPlaceholder(t *testing.T) {
	plan := targeting.TargetPlan{
		Digest:           "first-run-plan",
		DiscoveryRoots:   []targeting.DiscoveryRoot{{Domain: "x.test", Source: "test"}},
		ExactActiveSeeds: []targeting.ActiveSeed{{Host: "x.test", Endpoints: []targeting.Endpoint{{Protocol: "https", Port: 443, URL: "https://x.test/"}}}},
	}
	definitions := []workflow.Definition{
		ContinuousWebRecon(plan, false),
		AuthorizedWebBaseline(plan, false),
	}
	for _, definition := range definitions {
		t.Run(definition.Name, func(t *testing.T) {
			var compare *workflow.Step
			for index := range definition.Steps {
				if definition.Steps[index].Capability == "compare.assets" {
					compare = &definition.Steps[index]
					break
				}
			}
			if compare == nil {
				t.Fatal("compare.assets step missing")
			}
			if got, want := compare.Bindings["current"], "probe-http.output.authorized_records"; got != want {
				t.Fatalf("current binding=%q want=%q", got, want)
			}
			var input struct {
				Previous json.RawMessage `json:"previous"`
			}
			if err := json.Unmarshal(compare.Input, &input); err != nil {
				t.Fatal(err)
			}
			if string(input.Previous) != "[]" {
				t.Fatalf("previous=%s want=[]", input.Previous)
			}
		})
	}
}

func (c e2eCap) Validate(context.Context, capability.Request) error { return nil }
func (c e2eCap) Execute(_ context.Context, r capability.Request) (capability.Result, error) {
	outputs := map[string]string{"discover.subdomains": `{"lines":["api.example.test"],"authorized_urls":["https://api.example.test/"]}`, "targeting.prepare": `{"urls":["https://api.example.test/"],"port_targets":["https://api.example.test/"]}`, "resolve.dns": `{"lines":["api.example.test"]}`, "scan.ports": `{"lines":["api.example.test:443"]}`, "probe.http": `{"lines":["{\"url\":\"https://api.example.test\",\"status_code\":200}"],"authorized_records":[{"provider":"httpx","kind":"url","target":"https://api.example.test","status_code":200}]}`, "compare.assets": `{"crawl_targets":["https://api.example.test"],"scan_targets":["https://api.example.test"],"changes":[{"kind":"new"}]}`, "crawl.web": `{"lines":["https://api.example.test/openapi.json"],"authorized_records":[{"provider":"katana","kind":"url","target":"https://api.example.test/openapi.json"}]}`, "discover.archive_urls": `{"lines":["https://api.example.test/v1/users"],"authorized_records":[{"provider":"gau","kind":"url","target":"https://api.example.test/v1/users"}]}`, "classify.endpoint": `{"endpoints":[],"classifications":[],"interesting_endpoints":[],"relationships":[]}`, "scan.nuclei": `{"lines":[]}`, "report.changes": `{"changes":[{"kind":"new"}]}`}
	return capability.Result{Action: domain.ActionResult{RequestID: r.Action.ID, Status: "succeeded", Summary: c.name, Output: json.RawMessage(outputs[c.name])}}, nil
}

func TestContinuousWebReconEndToEndStateMachine(t *testing.T) {
	registry := capability.NewRegistry()
	for _, name := range []string{"discover.subdomains", "targeting.prepare", "resolve.dns", "scan.ports", "probe.http", "compare.assets", "crawl.web", "discover.archive_urls", "classify.endpoint", "scan.nuclei", "report.changes"} {
		if err := registry.Register(e2eCap{name}); err != nil {
			t.Fatal(err)
		}
	}
	sc, err := platformscope.Compile([]platformscope.Rule{{Protocol: `^https$`, Host: `^api\.example\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}, {Protocol: `^https$`, Host: `^.*\.example\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := targeting.Plan(sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	definition := ContinuousWebRecon(plan, false)
	engine := workflow.Engine{Registry: registry, Executor: registry, Policy: policy.Policy{AllowedCapabilities: registry.Names()}, Scope: sc, Approval: func(context.Context, workflow.Step, policy.Risk) (bool, error) { return true, nil }}
	state, err := engine.Run(context.Background(), definition, nil, domain.Task{ID: domain.NewID(), WorkflowDefinitionID: definition.ID, RequestedBy: "test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.Run.Status != domain.RunCompleted {
		t.Fatalf("status=%s", state.Run.Status)
	}
	if len(state.Steps) != 12 {
		t.Fatalf("steps=%d", len(state.Steps))
	}
	for id, step := range state.Steps {
		if step.Run.Status != domain.StepSucceeded {
			t.Fatalf("step %s status=%s", id, step.Run.Status)
		}
	}
}

func TestContinuousWebReconProducesBriefBeforeNucleiApproval(t *testing.T) {
	registry := capability.NewRegistry()
	for _, name := range []string{"discover.subdomains", "targeting.prepare", "resolve.dns", "scan.ports", "probe.http", "compare.assets", "crawl.web", "discover.archive_urls", "classify.endpoint", "scan.nuclei", "report.changes"} {
		if err := registry.Register(e2eCap{name}); err != nil {
			t.Fatal(err)
		}
	}
	sc, err := platformscope.Compile([]platformscope.Rule{{Protocol: `^https$`, Host: `^api\.example\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}, {Protocol: `^https$`, Host: `^.*\.example\.test$`, Port: `^443$`, File: `^/.*`, Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := targeting.Plan(sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	definition := ContinuousWebRecon(plan, false)
	engine := workflow.Engine{Registry: registry, Executor: registry, Policy: policy.Policy{AllowedCapabilities: registry.Names()}, Scope: sc}
	state, err := engine.Run(context.Background(), definition, nil, domain.Task{ID: domain.NewID(), WorkflowDefinitionID: definition.ID, RequestedBy: "test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.Run.Status != domain.RunPaused {
		t.Fatalf("status=%s", state.Run.Status)
	}
	if state.Steps["generate-recon-brief"].Run.Status != domain.StepSucceeded {
		t.Fatalf("preliminary brief did not run before approval: %#v", state.Steps["generate-recon-brief"])
	}
	if state.Steps["run-safe-nuclei-profile"].Run.Status != domain.StepAwaitingApproval {
		t.Fatalf("nuclei step should be awaiting approval: %#v", state.Steps["run-safe-nuclei-profile"])
	}
	if state.Steps["enrich-recon-brief"] != nil {
		t.Fatalf("enriched brief should wait for scanner evidence: %#v", state.Steps["enrich-recon-brief"])
	}
}
