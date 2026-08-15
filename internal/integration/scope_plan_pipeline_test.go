package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
)

type integrationProvenanceRecorder struct{}

func (integrationProvenanceRecorder) RecordPolicyDecision(context.Context, capability.PolicyDecisionRecord) (domain.ID, error) {
	return domain.NewID(), nil
}
func (integrationProvenanceRecorder) RecordProviderInvocationStarted(context.Context, capability.ProviderInvocationStartRecord) (domain.ID, error) {
	return domain.NewID(), nil
}
func (integrationProvenanceRecorder) RecordProviderInvocationTerminal(context.Context, capability.ProviderInvocationTerminalRecord) error {
	return nil
}

func executeIntegrationCapability(registry *capability.Registry, req capability.Request) (capability.Result, error) {
	recorder := integrationProvenanceRecorder{}
	req.DecisionRecorder = recorder
	req.InvocationRecorder = recorder
	return registry.Execute(context.Background(), req)
}

func TestLocalScopePlanProbeFilterCompareAndReport(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string][]string{"urls": {base + "/public", base + "/excluded"}})
	}))
	defer srv.Close()
	base = srv.URL
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := platformscope.Compile([]platformscope.Rule{{Protocol: `^http$`, Host: `^` + regexp.QuoteMeta(u.Hostname()) + `$`, Port: `^` + u.Port() + `$`, File: `^/.*`, Enabled: true}}, []platformscope.Rule{{Protocol: `^http$`, Host: `^` + regexp.QuoteMeta(u.Hostname()) + `$`, Port: `^` + u.Port() + `$`, File: `^/excluded$`, Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := targeting.Plan(sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.InitialURLs()) != 1 {
		t.Fatalf("seeds=%v", plan.InitialURLs())
	}
	resp, err := srv.Client().Get(plan.InitialURLs()[0])
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var discovered map[string][]string
	if err := json.NewDecoder(resp.Body).Decode(&discovered); err != nil {
		t.Fatal(err)
	}
	filtered := targeting.FilterURLs(sc, discovered["urls"])
	if len(filtered.Authorized) != 1 || len(filtered.Filtered) != 1 || filtered.Filtered[0].Reason != platformscope.ReasonExcluded {
		t.Fatalf("filter=%#v", filtered)
	}

	cfg, err := config.LoadPlanning()
	if err != nil {
		t.Fatal(err)
	}
	registry := providers.Registry(cfg)
	pol := policy.Policy{AllowedCapabilities: []string{"compare.assets", "report.changes"}}
	compareInput, _ := json.Marshal(map[string]any{"current": []string{`{"url":"` + filtered.Authorized[0] + `","status_code":200}`}, "previous": []string{}, "coverage_complete": true, "target_plan_digest": "integration-plan"})
	compare, err := executeIntegrationCapability(registry, capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "compare.assets", Input: compareInput}, Policy: pol, Scope: sc})
	if err != nil {
		t.Fatal(err)
	}
	var changes map[string]any
	if err := json.Unmarshal(compare.Action.Output, &changes); err != nil {
		t.Fatal(err)
	}
	reportInput, _ := json.Marshal(map[string]any{"changes": changes["changes"], "endpoints": []any{}, "candidate_matches": []string{}, "target_plan_digest": "integration-plan"})
	report, err := executeIntegrationCapability(registry, capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Capability: "report.changes", Input: reportInput}, Policy: pol, Scope: sc})
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(report.Action.Output) {
		t.Fatalf("invalid report: %s", report.Action.Output)
	}
}
