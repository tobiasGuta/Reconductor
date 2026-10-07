package workflows

import (
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/targeting"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

func TestWorkflowMaterializationReleaseContracts(t *testing.T) {
	exact := targeting.TargetPlan{
		ScopeDigest: "contract-scope-exact", Digest: "contract-plan-exact",
		ExactActiveSeeds: []targeting.ActiveSeed{{Host: "api.example.test", PathPattern: "^/v1/.*", SourceRuleIDs: []string{"exact"}, Endpoints: []targeting.Endpoint{{Protocol: "https", Port: 443, URL: "https://api.example.test/v1/"}}}},
	}
	noCommonPorts := targeting.TargetPlan{
		ScopeDigest: "contract-scope-disjoint", Digest: "contract-plan-disjoint",
		ExactActiveSeeds: []targeting.ActiveSeed{
			{Host: "one.example.test", SourceRuleIDs: []string{"one"}, Endpoints: []targeting.Endpoint{{Protocol: "https", Port: 443, URL: "https://one.example.test/"}}},
			{Host: "two.example.test", SourceRuleIDs: []string{"two"}, Endpoints: []targeting.Endpoint{{Protocol: "http", Port: 80, URL: "http://two.example.test/"}}},
		},
	}
	discovery := targeting.TargetPlan{
		ScopeDigest: "contract-scope-discovery", Digest: "contract-plan-discovery",
		DiscoveryRoots:   []targeting.DiscoveryRoot{{Domain: "example.test", SourceRuleIDs: []string{"wild"}, Source: "scope"}},
		WildcardRules:    []targeting.WildcardRule{{HostPattern: `^.*\.example\.test$`, BaseDomain: "example.test", Protocols: []string{"https"}, Ports: []int{443}, PathPattern: "^/", SourceRuleID: "wild"}},
		ExactActiveSeeds: []targeting.ActiveSeed{{Host: "api.example.test", SourceRuleIDs: []string{"exact"}, Endpoints: []targeting.Endpoint{{Protocol: "https", Port: 443, URL: "https://api.example.test/"}}}},
	}
	tests := []struct {
		name         string
		definition   workflow.Definition
		templateID   string
		version      string
		materializer string
		digest       string
	}{
		{"continuous-exact", ContinuousWebRecon(exact, false), string(ContinuousTemplateID), ContinuousVersion, "web-recon/v1", "85a142be2571fff5a4ea72dedaca689df558b2509d801eba7b41977d8bbc3522"},
		{"continuous-no-common-ports", ContinuousWebRecon(noCommonPorts, false), string(ContinuousTemplateID), ContinuousVersion, "web-recon/v1", "b55547ffd59077271e4c6e3749a5a56d3d47d8f5dfcfff01b3c205952eb203dc"},
		{"continuous-discovery-headless-false", ContinuousWebRecon(discovery, false), string(ContinuousTemplateID), ContinuousVersion, "web-recon/v1", "09d27977e3e8b51429dd51777efcf45b70e40da5127de90797530513dc1d2da2"},
		{"continuous-discovery-headless-true", ContinuousWebRecon(discovery, true), string(ContinuousTemplateID), ContinuousVersion, "web-recon/v1", "8d1789fb62576e4218464e9b7cd10b09d636cfe1b0b702eda8c3b919eb3ebfd8"},
		{"baseline-exact", AuthorizedWebBaseline(exact, false), string(BaselineTemplateID), BaselineVersion, "web-recon/v1", "06e061d74e7b488a60d60c2445fa4e687a3db4d176ec2416878017e510a575fa"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			template, err := CurrentTemplate(test.definition.Name)
			if err != nil {
				t.Fatal(err)
			}
			if string(template.ID) != test.templateID || template.Version != test.version || template.Materializer != test.materializer {
				t.Fatalf("release tuple=(%s,%s,%s) want=(%s,%s,%s)", template.ID, template.Version, template.Materializer, test.templateID, test.version, test.materializer)
			}
			_, digest, err := workflow.Materialize(test.definition)
			if err != nil {
				t.Fatal(err)
			}
			if digest != test.digest {
				t.Fatalf("materialization digest=%s want=%s", digest, test.digest)
			}
		})
	}
}

func TestSupportedReleaseRequiresCompleteFourPartIdentity(t *testing.T) {
	if !SupportsRelease(ContinuousTemplateID, ContinuousName, ContinuousVersion, "web-recon/v1") {
		t.Fatal("current source-controlled release was not supported")
	}
	if SupportsRelease(ContinuousTemplateID, ContinuousName, ContinuousVersion, "web-recon/v2") {
		t.Fatal("unsupported materializer revision was accepted")
	}
	if SupportsRelease(BaselineTemplateID, ContinuousName, ContinuousVersion, "web-recon/v1") {
		t.Fatal("mismatched template UUID was accepted")
	}
	if !SupportsRelease(continuousTemplateIDV240, ContinuousName, continuousVersionV240, "web-recon/v1") || !SupportsRelease(baselineTemplateIDV140, BaselineName, baselineVersionV140, "web-recon/v1") {
		t.Fatal("immediately previous materialized releases are no longer resumable")
	}
}
