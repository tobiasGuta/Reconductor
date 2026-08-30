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
		{"continuous-exact", ContinuousWebRecon(exact, false), string(ContinuousTemplateID), ContinuousVersion, "web-recon/v1", "62b8a326f9e1e06230156c459f16ccb79d0eb72526dc1a33c0229d02d96dfa6a"},
		{"continuous-no-common-ports", ContinuousWebRecon(noCommonPorts, false), string(ContinuousTemplateID), ContinuousVersion, "web-recon/v1", "761df9ad76fe03c12662af5f6bc0d19ffd442ae9e850ef19ac719511aad3b620"},
		{"continuous-discovery-headless-false", ContinuousWebRecon(discovery, false), string(ContinuousTemplateID), ContinuousVersion, "web-recon/v1", "6dbba39c6e2a59c4c32daa3ab8f064697c65d195c36732ca84af6823f467027d"},
		{"continuous-discovery-headless-true", ContinuousWebRecon(discovery, true), string(ContinuousTemplateID), ContinuousVersion, "web-recon/v1", "a0179d9574baebca7450a7cb82cc5d7c5b89a078c97ff615ba1e46a5e49afad7"},
		{"baseline-exact", AuthorizedWebBaseline(exact, false), string(BaselineTemplateID), BaselineVersion, "web-recon/v1", "d98290bb80ee2f84caf515b2dd2fe92e504847cf66e4466475f368370ad42d94"},
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
}
