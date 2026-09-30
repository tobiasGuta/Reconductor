package launchauthority

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/scope"
)

func TestScopeMaterialReconstructsActualEvaluator(t *testing.T) {
	sc, err := scope.Compile([]scope.Rule{{Protocol: "https", Host: "example\\.test", Port: "443", File: "/allowed/.*", Enabled: true}},
		[]scope.Rule{{Protocol: "https", Host: "example\\.test", Port: "443", File: "/allowed/private/.*", Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	raw, hash, digest, err := ScopeFromCompiled(sc)
	if err != nil || hash == "" || digest != sc.Digest() {
		t.Fatalf("material hash=%q digest=%q err=%v", hash, digest, err)
	}
	rebuilt, err := DecodeScope(raw, hash)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		url     string
		allowed bool
	}{
		{"https://example.test/allowed/one", true},
		{"https://example.test/allowed/private/one", false},
		{"https://example.test/other", false},
		{"http://example.test/allowed/one", false},
	} {
		if got := rebuilt.Evaluate(tc.url).Allowed; got != tc.allowed {
			t.Errorf("url=%s allowed=%v want=%v", tc.url, got, tc.allowed)
		}
	}
	if _, err := DecodeScope(raw, strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted bad material digest")
	}
	var candidate map[string]any
	if err := json.Unmarshal(raw, &candidate); err != nil {
		t.Fatal(err)
	}
	candidate["unexpected"] = true
	modified, modifiedHash, err := canonical(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeScope(modified, modifiedHash); err == nil {
		t.Fatal("accepted open material schema")
	}
	if _, err := DecodeScope(append(bytes.Clone(raw), ' '), hash); err == nil {
		t.Fatal("accepted noncanonical stored bytes")
	}
}

func TestPolicyMaterialIsClosedAndFailsOnUnknownRevision(t *testing.T) {
	raw, hash, err := PolicyFromPolicy(policy.Policy{AllowedCapabilities: []string{"http.request"}, AllowedHTTPMethods: []string{"GET"}, ScanWindows: []string{"09:00-17:00 UTC"}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodePolicy(raw, hash)
	if err != nil || len(p.AllowedHTTPMethods) != 1 || p.AllowedHTTPMethods[0] != "GET" {
		t.Fatalf("decoded=%#v err=%v", p, err)
	}
	var candidate map[string]any
	if err := json.Unmarshal(raw, &candidate); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"schema", func(v map[string]any) { v["schema"] = "v2" }},
		{"evaluator", func(v map[string]any) { v["evaluator"] = "v2" }},
		{"malformed window", func(v map[string]any) { v["scan_windows"] = []string{"unbounded"} }},
		{"unknown field", func(v map[string]any) { v["runtime_secrets"] = "never" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clone := map[string]any{}
			for k, v := range candidate {
				clone[k] = v
			}
			tc.mutate(clone)
			data, digest, err := canonical(clone)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodePolicy(data, digest); err == nil {
				t.Fatal("accepted invalid policy material")
			}
		})
	}
}

func TestPolicyMaterialPreservesEmptyAuthorityLists(t *testing.T) {
	raw, hash, err := PolicyFromPolicy(policy.Policy{
		AllowedCapabilities: []string{"http.request"},
		DeniedCapabilities:  []string{},
		ScanWindows:         []string{},
		AllowedHTTPMethods:  []string{"GET"},
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePolicy(raw, hash)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.DeniedCapabilities == nil || decoded.ScanWindows == nil {
		t.Fatalf("empty lists became null: %s", raw)
	}
}

func TestActionFixtureClosedAndStable(t *testing.T) {
	raw := json.RawMessage(`{"version":"exact-dispatch-fixture/v1","method":"GET","url":"https://example.test/allowed/one"}`)
	_, hash, err := DecodeActionFixture(raw)
	if err != nil || len(hash) != 64 {
		t.Fatalf("hash=%q err=%v", hash, err)
	}
	for _, candidate := range []string{
		`{"version":"exact-dispatch-fixture/v1","method":"GET","url":"https://example.test/allowed/one","headers":{}}`,
		`{"version":"exact-dispatch-fixture/v1","method":"POST","url":"https://example.test/allowed/one"}`,
		`{"version":"exact-dispatch-fixture/v1","method":"GET","url":"http://example.test/allowed/one"}`,
		`{"version":"exact-dispatch-fixture/v1","method":"GET","url":"https://example.test/allowed/one","url":"https://other.test/"}`,
	} {
		if _, _, err := DecodeActionFixture(json.RawMessage(candidate)); err == nil {
			t.Errorf("accepted %s", candidate)
		}
	}
}

func TestAuthoritativeMaterialRejectsAliasesAndMissingFields(t *testing.T) {
	policyRaw, _, err := PolicyFromPolicy(policy.Policy{AllowedCapabilities: []string{"http.request"},
		DeniedCapabilities: []string{"http.request"}, AllowedHTTPMethods: []string{"GET"},
		ScanWindows: []string{"09:00-17:00 UTC"}})
	if err != nil {
		t.Fatal(err)
	}
	policyCases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"alternate-case key", func(v map[string]any) {
			v["Denied_Capabilities"] = v["denied_capabilities"]
			delete(v, "denied_capabilities")
		}},
		{"semantic alias", func(v map[string]any) {
			v["Denied_Capabilities"] = v["denied_capabilities"]
			v["denied_capabilities"] = []string{}
		}},
		{"missing scan windows", func(v map[string]any) { delete(v, "scan_windows") }},
		{"missing denied capabilities", func(v map[string]any) { delete(v, "denied_capabilities") }},
		{"explicit null scan windows", func(v map[string]any) { v["scan_windows"] = nil }},
		{"wrong type", func(v map[string]any) { v["maximum_payload_size"] = "0" }},
		{"unknown field", func(v map[string]any) { v["unexpected"] = true }},
		{"missing typed default", func(v map[string]any) { delete(v, "authentication_usage") }},
	}
	for _, tc := range policyCases {
		t.Run("policy/"+tc.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(policyRaw, &value); err != nil {
				t.Fatal(err)
			}
			tc.mutate(value)
			raw, hash, err := canonical(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodePolicy(raw, hash); err == nil {
				t.Fatalf("accepted ambiguous or incomplete policy: %s", raw)
			}
		})
	}
	sc, err := scope.Compile([]scope.Rule{{Protocol: "https", Host: "example\\.test", Port: "443", File: "/.*", Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	scopeRaw, _, _, err := ScopeFromCompiled(sc)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"alternate-case key", func(v map[string]any) { v["Includes"] = v["includes"]; delete(v, "includes") }},
		{"missing excludes", func(v map[string]any) { delete(v, "excludes") }},
		{"null excludes", func(v map[string]any) { v["excludes"] = nil }},
		{"nested missing enabled", func(v map[string]any) { delete(v["includes"].([]any)[0].(map[string]any), "enabled") }},
	} {
		t.Run("scope/"+tc.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(scopeRaw, &value); err != nil {
				t.Fatal(err)
			}
			tc.mutate(value)
			raw, hash, err := canonical(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeScope(raw, hash); err == nil {
				t.Fatalf("accepted ambiguous or incomplete scope: %s", raw)
			}
		})
	}
}
