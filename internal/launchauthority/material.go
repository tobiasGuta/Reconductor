// Package launchauthority defines the closed material published for exact
// dispatch. It contains no transport or provider implementation.
package launchauthority

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/scope"
)

const (
	ScopeSchemaV1     = "exact-launch-scope/v1"
	ScopeEvaluatorV1  = "reconductor-scope/v1"
	PolicySchemaV1    = "exact-launch-policy/v1"
	PolicyEvaluatorV1 = "reconductor-policy/v1"
	MaxMaterialBytes  = 65_536
)

type ScopeMaterial struct {
	Schema    string                 `json:"schema"`
	Evaluator string                 `json:"evaluator"`
	Includes  []scope.NormalizedRule `json:"includes"`
	Excludes  []scope.NormalizedRule `json:"excludes"`
}

// PolicyMaterial contains only values used for the anonymous GET/HEAD launch
// decision. Runtime budgets remain separate operational controls.
type PolicyMaterial struct {
	Schema              string   `json:"schema"`
	Evaluator           string   `json:"evaluator"`
	AllowedCapabilities []string `json:"allowed_capabilities"`
	DeniedCapabilities  []string `json:"denied_capabilities"`
	ScanWindows         []string `json:"scan_windows"`
	AllowedHTTPMethods  []string `json:"allowed_http_methods"`
	AuthenticationUsage bool     `json:"authentication_usage"`
	MaximumPayloadSize  int64    `json:"maximum_payload_size"`
}

func ScopeFromCompiled(sc scope.Scope) ([]byte, string, string, error) {
	if len(sc.IncludeRules()) == 0 || sc.Digest() == "" {
		return nil, "", "", fmt.Errorf("scope has no compiled includes")
	}
	m := ScopeMaterial{Schema: ScopeSchemaV1, Evaluator: ScopeEvaluatorV1, Includes: sc.IncludeRules(), Excludes: sc.ExcludeRules()}
	raw, digest, err := canonical(m)
	return raw, digest, sc.Digest(), err
}

func DecodeScope(raw []byte, digest string) (scope.Scope, error) {
	if err := verifyCanonical(raw, digest); err != nil {
		return scope.Scope{}, err
	}
	var m ScopeMaterial
	if err := decodeClosed(raw, &m); err != nil {
		return scope.Scope{}, err
	}
	if err := verifyTypedMaterial(raw, m); err != nil {
		return scope.Scope{}, err
	}
	if m.Schema != ScopeSchemaV1 || m.Evaluator != ScopeEvaluatorV1 || len(m.Includes) == 0 || m.Excludes == nil {
		return scope.Scope{}, fmt.Errorf("unsupported scope material")
	}
	includes, excludes := make([]scope.Rule, 0, len(m.Includes)), make([]scope.Rule, 0, len(m.Excludes))
	for _, r := range m.Includes {
		if r.Kind != scope.IncludeRule || !r.Enabled {
			return scope.Scope{}, fmt.Errorf("invalid include rule")
		}
		includes = append(includes, scope.Rule{Protocol: r.Protocol, Host: r.Host, Port: r.Port, File: r.File, Enabled: true})
	}
	for _, r := range m.Excludes {
		if r.Kind != scope.ExcludeRule || !r.Enabled {
			return scope.Scope{}, fmt.Errorf("invalid exclude rule")
		}
		excludes = append(excludes, scope.Rule{Protocol: r.Protocol, Host: r.Host, Port: r.Port, File: r.File, Enabled: true})
	}
	sc, err := scope.Compile(includes, excludes)
	if err != nil {
		return scope.Scope{}, err
	}
	if !reflect.DeepEqual(sc.IncludeRules(), m.Includes) || !reflect.DeepEqual(sc.ExcludeRules(), m.Excludes) {
		return scope.Scope{}, fmt.Errorf("scope normalized rules do not reconstruct exactly")
	}
	return sc, nil
}

func PolicyFromPolicy(p policy.Policy) ([]byte, string, error) {
	m := PolicyMaterial{
		Schema: PolicySchemaV1, Evaluator: PolicyEvaluatorV1,
		AllowedCapabilities: nonnil(p.AllowedCapabilities), DeniedCapabilities: nonnil(p.DeniedCapabilities),
		ScanWindows: nonnil(p.ScanWindows), AllowedHTTPMethods: nonnil(p.AllowedHTTPMethods),
		AuthenticationUsage: p.AuthenticationUsage, MaximumPayloadSize: p.MaximumPayloadSize,
	}
	if err := validatePolicy(m); err != nil {
		return nil, "", err
	}
	return canonical(m)
}

func DecodePolicy(raw []byte, digest string) (policy.Policy, error) {
	if err := verifyCanonical(raw, digest); err != nil {
		return policy.Policy{}, err
	}
	var m PolicyMaterial
	if err := decodeClosed(raw, &m); err != nil {
		return policy.Policy{}, err
	}
	if err := verifyTypedMaterial(raw, m); err != nil {
		return policy.Policy{}, err
	}
	if err := validatePolicy(m); err != nil {
		return policy.Policy{}, err
	}
	return policy.Policy{ID: "exact-launch", AllowedCapabilities: m.AllowedCapabilities, DeniedCapabilities: m.DeniedCapabilities,
		ScanWindows: m.ScanWindows, AllowedHTTPMethods: m.AllowedHTTPMethods,
		AuthenticationUsage: m.AuthenticationUsage, MaximumPayloadSize: m.MaximumPayloadSize}, nil
}

func validatePolicy(m PolicyMaterial) error {
	if m.Schema != PolicySchemaV1 || m.Evaluator != PolicyEvaluatorV1 || m.MaximumPayloadSize < 0 ||
		m.AllowedCapabilities == nil || m.DeniedCapabilities == nil || m.ScanWindows == nil || len(m.AllowedHTTPMethods) == 0 {
		return fmt.Errorf("unsupported or incomplete policy material")
	}
	for _, method := range m.AllowedHTTPMethods {
		if method == "" {
			return fmt.Errorf("empty allowed method")
		}
	}
	return policy.ValidateScanWindows(m.ScanWindows)
}

func nonnil(values []string) []string {
	return append([]string{}, values...)
}

func canonical(value any) ([]byte, string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	_, canonical, nodes, depth, err := canonicaljson.ParseStrictBounded(raw, MaxMaterialBytes)
	if err != nil {
		return nil, "", err
	}
	if nodes > 8192 || depth > 8 {
		return nil, "", fmt.Errorf("material structure exceeds bounds")
	}
	sum := sha256.Sum256(canonical)
	return canonical, hex.EncodeToString(sum[:]), nil
}

func verifyCanonical(raw []byte, digest string) error {
	_, canonicalBytes, nodes, depth, err := canonicaljson.ParseStrictBounded(raw, MaxMaterialBytes)
	if err != nil {
		return err
	}
	if nodes > 8192 || depth > 8 || !bytes.Equal(raw, canonicalBytes) {
		return fmt.Errorf("material is not bounded canonical JSON")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != digest {
		return fmt.Errorf("material digest mismatch")
	}
	return nil
}

// The v1 schema requires every tagged field with its exact spelling. A typed
// round-trip catches aliases, omissions and semantic changes from Go's decoder.
func verifyTypedMaterial(raw []byte, material any) error {
	encoded, _, err := canonical(material)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, encoded) {
		return fmt.Errorf("material does not match its closed typed representation")
	}
	return nil
}

func decodeClosed(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("material contains trailing JSON")
	}
	return nil
}
