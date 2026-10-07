package domain

import (
	"encoding/json"
	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"strings"
	"testing"
)

func preparedUnknownField(t *testing.T, raw []byte, path []string) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	if len(path) == 0 {
		object["unknown_recovery_authority"] = json.RawMessage(`true`)
	} else {
		child := object[path[0]]
		if len(child) > 0 && child[0] == '[' {
			var items []json.RawMessage
			if err := json.Unmarshal(child, &items); err != nil {
				t.Fatal(err)
			}
			items[0] = preparedUnknownField(t, items[0], path[1:])
			child, _ = json.Marshal(items)
		} else {
			child = preparedUnknownField(t, child, path[1:])
		}
		object[path[0]] = child
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	_, canonical, _, _, err := canonicaljson.ParseStrict(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestPreparedContractsRejectUnknownFieldsAtTypedLevels(t *testing.T) {
	m, c := preparedFixture(t, 4)
	mraw, _ := m.CanonicalJSON()
	craw, _ := c.CanonicalJSON()
	for _, path := range [][]string{nil, {"control"}, {"members"}} {
		if _, err := DecodePreparedManifestV1(preparedUnknownField(t, mraw, path)); err == nil {
			t.Fatalf("manifest accepted unknown field at %v", path)
		}
	}
	for _, path := range [][]string{nil, {"admission"}, {"step"}, {"tool_run"}, {"envelope"}, {"envelope", "semantic_output"}, {"envelope", "artifacts"}, {"envelope", "error"}} {
		if _, err := DecodePreparedControlV1(preparedUnknownField(t, craw, path)); err == nil {
			t.Fatalf("control accepted unknown field at %v", path)
		}
	}
	// Opaque application JSON is intentionally not a typed recovery structure.
	c.ToolRun.SanitizedArguments = json.RawMessage(`{"unknown_recovery_authority":true}`)
	craw, err := c.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodePreparedControlV1(craw); err != nil {
		t.Fatal(err)
	}
	c.Envelope.Error.Limit = &ResultContractLimitV1{Subject: LimitProjectionItem, Unit: LimitBytes, Limit: 1, Observed: 2}
	c.Envelope.Error.Code = "result_contract_limit"
	c.EnvelopeSHA256, _ = EnvelopeDigest(c.Envelope)
	craw, err = c.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodePreparedControlV1(preparedUnknownField(t, craw, []string{"envelope", "error", "limit"})); err == nil {
		t.Fatal("unknown limit field accepted")
	}
	// encoding/json normally accepts case-insensitive field aliases; recovery
	// must accept only the frozen exact names.
	aliased := strings.Replace(string(craw), `"version":`, `"Version":`, 1)
	_, canonical, _, _, err := canonicaljson.ParseStrict([]byte(aliased))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodePreparedControlV1(canonical); err == nil {
		t.Fatal("case-folded field alias accepted")
	}
}
