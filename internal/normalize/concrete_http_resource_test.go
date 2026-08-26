package normalize

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
)

func TestConcreteHTTPResourcePreservesConcreteURIIdentity(t *testing.T) {
	tests := []struct {
		raw, wantURL, wantPath, wantQuery string
	}{
		{"HTTPS://Example.test:443/a%2fb?z=2&a=1&a=3#fragment", "https://example.test/a%2Fb?a=1&a=3&z=2", "/a%2Fb", "a=1&a=3&z=2"},
		{"http://example.test:80/a//b", "http://example.test/a//b", "/a//b", ""},
		{"https://example.test/a/./b", "https://example.test/a/./b", "/a/./b", ""},
		{"https://example.test/a/../b", "https://example.test/a/../b", "/a/../b", ""},
		{"https://example.test/a/", "https://example.test/a/", "/a/", ""},
		{"https://example.test/a%20b", "https://example.test/a%20b", "/a%20b", ""},
		{"https://example.test/a%25b", "https://example.test/a%25b", "/a%25b", ""},
		{"https://example.test/a/%2e%2e/b", "https://example.test/a/%2E%2E/b", "/a/%2E%2E/b", ""},
		{"https://example.test/path?", "https://example.test/path", "/path", ""},
		{"https://example.test/path?a=", "https://example.test/path?a=", "/path", "a="},
		{"https://example.test/path?a=+", "https://example.test/path?a=+", "/path", "a=+"},
		{"https://example.test/path?a=%2B", "https://example.test/path?a=%2B", "/path", "a=%2B"},
		{"https://example.test/path?a=%3B", "https://example.test/path?a=%3B", "/path", "a=%3B"},
	}
	for _, test := range tests {
		resource, err := ConcreteHTTPResource(test.raw)
		if err != nil {
			t.Fatalf("%s: %v", test.raw, err)
		}
		if resource.CanonicalURL != test.wantURL || resource.ConcreteEscapedPath != test.wantPath || resource.CanonicalQuery != test.wantQuery {
			t.Fatalf("%s: resource=%#v", test.raw, resource)
		}
	}

	left, err := ConcreteHTTPResource("https://example.test/a/b")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"https://example.test/a//b", "https://example.test/a/./b", "https://example.test/a/../b", "https://example.test/a/", "https://example.test/a%2Fb",
	} {
		right, err := ConcreteHTTPResource(raw)
		if err != nil {
			t.Fatal(err)
		}
		if left.ConcreteEscapedPath == right.ConcreteEscapedPath {
			t.Fatalf("concrete paths collapsed: %q", raw)
		}
	}
	if _, err := ConcreteHTTPResource("https://example.test/a?bad=%zz"); err == nil {
		t.Fatal("malformed query escape was accepted")
	}
	if _, err := ConcreteHTTPResource("https://example.test/a?bad=;"); err == nil {
		t.Fatal("raw query semicolon was accepted")
	}
	forward, err := ConcreteHTTPResource("https://example.test/path?a=1&a=2")
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := ConcreteHTTPResource("https://example.test/path?a=2&a=1")
	if err != nil {
		t.Fatal(err)
	}
	if forward.CanonicalQuery == reversed.CanonicalQuery {
		t.Fatalf("duplicate query value order collapsed: %q", forward.CanonicalQuery)
	}
}

func TestProbeHTTPSourceRecordsArePlatformDerivedAndStable(t *testing.T) {
	record := provideroutput.Record{
		Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://example.test/a%2fb?b=2&a=1",
		StatusCode: 200, Technologies: []string{"Go", "nginx", "Go"}, Fields: map[string]any{"z": json.Number("1.0"), "a": []any{json.Number("2"), nil}},
	}
	semantics := RequestSemantics{
		Method:      ValueSemantics{State: ValueKnown, Value: stringPointer("POST")},
		ContentType: ValueSemantics{State: ValueKnown, Value: stringPointer("application/json")},
	}
	sources, err := BuildProbeHTTPSourceRecords("00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", []provideroutput.Record{record, record}, semantics)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources[0].AuthorizedRecordIndex != 0 {
		t.Fatalf("sources=%#v", sources)
	}
	if sources[0].RequestMethod.State != ValueKnown || *sources[0].RequestMethod.Value != "POST" || *sources[0].RequestContentType.Value != "application/json" {
		t.Fatalf("request semantics=%#v", sources[0])
	}

	otherAttempt, err := BuildProbeHTTPSourceRecords("00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000003", []provideroutput.Record{record}, semantics)
	if err != nil {
		t.Fatal(err)
	}
	if sources[0].SourceLocator == otherAttempt[0].SourceLocator {
		t.Fatal("provider attempt did not affect source locator")
	}

	output, err := json.Marshal(map[string]any{
		"authorized_records":        []provideroutput.Record{record, record},
		"authorized_source_records": []any{map[string]any{"source_locator": "forged"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	decorated, err := AttachProbeHTTPSourceRecords(output, "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", json.RawMessage(`{"method":"post","request_content_type":"Application/JSON; charset=utf-8"}`))
	if err != nil {
		t.Fatal(err)
	}
	parsed, present, err := ParseProbeHTTPSourceOutput(decorated, "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002")
	if err != nil || !present || len(parsed.AuthorizedSourceRecords) != 1 {
		t.Fatalf("parsed=%#v present=%v err=%v", parsed, present, err)
	}
	if parsed.AuthorizedSourceRecords[0].SourceLocator == "forged" {
		t.Fatal("provider-supplied source locator was trusted")
	}

	canonical, err := CanonicalRecordJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	ordered, err := CanonicalRecordJSON(provideroutput.Record{Provider: "httpx", Kind: provideroutput.URLRecord, Target: record.Target, StatusCode: 200, Technologies: []string{"nginx", "Go"}, Fields: map[string]any{"a": []any{json.Number("2"), nil}, "z": json.Number("1.0")}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(canonical, ordered) {
		t.Fatalf("canonical record is not map-order stable:\n%s\n%s", canonical, ordered)
	}
}

func TestDeriveProbeHTTPSourceRecordsRequiresExplicitCollectionCorrespondence(t *testing.T) {
	const programID = "00000000-0000-4000-8000-000000000001"
	records := []provideroutput.Record{{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://example.test/", Fields: map[string]any{}}}

	legacy, err := DeriveProbeHTTPSourceRecords(programID, records, nil)
	if err != nil || legacy == nil || len(legacy) != 0 {
		t.Fatalf("legacy derivations=%#v err=%v", legacy, err)
	}
	empty, err := DeriveProbeHTTPSourceRecords(programID, []provideroutput.Record{}, []AuthorizedSourceRecord{})
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty derivations=%#v err=%v", empty, err)
	}
	if _, err := DeriveProbeHTTPSourceRecords(programID, records, []AuthorizedSourceRecord{}); !errors.Is(err, ErrProbeHTTPSourceContract) {
		t.Fatalf("empty source mismatch error=%v", err)
	}
}

func TestCanonicalRecordJSONNumberAndStructureContract(t *testing.T) {
	base := provideroutput.Record{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://example.test/", Technologies: []string{"nginx", "Go", "nginx"}}
	canonicalNumber := func(number string) []byte {
		record := base
		record.Fields = map[string]any{"number": json.Number(number)}
		encoded, err := CanonicalRecordJSON(record)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	// Numeric spellings are canonicalized by exact decimal value, never through float64.
	for _, number := range []string{"200.0", "2e2", "2E+2"} {
		if !reflect.DeepEqual(canonicalNumber("200"), canonicalNumber(number)) {
			t.Fatalf("equivalent JSON numbers differ: 200 and %s", number)
		}
	}
	if !reflect.DeepEqual(canonicalNumber("0"), canonicalNumber("-0")) {
		t.Fatal("negative zero is not canonicalized")
	}
	if !strings.Contains(string(canonicalNumber("9007199254740993")), "9007199254740993") || !strings.Contains(string(canonicalNumber("1.25")), "1.25") {
		t.Fatal("large integer or decimal precision was lost")
	}

	ordered := base
	ordered.Fields = map[string]any{"nested": map[string]any{"z": json.Number("2"), "a": nil}, "items": []any{json.Number("1"), "two"}}
	reordered := base
	reordered.Fields = map[string]any{"items": []any{json.Number("1"), "two"}, "nested": map[string]any{"a": nil, "z": json.Number("2")}}
	left, err := CanonicalRecordJSON(ordered)
	if err != nil {
		t.Fatal(err)
	}
	right, err := CanonicalRecordJSON(reordered)
	if err != nil || !reflect.DeepEqual(left, right) {
		t.Fatalf("nested map order or null was not deterministic: err=%v", err)
	}
	reordered.Fields = map[string]any{"items": []any{"two", json.Number("1")}}
	if changed, err := CanonicalRecordJSON(reordered); err != nil || reflect.DeepEqual(left, changed) {
		t.Fatalf("array order was not retained: err=%v", err)
	}
	nilFields := base
	nilFields.Fields = nil
	if encoded, err := CanonicalRecordJSON(nilFields); err != nil || !strings.Contains(string(encoded), `"fields":{}`) {
		t.Fatalf("nil fields=%s err=%v", encoded, err)
	}
	unsupported := base
	unsupported.Fields = map[string]any{"float": 1.25}
	if _, err := CanonicalRecordJSON(unsupported); err == nil {
		t.Fatal("float64 field was accepted")
	}
}

func TestProbeHTTPSourceRecordOrderingIsTotalAndPreservesDuplicateRepresentative(t *testing.T) {
	semantics := RequestSemantics{Method: ValueSemantics{State: ValueDefaulted, Value: stringPointer("GET")}, ContentType: ValueSemantics{State: ValueUnknown}}
	first := provideroutput.Record{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://example.test/same", Fields: map[string]any{"variant": "first"}}
	second := provideroutput.Record{Provider: "httpx", Kind: provideroutput.URLRecord, Target: first.Target, Fields: map[string]any{"variant": "second"}}
	forward, err := BuildProbeHTTPSourceRecords("00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", []provideroutput.Record{first, second}, semantics)
	if err != nil {
		t.Fatal(err)
	}
	reversed, err := BuildProbeHTTPSourceRecords("00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", []provideroutput.Record{second, first}, semantics)
	if err != nil {
		t.Fatal(err)
	}
	if len(forward) != 2 || len(reversed) != 2 || forward[0].SourceLocator != reversed[0].SourceLocator || forward[1].SourceLocator != reversed[1].SourceLocator || forward[0].SourceLocator >= forward[1].SourceLocator {
		t.Fatalf("source order is not total: forward=%#v reversed=%#v", forward, reversed)
	}
	duplicates, err := BuildProbeHTTPSourceRecords("00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", []provideroutput.Record{first, first, second}, semantics)
	if err != nil || len(duplicates) != 2 {
		t.Fatalf("duplicate sources=%#v err=%v", duplicates, err)
	}
	for _, source := range duplicates {
		if source.SourceLocator == forward[0].SourceLocator || source.SourceLocator == forward[1].SourceLocator {
			if source.AuthorizedRecordIndex != 0 && source.AuthorizedRecordIndex != 2 {
				t.Fatalf("unexpected duplicate representative=%#v", source)
			}
		}
	}
}

func TestProbeHTTPSourceRecordLocatorCollisionFailsClosed(t *testing.T) {
	semantics := RequestSemantics{Method: ValueSemantics{State: ValueDefaulted, Value: stringPointer("GET")}, ContentType: ValueSemantics{State: ValueUnknown}}
	records := []provideroutput.Record{
		{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://example.test/first", Fields: map[string]any{}},
		{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://example.test/second", Fields: map[string]any{}},
	}
	constantLocator := func(string, string, string, []byte, RequestSemantics) (string, error) {
		return strings.Repeat("0", 64), nil
	}
	if _, err := buildProbeHTTPSourceRecords("00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", records, semantics, constantLocator); !errors.Is(err, ErrProbeHTTPSourceContract) {
		t.Fatalf("materially different collision error=%v", err)
	}
	duplicates, err := buildProbeHTTPSourceRecords("00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", []provideroutput.Record{records[0], records[0]}, semantics, constantLocator)
	if err != nil || len(duplicates) != 1 || duplicates[0].AuthorizedRecordIndex != 0 {
		t.Fatalf("exact duplicate collision handling=%#v err=%v", duplicates, err)
	}
}

func TestProbeRequestSemanticsRejectsExplicitNullMethod(t *testing.T) {
	absent, err := ProbeRequestSemantics(json.RawMessage(`{}`))
	if err != nil || absent.Method.State != ValueDefaulted || absent.Method.Value == nil || *absent.Method.Value != "GET" {
		t.Fatalf("absent method semantics=%#v err=%v", absent, err)
	}
	known, err := ProbeRequestSemantics(json.RawMessage(`{"method":"post"}`))
	if err != nil || known.Method.State != ValueKnown || known.Method.Value == nil || *known.Method.Value != "POST" {
		t.Fatalf("known method semantics=%#v err=%v", known, err)
	}
	for _, raw := range []json.RawMessage{json.RawMessage(`{"method":""}`), json.RawMessage(`{"method":null}`)} {
		if _, err := ProbeRequestSemantics(raw); err == nil {
			t.Fatalf("invalid method was accepted: %s", raw)
		}
	}
}

func TestProbeHTTPSourceDerivationUsesExplicitUnknownAndDefaultedSemantics(t *testing.T) {
	records := []provideroutput.Record{{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://example.test/items/123?a=1", Fields: map[string]any{}}}
	semantics := RequestSemantics{
		Method:      ValueSemantics{State: ValueDefaulted, Value: stringPointer("GET")},
		ContentType: ValueSemantics{State: ValueUnknown},
	}
	sources, err := BuildProbeHTTPSourceRecords("00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", records, semantics)
	if err != nil {
		t.Fatal(err)
	}
	derivations, err := DeriveProbeHTTPSourceRecords("00000000-0000-4000-8000-000000000001", records, sources)
	if err != nil {
		t.Fatal(err)
	}
	if len(derivations) != 1 || derivations[0].Endpoint.Method != "GET" || derivations[0].Endpoint.ContentType != "" {
		t.Fatalf("derivations=%#v", derivations)
	}
	if derivations[0].EffectiveMethod.State != ValueDefaulted || derivations[0].EffectiveRequestContentType.State != ValueDefaulted || derivations[0].EffectiveRequestContentType.Value == nil || *derivations[0].EffectiveRequestContentType.Value != "" {
		t.Fatalf("effective semantics=%#v", derivations[0])
	}
	sources[0].SourceLocator = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := DeriveProbeHTTPSourceRecords("00000000-0000-4000-8000-000000000001", records, sources); !errors.Is(err, ErrProbeHTTPSourceContract) {
		t.Fatalf("tampered source error=%v", err)
	}
}
