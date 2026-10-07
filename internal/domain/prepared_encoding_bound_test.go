package domain

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This is a compositional upper bound over the schema, not an example encoding.
// Every optional field is counted simultaneously, even mutually exclusive ones.
// JSON field names, separators and quotes are included. New unbounded fields
// fail this proof until their validation and encoded budget are specified.
func preparedEncodingUpperBound(t *testing.T, typ reflect.Type, field string) int {
	t.Helper()
	if typ.Kind() == reflect.Pointer {
		return preparedEncodingUpperBound(t, typ.Elem(), field)
	}
	if typ == reflect.TypeOf(ID("")) {
		return 38
	} // canonical UUID + quotes
	if typ == reflect.TypeOf(time.Time{}) {
		return 37
	} // longest valid RFC3339Nano + quotes
	if typ == reflect.TypeOf(ResultEnvelopeV1{}) {
		return ResultEnvelopeMaxBytes
	} // EnvelopeDigest enforces CanonicalJSON
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return DiagnosticMaxBytes
	} // validatePreparedJSON includes canonical budget
	switch typ.Kind() {
	case reflect.Struct:
		n := 2
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				t.Fatalf("unproved JSON field %s.%s", typ, f.Name)
			}
			if i > 0 {
				n++
			}
			n += len(name) + 3 + preparedEncodingUpperBound(t, f.Type, typ.Name()+"."+f.Name)
		}
		return n
	case reflect.Slice:
		return 2 + ResultArtifactReferenceMaxCount*preparedEncodingUpperBound(t, typ.Elem(), field) + ResultArtifactReferenceMaxCount - 1
	case reflect.Int, reflect.Int64:
		return 20 // includes sign, all accepted machine/int64 values
	case reflect.Bool:
		return 5
	case reflect.String:
		// Values validated as exact literals, canonical storage keys, SHA-256,
		// closed enums, or encoded field budgets cannot undergo extra escaping.
		encoded := map[string]int{
			"PreparedManifestV1.Version":           len(PreparedManifestVersionV1) + 2,
			"PreparedControlV1.Version":            len(PreparedControlVersionV1) + 2,
			"PreparedManifestV1.StoreBackendKind":  len("local-v1") + 2,
			"PreparedManifestV1.StoreMarkerFormat": len("reconductor-artifact-store") + 2,
			"PreparedObjectRefV1.StorageKey":       len("prepared/v1/aa/00000000-0000-0000-0000-000000000000/control.json") + 2,
			"PreparedMemberV1.PreparedKey":         len("prepared/v1/aa/00000000-0000-0000-0000-000000000000/member-0003") + 2,
			"PreparedMemberV1.FinalKey":            len("v1/aa/00000000-0000-0000-0000-000000000000") + 2,
			"PreparedObjectRefV1.ContentSHA256":    66, "PreparedMemberV1.ContentSHA256": 66, "PreparedControlV1.EnvelopeSHA256": 66,
			"PreparedMemberV1.Role":        len("provider_diagnostic") + 2,
			"PreparedMemberV1.ContentType": 255 + 2, "PreparedMemberV1.ArtifactType": 64 + 2,
			"ToolRun.Provider": DiagnosticMaxBytes + 2, "ToolRun.ToolVersion": DiagnosticMaxBytes + 2,
			"PreparedAdmissionV1.Provider": DiagnosticMaxBytes + 2, "PreparedStepV1.IdempotencyKey": DiagnosticMaxBytes + 2,
			"PreparedControlV1.ProviderOutcome": len("cancelled") + 2, "PreparedStepV1.Status": len("succeeded") + 2,
			// Raw UTF-8 byte limits: worst JSON expansion is six bytes per
			// input byte (ASCII control characters). Quotes add two bytes.
			"ToolRun.Capability": 6*128 + 2, "PreparedStepV1.Capability": 6*128 + 2,
			"PreparedStepV1.ErrorClassification": 6*64 + 2, "PreparedStepV1.ErrorDetails": 6*SafeMessageMaxBytes + 2,
		}
		if n, ok := encoded[field]; ok {
			return n
		}
	}
	t.Fatalf("unproved prepared field %s (%s)", field, typ)
	return 0
}

func TestPreparedEncodingCompositionalMaximum(t *testing.T) {
	for _, c := range []struct {
		value   any
		ceiling int
	}{{PreparedManifestV1{}, PreparedManifestMaxBytes}, {PreparedControlV1{}, PreparedControlMaxBytes}} {
		upper := preparedEncodingUpperBound(t, reflect.TypeOf(c.value), "")
		t.Logf("%T compositional bound=%d ceiling=%d", c.value, upper, c.ceiling)
		if upper > c.ceiling {
			t.Fatalf("maximum encoding is not proved: %d > %d", upper, c.ceiling)
		}
	}
}

func TestPreparedEncodedFieldBudgetsRejectEscapingExpansion(t *testing.T) {
	for _, max := range []int{64, 255, DiagnosticMaxBytes} {
		if err := validatePreparedString("encoded", strings.Repeat("\x01", max), max); err == nil {
			t.Fatal("accepted over-budget escaped string")
		}
		if err := validatePreparedString("encoded", strings.Repeat("x", max), max); err != nil {
			t.Fatal(err)
		}
	}
}
