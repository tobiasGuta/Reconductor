package resultadmission

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestCompilerRejectsBeforeCopyOrStrictParse(t *testing.T) {
	for _, size := range []int{(1 << 20) + 1, 8 << 20} {
		raw := json.RawMessage(strings.Repeat("[", size)) // would be malformed/deep if decoded
		compiled := compileTestResult(t, capability.Result{Action: domain.ActionResult{Status: "succeeded", Output: raw}}, `{}`)
		if compiled.Envelope.Error == nil || compiled.Envelope.Error.Code != "result_contract_limit" || compiled.Envelope.Error.Retryable || compiled.Envelope.SemanticOutput.Mode != domain.SemanticModeNone {
			t.Fatalf("envelope=%#v", compiled.Envelope)
		}
		for _, a := range compiled.Artifacts {
			if a.Source.SizeBytes() > domain.ResultEnvelopeMaxBytes {
				t.Fatal("oversized invalid output copied to evidence")
			}
		}
		compiled.Close()
	}
}

func TestCompilerTinyReservationAndCanonicalExpansion(t *testing.T) {
	for _, test := range []struct {
		raw   string
		limit int64
	}{{"null", 1}, {"1e1000", 128}} {
		compiled := compileTestResult(t, capability.Result{Action: domain.ActionResult{Status: "succeeded", Output: json.RawMessage(test.raw)}}, `{}`, test.limit)
		defer compiled.Close()
		if compiled.Envelope.Error == nil || compiled.Envelope.Error.Code != "result_contract_limit" || compiled.Envelope.Error.Retryable {
			t.Fatalf("limit=%d envelope=%#v", test.limit, compiled.Envelope)
		}
	}
}

func TestCompilerControlStringsCannotBypassByteAdmission(t *testing.T) {
	large := strings.Repeat("x", (1<<20)+1)
	for _, action := range []domain.ActionResult{
		{Status: "succeeded", Summary: large},
		{Status: "failed", Error: &domain.StructuredError{Classification: large, Message: "failed"}},
		{Status: "failed", Error: &domain.StructuredError{Classification: "provider_error", Message: large}},
	} {
		compiled := compileTestResult(t, capability.Result{Action: action}, `{}`)
		if compiled.Envelope.Error == nil || compiled.Envelope.Error.Code != "result_contract_limit" || compiled.Envelope.Error.Retryable {
			t.Fatalf("control string bypassed byte admission: %#v", compiled.Envelope)
		}
		compiled.Close()
	}
}
