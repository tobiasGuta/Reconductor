package findings

import (
	"encoding/json"
	"testing"
)

func TestCandidateLifecycle(t *testing.T) {
	if err := Transition(New, Confirmed); err == nil {
		t.Fatal("candidate skipped verification")
	}
	if err := Transition(New, Queued); err != nil {
		t.Fatal(err)
	}
	if err := Transition(Queued, Verifying); err != nil {
		t.Fatal(err)
	}
	if err := Transition(Verifying, Confirmed); err != nil {
		t.Fatal(err)
	}
}
func TestSafeVerificationPlaybooks(t *testing.T) {
	v := Verify("openapi", VerificationInput{StatusCode: 200, Body: json.RawMessage(`{"openapi":"3.0.0","paths":{}}`)})
	if v.Verdict != VerdictManual || v.EvidenceVerdict != EvidenceObserved || v.ImpactVerdict != ImpactUnreviewed {
		t.Fatalf("got %s", v.Verdict)
	}
	v = Verify("missing-authentication", VerificationInput{UnauthenticatedStatusCode: 200})
	if v.Verdict != VerdictManual || v.EvidenceVerdict != EvidenceObserved || v.ImpactVerdict != ImpactUnreviewed {
		t.Fatal("missing auth must require human impact review")
	}
	v = Verify("openapi", VerificationInput{StatusCode: 404})
	if v.Verdict != VerdictRejected || v.EvidenceVerdict != EvidenceNotObserved || v.ImpactVerdict != ImpactRejected {
		t.Fatalf("missing behavior should be rejected evidence: %#v", v)
	}
}
