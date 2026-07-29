package providers

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompareAssetsCarriesPreviousCurrentAndReasons(t *testing.T) {
	input, err := json.Marshal(CompareAssetsInput{
		Previous:         []string{`{"url":"https://app.example.test/","status_code":200,"technologies":["old"]}`},
		Current:          []string{`{"url":"https://app.example.test/","status_code":401,"technologies":["new"]}`},
		CoverageComplete: true,
		TargetPlanDigest: "plan",
	})
	if err != nil {
		t.Fatal(err)
	}
	output, _, err := executeCompareAssets(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Changes) != 1 {
		t.Fatalf("changes = %#v", output.Changes)
	}
	change := output.Changes[0]
	if len(change.Previous) == 0 || len(change.Current) == 0 {
		t.Fatalf("missing structured evidence: %#v", change)
	}
	reasons := strings.Join(change.Reasons, " ")
	if !strings.Contains(reasons, "HTTP status changed") || !strings.Contains(reasons, "technology changed") {
		t.Fatalf("reasons = %#v", change.Reasons)
	}
}
