package providers

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/domain"
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

func TestCompareAssetsKeepsEveryChangeWithinBindingContract(t *testing.T) {
	previous := make([]string, 57)
	for index := range previous {
		target := "https://asset-" + strconv.Itoa(index) + ".example.test/"
		previous[index] = `{"provider":"httpx","kind":"url","target":"` + target + `","status_code":200,"fields":{"body":"` + strings.Repeat("x", 4096) + `"}}`
	}
	input, err := json.Marshal(CompareAssetsInput{Current: []string{}, Previous: previous, CoverageComplete: true, TargetPlanDigest: "plan"})
	if err != nil {
		t.Fatal(err)
	}
	output, _, err := executeCompareAssets(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Changes) != len(previous) {
		t.Fatalf("changes=%d want=%d", len(output.Changes), len(previous))
	}
	encoded, err := json.Marshal(output.Changes)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > domain.InlineSemanticJSONMaxBytes {
		t.Fatalf("change binding bytes=%d limit=%d", len(encoded), domain.InlineSemanticJSONMaxBytes)
	}
	if strings.Contains(string(encoded), strings.Repeat("x", 64)) {
		t.Fatal("change projection retained bulk observation evidence")
	}
	for index, change := range output.Changes {
		if len(change.Previous) == 0 || !strings.Contains(string(change.Previous), `"target":"https://asset-`+strconv.Itoa(index)+`.example.test/"`) || !strings.Contains(string(change.Previous), `"status_code":200`) {
			t.Fatalf("change %d evidence=%s", index, change.Previous)
		}
	}
}
