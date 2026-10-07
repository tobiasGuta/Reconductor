package normalize

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
)

func TestProbeSourceDecorationEnforcesInputAndExpandedOutputBudget(t *testing.T) {
	raw := json.RawMessage(`{"authorized_records":[{"provider":"httpx","kind":"url","target":"https://example.test/"}]}`)
	input := json.RawMessage(`{}`)
	for _, limit := range []int{len(raw) - 1, len(raw) + 1} {
		_, err := AttachProbeHTTPSourceRecordsBounded(raw, "program", "attempt", input, limit)
		var overflow *canonicaljson.EncodingLimitError
		if !errors.As(err, &overflow) {
			t.Fatalf("limit=%d err=%v", limit, err)
		}
	}
	want, err := AttachProbeHTTPSourceRecords(raw, "program", "attempt", input)
	if err != nil {
		t.Fatal(err)
	}
	_, want, _, _, err = canonicaljson.ParseStrict(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := AttachProbeHTTPSourceRecordsBounded(raw, "program", "attempt", input, len(want))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("within-bound decoration changed: %s %v", got, err)
	}
}
