package canonicaljson

import (
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestCanonicalExpansionStopsBeforeProportionalCopy(t *testing.T) {
	raw := []byte("[" + strings.Repeat("1e4000,", 1800) + "0]")
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, canonical, _, _, err := ParseStrictBounded(raw, 16384)
	runtime.ReadMemStats(&after)
	var bound *EncodingLimitError
	if !errors.As(err, &bound) || canonical != nil {
		t.Fatalf("canonical=%d err=%v", len(canonical), err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 2<<20 {
		t.Fatalf("canonical expansion allocated %d bytes", allocated)
	}
}

func TestBoundedCanonicalParityAtExactCeiling(t *testing.T) {
	for _, raw := range []string{`{"b":[1e2,"<\n"],"a":true}`, `[null,1.0,-0,1e-3]`} {
		_, want, _, _, err := ParseStrict([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		limit := len(want)
		if len(raw) > limit {
			limit = len(raw)
		}
		_, got, _, _, err := ParseStrictBounded([]byte(raw), limit)
		if err != nil || string(got) != string(want) {
			t.Fatalf("got=%s want=%s err=%v", got, want, err)
		}
	}
}
