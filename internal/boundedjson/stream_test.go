package boundedjson

import (
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
)

type repeatedByte struct{ remaining int64 }

func (r *repeatedByte) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for i := range p[:n] {
		p[i] = 'x'
	}
	r.remaining -= int64(n)
	return n, nil
}

func TestSkippedHugeScalarUsesFixedMemory(t *testing.T) {
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	input := io.MultiReader(strings.NewReader(`{"ignored":"`), &repeatedByte{remaining: 32 << 20}, strings.NewReader(`","chosen":{"v":1}}`))
	stream := New(input, 64)
	raw, found, err := stream.Select([]string{"chosen"}, 16384)
	if err != nil || !found || string(raw) != `{"v":1}` || stream.End() != nil {
		t.Fatalf("raw=%s found=%v err=%v", raw, found, err)
	}
	runtime.ReadMemStats(&after)
	if after.TotalAlloc-before.TotalAlloc > 2<<20 {
		t.Fatalf("skipped scalar allocated %d bytes", after.TotalAlloc-before.TotalAlloc)
	}
}

func TestHugeEmbeddedJSONSelectsSmallNestedFieldWithoutMaterializingString(t *testing.T) {
	input := io.MultiReader(strings.NewReader(`{"items":["{\"ignored\":\"`), &repeatedByte{remaining: 32 << 20}, strings.NewReader(`\",\"chosen\":\"ok\"}"]}`))
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	s := New(input, 64)
	raw, found, err := s.Select([]string{"items", "chosen"}, 16384)
	if err != nil || !found || string(raw) != `["ok"]` || s.End() != nil {
		t.Fatalf("raw=%s found=%v err=%v", raw, found, err)
	}
	runtime.ReadMemStats(&after)
	if n := after.TotalAlloc - before.TotalAlloc; n > 2<<20 {
		t.Fatalf("embedded string allocated %d", n)
	}
}

func TestSelectedValuesStopBeforeProportionalAllocation(t *testing.T) {
	for _, prefix := range []string{`"`, `["`, `{"v":"`} {
		source := &repeatedByte{remaining: 32 << 20}
		stream := New(io.MultiReader(strings.NewReader(prefix), source), 64)
		_, err := stream.ReadValue(16384)
		var limit *LimitError
		if !errors.As(err, &limit) || source.remaining < (32<<20)-32768 {
			t.Fatalf("prefix=%s consumed=%d error=%v", prefix, (32<<20)-source.remaining, err)
		}
	}
}

func TestMappedArrayAggregateIsBounded(t *testing.T) {
	stream := New(strings.NewReader(`{"items":[`+strings.Repeat(`{"x":"abcd"},`, 10000)+`{"x":"end"}]}`), 64)
	_, _, err := stream.Select([]string{"items", "x"}, 16384)
	var limit *LimitError
	if !errors.As(err, &limit) {
		t.Fatalf("error=%v", err)
	}
}

func TestSkippedValuesRejectMalformedJSON(t *testing.T) {
	for _, raw := range []string{`[1,]`, `{"x":true,}`, `"bad\x"`, `01`, `1e+`, `{"x":]}`, "\"\xff\""} {
		s := New(strings.NewReader(raw), 64)
		if err := s.Skip(); err == nil && s.End() == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
