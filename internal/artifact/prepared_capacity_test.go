package artifact

import (
	"bytes"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

func TestPreparedCapacityAggregatePreflight(t *testing.T) {
	for _, tc := range []struct {
		name    string
		control int64
		members []int64
		limit   int64
		reject  bool
	}{
		{"exact", 2, []int64{3, 4}, 10, false},
		{"one oversized member", 1, []int64{20}, 10, true},
		{"aggregate", 2, []int64{4, 4}, 10, true},
		{"integer overflow", 1, []int64{math.MaxInt64, math.MaxInt64}, 10, true},
		{"manifest charged", 0, []int64{10}, 10, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := PreparedStageRequest{ReservedCapacityBytes: tc.limit, ManifestJSON: []byte("m"), Control: PreparedStageObject{ExpectedSize: tc.control}}
			for _, n := range tc.members {
				r.Members = append(r.Members, PreparedStageObject{ExpectedSize: n})
			}
			err := r.ValidateCapacity()
			if (err != nil) != tc.reject {
				t.Fatalf("error=%v", err)
			}
			if tc.reject {
				var limit *PreparedCapacityError
				if !errors.As(err, &limit) || limit.ResultContractLimit().Validate() != nil {
					t.Fatalf("not a typed valid limit: %v", err)
				}
			}
		})
	}
}

type failingCapacityWriter struct {
	buffer    bytes.Buffer
	remaining int
}

func (w *failingCapacityWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		p = p[:w.remaining]
		n, _ := w.buffer.Write(p)
		w.remaining = 0
		return n, io.ErrClosedPipe
	}
	w.remaining -= len(p)
	return w.buffer.Write(p)
}

func TestPreparedStreamNeverWritesProbeByte(t *testing.T) {
	for _, n := range []int{0, 9, 10, 11, 100000} {
		var written bytes.Buffer
		count, err := copyPreparedBounded(&written, strings.NewReader(strings.Repeat("x", n)), 10)
		if written.Len() > 10 || count != int64(written.Len()) {
			t.Fatalf("physical bytes=%d count=%d", written.Len(), count)
		}
		if (n > 10) != errors.Is(err, ErrPreparedCapacityExceeded) {
			t.Fatalf("source=%d error=%v", n, err)
		}
	}
	w := &failingCapacityWriter{remaining: 4}
	count, err := copyPreparedBounded(w, strings.NewReader(strings.Repeat("x", 100)), 10)
	if !errors.Is(err, io.ErrClosedPipe) || count != 4 || w.buffer.Len() != 4 {
		t.Fatalf("partial count=%d bytes=%d error=%v", count, w.buffer.Len(), err)
	}
}
