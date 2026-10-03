package exactprocess

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type shortWriter struct {
	bytes.Buffer
	zero bool
	fail bool
}

func (w *shortWriter) Write(b []byte) (int, error) {
	if w.zero {
		return 0, nil
	}
	if len(b) > 2 {
		b = b[:2]
	}
	n, _ := w.Buffer.Write(b)
	if w.fail {
		return n, io.ErrClosedPipe
	}
	return n, nil
}

type fragmentedReader struct{ io.Reader }

func (r fragmentedReader) Read(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return r.Reader.Read(b)
}

func TestBoundedIO(t *testing.T) {
	for _, size := range []int{0, 1, 255, 256, 257, 4096} {
		b, err := readBounded(fragmentedReader{strings.NewReader(strings.Repeat("x", size))}, 256)
		if size > 256 {
			if !errors.Is(err, ErrOutputLimit) || b != nil {
				t.Fatalf("overflow size %d: %d, %v", size, len(b), err)
			}
		} else if err != nil || len(b) != size {
			t.Fatalf("inclusive bound size %d: %d, %v", size, len(b), err)
		}
	}
	w := &shortWriter{}
	if err := writeAll(w, []byte("abcdef")); err != nil || w.String() != "abcdef" {
		t.Fatal("partial write", err)
	}
	if err := writeAll(&shortWriter{zero: true}, []byte("a")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("zero write", err)
	}
	if err := writeAll(&shortWriter{fail: true}, []byte("abc")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("partial write error", err)
	}
	if _, err := readBounded(strings.NewReader("a"), -1); !errors.Is(err, ErrProcess) {
		t.Fatal(err)
	}
}
