package exactprocess

import (
	"errors"
	"io"
)

var (
	ErrProcess     = errors.New("exact process boundary rejected")
	ErrOutputLimit = errors.New("exact process output limit exceeded")
	ErrUnavailable = errors.New("exact process capability unavailable")
)

// readBounded requires EOF. The extra byte detects overflow without draining
// an attacker-controlled stream or retaining unbounded diagnostics.
func readBounded(r io.Reader, limit int) ([]byte, error) {
	if limit < 0 || limit > 64*1024 {
		return nil, ErrProcess
	}
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if len(b) > limit {
		return nil, ErrOutputLimit
	}
	return b, err
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) != 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
