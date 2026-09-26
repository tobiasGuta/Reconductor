package command

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/capability"
)

// Both pipe-copy goroutines share one byte authority. No Write grows storage
// past it; overflow cancels the process before returning a writer error.
type outputCapture struct {
	mu        sync.Mutex
	remaining int64
	limit     int64
	overflow  bool
	cancel    context.CancelFunc
}
type captureStream struct {
	capture *outputCapture
	data    []byte
}

func (s *captureStream) Write(p []byte) (int, error) {
	c := s.capture
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.overflow {
		return 0, &capability.OutputLimitError{Limit: c.limit}
	}
	n := len(p)
	if int64(n) > c.remaining {
		n = int(c.remaining)
	}
	// Explicit capped growth avoids append's capacity overshoot, even on the
	// final write. Initial allocations are demand driven, not reservation sized.
	if len(s.data)+n > cap(s.data) {
		next := 2 * cap(s.data)
		if next < len(s.data)+n {
			next = len(s.data) + n
		}
		if int64(next) > int64(len(s.data))+c.remaining {
			next = len(s.data) + int(c.remaining)
		}
		data := make([]byte, len(s.data), next)
		copy(data, s.data)
		s.data = data
	}
	s.data = append(s.data, p[:n]...)
	c.remaining -= int64(n)
	if n < len(p) {
		c.overflow = true
		c.cancel()
		return n, &capability.OutputLimitError{Limit: c.limit}
	}
	return n, nil
}

func runCaptured(ctx context.Context, name string, args []string, stdin []byte, limit int64) ([]byte, []byte, int, error) {
	if limit < 1 || limit > 1<<40 {
		return nil, nil, -1, errors.New("invalid provider output byte authority")
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	capture := &outputCapture{remaining: limit, limit: limit, cancel: cancel}
	out, stderr := &captureStream{capture: capture}, &captureStream{capture: capture}
	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Stdout = out
	cmd.Stderr = stderr
	// Bound inherited-pipe waits after cancellation/process exit. Go closes
	// pipes and joins copying goroutines; it does not drain rejected output.
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else {
			code = -1
		}
	}
	if capture.overflow {
		return out.data, stderr.data, code, &capability.OutputLimitError{Limit: limit}
	}
	return out.data, stderr.data, code, err
}
