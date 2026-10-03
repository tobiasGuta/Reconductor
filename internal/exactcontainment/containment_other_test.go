//go:build !linux || !amd64

package exactcontainment

import (
	"context"
	"errors"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/exactsandbox"
)

func TestUnsupportedFailsClosed(t *testing.T) {
	if e := Preflight(context.Background()); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if b, e := ExecuteOffline(context.Background(), exactsandbox.EncodedExecution{}); b != nil || !errors.Is(e, ErrUnavailable) {
		t.Fatal(b, e)
	}
}
