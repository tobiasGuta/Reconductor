//go:build !linux || !amd64

package exactcontainment

import (
	"context"

	"github.com/tobiasGuta/Reconductor/internal/exactsandbox"
)

func Preflight(context.Context) error { return ErrUnavailable }
func ExecuteOffline(context.Context, exactsandbox.EncodedExecution) (exactsandbox.EncodedResult, error) {
	return nil, ErrUnavailable
}
