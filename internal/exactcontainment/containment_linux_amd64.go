//go:build linux && amd64

package exactcontainment

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/tobiasGuta/Reconductor/internal/exactactivation"
	"github.com/tobiasGuta/Reconductor/internal/exactsandbox"
)

const probeReply = "exact-containment-preflight/v1"

// Preflight requires the dedicated peer identity and executes the same strict
// profile, mandatory policy and fixed offline runtime as an invocation. It
// does not cache readiness or authorize anything. Missing packaging fails closed.
func Preflight(ctx context.Context) error {
	if ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, maxLifetime)
	defer cancel()
	if err := verifyCoordinator(); err != nil {
		return fmt.Errorf("%w: peer identity", ErrUnavailable)
	}
	a, err := fixedArtifacts()
	if err != nil {
		return err
	}
	defer a.close()
	return probe(ctx, a)
}

// ExecuteOffline is an unpromoted diagnostic integration entry point, not a
// Runner. Only frozen typed execution material is admitted. There are no
// production callers, command hooks, retries, or unsandboxed fallback paths.
func ExecuteOffline(ctx context.Context, input exactsandbox.EncodedExecution) (exactsandbox.EncodedResult, error) {
	if ctx == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw := input.Bytes()
	digest := input.Digest()
	if _, err := exactsandbox.DecodeExecution(raw, digest); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, maxLifetime)
	defer cancel()
	if err := verifyCoordinator(); err != nil {
		return nil, fmt.Errorf("%w: peer identity", ErrUnavailable)
	}
	a, err := fixedArtifacts()
	if err != nil {
		return nil, err
	}
	defer a.close()
	if err = probe(ctx, a); err != nil {
		return nil, err
	}
	return exchange(ctx, a, raw, digest)
}

func probe(ctx context.Context, a artifacts) error {
	_, err := transact(ctx, a, true, nil, len(probeReply), func(b []byte) error {
		if !bytes.Equal(b, []byte(probeReply)) {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: strict profile probe: %w", ErrUnavailable, err)
	}
	return nil
}
func exchange(ctx context.Context, a artifacts, raw []byte, digest string) (exactsandbox.EncodedResult, error) {
	if len(raw) > exactsandbox.MaxExecutionBytes {
		return nil, exactsandbox.ErrProtocol
	}
	raw = append([]byte(nil), raw...)
	if _, err := exactsandbox.DecodeExecution(raw, digest); err != nil {
		return nil, err
	}
	b, err := transact(ctx, a, false, raw, exactsandbox.MaxResultBytes, func(b []byte) error {
		r, e := exactsandbox.DecodeResult(b, digest)
		if e == nil && r.Completed {
			return exactsandbox.ErrProtocol
		}
		return e
	})
	return exactsandbox.EncodedResult(b), err
}

func verifyCoordinator() error {
	if err := exactactivation.VerifyPeerCredentials(); err != nil {
		return err
	}
	return exactactivation.VerifyPeerEnvironment(os.Environ())
}
