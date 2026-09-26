//go:build !linux

package artifact

import (
	"context"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"io"
)

func (l *Local) openAuthoritativeArtifact(context.Context, domain.ResultArtifactRefV1) (io.ReadCloser, error) {
	return nil, ErrPreparedStoreUnsupported
}

func (l *Local) deleteAuthoritativeArtifact(context.Context, string) (ContentDeletionOutcome, error) {
	return "", ErrPreparedStoreUnsupported
}
