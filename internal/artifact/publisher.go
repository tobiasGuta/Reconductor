package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type StoreIdentity struct {
	ArtifactStoreID  domain.ID
	IncarnationNonce domain.ID
	BackendKind      string
	MarkerFormat     string
	MarkerVersion    int
}

func StoreIdentityFrom(store domain.ArtifactStore) StoreIdentity {
	return StoreIdentity{ArtifactStoreID: store.ID, IncarnationNonce: store.IncarnationNonce, BackendKind: store.BackendKind, MarkerFormat: store.MarkerFormat, MarkerVersion: store.MarkerVersion}
}

func (s StoreIdentity) Validate() error {
	if _, err := domain.ParseID(string(s.ArtifactStoreID)); err != nil {
		return fmt.Errorf("publisher store ID is not canonical")
	}
	if _, err := domain.ParseID(string(s.IncarnationNonce)); err != nil {
		return fmt.Errorf("publisher store incarnation is not canonical")
	}
	if s.BackendKind != BackendKind || s.MarkerFormat != MarkerFormat || s.MarkerVersion != MarkerVersion {
		return fmt.Errorf("publisher store identity is unsupported")
	}
	return nil
}

type ReplayableSource interface {
	Open() (io.ReadCloser, error)
	SizeBytes() int64
	SHA256() [32]byte
}

type ReservedArtifactV1 struct {
	PublicationID   domain.ID
	ArtifactID      domain.ID
	ArtifactStoreID domain.ID
	StorageKey      string
	ExpectedSize    int64
	ExpectedSHA256  [32]byte
}

type PublishedArtifactV1 struct {
	SizeBytes int64
	SHA256    [32]byte
	Durable   bool
}

type PublisherStore interface {
	AcquirePublisher(context.Context, StoreIdentity) (PublisherGuard, error)
}

type SemanticArtifactReader interface {
	OpenVerified(context.Context, domain.ResultArtifactRefV1) (io.ReadCloser, error)
}

type AuthorizedSemanticArtifactV1 struct {
	Reference          domain.ResultArtifactRefV1
	StoreIdentity      StoreIdentity
	CapabilityName     string
	CapabilityVersion  string
	OutputSchemaSHA256 string
}
type PublisherGuard interface {
	Identity() StoreIdentity
	PublishReserved(context.Context, ReservedArtifactV1, io.Reader) (PublishedArtifactV1, error)
	Close() error
}

type PublisherReleaseError struct{ Err error }

func (e *PublisherReleaseError) Error() string { return "release publisher guard: " + e.Err.Error() }
func (e *PublisherReleaseError) Unwrap() error { return e.Err }

type PublicationUnverifiableError struct{ Err error }

func (e *PublicationUnverifiableError) Error() string {
	return "publication is unverifiable: " + e.Err.Error()
}
func (e *PublicationUnverifiableError) Unwrap() error { return e.Err }

var ErrPublisherLockUnsupported = fmt.Errorf("publisher lock is unsupported on this platform or filesystem")

func DigestString(sum [32]byte) string { return hex.EncodeToString(sum[:]) }
func DigestBytes(data []byte) [32]byte { return sha256.Sum256(data) }
