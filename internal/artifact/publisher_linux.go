//go:build linux

package artifact

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

const (
	extSuperMagic   = 0xEF53
	xfsSuperMagic   = 0x58465342
	btrfsSuperMagic = 0x9123683E
)

type localPublisherGuard struct {
	local    *Local
	marker   *os.File
	rootFD   int
	identity StoreIdentity
	once     sync.Once
	closeErr error
}

func (l *Local) AcquirePublisher(ctx context.Context, expected StoreIdentity) (PublisherGuard, error) {
	marker, rootFD, identity, err := l.acquirePinnedStore(ctx, expected, unix.LOCK_SH)
	if err != nil {
		return nil, err
	}
	return &localPublisherGuard{local: l, marker: marker, rootFD: rootFD, identity: identity}, nil
}

func (g *localPublisherGuard) Identity() StoreIdentity { return g.identity }
func (g *localPublisherGuard) PublishReserved(ctx context.Context, r ReservedArtifactV1, source io.Reader) (PublishedArtifactV1, error) {
	if g == nil {
		return PublishedArtifactV1{}, fmt.Errorf("publisher guard is closed")
	}
	if err := validatePinnedMarker(g.rootFD, g.marker); err != nil {
		return PublishedArtifactV1{}, err
	}
	if err := ctx.Err(); err != nil {
		return PublishedArtifactV1{}, err
	}
	if r.ArtifactStoreID != g.identity.ArtifactStoreID || r.ExpectedSize < 0 {
		return PublishedArtifactV1{}, fmt.Errorf("reserved artifact identity mismatch")
	}
	if _, err := domain.ParseID(string(r.PublicationID)); err != nil {
		return PublishedArtifactV1{}, err
	}
	if err := ValidateStorageKey(r.StorageKey, r.ArtifactID); err != nil {
		return PublishedArtifactV1{}, err
	}
	parent, name, err := openStoreParent(g.rootFD, r.StorageKey, true)
	if err != nil {
		return PublishedArtifactV1{}, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return PublishedArtifactV1{}, &PublicationUnverifiableError{Err: err}
	}
	file := os.NewFile(uintptr(fd), name)
	hash := sha256.New()
	written, copyErr := copyPreparedBounded(io.MultiWriter(file, hash), source, r.ExpectedSize)
	syncErr := storeFsync(int(file.Fd()))
	closeErr := file.Close()
	var sum [32]byte
	copy(sum[:], hash.Sum(nil))
	if copyErr != nil || syncErr != nil || closeErr != nil || written != r.ExpectedSize || sum != r.ExpectedSHA256 {
		cause := errors.Join(copyErr, syncErr, closeErr, fmt.Errorf("publication content mismatch or durability failure"))
		if cleanupErr := unlinkCreatedPublication(parent, name); cleanupErr != nil {
			return PublishedArtifactV1{SizeBytes: written, SHA256: sum}, &PublicationUnverifiableError{Err: errors.Join(cause, fmt.Errorf("remove unverified publication: %w", cleanupErr))}
		}
		return PublishedArtifactV1{SizeBytes: written, SHA256: sum}, &PublicationRecoveryRequiredError{Err: cause}
	}
	if err := storeFsync(parent); err != nil {
		return PublishedArtifactV1{SizeBytes: written, SHA256: sum}, &PublicationRecoveryRequiredError{Err: fmt.Errorf("synchronize publication directory: %w", err)}
	}
	if err := validatePinnedMarker(g.rootFD, g.marker); err != nil {
		return PublishedArtifactV1{}, &PublicationUnverifiableError{Err: err}
	}
	return PublishedArtifactV1{SizeBytes: written, SHA256: sum, Durable: true}, nil
}

func unlinkCreatedPublication(parent int, name string) error {
	if err := unix.Unlinkat(parent, name, 0); err != nil {
		return err
	}
	return storeFsync(parent)
}

func (g *localPublisherGuard) Close() error {
	if g == nil {
		return nil
	}
	g.once.Do(func() {
		if g.marker == nil {
			return
		}
		g.closeErr = errors.Join(unix.Close(g.rootFD), syscall.Flock(int(g.marker.Fd()), syscall.LOCK_UN), g.marker.Close())
		g.rootFD = -1
		g.marker = nil
	})
	if g.closeErr != nil {
		return &PublisherReleaseError{Err: g.closeErr}
	}
	return nil
}
