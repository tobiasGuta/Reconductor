//go:build linux

package artifact

import (
	"context"
	"errors"
	"fmt"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// One synchronization boundary permits deterministic failure injection in
// serial native filesystem tests. Production always uses unix.Fsync.
var storeFsync = unix.Fsync

func openPinnedRoot(path string) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, fmt.Errorf("store root is not absolute")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			unix.Close(fd)
			return -1, fmt.Errorf("unsafe root component")
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

func (l *Local) acquirePinnedStore(ctx context.Context, expected StoreIdentity, lock int) (*os.File, int, StoreIdentity, error) {
	if l == nil || !l.initialized || expected != l.identity || l.rootInfo == nil || l.markerInfo == nil {
		return nil, -1, StoreIdentity{}, fmt.Errorf("store identity unavailable")
	}
	if err := expected.Validate(); err != nil {
		return nil, -1, StoreIdentity{}, err
	}
	fd, err := openPinnedRoot(l.root)
	if err != nil {
		return nil, -1, StoreIdentity{}, err
	}
	root := os.NewFile(uintptr(fd), "artifact-root")
	fail := func(err error) (*os.File, int, StoreIdentity, error) {
		root.Close()
		return nil, -1, StoreIdentity{}, err
	}
	info, err := root.Stat()
	if err != nil || !os.SameFile(l.rootInfo, info) {
		return fail(fmt.Errorf("registered store root was replaced"))
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return fail(err)
	}
	if filesystem.Type != extSuperMagic && filesystem.Type != xfsSuperMagic && uint64(filesystem.Type) != btrfsSuperMagic {
		return fail(fmt.Errorf("%w: filesystem magic %#x", ErrPreparedStoreUnsupported, filesystem.Type))
	}
	markerFD, err := unix.Openat(fd, markerName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	marker := os.NewFile(uintptr(markerFD), markerName)
	failMarker := func(err error) (*os.File, int, StoreIdentity, error) { marker.Close(); return fail(err) }
	markerInfo, err := marker.Stat()
	if err != nil || !os.SameFile(l.markerInfo, markerInfo) {
		return failMarker(fmt.Errorf("registered store marker was replaced"))
	}
	for {
		if err := ctx.Err(); err != nil {
			return failMarker(err)
		}
		err = unix.Flock(markerFD, lock|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return failMarker(err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return failMarker(ctx.Err())
		case <-timer.C:
		}
	}
	if err := validatePinnedMarker(fd, marker); err != nil {
		return failMarker(err)
	}
	registration, err := readMarkerFrom(marker)
	if err != nil {
		return failMarker(err)
	}
	actual := StoreIdentityFrom(domain.ArtifactStore{ArtifactStoreRegistration: registration})
	if actual != expected {
		return failMarker(fmt.Errorf("pinned store incarnation contradiction"))
	}
	if err := storeFsync(fd); err != nil {
		return failMarker(err)
	}
	// Transfer descriptor ownership without leaving an os.File finalizer able
	// to close a guard's live fd. Dup belongs solely to the returned guard.
	guardFD, err := unix.Dup(fd)
	if err != nil {
		return failMarker(err)
	}
	root.Close()
	return marker, guardFD, actual, nil
}

func validatePinnedMarker(rootFD int, marker *os.File) error {
	if marker == nil || rootFD < 0 {
		return fmt.Errorf("store guard is closed")
	}
	var opened, named unix.Stat_t
	if err := unix.Fstat(int(marker.Fd()), &opened); err != nil {
		return err
	}
	if err := unix.Fstatat(rootFD, markerName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino || opened.Nlink != 1 || named.Nlink != 1 || opened.Mode&unix.S_IFMT != unix.S_IFREG || named.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("pinned marker authority changed")
	}
	return nil
}

// openStoreParent accepts only the two canonical, already validated namespaces.
// Every component is pinned independently; neither symlinks nor path traversal
// can redirect an authoritative operation outside the held root descriptor.
func openStoreParent(rootFD int, key string, create bool) (int, string, error) {
	parts := strings.Split(key, "/")
	if strings.Contains(key, "\\") || len(parts) < 3 || (parts[0] != "v1" && !(parts[0] == "prepared" && parts[1] == "v1")) {
		return -1, "", fmt.Errorf("invalid store namespace")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return -1, "", fmt.Errorf("unsafe store key")
		}
	}
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, "", err
	}
	for _, part := range parts[:len(parts)-1] {
		if create {
			if err := unix.Mkdirat(current, part, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				unix.Close(current)
				return -1, "", err
			}
		}
		next, err := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			unix.Close(current)
			return -1, "", err
		}
		if create {
			if err := storeFsync(current); err != nil {
				unix.Close(next)
				unix.Close(current)
				return -1, "", err
			}
		}
		unix.Close(current)
		current = next
	}
	return current, parts[len(parts)-1], nil
}

func syncPinnedDirectories(rootFD int, key string) error {
	// Re-walk using pinned descriptors solely to synchronize containing
	// directory entries up to the same held root, propagating every failure.
	parts := strings.Split(key, "/")
	current, err := unix.Dup(rootFD)
	if err != nil {
		return err
	}
	for _, part := range parts[:len(parts)-1] {
		if err := storeFsync(current); err != nil {
			unix.Close(current)
			return err
		}
		next, err := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(current)
		if err != nil {
			return err
		}
		current = next
	}
	return errors.Join(storeFsync(current), unix.Close(current))
}

type guardedArtifactReader struct {
	io.ReadCloser
	guard PublisherGuard
}

// Establish durability of an already-absent path without reopening a pathname.
// Missing ancestors are success only after their nearest existing parent syncs.
func syncExistingPinnedAncestors(rootFD int, key string) error {
	current, err := unix.Dup(rootFD)
	if err != nil {
		return err
	}
	for _, part := range strings.Split(key, "/")[:len(strings.Split(key, "/"))-1] {
		if err := storeFsync(current); err != nil {
			unix.Close(current)
			return err
		}
		next, err := unix.Openat(current, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(current)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err != nil {
			return err
		}
		current = next
	}
	return errors.Join(storeFsync(current), unix.Close(current))
}

func (l *Local) deleteAuthoritativeArtifact(ctx context.Context, key string) (outcome ContentDeletionOutcome, returnedErr error) {
	guard, err := l.AcquirePreparedRecovery(ctx, l.identity)
	if err != nil {
		return "", err
	}
	defer func() { returnedErr = errors.Join(returnedErr, guard.Close()) }()
	g := guard.(*localPreparedRecoveryGuard)
	parent, name, err := openStoreParent(g.rootFD, key, false)
	if errors.Is(err, unix.ENOENT) {
		return ContentAlreadyAbsent, syncExistingPinnedAncestors(g.rootFD, key)
	}
	if err != nil {
		return "", err
	}
	defer unix.Close(parent)
	var stat unix.Stat_t
	err = unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return ContentAlreadyAbsent, syncExistingPinnedAncestors(g.rootFD, key)
	}
	if err != nil {
		return "", err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return "", ErrUnexpectedEntryType
	}
	if err := unix.Unlinkat(parent, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return "", err
	}
	if err := errors.Join(storeFsync(parent), syncPinnedDirectories(g.rootFD, key)); err != nil {
		return "", &DurabilitySyncError{Err: err}
	}
	return ContentRemoved, nil
}

func (r *guardedArtifactReader) Close() error {
	return errors.Join(r.ReadCloser.Close(), r.guard.Close())
}

// OpenVerified uses authority already held by this guard; acquiring another
// filesystem lock here would reverse recovery's store-before-database order.
func (g *localPublisherGuard) OpenVerified(ctx context.Context, reference domain.ResultArtifactRefV1) (io.ReadCloser, error) {
	if g == nil || g.marker == nil || g.rootFD < 0 || reference.ArtifactStoreID != g.identity.ArtifactStoreID {
		return nil, fmt.Errorf("semantic artifact store identity mismatch")
	}
	if err := reference.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validatePinnedMarker(g.rootFD, g.marker); err != nil {
		return nil, err
	}
	digest, err := decodePreparedDigest(reference.ContentSHA256)
	if err != nil {
		return nil, err
	}
	return openPreparedVerified(ctx, g.rootFD, reference.StorageKey, reference.ContentSizeBytes, digest)
}

func (l *Local) openAuthoritativeArtifact(ctx context.Context, reference domain.ResultArtifactRefV1) (io.ReadCloser, error) {
	guard, err := l.AcquirePublisher(ctx, l.identity)
	if err != nil {
		return nil, err
	}
	g := guard.(*localPublisherGuard)
	digest, err := decodePreparedDigest(reference.ContentSHA256)
	if err != nil {
		guard.Close()
		return nil, err
	}
	reader, err := openPreparedVerified(ctx, g.rootFD, reference.StorageKey, reference.ContentSizeBytes, digest)
	if err != nil {
		guard.Close()
		return nil, err
	}
	return &guardedArtifactReader{ReadCloser: reader, guard: guard}, nil
}
