//go:build linux

package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type localPreparedRecoveryGuard struct {
	local    *Local
	marker   *os.File
	rootFD   int
	identity StoreIdentity
	once     sync.Once
	err      error
}

func (l *Local) AcquirePreparedRecovery(ctx context.Context, expected StoreIdentity) (PreparedRecoveryGuard, error) {
	marker, rootFD, identity, err := l.acquirePinnedStore(ctx, expected, unix.LOCK_EX)
	if err != nil {
		return nil, err
	}
	return &localPreparedRecoveryGuard{local: l, marker: marker, rootFD: rootFD, identity: identity}, nil
}

func (g *localPublisherGuard) StagePrepared(ctx context.Context, request PreparedStageRequest) (PreparedStageReceipt, error) {
	if g == nil || g.marker == nil {
		return PreparedStageReceipt{}, fmt.Errorf("publisher guard is closed")
	}
	manifest, manifestDigest, err := validatePreparedStageRequest(g.identity, request)
	if err != nil {
		return PreparedStageReceipt{}, err
	}
	if err := validatePinnedMarker(g.rootFD, g.marker); err != nil {
		return PreparedStageReceipt{}, err
	}
	rootFD := g.rootFD
	objects := append([]PreparedStageObject{request.Control}, request.Members...)
	contentBytes := int64(0)
	remaining := request.ReservedCapacityBytes
	for _, object := range objects {
		if err := ctx.Err(); err != nil {
			return PreparedStageReceipt{}, err
		}
		reader, err := object.Source.Open()
		if err != nil {
			return PreparedStageReceipt{}, err
		}
		written, writeErr := writePreparedExclusive(rootFD, object.StorageKey, reader, object.ExpectedSize, object.ExpectedSHA256, remaining)
		remaining -= written
		err = writeErr
		if errors.Is(err, ErrPreparedCapacityExceeded) {
			err = &PreparedCapacityError{Limit: uint64(request.ReservedCapacityBytes), Observed: uint64(request.ReservedCapacityBytes) + 1}
		}
		closeErr := reader.Close()
		if err != nil || closeErr != nil {
			return PreparedStageReceipt{}, errors.Join(err, closeErr)
		}
		contentBytes += object.ExpectedSize
	}
	// manifest.json is deliberately created after every referenced object.
	if _, err := writePreparedExclusive(rootFD, request.ManifestKey, bytes.NewReader(request.ManifestJSON), int64(len(request.ManifestJSON)), manifestDigest, remaining); err != nil {
		return PreparedStageReceipt{}, err
	}
	if err := storeFsync(rootFD); err != nil {
		return PreparedStageReceipt{}, err
	}
	return PreparedStageReceipt{ManifestSize: int64(len(request.ManifestJSON)), ManifestSHA256: manifestDigest, MemberCount: len(manifest.Members), ContentBytes: contentBytes, Durable: true}, nil
}

func (g *localPublisherGuard) OpenPrepared(ctx context.Context, key string, size int64, digest [32]byte) (io.ReadCloser, error) {
	if g == nil {
		return nil, fmt.Errorf("publisher guard is closed")
	}
	if err := validatePinnedMarker(g.rootFD, g.marker); err != nil {
		return nil, err
	}
	return openPreparedVerified(ctx, g.rootFD, key, size, digest)
}

func (g *localPreparedRecoveryGuard) Identity() StoreIdentity { return g.identity }

func (g *localPreparedRecoveryGuard) PublishReserved(ctx context.Context, reserved ReservedArtifactV1, source io.Reader) (PublishedArtifactV1, error) {
	if g == nil || g.marker == nil || g.rootFD < 0 {
		return PublishedArtifactV1{}, fmt.Errorf("prepared recovery guard is closed")
	}
	return (&localPublisherGuard{local: g.local, marker: g.marker, rootFD: g.rootFD, identity: g.identity}).PublishReserved(ctx, reserved, source)
}

func (g *localPreparedRecoveryGuard) OpenPrepared(ctx context.Context, key string, size int64, digest [32]byte) (io.ReadCloser, error) {
	if g == nil || g.marker == nil || g.rootFD < 0 {
		return nil, fmt.Errorf("prepared recovery guard is closed")
	}
	if err := validatePinnedMarker(g.rootFD, g.marker); err != nil {
		return nil, err
	}
	return openPreparedVerified(ctx, g.rootFD, key, size, digest)
}

func (g *localPreparedRecoveryGuard) VerifyReserved(ctx context.Context, reserved ReservedArtifactV1) (PublishedArtifactV1, bool, error) {
	if g == nil || reserved.ArtifactStoreID != g.identity.ArtifactStoreID {
		return PublishedArtifactV1{}, false, fmt.Errorf("recovery identity contradiction")
	}
	if err := validatePinnedMarker(g.rootFD, g.marker); err != nil {
		return PublishedArtifactV1{}, false, err
	}
	if err := ValidateStorageKey(reserved.StorageKey, reserved.ArtifactID); err != nil {
		return PublishedArtifactV1{}, false, err
	}
	reader, err := openPreparedVerified(ctx, g.rootFD, reserved.StorageKey, reserved.ExpectedSize, reserved.ExpectedSHA256)
	if errors.Is(err, unix.ENOENT) {
		return PublishedArtifactV1{}, false, nil
	}
	if err != nil {
		return PublishedArtifactV1{}, true, &PublicationUnverifiableError{Err: err}
	}
	_, readErr := io.Copy(io.Discard, reader)
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return PublishedArtifactV1{}, true, &PublicationUnverifiableError{Err: err}
	}
	return PublishedArtifactV1{SizeBytes: reserved.ExpectedSize, SHA256: reserved.ExpectedSHA256, Durable: true}, true, nil
}

func (g *localPreparedRecoveryGuard) InspectPrepared(ctx context.Context, setID domain.ID) (PreparedInspection, error) {
	if err := validatePinnedMarker(g.rootFD, g.marker); err != nil {
		return PreparedInspection{}, err
	}
	manifestKey, err := domain.PreparedManifestKey(setID)
	if err != nil {
		return PreparedInspection{}, err
	}
	manifestJSON, err := readPreparedBounded(ctx, g.rootFD, manifestKey, domain.PreparedManifestMaxBytes)
	if err != nil {
		return PreparedInspection{}, err
	}
	manifest, err := domain.DecodePreparedManifestV1(manifestJSON)
	if err != nil || manifest.SetID != setID || manifest.ArtifactStoreID != g.identity.ArtifactStoreID || manifest.StoreIncarnationNonce != g.identity.IncarnationNonce {
		return PreparedInspection{}, fmt.Errorf("prepared manifest identity contradiction: %w", err)
	}
	controlDigest, err := decodePreparedDigest(manifest.Control.ContentSHA256)
	if err != nil {
		return PreparedInspection{}, err
	}
	controlReader, err := openPreparedVerified(ctx, g.rootFD, manifest.Control.StorageKey, manifest.Control.ContentSizeBytes, controlDigest)
	if err != nil {
		return PreparedInspection{}, err
	}
	controlJSON, readErr := io.ReadAll(io.LimitReader(controlReader, domain.PreparedControlMaxBytes+1))
	closeErr := controlReader.Close()
	if readErr != nil || closeErr != nil || len(controlJSON) > domain.PreparedControlMaxBytes {
		return PreparedInspection{}, errors.Join(readErr, closeErr, fmt.Errorf("prepared control is oversized"))
	}
	control, err := domain.DecodePreparedControlV1(controlJSON)
	if err != nil || control.SetID != setID || control.ManifestID != manifest.ManifestID || control.Envelope.ResultOccurrenceID != manifest.ResultOccurrenceID {
		return PreparedInspection{}, fmt.Errorf("prepared control identity contradiction: %w", err)
	}
	for _, member := range manifest.Members {
		digest, err := decodePreparedDigest(member.ContentSHA256)
		if err != nil {
			return PreparedInspection{}, err
		}
		reader, err := openPreparedVerified(ctx, g.rootFD, member.PreparedKey, member.ContentSizeBytes, digest)
		if err != nil {
			return PreparedInspection{}, err
		}
		_, copyErr := io.Copy(io.Discard, reader)
		closeErr := reader.Close()
		if copyErr != nil || closeErr != nil {
			return PreparedInspection{}, errors.Join(copyErr, closeErr)
		}
	}
	// Re-establish the last manifest barrier only after control/member bytes
	// were verified and synchronized. Readability alone never seals a set.
	lastManifest, err := readPreparedBounded(ctx, g.rootFD, manifestKey, domain.PreparedManifestMaxBytes)
	if err != nil || !bytes.Equal(lastManifest, manifestJSON) {
		return PreparedInspection{}, errors.Join(err, fmt.Errorf("manifest changed during durable inspection"))
	}
	return PreparedInspection{Manifest: manifest, ManifestJSON: manifestJSON, Control: control, ControlJSON: controlJSON, Durable: true}, nil
}

func (g *localPreparedRecoveryGuard) DeleteResolvedPrepared(ctx context.Context, record domain.PreparedSetRecord) (PreparedDeletionOutcome, error) {
	if err := validatePinnedMarker(g.rootFD, g.marker); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if record.State != domain.PreparedResolvedAdopted && record.State != domain.PreparedResolvedAbandoned {
		return "", fmt.Errorf("prepared cleanup requires authoritative resolution")
	}
	if record.ArtifactStoreID != g.identity.ArtifactStoreID || record.StoreIncarnationNonce != g.identity.IncarnationNonce {
		return "", fmt.Errorf("prepared cleanup store identity contradiction")
	}
	setID := record.ID
	manifestKey, err := domain.PreparedManifestKey(setID)
	if err != nil {
		return "", err
	}
	keys := []string{}
	if len(record.NonadmissionDetails) > 0 {
		// Rejection may precede the manifest. The resolved DB set authorizes
		// only this fixed namespace, never recursive or wildcard deletion.
		if record.State != domain.PreparedResolvedAbandoned || record.ResultOccurrenceID == nil || record.ProviderTerminalEventID == nil {
			return "", fmt.Errorf("invalid nonadmission cleanup authority")
		}
		controlKey, _ := domain.PreparedControlKey(setID)
		keys = append(keys, controlKey)
		for ordinal := 0; ordinal < domain.ResultArtifactReferenceMaxCount; ordinal++ {
			key, _ := domain.PreparedMemberKey(setID, ordinal)
			keys = append(keys, key)
		}
	} else {
		// Members/control may already be absent after a cleanup crash. Only
		// the DB-anchored manifest is needed to resume the deletion plan.
		raw, err := readPreparedBounded(ctx, g.rootFD, manifestKey, domain.PreparedManifestMaxBytes)
		if errors.Is(err, unix.ENOENT) {
			if err := removePreparedSetDirectory(g.rootFD, setID); err != nil {
				return "", err
			}
			return PreparedContentAlreadyAbsent, nil
		}
		if err != nil {
			return "", err
		}
		manifest, err := domain.DecodePreparedManifestV1(raw)
		if err != nil {
			return "", err
		}
		if record.ManifestSHA256 == nil || record.ManifestSizeBytes == nil || record.MemberCount == nil || record.ResultOccurrenceID == nil ||
			*record.ManifestSHA256 != DigestString(DigestBytes(raw)) || *record.ManifestSizeBytes != int64(len(raw)) || *record.MemberCount != len(manifest.Members) ||
			manifest.SetID != setID || manifest.ManifestID != record.ManifestID || manifest.ResultOccurrenceID != *record.ResultOccurrenceID || manifest.ArtifactStoreID != record.ArtifactStoreID || manifest.StoreIncarnationNonce != record.StoreIncarnationNonce {
			return "", fmt.Errorf("prepared cleanup manifest does not match resolved database anchors")
		}
		keys = append(keys, manifest.Control.StorageKey)
		for _, member := range manifest.Members {
			keys = append(keys, member.PreparedKey)
		}
	}
	keys = append(keys, manifestKey)
	for _, key := range keys {
		if err := unlinkPrepared(g.rootFD, key); err != nil {
			return "", err
		}
	}
	if err := removePreparedSetDirectory(g.rootFD, setID); err != nil {
		return "", err
	}
	return PreparedContentRemoved, nil
}

func (g *localPreparedRecoveryGuard) Close() error {
	if g == nil {
		return nil
	}
	g.once.Do(func() {
		if g.rootFD >= 0 {
			g.err = errors.Join(g.err, unix.Close(g.rootFD))
			g.rootFD = -1
		}
		if g.marker != nil {
			g.err = errors.Join(g.err, unix.Flock(int(g.marker.Fd()), unix.LOCK_UN), g.marker.Close())
			g.marker = nil
		}
	})
	return g.err
}

func writePreparedExclusive(rootFD int, key string, source io.Reader, expectedSize int64, expectedDigest [32]byte, remaining int64) (int64, error) {
	parentFD, name, err := openPreparedParent(rootFD, key, true)
	if err != nil {
		return 0, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return 0, err
	}
	file := os.NewFile(uintptr(fd), name)
	hash := sha256.New()
	written, copyErr := copyPreparedBounded(io.MultiWriter(file, hash), source, remaining)
	syncErr := storeFsync(int(file.Fd()))
	closeErr := file.Close()
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	if copyErr != nil || syncErr != nil || closeErr != nil || written != expectedSize || digest != expectedDigest {
		return written, errors.Join(copyErr, syncErr, closeErr, fmt.Errorf("prepared object verification failed"))
	}
	return written, storeFsync(parentFD)
}

func openPreparedVerified(ctx context.Context, rootFD int, key string, size int64, digest [32]byte) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parentFD, name, err := openPreparedParent(rootFD, key, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size != size {
		unix.Close(fd)
		return nil, fmt.Errorf("prepared object inode or length is unsafe: %w", err)
	}
	if err := errors.Join(storeFsync(fd), syncPinnedDirectories(rootFD, key)); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return newVerifiedPreparedReader(os.NewFile(uintptr(fd), name), size, digest), nil
}

func readPreparedBounded(ctx context.Context, rootFD int, key string, max int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parentFD, name, err := openPreparedParent(rootFD, key, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parentFD)
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size < 1 || stat.Size > int64(max) {
		unix.Close(fd)
		return nil, fmt.Errorf("prepared bounded object inode or length is unsafe: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	raw, readErr := io.ReadAll(io.LimitReader(file, int64(max)+1))
	syncErr := storeFsync(int(file.Fd()))
	closeErr := file.Close()
	return raw, errors.Join(readErr, syncErr, closeErr, syncPinnedDirectories(rootFD, key))
}

func openPreparedParent(rootFD int, key string, create bool) (int, string, error) {
	return openStoreParent(rootFD, key, create)
}

func preparedKeyParts(key string) ([]string, error) {
	if strings.Contains(key, "\\") {
		return nil, fmt.Errorf("prepared key contains platform separator")
	}
	parts := strings.Split(key, "/")
	if len(parts) < 4 || parts[0] != "prepared" || parts[1] != "v1" {
		return nil, fmt.Errorf("prepared key is outside namespace")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("prepared key contains unsafe component")
		}
	}
	return parts, nil
}

func decodePreparedDigest(value string) ([32]byte, error) {
	var digest [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(digest) {
		return digest, fmt.Errorf("invalid prepared digest")
	}
	copy(digest[:], decoded)
	return digest, nil
}

func unlinkPrepared(rootFD int, key string) error {
	parentFD, name, err := openPreparedParent(rootFD, key, false)
	if errors.Is(err, unix.ENOENT) {
		return syncExistingPinnedAncestors(rootFD, key)
	}
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	var stat unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	} else if err == nil && (stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1) {
		return fmt.Errorf("unsafe prepared cleanup inode")
	}
	if err := unix.Unlinkat(parentFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return storeFsync(parentFD)
}

func removePreparedSetDirectory(rootFD int, setID domain.ID) error {
	prefix, err := domain.PreparedSetPrefix(setID)
	if err != nil {
		return err
	}
	parentFD, name, err := openPreparedParent(rootFD, prefix, false)
	if errors.Is(err, unix.ENOENT) {
		return syncExistingPinnedAncestors(rootFD, prefix)
	}
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return storeFsync(parentFD)
}
