package artifact

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

var ErrPreparedStoreUnsupported = errors.New("prepared evidence store is unsupported on this platform or filesystem")
var ErrPreparedCapacityExceeded = errors.New("prepared stream exceeds authorized capacity")

type PreparedStageObject struct {
	StorageKey     string
	ExpectedSize   int64
	ExpectedSHA256 [32]byte
	Source         ReplayableSource
}

type PreparedStageRequest struct {
	// The durable allocation authorizes this total, including control and manifest.
	ReservedCapacityBytes int64
	SetID                 domain.ID
	ManifestID            domain.ID
	Control               PreparedStageObject
	Members               []PreparedStageObject
	ManifestKey           string
	ManifestJSON          []byte
}

// PreparedCapacityError describes known nonadmission, not a new lifecycle state.
// Observed is a lower bound when an aggregate cannot be represented exactly.
type PreparedCapacityError struct {
	Limit, Observed uint64
}

func (e *PreparedCapacityError) Error() string {
	return "result_contract_limit: prepared evidence exceeds its authorized reservation"
}
func (e *PreparedCapacityError) ResultContractLimit() domain.ResultContractLimitV1 {
	return domain.ResultContractLimitV1{Subject: domain.LimitPreparedEvidence, Unit: domain.LimitBytes, Limit: e.Limit, Observed: e.Observed}
}

// ValidateCapacity performs an overflow-safe preflight without opening sources or
// creating directories. Subtraction also bounds the aggregate of hostile lengths.
func (r PreparedStageRequest) ValidateCapacity() error {
	if r.ReservedCapacityBytes < 1 || r.ReservedCapacityBytes > domain.PreparedSetOutputAuthorityMaxBytes {
		return fmt.Errorf("invalid prepared reservation")
	}
	remaining := r.ReservedCapacityBytes
	charge := func(size int64) error {
		if size < 0 {
			return fmt.Errorf("negative prepared object length")
		}
		if size > remaining {
			return &PreparedCapacityError{Limit: uint64(r.ReservedCapacityBytes), Observed: uint64(r.ReservedCapacityBytes-remaining) + uint64(size)}
		}
		remaining -= size
		return nil
	}
	if err := charge(int64(len(r.ManifestJSON))); err != nil {
		return err
	}
	if err := charge(r.Control.ExpectedSize); err != nil {
		return err
	}
	for _, member := range r.Members {
		if err := charge(member.ExpectedSize); err != nil {
			return err
		}
	}
	return nil
}

// copyPreparedBounded never sends the overflow-probe byte to the destination.
// Every object is bounded by its preflighted share of the original reservation,
// including on short reads, write errors, and incorrectly declared lengths.
func copyPreparedBounded(dst io.Writer, src io.Reader, size int64) (int64, error) {
	if size < 0 {
		return 0, fmt.Errorf("negative prepared object length")
	}
	written, err := io.Copy(dst, io.LimitReader(src, size))
	if err != nil {
		return written, err
	}
	if written < size {
		return written, nil
	}
	var probe [1]byte
	n, err := io.ReadFull(src, probe[:])
	if n != 0 {
		return written, ErrPreparedCapacityExceeded
	}
	if err != io.EOF {
		return written, err
	}
	return written, nil
}

type PreparedStageReceipt struct {
	ManifestSize   int64
	ManifestSHA256 [32]byte
	MemberCount    int
	ContentBytes   int64
	Durable        bool
}

type PreparedPublisherGuard interface {
	PublisherGuard
	StagePrepared(context.Context, PreparedStageRequest) (PreparedStageReceipt, error)
	OpenPrepared(context.Context, string, int64, [32]byte) (io.ReadCloser, error)
}

type PreparedInspection struct {
	Durable      bool
	Manifest     domain.PreparedManifestV1
	ManifestJSON []byte
	Control      domain.PreparedControlV1
	ControlJSON  []byte
}

type PreparedDeletionOutcome string

const (
	PreparedContentRemoved       PreparedDeletionOutcome = "removed"
	PreparedContentAlreadyAbsent PreparedDeletionOutcome = "already_absent"
)

type PreparedRecoveryStore interface {
	AcquirePreparedRecovery(context.Context, StoreIdentity) (PreparedRecoveryGuard, error)
}

type PreparedRecoveryGuard interface {
	PublisherGuard
	InspectPrepared(context.Context, domain.ID) (PreparedInspection, error)
	OpenPrepared(context.Context, string, int64, [32]byte) (io.ReadCloser, error)
	VerifyReserved(context.Context, ReservedArtifactV1) (PublishedArtifactV1, bool, error)
	DeleteResolvedPrepared(context.Context, domain.PreparedSetRecord) (PreparedDeletionOutcome, error)
	Close() error
}

func validatePreparedStageRequest(identity StoreIdentity, request PreparedStageRequest) (domain.PreparedManifestV1, [32]byte, error) {
	if err := identity.Validate(); err != nil {
		return domain.PreparedManifestV1{}, [32]byte{}, err
	}
	if err := request.ValidateCapacity(); err != nil {
		return domain.PreparedManifestV1{}, [32]byte{}, err
	}
	manifest, err := domain.DecodePreparedManifestV1(request.ManifestJSON)
	if err != nil {
		return domain.PreparedManifestV1{}, [32]byte{}, err
	}
	if manifest.SetID != request.SetID || manifest.ManifestID != request.ManifestID || manifest.ArtifactStoreID != identity.ArtifactStoreID || manifest.StoreIncarnationNonce != identity.IncarnationNonce || manifest.StoreBackendKind != identity.BackendKind || manifest.StoreMarkerFormat != identity.MarkerFormat || manifest.StoreMarkerVersion != identity.MarkerVersion {
		return domain.PreparedManifestV1{}, [32]byte{}, fmt.Errorf("prepared stage identity mismatch")
	}
	manifestKey, _ := domain.PreparedManifestKey(request.SetID)
	if request.ManifestKey != manifestKey || request.Control.StorageKey != manifest.Control.StorageKey || request.Control.ExpectedSize != manifest.Control.ContentSizeBytes || DigestString(request.Control.ExpectedSHA256) != manifest.Control.ContentSHA256 || request.Control.Source == nil {
		return domain.PreparedManifestV1{}, [32]byte{}, fmt.Errorf("prepared control stage mismatch")
	}
	if len(request.Members) != len(manifest.Members) {
		return domain.PreparedManifestV1{}, [32]byte{}, fmt.Errorf("prepared member stage count mismatch")
	}
	for i, object := range request.Members {
		member := manifest.Members[i]
		if object.Source == nil || object.StorageKey != member.PreparedKey || object.ExpectedSize != member.ContentSizeBytes || DigestString(object.ExpectedSHA256) != member.ContentSHA256 {
			return domain.PreparedManifestV1{}, [32]byte{}, fmt.Errorf("prepared member %d stage mismatch", i)
		}
	}
	return manifest, DigestBytes(request.ManifestJSON), nil
}

type verifiedPreparedReader struct {
	reader   io.ReadCloser
	expected int64
	digest   [32]byte
	read     int64
	hash     hashWriter
	failed   error
}

type hashWriter interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func newVerifiedPreparedReader(reader io.ReadCloser, expected int64, digest [32]byte) io.ReadCloser {
	return &verifiedPreparedReader{reader: reader, expected: expected, digest: digest, hash: sha256.New()}
}

func (r *verifiedPreparedReader) Read(p []byte) (int, error) {
	if r.failed != nil {
		return 0, r.failed
	}
	n, err := r.reader.Read(p)
	if n > 0 {
		r.read += int64(n)
		_, _ = r.hash.Write(p[:n])
		if r.read > r.expected {
			r.failed = fmt.Errorf("prepared object exceeds expected length")
			return n, r.failed
		}
	}
	if err == io.EOF {
		var actual [32]byte
		copy(actual[:], r.hash.Sum(nil))
		if r.read != r.expected || actual != r.digest {
			r.failed = fmt.Errorf("prepared object verification failed")
			return n, r.failed
		}
	}
	return n, err
}

func (r *verifiedPreparedReader) Close() error {
	_, verifyErr := io.Copy(io.Discard, r)
	return errors.Join(verifyErr, r.failed, r.reader.Close())
}
