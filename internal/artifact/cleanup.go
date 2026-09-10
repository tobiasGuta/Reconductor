package artifact

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type ContentDeletionOutcome string

const (
	ContentRemoved       ContentDeletionOutcome = "removed"
	ContentAlreadyAbsent ContentDeletionOutcome = "already_absent"
)

const (
	ErrorCodeFilesystemIO        = "filesystem_io"
	ErrorCodeDurabilitySync      = "durability_sync"
	ErrorCodeUnexpectedEntryType = "unexpected_entry_type"
)

var ErrUnexpectedEntryType = errors.New("unexpected entry type")

type DurabilitySyncError struct {
	Err error
}

func (e *DurabilitySyncError) Error() string {
	return fmt.Sprintf("durability sync: %v", e.Err)
}

func (e *DurabilitySyncError) Unwrap() error {
	return e.Err
}

func ClassifyCleanupError(err error) string {
	if errors.Is(err, ErrUnexpectedEntryType) {
		return ErrorCodeUnexpectedEntryType
	}
	var durabilityErr *DurabilitySyncError
	if errors.As(err, &durabilityErr) {
		return ErrorCodeDurabilitySync
	}
	return ErrorCodeFilesystemIO
}

type ContentDeleter interface {
	StoreID() domain.ID
	DeleteContent(ctx context.Context, id domain.ID, storageKey string) (ContentDeletionOutcome, error)
}

type CleanupClaim struct {
	ID                domain.ID `json:"id"`
	ArtifactStoreID   domain.ID `json:"artifact_store_id"`
	StorageKey        string    `json:"storage_key"`
	CleanupClaimToken domain.ID `json:"cleanup_claim_token"`
	CleanupClaimedAt  time.Time `json:"cleanup_claimed_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type DatabaseCleanupStore interface {
	ClaimExpiredArtifacts(ctx context.Context, storeID domain.ID, limit int) ([]CleanupClaim, error)
	FinalizeArtifactCleanup(ctx context.Context, id domain.ID, storeID domain.ID, token domain.ID, observation string) (bool, error)
	RecordArtifactCleanupRetry(ctx context.Context, id domain.ID, storeID domain.ID, token domain.ID, errorCode string) (bool, error)
	QuarantineArtifactCleanup(ctx context.Context, id domain.ID, storeID domain.ID, token domain.ID, errorCode string) (bool, error)
}

type QuarantinedArtifact struct {
	ArtifactID domain.ID `json:"artifact_id"`
	ErrorCode  string    `json:"error_code"`
}

type CleanupResult struct {
	ArtifactStoreID domain.ID             `json:"artifact_store_id"`
	Claimed         int                   `json:"claimed"`
	Removed         int                   `json:"removed"`
	AlreadyAbsent   int                   `json:"already_absent"`
	RetryScheduled  int                   `json:"retry_scheduled"`
	LostClaim       int                   `json:"lost_claim"`
	Quarantined     []QuarantinedArtifact `json:"quarantined"`
}

func CleanupBatch(ctx context.Context, store DatabaseCleanupStore, deleter ContentDeleter, batchSize int) (CleanupResult, error) {
	if store == nil {
		return CleanupResult{}, fmt.Errorf("database cleanup store is required")
	}
	if deleter == nil {
		return CleanupResult{}, fmt.Errorf("content deleter is required")
	}
	if batchSize < 1 || batchSize > 1000 {
		return CleanupResult{}, fmt.Errorf("batch size %d must be between 1 and 1000", batchSize)
	}

	storeID := deleter.StoreID()
	if _, err := domain.ParseID(string(storeID)); err != nil {
		return CleanupResult{}, fmt.Errorf("configured artifact store ID is not canonical: %w", err)
	}

	result := CleanupResult{
		ArtifactStoreID: storeID,
		Quarantined:     make([]QuarantinedArtifact, 0),
	}

	claims, err := store.ClaimExpiredArtifacts(ctx, storeID, batchSize)
	if err != nil {
		return result, err
	}
	result.Claimed = len(claims)

	for _, claim := range claims {
		if err := ValidateStorageKey(claim.StorageKey, claim.ID); err != nil {
			return result, fmt.Errorf("invariant failure: artifact storage identity mismatch")
		}

		outcome, err := deleter.DeleteContent(ctx, claim.ID, claim.StorageKey)
		if err == nil {
			finalized, fErr := store.FinalizeArtifactCleanup(ctx, claim.ID, storeID, claim.CleanupClaimToken, string(outcome))
			if fErr != nil {
				return result, fErr
			}
			if !finalized {
				result.LostClaim++
			} else if outcome == ContentRemoved {
				result.Removed++
			} else {
				result.AlreadyAbsent++
			}
			continue
		}

		errorCode := ClassifyCleanupError(err)
		if errorCode == ErrorCodeUnexpectedEntryType {
			quarantined, qErr := store.QuarantineArtifactCleanup(ctx, claim.ID, storeID, claim.CleanupClaimToken, errorCode)
			if qErr != nil {
				return result, qErr
			}
			if !quarantined {
				result.LostClaim++
			} else {
				result.Quarantined = append(result.Quarantined, QuarantinedArtifact{
					ArtifactID: claim.ID,
					ErrorCode:  errorCode,
				})
			}
		} else {
			retried, rErr := store.RecordArtifactCleanupRetry(ctx, claim.ID, storeID, claim.CleanupClaimToken, errorCode)
			if rErr != nil {
				return result, rErr
			}
			if !retried {
				result.LostClaim++
			} else {
				result.RetryScheduled++
			}
		}
	}

	return result, nil
}
