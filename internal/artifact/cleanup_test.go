package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type mockDeleter struct {
	storeID   domain.ID
	deleteFn  func(ctx context.Context, id domain.ID, key string) (ContentDeletionOutcome, error)
	callCount int
}

func (m *mockDeleter) StoreID() domain.ID {
	return m.storeID
}

func (m *mockDeleter) DeleteContent(ctx context.Context, id domain.ID, key string) (ContentDeletionOutcome, error) {
	m.callCount++
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id, key)
	}
	return ContentRemoved, nil
}

type mockCleanupStore struct {
	claims         []CleanupClaim
	claimErr       error
	finalizeErr    error
	finalizeLost   bool
	retryErr       error
	retryLost      bool
	quarantineErr  error
	quarantineLost bool

	finalizedCalls   []domain.ID
	retryCalls       []domain.ID
	quarantinedCalls []domain.ID
	claimCalls int
	claimStoreID domain.ID
	claimLimit int
	observations []string
}

func (m *mockCleanupStore) ClaimExpiredArtifacts(ctx context.Context, storeID domain.ID, limit int) ([]CleanupClaim, error) {
	m.claimCalls++
	m.claimStoreID, m.claimLimit = storeID, limit
	if m.claimErr != nil {
		return nil, m.claimErr
	}
	return m.claims, nil
}

func (m *mockCleanupStore) FinalizeArtifactCleanup(ctx context.Context, id domain.ID, storeID domain.ID, token domain.ID, observation string) (bool, error) {
	m.finalizedCalls = append(m.finalizedCalls, id)
	m.observations = append(m.observations, observation)
	if m.finalizeErr != nil {
		return false, m.finalizeErr
	}
	if m.finalizeLost {
		return false, nil
	}
	return true, nil
}

func (m *mockCleanupStore) RecordArtifactCleanupRetry(ctx context.Context, id domain.ID, storeID domain.ID, token domain.ID, errorCode string) (bool, error) {
	m.retryCalls = append(m.retryCalls, id)
	if m.retryErr != nil {
		return false, m.retryErr
	}
	if m.retryLost {
		return false, nil
	}
	return true, nil
}

func (m *mockCleanupStore) QuarantineArtifactCleanup(ctx context.Context, id domain.ID, storeID domain.ID, token domain.ID, errorCode string) (bool, error) {
	m.quarantinedCalls = append(m.quarantinedCalls, id)
	if m.quarantineErr != nil {
		return false, m.quarantineErr
	}
	if m.quarantineLost {
		return false, nil
	}
	return true, nil
}

func TestCleanupBatchValidatesInputs(t *testing.T) {
	storeID := domain.ID("00000000-0000-4000-8000-000000000001")
	deleter := &mockDeleter{storeID: storeID}
	store := &mockCleanupStore{}

	if _, err := CleanupBatch(context.Background(), nil, deleter, 100); err == nil {
		t.Fatal("nil store was accepted")
	}
	if _, err := CleanupBatch(context.Background(), store, nil, 100); err == nil {
		t.Fatal("nil deleter was accepted")
	}
	for _, invalid := range []int{0, -1, 1001} {
		if _, err := CleanupBatch(context.Background(), store, deleter, invalid); err == nil {
			t.Fatalf("batch size %d was accepted", invalid)
		}
	}
	emptyDeleter := &mockDeleter{storeID: ""}
	if _, err := CleanupBatch(context.Background(), store, emptyDeleter, 100); err == nil {
		t.Fatal("empty StoreID was accepted")
	}
	malformedDeleter := &mockDeleter{storeID: "not-a-uuid"}
	if _, err := CleanupBatch(context.Background(), store, malformedDeleter, 100); err == nil {
		t.Fatal("malformed StoreID was accepted")
	}
}

func TestCleanupBatchStopsOnInvariantMismatchWithoutTouchingDiskOrState(t *testing.T) {
	storeID := domain.ID("00000000-0000-4000-8000-000000000001")
	artID := domain.ID("00000000-0000-4000-8000-000000000002")
	deleter := &mockDeleter{storeID: storeID}
	store := &mockCleanupStore{
		claims: []CleanupClaim{
			{
				ID:                artID,
				ArtifactStoreID:   storeID,
				StorageKey:        "v1/00/00000000-0000-4000-8000-000000000099", // mismatched key!
				CleanupClaimToken: domain.NewID(),
				CleanupClaimedAt:  time.Now(),
				ExpiresAt:         time.Now().Add(-time.Hour),
			},
		},
	}

	claimBefore := store.claims[0]
	_, err := CleanupBatch(context.Background(), store, deleter, 100)
	if err == nil || !strings.Contains(err.Error(), "invariant failure") {
		t.Fatalf("invariant mismatch error=%v", err)
	}
	if deleter.callCount != 0 {
		t.Fatalf("deleter was called %d times on invariant failure", deleter.callCount)
	}
	if len(store.finalizedCalls) != 0 || len(store.retryCalls) != 0 || len(store.quarantinedCalls) != 0 {
		t.Fatal("state transition attempted on invariant failure")
	}
	if store.claimCalls != 1 || store.claims[0] != claimBefore {
		t.Fatal("claim was changed or reacquired after invariant failure")
	}
	if strings.Contains(err.Error(), claimBefore.StorageKey) { t.Fatal("invariant error exposed storage key") }
}

func TestCleanupBatchProcessesMixedOutcomesAndLostClaims(t *testing.T) {
	storeID := domain.ID("00000000-0000-4000-8000-000000000001")
	id1 := domain.ID("00000000-0000-4000-8000-000000000001")
	id2 := domain.ID("00000000-0000-4000-8000-000000000002")
	id3 := domain.ID("00000000-0000-4000-8000-000000000003")
	id4 := domain.ID("00000000-0000-4000-8000-000000000004")
	id5 := domain.ID("00000000-0000-4000-8000-000000000005")

	key1, _ := StorageKeyFor(id1)
	key2, _ := StorageKeyFor(id2)
	key3, _ := StorageKeyFor(id3)
	key4, _ := StorageKeyFor(id4)
	key5, _ := StorageKeyFor(id5)

	deleter := &mockDeleter{
		storeID: storeID,
		deleteFn: func(ctx context.Context, id domain.ID, key string) (ContentDeletionOutcome, error) {
			switch id {
			case id1:
				return ContentRemoved, nil
			case id2:
				return ContentAlreadyAbsent, nil
			case id3:
				return "", errors.New("i/o error")
			case id4:
				return "", ErrUnexpectedEntryType
			case id5:
				return ContentRemoved, nil
			default:
				return "", errors.New("unknown")
			}
		},
	}

	store := &mockCleanupStore{
		claims: []CleanupClaim{
			{ID: id1, ArtifactStoreID: storeID, StorageKey: key1, CleanupClaimToken: domain.NewID(), ExpiresAt: time.Now()},
			{ID: id2, ArtifactStoreID: storeID, StorageKey: key2, CleanupClaimToken: domain.NewID(), ExpiresAt: time.Now()},
			{ID: id3, ArtifactStoreID: storeID, StorageKey: key3, CleanupClaimToken: domain.NewID(), ExpiresAt: time.Now()},
			{ID: id4, ArtifactStoreID: storeID, StorageKey: key4, CleanupClaimToken: domain.NewID(), ExpiresAt: time.Now()},
			{ID: id5, ArtifactStoreID: storeID, StorageKey: key5, CleanupClaimToken: domain.NewID(), ExpiresAt: time.Now()},
		},
	}

	result, err := CleanupBatch(context.Background(), store, deleter, 5)
	if err != nil {
		t.Fatalf("unexpected cleanup error: %v", err)
	}

	if result.Claimed != 5 {
		t.Fatalf("claimed=%d want=5", result.Claimed)
	}
	if store.claimCalls != 1 || store.claimStoreID != storeID || store.claimLimit != 5 {
		t.Fatal("cleanup did not claim exactly one configured bounded batch")
	}
	if len(store.observations) != 3 || store.observations[0] != "removed" || store.observations[1] != "already_absent" || store.observations[2] != "removed" {
		t.Fatalf("actual deletion observations not passed to finalization: %v", store.observations)
	}
	if result.Removed != 2 {
		t.Fatalf("removed=%d want=2", result.Removed)
	}
	if result.AlreadyAbsent != 1 {
		t.Fatalf("already_absent=%d want=1", result.AlreadyAbsent)
	}
	if result.RetryScheduled != 1 {
		t.Fatalf("retry_scheduled=%d want=1", result.RetryScheduled)
	}
	if len(result.Quarantined) != 1 {
		t.Fatalf("quarantined count=%d want=1", len(result.Quarantined))
	}
	if result.Quarantined[0].ArtifactID != id4 || result.Quarantined[0].ErrorCode != ErrorCodeUnexpectedEntryType {
		t.Fatalf("unexpected quarantine entry: %+v", result.Quarantined[0])
	}
}

func TestCleanupBatchEmptyQuarantineAndLostClaims(t *testing.T) {
	storeID, id := domain.NewID(), domain.NewID()
	key, _ := StorageKeyFor(id)
	for _, tc := range []struct { name string; deletionErr error }{
		{"finalize", nil}, {"retry", errors.New("filesystem failure")}, {"quarantine", ErrUnexpectedEntryType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &mockCleanupStore{claims: []CleanupClaim{{ID:id, ArtifactStoreID:storeID, StorageKey:key, CleanupClaimToken:domain.NewID()}}, finalizeLost:true, retryLost:true, quarantineLost:true}
			deleter := &mockDeleter{storeID:storeID, deleteFn:func(context.Context, domain.ID, string)(ContentDeletionOutcome,error){ return ContentRemoved, tc.deletionErr }}
			result, err := CleanupBatch(context.Background(), store, deleter, 1)
			if err != nil || result.LostClaim != 1 || result.Removed != 0 || result.AlreadyAbsent != 0 || result.RetryScheduled != 0 || len(result.Quarantined) != 0 { t.Fatalf("result=%+v err=%v", result,err) }
			encoded, err := json.Marshal(result)
			if err != nil || !strings.Contains(string(encoded), `"quarantined":[]`) { t.Fatalf("empty quarantine output=%s err=%v", encoded,err) }
			if store.claimCalls != 1 || len(store.finalizedCalls)+len(store.retryCalls)+len(store.quarantinedCalls) != 1 { t.Fatal("lost claim caused fallback mutation or another claim") }
		})
	}
}
