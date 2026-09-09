package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	artifactstorage "github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

const (
	testArtifactStoreID    domain.ID = "00000000-0000-4000-8000-000000001016"
	testArtifactStoreNonce domain.ID = "00000000-0000-4000-8000-000000002016"
)

func TestRegisterArtifactStoreRejectsNoncanonicalIdentityBeforePoolUse(t *testing.T) {
	store := &Store{}
	for _, registration := range []domain.ArtifactStoreRegistration{
		artifactStoreRegistration("not-a-uuid", domain.NewID()),
		artifactStoreRegistration("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", domain.NewID()),
		artifactStoreRegistration(domain.NewID(), "not-a-uuid"),
		artifactStoreRegistration(domain.NewID(), "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB"),
	} {
		if _, err := store.RegisterArtifactStore(context.Background(), registration); err == nil || errors.Is(err, ErrArtifactStoreRegistrationConflict) {
			t.Fatalf("noncanonical registration error=%v registration=%#v", err, registration)
		}
	}
}

func ensureTestArtifactStore(t *testing.T, ctx context.Context, store *Store) domain.ArtifactStore {
	t.Helper()
	item, err := store.RegisterArtifactStore(ctx, domain.ArtifactStoreRegistration{ID: testArtifactStoreID, IncarnationNonce: testArtifactStoreNonce, BackendKind: artifactstorage.BackendKind, MarkerFormat: artifactstorage.MarkerFormat, MarkerVersion: artifactstorage.MarkerVersion})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func withTestArtifactAddress(item domain.Artifact) domain.Artifact {
	key, err := artifactstorage.StorageKeyFor(item.ID)
	if err != nil {
		panic(fmt.Sprintf("derive test artifact storage key: %v", err))
	}
	storeID := testArtifactStoreID
	item.AddressingVersion = 1
	item.ArtifactStoreID = &storeID
	item.StorageKey = &key
	item.StorageLocation = nil
	return item
}

func TestArtifactStoreRegistrationIsIdentityIdempotent(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	first := ensureTestArtifactStore(t, ctx, store)
	second := ensureTestArtifactStore(t, ctx, store)
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("created_at changed: first=%v second=%v", first.CreatedAt, second.CreatedAt)
	}
	conflict := first.ArtifactStoreRegistration
	conflict.IncarnationNonce = domain.NewID()
	if _, err := store.RegisterArtifactStore(ctx, conflict); !errors.Is(err, ErrArtifactStoreRegistrationConflict) {
		t.Fatalf("same-ID conflict error=%v", err)
	}
	if _, err := store.Pool.Exec(ctx, `UPDATE artifact_stores SET incarnation_nonce=$2 WHERE id=$1`, first.ID, domain.NewID()); err == nil {
		t.Fatal("constraint-valid registry mutation accepted")
	} else {
		assertArtifactStoreTriggerError(t, err)
	}
	unreferenced, err := store.RegisterArtifactStore(ctx, artifactStoreRegistration(domain.NewID(), domain.NewID()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `DELETE FROM artifact_stores WHERE id=$1`, unreferenced.ID); err == nil {
		t.Fatal("unreferenced registry delete accepted")
	} else {
		assertArtifactStoreTriggerError(t, err)
	}
	if _, err := store.RegisterArtifactStore(ctx, artifactStoreRegistration(domain.NewID(), testArtifactStoreNonce)); !errors.Is(err, ErrArtifactStoreRegistrationConflict) {
		t.Fatalf("duplicate-nonce conflict error=%v", err)
	}
	if time.Since(first.CreatedAt) < 0 {
		t.Fatalf("created_at is in the future: %v", first.CreatedAt)
	}
}

func TestArtifactStoreRegistrationRejectsNoncanonicalIdentityBeforeMutation(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	var before int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM artifact_stores`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	tests := []domain.ArtifactStoreRegistration{
		artifactStoreRegistration("not-a-uuid", domain.NewID()),
		artifactStoreRegistration("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", domain.NewID()),
		artifactStoreRegistration(domain.NewID(), "not-a-uuid"),
		artifactStoreRegistration(domain.NewID(), "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB"),
	}
	for _, registration := range tests {
		if _, err := store.RegisterArtifactStore(ctx, registration); err == nil || errors.Is(err, ErrArtifactStoreRegistrationConflict) {
			t.Fatalf("noncanonical registration error=%v registration=%#v", err, registration)
		}
	}
	var after int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM artifact_stores`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("invalid identity mutated registry: before=%d after=%d", before, after)
	}
}

func TestArtifactStoreRegistrationConcurrentIdentitySemantics(t *testing.T) {
	t.Run("simultaneous identical registration", func(t *testing.T) {
		store, ctx := schedulerIntegrationStore(t)
		registration := artifactStoreRegistration(domain.NewID(), domain.NewID())
		results := runConcurrentRegistrations(t, ctx, store, registration, registration)
		if results[0].err != nil || results[1].err != nil || !results[0].item.CreatedAt.Equal(results[1].item.CreatedAt) {
			t.Fatalf("identical results=%#v", results)
		}
		assertArtifactStoreRowCount(t, ctx, store, registration.ID, 1)
	})

	t.Run("same StoreID different nonce", func(t *testing.T) {
		store, ctx := schedulerIntegrationStore(t)
		storeID := domain.NewID()
		results := runConcurrentRegistrations(t, ctx, store, artifactStoreRegistration(storeID, domain.NewID()), artifactStoreRegistration(storeID, domain.NewID()))
		assertOneRegistrationConflict(t, results)
		assertArtifactStoreRowCount(t, ctx, store, storeID, 1)
	})

	t.Run("different StoreID same nonce", func(t *testing.T) {
		store, ctx := schedulerIntegrationStore(t)
		nonce := domain.NewID()
		firstID, secondID := domain.NewID(), domain.NewID()
		results := runConcurrentRegistrations(t, ctx, store, artifactStoreRegistration(firstID, nonce), artifactStoreRegistration(secondID, nonce))
		assertOneRegistrationConflict(t, results)
		var rows int
		if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM artifact_stores WHERE id=ANY($1::uuid[])`, []string{string(firstID), string(secondID)}).Scan(&rows); err != nil || rows != 1 {
			t.Fatalf("same-nonce rows=%d err=%v", rows, err)
		}
	})
}

func TestArtifactStoreRegistrationCancellationLeavesNoAmbiguousRowAndCanRetry(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	registration := artifactStoreRegistration(domain.NewID(), domain.NewID())
	blocker, err := store.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, `LOCK TABLE artifact_stores IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	registrationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	registrationDone := make(chan error, 1)
	go func() {
		_, registrationErr := store.RegisterArtifactStore(registrationCtx, registration)
		registrationDone <- registrationErr
	}()
	waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
	waitForPostgresLock(t, waitCtx, store, `%INSERT INTO artifact_stores%`)
	waitCancel()
	cancel()
	select {
	case err := <-registrationDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked cancelled registration error=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled registration did not return")
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertArtifactStoreRowCount(t, ctx, store, registration.ID, 0)
	if _, err := store.RegisterArtifactStore(ctx, registration); err != nil {
		t.Fatalf("deterministic retry failed: %v", err)
	}
	assertArtifactStoreRowCount(t, ctx, store, registration.ID, 1)
}

type artifactStoreRegistrationResult struct {
	item domain.ArtifactStore
	err  error
}

func runConcurrentRegistrations(t *testing.T, ctx context.Context, store *Store, registrations ...domain.ArtifactStoreRegistration) []artifactStoreRegistrationResult {
	t.Helper()
	if len(registrations) != 2 {
		t.Fatalf("registration barrier requires two registrations, got %d", len(registrations))
	}
	runCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	barrierPID, releaseBarrier := holdArtifactStoreRegistrationBarrier(t, runCtx, store)
	defer releaseBarrier()
	start := make(chan struct{})
	done := make(chan int, len(registrations))
	results := make([]artifactStoreRegistrationResult, len(registrations))
	for index := range registrations {
		go func(index int) {
			<-start
			results[index].item, results[index].err = store.RegisterArtifactStore(runCtx, registrations[index])
			done <- index
		}(index)
	}
	close(start)
	waitForArtifactStoreRegistrationBarrier(t, runCtx, store, barrierPID, done, len(registrations))
	releaseBarrier()
	for range registrations {
		select {
		case <-done:
		case <-runCtx.Done():
			t.Fatalf("concurrent registrations did not finish: %v", runCtx.Err())
		}
	}
	return results
}

func holdArtifactStoreRegistrationBarrier(t *testing.T, ctx context.Context, store *Store) (int, func()) {
	t.Helper()
	var key int64
	if err := store.Pool.QueryRow(ctx, `SELECT hashtextextended($1,0)`, string(domain.NewID())).Scan(&key); err != nil {
		t.Fatal(err)
	}
	functionSQL := fmt.Sprintf(`CREATE FUNCTION artifact_store_registration_test_barrier() RETURNS trigger AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock_shared(%d);
			RETURN NEW;
		END;
	$$ LANGUAGE plpgsql`, key)
	if _, err := store.Pool.Exec(ctx, functionSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `CREATE TRIGGER artifact_store_registration_test_barrier BEFORE INSERT ON artifact_stores FOR EACH ROW EXECUTE FUNCTION artifact_store_registration_test_barrier()`); err != nil {
		t.Fatal(err)
	}
	connection, err := store.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := connection.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		connection.Release()
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		connection.Release()
		t.Fatal(err)
	}
	released := false
	return pid, func() {
		if released {
			return
		}
		released = true
		if _, err := connection.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key); err != nil {
			t.Errorf("release artifact store registration barrier: %v", err)
		}
		connection.Release()
	}
}

func waitForArtifactStoreRegistrationBarrier(t *testing.T, ctx context.Context, store *Store, holderPID int, done <-chan int, want int) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int
		if err := store.Pool.QueryRow(ctx, `SELECT count(DISTINCT waiting_lock.pid)
			FROM pg_locks waiting_lock
			JOIN pg_locks held_lock
			  ON held_lock.locktype=waiting_lock.locktype
			 AND held_lock.database IS NOT DISTINCT FROM waiting_lock.database
			 AND held_lock.classid IS NOT DISTINCT FROM waiting_lock.classid
			 AND held_lock.objid IS NOT DISTINCT FROM waiting_lock.objid
			 AND held_lock.objsubid IS NOT DISTINCT FROM waiting_lock.objsubid
			JOIN pg_stat_activity activity ON activity.pid=waiting_lock.pid
			WHERE waiting_lock.locktype='advisory'
			  AND NOT waiting_lock.granted
			  AND held_lock.pid=$1
			  AND held_lock.granted
			  AND activity.query LIKE 'INSERT INTO artifact_stores%'`, holderPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == want {
			return
		}
		select {
		case index := <-done:
			t.Fatalf("registration %d returned before both backends reached the advisory-lock barrier", index)
		case <-ctx.Done():
			t.Fatalf("registration backends did not reach the advisory-lock barrier: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func artifactStoreRegistration(id, nonce domain.ID) domain.ArtifactStoreRegistration {
	return domain.ArtifactStoreRegistration{ID: id, IncarnationNonce: nonce, BackendKind: artifactstorage.BackendKind, MarkerFormat: artifactstorage.MarkerFormat, MarkerVersion: artifactstorage.MarkerVersion}
}

func assertOneRegistrationConflict(t *testing.T, results []artifactStoreRegistrationResult) {
	t.Helper()
	var successes, conflicts int
	for _, result := range results {
		switch {
		case result.err == nil:
			successes++
		case errors.Is(result.err, ErrArtifactStoreRegistrationConflict):
			conflicts++
		default:
			t.Fatalf("unexpected registration error: %v", result.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("registration outcomes: successes=%d conflicts=%d results=%#v", successes, conflicts, results)
	}
}

func assertArtifactStoreRowCount(t *testing.T, ctx context.Context, store *Store, id domain.ID, want int) {
	t.Helper()
	var count int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM artifact_stores WHERE id=$1`, id).Scan(&count); err != nil || count != want {
		t.Fatalf("artifact store %s rows=%d want=%d err=%v", id, count, want, err)
	}
}

func assertArtifactStoreTriggerError(t *testing.T, err error) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "P0001" || postgresError.Message != "artifact store registrations are immutable" {
		t.Fatalf("registry trigger error=%v", err)
	}
}

func TestArtifactStoreRegistrationInsertTime23505Classification(t *testing.T) {
	installSimulated23505 := func(t *testing.T, ctx context.Context, store *Store) {
		t.Helper()
		functionSQL := `CREATE FUNCTION artifact_store_simulated_23505() RETURNS trigger AS $$
			BEGIN
				RAISE EXCEPTION 'simulated unique index failure' USING ERRCODE = '23505';
			END;
		$$ LANGUAGE plpgsql`
		if _, err := store.Pool.Exec(ctx, functionSQL); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Pool.Exec(ctx, `CREATE TRIGGER artifact_store_simulated_23505 BEFORE INSERT ON artifact_stores FOR EACH ROW EXECUTE FUNCTION artifact_store_simulated_23505()`); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("insert 23505 with exact authoritative row succeeds", func(t *testing.T) {
		store, ctx := schedulerIntegrationStore(t)
		reg := artifactStoreRegistration(domain.NewID(), domain.NewID())
		existing, err := store.RegisterArtifactStore(ctx, reg)
		if err != nil {
			t.Fatal(err)
		}
		installSimulated23505(t, ctx, store)
		result, err := store.RegisterArtifactStore(ctx, reg)
		if err != nil {
			t.Fatalf("expected idempotent success on insert-time 23505 with exact row, got error: %v", err)
		}
		if !result.CreatedAt.Equal(existing.CreatedAt) || result.ID != existing.ID || result.IncarnationNonce != existing.IncarnationNonce {
			t.Fatalf("result mismatch: got %#v, want %#v", result, existing)
		}
	})

	t.Run("insert 23505 with conflicting StoreID returns conflict", func(t *testing.T) {
		store, ctx := schedulerIntegrationStore(t)
		storeID := domain.NewID()
		regExisting := artifactStoreRegistration(storeID, domain.NewID())
		if _, err := store.RegisterArtifactStore(ctx, regExisting); err != nil {
			t.Fatal(err)
		}
		installSimulated23505(t, ctx, store)
		regConflicting := artifactStoreRegistration(storeID, domain.NewID())
		_, err := store.RegisterArtifactStore(ctx, regConflicting)
		if !errors.Is(err, ErrArtifactStoreRegistrationConflict) {
			t.Fatalf("expected ErrArtifactStoreRegistrationConflict on conflicting StoreID, got: %v", err)
		}
	})

	t.Run("insert 23505 with conflicting nonce returns conflict", func(t *testing.T) {
		store, ctx := schedulerIntegrationStore(t)
		nonce := domain.NewID()
		regExisting := artifactStoreRegistration(domain.NewID(), nonce)
		if _, err := store.RegisterArtifactStore(ctx, regExisting); err != nil {
			t.Fatal(err)
		}
		installSimulated23505(t, ctx, store)
		regConflicting := artifactStoreRegistration(domain.NewID(), nonce)
		_, err := store.RegisterArtifactStore(ctx, regConflicting)
		if !errors.Is(err, ErrArtifactStoreRegistrationConflict) {
			t.Fatalf("expected ErrArtifactStoreRegistrationConflict on conflicting nonce, got: %v", err)
		}
	})

	t.Run("insert 23505 with neither row preserves original database error", func(t *testing.T) {
		store, ctx := schedulerIntegrationStore(t)
		installSimulated23505(t, ctx, store)
		reg := artifactStoreRegistration(domain.NewID(), domain.NewID())
		_, err := store.RegisterArtifactStore(ctx, reg)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if errors.Is(err, ErrArtifactStoreRegistrationConflict) {
			t.Fatalf("must NOT return ErrArtifactStoreRegistrationConflict when neither row exists, got: %v", err)
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			t.Fatalf("expected preserved PostgreSQL error with SQLSTATE 23505, got: %v", err)
		}
	})

	t.Run("insert 23505 with dual match prefers StoreID conflict", func(t *testing.T) {
		store, ctx := schedulerIntegrationStore(t)
		storeID := domain.NewID()
		nonceB := domain.NewID()
		if _, err := store.RegisterArtifactStore(ctx, artifactStoreRegistration(storeID, domain.NewID())); err != nil {
			t.Fatal(err)
		}
		if _, err := store.RegisterArtifactStore(ctx, artifactStoreRegistration(domain.NewID(), nonceB)); err != nil {
			t.Fatal(err)
		}
		installSimulated23505(t, ctx, store)
		_, err := store.RegisterArtifactStore(ctx, artifactStoreRegistration(storeID, nonceB))
		if !errors.Is(err, ErrArtifactStoreRegistrationConflict) {
			t.Fatalf("expected ErrArtifactStoreRegistrationConflict, got: %v", err)
		}
		if !strings.Contains(err.Error(), "StoreID is already registered with different identity") {
			t.Fatalf("expected StoreID conflict preference, got: %v", err)
		}
	})
}
