package database

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	artifactstorage "github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type cleanupTestLineage struct {
	programID  domain.ID
	taskID     domain.ID
	runID      domain.ID
	stepID     domain.ID
	toolID     domain.ID
	defID      domain.ID
	scopeVerID domain.ID
}

func setupCleanupTestLineage(t *testing.T, ctx context.Context, store *Store, prefix string) cleanupTestLineage {
	t.Helper()
	l := cleanupTestLineage{
		programID:  domain.NewID(),
		taskID:     domain.NewID(),
		runID:      domain.NewID(),
		stepID:     domain.NewID(),
		toolID:     domain.NewID(),
		defID:      domain.NewID(),
		scopeVerID: domain.NewID(),
	}
	digest := strings.Repeat("a", 64)
	for _, statement := range []string{
		`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES('` + string(l.programID) + `','` + prefix + `-prog','integration','synthetic://local','integration')`,
		`INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,target_plan_digest,target_plan) VALUES('` + string(l.scopeVerID) + `','` + string(l.programID) + `','synthetic://local','` + digest + `','` + digest + `','{}'::jsonb)`,
		`INSERT INTO workflow_definitions(id,name,version,definition) VALUES('` + string(l.defID) + `','` + prefix + `-wf','1','{}')`,
		`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES('` + string(l.taskID) + `','` + string(l.programID) + `','test','` + string(l.defID) + `','running','integration')`,
		`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source,materialized_definition,materialization_digest,original_scope_version_id) VALUES('` + string(l.runID) + `','` + string(l.taskID) + `','` + string(l.defID) + `','1','running','integration','{}'::jsonb,'` + digest + `','` + string(l.scopeVerID) + `')`,
		`INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,idempotency_key) VALUES('` + string(l.stepID) + `','` + string(l.runID) + `','step','test.capability','running','idemp-` + string(l.stepID) + `')`,
		`INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at) VALUES('` + string(l.toolID) + `','` + string(l.stepID) + `','test.capability','test-provider',clock_timestamp())`,
	} {
		if _, err := store.Pool.Exec(ctx, statement); err != nil {
			t.Fatalf("setupCleanupTestLineage failed: %v\nstmt: %s", err, statement)
		}
	}
	return l
}

func TestClaimExpiredArtifactsStoreIsolationAndEligibility(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)

	storeA := domain.ID("00000000-0000-4000-8000-000000000a01")
	nonceA := domain.ID("00000000-0000-4000-8000-000000000a02")
	storeB := domain.ID("00000000-0000-4000-8000-000000000b01")
	nonceB := domain.ID("00000000-0000-4000-8000-000000000b02")

	for _, reg := range []domain.ArtifactStoreRegistration{
		{ID: storeA, IncarnationNonce: nonceA, BackendKind: artifactstorage.BackendKind, MarkerFormat: artifactstorage.MarkerFormat, MarkerVersion: artifactstorage.MarkerVersion},
		{ID: storeB, IncarnationNonce: nonceB, BackendKind: artifactstorage.BackendKind, MarkerFormat: artifactstorage.MarkerFormat, MarkerVersion: artifactstorage.MarkerVersion},
	} {
		if _, err := store.RegisterArtifactStore(ctx, reg); err != nil {
			t.Fatal(err)
		}
	}

	l := setupCleanupTestLineage(t, ctx, store, "iso-elig")

	insertArtifact := func(id domain.ID, sID *domain.ID, version int16, loc *string, expires *time.Time) {
		t.Helper()
		var key *string
		if version == 1 && sID != nil {
			k, _ := artifactstorage.StorageKeyFor(id)
			key = &k
		}
		_, err := store.Pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,storage_location,redaction_state,expires_at) VALUES($1,$2,$3,$4,$5,'raw-provider-output','text/plain',1,'sha',$6,$7,$8,$9,'redacted',$10)`,
			id, l.taskID, l.runID, l.stepID, l.toolID, version, sID, key, loc, expires)
		if err != nil {
			t.Fatalf("insertArtifact %s failed: %v", id, err)
		}
	}

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	expiredA := domain.NewID()
	insertArtifact(expiredA, &storeA, 1, nil, &past)

	expiredB := domain.NewID()
	insertArtifact(expiredB, &storeB, 1, nil, &past)

	unexpiredA := domain.NewID()
	insertArtifact(unexpiredA, &storeA, 1, nil, &future)

	nullExpiryA := domain.NewID()
	insertArtifact(nullExpiryA, &storeA, 1, nil, nil)

	// Legacy v0 artifact with storage_location NOT NULL and past expiry
	legacyV0 := domain.NewID()
	legacyLoc := "legacy://test/v0"
	if _, err := store.Pool.Exec(ctx, `ALTER TABLE artifacts DISABLE TRIGGER artifacts_reject_legacy_insert`); err != nil {
		t.Fatal(err)
	}
	insertArtifact(legacyV0, nil, 0, &legacyLoc, &past)
	if _, err := store.Pool.Exec(ctx, `ALTER TABLE artifacts ENABLE TRIGGER artifacts_reject_legacy_insert`); err != nil {
		t.Fatal(err)
	}

	// Artifact with retry_after in future (should be excluded)
	retryFutureID := domain.NewID()
	insertArtifact(retryFutureID, &storeA, 1, nil, &past)
	if _, err := store.Pool.Exec(ctx, `UPDATE artifacts SET cleanup_claim_token=gen_random_uuid(), cleanup_claimed_at=clock_timestamp() WHERE id=$1`, retryFutureID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `UPDATE artifacts SET cleanup_claim_token=NULL, cleanup_claimed_at=NULL, cleanup_retry_after=clock_timestamp()+interval '10 minutes', cleanup_last_error_code='filesystem_io' WHERE id=$1`, retryFutureID); err != nil {
		t.Fatal(err)
	}

	// Artifact with retry_after in past (should be eligible)
	retryPastID := domain.NewID()
	insertArtifact(retryPastID, &storeA, 1, nil, &past)
	if _, err := store.Pool.Exec(ctx, `UPDATE artifacts SET cleanup_claim_token=gen_random_uuid(), cleanup_claimed_at=clock_timestamp() WHERE id=$1`, retryPastID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `UPDATE artifacts SET cleanup_claim_token=NULL, cleanup_claimed_at=NULL, cleanup_retry_after=clock_timestamp()-interval '5 minutes', cleanup_last_error_code='filesystem_io' WHERE id=$1`, retryPastID); err != nil {
		t.Fatal(err)
	}

	// Artifact with recent claim (< 15 min, should be excluded)
	recentClaimID := domain.NewID()
	insertArtifact(recentClaimID, &storeA, 1, nil, &past)
	if _, err := store.Pool.Exec(ctx, `UPDATE artifacts SET cleanup_claim_token=gen_random_uuid(), cleanup_claimed_at=clock_timestamp()-interval '5 minutes' WHERE id=$1`, recentClaimID); err != nil {
		t.Fatal(err)
	}

	// Artifact with stale claim (> 15 min, should be eligible for takeover)
	staleClaimID := domain.NewID()
	insertArtifact(staleClaimID, &storeA, 1, nil, &past)
	if _, err := store.Pool.Exec(ctx, `UPDATE artifacts SET cleanup_claim_token=gen_random_uuid(), cleanup_claimed_at=clock_timestamp()-interval '20 minutes' WHERE id=$1`, staleClaimID); err != nil {
		t.Fatal(err)
	}

	// Artifact with non-canonical storage key (bypassing check constraint to test claim query key filter)
	badKeyID := domain.NewID()
	if _, err := store.Pool.Exec(ctx, `ALTER TABLE artifacts DROP CONSTRAINT artifacts_storage_key_v1_ck`); err != nil {
		t.Fatal(err)
	}
	badKey := "v1/xx/" + string(badKeyID)
	if _, err := store.Pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,storage_location,redaction_state,expires_at) VALUES($1,$2,$3,$4,$5,'raw-provider-output','text/plain',1,'sha',1,$6,$7,NULL,'redacted',$8)`,
		badKeyID, l.taskID, l.runID, l.stepID, l.toolID, storeA, badKey, past); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `ALTER TABLE artifacts ADD CONSTRAINT artifacts_storage_key_v1_ck CHECK (addressing_version<>1 OR storage_key=('v1/' || substr(replace(id::text,'-',''),1,2) || '/' || id::text)) NOT VALID`); err != nil {
		t.Fatal(err)
	}

	// Claim on storeA: should claim expiredA, retryPastID, and staleClaimID (3 total)
	// Must NOT claim: expiredB (wrong store), unexpiredA, nullExpiryA, legacyV0 (version 0 & storage_location not null),
	// retryFutureID (retry not due), recentClaimID (claim active), badKeyID (non-canonical key)
	claimsA, err := store.ClaimExpiredArtifacts(ctx, storeA, 100)
	if err != nil {
		t.Fatalf("claim storeA error: %v", err)
	}

	if len(claimsA) != 3 {
		t.Fatalf("claimsA count=%d want=3; got IDs: %+v", len(claimsA), claimsA)
	}

	claimedIDs := map[domain.ID]bool{}
	for _, c := range claimsA {
		claimedIDs[c.ID] = true
		if c.ArtifactStoreID != storeA {
			t.Fatalf("claimed storeID=%s want=%s", c.ArtifactStoreID, storeA)
		}
		expectedKey, _ := artifactstorage.StorageKeyFor(c.ID)
		if c.StorageKey != expectedKey {
			t.Fatalf("claimed key=%q want=%q", c.StorageKey, expectedKey)
		}
		if c.CleanupClaimToken == "" {
			t.Fatal("expected non-empty claim token")
		}
		if c.CleanupClaimedAt.IsZero() {
			t.Fatal("expected non-zero cleanup claimed at")
		}
		if c.ExpiresAt.IsZero() {
			t.Fatal("expected non-zero expires at")
		}
	}

	for _, expectedID := range []domain.ID{expiredA, retryPastID, staleClaimID} {
		if !claimedIDs[expectedID] {
			t.Fatalf("expected artifact %s to be claimed on storeA", expectedID)
		}
	}

	for _, excludedID := range []domain.ID{expiredB, unexpiredA, nullExpiryA, legacyV0, retryFutureID, recentClaimID, badKeyID} {
		if claimedIDs[excludedID] {
			t.Fatalf("excluded artifact %s was unexpectedly claimed on storeA", excludedID)
		}
	}

	// Claim on storeB: should claim expiredB only
	claimsB, err := store.ClaimExpiredArtifacts(ctx, storeB, 100)
	if err != nil {
		t.Fatalf("claim storeB error: %v", err)
	}
	if len(claimsB) != 1 || claimsB[0].ID != expiredB {
		t.Fatalf("claimsB count=%d want 1 for expiredB; got: %+v", len(claimsB), claimsB)
	}
}

func TestClaimExpiredArtifactsPerArtifactTokenAndDeterminism(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	storeID := domain.ID("00000000-0000-4000-8000-000000000c01")
	storeNonce := domain.ID("00000000-0000-4000-8000-000000000c02")

	if _, err := store.RegisterArtifactStore(ctx, domain.ArtifactStoreRegistration{
		ID: storeID, IncarnationNonce: storeNonce, BackendKind: artifactstorage.BackendKind, MarkerFormat: artifactstorage.MarkerFormat, MarkerVersion: artifactstorage.MarkerVersion,
	}); err != nil {
		t.Fatal(err)
	}

	l := setupCleanupTestLineage(t, ctx, store, "claims-det")

	// Fixed timestamps: tEarlier < tEqual < tLater
	tEarlier := time.Now().Add(-3 * time.Hour).Truncate(time.Microsecond)
	tEqual := time.Now().Add(-2 * time.Hour).Truncate(time.Microsecond)
	tLater := time.Now().Add(-1 * time.Hour).Truncate(time.Microsecond)

	// Deterministic fixed UUIDs with deliberately adversarial ordering:
	// idLater has the LOWEST UUID overall (adversarial to expires_at ASC)
	// idEarlier has a relatively HIGH UUID (higher than equal-expiry group and idLater)
	// idEqual1, idEqual2, idEqual3 have clear ascending UUID order
	idLater := domain.ID("00000000-0000-4000-8000-000000000000")
	idEqual1 := domain.ID("00000000-0000-4000-8000-000000000001")
	idEqual2 := domain.ID("00000000-0000-4000-8000-000000000002")
	idEqual3 := domain.ID("00000000-0000-4000-8000-000000000003")
	idEarlier := domain.ID("00000000-0000-4000-8000-0000000000ff")

	// Insert rows in deliberately non-sorted order (different from expires_at ASC, id ASC):
	// Insertion sequence: idEqual3, idLater, idEarlier, idEqual1, idEqual2
	fixtures := []struct {
		id  domain.ID
		exp time.Time
	}{
		{idEqual3, tEqual},
		{idLater, tLater},
		{idEarlier, tEarlier},
		{idEqual1, tEqual},
		{idEqual2, tEqual},
	}

	for _, item := range fixtures {
		key, _ := artifactstorage.StorageKeyFor(item.id)
		if _, err := store.Pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state,expires_at) VALUES($1,$2,$3,$4,$5,'raw-provider-output','text/plain',1,'sha',1,$6,$7,'redacted',$8)`,
			item.id, l.taskID, l.runID, l.stepID, l.toolID, storeID, key, item.exp); err != nil {
			t.Fatal(err)
		}
	}

	// Bounded batch size = 3 (smaller than total population 5).
	// Cuts through the 3 equal-expiry rows: room for only 2 after idEarlier.
	claims, err := store.ClaimExpiredArtifacts(ctx, storeID, 3)
	if err != nil {
		t.Fatalf("claim batch error: %v", err)
	}

	if len(claims) != 3 {
		t.Fatalf("claims count=%d want=3", len(claims))
	}

	// Build membership set to assert candidate selection regardless of UPDATE ... RETURNING output order
	claimedIDs := make(map[domain.ID]bool, len(claims))
	for _, c := range claims {
		claimedIDs[c.ID] = true
	}

	// Primary ordering proof:
	// idEarlier must be claimed even though its UUID is higher than idLater (expires_at ASC dominates id ASC).
	// idLater must NOT be claimed in batch 1 even though it has the lowest UUID overall.
	if !claimedIDs[idEarlier] {
		t.Fatalf("expected earliest-expiry artifact %s to be claimed in first batch; got claims: %+v", idEarlier, claims)
	}
	if claimedIDs[idLater] {
		t.Fatalf("later-expiry artifact %s was unexpectedly claimed in first batch (expires_at ASC must dominate id ASC)", idLater)
	}

	// Secondary tie-break proof:
	// For equal-expiry group, lowest UUIDs (idEqual1, idEqual2) must be claimed.
	// idEqual3 must NOT be claimed because it loses the id ASC tie-break at the batch boundary.
	if !claimedIDs[idEqual1] {
		t.Fatalf("expected lowest equal-expiry artifact %s to be claimed in first batch; got claims: %+v", idEqual1, claims)
	}
	if !claimedIDs[idEqual2] {
		t.Fatalf("expected second-lowest equal-expiry artifact %s to be claimed in first batch; got claims: %+v", idEqual2, claims)
	}
	if claimedIDs[idEqual3] {
		t.Fatalf("highest equal-expiry artifact %s was unexpectedly claimed in first batch (should lose id ASC tie-break)", idEqual3)
	}

	// Persisted database state verification: independently prove which rows were mutated
	type rowState struct {
		token     *domain.ID
		claimedAt *time.Time
	}
	persisted := make(map[domain.ID]rowState)
	rows, err := store.Pool.Query(ctx, `SELECT id, cleanup_claim_token, cleanup_claimed_at FROM artifacts WHERE artifact_store_id = $1`, storeID)
	if err != nil {
		t.Fatalf("query persisted state error: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id domain.ID
		var tok *domain.ID
		var cat *time.Time
		if err := rows.Scan(&id, &tok, &cat); err != nil {
			t.Fatalf("scan persisted state error: %v", err)
		}
		persisted[id] = rowState{token: tok, claimedAt: cat}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows iteration error: %v", err)
	}

	for _, id := range []domain.ID{idEarlier, idEqual1, idEqual2} {
		state, ok := persisted[id]
		if !ok {
			t.Fatalf("persisted row %s missing from database", id)
		}
		if state.token == nil {
			t.Fatalf("persisted row %s expected cleanup_claim_token IS NOT NULL", id)
		}
		if state.claimedAt == nil {
			t.Fatalf("persisted row %s expected cleanup_claimed_at IS NOT NULL", id)
		}
	}

	for _, id := range []domain.ID{idEqual3, idLater} {
		state, ok := persisted[id]
		if !ok {
			t.Fatalf("persisted row %s missing from database", id)
		}
		if state.token != nil {
			t.Fatalf("persisted row %s expected cleanup_claim_token IS NULL, got %s", id, *state.token)
		}
		if state.claimedAt != nil {
			t.Fatalf("persisted row %s expected cleanup_claimed_at IS NULL, got %v", id, *state.claimedAt)
		}
	}

	// Preserved: verify all returned cleanup_claimed_at timestamps are exactly identical (same database statement time)
	firstClaimedAt := claims[0].CleanupClaimedAt
	if firstClaimedAt.IsZero() {
		t.Fatal("expected non-zero cleanup_claimed_at")
	}
	for i, c := range claims {
		if !c.CleanupClaimedAt.Equal(firstClaimedAt) {
			t.Fatalf("claim %d cleanup_claimed_at (%v) does not match first claim statement timestamp (%v)", i, c.CleanupClaimedAt, firstClaimedAt)
		}
	}

	// Preserved: verify PER-ROW unique tokens across batch
	tokens := make(map[domain.ID]bool, len(claims))
	for _, c := range claims {
		if c.CleanupClaimToken == "" {
			t.Fatal("expected non-empty claim token")
		}
		if tokens[c.CleanupClaimToken] {
			t.Fatalf("duplicate claim token detected across batch: %s", c.CleanupClaimToken)
		}
		tokens[c.CleanupClaimToken] = true
	}

	// Optional second-batch confirmation: claim next batch with limit 1
	// Confirms the previously excluded equal-expiry row (idEqual3) becomes claimable before idLater
	claimsBatch2, err := store.ClaimExpiredArtifacts(ctx, storeID, 1)
	if err != nil {
		t.Fatalf("second claim batch error: %v", err)
	}
	if len(claimsBatch2) != 1 {
		t.Fatalf("claimsBatch2 count=%d want=1", len(claimsBatch2))
	}
	if claimsBatch2[0].ID != idEqual3 {
		t.Fatalf("claimsBatch2 claimed %s; want %s (equal-expiry artifact must precede later-expiry artifact)", claimsBatch2[0].ID, idEqual3)
	}

	// Confirm idLater is STILL unclaimed in database
	var laterToken *domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT cleanup_claim_token FROM artifacts WHERE id = $1`, idLater).Scan(&laterToken); err != nil {
		t.Fatalf("query idLater state error: %v", err)
	}
	if laterToken != nil {
		t.Fatalf("idLater unexpectedly claimed after second batch: %s", *laterToken)
	}
}

func TestClaimExpiredArtifactsDisjointSkipLocked(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	storeID := domain.ID("00000000-0000-4000-8000-000000000cc1")
	storeNonce := domain.ID("00000000-0000-4000-8000-000000000cc2")

	if _, err := store.RegisterArtifactStore(ctx, domain.ArtifactStoreRegistration{
		ID: storeID, IncarnationNonce: storeNonce, BackendKind: artifactstorage.BackendKind, MarkerFormat: artifactstorage.MarkerFormat, MarkerVersion: artifactstorage.MarkerVersion,
	}); err != nil {
		t.Fatal(err)
	}

	l := setupCleanupTestLineage(t, ctx, store, "skip-locked")

	// 1. Create a deterministic ordered set of eligible artifacts:
	// id1 is the leading eligible artifact by oldest expires_at.
	id1 := domain.ID("00000000-0000-4000-8000-000000000301")
	id2 := domain.ID("00000000-0000-4000-8000-000000000302")
	id3 := domain.ID("00000000-0000-4000-8000-000000000303")

	t1 := time.Now().Add(-3 * time.Hour).Truncate(time.Microsecond)
	t2 := time.Now().Add(-2 * time.Hour).Truncate(time.Microsecond)
	t3 := time.Now().Add(-1 * time.Hour).Truncate(time.Microsecond)

	insertedIDs := map[domain.ID]bool{id1: true, id2: true, id3: true}
	for _, item := range []struct {
		id  domain.ID
		exp time.Time
	}{
		{id1, t1},
		{id2, t2},
		{id3, t3},
	} {
		key, _ := artifactstorage.StorageKeyFor(item.id)
		if _, err := store.Pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state,expires_at) VALUES($1,$2,$3,$4,$5,'raw-provider-output','text/plain',1,'sha',1,$6,$7,'redacted',$8)`,
			item.id, l.taskID, l.runID, l.stepID, l.toolID, storeID, key, item.exp); err != nil {
			t.Fatal(err)
		}
	}

	// 2. Open an explicit database transaction on a separate acquired connection
	conn, err := store.Pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire separate connection: %v", err)
	}
	defer func() {
		if conn != nil {
			conn.Release()
		}
	}()

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback(ctx)

	// 3 & 4. Lock the leading eligible artifact (id1) and keep transaction OPEN so row lock remains held
	var lockedID domain.ID
	if err := tx.QueryRow(ctx, `SELECT id FROM artifacts WHERE id = $1 FOR UPDATE`, id1).Scan(&lockedID); err != nil {
		t.Fatalf("failed to lock leading artifact %s: %v", id1, err)
	}
	if lockedID != id1 {
		t.Fatalf("locked ID=%s want=%s", lockedID, id1)
	}

	// 5. From a different connection/call path, invoke ClaimExpiredArtifacts with a bounded context/deadline
	claimCtx, claimCancel := context.WithTimeout(ctx, 3*time.Second)
	claims1, err := store.ClaimExpiredArtifacts(claimCtx, storeID, 10)
	claimCancel()
	if err != nil {
		t.Fatalf("claim failed while leading row was locked: %v (SKIP LOCKED may have blocked)", err)
	}

	// 6 & 7. While leading row remains locked:
	// - Returned without waiting for lock holder (bounded context did not expire)
	// - Did NOT claim the locked artifact (id1)
	// - Claimed later eligible artifacts (id2, id3)
	for _, c := range claims1 {
		if c.ID == id1 {
			t.Fatalf("locked artifact %s was unexpectedly claimed while explicit row lock was held", id1)
		}
	}
	if len(claims1) != 2 {
		t.Fatalf("expected 2 claimed artifacts while leading was locked, got %d: %+v", len(claims1), claims1)
	}
	if claims1[0].ID != id2 || claims1[1].ID != id3 {
		t.Fatalf("expected claimed artifacts to be id2 and id3 in order, got: %+v", claims1)
	}

	// 8. Release/rollback the explicit lock transaction
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback lock transaction failed: %v", err)
	}
	conn.Release()
	conn = nil

	// 9. Subsequent claim from pool can now claim the previously locked still-eligible artifact
	claims2, err := store.ClaimExpiredArtifacts(ctx, storeID, 10)
	if err != nil {
		t.Fatalf("subsequent claim after lock release failed: %v", err)
	}
	if len(claims2) != 1 || claims2[0].ID != id1 {
		t.Fatalf("expected previously locked artifact %s to be claimed after release, got: %+v", id1, claims2)
	}

	// 10. Assert claimed sets are disjoint and no duplicate artifact was claimed
	claimedSet := make(map[domain.ID]string)
	for _, c := range claims1 {
		if !insertedIDs[c.ID] {
			t.Fatalf("claim1 artifact %s not in inserted set", c.ID)
		}
		claimedSet[c.ID] = "batch1"
	}
	for _, c := range claims2 {
		if !insertedIDs[c.ID] {
			t.Fatalf("claim2 artifact %s not in inserted set", c.ID)
		}
		if priorBatch, seen := claimedSet[c.ID]; seen {
			t.Fatalf("artifact %s claimed by both %s and batch2 (duplicate claim)", c.ID, priorBatch)
		}
		claimedSet[c.ID] = "batch2"
	}
	if len(claimedSet) != 3 {
		t.Fatalf("total claimed artifacts=%d want=3 across disjoint batches", len(claimedSet))
	}
}

func TestStaleClaimTakeoverAndFinalizeFencing(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	storeID := domain.ID("00000000-0000-4000-8000-000000000d01")
	storeNonce := domain.ID("00000000-0000-4000-8000-000000000d02")
	otherStoreID := domain.ID("00000000-0000-4000-8000-000000000d03")
	otherNonce := domain.ID("00000000-0000-4000-8000-000000000d04")

	for _, reg := range []domain.ArtifactStoreRegistration{
		{ID: storeID, IncarnationNonce: storeNonce, BackendKind: artifactstorage.BackendKind, MarkerFormat: artifactstorage.MarkerFormat, MarkerVersion: artifactstorage.MarkerVersion},
		{ID: otherStoreID, IncarnationNonce: otherNonce, BackendKind: artifactstorage.BackendKind, MarkerFormat: artifactstorage.MarkerFormat, MarkerVersion: artifactstorage.MarkerVersion},
	} {
		if _, err := store.RegisterArtifactStore(ctx, reg); err != nil {
			t.Fatal(err)
		}
	}

	l := setupCleanupTestLineage(t, ctx, store, "fencing-test")
	artID := domain.ID("00000000-0000-4000-8000-000000000d10")

	key, _ := artifactstorage.StorageKeyFor(artID)
	past := time.Now().Add(-time.Hour)
	if _, err := store.Pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state,expires_at) VALUES($1,$2,$3,$4,$5,'raw-provider-output','text/plain',1,'sha',1,$6,$7,'redacted',$8)`,
		artID, l.taskID, l.runID, l.stepID, l.toolID, storeID, key, past); err != nil {
		t.Fatal(err)
	}

	// 1. Process A holds claim token T1 from 16 minutes ago (stale claim)
	t1 := domain.NewID()
	if _, err := store.Pool.Exec(ctx, `UPDATE artifacts SET cleanup_claim_token=$1, cleanup_claimed_at=clock_timestamp()-interval '16 minutes' WHERE id=$2`, t1, artID); err != nil {
		t.Fatal(err)
	}

	// 2. Process B claims token T2 (stale claim takeover)
	claimsB, err := store.ClaimExpiredArtifacts(ctx, storeID, 1)
	if err != nil || len(claimsB) != 1 {
		t.Fatalf("claim B failed: %v", err)
	}
	t2 := claimsB[0].CleanupClaimToken
	if t1 == t2 {
		t.Fatalf("token was not regenerated on stale claim takeover: %s", t1)
	}

	// 3. Process A attempts to finalize with stale token T1 -> MUST FAIL (0 rows / lost claim)
	finalizedA, err := store.FinalizeArtifactCleanup(ctx, artID, storeID, t1, "removed")
	if err != nil {
		t.Fatalf("finalize A returned error: %v", err)
	}
	if finalizedA {
		t.Fatal("finalize A unexpectedly succeeded with stale token")
	}

	// Verify no audit event was emitted for process A
	var auditCount int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE task_id=$1 AND event_type='artifact_content_deleted'`, l.taskID).Scan(&auditCount); err != nil || auditCount != 0 {
		t.Fatalf("audit event was unexpectedly created by stale finalizer: count=%d", auditCount)
	}

	// 4. Mutation fencing: store mismatch with valid token T2 -> MUST FAIL (returns false)
	finalizedMismatchStore, err := store.FinalizeArtifactCleanup(ctx, artID, otherStoreID, t2, "removed")
	if err != nil {
		t.Fatalf("finalize mismatch store error: %v", err)
	}
	if finalizedMismatchStore {
		t.Fatal("finalize unexpectedly succeeded with wrong storeID")
	}
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE task_id=$1 AND event_type='artifact_content_deleted'`, l.taskID).Scan(&auditCount); err != nil || auditCount != 0 {
		t.Fatalf("audit event was unexpectedly created on store mismatch: count=%d", auditCount)
	}

	// 5. Mutation fencing: retry recording with stale token T1 -> MUST FAIL (returns false)
	retriedStale, err := store.RecordArtifactCleanupRetry(ctx, artID, storeID, t1, "filesystem_io")
	if err != nil {
		t.Fatalf("retry stale token error: %v", err)
	}
	if retriedStale {
		t.Fatal("retry unexpectedly succeeded with stale token")
	}

	// 6. Process B finalizes with T2 and observation "already_absent" -> MUST SUCCEED
	finalizedB, err := store.FinalizeArtifactCleanup(ctx, artID, storeID, t2, "already_absent")
	if err != nil {
		t.Fatalf("finalize B error: %v", err)
	}
	if !finalizedB {
		t.Fatal("finalize B with valid token failed")
	}

	// Verify tombstone state in artifacts table
	var contentDeletedAt *time.Time
	var claimTokenAfter *domain.ID
	var claimedAtAfter *time.Time
	var retryAfter *time.Time
	var lastErrorCode *string
	if err := store.Pool.QueryRow(ctx, `SELECT content_deleted_at, cleanup_claim_token, cleanup_claimed_at, cleanup_retry_after, cleanup_last_error_code FROM artifacts WHERE id=$1`, artID).
		Scan(&contentDeletedAt, &claimTokenAfter, &claimedAtAfter, &retryAfter, &lastErrorCode); err != nil || contentDeletedAt == nil {
		t.Fatalf("content_deleted_at not set: %v", err)
	}
	if claimTokenAfter != nil || claimedAtAfter != nil || retryAfter != nil || lastErrorCode != nil {
		t.Fatalf("cleanup tracking columns not cleared: token=%v at=%v retry=%v code=%v", claimTokenAfter, claimedAtAfter, retryAfter, lastErrorCode)
	}

	// Verify audit event details
	var detailsRaw []byte
	var eventProgramID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT program_id, details FROM audit_events WHERE task_id=$1 AND event_type='artifact_content_deleted'`, l.taskID).Scan(&eventProgramID, &detailsRaw); err != nil {
		t.Fatalf("load audit event error: %v", err)
	}
	if eventProgramID != l.programID {
		t.Fatalf("derived program_id=%s want=%s", eventProgramID, l.programID)
	}

	var details map[string]any
	if err := json.Unmarshal(detailsRaw, &details); err != nil {
		t.Fatal(err)
	}
	if len(details) != 3 {
		t.Fatalf("expected exactly 3 keys in artifact_content_deleted details, got %d: %s", len(details), detailsRaw)
	}
	for k := range details {
		if k != "artifact_id" && k != "artifact_store_id" && k != "delete_observation" {
			t.Fatalf("unexpected key %q in artifact_content_deleted details: %s", k, detailsRaw)
		}
	}
	if details["delete_observation"] != "already_absent" {
		t.Fatalf("delete_observation=%v want already_absent", details["delete_observation"])
	}
	if details["artifact_id"] != string(artID) {
		t.Fatalf("artifact_id=%v want %s", details["artifact_id"], artID)
	}
	if details["artifact_store_id"] != string(storeID) {
		t.Fatalf("artifact_store_id=%v want %s", details["artifact_store_id"], storeID)
	}
	for _, forbidden := range []string{"storage_key", "path", "sha256", "size", "content"} {
		if _, exists := details[forbidden]; exists {
			t.Fatalf("forbidden key %q in audit details: %s", forbidden, detailsRaw)
		}
	}

	// 7. Test delete_observation "removed" with second artifact
	artID2 := domain.ID("00000000-0000-4000-8000-000000000d20")
	key2, _ := artifactstorage.StorageKeyFor(artID2)
	if _, err := store.Pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state,expires_at) VALUES($1,$2,$3,$4,$5,'raw-provider-output','text/plain',1,'sha',1,$6,$7,'redacted',$8)`,
		artID2, l.taskID, l.runID, l.stepID, l.toolID, storeID, key2, past); err != nil {
		t.Fatal(err)
	}
	claims2, err := store.ClaimExpiredArtifacts(ctx, storeID, 1)
	if err != nil || len(claims2) != 1 || claims2[0].ID != artID2 {
		t.Fatalf("claim 2 failed: %v", err)
	}
	t3 := claims2[0].CleanupClaimToken
	finalized2, err := store.FinalizeArtifactCleanup(ctx, artID2, storeID, t3, "removed")
	if err != nil || !finalized2 {
		t.Fatalf("finalize 2 failed: %v", err)
	}
	var detailsRaw2 []byte
	if err := store.Pool.QueryRow(ctx, `SELECT details FROM audit_events WHERE task_id=$1 AND event_type='artifact_content_deleted' AND details->>'artifact_id'=$2`, l.taskID, string(artID2)).Scan(&detailsRaw2); err != nil {
		t.Fatalf("load audit event 2 error: %v", err)
	}
	var details2 map[string]any
	if err := json.Unmarshal(detailsRaw2, &details2); err != nil {
		t.Fatal(err)
	}
	if len(details2) != 3 {
		t.Fatalf("expected exactly 3 keys in artifact_content_deleted details 2, got %d: %s", len(details2), detailsRaw2)
	}
	for k := range details2 {
		if k != "artifact_id" && k != "artifact_store_id" && k != "delete_observation" {
			t.Fatalf("unexpected key %q in artifact_content_deleted details 2: %s", k, detailsRaw2)
		}
	}
	if details2["delete_observation"] != "removed" {
		t.Fatalf("expected delete_observation='removed', got details: %s", detailsRaw2)
	}
	if details2["artifact_id"] != string(artID2) {
		t.Fatalf("artifact_id=%v want %s", details2["artifact_id"], artID2)
	}
	if details2["artifact_store_id"] != string(storeID) {
		t.Fatalf("artifact_store_id=%v want %s", details2["artifact_store_id"], storeID)
	}

	// Verify exact audit event count after successful first finalization of artID2
	var auditCountBeforeDouble int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE task_id=$1 AND event_type='artifact_content_deleted'`, l.taskID).Scan(&auditCountBeforeDouble); err != nil {
		t.Fatalf("load audit count before double finalize error: %v", err)
	}
	if auditCountBeforeDouble != 2 {
		t.Fatalf("expected exactly 2 artifact_content_deleted audit events before double finalize, got %d", auditCountBeforeDouble)
	}

	// 8. Double-finalize fencing: attempt to finalize again -> MUST return false
	finalizedAgain, err := store.FinalizeArtifactCleanup(ctx, artID2, storeID, t3, "removed")
	if err != nil {
		t.Fatalf("double finalize returned error: %v", err)
	}
	if finalizedAgain {
		t.Fatal("double finalize unexpectedly succeeded on already finalized tombstone")
	}

	// Verify audit event count remains unchanged after double-finalization attempt
	var auditCountAfterDouble int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE task_id=$1 AND event_type='artifact_content_deleted'`, l.taskID).Scan(&auditCountAfterDouble); err != nil {
		t.Fatalf("load audit count after double finalize error: %v", err)
	}
	if auditCountAfterDouble != auditCountBeforeDouble {
		t.Fatalf("audit event count changed after double finalization attempt: before=%d after=%d", auditCountBeforeDouble, auditCountAfterDouble)
	}

	// 9. Test RecordArtifactCleanupRetry happy path and tracking columns
	artID3 := domain.ID("00000000-0000-4000-8000-000000000d30")
	key3, _ := artifactstorage.StorageKeyFor(artID3)
	if _, err := store.Pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state,expires_at) VALUES($1,$2,$3,$4,$5,'raw-provider-output','text/plain',1,'sha',1,$6,$7,'redacted',$8)`,
		artID3, l.taskID, l.runID, l.stepID, l.toolID, storeID, key3, past); err != nil {
		t.Fatal(err)
	}
	claims3, err := store.ClaimExpiredArtifacts(ctx, storeID, 1)
	if err != nil || len(claims3) != 1 || claims3[0].ID != artID3 {
		t.Fatalf("claim 3 failed: %v", err)
	}
	t4 := claims3[0].CleanupClaimToken
	retried, err := store.RecordArtifactCleanupRetry(ctx, artID3, storeID, t4, "durability_sync")
	if err != nil || !retried {
		t.Fatalf("retry recording failed: %v", err)
	}
	var retryAfter3 *time.Time
	var lastErrorCode3 *string
	var claimToken3 *domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT cleanup_retry_after, cleanup_last_error_code, cleanup_claim_token FROM artifacts WHERE id=$1`, artID3).
		Scan(&retryAfter3, &lastErrorCode3, &claimToken3); err != nil || retryAfter3 == nil || lastErrorCode3 == nil || *lastErrorCode3 != "durability_sync" || claimToken3 != nil {
		t.Fatalf("retry row state invalid: err=%v retry=%v code=%v token=%v", err, retryAfter3, lastErrorCode3, claimToken3)
	}
}

func TestQuarantineArtifactCleanupAndAuditAtomicity(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	storeID := domain.ID("00000000-0000-4000-8000-000000000e01")
	storeNonce := domain.ID("00000000-0000-4000-8000-000000000e02")
	otherStoreID := domain.ID("00000000-0000-4000-8000-000000000e03")
	otherNonce := domain.ID("00000000-0000-4000-8000-000000000e04")

	for _, reg := range []domain.ArtifactStoreRegistration{
		{ID: storeID, IncarnationNonce: storeNonce, BackendKind: artifactstorage.BackendKind, MarkerFormat: artifactstorage.MarkerFormat, MarkerVersion: artifactstorage.MarkerVersion},
		{ID: otherStoreID, IncarnationNonce: otherNonce, BackendKind: artifactstorage.BackendKind, MarkerFormat: artifactstorage.MarkerFormat, MarkerVersion: artifactstorage.MarkerVersion},
	} {
		if _, err := store.RegisterArtifactStore(ctx, reg); err != nil {
			t.Fatal(err)
		}
	}

	l := setupCleanupTestLineage(t, ctx, store, "quarantine-test")
	artID := domain.ID("00000000-0000-4000-8000-000000000e10")

	key, _ := artifactstorage.StorageKeyFor(artID)
	past := time.Now().Add(-time.Hour)
	if _, err := store.Pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state,expires_at) VALUES($1,$2,$3,$4,$5,'raw-provider-output','text/plain',1,'sha',1,$6,$7,'redacted',$8)`,
		artID, l.taskID, l.runID, l.stepID, l.toolID, storeID, key, past); err != nil {
		t.Fatal(err)
	}

	claims, err := store.ClaimExpiredArtifacts(ctx, storeID, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim failed: %v", err)
	}
	token := claims[0].CleanupClaimToken

	// Fencing test 1: wrong token -> returns false, nil
	wrongToken := domain.NewID()
	quarantinedWrongToken, err := store.QuarantineArtifactCleanup(ctx, artID, storeID, wrongToken, "unexpected_entry_type")
	if err != nil {
		t.Fatalf("quarantine wrong token error: %v", err)
	}
	if quarantinedWrongToken {
		t.Fatal("quarantine unexpectedly succeeded with wrong token")
	}

	// Fencing test 2: wrong store -> returns false, nil
	quarantinedWrongStore, err := store.QuarantineArtifactCleanup(ctx, artID, otherStoreID, token, "unexpected_entry_type")
	if err != nil {
		t.Fatalf("quarantine wrong store error: %v", err)
	}
	if quarantinedWrongStore {
		t.Fatal("quarantine unexpectedly succeeded with wrong store")
	}

	// Verify no audit event was emitted for failed quarantine attempts
	var auditCount int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE task_id=$1 AND event_type='artifact_quarantined'`, l.taskID).Scan(&auditCount); err != nil || auditCount != 0 {
		t.Fatalf("audit event was unexpectedly created on failed quarantine: count=%d", auditCount)
	}

	// Valid quarantine
	quarantined, err := store.QuarantineArtifactCleanup(ctx, artID, storeID, token, "unexpected_entry_type")
	if err != nil {
		t.Fatalf("quarantine error: %v", err)
	}
	if !quarantined {
		t.Fatal("quarantine reported lost claim unexpectedly")
	}

	var quarantinedAt *time.Time
	var lastErrorCode *string
	var tokenAfter *domain.ID
	var claimedAtAfter *time.Time
	var contentDeletedAfter *time.Time
	if err := store.Pool.QueryRow(ctx, `SELECT cleanup_quarantined_at, cleanup_last_error_code, cleanup_claim_token, cleanup_claimed_at, content_deleted_at FROM artifacts WHERE id=$1`, artID).
		Scan(&quarantinedAt, &lastErrorCode, &tokenAfter, &claimedAtAfter, &contentDeletedAfter); err != nil || quarantinedAt == nil || lastErrorCode == nil || *lastErrorCode != "unexpected_entry_type" {
		t.Fatalf("quarantine row state invalid: err=%v at=%v code=%v", err, quarantinedAt, lastErrorCode)
	}
	if tokenAfter != nil || claimedAtAfter != nil || contentDeletedAfter != nil {
		t.Fatalf("expected cleared claim and null content_deleted_at: token=%v at=%v deleted=%v", tokenAfter, claimedAtAfter, contentDeletedAfter)
	}

	var detailsRaw []byte
	var eventProgramID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT program_id, details FROM audit_events WHERE task_id=$1 AND event_type='artifact_quarantined'`, l.taskID).Scan(&eventProgramID, &detailsRaw); err != nil {
		t.Fatalf("quarantine audit event missing: %v", err)
	}
	if eventProgramID != l.programID {
		t.Fatalf("quarantine event program_id=%s want=%s", eventProgramID, l.programID)
	}
	var details map[string]any
	if err := json.Unmarshal(detailsRaw, &details); err != nil {
		t.Fatal(err)
	}
	if len(details) != 3 {
		t.Fatalf("expected exactly 3 keys in artifact_quarantined details, got %d: %s", len(details), detailsRaw)
	}
	for k := range details {
		if k != "artifact_id" && k != "artifact_store_id" && k != "error_code" {
			t.Fatalf("unexpected key %q in artifact_quarantined details: %s", k, detailsRaw)
		}
	}
	if details["error_code"] != "unexpected_entry_type" {
		t.Fatalf("details error_code=%v want unexpected_entry_type", details["error_code"])
	}
	if details["artifact_id"] != string(artID) {
		t.Fatalf("details artifact_id=%v want %s", details["artifact_id"], artID)
	}
	if details["artifact_store_id"] != string(storeID) {
		t.Fatalf("details artifact_store_id=%v want %s", details["artifact_store_id"], storeID)
	}
	for _, forbidden := range []string{"storage_key", "path", "sha256", "size", "content"} {
		if _, exists := details[forbidden]; exists {
			t.Fatalf("forbidden key %q in quarantine audit details: %s", forbidden, detailsRaw)
		}
	}

	// Subsequent claim pass ignores quarantined row
	subsequent, err := store.ClaimExpiredArtifacts(ctx, storeID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(subsequent) != 0 {
		t.Fatalf("quarantined artifact was claimed: %+v", subsequent)
	}
}

func TestReferencePreservationAcrossTombstone(t *testing.T) {
	// Set up full scheduled result lineage to support probe_http_source_records
	lineage := newDirectProbeHTTPSourceLineage(t, "ref-preserv", false, "probe.http", "fixture-provider", "fixture-provider")
	store := lineage.fixture.env.store
	ctx := lineage.fixture.env.ctx

	storeID := domain.ID("00000000-0000-4000-8000-000000000f01")
	storeNonce := domain.ID("00000000-0000-4000-8000-000000000f02")

	if _, err := store.RegisterArtifactStore(ctx, domain.ArtifactStoreRegistration{
		ID: storeID, IncarnationNonce: storeNonce, BackendKind: artifactstorage.BackendKind, MarkerFormat: artifactstorage.MarkerFormat, MarkerVersion: artifactstorage.MarkerVersion,
	}); err != nil {
		t.Fatal(err)
	}

	// Distinct artifacts for all 7 reference surfaces:
	// Surface 1: tool_runs.stdout_artifact_id
	// Surface 2: tool_runs.stderr_artifact_id
	// Surface 3: asset_observations.evidence_artifact_ids
	// Surface 4: candidate_findings.evidence_artifact_ids
	// Surface 5: verification_results.evidence_artifact_ids
	// Surface 6: change_items.evidence_artifact_ids
	// Surface 7: probe_http_source_records.normalized_result_artifact_id
	artStdout := domain.ID("00000000-0000-4000-8000-000000000f11")
	artStderr := domain.ID("00000000-0000-4000-8000-000000000f12")
	artEvidence := domain.ID("00000000-0000-4000-8000-000000000f13")
	artNormalized := domain.ID("00000000-0000-4000-8000-000000000f14")

	past := time.Now().Add(-time.Hour)

	insertArt := func(id domain.ID, artType string) {
		key, _ := artifactstorage.StorageKeyFor(id)
		if _, err := store.Pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state,expires_at) VALUES($1,$2,$3,$4,$5,$6,'text/plain',1,'sha',1,$7,$8,'redacted',$9)`,
			id, lineage.fixture.lineage.task.ID, lineage.fixture.lineage.runID, lineage.fixture.stepID, lineage.toolID, artType, storeID, key, past); err != nil {
			t.Fatalf("insertArt %s failed: %v", id, err)
		}
	}

	insertArt(artStdout, "raw-provider-output")
	insertArt(artStderr, "raw-provider-output")
	insertArt(artEvidence, "raw-provider-output")
	insertArt(artNormalized, "normalized-result")

	// Surface 1 & 2: tool_runs.stdout_artifact_id and tool_runs.stderr_artifact_id
	if _, err := store.Pool.Exec(ctx, `UPDATE tool_runs SET stdout_artifact_id=$1, stderr_artifact_id=$2 WHERE id=$3`,
		artStdout, artStderr, lineage.toolID); err != nil {
		t.Fatalf("update tool_runs failed: %v", err)
	}

	// Surface 3: asset_observations.evidence_artifact_ids
	if _, err := store.Pool.Exec(ctx, `UPDATE asset_observations SET evidence_artifact_ids=ARRAY[$1]::uuid[] WHERE id=$2`,
		artEvidence, lineage.observationID); err != nil {
		t.Fatalf("update asset_observations failed: %v", err)
	}

	// Surface 4: candidate_findings.evidence_artifact_ids
	findingID := domain.NewID()
	if _, err := store.Pool.Exec(ctx, `INSERT INTO candidate_findings(id,task_id,workflow_run_id,target_asset_id,source_capability,template_id,claimed_vulnerability,severity,detection_confidence,status,evidence_artifact_ids) VALUES($1,$2,$3,$4,'probe.http','tmpl-1','vuln-test','low',1,'new',ARRAY[$5]::uuid[])`,
		findingID, lineage.fixture.lineage.task.ID, lineage.fixture.lineage.runID, lineage.assetID, artEvidence); err != nil {
		t.Fatalf("insert candidate_findings failed: %v", err)
	}

	// Surface 5: verification_results.evidence_artifact_ids
	verificationID := domain.NewID()
	if _, err := store.Pool.Exec(ctx, `INSERT INTO verification_results(id,candidate_id,playbook,independent_provider,verdict,summary,evidence_artifact_ids) VALUES($1,$2,'playbook-test','test-provider','confirmed','verified',ARRAY[$3]::uuid[])`,
		verificationID, findingID, artEvidence); err != nil {
		t.Fatalf("insert verification_results failed: %v", err)
	}

	// Surface 6: change_items.evidence_artifact_ids
	changeItemID := domain.NewID()
	if _, err := store.Pool.Exec(ctx, `INSERT INTO change_items(id,program_id,workflow_run_id,kind,entity_type,entity_key,priority,title,safe_summary,evidence_artifact_ids,observed_at) VALUES($1,$2,$3,'asset_discovered','http_service','ref-key','low','title','summary',ARRAY[$4]::uuid[],clock_timestamp())`,
		changeItemID, lineage.fixture.env.programID, lineage.fixture.lineage.runID, artEvidence); err != nil {
		t.Fatalf("insert change_items failed: %v", err)
	}

	// Surface 7: probe_http_source_records.normalized_result_artifact_id
	if err := lineage.insertWithArtifact(artNormalized); err != nil {
		t.Fatalf("insert probe_http_source_records with artifact failed: %v", err)
	}

	// Claim and finalize all 4 expired artifacts
	claims, err := store.ClaimExpiredArtifacts(ctx, storeID, 10)
	if err != nil {
		t.Fatalf("claim failed: %v", err)
	}
	if len(claims) != 4 {
		t.Fatalf("claimed count=%d want=4; claims: %+v", len(claims), claims)
	}

	for _, c := range claims {
		finalized, err := store.FinalizeArtifactCleanup(ctx, c.ID, storeID, c.CleanupClaimToken, "removed")
		if err != nil || !finalized {
			t.Fatalf("finalize failed for artifact %s: %v", c.ID, err)
		}
	}

	// Verify all 7 references survived with content_deleted_at set on all artifacts
	// 1. tool_runs.stdout_artifact_id
	var stdoutRef *domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT stdout_artifact_id FROM tool_runs WHERE id=$1`, lineage.toolID).Scan(&stdoutRef); err != nil || stdoutRef == nil || *stdoutRef != artStdout {
		t.Fatalf("Surface 1 stdout_artifact_id mutated or lost: %v", stdoutRef)
	}

	// 2. tool_runs.stderr_artifact_id
	var stderrRef *domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT stderr_artifact_id FROM tool_runs WHERE id=$1`, lineage.toolID).Scan(&stderrRef); err != nil || stderrRef == nil || *stderrRef != artStderr {
		t.Fatalf("Surface 2 stderr_artifact_id mutated or lost: %v", stderrRef)
	}

	// 3. asset_observations.evidence_artifact_ids
	var obsEvidence []domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT evidence_artifact_ids FROM asset_observations WHERE id=$1`, lineage.observationID).Scan(&obsEvidence); err != nil || len(obsEvidence) != 1 || obsEvidence[0] != artEvidence {
		t.Fatalf("Surface 3 asset_observations.evidence_artifact_ids mutated or lost: %v", obsEvidence)
	}

	// 4. candidate_findings.evidence_artifact_ids
	var findingEvidence []domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT evidence_artifact_ids FROM candidate_findings WHERE id=$1`, findingID).Scan(&findingEvidence); err != nil || len(findingEvidence) != 1 || findingEvidence[0] != artEvidence {
		t.Fatalf("Surface 4 candidate_findings.evidence_artifact_ids mutated or lost: %v", findingEvidence)
	}

	// 5. verification_results.evidence_artifact_ids
	var verifEvidence []domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT evidence_artifact_ids FROM verification_results WHERE id=$1`, verificationID).Scan(&verifEvidence); err != nil || len(verifEvidence) != 1 || verifEvidence[0] != artEvidence {
		t.Fatalf("Surface 5 verification_results.evidence_artifact_ids mutated or lost: %v", verifEvidence)
	}

	// 6. change_items.evidence_artifact_ids
	var changeEvidence []domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT evidence_artifact_ids FROM change_items WHERE id=$1`, changeItemID).Scan(&changeEvidence); err != nil || len(changeEvidence) != 1 || changeEvidence[0] != artEvidence {
		t.Fatalf("Surface 6 change_items.evidence_artifact_ids mutated or lost: %v", changeEvidence)
	}

	// 7. probe_http_source_records.normalized_result_artifact_id
	var normalizedRef *domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT normalized_result_artifact_id FROM probe_http_source_records WHERE normalized_result_artifact_id=$1`, artNormalized).Scan(&normalizedRef); err != nil || normalizedRef == nil || *normalizedRef != artNormalized {
		t.Fatalf("Surface 7 probe_http_source_records.normalized_result_artifact_id mutated or lost: %v", normalizedRef)
	}

	// Verify all 4 artifacts are tombstones
	for _, id := range []domain.ID{artStdout, artStderr, artEvidence, artNormalized} {
		var contentDeletedAt *time.Time
		if err := store.Pool.QueryRow(ctx, `SELECT content_deleted_at FROM artifacts WHERE id=$1`, id).Scan(&contentDeletedAt); err != nil || contentDeletedAt == nil {
			t.Fatalf("artifact %s content_deleted_at not set: %v", id, err)
		}
	}
}
