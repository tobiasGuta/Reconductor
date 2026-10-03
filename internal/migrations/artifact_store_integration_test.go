package migrations

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestArtifactStoreOwnershipMigration(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "migration_artifact_store_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop migration test schema: %v", err)
		}
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	pool, err := pgxpool.New(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	applyEmbeddedMigrationsThrough(t, ctx, pool, 14)
	const (
		programID    = "00000000-0000-4000-8000-000000001600"
		definitionID = "00000000-0000-4000-8000-000000001601"
		taskID       = "00000000-0000-4000-8000-000000001602"
		runID        = "00000000-0000-4000-8000-000000001603"
		stepID       = "00000000-0000-4000-8000-000000001604"
		toolID       = "00000000-0000-4000-8000-000000001605"
		legacyID     = "00000000-0000-4000-8000-000000001606"
		storeID      = "00000000-0000-4000-8000-000000001607"
		storeNonce   = "00000000-0000-4000-8000-000000001608"
		lockedLegacy = "00000000-0000-4000-8000-000000001609"
		queuedLegacy = "00000000-0000-4000-8000-000000001610"
		secondStore  = "00000000-0000-4000-8000-000000001620"
		secondNonce  = "00000000-0000-4000-8000-000000001621"
	)
	legacyLocator := `C:\synthetic-fixture\retained\artifact.bin`
	for _, statement := range []string{
		`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES('` + programID + `','artifact-store-migration','integration','synthetic://scope','integration')`,
		`INSERT INTO workflow_definitions(id,name,version,definition) VALUES('` + definitionID + `','artifact-store-migration','1','{}')`,
		`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES('` + taskID + `','` + programID + `','artifact store migration','` + definitionID + `','running','integration')`,
		`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source) VALUES('` + runID + `','` + taskID + `','` + definitionID + `','1','running','integration')`,
		`INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,idempotency_key) VALUES('` + stepID + `','` + runID + `','artifact-store','test.capability','running','artifact-store-migration')`,
		`INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at) VALUES('` + toolID + `','` + stepID + `','test.capability','integration',clock_timestamp())`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,storage_location,redaction_state,sensitive) VALUES($1,$2,$3,$4,$5,'raw-provider-output','application/octet-stream',7,'legacy-sha',$6,'redacted',false)`, legacyID, taskID, runID, stepID, toolID, legacyLocator); err != nil {
		t.Fatal(err)
	}
	migration15, err := files.ReadFile("sql/0015_workflow_template_materialization_integrity.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(migration15)); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version,name) VALUES(15,'0015_workflow_template_materialization_integrity.sql')`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE step_runs SET status='succeeded',completed_at=clock_timestamp() WHERE id=$1`, stepID); err != nil {
		t.Fatal(err)
	}
	var locatorBefore string
	if err := pool.QueryRow(ctx, `SELECT encode(convert_to(storage_location,'UTF8'),'hex') FROM artifacts WHERE id=$1`, legacyID).Scan(&locatorBefore); err != nil {
		t.Fatal(err)
	}

	oldWriter, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer oldWriter.Rollback(context.Background())
	if _, err := oldWriter.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,storage_location,redaction_state,sensitive) VALUES($1,$2,$3,$4,$5,'raw-provider-output','application/octet-stream',7,'legacy-sha',$6,'redacted',false)`, lockedLegacy, taskID, runID, stepID, toolID, legacyLocator); err != nil {
		t.Fatal(err)
	}
	var artifactRelationOID uint32
	if err := pool.QueryRow(ctx, `SELECT 'artifacts'::regclass::oid`).Scan(&artifactRelationOID); err != nil {
		t.Fatal(err)
	}
	migrationConnection, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer migrationConnection.Release()
	var migrationPID int
	if err := migrationConnection.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&migrationPID); err != nil {
		t.Fatal(err)
	}
	migrationDone := make(chan error, 1)
	go func() { migrationDone <- Up(ctx, migrationConnection) }()
	waitForRelationLock(t, ctx, admin, migrationPID, artifactRelationOID, "AccessExclusiveLock", false)

	queuedWriter, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer queuedWriter.Release()
	var queuedWriterPID int
	if err := queuedWriter.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&queuedWriterPID); err != nil {
		t.Fatal(err)
	}
	queuedWriterDone := make(chan error, 1)
	go func() {
		_, writeErr := queuedWriter.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,storage_location,redaction_state,sensitive) VALUES($1,$2,$3,$4,$5,'raw-provider-output','application/octet-stream',7,'legacy-sha',$6,'redacted',false)`, queuedLegacy, taskID, runID, stepID, toolID, legacyLocator)
		queuedWriterDone <- writeErr
	}()
	waitForRelationLock(t, ctx, admin, queuedWriterPID, artifactRelationOID, "RowExclusiveLock", false)
	if err := oldWriter.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-migrationDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("migration did not complete after the old writer committed")
	}
	select {
	case err := <-queuedWriterDone:
		if err == nil {
			t.Fatal("writer queued behind migration was accepted with obsolete addressing")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer queued behind migration did not resume")
	}
	if err := Up(ctx, pool); err != nil {
		t.Fatalf("second migration run: %v", err)
	}
	var version int16
	var store, key *string
	var locator, locatorAfter string
	if err := pool.QueryRow(ctx, `SELECT addressing_version,artifact_store_id::text,storage_key,storage_location,encode(convert_to(storage_location,'UTF8'),'hex') FROM artifacts WHERE id=$1`, legacyID).Scan(&version, &store, &key, &locator, &locatorAfter); err != nil {
		t.Fatal(err)
	}
	if version != 0 || store != nil || key != nil || locator != legacyLocator || locatorAfter != locatorBefore {
		t.Fatalf("legacy address changed: version=%d store=%v key=%v locator=%q bytes_before=%s bytes_after=%s", version, store, key, locator, locatorBefore, locatorAfter)
	}
	var lockedLegacyVersion int16
	if err := pool.QueryRow(ctx, `SELECT addressing_version FROM artifacts WHERE id=$1`, lockedLegacy).Scan(&lockedLegacyVersion); err != nil || lockedLegacyVersion != 0 {
		t.Fatalf("old writer row version=%d err=%v", lockedLegacyVersion, err)
	}
	var migrationCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=16 AND name='0016_artifact_store_ownership.sql'`).Scan(&migrationCount); err != nil || migrationCount != 1 {
		t.Fatalf("migration ledger count=%d err=%v", migrationCount, err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO artifact_stores(id,incarnation_nonce,backend_kind,marker_format,marker_version) VALUES($1,$2,'local-v1','reconductor-artifact-store',1)`, storeID, storeNonce); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO artifact_stores(id,incarnation_nonce,backend_kind,marker_format,marker_version) VALUES($1,$2,'local-v1','reconductor-artifact-store',1)`, secondStore, secondNonce); err != nil {
		t.Fatal(err)
	}
	assertRejected := func(name, sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	assertRejected("obsolete writer", `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,storage_location,redaction_state) VALUES('00000000-0000-4000-8000-000000001622',$1,$2,$3,$4,'raw-provider-output','text/plain',1,'sha','obsolete://locator','redacted')`, taskID, runID, stepID, toolID)
	assertRejected("explicit new v0", `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,storage_location,redaction_state) VALUES('00000000-0000-4000-8000-000000001611',$1,$2,$3,$4,'raw-provider-output','text/plain',1,'sha',0,'legacy://locator','redacted')`, taskID, runID, stepID, toolID)
	assertRejected("incomplete v1", `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,redaction_state) VALUES('00000000-0000-4000-8000-000000001612',$1,$2,$3,$4,'raw-provider-output','text/plain',1,'sha',1,'redacted')`, taskID, runID, stepID, toolID)
	assertRejected("modern locator", `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,storage_location,redaction_state) VALUES('00000000-0000-4000-8000-000000001613',$1,$2,$3,$4,'raw-provider-output','text/plain',1,'sha',1,$5,'v1/00/00000000-0000-4000-8000-000000001613','modern://locator','redacted')`, taskID, runID, stepID, toolID, storeID)
	assertRejected("unregistered store", `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state) VALUES('00000000-0000-4000-8000-000000001614',$1,$2,$3,$4,'raw-provider-output','text/plain',1,'sha',1,'00000000-0000-4000-8000-000000009999','v1/00/00000000-0000-4000-8000-000000001614','redacted')`, taskID, runID, stepID, toolID)
	assertRejected("wrong key", `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state) VALUES('00000000-0000-4000-8000-000000001615',$1,$2,$3,$4,'raw-provider-output','text/plain',1,'sha',1,$5,'v1/ff/00000000-0000-4000-8000-000000001615','redacted')`, taskID, runID, stepID, toolID, storeID)
	assertRejected("wrong UUID key", `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,redaction_state) VALUES('00000000-0000-4000-8000-000000001619',$1,$2,$3,$4,'raw-provider-output','text/plain',1,'sha',1,$5,'v1/00/00000000-0000-4000-8000-000000001615','redacted')`, taskID, runID, stepID, toolID, storeID)
	assertArtifactStoreMigrationTrigger(t, "legacy locator mutation", "Artifact addressing is immutable", pool, ctx, `UPDATE artifacts SET storage_location='legacy://changed' WHERE id=$1`, legacyID)

	const modernID = "00000000-0000-4000-8000-000000001616"
	if _, err := pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,expires_at,redaction_state) VALUES($1,$2,$3,$4,$5,'raw-provider-output','text/plain',1,'sha',1,$6,$7,clock_timestamp()-interval '1 second','redacted')`, modernID, taskID, runID, stepID, toolID, storeID, "v1/00/"+modernID); err != nil {
		t.Fatalf("valid v1 insert: %v", err)
	}
	assertArtifactStoreMigrationTrigger(t, "constraint-valid address mutation", "Artifact addressing is immutable", pool, ctx, `UPDATE artifacts SET artifact_store_id=$2 WHERE id=$1`, modernID, secondStore)
	assertRejected("address downgrade", `UPDATE artifacts SET addressing_version=0,artifact_store_id=NULL,storage_key=NULL,storage_location='legacy://downgrade' WHERE id=$1`, modernID)
	assertArtifactStoreMigrationTrigger(t, "artifact delete", "Artifact metadata deletion is prohibited", pool, ctx, `DELETE FROM artifacts WHERE id=$1`, modernID)
	assertArtifactStoreMigrationTrigger(t, "constraint-valid registry mutation", "artifact store registrations are immutable", pool, ctx, `UPDATE artifact_stores SET incarnation_nonce=$2 WHERE id=$1`, storeID, "00000000-0000-4000-8000-000000001623")
	assertArtifactStoreMigrationTrigger(t, "unreferenced registry delete", "artifact store registrations are immutable", pool, ctx, `DELETE FROM artifact_stores WHERE id=$1`, secondStore)
	assertRejected("registry nonce reuse", `INSERT INTO artifact_stores(id,incarnation_nonce,backend_kind,marker_format,marker_version) VALUES('00000000-0000-4000-8000-000000001618',$1,'local-v1','reconductor-artifact-store',1)`, storeNonce)
	var retained, expiryEvents, legacyOwned int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM artifacts WHERE id=$1),(SELECT count(*) FROM audit_events WHERE event_type='artifact_expired' AND step_run_id=$2),(SELECT count(*) FROM artifacts WHERE id=$3 AND artifact_store_id IS NOT NULL)`, modernID, stepID, legacyID).Scan(&retained, &expiryEvents, &legacyOwned); err != nil {
		t.Fatal(err)
	}
	if retained != 1 || expiryEvents != 0 || legacyOwned != 0 {
		t.Fatalf("expiry or legacy ownership changed rows: artifacts=%d expiry_events=%d legacy_owned=%d", retained, expiryEvents, legacyOwned)
	}
}

func waitForRelationLock(t *testing.T, ctx context.Context, observer *pgxpool.Pool, pid int, relationOID uint32, mode string, granted bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var found bool
		err := observer.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM pg_locks
			WHERE pid=$1 AND relation=$2 AND mode=$3 AND granted=$4
		)`, pid, relationOID, mode, granted).Scan(&found)
		if err != nil {
			t.Fatal(err)
		}
		if found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("backend %d did not reach %s granted=%v on relation %d", pid, mode, granted, relationOID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertArtifactStoreMigrationTrigger(t *testing.T, name, message string, pool *pgxpool.Pool, ctx context.Context, statement string, args ...any) {
	t.Helper()
	_, err := pool.Exec(ctx, statement, args...)
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "P0001" || postgresError.Message != message {
		t.Fatalf("%s trigger error=%v", name, err)
	}
}
