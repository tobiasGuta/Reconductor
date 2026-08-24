package database

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/intelligence"
	"github.com/tobiasGuta/Reconductor/internal/normalize"
	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
)

func TestPersistEndpointsTrustIdentityAndAggregateReductions(t *testing.T) {
	store, ctx := endpointIntegrationStore(t)
	programA := createEndpointProgram(t, ctx, store, "trust-a")
	programB := createEndpointProgram(t, ctx, store, "trust-b")
	older := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	newer := older.Add(2 * time.Hour)

	large, _, err := normalize.CanonicalEndpoint("https://a.example/api/users/999?x=z", "GET", "application/json")
	if err != nil {
		t.Fatal(err)
	}
	small, _, err := normalize.CanonicalEndpoint("https://a.example:443/api/users/111?x=a", "GET", "application/json; charset=utf-8")
	if err != nil {
		t.Fatal(err)
	}
	if large.Digest != small.Digest {
		t.Fatal("same corrected identity produced different digests")
	}
	if err := persistEndpointPayload(ctx, store, programA, &newer, endpointPayload(t, large)); err != nil {
		t.Fatal(err)
	}
	if err := persistEndpointPayload(ctx, store, programA, &older, endpointPayload(t, small)); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		program domain.ID
		raw     string
	}{
		{program: programA, raw: "https://b.example/api/users/123?x=1"},
		{program: programA, raw: "http://a.example/api/users/123?x=1"},
		{program: programA, raw: "https://a.example:8443/api/users/123?x=1"},
		{program: programB, raw: "https://a.example/api/users/123?x=1"},
	} {
		key, _, err := normalize.CanonicalEndpoint(test.raw, "GET", "application/json")
		if err != nil {
			t.Fatal(err)
		}
		if err := persistEndpointPayload(ctx, store, test.program, &newer, endpointPayload(t, key)); err != nil {
			t.Fatal(err)
		}
	}

	var rowCount int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM endpoints`).Scan(&rowCount); err != nil {
		t.Fatal(err)
	}
	if rowCount != 5 {
		t.Fatalf("endpoint rows=%d want=5", rowCount)
	}
	var exactURL, scheme, host string
	var port int
	var firstSeen, lastSeen time.Time
	if err := store.Pool.QueryRow(ctx, `SELECT exact_url,origin_scheme,origin_host,origin_effective_port,first_seen,last_seen FROM endpoints WHERE program_id=$1 AND origin_scheme='https' AND origin_host='a.example' AND origin_effective_port=443`, programA).Scan(&exactURL, &scheme, &host, &port, &firstSeen, &lastSeen); err != nil {
		t.Fatal(err)
	}
	if exactURL != small.ExactURL || scheme != "https" || host != "a.example" || port != 443 || !firstSeen.Equal(older) || !lastSeen.Equal(newer) {
		t.Fatalf("aggregate exact=%q origin=%s/%s/%d first=%s last=%s", exactURL, scheme, host, port, firstSeen, lastSeen)
	}

	base, _, err := normalize.CanonicalEndpoint("https://invalid.example/api/users/123?a=1&b=2", "GET", "application/json")
	if err != nil {
		t.Fatal(err)
	}
	invalid := []struct {
		name        string
		completedAt *time.Time
		payload     json.RawMessage
	}{
		{name: "missing endpoints", completedAt: &newer, payload: json.RawMessage(`{}`)},
		{name: "null endpoints", completedAt: &newer, payload: json.RawMessage(`{"endpoints":null}`)},
		{name: "missing completion", payload: endpointPayload(t, base)},
		{name: "zero completion", completedAt: new(time.Time), payload: endpointPayload(t, base)},
		{name: "missing field", completedAt: &newer, payload: json.RawMessage(`{"endpoints":[{"exact_url":"https://invalid.example/"}]}`)},
	}
	for _, mutation := range []struct {
		name   string
		mutate func(*normalize.EndpointKey)
	}{
		{name: "exact URL", mutate: func(key *normalize.EndpointKey) { key.ExactURL = "https://invalid.example:443/api/users/123?a=1&b=2" }},
		{name: "route", mutate: func(key *normalize.EndpointKey) { key.RouteSignature = "/other" }},
		{name: "method", mutate: func(key *normalize.EndpointKey) { key.Method = "get" }},
		{name: "content type", mutate: func(key *normalize.EndpointKey) { key.ContentType = "Application/JSON" }},
		{name: "query names", mutate: func(key *normalize.EndpointKey) { key.QueryParameters = []string{"b", "a"} }},
		{name: "digest", mutate: func(key *normalize.EndpointKey) { key.Digest = strings.Repeat("0", 64) }},
	} {
		key := base
		key.QueryParameters = append([]string(nil), base.QueryParameters...)
		mutation.mutate(&key)
		invalid = append(invalid, struct {
			name        string
			completedAt *time.Time
			payload     json.RawMessage
		}{name: "mismatched " + mutation.name, completedAt: &newer, payload: endpointPayload(t, key)})
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			before := endpointState(t, ctx, store)
			if err := persistEndpointPayload(ctx, store, programA, test.completedAt, test.payload); err == nil {
				t.Fatal("invalid endpoint result was accepted")
			}
			after := endpointState(t, ctx, store)
			if before != after {
				t.Fatalf("failed persistence mutated endpoints\nbefore=%s\nafter=%s", before, after)
			}
		})
	}
	t.Run("malformed exact URL error is sanitized", func(t *testing.T) {
		const sentinel = "endpoint-secret-sentinel"
		malformed := base
		malformed.QueryParameters = append([]string(nil), base.QueryParameters...)
		malformed.ExactURL = "https://invalid.example/%zz?token=" + sentinel
		before := endpointState(t, ctx, store)
		err := persistEndpointPayload(ctx, store, programA, &newer, endpointPayload(t, malformed))
		if err == nil {
			t.Fatal("malformed endpoint result was accepted")
		}
		if strings.Contains(err.Error(), malformed.ExactURL) || strings.Contains(err.Error(), sentinel) {
			t.Fatalf("persistence error exposed malformed exact_url: %q", err)
		}
		if after := endpointState(t, ctx, store); before != after {
			t.Fatalf("failed malformed persistence mutated endpoints\nbefore=%s\nafter=%s", before, after)
		}
	})
	if err := persistEndpointPayload(ctx, store, programA, &newer, json.RawMessage(`{"endpoints":[]}`)); err != nil {
		t.Fatalf("empty endpoints array: %v", err)
	}
}

func TestEndpointMigrationFailsClosedForOldWriters(t *testing.T) {
	store, ctx := endpointIntegrationStore(t)
	programID := createEndpointProgram(t, ctx, store, "old-writer")
	before := endpointState(t, ctx, store)
	if _, err := store.Pool.Exec(ctx, `INSERT INTO endpoints(id,program_id,exact_url,route_signature,method,content_type,parameter_schema,first_seen,last_seen) VALUES(gen_random_uuid(),$1,'https://legacy.example/','/','GET','','[]',clock_timestamp(),clock_timestamp())`, programID); err == nil || !strings.Contains(err.Error(), "endpoints_corrected_row_ck") {
		t.Fatalf("direct legacy insert error=%v", err)
	}
	if after := endpointState(t, ctx, store); before != after {
		t.Fatalf("direct legacy insert changed state before=%s after=%s", before, after)
	}
	_, err := store.Pool.Exec(ctx, `INSERT INTO endpoints(id,program_id,exact_url,route_signature,method,content_type,parameter_schema,first_seen,last_seen) VALUES(gen_random_uuid(),$1,'https://old-writer.example/','/','GET','','[]',now(),now()) ON CONFLICT(program_id,route_signature,method,content_type,parameter_schema) DO UPDATE SET exact_url=EXCLUDED.exact_url,last_seen=now()`, programID)
	if err == nil {
		t.Fatal("old production-style endpoint upsert succeeded")
	}
	if after := endpointState(t, ctx, store); before != after {
		t.Fatalf("old production-style endpoint upsert changed state before=%s after=%s", before, after)
	}
}

func TestPersistEndpointsConcurrentSameIdentityUsesPostgresArbitration(t *testing.T) {
	store, ctx := endpointIntegrationStore(t)
	programID := createEndpointProgram(t, ctx, store, "concurrency")
	older := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)
	large, _, err := normalize.CanonicalEndpoint("https://race.example/api/users/999?x=z", "GET", "")
	if err != nil {
		t.Fatal(err)
	}
	small, _, err := normalize.CanonicalEndpoint("https://race.example/api/users/111?x=a", "GET", "")
	if err != nil {
		t.Fatal(err)
	}
	largePayload := endpointPayload(t, large)
	smallPayload := endpointPayload(t, small)

	connectionOne, err := store.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connectionOne.Release)
	connectionTwo, err := store.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connectionTwo.Release)
	txOne, err := connectionOne.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	txOneOpen := true
	var txTwo pgx.Tx
	txTwoOpen := false
	t2Started := false
	t2Done := make(chan struct{})
	t2Context, cancelT2 := context.WithTimeout(ctx, 30*time.Second)
	t.Cleanup(func() {
		cancelT2()
		if txOneOpen {
			rollbackContext, cancelRollback := context.WithTimeout(context.Background(), 5*time.Second)
			if err := txOne.Rollback(rollbackContext); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
				t.Errorf("roll back first endpoint transaction: %v", err)
			}
			cancelRollback()
			txOneOpen = false
		}
		if t2Started {
			waitContext, cancelWait := context.WithTimeout(context.Background(), 5*time.Second)
			finished := false
			select {
			case <-t2Done:
				finished = true
			case <-waitContext.Done():
				t.Errorf("second endpoint upsert did not stop after cancellation: %v", waitContext.Err())
				closeContext, cancelClose := context.WithTimeout(context.Background(), 5*time.Second)
				if err := connectionTwo.Conn().Close(closeContext); err != nil {
					t.Errorf("force-close second endpoint connection: %v", err)
				}
				cancelClose()
				txTwoOpen = false
				finalWaitContext, cancelFinalWait := context.WithTimeout(context.Background(), 5*time.Second)
				select {
				case <-t2Done:
					finished = true
				case <-finalWaitContext.Done():
					t.Errorf("second endpoint upsert goroutine did not finish after forced connection close: %v", finalWaitContext.Err())
				}
				cancelFinalWait()
			}
			cancelWait()
			if !finished {
				txTwoOpen = false
			}
		}
		if txTwoOpen {
			rollbackContext, cancelRollback := context.WithTimeout(context.Background(), 5*time.Second)
			if err := txTwo.Rollback(rollbackContext); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
				t.Errorf("roll back second endpoint transaction: %v", err)
			}
			cancelRollback()
			txTwoOpen = false
		}
	})
	txTwo, err = connectionTwo.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	txTwoOpen = true
	if err := persistEndpoints(ctx, txOne, programID, &newer, largePayload); err != nil {
		t.Fatal(err)
	}
	pidOne := int32(connectionOne.Conn().PgConn().PID())
	pidTwo := int32(connectionTwo.Conn().PgConn().PID())
	result := make(chan error, 1)
	t2Started = true
	go func() {
		defer close(t2Done)
		result <- persistEndpoints(t2Context, txTwo, programID, &older, smallPayload)
	}()
	waitForEndpointBlock(t, ctx, store, pidOne, pidTwo, result)
	commitOneContext, cancelCommitOne := context.WithTimeout(ctx, 5*time.Second)
	err = txOne.Commit(commitOneContext)
	cancelCommitOne()
	if err != nil {
		t.Fatal(err)
	}
	txOneOpen = false
	completionContext, cancelCompletion := context.WithTimeout(ctx, 10*time.Second)
	defer cancelCompletion()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-completionContext.Done():
		t.Fatalf("second endpoint upsert remained blocked after first commit: %v", completionContext.Err())
	}
	completionWaitContext, cancelCompletionWait := context.WithTimeout(ctx, 5*time.Second)
	select {
	case <-t2Done:
	case <-completionWaitContext.Done():
		cancelCompletionWait()
		t.Fatalf("second endpoint upsert goroutine did not finish after returning its result: %v", completionWaitContext.Err())
	}
	cancelCompletionWait()
	commitTwoContext, cancelCommitTwo := context.WithTimeout(ctx, 5*time.Second)
	err = txTwo.Commit(commitTwoContext)
	cancelCommitTwo()
	if err != nil {
		t.Fatal(err)
	}
	txTwoOpen = false

	var count int
	var exact string
	var firstSeen, lastSeen time.Time
	if err := store.Pool.QueryRow(ctx, `SELECT count(*),min(exact_url),min(first_seen),max(last_seen) FROM endpoints WHERE program_id=$1`, programID).Scan(&count, &exact, &firstSeen, &lastSeen); err != nil {
		t.Fatal(err)
	}
	if count != 1 || exact != small.ExactURL || !firstSeen.Equal(older) || !lastSeen.Equal(newer) {
		t.Fatalf("concurrent aggregate count=%d exact=%q first=%s last=%s", count, exact, firstSeen, lastSeen)
	}
}

func TestPersistEndpointsOlderTransactionCommittingLaterDoesNotRegressLastSeen(t *testing.T) {
	store, ctx := endpointIntegrationStore(t)
	programID := createEndpointProgram(t, ctx, store, "commit-order")
	older := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)
	large, _, err := normalize.CanonicalEndpoint("https://commit.example/api/users/999?x=z", "GET", "")
	if err != nil {
		t.Fatal(err)
	}
	small, _, err := normalize.CanonicalEndpoint("https://commit.example/api/users/111?x=a", "GET", "")
	if err != nil {
		t.Fatal(err)
	}
	if large.Digest != small.Digest || !(small.ExactURL < large.ExactURL) {
		t.Fatal("reverse aggregate fixture does not share identity with ordered exact URLs")
	}
	oldTransaction, err := store.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldOpen := true
	t.Cleanup(func() {
		if oldOpen {
			_ = oldTransaction.Rollback(context.Background())
		}
	})
	if err := persistEndpointPayload(ctx, store, programID, &newer, endpointPayload(t, small)); err != nil {
		t.Fatal(err)
	}
	if err := persistEndpoints(ctx, oldTransaction, programID, &older, endpointPayload(t, large)); err != nil {
		t.Fatal(err)
	}
	if err := oldTransaction.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	oldOpen = false
	var exactURL string
	var firstSeen, lastSeen time.Time
	if err := store.Pool.QueryRow(ctx, `SELECT exact_url,first_seen,last_seen FROM endpoints WHERE program_id=$1`, programID).Scan(&exactURL, &firstSeen, &lastSeen); err != nil {
		t.Fatal(err)
	}
	if exactURL != small.ExactURL || !firstSeen.Equal(older) || !lastSeen.Equal(newer) {
		t.Fatalf("commit order regressed independent aggregate exact=%q first=%s last=%s", exactURL, firstSeen, lastSeen)
	}
}

func TestPersistResultEndpointIdentityFailureRollsBackEntireTransaction(t *testing.T) {
	fixture := newScheduledResultFixture(t, "endpoint-identity-rollback", "classify.endpoint")
	action := scheduledProviderAction(fixture, 1)
	queueJobID := domain.NewID()
	admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, &queueJobID, "fixture-provider")
	const sentinel = "rollback-secret-sentinel"
	classified, err := intelligence.Classify(intelligence.Input{HTTPObservations: []provideroutput.Record{
		{
			Provider:   "httpx",
			Kind:       provideroutput.URLRecord,
			Target:     "https://rollback.example/api/accounts/alpha?token=" + sentinel + "-a",
			StatusCode: 200,
			Fields: map[string]any{
				"method":               "GET",
				"request_content_type": "application/json",
			},
		},
		{
			Provider:   "httpx",
			Kind:       provideroutput.URLRecord,
			Target:     "https://rollback.example/api/users/123?token=" + sentinel + "-b",
			StatusCode: 200,
			Fields: map[string]any{
				"method":               "GET",
				"request_content_type": "application/json",
			},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(classified.Endpoints) != 2 || len(classified.Classifications) != 2 {
		t.Fatalf("classifier fixture endpoints=%d classifications=%d", len(classified.Endpoints), len(classified.Classifications))
	}
	malformedExactURL := classified.Endpoints[1].ExactURL
	classified.Endpoints[1].RouteSignature = "/serialized-identity-is-inconsistent"
	output, err := json.Marshal(classified)
	if err != nil {
		t.Fatal(err)
	}
	step, tool, artifacts, result := scheduledResultPayload(fixture, output)
	applyScheduledProviderAdmission(tool, &result, admission)
	before := resultFenceSnapshot(t, fixture)
	err = fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission)
	if err == nil {
		t.Fatal("inconsistent serialized endpoint identity was accepted")
	}
	if !strings.Contains(err.Error(), "classify.endpoint endpoint 1 route_signature does not match canonical identity") {
		t.Fatalf("endpoint identity failure=%q", err)
	}
	if strings.Contains(err.Error(), malformedExactURL) || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("endpoint identity failure exposed URL material: %q", err)
	}
	after := resultFenceSnapshot(t, fixture)
	if after != before {
		t.Fatalf("endpoint identity failure mutated the result transaction\nbefore=%s\nafter=%s", before, after)
	}
	assertEndpointResultRollbackCounts(t, fixture)
}

func assertEndpointResultRollbackCounts(t *testing.T, fixture scheduledResultFixture) {
	t.Helper()
	var stepStatus domain.StepStatus
	var tools, artifacts, artifactAudits, endpoints int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
		(SELECT status FROM step_runs WHERE id=$1),
		(SELECT count(*) FROM tool_runs WHERE step_run_id=$1),
		(SELECT count(*) FROM artifacts WHERE step_run_id=$1),
		(SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type='artifact_retention_applied'),
		(SELECT count(*) FROM endpoints WHERE program_id=$2)`, fixture.stepID, fixture.env.programID).Scan(&stepStatus, &tools, &artifacts, &artifactAudits, &endpoints); err != nil {
		t.Fatal(err)
	}
	if stepStatus != domain.StepRunning || tools != 0 || artifacts != 0 || artifactAudits != 0 || endpoints != 0 {
		t.Fatalf("rollback state step=%s tools=%d artifacts=%d artifact_audits=%d endpoints=%d", stepStatus, tools, artifacts, artifactAudits, endpoints)
	}
}

func waitForEndpointBlock(t *testing.T, parent context.Context, store *Store, blockerPID, blockedPID int32, result <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := store.Pool.QueryRow(ctx, `SELECT $1::integer = ANY(pg_blocking_pids($2::integer))`, blockerPID, blockedPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case err := <-result:
			t.Fatalf("second endpoint upsert completed before PostgreSQL reported blocking: %v", err)
		case <-ctx.Done():
			t.Fatalf("PostgreSQL did not report the expected endpoint upsert blocker: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func persistEndpointPayload(ctx context.Context, store *Store, programID domain.ID, completedAt *time.Time, payload json.RawMessage) error {
	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	if err := persistEndpoints(ctx, tx, programID, completedAt, payload); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func endpointPayload(t *testing.T, keys ...normalize.EndpointKey) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(struct {
		Endpoints []normalize.EndpointKey `json:"endpoints"`
	}{Endpoints: keys})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func endpointState(t *testing.T, ctx context.Context, store *Store) string {
	t.Helper()
	var state string
	if err := store.Pool.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb)::text FROM endpoints e`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func createEndpointProgram(t *testing.T, ctx context.Context, store *Store, name string) domain.ID {
	t.Helper()
	id := domain.NewID()
	if _, err := store.Pool.Exec(ctx, `INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,$2,'integration','synthetic://local','integration')`, id, name+"-"+string(id)); err != nil {
		t.Fatal(err)
	}
	return id
}

func endpointIntegrationStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
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
	schema := "endpoint_" + strings.ReplaceAll(string(domain.NewID()), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop endpoint integration schema: %v", err)
		}
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	store, err := Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return store, ctx
}
