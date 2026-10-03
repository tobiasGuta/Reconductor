package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/queue"
)

func TestRedisRedeliveryUsesPostgresCompletedAuthority(t *testing.T) {
	redisAddress := os.Getenv("TEST_REDIS_ADDR")
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if redisAddress == "" || databaseURL == "" {
		t.Skip("TEST_REDIS_ADDR and TEST_DATABASE_URL are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	store := openRedisPostgresWorkerTestStore(t, ctx, databaseURL)
	idempotencyKey := "redis-postgres-authority-" + string(domain.NewID())
	insertCompletedWorkerAuthority(t, ctx, store, idempotencyKey)

	client := redis.NewClient(&redis.Options{
		Addr:     redisAddress,
		Username: os.Getenv("TEST_REDIS_USERNAME"),
		Password: os.Getenv("TEST_REDIS_PASSWORD"),
		DB:       0,
	})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	suffix := string(domain.NewID())
	names := queue.Names{
		Jobs:       "test.worker.jobs." + suffix,
		Results:    "test.worker.results." + suffix,
		Events:     "test.worker.events." + suffix,
		DeadLetter: "test.worker.dead." + suffix,
		Retry:      "test.worker.retry." + suffix,
	}
	t.Cleanup(func() {
		_ = client.Del(context.Background(), names.Jobs, names.Results, names.Events, names.DeadLetter, names.Retry).Err()
	})
	group := "test-worker-" + suffix
	first := queue.NewWithNames(client, group, "first", 1, time.Millisecond, names)
	if err := first.EnsureGroup(ctx); err != nil {
		t.Fatal(err)
	}
	job := queue.Job{
		ID:        domain.NewID(),
		ProgramID: domain.NewID(),
		Action: domain.ActionRequest{
			ID:             domain.NewID(),
			IdempotencyKey: idempotencyKey,
		},
	}
	messageID, err := first.Enqueue(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	delivered, err := first.Read(ctx, time.Second, 1)
	if err != nil || len(delivered) != 1 {
		t.Fatalf("initial delivery: deliveries=%#v err=%v", delivered, err)
	}
	second := queue.NewWithNames(client, group, "second", 1, time.Millisecond, names)
	reclaimed, err := second.ClaimStale(ctx, 0, 1)
	if err != nil || len(reclaimed) != 1 {
		t.Fatalf("reclaimed delivery: deliveries=%#v err=%v", reclaimed, err)
	}
	if delivered[0].MessageID != messageID || reclaimed[0].MessageID != messageID || reclaimed[0].Job.ID != job.ID || reclaimed[0].Job.Action.ID != job.Action.ID {
		t.Fatalf("transport redelivery changed identity: initial=%#v reclaimed=%#v", delivered[0], reclaimed[0])
	}

	before := workerAuthorityCounts(t, ctx, store)
	service := &Service{
		Queue:        second,
		Results:      store,
		LeaseTimeout: time.Hour,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	errors := make(chan error, 2)
	go func() { errors <- service.handle(ctx, delivered[0]) }()
	go func() { errors <- service.handle(ctx, reclaimed[0]) }()
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatalf("completed-authority duplicate handling: %v", err)
		}
	}
	after := workerAuthorityCounts(t, ctx, store)
	if before != after {
		t.Fatalf("duplicate Redis delivery mutated PostgreSQL authority: before=%#v after=%#v", before, after)
	}
	if after.steps != 1 || after.tools != 0 || after.status != string(domain.StepSucceeded) {
		t.Fatalf("unexpected authoritative state after duplicate delivery: %#v", after)
	}
	pending, err := second.Pending(ctx)
	if err != nil || pending.Count != 0 {
		t.Fatalf("pending after duplicate completion acknowledgement: pending=%#v err=%v", pending, err)
	}
	if length, err := client.XLen(ctx, names.Jobs).Result(); err != nil || length != 0 {
		t.Fatalf("job stream after duplicate completion acknowledgement: length=%d err=%v", length, err)
	}
	if length, err := client.XLen(ctx, names.Results).Result(); err != nil || length != 2 {
		t.Fatalf("derived result projections after at-least-once acknowledgement: length=%d err=%v", length, err)
	}
}

func openRedisPostgresWorkerTestStore(t *testing.T, ctx context.Context, databaseURL string) *database.Store {
	t.Helper()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "redis_worker_" + strings.ReplaceAll(string(domain.NewID()), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop Redis/PostgreSQL integration schema: %v", err)
		}
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	store, err := database.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return store
}

func insertCompletedWorkerAuthority(t *testing.T, ctx context.Context, store *database.Store, idempotencyKey string) {
	t.Helper()
	now := time.Now().UTC()
	programID, scopeID, definitionID := domain.NewID(), domain.NewID(), domain.NewID()
	taskID, runID, stepID := domain.NewID(), domain.NewID(), domain.NewID()
	program := domain.Program{
		ID: programID, Name: "redis-authority-" + string(programID), Platform: "integration", Description: "Redis authority boundary",
		ScopeReference: "synthetic://redis-authority", PolicyReference: "integration", ScopeDigest: "scope", IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{},
		TargetPlanDigest: "plan", ScopePlanWarnings: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now,
	}
	snapshot := domain.ScopeSnapshot{
		ID: scopeID, ScopeReference: program.ScopeReference, ScopeDigest: program.ScopeDigest, IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{},
		TargetPlanDigest: program.TargetPlanDigest, PlanningWarnings: json.RawMessage(`[]`), TargetPlan: json.RawMessage(`{}`), CreatedAt: now,
	}
	if err := store.CreateProgram(ctx, program, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements,created_at) VALUES($1,$2,'1','Redis authority fixture','{}','{}',$3)`, definitionID, "redis-authority-"+string(definitionID), now); err != nil {
		t.Fatal(err)
	}
	task := domain.Task{ID: taskID, ProgramID: programID, Objective: "verify Redis transport authority boundary", WorkflowDefinitionID: definitionID, Status: domain.TaskCompleted, RequestedBy: "integration-test", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,completed_at,trigger_source,summary,materialized_definition,materialization_digest,original_scope_version_id) VALUES($1,$2,$3,'1','completed',$4,$4,'integration-test','{}','{}',$5,$6)`, runID, taskID, definitionID, now, strings.Repeat("a", 64), scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,attempt_count,input,output,started_at,completed_at,idempotency_key) VALUES($1,$2,'redis-authority','test.redis-authority','succeeded',1,'{}','{}',$3,$3,$4)`, stepID, runID, now, idempotencyKey); err != nil {
		t.Fatal(err)
	}
}

type workerAuthorityState struct {
	steps, tools, audits int
	status               string
}

func workerAuthorityCounts(t *testing.T, ctx context.Context, store *database.Store) workerAuthorityState {
	t.Helper()
	var state workerAuthorityState
	if err := store.Pool.QueryRow(ctx, `SELECT count(*),COALESCE(min(status),'') FROM step_runs`).Scan(&state.steps, &state.status); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM tool_runs`).Scan(&state.tools); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&state.audits); err != nil {
		t.Fatal(err)
	}
	return state
}
