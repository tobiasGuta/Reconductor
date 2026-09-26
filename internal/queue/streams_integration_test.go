package queue

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestRedisStreamsDeliveryRecoveryAndDeadLetter(t *testing.T) {
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR is not set")
	}
	ctx := context.Background()
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Username: os.Getenv("TEST_REDIS_USERNAME"),
		Password: os.Getenv("TEST_REDIS_PASSWORD"),
		DB:       0,
	})
	defer client.Close()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	suffix := string(domain.NewID())
	names := Names{Jobs: "test.jobs." + suffix, Results: "test.results." + suffix, Events: "test.events." + suffix, DeadLetter: "test.dead." + suffix, Retry: "test.retry." + suffix}
	defer client.Del(ctx, names.Jobs, names.Results, names.Events, names.DeadLetter, names.Retry)
	group := "test-" + suffix
	first := NewWithNames(client, group, "first", 1, time.Millisecond, names)
	if err := first.EnsureGroup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.EnsureGroup(ctx); err != nil {
		t.Fatalf("idempotent group setup: %v", err)
	}
	job := Job{ID: domain.NewID(), Action: domain.ActionRequest{ID: domain.NewID(), IdempotencyKey: "integration-key"}}
	messageID, err := first.Enqueue(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	if messageID == string(job.ID) || messageID == string(job.Action.ID) {
		t.Fatalf("Redis message identity collapsed into durable identity: message=%s job=%s action=%s", messageID, job.ID, job.Action.ID)
	}
	deliveries, err := first.Read(ctx, time.Second, 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("read: %v %#v", err, deliveries)
	}
	if deliveries[0].MessageID != messageID || deliveries[0].Job.ID != job.ID || deliveries[0].Job.Action.ID != job.Action.ID {
		t.Fatalf("initial delivery identity changed: %#v", deliveries[0])
	}
	pending, err := first.Pending(ctx)
	if err != nil || pending.Count != 1 {
		t.Fatalf("pending after initial delivery: pending=%#v err=%v", pending, err)
	}
	second := NewWithNames(client, group, "second", 1, time.Millisecond, names)
	claimed, err := second.ClaimStale(ctx, 0, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v %#v", err, claimed)
	}
	if claimed[0].MessageID != messageID || claimed[0].Job.ID != job.ID || claimed[0].Job.Action.ID != job.Action.ID {
		t.Fatalf("redelivery identity changed: %#v", claimed[0])
	}
	if err := second.Fail(ctx, claimed[0].MessageID, claimed[0].Job, "temporary", true); err != nil {
		t.Fatal(err)
	}
	pumpRetriesUntilMoved(t, ctx, second)
	retried, err := second.Read(ctx, time.Second, 1)
	if err != nil || len(retried) != 1 {
		t.Fatalf("retry delivery: %v %#v", err, retried)
	}
	if retried[0].MessageID == messageID || retried[0].Job.ID != job.ID || retried[0].Job.Action.ID != job.Action.ID || retried[0].Job.Attempt != 1 {
		t.Fatalf("retry changed logical identity or attempt: %#v", retried[0])
	}
	if err := second.Fail(ctx, retried[0].MessageID, retried[0].Job, "permanent", false); err != nil {
		t.Fatal(err)
	}
	dead, err := second.DeadLetters(ctx, 10)
	if err != nil || len(dead) != 1 {
		t.Fatalf("dead letters: %v %#v", err, dead)
	}
	if err := second.RetryDeadLetter(ctx, dead[0].ID); err != nil {
		t.Fatal(err)
	}
	requeued, err := second.Read(ctx, time.Second, 1)
	if err != nil || len(requeued) != 1 {
		t.Fatalf("dead-letter requeue delivery: %v %#v", err, requeued)
	}
	if requeued[0].Job.ID != job.ID || requeued[0].Job.Action.ID != job.Action.ID || requeued[0].Job.Attempt != 0 {
		t.Fatalf("dead-letter requeue changed logical identity: %#v", requeued[0])
	}
	result := domain.QueueResultV1{Version: "queue-result/v1", ActionRequestID: job.Action.ID, Status: "succeeded", Summary: "transport completed"}
	if err := second.Ack(ctx, requeued[0].MessageID, result); err != nil {
		t.Fatal(err)
	}
	if err := second.Ack(ctx, requeued[0].MessageID, result); err != nil {
		t.Fatalf("repeated acknowledgement: %v", err)
	}
	pending, err = second.Pending(ctx)
	if err != nil || pending.Count != 0 {
		t.Fatalf("pending after repeated acknowledgement: pending=%#v err=%v", pending, err)
	}
	if length, err := client.XLen(ctx, names.Jobs).Result(); err != nil || length != 0 {
		t.Fatalf("job stream after repeated acknowledgement: length=%d err=%v", length, err)
	}
}

func pumpRetriesUntilMoved(t *testing.T, ctx context.Context, streams *Streams) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		moved, err := streams.PumpRetries(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		if moved == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("retry entry did not become eligible before the bounded deadline")
		}
		time.Sleep(time.Millisecond)
	}
}
