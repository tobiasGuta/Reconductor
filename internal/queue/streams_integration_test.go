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
	first := NewWithNames(client, group, "first", 0, time.Millisecond, names)
	if err := first.EnsureGroup(ctx); err != nil {
		t.Fatal(err)
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
	second := NewWithNames(client, group, "second", 0, time.Millisecond, names)
	time.Sleep(5 * time.Millisecond)
	claimed, err := second.ClaimStale(ctx, time.Millisecond, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v %#v", err, claimed)
	}
	if claimed[0].MessageID != messageID || claimed[0].Job.ID != job.ID || claimed[0].Job.Action.ID != job.Action.ID {
		t.Fatalf("redelivery identity changed: %#v", claimed[0])
	}
	if err := second.Fail(ctx, claimed[0].MessageID, claimed[0].Job, "permanent", false); err != nil {
		t.Fatal(err)
	}
	dead, err := second.DeadLetters(ctx, 10)
	if err != nil || len(dead) != 1 {
		t.Fatalf("dead letters: %v %#v", err, dead)
	}
}
