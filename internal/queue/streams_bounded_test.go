package queue

import (
	"context"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestAckRejectsActionResultBeforeRedisMutation(t *testing.T) {
	streams := &Streams{}
	err := streams.Ack(context.Background(), "message", domain.ActionResult{RequestID: domain.NewID(), Status: "succeeded", Output: []byte(`{"unbounded":true}`)})
	if err == nil || !strings.Contains(err.Error(), "bounded result envelope") {
		t.Fatalf("error=%v", err)
	}
}

func TestAckValidatesBoundedQueueProjectionBeforeRedisMutation(t *testing.T) {
	streams := &Streams{}
	for name, result := range map[string]domain.QueueResultV1{
		"noncanonical id": {Version: "queue-result/v1", ActionRequestID: "NOT-A-UUID", Status: "succeeded", Summary: "ok"},
		"unknown status":  {Version: "queue-result/v1", ActionRequestID: domain.NewID(), Status: "other", Summary: "ok"},
		"large summary":   {Version: "queue-result/v1", ActionRequestID: domain.NewID(), Status: "succeeded", Summary: strings.Repeat("x", domain.SafeMessageMaxBytes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := streams.Ack(context.Background(), "message", result); err == nil {
				t.Fatal("invalid projection reached Redis client")
			}
		})
	}
}
