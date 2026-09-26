package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/scope"
)

const pumpRetriesScript = `
local due = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, ARGV[2])
local moved = 0
for _, raw in ipairs(due) do
  if redis.call('ZREM', KEYS[1], raw) == 1 then
    local ok, job = pcall(cjson.decode, raw)
    if ok and type(job) == 'table' and job['id'] and type(job['action']) == 'table' then
      local idempotency = job['action']['idempotency_key'] or ''
      redis.call('XADD', KEYS[2], '*', 'payload', raw, 'job_id', job['id'], 'idempotency_key', idempotency)
      moved = moved + 1
    end
  end
end
return moved
`

const touchLeaseScript = `
local pending = redis.call('XPENDING', KEYS[1], ARGV[1], ARGV[2], ARGV[2], 1)
if #pending ~= 1 or pending[1][1] ~= ARGV[2] or pending[1][2] ~= ARGV[3] then
  return 0
end
local claimed = redis.call('XCLAIM', KEYS[1], ARGV[1], ARGV[3], 0, ARGV[2], 'JUSTID')
if #claimed == 1 and claimed[1] == ARGV[2] then
  return 1
end
return 0
`

const (
	JobsStream       = "platform.capability.jobs"
	ResultsStream    = "platform.capability.results"
	EventsStream     = "platform.events"
	DeadLetterStream = "platform.dead_letter"
	RetrySet         = "platform.capability.retry"
)

type Names struct{ Jobs, Results, Events, DeadLetter, Retry string }

func DefaultNames() Names {
	return Names{Jobs: JobsStream, Results: ResultsStream, Events: EventsStream, DeadLetter: DeadLetterStream, Retry: RetrySet}
}

type Job struct {
	ID            domain.ID            `json:"id"`
	ProgramID     domain.ID            `json:"program_id"`
	Action        domain.ActionRequest `json:"action"`
	Provider      string               `json:"provider"`
	Policy        policy.Policy        `json:"policy"`
	ScopeIncludes []scope.Rule         `json:"scope_includes"`
	ScopeExcludes []scope.Rule         `json:"scope_excludes"`
	Approved      bool                 `json:"approved"`
	Attempt       int                  `json:"attempt"`
	EnqueuedAt    time.Time            `json:"enqueued_at"`
	AvailableAt   time.Time            `json:"available_at"`
}
type Delivery struct {
	MessageID string
	Job       Job
}
type Streams struct {
	client          *redis.Client
	group, consumer string
	maxRetries      int
	retryBase       time.Duration
	names           Names
}

func New(client *redis.Client, group, consumer string, maxRetries int, retryBase time.Duration) *Streams {
	return NewWithNames(client, group, consumer, maxRetries, retryBase, DefaultNames())
}
func NewWithNames(client *redis.Client, group, consumer string, maxRetries int, retryBase time.Duration, names Names) *Streams {
	return &Streams{client: client, group: group, consumer: consumer, maxRetries: maxRetries, retryBase: retryBase, names: names}
}
func (s *Streams) EnsureGroup(ctx context.Context) error {
	err := s.client.XGroupCreateMkStream(ctx, s.names.Jobs, s.group, "0").Err()
	if err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
		return err
	}
	return nil
}
func (s *Streams) Enqueue(ctx context.Context, j Job) (string, error) {
	if j.ID == "" {
		j.ID = domain.NewID()
	}
	if j.EnqueuedAt.IsZero() {
		j.EnqueuedAt = time.Now().UTC()
	}
	if j.AvailableAt.IsZero() {
		j.AvailableAt = j.EnqueuedAt
	}
	b, err := json.Marshal(j)
	if err != nil {
		return "", err
	}
	pipe := s.client.TxPipeline()
	cmd := pipe.XAdd(ctx, &redis.XAddArgs{Stream: s.names.Jobs, Values: map[string]any{"payload": string(b), "job_id": string(j.ID), "idempotency_key": j.Action.IdempotencyKey}})
	pipe.XAdd(ctx, &redis.XAddArgs{Stream: s.names.Events, Values: map[string]any{"event": "job_enqueued", "job_id": string(j.ID), "request_id": string(j.Action.ID)}})
	if _, err := pipe.Exec(ctx); err != nil {
		return "", err
	}
	return cmd.Val(), nil
}
func (s *Streams) Read(ctx context.Context, block time.Duration, count int64) ([]Delivery, error) {
	streams, err := s.client.XReadGroup(ctx, &redis.XReadGroupArgs{Group: s.group, Consumer: s.consumer, Streams: []string{s.names.Jobs, ">"}, Count: count, Block: block}).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decode(streams)
}
func (s *Streams) ClaimStale(ctx context.Context, minIdle time.Duration, count int64) ([]Delivery, error) {
	messages, _, err := s.client.XAutoClaim(ctx, &redis.XAutoClaimArgs{Stream: s.names.Jobs, Group: s.group, Consumer: s.consumer, MinIdle: minIdle, Start: "0-0", Count: count}).Result()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decode([]redis.XStream{{Stream: s.names.Jobs, Messages: messages}})
}
func (s *Streams) Touch(ctx context.Context, messageID string) error {
	refreshed, err := s.client.Eval(ctx, touchLeaseScript, []string{s.names.Jobs}, s.group, messageID, s.consumer).Int()
	if err != nil {
		return err
	}
	if refreshed != 1 {
		return fmt.Errorf("queue delivery %s lease could not be refreshed", messageID)
	}
	return nil
}
func (s *Streams) Ack(ctx context.Context, messageID string, result any) error {
	requestID := domain.ID("")
	switch value := result.(type) {
	case domain.ResultEnvelopeV1:
		if err := value.Validate(); err != nil {
			return err
		}
		requestID = value.ActionRequestID
	case domain.QueueResultV1:
		if value.Version != "queue-result/v1" || (value.Status != "succeeded" && value.Status != "failed" && value.Status != "retryable" && value.Status != "cancelled") {
			return fmt.Errorf("invalid bounded queue result")
		}
		if _, err := domain.ParseID(string(value.ActionRequestID)); err != nil {
			return fmt.Errorf("invalid bounded queue result")
		}
		if err := domain.ValidateUTF8Bytes("queue result summary", value.Summary, domain.SafeMessageMaxBytes); err != nil {
			return fmt.Errorf("invalid bounded queue result")
		}
		requestID = value.ActionRequestID
	default:
		return fmt.Errorf("queue acknowledgement requires a bounded result envelope or projection")
	}
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	pipe := s.client.TxPipeline()
	pipe.XAdd(ctx, &redis.XAddArgs{Stream: s.names.Results, Values: map[string]any{"payload": string(b), "request_id": string(requestID)}})
	pipe.XAck(ctx, s.names.Jobs, s.group, messageID)
	pipe.XDel(ctx, s.names.Jobs, messageID)
	pipe.XAdd(ctx, &redis.XAddArgs{Stream: s.names.Events, Values: map[string]any{"event": "job_completed", "request_id": string(requestID), "message_id": messageID}})
	_, err = pipe.Exec(ctx)
	return err
}
func (s *Streams) Fail(ctx context.Context, messageID string, j Job, classified string, retryable bool) error {
	classified = domain.BoundUTF8(classified, domain.SafeMessageMaxBytes)
	j.Attempt++
	if retryable && j.Attempt <= s.maxRetries {
		delay := s.retryBase * time.Duration(1<<min(j.Attempt-1, 10))
		j.AvailableAt = time.Now().UTC().Add(delay)
		b, err := json.Marshal(j)
		if err != nil {
			return err
		}
		pipe := s.client.TxPipeline()
		pipe.ZAdd(ctx, s.names.Retry, redis.Z{Score: float64(j.AvailableAt.UnixMilli()), Member: string(b)})
		pipe.XAck(ctx, s.names.Jobs, s.group, messageID)
		pipe.XDel(ctx, s.names.Jobs, messageID)
		pipe.XAdd(ctx, &redis.XAddArgs{Stream: s.names.Events, Values: map[string]any{"event": "job_retry_scheduled", "job_id": string(j.ID), "attempt": j.Attempt}})
		_, err = pipe.Exec(ctx)
		return err
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	pipe := s.client.TxPipeline()
	pipe.XAdd(ctx, &redis.XAddArgs{Stream: s.names.DeadLetter, Values: map[string]any{"payload": string(b), "error": classified, "failed_at": time.Now().UTC().Format(time.RFC3339Nano)}})
	pipe.XAck(ctx, s.names.Jobs, s.group, messageID)
	pipe.XDel(ctx, s.names.Jobs, messageID)
	pipe.XAdd(ctx, &redis.XAddArgs{Stream: s.names.Events, Values: map[string]any{"event": "job_dead_lettered", "job_id": string(j.ID), "attempt": j.Attempt}})
	_, err = pipe.Exec(ctx)
	return err
}
func (s *Streams) PumpRetries(ctx context.Context, limit int64) (int, error) {
	if limit < 1 {
		return 0, nil
	}
	return s.client.Eval(ctx, pumpRetriesScript, []string{s.names.Retry, s.names.Jobs}, time.Now().UnixMilli(), limit).Int()
}
func (s *Streams) Pending(ctx context.Context) (*redis.XPending, error) {
	return s.client.XPending(ctx, s.names.Jobs, s.group).Result()
}
func (s *Streams) DeadLetters(ctx context.Context, count int64) ([]redis.XMessage, error) {
	return s.client.XRevRangeN(ctx, s.names.DeadLetter, "+", "-", count).Result()
}
func (s *Streams) RetryDeadLetter(ctx context.Context, messageID string) error {
	messages, err := s.client.XRangeN(ctx, s.names.DeadLetter, messageID, messageID, 1).Result()
	if err != nil {
		return err
	}
	if len(messages) != 1 {
		return fmt.Errorf("dead-letter message %s not found", messageID)
	}
	raw, ok := messages[0].Values["payload"].(string)
	if !ok {
		return fmt.Errorf("dead-letter payload is invalid")
	}
	var j Job
	if err := json.Unmarshal([]byte(raw), &j); err != nil {
		return err
	}
	j.Attempt = 0
	j.AvailableAt = time.Now().UTC()
	if _, err := s.Enqueue(ctx, j); err != nil {
		return err
	}
	return s.client.XDel(ctx, s.names.DeadLetter, messageID).Err()
}
func decode(streams []redis.XStream) ([]Delivery, error) {
	var out []Delivery
	for _, stream := range streams {
		for _, m := range stream.Messages {
			raw, ok := m.Values["payload"].(string)
			if !ok {
				return nil, fmt.Errorf("message %s has no string payload", m.ID)
			}
			var j Job
			if err := json.Unmarshal([]byte(raw), &j); err != nil {
				return nil, fmt.Errorf("message %s: %w", m.ID, err)
			}
			out = append(out, Delivery{m.ID, j})
		}
	}
	return out, nil
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
