package console

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/queue"
	schedulecron "github.com/tobiasGuta/Reconductor/internal/scheduler"
)

//go:embed static/*
var staticFiles embed.FS

type Store interface {
	ConsoleSnapshot(context.Context, domain.ID) (database.ConsoleSnapshot, error)
	DecideApproval(context.Context, domain.ID, string, string) error
}

type scheduleMutationStore interface {
	CreateSchedule(context.Context, domain.Schedule) error
	GetSchedule(context.Context, domain.ID) (domain.Schedule, error)
	UpdateSchedule(context.Context, domain.Schedule, string) error
	SetScheduleEnabled(context.Context, domain.ID, bool, string) error
	EnqueueRunNow(context.Context, domain.ID, string) (domain.ScheduledExecution, error)
	RequestScheduledExecutionResume(context.Context, domain.ID, string) error
}

type reviewMutationStore interface {
	ReviewChangeItem(context.Context, domain.ID, domain.ChangeReviewDisposition, string, string) error
	AcknowledgeScopeVersion(context.Context, domain.ID, string) error
}

type Queue interface {
	Pending(context.Context) (*redis.XPending, error)
	DeadLetters(context.Context, int64) ([]redis.XMessage, error)
	RetryDeadLetter(context.Context, string) error
}

type Server struct {
	store     Store
	queue     Queue
	validator *schedulecron.ScheduleValidator
	mux       *http.ServeMux
}

type Snapshot struct {
	database.ConsoleSnapshot
	Queue QueueStatus `json:"queue"`
}

type QueueStatus struct {
	Pending     int64        `json:"pending"`
	DeadLetters []DeadLetter `json:"dead_letters"`
	Error       string       `json:"error,omitempty"`
}

type DeadLetter struct {
	MessageID  string    `json:"message_id"`
	JobID      domain.ID `json:"job_id,omitempty"`
	Capability string    `json:"capability,omitempty"`
	Provider   string    `json:"provider,omitempty"`
	Attempt    int       `json:"attempt"`
	Error      string    `json:"error"`
	FailedAt   string    `json:"failed_at"`
}

func New(store Store, workQueue Queue, validators ...*schedulecron.ScheduleValidator) http.Handler {
	var validator *schedulecron.ScheduleValidator
	if len(validators) > 0 {
		validator = validators[0]
	}
	s := &Server{store: store, queue: workQueue, validator: validator, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /api/v1/snapshot", s.snapshot)
	s.mux.HandleFunc("POST /api/v1/approvals/{id}/decision", s.decideApproval)
	s.mux.HandleFunc("POST /api/v1/schedules", s.createSchedule)
	s.mux.HandleFunc("POST /api/v1/schedules/{id}/update", s.updateSchedule)
	s.mux.HandleFunc("POST /api/v1/schedules/{id}/enable", s.enableSchedule)
	s.mux.HandleFunc("POST /api/v1/schedules/{id}/disable", s.disableSchedule)
	s.mux.HandleFunc("POST /api/v1/schedules/{id}/run-now", s.runNow)
	s.mux.HandleFunc("POST /api/v1/scheduled-executions/{id}/resume", s.resumeScheduledExecution)
	s.mux.HandleFunc("POST /api/v1/change-items/{id}/review", s.reviewChangeItem)
	s.mux.HandleFunc("POST /api/v1/scope-versions/{id}/acknowledge", s.acknowledgeScopeVersion)
	s.mux.HandleFunc("POST /api/v1/dead-letters/{id}/retry", s.retryDeadLetter)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	staticRoot, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	assets := http.FileServer(http.FS(staticRoot))
	s.mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/app.js" && r.URL.Path != "/styles.css" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/" {
			w.Header().Set("Cache-Control", "no-store")
		}
		assets.ServeHTTP(w, r)
	}))
	return s.securityHeaders(s.mux)
}

func (s *Server) createSchedule(w http.ResponseWriter, r *http.Request) {
	if !validOperatorRequest(r) {
		writeError(w, http.StatusForbidden, "operator request validation failed")
		return
	}
	store, ok := s.store.(scheduleMutationStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "schedule mutations unavailable")
		return
	}
	var body struct {
		ProgramID      domain.ID `json:"program_id"`
		Name           string    `json:"name"`
		WorkflowName   string    `json:"workflow_name"`
		Objective      string    `json:"objective"`
		CronExpression string    `json:"cron_expression"`
		Timezone       string    `json:"timezone"`
		Headless       bool      `json:"headless"`
		Actor          string    `json:"actor"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Actor == "" {
		body.Actor = "console-operator"
	}
	if body.WorkflowName == "" {
		body.WorkflowName = "continuous-web-recon"
	}
	if s.validator == nil {
		writeError(w, http.StatusServiceUnavailable, "schedule validation unavailable")
		return
	}
	now := time.Now().UTC()
	item := domain.Schedule{ID: domain.NewID(), ProgramID: body.ProgramID, Name: body.Name, WorkflowName: body.WorkflowName, Objective: body.Objective, CronExpression: body.CronExpression, Timezone: body.Timezone, Enabled: true, Headless: body.Headless, CreatedBy: body.Actor, CreatedAt: now, UpdatedAt: now}
	item, err := s.validator.Validate(r.Context(), item, now)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := store.CreateSchedule(r.Context(), item); err != nil {
		writeError(w, http.StatusConflict, "schedule could not be created")
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) updateSchedule(w http.ResponseWriter, r *http.Request) {
	if !validOperatorRequest(r) {
		writeError(w, http.StatusForbidden, "operator request validation failed")
		return
	}
	store, ok := s.store.(scheduleMutationStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "schedule mutations unavailable")
		return
	}
	current, err := store.GetSchedule(r.Context(), domain.ID(r.PathValue("id")))
	if err != nil {
		writeError(w, http.StatusNotFound, "schedule not found")
		return
	}
	var body struct {
		Name           *string `json:"name"`
		WorkflowName   *string `json:"workflow_name"`
		Objective      *string `json:"objective"`
		CronExpression *string `json:"cron_expression"`
		Timezone       *string `json:"timezone"`
		Enabled        *bool   `json:"enabled"`
		Headless       *bool   `json:"headless"`
		Actor          string  `json:"actor"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Name != nil {
		current.Name = *body.Name
	}
	if body.WorkflowName != nil {
		current.WorkflowName = *body.WorkflowName
	}
	if body.Objective != nil {
		current.Objective = *body.Objective
	}
	if body.CronExpression != nil {
		current.CronExpression = *body.CronExpression
	}
	if body.Timezone != nil {
		current.Timezone = *body.Timezone
	}
	if body.Enabled != nil {
		current.Enabled = *body.Enabled
	}
	if body.Headless != nil {
		current.Headless = *body.Headless
	}
	if s.validator == nil {
		writeError(w, http.StatusServiceUnavailable, "schedule validation unavailable")
		return
	}
	current, err = s.validator.Validate(r.Context(), current, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Actor == "" {
		body.Actor = "console-operator"
	}
	if err := store.UpdateSchedule(r.Context(), current, body.Actor); err != nil {
		writeError(w, http.StatusConflict, "schedule could not be updated")
		return
	}
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) enableSchedule(w http.ResponseWriter, r *http.Request) {
	s.setScheduleEnabled(w, r, true)
}

func (s *Server) disableSchedule(w http.ResponseWriter, r *http.Request) {
	s.setScheduleEnabled(w, r, false)
}

func (s *Server) setScheduleEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	if !validOperatorRequest(r) {
		writeError(w, http.StatusForbidden, "operator request validation failed")
		return
	}
	if !jsonContentType(r) {
		writeError(w, http.StatusBadRequest, "content type must be application/json")
		return
	}
	store, ok := s.store.(scheduleMutationStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "schedule mutations unavailable")
		return
	}
	if err := store.SetScheduleEnabled(r.Context(), domain.ID(r.PathValue("id")), enabled, "console-operator"); err != nil {
		writeError(w, http.StatusConflict, "schedule state could not be changed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": enabled})
}

func (s *Server) runNow(w http.ResponseWriter, r *http.Request) {
	if !validOperatorRequest(r) {
		writeError(w, http.StatusForbidden, "operator request validation failed")
		return
	}
	if !jsonContentType(r) {
		writeError(w, http.StatusBadRequest, "content type must be application/json")
		return
	}
	store, ok := s.store.(scheduleMutationStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "schedule mutations unavailable")
		return
	}
	item, err := store.EnqueueRunNow(r.Context(), domain.ID(r.PathValue("id")), "console-operator")
	if err != nil {
		if errors.Is(err, database.ErrScheduleOverlap) {
			writeError(w, http.StatusConflict, "schedule already has a queued or active execution")
			return
		}
		writeError(w, http.StatusConflict, "run now could not be queued")
		return
	}
	writeJSON(w, http.StatusAccepted, item)
}

func (s *Server) resumeScheduledExecution(w http.ResponseWriter, r *http.Request) {
	if !validOperatorRequest(r) {
		writeError(w, http.StatusForbidden, "operator request validation failed")
		return
	}
	if !jsonContentType(r) {
		writeError(w, http.StatusBadRequest, "content type must be application/json")
		return
	}
	store, ok := s.store.(scheduleMutationStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "schedule mutations unavailable")
		return
	}
	if err := store.RequestScheduledExecutionResume(r.Context(), domain.ID(r.PathValue("id")), "console-operator"); err != nil {
		if errors.Is(err, database.ErrApprovalRejected) {
			writeError(w, http.StatusConflict, "scheduled execution was closed because approval was rejected")
			return
		}
		writeError(w, http.StatusConflict, "scheduled execution is not ready to resume")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "pending"})
}

func (s *Server) reviewChangeItem(w http.ResponseWriter, r *http.Request) {
	if !validOperatorRequest(r) {
		writeError(w, http.StatusForbidden, "operator request validation failed")
		return
	}
	store, ok := s.store.(reviewMutationStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "review mutations unavailable")
		return
	}
	var body struct {
		Disposition string `json:"disposition"`
		Note        string `json:"note"`
		Actor       string `json:"actor"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Actor == "" {
		body.Actor = "console-operator"
	}
	if err := store.ReviewChangeItem(r.Context(), domain.ID(r.PathValue("id")), domain.ChangeReviewDisposition(body.Disposition), body.Note, body.Actor); err != nil {
		writeError(w, http.StatusBadRequest, "change review was not accepted")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"disposition": body.Disposition})
}

func (s *Server) acknowledgeScopeVersion(w http.ResponseWriter, r *http.Request) {
	if !validOperatorRequest(r) {
		writeError(w, http.StatusForbidden, "operator request validation failed")
		return
	}
	if !jsonContentType(r) {
		writeError(w, http.StatusBadRequest, "content type must be application/json")
		return
	}
	store, ok := s.store.(reviewMutationStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "review mutations unavailable")
		return
	}
	if err := store.AcknowledgeScopeVersion(r.Context(), domain.ID(r.PathValue("id")), "console-operator"); err != nil {
		writeError(w, http.StatusConflict, "scope version could not be acknowledged")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) {
	data, err := s.store.ConsoleSnapshot(r.Context(), domain.ID(strings.TrimSpace(r.URL.Query().Get("program_id"))))
	if err != nil {
		slog.Error("operator console snapshot failed", "error", err)
		writeError(w, http.StatusInternalServerError, "console data is temporarily unavailable")
		return
	}
	out := Snapshot{ConsoleSnapshot: data, Queue: QueueStatus{DeadLetters: []DeadLetter{}}}
	if s.queue != nil {
		pending, pendingErr := s.queue.Pending(r.Context())
		messages, deadErr := s.queue.DeadLetters(r.Context(), 50)
		if pendingErr == nil && pending != nil {
			out.Queue.Pending = pending.Count
		}
		if deadErr == nil {
			out.Queue.DeadLetters = sanitizeDeadLetters(messages)
		}
		if pendingErr != nil || deadErr != nil {
			out.Queue.Error = "queue status unavailable"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) decideApproval(w http.ResponseWriter, r *http.Request) {
	if !validOperatorRequest(r) {
		writeError(w, http.StatusForbidden, "operator request validation failed")
		return
	}
	var body struct {
		Decision string `json:"decision"`
		Actor    string `json:"actor"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	body.Decision = strings.ToLower(strings.TrimSpace(body.Decision))
	if body.Decision != "approved" && body.Decision != "rejected" {
		writeError(w, http.StatusBadRequest, "decision must be approved or rejected")
		return
	}
	body.Actor = strings.TrimSpace(body.Actor)
	if body.Actor == "" {
		body.Actor = "console-operator"
	}
	if len(body.Actor) > 80 {
		writeError(w, http.StatusBadRequest, "actor is too long")
		return
	}
	if err := s.store.DecideApproval(r.Context(), domain.ID(r.PathValue("id")), body.Decision, body.Actor); err != nil {
		slog.Warn("operator console approval failed", "approval_id", r.PathValue("id"), "error", err)
		writeError(w, http.StatusConflict, "approval is no longer pending")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": body.Decision})
}

func (s *Server) retryDeadLetter(w http.ResponseWriter, r *http.Request) {
	if !validOperatorRequest(r) {
		writeError(w, http.StatusForbidden, "operator request validation failed")
		return
	}
	if s.queue == nil {
		writeError(w, http.StatusServiceUnavailable, "queue status unavailable")
		return
	}
	if err := s.queue.RetryDeadLetter(r.Context(), r.PathValue("id")); err != nil {
		slog.Warn("operator console dead-letter retry failed", "message_id", r.PathValue("id"), "error", err)
		writeError(w, http.StatusConflict, "dead-letter job could not be retried")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

func sanitizeDeadLetters(messages []redis.XMessage) []DeadLetter {
	out := make([]DeadLetter, 0, len(messages))
	for _, message := range messages {
		item := DeadLetter{MessageID: message.ID, Error: stringValue(message.Values["error"]), FailedAt: stringValue(message.Values["failed_at"])}
		raw := stringValue(message.Values["payload"])
		var job queue.Job
		if json.Unmarshal([]byte(raw), &job) == nil {
			item.JobID = job.ID
			item.Capability = job.Action.Capability
			item.Provider = job.Provider
			item.Attempt = job.Attempt
		}
		out = append(out, item)
	}
	return out
}

func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}

func validOperatorRequest(r *http.Request) bool {
	if r.Header.Get("X-Reconductor-Request") != "operator-console" {
		return false
	}
	if site := strings.ToLower(r.Header.Get("Sec-Fetch-Site")); site != "" && site != "same-origin" {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if !jsonContentType(r) {
		return errors.New("content type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("request body must be valid JSON")
	}
	return nil
}

func jsonContentType(r *http.Request) bool {
	return strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json")
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSONStatus(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	writeJSONStatus(w, status, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func HTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}
