package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	"github.com/tobiasGuta/Reconductor/internal/queue"
	schedulecron "github.com/tobiasGuta/Reconductor/internal/scheduler"
)

type fakeStore struct {
	snapshot database.ConsoleSnapshot
	decided  string
}

func (f *fakeStore) ConsoleSnapshot(context.Context, domain.ID) (database.ConsoleSnapshot, error) {
	return f.snapshot, nil
}

func (f *fakeStore) DecideApproval(_ context.Context, _ domain.ID, decision, _ string) error {
	f.decided = decision
	return nil
}

type fakeQueue struct {
	retried string
	dead    []redis.XMessage
}

type mutationStore struct {
	fakeStore
	program      domain.Program
	schedules    map[domain.ID]domain.Schedule
	runNowErr    error
	acknowledged domain.ID
	resumed      domain.ID
}

func (s *mutationStore) GetProgram(context.Context, domain.ID) (domain.Program, error) {
	return s.program, nil
}

func (s *mutationStore) CreateSchedule(_ context.Context, item domain.Schedule) error {
	s.schedules[item.ID] = item
	return nil
}

func (s *mutationStore) GetSchedule(_ context.Context, id domain.ID) (domain.Schedule, error) {
	item, ok := s.schedules[id]
	if !ok {
		return domain.Schedule{}, errors.New("not found")
	}
	return item, nil
}

func (s *mutationStore) UpdateSchedule(_ context.Context, item domain.Schedule, _ string) error {
	s.schedules[item.ID] = item
	return nil
}

func (s *mutationStore) SetScheduleEnabled(_ context.Context, id domain.ID, enabled bool, _ string) error {
	item := s.schedules[id]
	item.Enabled = enabled
	s.schedules[id] = item
	return nil
}

func (s *mutationStore) EnqueueRunNow(_ context.Context, scheduleID domain.ID, _ string) (domain.ScheduledExecution, error) {
	if s.runNowErr != nil {
		return domain.ScheduledExecution{}, s.runNowErr
	}
	return domain.ScheduledExecution{ID: domain.NewID(), ScheduleID: scheduleID, Status: domain.ScheduledExecutionPending}, nil
}

func (s *mutationStore) RequestScheduledExecutionResume(_ context.Context, id domain.ID, _ string) error {
	s.resumed = id
	return nil
}

func (s *mutationStore) ReviewChangeItem(context.Context, domain.ID, domain.ChangeReviewDisposition, string, string) error {
	return nil
}

func (s *mutationStore) AcknowledgeScopeVersion(_ context.Context, id domain.ID, _ string) error {
	s.acknowledged = id
	return nil
}

func (f *fakeQueue) Pending(context.Context) (*redis.XPending, error) {
	return &redis.XPending{Count: 3}, nil
}

func (f *fakeQueue) DeadLetters(context.Context, int64) ([]redis.XMessage, error) {
	return f.dead, nil
}

func (f *fakeQueue) RetryDeadLetter(_ context.Context, id string) error {
	f.retried = id
	return nil
}

func TestSnapshotSanitizesDeadLetterPayload(t *testing.T) {
	job := queue.Job{ID: "job-1", Provider: "nuclei", Attempt: 4, Action: domain.ActionRequest{Capability: "scan.nuclei", Input: json.RawMessage(`{"target":"https://secret.example.test","authorization":"secret"}`)}}
	payload, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	workQueue := &fakeQueue{dead: []redis.XMessage{{ID: "1-0", Values: map[string]any{"payload": string(payload), "error": "permanent_provider_failure", "failed_at": "2026-07-22T12:00:00Z"}}}}
	recorder := httptest.NewRecorder()
	New(&fakeStore{}, workQueue).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, forbidden := range []string{"secret.example.test", "authorization", `\"scope_includes\"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response exposed dead-letter payload field %q: %s", forbidden, body)
		}
	}
	for _, expected := range []string{"scan.nuclei", "nuclei", "permanent_provider_failure"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("response missing sanitized field %q: %s", expected, body)
		}
	}
}

func TestSnapshotSanitizesPendingScopeExpansionTargetPlan(t *testing.T) {
	store := &fakeStore{snapshot: database.ConsoleSnapshot{
		Programs:          []domain.Program{{ID: "program-1", Name: "Program"}},
		SelectedProgramID: "program-1",
		PendingScopeExpansions: []database.ConsolePendingScopeExpansion{{
			ID: "scope-1", ProgramID: "program-1", ScopeDigest: "scope-digest", TargetPlanDigest: "plan-digest",
			PlanningWarnings:    json.RawMessage(`["review required"]`),
			AddedIncludeDigests: []string{"include-digest"}, RemovedIncludeDigests: []string{},
			AddedExcludeDigests: []string{}, RemovedExcludeDigests: []string{},
		}},
	}}
	recorder := httptest.NewRecorder()
	New(store, nil).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, `"target_plan":`) {
		t.Fatalf("snapshot exposed full target plan: %s", body)
	}
	for _, expected := range []string{"scope-digest", "plan-digest", "include-digest", "review required"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("snapshot missing sanitized scope field %q: %s", expected, body)
		}
	}
}

func TestApprovalRequiresOperatorHeader(t *testing.T) {
	store := &fakeStore{}
	handler := New(store, nil)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/approval-1/decision", strings.NewReader(`{"decision":"approved"}`))
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if store.decided != "" {
		t.Fatalf("decision unexpectedly persisted: %s", store.decided)
	}
}

func TestApprovalAcceptsSameOriginOperatorRequest(t *testing.T) {
	store := &fakeStore{}
	handler := New(store, nil)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8088/api/v1/approvals/approval-1/decision", strings.NewReader(`{"decision":"approved","actor":"alice"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Reconductor-Request", "operator-console")
	request.Header.Set("Origin", "http://127.0.0.1:8088")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if store.decided != "approved" {
		t.Fatalf("decision = %q", store.decided)
	}
}

func TestConsoleScheduleAndScopeMutationsUseSharedValidation(t *testing.T) {
	scopePath := filepath.Join(t.TempDir(), "scope.json")
	scopeJSON := `{"target":{"scope":{"advanced_mode":true,"exclude":[],"include":[{"enabled":true,"file":"^/.*","host":"^app\\.example\\.test$","port":"^443$","protocol":"https"}]}}}`
	if err := os.WriteFile(scopePath, []byte(scopeJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	programID := domain.NewID()
	store := &mutationStore{
		program:   domain.Program{ID: programID, ScopeReference: scopePath},
		schedules: map[domain.ID]domain.Schedule{},
	}
	validator := &schedulecron.ScheduleValidator{Programs: store, Registry: providers.Registry(config.Config{})}
	handler := New(store, nil, validator)

	create := operatorRequest(http.MethodPost, "/api/v1/schedules", `{"program_id":"`+string(programID)+`","name":"Daily","workflow_name":"continuous-web-recon","objective":"Authorized scan","cron_expression":"0 9 * * *","timezone":"UTC","headless":true}`)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, create)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if len(store.schedules) != 1 {
		t.Fatalf("created schedules = %#v", store.schedules)
	}
	var schedule domain.Schedule
	for _, item := range store.schedules {
		schedule = item
	}
	if schedule.NextRunAt.IsZero() || !schedule.Headless {
		t.Fatalf("schedule was not fully validated: %#v", schedule)
	}

	invalidUpdate := operatorRequest(http.MethodPost, "/api/v1/schedules/"+string(schedule.ID)+"/update", `{"timezone":""}`)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, invalidUpdate)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("empty-timezone update status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	store.runNowErr = database.ErrScheduleOverlap
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, operatorRequest(http.MethodPost, "/api/v1/schedules/"+string(schedule.ID)+"/run-now", `{}`))
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "queued or active") {
		t.Fatalf("overlap status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, operatorRequest(http.MethodPost, "/api/v1/scope-versions/scope-1/acknowledge", `{}`))
	if recorder.Code != http.StatusOK || store.acknowledged != "scope-1" {
		t.Fatalf("scope acknowledgement status=%d id=%s body=%s", recorder.Code, store.acknowledged, recorder.Body.String())
	}
}

func operatorRequest(method, target, body string) *http.Request {
	request := httptest.NewRequest(method, "http://127.0.0.1:8088"+target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Reconductor-Request", "operator-console")
	request.Header.Set("Origin", "http://127.0.0.1:8088")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	return request
}

func TestStaticConsoleHasSecurityHeaders(t *testing.T) {
	recorder := httptest.NewRecorder()
	New(&fakeStore{}, nil).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if !strings.Contains(recorder.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("missing restrictive CSP: %q", recorder.Header().Get("Content-Security-Policy"))
	}
	if !strings.Contains(recorder.Body.String(), "Reconductor Console") {
		t.Fatal("console shell was not served")
	}
	for _, expected := range []string{"Pending scope expansions", "continuous-web-recon", "headless", "schedule-cancel"} {
		if !strings.Contains(recorder.Body.String(), expected) {
			t.Fatalf("console shell is missing schedule/scope control %q", expected)
		}
	}
}
