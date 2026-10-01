package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
)

// Tripwires make approval/execution separation observable through HTTP.
type noExactDispatchStore struct {
	*database.Store
	admissions atomic.Int64
}

func (s *noExactDispatchStore) AdmitExactDispatch(context.Context, domain.ID, domain.StepRun, domain.ID) (*database.ExactDispatchPermit, error) {
	s.admissions.Add(1)
	return nil, errors.New("console must never admit dispatch")
}

type exactNetworkTripwire struct{ calls atomic.Int64 }

func (n *exactNetworkTripwire) RoundTrip(*http.Request) (*http.Response, error) {
	n.calls.Add(1)
	return nil, errors.New("console must never issue a target request")
}

type exactHTTPFixture struct {
	store                                    *database.Store
	ctx                                      context.Context
	program, step, approval, attempt, legacy domain.ID
}

func newExactHTTPFixture(t *testing.T) exactHTTPFixture {
	t.Helper()
	uri := os.Getenv("TEST_DATABASE_URL")
	if uri == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "console_exact_" + strings.ReplaceAll(string(domain.NewID()), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	q.Set("search_path", schema)
	parsed.RawQuery = q.Encode()
	store, err := database.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if err = store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	f := exactHTTPFixture{store: store, ctx: ctx, program: domain.NewID(), step: domain.NewID(), attempt: domain.NewID(), legacy: domain.NewID()}
	definition, task, run, scope, action, auth := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := store.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,$2,'test','synthetic','test')`, f.program, "exact-console-"+string(f.program))
	exec(`INSERT INTO program_launch_authority(program_id) VALUES($1)`, f.program)
	exec(`INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,target_plan_digest,target_plan) VALUES($1,$2,'synthetic','digest','plan','{}')`, scope, f.program)
	exec(`INSERT INTO workflow_definitions(id,name,version,definition) VALUES($1,'console-fixture','1','{}')`, definition)
	exec(`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES($1,$2,'test',$3,'running','test')`, task, f.program, definition)
	exec(`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source,materialized_definition,materialization_digest,original_scope_version_id) VALUES($1,$2,$3,'1','running','test','{}',$4,$5)`, run, task, definition, strings.Repeat("a", 64), scope)
	exec(`INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,attempt_count,idempotency_key) VALUES($1,$2,'request','http.request','running',1,'test')`, f.step, run)
	exec(`INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,step_run_id,capability,action_request_id,step_attempt,safe_message,details) VALUES($1,'policy_allowed','test','test',$2,$3,$4,$5,'http.request',$6,1,'fixture', '{"phase":"execution"}')`, auth, f.program, task, run, f.step, action)
	// Fixture provenance only: no provider process or target request is invoked.
	exec(`INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,step_run_id,capability,action_request_id,step_attempt,execution_authorization_event_id,safe_message) VALUES($1,'provider_invocation_started','test','test',$2,$3,$4,$5,'http.request',$6,1,$7,'fixture')`, f.attempt, f.program, task, run, f.step, action, auth)
	review := exactaction.ReviewContextV1{ReviewVersion: exactaction.ReviewVersion, ProposalSource: exactaction.ProposalSource{Kind: "test"}, Purpose: "compare", ExpectedPositiveOutcome: "positive", ExpectedNegativeOutcome: "negative", Assumptions: []string{}, MissingEvidence: []string{}, SupportingEvidence: []exactaction.Citation{}, ContradictoryEvidence: []exactaction.Citation{}}
	f.approval, err = store.PrepareExactActionApproval(ctx, f.program, domain.StepRun{ID: f.step, WorkflowRunID: run, Capability: "http.request", IdempotencyKey: "test"}, f.attempt, exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/item/%2F?id=2&id=1?"}, review, "proposer", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO approvals(id,request_id,task_id,action_request_id,requested_risk_level,reason,decision) VALUES($1,$2,$3,$4,'low','legacy','pending')`, f.legacy, f.step, task, domain.NewID())
	return f
}
func (f exactHTTPFixture) body(t *testing.T, decision string) string {
	t.Helper()
	v, err := f.store.GetExactApprovalReview(f.ctx, f.approval)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"decision": decision, "action_hash": v.ActionSHA256, "review_hash": v.ReviewContextSHA256})
	return string(b)
}
func (f exactHTTPFixture) assertUndispatched(t *testing.T, decisions int) {
	t.Helper()
	var state string
	var intentAt *time.Time
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT state,dispatch_intent_at FROM exact_dispatch_attempts WHERE provider_attempt_id=$1`, f.attempt).Scan(&state, &intentAt); err != nil {
		t.Fatal(err)
	}
	if state != "UNDISPATCHED" || intentAt != nil {
		t.Fatalf("approval dispatched: %s %v", state, intentAt)
	}
	var count int
	if err := f.store.Pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_events WHERE event_type='exact_approval_decided' AND provider_attempt_id=$1`, f.attempt).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != decisions {
		t.Fatalf("terminal decision count=%d want=%d", count, decisions)
	}
	// A permit is minted only by dispatch admission after DISPATCH_INTENT. The
	// server interface exposes no such method; this persisted state precludes it.
}
func TestExactHTTPApprovalRecordsDecisionWithoutDispatch(t *testing.T) {
	for _, decision := range []string{"approved", "rejected"} {
		t.Run(decision, func(t *testing.T) {
			f := newExactHTTPFixture(t)
			guard := &noExactDispatchStore{Store: f.store}
			network := &exactNetworkTripwire{}
			originalTransport := http.DefaultTransport
			http.DefaultTransport = network
			t.Cleanup(func() { http.DefaultTransport = originalTransport })
			handler := newTestOperator(t, guard, nil)
			t.Cleanup(func() {
				if guard.admissions.Load() != 0 || network.calls.Load() != 0 {
					t.Fatal("approval invoked dispatch or target transport")
				}
			})
			before, err := f.store.GetExactApprovalReview(f.ctx, f.approval)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.Pool.Exec(f.ctx, `UPDATE step_runs SET input='{"method":"HEAD","hostname":"attacker.test","request_target":"/changed"}' WHERE id=$1`, f.step); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/api/v1/exact-approvals", "/api/v1/exact-approvals/" + string(f.approval)} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, operatorRequest("GET", path, ""))
				if w.Code != 200 {
					t.Fatal(w.Body.String())
				}
				if strings.Contains(w.Body.String(), "attacker.test") {
					t.Fatal("mutable input leaked")
				}
				if strings.Contains(path, string(f.approval)) {
					var dto exactDetailDTO
					if err = json.Unmarshal(w.Body.Bytes(), &dto); err != nil {
						t.Fatal(err)
					}
					if dto.Request.RequestTarget != before.Action.Request.RequestTarget || dto.ActionHash != before.ActionSHA256 || dto.ReviewHash != before.ReviewContextSHA256 || dto.ProgramID != before.Action.Ownership.ProgramID || dto.ProviderAttemptID != before.ProviderAttemptID || dto.Capability != before.Action.Capability.Name {
						t.Fatal("frozen semantics changed")
					}
				}
			}
			f.assertUndispatched(t, 0)
			for _, bad := range []struct{ path, body string }{{"/api/v1/approvals/" + string(f.approval) + "/decision", `{"decision":"approved"}`}, {"/api/v1/exact-approvals/" + string(f.legacy) + "/decision", f.body(t, decision)}} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, operatorRequest("POST", bad.path, bad.body))
				if w.Code == 200 {
					t.Fatal("approval kinds confused")
				}
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, operatorRequest("POST", "/api/v1/exact-approvals/"+string(f.approval)+"/decision", f.body(t, decision)))
			if w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			var got, actor string
			if err = f.store.Pool.QueryRow(f.ctx, `SELECT decision,decided_by FROM approvals WHERE id=$1`, f.approval).Scan(&got, &actor); err != nil {
				t.Fatal(err)
			}
			if got != decision || actor != "configured-operator" {
				t.Fatalf("decision=%s actor=%s", got, actor)
			}
			f.assertUndispatched(t, 1)
			w = httptest.NewRecorder()
			handler.ServeHTTP(w, operatorRequest("POST", "/api/v1/exact-approvals/"+string(f.approval)+"/decision", f.body(t, decision)))
			if w.Code != 409 {
				t.Fatal("stale decision accepted")
			}
			f.assertUndispatched(t, 1)
		})
	}
}
func TestExactHTTPExpiryRevocationAndDecisionRaces(t *testing.T) {
	for _, condition := range []string{"expired", "revoked"} {
		t.Run(condition, func(t *testing.T) {
			f := newExactHTTPFixture(t)
			sql := `UPDATE approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`
			if condition == "revoked" {
				sql = `UPDATE approvals SET revoked_at=clock_timestamp(),revoked_by='reviewer' WHERE id=$1`
			}
			if _, err := f.store.Pool.Exec(f.ctx, sql, f.approval); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			newTestOperator(t, f.store, nil).ServeHTTP(w, operatorRequest("POST", "/api/v1/exact-approvals/"+string(f.approval)+"/decision", f.body(t, "approved")))
			if w.Code != 409 || !strings.Contains(w.Body.String(), `"status":"`+condition+`"`) {
				t.Fatal(w.Body.String())
			}
			f.assertUndispatched(t, 0)
		})
	}
	for _, pair := range [][2]string{{"approved", "approved"}, {"approved", "rejected"}, {"rejected", "rejected"}} {
		t.Run(pair[0]+"/"+pair[1], func(t *testing.T) {
			f := newExactHTTPFixture(t)
			handler := newTestOperator(t, f.store, nil)
			bodies := []string{f.body(t, pair[0]), f.body(t, pair[1])}
			start := make(chan struct{})
			results := make(chan int, 2)
			var wg sync.WaitGroup
			for _, body := range bodies {
				wg.Add(1)
				go func(body string) {
					defer wg.Done()
					<-start
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, operatorRequest("POST", "/api/v1/exact-approvals/"+string(f.approval)+"/decision", body))
					results <- w.Code
				}(body)
			}
			close(start)
			wg.Wait()
			close(results)
			success := 0
			for code := range results {
				if code == 200 {
					success++
				} else if code != 409 {
					t.Fatalf("unexpected race status %d", code)
				}
			}
			if success != 1 {
				t.Fatalf("terminal winners=%d", success)
			}
			f.assertUndispatched(t, 1)
		})
	}
}

func TestExactHTTPListCursorAndProgramFilter(t *testing.T) {
	f := newExactHTTPFixture(t)
	original, err := f.store.GetExactApprovalReview(f.ctx, f.approval)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		action, auth, attempt := domain.NewID(), domain.NewID(), domain.NewID()
		_, err = f.store.Pool.Exec(f.ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,step_run_id,capability,action_request_id,step_attempt,safe_message,details)
   SELECT $1,'policy_allowed','test','test',program_id,task_id,workflow_run_id,step_run_id,capability,$2,step_attempt,'fixture','{"phase":"execution"}' FROM audit_events WHERE id=(SELECT execution_authorization_event_id FROM audit_events WHERE id=$3)`, auth, action, f.attempt)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.store.Pool.Exec(f.ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,task_id,workflow_run_id,step_run_id,capability,action_request_id,step_attempt,execution_authorization_event_id,safe_message)
   SELECT $1,'provider_invocation_started','test','test',program_id,task_id,workflow_run_id,step_run_id,capability,$2,step_attempt,$3,'fixture' FROM audit_events WHERE id=$4`, attempt, action, auth, f.attempt)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.store.PrepareExactActionApproval(f.ctx, f.program, domain.StepRun{ID: f.step, WorkflowRunID: original.Action.Ownership.WorkflowRunID, Capability: "http.request", IdempotencyKey: "test"}, attempt, exactaction.ProposedRequest{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/page"}, original.Review, "proposer", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
	}
	handler := newTestOperator(t, f.store, nil)
	read := func(query string) ([]exactStateDTO, string) {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, operatorRequest("GET", "/api/v1/exact-approvals"+query, ""))
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var page struct {
			Items []exactStateDTO `json:"items"`
			Next  string          `json:"next_cursor"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		return page.Items, page.Next
	}
	first, next := read("?program_id=" + string(f.program))
	if len(first) != 100 || next == "" {
		t.Fatal("first page was not bounded")
	}
	second, end := read("?program_id=" + string(f.program) + "&after=" + next)
	if len(second) != 1 || end != "" || second[0].ApprovalID != f.approval {
		t.Fatal("cursor omitted/duplicated frozen identities")
	}
	ids := map[domain.ID]bool{}
	for _, row := range append(first, second...) {
		if ids[row.ApprovalID] {
			t.Fatal("duplicate paged approval")
		}
		ids[row.ApprovalID] = true
	}
	filtered, _ := read("?program_id=" + string(domain.NewID()))
	if len(filtered) != 0 {
		t.Fatal("program filter ignored")
	}
	var decisions int
	if err = f.store.Pool.QueryRow(f.ctx, `SELECT count(*) FROM approvals WHERE approval_kind='exact_action' AND decision<>'pending'`).Scan(&decisions); err != nil {
		t.Fatal(err)
	}
	if decisions != 0 {
		t.Fatal("list GET changed decisions")
	}
	f.assertUndispatched(t, 0)
}
