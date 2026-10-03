package console

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
)

type exactConsoleFake struct {
	fakeStore
	view            database.ExactApprovalReview
	state           database.ExactApprovalState
	ids             []database.ExactApprovalState
	actor, decision string
	calls, reads    int
	deny            bool
}

func exactConsoleFixture() *exactConsoleFake {
	f := &exactConsoleFake{state: database.ExactApprovalState{ApprovalID: "exact-1", Decision: "pending", Status: "pending", Decisionable: true, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}}
	f.view = database.ExactApprovalReview{ApprovalID: "exact-1", ActionSHA256: strings.Repeat("a", 64), ReviewContextSHA256: strings.Repeat("b", 64), Decision: "pending",
		Action: exactaction.ActionContractV1{ContractVersion: exactaction.ContractVersion, ActionID: "action-1", Request: exactaction.Request{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/item/%2f?id=2&id=1?", Headers: []string{}}, Identity: exactaction.Identity{Kind: "anonymous"}, Limits: exactaction.Limits{MaxRequests: 1}},
		Review: exactaction.ReviewContextV1{ReviewVersion: exactaction.ReviewVersion, ProposalSource: exactaction.ProposalSource{Kind: "test", Provider: "model", Model: "revision"}, Purpose: "compare", ExpectedPositiveOutcome: "positive", ExpectedNegativeOutcome: "negative", Assumptions: []string{"assumption"}, MissingEvidence: []string{"missing"}, SupportingEvidence: []exactaction.Citation{{ArtifactID: "support", ArtifactSHA256: strings.Repeat("c", 64), Locator: "line 1"}}, ContradictoryEvidence: []exactaction.Citation{{ArtifactID: "against", ArtifactSHA256: strings.Repeat("d", 64), Locator: "line 2"}}}, CitationAvailability: []database.ExactCitationAvailability{{ArtifactID: "support", Status: "available"}, {ArtifactID: "against", Status: "available"}}}
	return f
}
func (f *exactConsoleFake) ListExactApprovalStates(context.Context, domain.ID, domain.ID) ([]database.ExactApprovalState, error) {
	f.reads++
	if f.ids != nil {
		return f.ids, nil
	}
	return []database.ExactApprovalState{f.state}, nil
}
func (f *exactConsoleFake) GetExactApprovalState(_ context.Context, id domain.ID) (database.ExactApprovalState, error) {
	f.reads++
	if id != "exact-1" {
		return database.ExactApprovalState{}, pgx.ErrNoRows
	}
	return f.state, nil
}
func (f *exactConsoleFake) GetExactApprovalReview(_ context.Context, id domain.ID) (database.ExactApprovalReview, error) {
	f.reads++
	if id != "exact-1" {
		return database.ExactApprovalReview{}, pgx.ErrNoRows
	}
	return f.view, nil
}
func (f *exactConsoleFake) DecideExactApproval(_ context.Context, _ domain.ID, h, rh, decision, actor string) error {
	f.calls++
	f.actor = actor
	f.decision = decision
	if f.deny || !f.state.Decisionable || h != f.view.ActionSHA256 || rh != f.view.ReviewContextSHA256 {
		return database.ErrExactApprovalDenied
	}
	f.state.Decision = decision
	f.state.Status = decision
	f.state.Decisionable = false
	return nil
}
func exactDecisionBody(f *exactConsoleFake, decision string) string {
	b, _ := json.Marshal(map[string]string{"decision": decision, "action_hash": f.view.ActionSHA256, "review_hash": f.view.ReviewContextSHA256})
	return string(b)
}
func TestExactSensitiveReadsAndDTO(t *testing.T) {
	for _, path := range []string{"/api/v1/exact-approvals", "/api/v1/exact-approvals/exact-1"} {
		for _, attempt := range []struct {
			name, host, token string
			want              int
		}{{"unauthenticated", "127.0.0.1:8088", "", 401}, {"wrong bearer", "127.0.0.1:8088", "wrong", 401}, {"attacker", "attacker.example", testOperatorToken, 403}, {"valid", "127.0.0.1:8088", testOperatorToken, 200}} {
			t.Run(path+attempt.name, func(t *testing.T) {
				f := exactConsoleFixture()
				r := httptest.NewRequest("GET", "http://127.0.0.1:8088"+path, nil)
				r.Host = attempt.host
				if attempt.token != "" {
					r.Header.Set("Authorization", "Bearer "+attempt.token)
				}
				w := httptest.NewRecorder()
				newTestOperator(t, f, nil).ServeHTTP(w, r)
				if w.Code != attempt.want {
					t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
				}
				if f.calls != 0 || (attempt.want != 200 && f.reads != 0) {
					t.Fatal("sensitive read escaped gate or mutated")
				}
			})
		}
	}
	f := exactConsoleFixture()
	f.view.CitationAvailability[1].Status = "restricted"
	handler := newTestOperator(t, f, nil)
	read := func() exactDetailDTO {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, operatorRequest("GET", "/api/v1/exact-approvals/exact-1", ""))
		var dto exactDetailDTO
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &dto); err != nil {
			t.Fatal(err)
		}
		return dto
	}
	dto := read()
	if dto.Request.RequestTarget != f.view.Action.Request.RequestTarget || dto.ActionHash != f.view.ActionSHA256 || dto.ReviewHash != f.view.ReviewContextSHA256 || dto.Request.Body != "none" || len(dto.Request.Headers) != 0 || dto.Request.MaxRequests != 1 || dto.Request.Identity != "anonymous" || dto.Request.Redirects || dto.Request.Retries {
		t.Fatalf("incorrect frozen DTO: %+v", dto)
	}
	if dto.Review.Citations[0].Role != "supporting" || dto.Review.Citations[1].Role != "contradictory" || dto.EvidenceAvailable {
		t.Fatal("citation roles or availability lost")
	}
	f.view.CitationAvailability[1].Status = "available"
	changed := read()
	if !changed.EvidenceAvailable || changed.ReviewHash != dto.ReviewHash {
		t.Fatal("availability altered frozen RH")
	}
}
func TestExactDecisionGuardsActorAndRefresh(t *testing.T) {
	for _, decision := range []string{"approved", "rejected"} {
		t.Run(decision, func(t *testing.T) {
			f := exactConsoleFixture()
			w := httptest.NewRecorder()
			newTestOperator(t, f, nil).ServeHTTP(w, operatorRequest("POST", "/api/v1/exact-approvals/exact-1/decision", exactDecisionBody(f, decision)))
			if w.Code != 200 || f.actor != "configured-operator" || f.decision != decision || f.calls != 1 || f.reads != 4 {
				t.Fatalf("status=%d actor=%q calls=%d reads=%d", w.Code, f.actor, f.calls, f.reads)
			}
			var out struct{ Review exactDetailDTO }
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out.Review.Status != decision || out.Review.Decisionable {
				t.Fatal("response was not terminal authoritative state")
			}
		})
	}
	for _, guard := range []string{"action_hash", "review_hash"} {
		t.Run(guard, func(t *testing.T) {
			f := exactConsoleFixture()
			b := map[string]string{"decision": "approved", "action_hash": f.view.ActionSHA256, "review_hash": f.view.ReviewContextSHA256}
			b[guard] = strings.Repeat("f", 64)
			raw, _ := json.Marshal(b)
			w := httptest.NewRecorder()
			newTestOperator(t, f, nil).ServeHTTP(w, operatorRequest("POST", "/api/v1/exact-approvals/exact-1/decision", string(raw)))
			if w.Code != 409 || f.calls != 0 || f.reads != 4 || !strings.Contains(w.Body.String(), f.view.ActionSHA256) {
				t.Fatal("stale hash did not return authoritative state")
			}
		})
	}
	for _, reason := range []string{"decided", "expired", "revoked", "missing evidence", "restricted evidence"} {
		t.Run(reason, func(t *testing.T) {
			f := exactConsoleFixture()
			if strings.Contains(reason, "evidence") {
				f.deny = true
			} else {
				f.state.Decisionable = false
				f.state.Status = reason
			}
			w := httptest.NewRecorder()
			newTestOperator(t, f, nil).ServeHTTP(w, operatorRequest("POST", "/api/v1/exact-approvals/exact-1/decision", exactDecisionBody(f, "approved")))
			if w.Code != 409 || f.calls != 1 || f.reads != 4 {
				t.Fatal("backend rejection bypassed or failed refresh")
			}
		})
	}
}
func TestExactDecisionRequestShapeAndLegacySeparation(t *testing.T) {
	f := exactConsoleFixture()
	good := exactDecisionBody(f, "approved")
	for _, field := range []string{"actor", "decided_by", "operator", "username", "target", "method", "evidence"} {
		w := httptest.NewRecorder()
		newTestOperator(t, f, nil).ServeHTTP(w, operatorRequest("POST", "/api/v1/exact-approvals/exact-1/decision", strings.TrimSuffix(good, "}")+`,"`+field+`":"client-forged-alice"}`))
		if w.Code != 400 || f.calls != 0 {
			t.Fatalf("client field %s accepted", field)
		}
	}
	for _, raw := range []string{good + `{}`, strings.TrimSuffix(good, "}") + `,"decision":"rejected"}`, `null`, `{}`, strings.Replace(good, `"decision"`, `"Decision"`, 1)} {
		w := httptest.NewRecorder()
		newTestOperator(t, f, nil).ServeHTTP(w, operatorRequest("POST", "/api/v1/exact-approvals/exact-1/decision", raw))
		if w.Code != 400 || f.calls != 0 {
			t.Fatalf("invalid shape accepted: %s", raw)
		}
	}
	for _, change := range []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{"missing bearer", func(r *http.Request) { r.Header.Del("Authorization") }, 401},
		{"attacker", func(r *http.Request) { r.Host = "attacker.example"; r.Header.Set("Origin", "http://attacker.example") }, 403},
		{"wrong origin", func(r *http.Request) { r.Header.Set("Origin", "http://attacker.example") }, 403},
		{"no custom header", func(r *http.Request) { r.Header.Del("X-Reconductor-Request") }, 403},
		{"wrong content type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 400},
		{"fake JSON content type", func(r *http.Request) { r.Header.Set("Content-Type", "application/jsonp") }, 400},
	} {
		t.Run(change.name, func(t *testing.T) {
			r := operatorRequest("POST", "/api/v1/exact-approvals/exact-1/decision", good)
			change.mutate(r)
			w := httptest.NewRecorder()
			newTestOperator(t, f, nil).ServeHTTP(w, r)
			if w.Code != change.want || f.calls != 0 {
				t.Fatal("invalid operator shape accepted")
			}
		})
	}
	w := httptest.NewRecorder()
	newTestOperator(t, f, nil).ServeHTTP(w, operatorRequest("POST", "/api/v1/exact-approvals/legacy/decision", good))
	if w.Code != 404 || f.calls != 0 {
		t.Fatal("exact endpoint accepted legacy identity")
	}
}
func TestExactListPaginationDTO(t *testing.T) {
	f := exactConsoleFixture()
	f.ids = make([]database.ExactApprovalState, 101)
	for i := range f.ids {
		f.ids[i] = f.state
	}
	w := httptest.NewRecorder()
	newTestOperator(t, f, nil).ServeHTTP(w, operatorRequest("GET", "/api/v1/exact-approvals", ""))
	var out struct {
		Items []exactStateDTO `json:"items"`
		Next  string          `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 100 || out.Next != "exact-1" || strings.Contains(w.Body.String(), "request_target") {
		t.Fatal("list boundary leaked or lost pagination")
	}
}

var _ exactApprovalStore = (*exactConsoleFake)(nil)
