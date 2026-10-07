package console

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/config"
	schedulecron "github.com/tobiasGuta/Reconductor/internal/scheduler"
)

const testOperatorToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newTestOperator(t *testing.T, store Store, queue Queue, validators ...*schedulecron.ScheduleValidator) http.Handler {
	t.Helper()
	handler, err := NewOperator(store, queue, "127.0.0.1:8088", config.Console{
		OperatorToken: testOperatorToken, OperatorActor: "configured-operator",
	}, validators...)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func operatorDecisionRequest() *http.Request {
	return operatorRequest(http.MethodPost, "/api/v1/approvals/approval-1/decision", `{"decision":"approved"}`)
}

func TestOperatorHostAndOriginBoundary(t *testing.T) {
	tests := []struct {
		name, host, origin string
		want               int
	}{
		{"configured", "127.0.0.1:8088", "http://127.0.0.1:8088", http.StatusOK},
		{"wrong host", "127.0.0.2:8088", "http://127.0.0.1:8088", http.StatusForbidden},
		{"wrong port", "127.0.0.1:8089", "http://127.0.0.1:8088", http.StatusForbidden},
		{"attacker host", "attacker.example:8088", "http://127.0.0.1:8088", http.StatusForbidden},
		{"matching attacker origin", "attacker.example:8088", "http://attacker.example:8088", http.StatusForbidden},
		{"localhost suffix", "localhost.attacker.example:8088", "http://localhost.attacker.example:8088", http.StatusForbidden},
		{"malformed host", "127.0.0.1:bogus", "http://127.0.0.1:8088", http.StatusForbidden},
		{"missing port", "127.0.0.1", "http://127.0.0.1:8088", http.StatusForbidden},
		{"wrong scheme", "127.0.0.1:8088", "https://127.0.0.1:8088", http.StatusForbidden},
		{"wrong origin host", "127.0.0.1:8088", "http://attacker.example:8088", http.StatusForbidden},
		{"wrong origin port", "127.0.0.1:8088", "http://127.0.0.1:8089", http.StatusForbidden},
		{"null origin", "127.0.0.1:8088", "null", http.StatusForbidden},
		{"malformed origin", "127.0.0.1:8088", "%%%%", http.StatusForbidden},
		{"origin path", "127.0.0.1:8088", "http://127.0.0.1:8088/path", http.StatusForbidden},
		{"comma-separated origins", "127.0.0.1:8088", "http://127.0.0.1:8088, http://attacker.example:8088", http.StatusForbidden},
	}
	t.Run("matching attacker origin without bearer", func(t *testing.T) {
		request := operatorDecisionRequest()
		request.Host = "attacker.example:8088"
		request.Header.Set("Origin", "http://attacker.example:8088")
		request.Header.Del("Authorization")
		response := httptest.NewRecorder()
		newTestOperator(t, &fakeStore{}, nil).ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{}
			request := operatorDecisionRequest()
			request.Host = test.host
			request.Header.Set("Origin", test.origin)
			response := httptest.NewRecorder()
			newTestOperator(t, store, nil).ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
			if (store.decided != "") != (test.want == http.StatusOK) {
				t.Fatalf("decision=%q for status=%d", store.decided, response.Code)
			}
		})
	}
	for _, name := range []string{"multiple origin", "duplicate host header", "cross-site fetch"} {
		t.Run(name, func(t *testing.T) {
			request := operatorDecisionRequest()
			switch name {
			case "multiple origin":
				request.Header.Add("Origin", "http://127.0.0.1:8088")
			case "duplicate host header":
				request.Header.Add("Host", "attacker.example:8088")
			case "cross-site fetch":
				request.Header.Set("Sec-Fetch-Site", "cross-site")
			}
			response := httptest.NewRecorder()
			newTestOperator(t, &fakeStore{}, nil).ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestOperatorCredentialBoundary(t *testing.T) {
	tests := []struct {
		name string
		set  func(*http.Request)
		want int
	}{
		{"missing", func(r *http.Request) { r.Header.Del("Authorization") }, http.StatusUnauthorized},
		{"wrong scheme", func(r *http.Request) { r.Header.Set("Authorization", "Basic "+testOperatorToken) }, http.StatusUnauthorized},
		{"empty bearer", func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") }, http.StatusUnauthorized},
		{"wrong token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64)) }, http.StatusUnauthorized},
		{"malformed", func(r *http.Request) { r.Header.Set("Authorization", "Bearer  "+testOperatorToken) }, http.StatusUnauthorized},
		{"duplicate", func(r *http.Request) { r.Header.Add("Authorization", "Bearer "+testOperatorToken) }, http.StatusUnauthorized},
		{"correct", func(*http.Request) {}, http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{}
			request := operatorDecisionRequest()
			test.set(request)
			response := httptest.NewRecorder()
			newTestOperator(t, store, nil).ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
			if strings.Contains(response.Body.String(), testOperatorToken) || strings.Contains(response.Body.String(), strings.Repeat("a", 64)) {
				t.Fatal("credential leaked in response")
			}
			if test.want != http.StatusOK && store.decided != "" {
				t.Fatal("unauthorized mutation reached store")
			}
		})
	}
	request := operatorDecisionRequest()
	request.Header.Del("Origin")
	response := httptest.NewRecorder()
	newTestOperator(t, &fakeStore{}, nil).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated Origin-less local API status=%d", response.Code)
	}
}

func TestOperatorActorAndRouteScope(t *testing.T) {
	store := &fakeStore{}
	handler := newTestOperator(t, store, nil)
	for _, body := range []string{`{"decision":"approved","actor":"client-forged-alice"}`, `{"decision":"approved","actor":""}`, `{"decision":"approved","actor":"alternate"}`} {
		request := operatorRequest(http.MethodPost, "/api/v1/approvals/approval-1/decision", body)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || store.decided != "" {
			t.Fatalf("client actor accepted: %d %q", response.Code, store.decided)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, operatorDecisionRequest())
	if response.Code != http.StatusOK || store.decidedActor != "configured-operator" {
		t.Fatalf("server actor=%q status=%d", store.decidedActor, response.Code)
	}

	for _, path := range []string{
		"/api/v1/approvals/id/decision", "/api/v1/schedules", "/api/v1/schedules/id/update",
		"/api/v1/schedules/id/enable", "/api/v1/schedules/id/disable", "/api/v1/schedules/id/run-now",
		"/api/v1/scheduled-executions/id/resume", "/api/v1/change-items/id/review",
		"/api/v1/scope-versions/id/acknowledge", "/api/v1/dead-letters/id/retry",
	} {
		request := operatorRequest(http.MethodPost, path, `{}`)
		request.Header.Del("Authorization")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("unprotected route %s: %d", path, response.Code)
		}
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8088/healthz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("health=%d", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8088/", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("static=%d", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8088/api/v1/operator/check", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("sensitive GET without bearer=%d", response.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8088/api/v1/operator/check", nil)
	request.Header.Set("Authorization", "Bearer "+testOperatorToken)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("sensitive GET with bearer=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8088/api/v1/approvals/approval-1/decision", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("GET decision=%d", response.Code)
	}

	response = httptest.NewRecorder()
	New(store, nil).ServeHTTP(response, operatorDecisionRequest())
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured console mutation=%d", response.Code)
	}
}

func TestOperatorConfiguredAddresses(t *testing.T) {
	operator := config.Console{OperatorToken: testOperatorToken, OperatorActor: "configured-operator"}
	for _, address := range []string{"127.0.0.1:8088", "localhost:8088", "[::1]:8088", "127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		t.Run(address, func(t *testing.T) {
			handler, err := NewOperator(&fakeStore{}, nil, address, operator)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "http://"+address+"/api/v1/approvals/id/decision", strings.NewReader(`{"decision":"approved"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Reconductor-Request", "operator-console")
			request.Header.Set("Authorization", "Bearer "+testOperatorToken)
			request.Header.Set("Origin", "http://"+address)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	for _, address := range []string{"attacker.example:8088", "0.0.0.0:8088", "127.0.0.1:0", "127.0.0.1:abc"} {
		if _, err := NewOperator(&fakeStore{}, nil, address, operator); err == nil {
			t.Fatalf("accepted invalid listen address %q", address)
		}
	}
}

func TestOperatorRejectsIPv4MappedIPv6(t *testing.T) {
	operator := config.Console{OperatorToken: testOperatorToken, OperatorActor: "configured-operator"}
	for _, address := range []string{
		"[::ffff:127.0.0.1]:80", "[::ffff:127.0.0.1]:8080",
		"[::ffff:7f00:1]:80", "[::ffff:7f00:1]:8080",
		"[0:0:0:0:0:FFFF:7f00:1]:80", "[0:0:0:0:0:FFFF:7f00:1]:8080",
	} {
		t.Run(address, func(t *testing.T) {
			handler, err := NewOperator(&fakeStore{}, nil, address, operator)
			if err == nil || err.Error() != "IPv4-mapped IPv6 console addresses are unsupported" || handler != nil {
				t.Fatalf("handler=%v error=%v; want mapped IPv6 configuration rejection", handler, err)
			}
		})
	}
}

func TestOperatorDefaultHTTPPortUsesBrowserAuthority(t *testing.T) {
	operator := config.Console{OperatorToken: testOperatorToken, OperatorActor: "configured-operator"}
	for _, test := range []struct {
		address, host string
	}{
		{"127.0.0.1:80", "127.0.0.1"},
		{"localhost:80", "localhost"},
		{"[::1]:80", "[::1]"},
	} {
		t.Run(test.address, func(t *testing.T) {
			store := &fakeStore{}
			handler, err := NewOperator(store, nil, test.address, operator)
			if err != nil {
				t.Fatal(err)
			}
			origin := "http://" + test.host
			for _, attempt := range []struct {
				name, host, origin, authorization string
				want                              int
			}{
				{"browser canonical", test.host, origin, "Bearer " + testOperatorToken, http.StatusOK},
				{"authenticated API without Origin", test.host, "", "Bearer " + testOperatorToken, http.StatusOK},
				{"explicit default port", test.address, origin, "Bearer " + testOperatorToken, http.StatusForbidden},
				{"wrong Host port", net.JoinHostPort(strings.Trim(test.host, "[]"), "81"), origin, "Bearer " + testOperatorToken, http.StatusForbidden},
				{"attacker Host and Origin", "attacker.example", "http://attacker.example", "Bearer " + testOperatorToken, http.StatusForbidden},
				{"attacker localhost suffix", "localhost.attacker.example", "http://localhost.attacker.example", "Bearer " + testOperatorToken, http.StatusForbidden},
				{"attacker localhost prefix", "attacker.localhost", "http://attacker.localhost", "Bearer " + testOperatorToken, http.StatusForbidden},
				{"malformed Host", "127.0.0.1:bogus", origin, "Bearer " + testOperatorToken, http.StatusForbidden},
				{"wrong Origin port", test.host, "http://" + test.address[:len(test.address)-2] + "81", "Bearer " + testOperatorToken, http.StatusForbidden},
				{"attacker Origin", test.host, "http://attacker.example", "Bearer " + testOperatorToken, http.StatusForbidden},
				{"wrong bearer", test.host, origin, "Bearer wrong", http.StatusUnauthorized},
				{"missing bearer", test.host, origin, "", http.StatusUnauthorized},
			} {
				t.Run(attempt.name, func(t *testing.T) {
					request := operatorDecisionRequest()
					request.Host = attempt.host
					if attempt.origin == "" {
						request.Header.Del("Origin")
					} else {
						request.Header.Set("Origin", attempt.origin)
					}
					if attempt.authorization == "" {
						request.Header.Del("Authorization")
					} else {
						request.Header.Set("Authorization", attempt.authorization)
					}
					request.Header.Set("X-Forwarded-Host", test.host)
					request.Header.Set("Forwarded", "host="+test.host)
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, request)
					if response.Code != attempt.want {
						t.Fatalf("status=%d want=%d body=%s", response.Code, attempt.want, response.Body.String())
					}
					if (store.decided == "approved") != (attempt.want == http.StatusOK) {
						t.Fatalf("decision=%q for status=%d", store.decided, response.Code)
					}
					store.decided = ""
				})
			}
		})
	}
}

func TestOperatorNondefaultPortRemainsExplicit(t *testing.T) {
	handler, err := NewOperator(&fakeStore{}, nil, "127.0.0.1:8080", config.Console{
		OperatorToken: testOperatorToken, OperatorActor: "configured-operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		host, origin string
		want         int
	}{
		{"127.0.0.1:8080", "http://127.0.0.1:8080", http.StatusOK},
		{"127.0.0.1", "http://127.0.0.1:8080", http.StatusForbidden},
		{"127.0.0.1:8080", "http://127.0.0.1", http.StatusForbidden},
		{"127.0.0.1:8081", "http://127.0.0.1:8081", http.StatusForbidden},
		{"attacker.example:8080", "http://attacker.example:8080", http.StatusForbidden},
	} {
		request := operatorDecisionRequest()
		request.Host = test.host
		request.Header.Set("Origin", test.origin)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Fatalf("Host=%q Origin=%q status=%d want=%d", test.host, test.origin, response.Code, test.want)
		}
	}
}
