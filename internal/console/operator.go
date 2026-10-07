package console

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/tobiasGuta/Reconductor/internal/config"
)

// operatorBoundary represents one configured local console, never request data.
type operatorBoundary struct {
	host   string
	origin string
	token  string
	actor  string
}

func newOperatorBoundary(address string, operator config.Console) (*operatorBoundary, error) {
	if err := operator.Validate(); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("console listen address must be a loopback host:port")
	}
	if !strings.EqualFold(host, "localhost") {
		ip, err := netip.ParseAddr(host)
		if err == nil && ip.Is4In6() {
			return nil, errors.New("IPv4-mapped IPv6 console addresses are unsupported")
		}
		if err != nil || !ip.IsLoopback() || ip.Zone() != "" {
			return nil, errors.New("console listen address must be a loopback host:port")
		}
		host = ip.String()
	} else {
		host = "localhost"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("console listen port must be between 1 and 65535")
	}
	trustedHost := net.JoinHostPort(host, strconv.Itoa(portNumber))
	if portNumber == 80 {
		trustedHost = host
		if strings.Contains(host, ":") {
			trustedHost = "[" + host + "]"
		}
	}
	return &operatorBoundary{
		host: trustedHost, origin: (&url.URL{Scheme: "http", Host: trustedHost}).String(),
		token: operator.OperatorToken, actor: operator.OperatorActor,
	}, nil
}

func (b *operatorBoundary) trustedHost(r *http.Request) bool {
	return b != nil && len(r.Header.Values("Host")) == 0 && r.Host == b.host
}

func (b *operatorBoundary) authenticated(r *http.Request) bool {
	if b == nil {
		return false
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	scheme, token, ok := strings.Cut(values[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || len(token) != len(b.token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(b.token)) == 1
}

// operatorGate covers every API mutation and is reusable for sensitive GETs.
// Static assets, health, and the existing summary reads remain public locally.
func (s *Server) operatorGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.operator != nil && !s.operator.trustedHost(r) {
			writeError(w, http.StatusForbidden, "console host is not trusted")
			return
		}
		protected := r.URL.Path == "/api/v1/operator/check" ||
			r.URL.Path == "/api/v1/exact-approvals" || strings.HasPrefix(r.URL.Path, "/api/v1/exact-approvals/") ||
			(strings.HasPrefix(r.URL.Path, "/api/v1/") && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions)
		if protected && s.operator == nil {
			writeError(w, http.StatusServiceUnavailable, "operator mutations are not configured")
			return
		}
		if protected && !s.operator.authenticated(r) {
			writeError(w, http.StatusUnauthorized, "operator authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) validOperatorRequest(r *http.Request) bool {
	if !s.operator.trustedHost(r) || r.Header.Get("X-Reconductor-Request") != "operator-console" {
		return false
	}
	if site := strings.ToLower(r.Header.Get("Sec-Fetch-Site")); site != "" && site != "same-origin" {
		return false
	}
	origins := r.Header.Values("Origin")
	if len(origins) == 0 {
		return true // Authenticated local API client without a browser Origin.
	}
	return len(origins) == 1 && origins[0] == s.operator.origin
}
