package exactactivation

import (
	"errors"
	"strings"
	"testing"
)

func TestPeerEnvironment(t *testing.T) {
	if err := VerifyPeerEnvironment(PeerEnvironment()); err != nil {
		t.Fatal(err)
	}
	// Callers cannot mutate a shared environment slice.
	first := PeerEnvironment()
	first[0] = "DATABASE_URL=secret"
	if err := VerifyPeerEnvironment(PeerEnvironment()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"DATABASE_URL", "PGSERVICE", "PGPASSWORD", "REDIS_PASSWORD", "REDIS_URL", "ARTIFACT_TOKEN", "CONSOLE_OPERATOR_TOKEN", "CHAOS_KEY", "FUTURE_PROVIDER_CREDENTIAL", "HOME", "SSH_AUTH_SOCK", "LISTEN_FDS", "REDACT_SECRET_NAMES"} {
		t.Run(name, func(t *testing.T) {
			for _, value := range []string{"", "do-not-print-this-secret"} {
				env := append(PeerEnvironment(), name+"="+value)
				err := VerifyPeerEnvironment(env, "FUTURE_PROVIDER_CREDENTIAL")
				if !errors.Is(err, ErrPeerEnvironment) || strings.Contains(err.Error(), name) || strings.Contains(err.Error(), value) && value != "" {
					t.Fatalf("environment diagnostic leaked or accepted authority: %v", err)
				}
			}
		})
	}
	for _, env := range [][]string{nil, {"LANG=C"}, {"LANG=C", "LC_ALL=C", "TZ=UTC", "LANG=C"}, {"LANG=C", "LC_ALL=C", "TZ=UTC", "malformed-secret"}, {"LANG=secret", "LC_ALL=C", "TZ=UTC"}, {"LANG=C", "LC_ALL=C", "TZ=UTC\x00secret"}} {
		if !errors.Is(VerifyPeerEnvironment(env), ErrPeerEnvironment) {
			t.Fatal("accepted malformed, duplicate, missing or changed environment")
		}
	}
	if !errors.Is(VerifyPeerEnvironment(PeerEnvironment(), " lang "), ErrPeerEnvironment) {
		t.Fatal("configured secret names must also apply to the allowlist")
	}
}
