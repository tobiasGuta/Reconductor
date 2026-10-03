package exactactivation

import (
	"errors"
	"strings"
)

const (
	PeerUser       = "reconductor-exact"
	PeerGroup      = "reconductor-exact"
	ListenerPath   = "/run/reconductor-exact/control.sock"
	DescriptorName = "reconductor-exact-control"
)

var (
	ErrActivation      = errors.New("exact activation contract rejected")
	ErrPeerCredentials = errors.New("exact peer credentials rejected")
	ErrPeerEnvironment = errors.New("exact peer environment rejected")
	ErrUnsupported     = errors.New("exact activation requires Linux")
)

// PeerEnvironment is the coordinator environment, not the future sandbox
// environment. It is constructed from scratch and never copies worker inputs.
func PeerEnvironment() []string {
	return []string{"LANG=C", "LC_ALL=C", "TZ=UTC"}
}

// VerifyPeerEnvironment accepts only the fixed coordinator environment. Pass
// cfg.Logging.SecretNames as secretNames when diagnosing a configured launch.
// The closed allowlist rejects unknown future credential names as well as
// today's names. Errors reveal neither names nor values, including malformed
// entries. Empty secret values are still prohibited presence.
func VerifyPeerEnvironment(environ []string, secretNames ...string) error {
	allowed := map[string]string{"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
	seen := make(map[string]bool, len(allowed))
	for _, entry := range environ {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || seen[name] {
			return ErrPeerEnvironment
		}
		for _, secret := range secretNames {
			if strings.EqualFold(name, strings.TrimSpace(secret)) {
				return ErrPeerEnvironment
			}
		}
		want, ok := allowed[name]
		if !ok || value != want {
			return ErrPeerEnvironment
		}
		seen[name] = true
	}
	if len(seen) != len(allowed) {
		return ErrPeerEnvironment
	}
	return nil
}
