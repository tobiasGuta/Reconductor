//go:build linux && amd64 && exactcontainment_deployment

package exactcontainment

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/exactsandbox"
)

// Run ONLY inside an independently provisioned disposable Fedora guest as the
// locked reconductor-exact account, with the exact coordinator environment.
// This test never provisions accounts, installs artifacts, or changes policy.
func TestDisposableFedoraProductionPreflight(t *testing.T) {
	requireDisposableFedoraDeployment(t)
	if err := Preflight(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDisposableFedoraProductionExecuteOffline(t *testing.T) {
	requireDisposableFedoraDeployment(t)
	in := exactsandbox.DeploymentFixtureEncodedExecution()
	// Use the public production entry: credentials, environment, artifact trust,
	// a fresh Preflight probe, Bubblewrap and seccomp remain mandatory.
	raw, err := ExecuteOffline(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	result, err := exactsandbox.DecodeResult(raw, in.Digest())
	if err != nil || result.Completed {
		t.Fatal("expected bound canonical Completed=false result:", err)
	}
	want, err := exactsandbox.EncodeResult(in.Digest(), false)
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatal("offline result differs from the canonical fixed result:", err)
	}
}

func requireDisposableFedoraDeployment(t *testing.T) {
	t.Helper()
	// Opt-in is the build tag, avoiding an extra environment variable at the
	// frozen peer environment boundary. Host ordinary tests cannot enter here.
	state, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil || !bytes.Equal(bytes.TrimSpace(state), []byte("1")) {
		t.Fatal("disposable Fedora proof requires SELinux Enforcing", err)
	}
	if _, err := os.Stat(launcherPath); err != nil {
		t.Fatal("guest artifacts must already be provisioned:", err)
	}
}
