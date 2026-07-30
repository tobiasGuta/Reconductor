//go:build operational

package operational

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateTemporaryRootRequiresImmediateOwnedPrefix(t *testing.T) {
	valid, err := os.MkdirTemp("", "reconductor-operational-e2e-unit-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(valid) })
	if err := validateTemporaryRoot(valid); err != nil {
		t.Fatalf("valid temporary root rejected: %v", err)
	}

	wrongPrefix, err := os.MkdirTemp("", "other-operational-root-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(wrongPrefix) })
	if err := validateTemporaryRoot(wrongPrefix); err == nil || !strings.Contains(err.Error(), "required safety prefix") {
		t.Fatalf("wrong-prefix error=%v", err)
	}

	nested := filepath.Join(valid, "reconductor-operational-e2e-nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateTemporaryRoot(nested); err == nil || !strings.Contains(err.Error(), "immediate child") {
		t.Fatalf("nested-root error=%v", err)
	}
}

func TestRemoveTemporaryRootDoesNotFollowSymlink(t *testing.T) {
	root, err := os.MkdirTemp("", "reconductor-operational-e2e-remove-")
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	marker := filepath.Join(outside, "marker.txt")
	if err := os.WriteFile(marker, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "outside-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Logf("symlink cleanup case unavailable: %v", err)
		_ = os.RemoveAll(root)
		return
	}
	if err := removeTemporaryRoot(root); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "preserve" {
		t.Fatalf("cleanup followed symlink outside generated root: data=%q err=%v", data, err)
	}
}

func TestScrubOperationalEnvironmentRemovesInheritedControlAndProxyValues(t *testing.T) {
	base := []string{
		"PATH=test",
		"SYSTEMROOT=C:\\Windows",
		"DATABASE_URL=postgres://normal",
		"NUCLEI_TEMPLATE_DIR=C:\\Users\\normal\\nuclei-templates",
		"POLICY_INTRUSIVE_CHECKS=true",
		"RECON_HEADLESS=true",
		"HTTP_PROXY=https://proxy.example.test",
		"PDCP_API_KEY=secret",
		"CHAOS_KEY=secret",
	}
	got := scrubOperationalEnvironment(base)
	joined := strings.Join(got, "\n")
	for _, forbidden := range []string{
		"DATABASE_URL", "NUCLEI_TEMPLATE_DIR", "POLICY_INTRUSIVE_CHECKS", "RECON_HEADLESS",
		"HTTP_PROXY", "PDCP_API_KEY", "CHAOS_KEY",
	} {
		if strings.Contains(joined, forbidden+"=") {
			t.Fatalf("unsafe inherited variable %s remained: %v", forbidden, got)
		}
	}
	for _, required := range []string{"PATH=test", "SYSTEMROOT=C:\\Windows"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("safe system variable %q was removed: %v", required, got)
		}
	}
}

func TestOwnedContainerLabelsRequireExactRunIdentity(t *testing.T) {
	if !ownedContainerLabels("run123|true", "run123") {
		t.Fatal("exact ownership labels were rejected")
	}
	for _, value := range []string{"run123|false", "run124|true", "|true", "run123|true|extra"} {
		if ownedContainerLabels(value, "run123") {
			t.Fatalf("non-owned labels %q were accepted", value)
		}
	}
}
