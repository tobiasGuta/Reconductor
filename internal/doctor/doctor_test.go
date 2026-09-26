package doctor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/providercheck"
	"github.com/tobiasGuta/Reconductor/internal/providers"
)

type fakeDoctorRunner struct {
	path, output string
	lookErr      error
	probeErr     error
}

func (f fakeDoctorRunner) LookPath(string) (string, error) { return f.path, f.lookErr }
func (f fakeDoctorRunner) CombinedOutput(context.Context, string, []string) (string, error) {
	return f.output, f.probeErr
}

func TestTemplateSnapshotStatus(t *testing.T) {
	dir := t.TempDir()
	runner := fakeDoctorRunner{path: "nuclei", output: "[INF] Public nuclei-templates version: " + providers.TemplatesPinnedVersion + " (" + dir + ")"}
	if got := checkTemplates(context.Background(), dir, "nuclei", runner); got.Status != providercheck.Status("current") {
		t.Fatalf("nuclei tv fallback result=%+v", got)
	}
	if got := checkTemplates(context.Background(), dir, "nuclei", fakeDoctorRunner{path: "nuclei", output: "no version"}); got.Status != providercheck.Status("untracked") {
		t.Fatalf("untracked result=%+v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, ".platform-template-version"), []byte(providers.TemplatesPinnedVersion+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := checkTemplates(context.Background(), dir, "nuclei", nil); got.Status != providercheck.Status("current") {
		t.Fatalf("current result=%+v", got)
	}
}

func TestTemplateDiscoveryUsesNucleiDefaultDirectory(t *testing.T) {
	output := `[INF] Public nuclei-templates version: v10.4.6 (C:\Users\BigBrooklyn\nuclei-templates)`
	got := checkTemplates(context.Background(), "", "nuclei", fakeDoctorRunner{path: `C:\Users\BigBrooklyn\go\bin\nuclei.exe`, output: output})
	if got.Status != providercheck.Status("ahead") {
		t.Fatalf("status=%s result=%+v", got.Status, got)
	}
	if got.DetectedVersion != "v10.4.6" || got.Path != `C:\Users\BigBrooklyn\nuclei-templates` {
		t.Fatalf("unexpected template discovery result=%+v", got)
	}
}

func TestTemplateDiscoveryClassifiesOlderAndProbeFailures(t *testing.T) {
	older := checkTemplates(context.Background(), "", "nuclei", fakeDoctorRunner{path: "nuclei", output: "[INF] Public nuclei-templates version: v10.4.2"})
	if older.Status != providercheck.Status("outdated") {
		t.Fatalf("older result=%+v", older)
	}
	failed := checkTemplates(context.Background(), "", "nuclei", fakeDoctorRunner{lookErr: errors.New("not found")})
	if failed.Status != providercheck.Missing {
		t.Fatalf("missing result=%+v", failed)
	}
}

func TestTemplateDiscoveryRequiresConfiguredDirectoryToMatchNuclei(t *testing.T) {
	dir := t.TempDir()
	output := "[INF] Public nuclei-templates version: " + providers.TemplatesPinnedVersion + " (" + filepath.Join(t.TempDir(), "nuclei-templates") + ")"
	got := checkTemplates(context.Background(), dir, "nuclei", fakeDoctorRunner{path: "nuclei", output: output})
	if got.Status != providercheck.Status("untracked") {
		t.Fatalf("configured directory mismatch result=%+v", got)
	}
}

func TestFailuresAndTableOutput(t *testing.T) {
	results := []providercheck.Result{
		{Component: "Subfinder", Required: true, Status: providercheck.Compatible},
		{Component: "Nuclei templates", Required: true, Status: providercheck.Status("ahead")},
		{Component: "Chaos", Required: false, Status: providercheck.Missing},
		{Component: "Redis", Required: true, Status: providercheck.Status("unreachable")},
	}
	if got := Failures(results, false); len(got) != 1 || got[0].Component != "Redis" {
		t.Fatalf("failures=%+v", got)
	}
	if got := Failures(results, true); len(got) != 2 {
		t.Fatalf("all failures=%+v", got)
	}
	var out bytes.Buffer
	if err := WriteTable(&out, Report{Results: results}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "COMPONENT") || !strings.Contains(out.String(), "Subfinder") {
		t.Fatalf("table=%q", out.String())
	}
}

func TestPreparedEvidenceCheckRequiresDatabaseAndStoreIdentity(t *testing.T) {
	got := checkPreparedEvidence(context.Background(), config.Config{})
	if got.Status != providercheck.Status("not_configured") || !strings.Contains(got.Details, "DATABASE_URL") {
		t.Fatalf("missing database result=%+v", got)
	}
	got = checkPreparedEvidence(context.Background(), config.Config{Database: config.Database{URL: "postgres://unused"}})
	if got.Status != providercheck.Status("not_configured") || !strings.Contains(got.Details, "ARTIFACT_STORE_ID") {
		t.Fatalf("missing store result=%+v", got)
	}
}
