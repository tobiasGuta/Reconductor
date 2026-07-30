package scope

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const referenceTestScope = `{"target":{"scope":{"advanced_mode":true,"exclude":[],"include":[{"enabled":true,"file":"^/.*","host":"^app\\.example\\.test$","port":"^443$","protocol":"https"}]}}}`

func TestResolveReferencePortability(t *testing.T) {
	root := t.TempDir()
	want := filepath.Join(root, "scope", "example.json")

	for name, reference := range map[string]string{
		"repository relative": "scope/example.json",
		"Windows separators":  `scope\example.json`,
		"legacy container":    "/scope/example.json",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ResolveReference(reference, root)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("resolved %q to %q, want %q", reference, got, want)
			}
		})
	}

	absolute := filepath.Join(t.TempDir(), "absolute.json")
	got, err := ResolveReference(absolute, root)
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Clean(absolute) {
		t.Fatalf("absolute reference was remapped: %q", got)
	}

	got, err = ResolveReference("/scope/example.json", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/scope/example.json" {
		t.Fatalf("unconfigured legacy reference was guessed as %q", got)
	}
	got, err = ResolveReference("scope/example.json", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join("scope", "example.json") {
		t.Fatalf("unconfigured repository-relative reference = %q", got)
	}
}

func TestResolveReferenceRejectsTraversalAndForeignWindowsAbsolutePaths(t *testing.T) {
	root := t.TempDir()
	for _, reference := range []string{"../outside.json", "scope/../outside.json", `scope\..\outside.json`, "/scope/../outside.json"} {
		if _, err := ResolveReference(reference, root); err == nil {
			t.Fatalf("traversal reference %q was accepted", reference)
		}
	}

	const windowsAbsolute = `D:\scopes\example.json`
	got, err := ResolveReference(windowsAbsolute, root)
	if runtime.GOOS == "windows" {
		if err != nil || got != filepath.Clean(windowsAbsolute) {
			t.Fatalf("Windows absolute path resolution = %q, %v", got, err)
		}
	} else if err == nil || !strings.Contains(err.Error(), "cannot be resolved") {
		t.Fatalf("foreign Windows absolute path error = %v", err)
	}
}

func TestLoadBurpReferenceKeepsScopeAndPlanDigestsIndependentOfReference(t *testing.T) {
	root := t.TempDir()
	scopeDir := filepath.Join(root, "scope")
	if err := os.Mkdir(scopeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	scopePath := filepath.Join(scopeDir, "example.json")
	if err := os.WriteFile(scopePath, []byte(referenceTestScope), 0o600); err != nil {
		t.Fatal(err)
	}

	direct, err := LoadBurp(scopePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range []string{"scope/example.json", "/scope/example.json"} {
		resolved, err := LoadBurpReference(reference, root)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.Digest() != direct.Digest() {
			t.Fatalf("%q changed scope digest: got %s want %s", reference, resolved.Digest(), direct.Digest())
		}
	}
}

func TestLoadBurpReferenceReportsMissingResolvedFile(t *testing.T) {
	root := t.TempDir()
	_, err := LoadBurpReference("scope/missing.json", root)
	if err == nil || !strings.Contains(err.Error(), "does not exist") || !strings.Contains(err.Error(), "scope/missing.json") {
		t.Fatalf("missing scope error = %v", err)
	}
}

func TestCanonicalReferenceUsesPortableLogicalSeparators(t *testing.T) {
	got, err := CanonicalReference(`.\scope\example.json`)
	if err != nil {
		t.Fatal(err)
	}
	if got != "scope/example.json" {
		t.Fatalf("canonical reference = %q", got)
	}
}
