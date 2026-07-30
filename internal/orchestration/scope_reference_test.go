package orchestration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/config"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
)

func TestServiceLoadsLogicalAndLegacyScopeReferencesIdentically(t *testing.T) {
	root := t.TempDir()
	scopeDir := filepath.Join(root, "scope")
	if err := os.Mkdir(scopeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	scopePath := filepath.Join(scopeDir, "example.json")
	scopeJSON := `{"target":{"scope":{"exclude":[],"include":[{"enabled":true,"file":"^/.*","host":"^app\\.example\\.test$","port":"^443$","protocol":"https"}]}}}`
	if err := os.WriteFile(scopePath, []byte(scopeJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	service := Service{Config: config.Config{Scope: config.Scope{Root: root}}}
	direct, err := platformscope.LoadBurp(scopePath)
	if err != nil {
		t.Fatal(err)
	}
	directPlan, err := targeting.Plan(direct, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range []string{"scope/example.json", "/scope/example.json"} {
		loaded, err := service.loadScope(reference)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := targeting.Plan(loaded, nil)
		if err != nil {
			t.Fatal(err)
		}
		if loaded.Digest() != direct.Digest() || plan.Digest != directPlan.Digest {
			t.Fatalf("%q changed scope or target-plan digest", reference)
		}
	}
}
