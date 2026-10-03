package exactactivation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Guard the slice boundary: startup validation must remain independent of
// execution/handoff machinery and must not acquire capacity by accepting it.
// This is a source-level regression check, not a claim about deployed units.
func TestFoundationHasNoExecutionOrAcceptPath(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"/exactexecution", "/exactsandbox", "/exacthandoff", "/execution", "/providers", "/queue", "/worker"} {
				if strings.HasSuffix(path, forbidden) {
					t.Fatalf("activation foundation acquired execution dependency: %s", path)
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if method, ok := call.Fun.(*ast.SelectorExpr); ok {
				switch method.Sel.Name {
				case "Accept", "AcceptUnix", "Accept4", "Shutdown", "ExecuteApprovedExact":
					t.Errorf("startup foundation contains prohibited operation: %s", method.Sel.Name)
				}
			}
			return true
		})
	}
}
