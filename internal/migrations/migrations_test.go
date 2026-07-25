package migrations

import (
	"strings"
	"testing"
)

func TestEmbeddedMigrationsAreOrderedAndNonDestructive(t *testing.T) {
	versions, err := Versions()
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 6 {
		t.Fatalf("migrations=%v", versions)
	}
	for _, name := range versions {
		body, err := files.ReadFile("sql/" + name)
		if err != nil {
			t.Fatal(err)
		}
		sql := strings.ToUpper(string(body))
		for _, forbidden := range []string{"DROP TABLE", "TRUNCATE ", "DELETE FROM FINDINGS", "DELETE FROM ENDPOINTS"} {
			if strings.Contains(sql, forbidden) {
				t.Fatalf("migration %s contains destructive statement %q", name, forbidden)
			}
		}
	}
}
