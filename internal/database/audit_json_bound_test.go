package database

import (
	"encoding/json"
	"errors"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"strings"
	"testing"
)

func TestAuditJSONBExactSerializedBoundary(t *testing.T) {
	for _, length := range []int{4081, 4082, 4083} {
		raw, _ := json.Marshal(map[string]string{"target": strings.Repeat("x", length)})
		err := checkAuditProjection(raw)
		if (err != nil) != (length > 4082) {
			t.Fatalf("length=%d err=%v", length, err)
		}
		if err != nil {
			var limit *ProjectionContractLimitError
			if !errors.As(err, &limit) || limit.Limit.Limit != domain.DiagnosticMaxBytes {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		raw  string
		size int
	}{
		{`{"target":"<>&"}`, 17}, {`{"x":"\n\"\\\u0001"}`, 21}, {`{"x":[true,false,null]}`, 26}, {`{"n":1.23e2}`, 10}, {`{"n":1.230e2}`, 12}, {`{"n":1e-2}`, 11}, {`{"n":-0}`, 8},
	} {
		got, err := auditJSONBTextSize([]byte(tc.raw))
		if err != nil || got != tc.size {
			t.Fatalf("%s size=%d want=%d err=%v", tc.raw, got, tc.size, err)
		}
	}
	if err := checkAuditProjection([]byte(`{"n":1e1000000000}`)); err == nil {
		t.Fatal("unbounded numeric expansion reached SQL")
	}
}
