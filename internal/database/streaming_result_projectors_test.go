package database

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type staticProjectionSource struct {
	raw    []byte
	digest [32]byte
}

func projectionSource(raw []byte) *staticProjectionSource {
	return &staticProjectionSource{raw: append([]byte(nil), raw...), digest: sha256.Sum256(raw)}
}
func (s *staticProjectionSource) Open() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.raw)), nil
}
func (s *staticProjectionSource) SizeBytes() int64 { return int64(len(s.raw)) }
func (s *staticProjectionSource) SHA256() [32]byte { return s.digest }

func TestClosedResultProjectorRegistryIsExact(t *testing.T) {
	want := map[string][]string{
		"discover.subdomains/v2":   {"asset-observation/v1", "target-decision-audit/v1"},
		"resolve.dns/v3":           {"asset-observation/v1", "target-decision-audit/v1"},
		"scan.ports/v2":            {"asset-observation/v1", "target-decision-audit/v1"},
		"probe.http/v4":            {"asset-observation/v1", "probe-http-source-lineage/v1", "target-decision-audit/v1"},
		"crawl.web/v2":             {"asset-observation/v1", "target-decision-audit/v1"},
		"discover.archive_urls/v2": {"asset-observation/v1", "target-decision-audit/v1"},
		"scan.nuclei/v2":           {"nuclei-candidate/v1", "target-decision-audit/v1"},
		"targeting.prepare/v2":     {"targeting-prepare-filter-audit/v1"},
		"compare.assets/v2":        {},
		"classify.endpoint/v5":     {"endpoint/v1"},
		"report.changes/v3":        {"report-change/v1"},
	}
	if !reflect.DeepEqual(resultProjectorRegistry, want) {
		t.Fatalf("registry=%#v", resultProjectorRegistry)
	}
}

func TestTopLevelArrayProjectionStreamsPastLargeUnselectedFields(t *testing.T) {
	raw := []byte(`{"ignored":"` + strings.Repeat("x", 300_000) + `","items":[{"id":1},{"id":2}],"later":[1,2,3]}`)
	var ids []json.Number
	found, count, err := forEachTopLevelArray(projectionSource(raw), "items", func(_ int, item json.RawMessage) error {
		var value struct {
			ID json.Number `json:"id"`
		}
		decoder := json.NewDecoder(bytes.NewReader(item))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		ids = append(ids, value.ID)
		return nil
	})
	if err != nil || !found || count != 2 || len(ids) != 2 || ids[0] != "1" || ids[1] != "2" {
		t.Fatalf("found=%v count=%d ids=%#v error=%v", found, count, ids, err)
	}
}

func TestProjectionItemLimitIsTypedBeforeSQL(t *testing.T) {
	raw := []byte(`{"items":["` + strings.Repeat("x", projectionItemMaxBytes+1) + `"]}`)
	_, _, err := forEachTopLevelArray(projectionSource(raw), "items", func(int, json.RawMessage) error {
		t.Fatal("oversized item reached projector callback")
		return nil
	})
	var limit *ProjectionContractLimitError
	if !errors.As(err, &limit) || limit.Limit.Subject != domain.LimitProjectionItem || limit.Limit.Unit != domain.LimitBytes || limit.Limit.Observed <= limit.Limit.Limit {
		t.Fatalf("error=%T %v limit=%#v", err, err, limit)
	}
}
