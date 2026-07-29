package database

import (
	"encoding/json"
	"testing"
)

func TestObservationLinesPreferAuthorizedStructuredRecords(t *testing.T) {
	raw := json.RawMessage(`{"lines":["https://inside.test/"],"authorized_records":[{"provider":"httpx","kind":"url","target":"https://inside.test/","status_code":401}],"records":[{"provider":"httpx","kind":"url","target":"https://outside.test/"}]}`)
	lines := observationLines(raw)
	if len(lines) != 1 || extractValue(lines[0]) != "https://inside.test/" {
		t.Fatalf("authorized observations=%q", lines)
	}
	if json.Valid(json.RawMessage(lines[0])) == false {
		t.Fatalf("structured observation was not retained: %q", lines[0])
	}
}

func TestObservationLinesFallsBackToLegacyLines(t *testing.T) {
	lines := observationLines(json.RawMessage(`{"lines":["https://legacy.test/"]}`))
	if len(lines) != 1 || lines[0] != "https://legacy.test/" {
		t.Fatalf("legacy observations=%q", lines)
	}
}

func TestPreviousObservationValueOnlyUnwrapsLegacyValueMetadata(t *testing.T) {
	tests := []struct {
		name          string
		metadata      json.RawMessage
		observedValue string
		want          string
	}{
		{"legacy value wrapper", json.RawMessage(`{"value":"https://example.test/"}`), "https://example.test/", "https://example.test/"},
		{"plain URL wrapper remains rejected later when malformed", json.RawMessage(`{"value":"not a url"}`), "not a url", "not a url"},
		{"structured HTTPX JSON", json.RawMessage(`{"url":"https://example.test/","status_code":200,"tech":["Go"]}`), "https://example.test/", `{"url":"https://example.test/","status_code":200,"tech":["Go"]}`},
		{"normalized HTTPX record", json.RawMessage(`{"provider":"httpx","kind":"url","target":"https://example.test/","status_code":200}`), "https://example.test/", `{"provider":"httpx","kind":"url","target":"https://example.test/","status_code":200}`},
		{"unexpected wrapper shape", json.RawMessage(`{"value":"https://other.test/","status_code":200}`), "https://other.test/", `{"value":"https://other.test/","status_code":200}`},
		{"value mismatch", json.RawMessage(`{"value":"https://other.test/"}`), "https://example.test/", `{"value":"https://other.test/"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := previousObservationValue(test.metadata, test.observedValue); got != test.want {
				t.Fatalf("value=%q want=%q", got, test.want)
			}
		})
	}
}
