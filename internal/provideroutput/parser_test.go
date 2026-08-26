package provideroutput

import (
	"encoding/json"
	"testing"
)

func TestProviderAdaptersParseIndependently(t *testing.T) {
	cases := map[string][]string{
		"subfinder": {"api.example.com", "bad host", `{"host":"www.example.com"}`},
		"dnsx":      {`{"host":"api.example.com","a":["192.0.2.1"]}`},
		"naabu":     {`{"host":"api.example.com","port":8443}`, "broken"},
		"httpx":     {`{"url":"https://api.example.com/","status_code":200,"tech":["Go"]}`},
		"katana":    {`{"request":{"endpoint":"https://api.example.com/v1"}}`},
		"gau":       {`{"url":"https://api.example.com/archive"}`},
		"nuclei":    {`{"matched-at":"https://api.example.com/v1"}`},
	}
	for provider, lines := range cases {
		batch := Parse(provider, lines)
		if len(batch.Records) == 0 {
			t.Fatalf("%s produced no records: %#v", provider, batch)
		}
		if provider == "subfinder" || provider == "naabu" {
			if len(batch.Warnings) != 1 {
				t.Fatalf("%s malformed record should warn: %#v", provider, batch)
			}
		}
	}
}

func TestHTTPXAdapterPreservesClassifierEvidence(t *testing.T) {
	batch := Parse("httpx", []string{`{"url":"https://api.example.com/v1","status_code":302,"content_type":"application/json","location":"https://api.example.com/login","tech":["Go"]}`})
	if len(batch.Records) != 1 || len(batch.Warnings) != 0 {
		t.Fatalf("batch=%#v", batch)
	}
	record := batch.Records[0]
	if record.StatusCode != 302 || len(record.Technologies) != 1 || record.Fields["content_type"] != "application/json" || record.Fields["location"] != "https://api.example.com/login" {
		t.Fatalf("classifier evidence was lost: %#v", record)
	}
}

func TestHostAdaptersRejectJSONNullWithoutRawFallback(t *testing.T) {
	for _, provider := range []string{"subfinder", "chaos", "dnsx"} {
		t.Run(provider, func(t *testing.T) {
			batch := Parse(provider, []string{"null"})
			if len(batch.Records) != 0 || len(batch.Warnings) != 1 {
				t.Fatalf("null batch=%#v", batch)
			}
		})
	}
}

func TestJSONNumberIntegerExtractionIsExact(t *testing.T) {
	for _, test := range []struct {
		name, raw string
	}{
		{name: "integer", raw: `{"url":"https://api.example.com/","status_code":200}`},
		{name: "decimal integral", raw: `{"url":"https://api.example.com/","status_code":200.0}`},
		{name: "exponent integral", raw: `{"url":"https://api.example.com/","status_code":2e2}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			batch := Parse("httpx", []string{test.raw})
			if len(batch.Records) != 1 || batch.Records[0].StatusCode != 200 {
				t.Fatalf("status batch=%#v", batch)
			}
			if _, ok := batch.Records[0].Fields["status_code"].(json.Number); !ok {
				t.Fatalf("numeric field lost exact representation: %#v", batch.Records[0].Fields)
			}
		})
	}
	batch := Parse("naabu", []string{`{"host":"api.example.com","port":8443.5}`})
	if len(batch.Records) != 0 || len(batch.Warnings) != 1 {
		t.Fatalf("non-integral port batch=%#v", batch)
	}
}

func TestHTTPXStatusCodeRejectsPresentInvalidValues(t *testing.T) {
	for _, raw := range []string{
		`{"url":"https://api.example.com/","status_code":1.25}`,
		`{"url":"https://api.example.com/","status_code":999999999999999999999999999999999}`,
		`{"url":"https://api.example.com/","status_code":-1}`,
		`{"url":"https://api.example.com/","status_code":0}`,
		`{"url":"https://api.example.com/","status_code":99}`,
		`{"url":"https://api.example.com/","status_code":600}`,
		`{"url":"https://api.example.com/","status_code":"invalid"}`,
		`{"url":"https://api.example.com/","status_code":1e1000000}`,
		`{"url":"https://api.example.com/","status_code":1e-1000000}`,
		`{"url":"https://api.example.com/","status_code":1234567890123456789012345678901234567890}`,
		`{"url":"https://api.example.com/","status_code":1e}`,
	} {
		batch := Parse("httpx", []string{raw})
		if len(batch.Records) != 0 || len(batch.Warnings) != 1 {
			t.Fatalf("invalid status was accepted: raw=%s batch=%#v", raw, batch)
		}
	}
	batch := Parse("httpx", []string{`{"url":"https://api.example.com/"}`})
	if len(batch.Records) != 1 || batch.Records[0].StatusCode != 0 || len(batch.Warnings) != 0 {
		t.Fatalf("absent status did not remain unknown: %#v", batch)
	}
}

func TestExactJSONIntegerRejectsUnboundedTokensBeforeExpansion(t *testing.T) {
	for _, raw := range []string{"200", "200.0", "2e2", "2E+2", "0", "-0", "65535"} {
		if _, ok := ExactJSONInteger(raw); !ok {
			t.Fatalf("valid exact integer %q was rejected", raw)
		}
	}
	for _, raw := range []string{
		"1.25",
		"1e1000000",
		"1e-1000000",
		"999999999999999999999999999999999",
		"1234567890123456789012345678901234567890.0",
		"1e",
		"1e+",
		"9223372036854775808",
	} {
		if _, ok := ExactJSONInteger(raw); ok {
			t.Fatalf("invalid or unbounded exact integer %q was accepted", raw)
		}
	}
}
