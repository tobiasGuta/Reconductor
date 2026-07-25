package provideroutput

import "testing"

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
