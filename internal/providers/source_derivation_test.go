package providers

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/normalize"
	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
)

func TestClassifyEndpointSourceDerivationsAreAdditiveAndVerified(t *testing.T) {
	const (
		programID = "00000000-0000-4000-8000-000000000101"
		attemptID = "00000000-0000-4000-8000-000000000102"
	)
	records := []provideroutput.Record{{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://example.test/api/users/123?a=1", StatusCode: 200, Fields: map[string]any{}}}
	sources, err := normalize.BuildProbeHTTPSourceRecords(programID, attemptID, records, normalize.RequestSemantics{
		Method:      normalize.ValueSemantics{State: normalize.ValueDefaulted, Value: sourceString("GET")},
		ContentType: normalize.ValueSemantics{State: normalize.ValueUnknown},
	})
	if err != nil {
		t.Fatal(err)
	}
	baseInput := ClassifyEndpointInput{
		Active:                 []string{},
		Passive:                []string{},
		HTTPObservations:       records,
		CrawlObservations:      []provideroutput.Record{},
		PassiveObservations:    []provideroutput.Record{},
		HistoricalObservations: []provideroutput.Record{},
		APISchemaEndpoints:     []string{},
		TargetPlanDigest:       "plan",
	}
	legacy, err := classifyEndpoints(baseInput, programID, false)
	if err != nil {
		t.Fatal(err)
	}
	withSources := baseInput
	withSources.HTTPSourceRecords = sources
	derived, err := classifyEndpoints(withSources, programID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacy.Endpoints, derived.Endpoints) || !reflect.DeepEqual(legacy.Classifications, derived.Classifications) || !reflect.DeepEqual(legacy.InterestingEndpoints, derived.InterestingEndpoints) || !reflect.DeepEqual(legacy.Relationships, derived.Relationships) {
		t.Fatalf("source derivations changed classification output:\nlegacy=%#v\nderived=%#v", legacy, derived)
	}
	if len(derived.SourceDerivations) != 1 || derived.SourceDerivations[0].Endpoint.Digest != derived.Endpoints[0].Digest {
		t.Fatalf("derivations=%#v endpoints=%#v", derived.SourceDerivations, derived.Endpoints)
	}

	tampered := append([]normalize.AuthorizedSourceRecord(nil), sources...)
	tampered[0].RecordDigest = "0000000000000000000000000000000000000000000000000000000000000000"
	withSources.HTTPSourceRecords = tampered
	if _, err := classifyEndpoints(withSources, programID, true); !errors.Is(err, normalize.ErrProbeHTTPSourceContract) {
		t.Fatalf("tampered source error=%v", err)
	}
}

func TestClassifyEndpointSourceCollectionPresenceContract(t *testing.T) {
	const (
		programID = "00000000-0000-4000-8000-000000000301"
		attemptID = "00000000-0000-4000-8000-000000000302"
	)
	records := []provideroutput.Record{{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://example.test/api/users/123", StatusCode: 200, Fields: map[string]any{}}}
	sources, err := normalize.BuildProbeHTTPSourceRecords(programID, attemptID, records, normalize.RequestSemantics{
		Method:      normalize.ValueSemantics{State: normalize.ValueDefaulted, Value: sourceString("GET")},
		ContentType: normalize.ValueSemantics{State: normalize.ValueUnknown},
	})
	if err != nil {
		t.Fatal(err)
	}
	var classifier capability.Capability
	for _, candidate := range internalCapabilities() {
		if candidate.Manifest().Name == "classify.endpoint" {
			classifier = candidate
			break
		}
	}
	if classifier == nil {
		t.Fatal("classify.endpoint capability is missing")
	}
	tampered := append([]normalize.AuthorizedSourceRecord(nil), sources...)
	tampered[0].RecordDigest = "0000000000000000000000000000000000000000000000000000000000000000"

	tests := []struct {
		name              string
		records           []provideroutput.Record
		sourceFields      map[string]any
		wantContractErr   bool
		wantErrorContains string
		wantDerivations   int
	}{
		{name: "missing is legacy", records: records},
		{name: "null fails closed", records: records, sourceFields: map[string]any{"http_source_records": nil}, wantContractErr: true},
		{name: "empty sources and observations", records: []provideroutput.Record{}, sourceFields: map[string]any{"http_source_records": []normalize.AuthorizedSourceRecord{}}},
		{name: "empty sources with observations fails closed", records: records, sourceFields: map[string]any{"http_source_records": []normalize.AuthorizedSourceRecord{}}, wantContractErr: true},
		{name: "valid nonempty sources", records: records, sourceFields: map[string]any{"http_source_records": sources}, wantDerivations: 1},
		{name: "mismatched nonempty sources fail closed", records: records, sourceFields: map[string]any{"http_source_records": tampered}, wantContractErr: true},
		{name: "uppercase alias null fails closed", records: records, sourceFields: map[string]any{"HTTP_SOURCE_RECORDS": nil}, wantContractErr: true, wantErrorContains: "must use canonical spelling"},
		{name: "uppercase alias empty with observations fails closed", records: records, sourceFields: map[string]any{"HTTP_SOURCE_RECORDS": []normalize.AuthorizedSourceRecord{}}, wantContractErr: true, wantErrorContains: "must use canonical spelling"},
		{name: "uppercase alias tampered nonempty fails closed", records: records, sourceFields: map[string]any{"HTTP_SOURCE_RECORDS": tampered}, wantContractErr: true, wantErrorContains: "must use canonical spelling"},
		{name: "mixed case alias valid nonempty fails closed", records: records, sourceFields: map[string]any{"Http_Source_Records": sources}, wantContractErr: true, wantErrorContains: "must use canonical spelling"},
		{name: "canonical and alias duplicate fails closed", records: records, sourceFields: map[string]any{"http_source_records": sources, "http_Source_Records": nil}, wantContractErr: true, wantErrorContains: "must use canonical spelling"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := map[string]any{
				"active":                  []string{},
				"passive":                 []string{},
				"http_observations":       test.records,
				"crawl_observations":      []provideroutput.Record{},
				"passive_observations":    []provideroutput.Record{},
				"historical_observations": []provideroutput.Record{},
				"api_schema_endpoints":    []string{},
				"target_plan_digest":      "plan",
			}
			for field, value := range test.sourceFields {
				input[field] = value
			}
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			req := capability.Request{ProgramID: domain.ID(programID), Action: domain.ActionRequest{Input: raw}}
			validationErr := classifier.Validate(context.Background(), req)
			output, _, err := executeClassifyEndpoint(req)
			if test.wantContractErr {
				if !errors.Is(validationErr, normalize.ErrProbeHTTPSourceContract) {
					t.Fatalf("validation source contract error=%v", validationErr)
				}
				if !errors.Is(err, normalize.ErrProbeHTTPSourceContract) {
					t.Fatalf("source contract error=%v", err)
				}
				if test.wantErrorContains != "" && (!strings.Contains(validationErr.Error(), test.wantErrorContains) || !strings.Contains(err.Error(), test.wantErrorContains)) {
					t.Fatalf("errors do not identify canonical spelling: validation=%v execution=%v", validationErr, err)
				}
				return
			}
			if validationErr != nil {
				t.Fatal(validationErr)
			}
			if err != nil {
				t.Fatal(err)
			}
			if output.SourceDerivations == nil || len(output.SourceDerivations) != test.wantDerivations {
				t.Fatalf("source derivations=%#v want=%d", output.SourceDerivations, test.wantDerivations)
			}
		})
	}
}

func TestClassifyEndpointLegacyInputHasNoSourceDerivations(t *testing.T) {
	input := ClassifyEndpointInput{
		Active:                 []string{},
		Passive:                []string{},
		HTTPObservations:       []provideroutput.Record{},
		CrawlObservations:      []provideroutput.Record{},
		PassiveObservations:    []provideroutput.Record{},
		HistoricalObservations: []provideroutput.Record{},
		APISchemaEndpoints:     []string{},
		TargetPlanDigest:       "plan",
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	output, _, err := executeClassifyEndpoint(capability.Request{ProgramID: domain.ID("00000000-0000-4000-8000-000000000101"), Action: domain.ActionRequest{Input: raw}})
	if err != nil {
		t.Fatal(err)
	}
	if output.SourceDerivations == nil || len(output.SourceDerivations) != 0 {
		t.Fatalf("legacy derivations=%#v", output.SourceDerivations)
	}
}

func TestClassifyEndpointRetainsHTTPXNumbersAcrossSerializedInput(t *testing.T) {
	const (
		programID = "00000000-0000-4000-8000-000000000201"
		attemptID = "00000000-0000-4000-8000-000000000202"
	)
	batch := provideroutput.Parse("httpx", []string{`{"url":"https://example.test/api/users/123","status_code":200,"meta":{"confidence":0.75,"large":9007199254740993}}`})
	if len(batch.Records) != 1 || len(batch.Warnings) != 0 {
		t.Fatalf("httpx batch=%#v", batch)
	}
	records := batch.Records
	sources, err := normalize.BuildProbeHTTPSourceRecords(programID, attemptID, records, normalize.RequestSemantics{
		Method:      normalize.ValueSemantics{State: normalize.ValueDefaulted, Value: sourceString("GET")},
		ContentType: normalize.ValueSemantics{State: normalize.ValueUnknown},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ClassifyEndpointInput{
		Active:                 []string{},
		Passive:                []string{},
		HTTPObservations:       records,
		HTTPSourceRecords:      sources,
		CrawlObservations:      []provideroutput.Record{},
		PassiveObservations:    []provideroutput.Record{},
		HistoricalObservations: []provideroutput.Record{},
		APISchemaEndpoints:     []string{},
		TargetPlanDigest:       "plan",
	})
	if err != nil {
		t.Fatal(err)
	}
	output, _, err := executeClassifyEndpoint(capability.Request{ProgramID: domain.ID(programID), Action: domain.ActionRequest{Input: raw}})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.SourceDerivations) != 1 || len(output.Endpoints) != 1 {
		t.Fatalf("source derivation was lost: %#v", output)
	}
}

func TestObservationSerializationPreservesExactNumbers(t *testing.T) {
	const (
		large    = "9007199254740993"
		fraction = "0.10000000000000001"
	)
	observation := `{"url":"https://example.test/","status_code":200,"title":9007199254740993,"tech":[0.10000000000000001]}`
	for name, value := range map[string]string{
		"fingerprint": observationFingerprint(observation),
		"structured":  string(structuredObservation(observation)),
	} {
		if !strings.Contains(value, large) || !strings.Contains(value, fraction) {
			t.Fatalf("%s lost exact numbers: %s", name, value)
		}
	}

	var values HTTPObservationValues
	raw := `[{"provider":"httpx","kind":"url","target":"https://example.test/","fields":{"large":9007199254740993,"fraction":0.10000000000000001}}]`
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || !strings.Contains(values[0], large) || !strings.Contains(values[0], fraction) {
		t.Fatalf("structured observation lost exact numbers: %#v", values)
	}
}

func sourceString(value string) *string { return &value }
