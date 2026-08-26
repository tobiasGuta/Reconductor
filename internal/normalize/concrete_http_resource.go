package normalize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
)

const (
	HTTPURIResourceNamespace     = "http-uri-resource-v1"
	HTTPResourceDerivationV1     = "http-resource-derivation-v1"
	probeHTTPSourceLocatorDomain = "reconductor/probe-http-source-locator/v1"
)

var ErrProbeHTTPSourceContract = errors.New("probe HTTP source contract is invalid")

type ValueState string

const (
	ValueKnown     ValueState = "known"
	ValueDefaulted ValueState = "defaulted"
	ValueUnknown   ValueState = "unknown"
)

// ValueSemantics distinguishes unavailable data from an explicitly known empty
// value. Value is nil only when State is unknown.
type ValueSemantics struct {
	State ValueState `json:"state"`
	Value *string    `json:"value"`
}

type RequestSemantics struct {
	Method      ValueSemantics `json:"request_method"`
	ContentType ValueSemantics `json:"request_content_type"`
}

type CanonicalConcreteHTTPResource struct {
	IdentityNamespace   string `json:"identity_namespace"`
	Scheme              string `json:"scheme"`
	Host                string `json:"host"`
	EffectivePort       int    `json:"effective_port"`
	ConcreteEscapedPath string `json:"concrete_escaped_path"`
	CanonicalQuery      string `json:"canonical_query"`
	CanonicalURL        string `json:"canonical_url"`
}

// AuthorizedSourceRecord is platform-owned lineage. The provider record is
// referenced by index instead of copied into this collection.
type AuthorizedSourceRecord struct {
	AuthorizedRecordIndex int            `json:"authorized_record_index"`
	RecordDigest          string         `json:"record_digest"`
	SourceLocator         string         `json:"source_locator"`
	IdentityNamespace     string         `json:"identity_namespace"`
	DerivationVersion     string         `json:"derivation_version"`
	ProviderAttemptID     string         `json:"provider_attempt_id"`
	RequestMethod         ValueSemantics `json:"request_method"`
	RequestContentType    ValueSemantics `json:"request_content_type"`
}

type ProbeHTTPSourceOutput struct {
	AuthorizedRecords       []provideroutput.Record  `json:"authorized_records"`
	AuthorizedSourceRecords []AuthorizedSourceRecord `json:"authorized_source_records"`
}

type SourceDerivation struct {
	SourceLocator               string         `json:"source_locator"`
	IdentityNamespace           string         `json:"identity_namespace"`
	Endpoint                    EndpointKey    `json:"endpoint"`
	EffectiveMethod             ValueSemantics `json:"effective_method"`
	EffectiveRequestContentType ValueSemantics `json:"effective_request_content_type"`
	DerivationVersion           string         `json:"derivation_version"`
}

// CanonicalConcreteHTTPResource preserves the URI details intentionally
// discarded by Endpoint route-family identity.
func ConcreteHTTPResource(rawURL string) (CanonicalConcreteHTTPResource, error) {
	u, origin, err := endpointURL(rawURL)
	if err != nil {
		return CanonicalConcreteHTTPResource{}, err
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return CanonicalConcreteHTTPResource{}, fmt.Errorf("parse concrete resource query: %w", err)
	}
	u.RawQuery = values.Encode()
	u.ForceQuery = false
	return CanonicalConcreteHTTPResource{
		IdentityNamespace:   HTTPURIResourceNamespace,
		Scheme:              origin.Scheme,
		Host:                origin.Host,
		EffectivePort:       origin.EffectivePort,
		ConcreteEscapedPath: u.EscapedPath(),
		CanonicalQuery:      u.RawQuery,
		CanonicalURL:        u.String(),
	}, nil
}

// ProbeRequestSemantics derives only typed platform request data. It never
// promotes provider response metadata into request semantics.
func ProbeRequestSemantics(raw json.RawMessage) (RequestSemantics, error) {
	var input struct {
		Method             *string `json:"method"`
		RequestContentType *string `json:"request_content_type"`
	}
	if len(raw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		if err := decoder.Decode(&input); err != nil {
			return RequestSemantics{}, sourceContractError("decode request semantics")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return RequestSemantics{}, sourceContractError("decode request semantics")
		}
		if method, present := fields["method"]; present && bytes.Equal(bytes.TrimSpace(method), []byte("null")) {
			return RequestSemantics{}, sourceContractError("request method is invalid")
		}
	}
	method := "GET"
	methodState := ValueDefaulted
	if input.Method != nil {
		method = strings.ToUpper(strings.TrimSpace(*input.Method))
		if method == "" || !validHTTPMethod(method) {
			return RequestSemantics{}, sourceContractError("request method is invalid")
		}
		methodState = ValueKnown
	}
	content := ValueSemantics{State: ValueUnknown, Value: nil}
	if input.RequestContentType != nil {
		value, err := normalizeRequestContentType(*input.RequestContentType)
		if err != nil {
			return RequestSemantics{}, sourceContractError("request content type is invalid")
		}
		content = ValueSemantics{State: ValueKnown, Value: stringPointer(value)}
	}
	return RequestSemantics{
		Method:      ValueSemantics{State: methodState, Value: stringPointer(method)},
		ContentType: content,
	}, nil
}

// AttachProbeHTTPSourceRecords replaces any pre-existing lineage collection
// with one generated exclusively from the normalized provider records and the
// durable platform provider-attempt identity.
func AttachProbeHTTPSourceRecords(output json.RawMessage, programID, providerAttemptID string, input json.RawMessage) (json.RawMessage, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(output, &envelope); err != nil || envelope == nil {
		return nil, sourceContractError("probe output must be a JSON object")
	}
	recordsRaw, ok := envelope["authorized_records"]
	if !ok || bytes.Equal(bytes.TrimSpace(recordsRaw), []byte("null")) {
		return nil, sourceContractError("authorized records are required")
	}
	records, err := decodeRecords(recordsRaw)
	if err != nil {
		return nil, err
	}
	semantics, err := ProbeRequestSemantics(input)
	if err != nil {
		return nil, err
	}
	sources, err := BuildProbeHTTPSourceRecords(programID, providerAttemptID, records, semantics)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(sources)
	if err != nil {
		return nil, sourceContractError("encode source records")
	}
	// Never preserve a provider-controlled or caller-supplied lineage value.
	envelope["authorized_source_records"] = encoded
	result, err := json.Marshal(envelope)
	if err != nil {
		return nil, sourceContractError("encode decorated probe output")
	}
	return result, nil
}

// ParseProbeHTTPSourceOutput recognizes legacy outputs by the absence of the
// v4 source collection. Present v4 collections are recomputed and compared in
// full before callers can trust them.
func ParseProbeHTTPSourceOutput(raw json.RawMessage, programID, providerAttemptID string) (ProbeHTTPSourceOutput, bool, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope == nil {
		return ProbeHTTPSourceOutput{}, false, nil
	}
	sourcesRaw, present := envelope["authorized_source_records"]
	if !present {
		return ProbeHTTPSourceOutput{}, false, nil
	}
	if bytes.Equal(bytes.TrimSpace(sourcesRaw), []byte("null")) {
		return ProbeHTTPSourceOutput{}, true, sourceContractError("source records must be an array")
	}
	recordsRaw, ok := envelope["authorized_records"]
	if !ok || bytes.Equal(bytes.TrimSpace(recordsRaw), []byte("null")) {
		return ProbeHTTPSourceOutput{}, true, sourceContractError("authorized records are required")
	}
	records, err := decodeRecords(recordsRaw)
	if err != nil {
		return ProbeHTTPSourceOutput{}, true, err
	}
	sources, err := decodeSourceRecords(sourcesRaw)
	if err != nil {
		return ProbeHTTPSourceOutput{}, true, err
	}
	if len(programID) == 0 || len(providerAttemptID) == 0 {
		return ProbeHTTPSourceOutput{}, true, sourceContractError("trusted program and provider-attempt identities are required")
	}
	if len(sources) == 0 && sources == nil {
		return ProbeHTTPSourceOutput{}, true, sourceContractError("source records must be a non-null array")
	}
	semantics, err := sourceSemanticsFromRecords(sources)
	if err != nil {
		return ProbeHTTPSourceOutput{}, true, err
	}
	expected, err := BuildProbeHTTPSourceRecords(programID, providerAttemptID, records, semantics)
	if err != nil {
		return ProbeHTTPSourceOutput{}, true, err
	}
	if !reflect.DeepEqual(sources, expected) {
		return ProbeHTTPSourceOutput{}, true, sourceContractError("source records do not match platform-derived lineage")
	}
	return ProbeHTTPSourceOutput{AuthorizedRecords: records, AuthorizedSourceRecords: sources}, true, nil
}

// BuildProbeHTTPSourceRecords emits one deterministically ordered locator per
// logical record within an attempt. Exact duplicates retain the lowest
// authorized-record index as their representative.
func BuildProbeHTTPSourceRecords(programID, providerAttemptID string, records []provideroutput.Record, semantics RequestSemantics) ([]AuthorizedSourceRecord, error) {
	return buildProbeHTTPSourceRecords(programID, providerAttemptID, records, semantics, SourceLocator)
}

func buildProbeHTTPSourceRecords(programID, providerAttemptID string, records []provideroutput.Record, semantics RequestSemantics, locatorFor func(string, string, string, []byte, RequestSemantics) (string, error)) ([]AuthorizedSourceRecord, error) {
	if strings.TrimSpace(programID) == "" || strings.TrimSpace(providerAttemptID) == "" {
		return nil, sourceContractError("trusted program and provider-attempt identities are required")
	}
	if err := validateRequestSemantics(semantics, false); err != nil {
		return nil, err
	}
	out := make([]AuthorizedSourceRecord, 0, len(records))
	seen := make(map[string][]byte, len(records))
	for index, record := range records {
		if record.Kind != provideroutput.URLRecord {
			return nil, sourceContractError("authorized record %d is not an HTTP URL record", index)
		}
		if _, err := ConcreteHTTPResource(record.Target); err != nil {
			return nil, sourceContractError("authorized record %d has an invalid concrete HTTP resource", index)
		}
		material, err := CanonicalRecordJSON(record)
		if err != nil {
			return nil, sourceContractError("authorized record %d cannot be canonicalized", index)
		}
		recordDigest := digestHex(material)
		locator, err := locatorFor(programID, HTTPURIResourceNamespace, providerAttemptID, material, semantics)
		if err != nil {
			return nil, err
		}
		if previous, duplicate := seen[locator]; duplicate {
			if bytes.Equal(previous, material) {
				continue
			}
			return nil, sourceContractError("distinct source records produced the same source locator")
		}
		seen[locator] = append([]byte(nil), material...)
		out = append(out, AuthorizedSourceRecord{
			AuthorizedRecordIndex: index,
			RecordDigest:          recordDigest,
			SourceLocator:         locator,
			IdentityNamespace:     HTTPURIResourceNamespace,
			DerivationVersion:     HTTPResourceDerivationV1,
			ProviderAttemptID:     providerAttemptID,
			RequestMethod:         semantics.Method,
			RequestContentType:    semantics.ContentType,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SourceLocator < out[j].SourceLocator
	})
	return out, nil
}

func SourceLocator(programID, identityNamespace, providerAttemptID string, recordJSON []byte, semantics RequestSemantics) (string, error) {
	if strings.TrimSpace(programID) == "" || identityNamespace != HTTPURIResourceNamespace || strings.TrimSpace(providerAttemptID) == "" || len(recordJSON) == 0 {
		return "", sourceContractError("source locator material is incomplete")
	}
	if err := validateRequestSemantics(semantics, false); err != nil {
		return "", err
	}
	requestJSON, err := canonicalRequestSemanticsJSON(semantics)
	if err != nil {
		return "", err
	}
	var material bytes.Buffer
	material.WriteString(`{"program_id":`)
	appendJSONString(&material, programID)
	material.WriteString(`,"identity_namespace":`)
	appendJSONString(&material, identityNamespace)
	material.WriteString(`,"provider_attempt_id":`)
	appendJSONString(&material, providerAttemptID)
	material.WriteString(`,"record":`)
	material.Write(recordJSON)
	material.WriteString(`,"request":`)
	material.Write(requestJSON)
	material.WriteByte('}')
	sum := sha256.Sum256(append([]byte(probeHTTPSourceLocatorDomain+"\x00"), material.Bytes()...))
	return hex.EncodeToString(sum[:]), nil
}

func DeriveEndpointFromConcrete(resource CanonicalConcreteHTTPResource, semantics RequestSemantics) (EndpointKey, ValueSemantics, ValueSemantics, error) {
	if resource.IdentityNamespace != HTTPURIResourceNamespace || resource.CanonicalURL == "" {
		return EndpointKey{}, ValueSemantics{}, ValueSemantics{}, sourceContractError("concrete resource identity is incomplete")
	}
	if err := validateRequestSemantics(semantics, false); err != nil {
		return EndpointKey{}, ValueSemantics{}, ValueSemantics{}, err
	}
	effectiveMethod := semantics.Method
	if effectiveMethod.State == ValueUnknown {
		effectiveMethod = ValueSemantics{State: ValueDefaulted, Value: stringPointer("GET")}
	}
	effectiveContent := semantics.ContentType
	if effectiveContent.State == ValueUnknown {
		effectiveContent = ValueSemantics{State: ValueDefaulted, Value: stringPointer("")}
	}
	key, err := Endpoint(resource.CanonicalURL, *effectiveMethod.Value, *effectiveContent.Value)
	if err != nil {
		return EndpointKey{}, ValueSemantics{}, ValueSemantics{}, err
	}
	return key, effectiveMethod, effectiveContent, nil
}

func DeriveProbeHTTPSourceRecords(programID string, records []provideroutput.Record, sources []AuthorizedSourceRecord) ([]SourceDerivation, error) {
	if sources == nil {
		return []SourceDerivation{}, nil
	}
	if len(sources) == 0 {
		if len(records) > 0 {
			return nil, sourceContractError("source records do not match platform-derived lineage")
		}
		return []SourceDerivation{}, nil
	}
	if strings.TrimSpace(programID) == "" {
		return nil, sourceContractError("trusted program identity is required")
	}
	providerAttemptID := sources[0].ProviderAttemptID
	for _, source := range sources[1:] {
		if source.ProviderAttemptID != providerAttemptID {
			return nil, sourceContractError("source records span multiple provider attempts")
		}
	}
	semantics, err := sourceSemanticsFromRecords(sources)
	if err != nil {
		return nil, err
	}
	expected, err := BuildProbeHTTPSourceRecords(programID, providerAttemptID, records, semantics)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(sources, expected) {
		return nil, sourceContractError("source records do not match platform-derived lineage")
	}
	derivations := make([]SourceDerivation, 0, len(sources))
	for _, source := range sources {
		record := records[source.AuthorizedRecordIndex]
		resource, err := ConcreteHTTPResource(record.Target)
		if err != nil {
			return nil, sourceContractError("source resource canonicalization failed")
		}
		semantics := RequestSemantics{Method: source.RequestMethod, ContentType: source.RequestContentType}
		key, effectiveMethod, effectiveContent, err := DeriveEndpointFromConcrete(resource, semantics)
		if err != nil {
			return nil, err
		}
		derivations = append(derivations, SourceDerivation{
			SourceLocator:               source.SourceLocator,
			IdentityNamespace:           source.IdentityNamespace,
			Endpoint:                    key,
			EffectiveMethod:             effectiveMethod,
			EffectiveRequestContentType: effectiveContent,
			DerivationVersion:           source.DerivationVersion,
		})
	}
	sort.Slice(derivations, func(i, j int) bool { return derivations[i].SourceLocator < derivations[j].SourceLocator })
	return derivations, nil
}

func CanonicalRecordJSON(record provideroutput.Record) ([]byte, error) {
	if strings.TrimSpace(record.Provider) == "" || record.Kind == "" || strings.TrimSpace(record.Target) == "" {
		return nil, fmt.Errorf("record identity is incomplete")
	}
	technologies := append([]string(nil), record.Technologies...)
	sort.Strings(technologies)
	technologies = dedupeStrings(technologies)
	fields := any(map[string]any{})
	if record.Fields != nil {
		fields = record.Fields
	}
	encodedFields, err := canonicalJSON(fields)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString(`{"provider":`)
	appendJSONString(&out, record.Provider)
	out.WriteString(`,"kind":`)
	appendJSONString(&out, string(record.Kind))
	out.WriteString(`,"target":`)
	appendJSONString(&out, record.Target)
	out.WriteString(`,"host":`)
	if record.Host == "" {
		out.WriteString("null")
	} else {
		appendJSONString(&out, record.Host)
	}
	out.WriteString(`,"port":`)
	if record.Port == 0 {
		out.WriteString("null")
	} else {
		out.WriteString(strconv.Itoa(record.Port))
	}
	out.WriteString(`,"status_code":`)
	if record.StatusCode == 0 {
		out.WriteString("null")
	} else {
		out.WriteString(strconv.Itoa(record.StatusCode))
	}
	out.WriteString(`,"technologies":[`)
	for index, technology := range technologies {
		if index > 0 {
			out.WriteByte(',')
		}
		appendJSONString(&out, technology)
	}
	out.WriteString(`],"fields":`)
	out.Write(encodedFields)
	out.WriteByte('}')
	return out.Bytes(), nil
}

func decodeRecords(raw json.RawMessage) ([]provideroutput.Record, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	var records []provideroutput.Record
	if err := decoder.Decode(&records); err != nil {
		return nil, sourceContractError("authorized records are malformed")
	}
	if err := ensureSingleJSONValue(decoder); err != nil {
		return nil, sourceContractError("authorized records are malformed")
	}
	if records == nil {
		return nil, sourceContractError("authorized records must be a non-null array")
	}
	return records, nil
}

func decodeSourceRecords(raw json.RawMessage) ([]AuthorizedSourceRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var records []AuthorizedSourceRecord
	if err := decoder.Decode(&records); err != nil {
		return nil, sourceContractError("source records are malformed")
	}
	if err := ensureSingleJSONValue(decoder); err != nil {
		return nil, sourceContractError("source records are malformed")
	}
	return records, nil
}

func sourceSemanticsFromRecords(sources []AuthorizedSourceRecord) (RequestSemantics, error) {
	if len(sources) == 0 {
		return RequestSemantics{Method: ValueSemantics{State: ValueDefaulted, Value: stringPointer("GET")}, ContentType: ValueSemantics{State: ValueUnknown}}, nil
	}
	semantics := RequestSemantics{Method: sources[0].RequestMethod, ContentType: sources[0].RequestContentType}
	if err := validateRequestSemantics(semantics, false); err != nil {
		return RequestSemantics{}, err
	}
	for _, source := range sources[1:] {
		if !reflect.DeepEqual(source.RequestMethod, semantics.Method) || !reflect.DeepEqual(source.RequestContentType, semantics.ContentType) {
			return RequestSemantics{}, sourceContractError("source records have inconsistent request semantics")
		}
	}
	return semantics, nil
}

func canonicalRequestSemanticsJSON(semantics RequestSemantics) ([]byte, error) {
	if err := validateRequestSemantics(semantics, false); err != nil {
		return nil, err
	}
	return json.Marshal(semantics)
}

func validateRequestSemantics(semantics RequestSemantics, allowDerivationDefault bool) error {
	if err := validateMethodSemantics(semantics.Method); err != nil {
		return err
	}
	if err := validateContentTypeSemantics(semantics.ContentType, allowDerivationDefault); err != nil {
		return err
	}
	return nil
}

func validateMethodSemantics(value ValueSemantics) error {
	switch value.State {
	case ValueKnown:
		if value.Value == nil || *value.Value == "" || *value.Value != strings.ToUpper(*value.Value) || !validHTTPMethod(*value.Value) {
			return sourceContractError("request method state/value is invalid")
		}
	case ValueDefaulted:
		if value.Value == nil || *value.Value != "GET" {
			return sourceContractError("defaulted request method must be GET")
		}
	case ValueUnknown:
		if value.Value != nil {
			return sourceContractError("unknown request method must be null")
		}
	default:
		return sourceContractError("request method state is invalid")
	}
	return nil
}

func validateContentTypeSemantics(value ValueSemantics, allowDerivationDefault bool) error {
	switch value.State {
	case ValueKnown:
		if value.Value == nil {
			return sourceContractError("known request content type must have a value")
		}
		canonical, err := normalizeRequestContentType(*value.Value)
		if err != nil || canonical != *value.Value {
			return sourceContractError("request content type state/value is invalid")
		}
	case ValueDefaulted:
		if !allowDerivationDefault || value.Value == nil || *value.Value != "" {
			return sourceContractError("defaulted request content type is invalid")
		}
	case ValueUnknown:
		if value.Value != nil {
			return sourceContractError("unknown request content type must be null")
		}
	default:
		return sourceContractError("request content type state is invalid")
	}
	return nil
}

func normalizeRequestContentType(raw string) (string, error) {
	if strings.ContainsAny(raw, "\r\n") {
		return "", fmt.Errorf("contains a line break")
	}
	return strings.ToLower(strings.TrimSpace(strings.Split(raw, ";")[0])), nil
}

func validHTTPMethod(method string) bool {
	if method == "" {
		return false
	}
	for _, character := range method {
		if !(character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", character)) {
			return false
		}
	}
	return true
}

func canonicalJSON(value any) ([]byte, error) {
	var out bytes.Buffer
	if err := appendCanonicalJSON(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func appendCanonicalJSON(out *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if value {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		appendJSONString(out, value)
	case json.Number:
		number, err := canonicalJSONNumber(value.String())
		if err != nil {
			return err
		}
		out.WriteString(number)
	case int:
		out.WriteString(strconv.Itoa(value))
	case int8:
		out.WriteString(strconv.FormatInt(int64(value), 10))
	case int16:
		out.WriteString(strconv.FormatInt(int64(value), 10))
	case int32:
		out.WriteString(strconv.FormatInt(int64(value), 10))
	case int64:
		out.WriteString(strconv.FormatInt(value, 10))
	case uint:
		out.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint8:
		out.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint16:
		out.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint32:
		out.WriteString(strconv.FormatUint(uint64(value), 10))
	case uint64:
		out.WriteString(strconv.FormatUint(value, 10))
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				out.WriteByte(',')
			}
			appendJSONString(out, key)
			out.WriteByte(':')
			if err := appendCanonicalJSON(out, value[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for index, item := range value {
			if index > 0 {
				out.WriteByte(',')
			}
			if err := appendCanonicalJSON(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case []string:
		out.WriteByte('[')
		for index, item := range value {
			if index > 0 {
				out.WriteByte(',')
			}
			appendJSONString(out, item)
		}
		out.WriteByte(']')
	case json.RawMessage:
		decoder := json.NewDecoder(bytes.NewReader(value))
		decoder.UseNumber()
		var decoded any
		if err := decoder.Decode(&decoded); err != nil || ensureSingleJSONValue(decoder) != nil {
			return fmt.Errorf("raw JSON is malformed")
		}
		return appendCanonicalJSON(out, decoded)
	case float32, float64:
		return fmt.Errorf("floating-point values are unsupported; decode JSON with UseNumber")
	default:
		return fmt.Errorf("unsupported JSON value type %T", value)
	}
	return nil
}

func canonicalJSONNumber(raw string) (string, error) {
	if raw == "" || len(raw) > 4096 {
		return "", fmt.Errorf("invalid JSON number")
	}
	index := 0
	negative := false
	if raw[index] == '-' {
		negative = true
		index++
		if index == len(raw) {
			return "", fmt.Errorf("invalid JSON number")
		}
	}
	integerStart := index
	if raw[index] == '0' {
		index++
		if index < len(raw) && raw[index] >= '0' && raw[index] <= '9' {
			return "", fmt.Errorf("invalid JSON number")
		}
	} else if raw[index] >= '1' && raw[index] <= '9' {
		for index < len(raw) && raw[index] >= '0' && raw[index] <= '9' {
			index++
		}
	} else {
		return "", fmt.Errorf("invalid JSON number")
	}
	digits := raw[integerStart:index]
	fractionLength := 0
	if index < len(raw) && raw[index] == '.' {
		index++
		fractionStart := index
		for index < len(raw) && raw[index] >= '0' && raw[index] <= '9' {
			index++
		}
		if fractionStart == index {
			return "", fmt.Errorf("invalid JSON number")
		}
		digits += raw[fractionStart:index]
		fractionLength = index - fractionStart
	}
	exponent := 0
	if index < len(raw) && (raw[index] == 'e' || raw[index] == 'E') {
		index++
		sign := 1
		if index < len(raw) && (raw[index] == '+' || raw[index] == '-') {
			if raw[index] == '-' {
				sign = -1
			}
			index++
		}
		exponentStart := index
		for index < len(raw) && raw[index] >= '0' && raw[index] <= '9' {
			index++
		}
		if exponentStart == index {
			return "", fmt.Errorf("invalid JSON number")
		}
		parsed, err := strconv.Atoi(raw[exponentStart:index])
		if err != nil || parsed > 4096 {
			return "", fmt.Errorf("JSON number exponent is unsupported")
		}
		exponent = sign * parsed
	}
	if index != len(raw) {
		return "", fmt.Errorf("invalid JSON number")
	}
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0", nil
	}
	scale := exponent - fractionLength
	for strings.HasSuffix(digits, "0") {
		digits = strings.TrimSuffix(digits, "0")
		scale++
	}
	if len(digits)+abs(scale)+4 > 4096 {
		return "", fmt.Errorf("JSON number is too large")
	}
	value := ""
	if scale >= 0 {
		value = digits + strings.Repeat("0", scale)
	} else if point := len(digits) + scale; point > 0 {
		value = digits[:point] + "." + digits[point:]
	} else {
		value = "0." + strings.Repeat("0", -point) + digits
	}
	if negative {
		value = "-" + value
	}
	return value, nil
}

func ensureSingleJSONValue(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("contains multiple JSON values")
}

func appendJSONString(out *bytes.Buffer, value string) {
	encoded, _ := json.Marshal(value)
	out.Write(encoded)
}

func digestHex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func dedupeStrings(items []string) []string {
	if len(items) < 2 {
		return items
	}
	out := items[:1]
	for _, item := range items[1:] {
		if item != out[len(out)-1] {
			out = append(out, item)
		}
	}
	return out
}

func stringPointer(value string) *string { return &value }

func sourceContractError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrProbeHTTPSourceContract}, args...)...)
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
