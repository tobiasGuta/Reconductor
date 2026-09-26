package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
)

const (
	PreparedManifestVersionV1 = "prepared-evidence-manifest/v1"
	PreparedControlVersionV1  = "prepared-evidence-control/v1"
	PreparedManifestMaxBytes  = 8_192
	PreparedControlMaxBytes   = 128 * 1_024
)

type PreparedEvidenceState string

const (
	PreparedAllocated         PreparedEvidenceState = "ALLOCATED"
	PreparedSealed            PreparedEvidenceState = "SEALED"
	PreparedResolvedAdopted   PreparedEvidenceState = "RESOLVED_ADOPTED"
	PreparedResolvedAbandoned PreparedEvidenceState = "RESOLVED_ABANDONED"
	PreparedQuarantined       PreparedEvidenceState = "QUARANTINED"
	PreparedCleaned           PreparedEvidenceState = "CLEANED"
)

func (s PreparedEvidenceState) Validate() error {
	switch s {
	case PreparedAllocated, PreparedSealed, PreparedResolvedAdopted, PreparedResolvedAbandoned, PreparedQuarantined, PreparedCleaned:
		return nil
	default:
		return fmt.Errorf("invalid prepared evidence state %q", s)
	}
}

type PreparedSetRecord struct {
	ID                      ID
	ManifestID              ID
	ProviderAttemptID       *ID
	FailureFinalizationID   *ID
	ProgramID               ID
	TaskID                  ID
	WorkflowRunID           ID
	StepRunID               ID
	ActionRequestID         ID
	StepAttempt             int
	ArtifactStoreID         ID
	StoreIncarnationNonce   ID
	State                   PreparedEvidenceState
	ReservedCapacityBytes   int64
	ResultOccurrenceID      *ID
	ProviderTerminalEventID *ID
	ManifestStorageKey      *string
	ManifestSizeBytes       *int64
	ManifestSHA256          *string
	MemberCount             *int
	ContentSizeBytes        *int64
	QuarantineReasonCode    *string
	NonadmissionDetails     json.RawMessage
}

type PreparedOwnerKind string

const (
	PreparedOwnerProviderAttempt     PreparedOwnerKind = "provider_attempt"
	PreparedOwnerFailureFinalization PreparedOwnerKind = "failure_finalization"
)

type PreparedObjectRefV1 struct {
	StorageKey       string `json:"storage_key"`
	ContentSizeBytes int64  `json:"content_size_bytes"`
	ContentSHA256    string `json:"content_sha256"`
}

type PreparedMemberV1 struct {
	Ordinal          int                  `json:"ordinal"`
	PublicationID    ID                   `json:"publication_id"`
	ArtifactID       ID                   `json:"artifact_id"`
	PreparedKey      string               `json:"prepared_key"`
	FinalKey         string               `json:"final_key"`
	Role             ResultArtifactRoleV1 `json:"role"`
	ContentType      string               `json:"content_type"`
	ArtifactType     string               `json:"artifact_type"`
	ContentSizeBytes int64                `json:"content_size_bytes"`
	ContentSHA256    string               `json:"content_sha256"`
}

type PreparedManifestV1 struct {
	Version                     string              `json:"version"`
	SetID                       ID                  `json:"set_id"`
	ManifestID                  ID                  `json:"manifest_id"`
	ArtifactStoreID             ID                  `json:"artifact_store_id"`
	StoreIncarnationNonce       ID                  `json:"store_incarnation_nonce"`
	StoreBackendKind            string              `json:"store_backend_kind"`
	StoreMarkerFormat           string              `json:"store_marker_format"`
	StoreMarkerVersion          int                 `json:"store_marker_version"`
	ProviderAttemptID           *ID                 `json:"provider_attempt_id,omitempty"`
	FailureFinalizationRecordID *ID                 `json:"failure_finalization_record_id,omitempty"`
	ResultOccurrenceID          ID                  `json:"result_occurrence_id"`
	Control                     PreparedObjectRefV1 `json:"control"`
	Members                     []PreparedMemberV1  `json:"members"`
}

type PreparedAdmissionV1 struct {
	ProviderAttemptID             ID     `json:"provider_attempt_id"`
	PreparedSetID                 ID     `json:"prepared_set_id"`
	ActionRequestID               ID     `json:"action_request_id"`
	StepAttempt                   int    `json:"step_attempt"`
	QueueJobID                    *ID    `json:"queue_job_id,omitempty"`
	ExecutionAuthorizationEventID ID     `json:"execution_authorization_event_id"`
	Provider                      string `json:"provider"`
}

type PreparedStepV1 struct {
	ID                  ID                     `json:"id"`
	WorkflowRunID       ID                     `json:"workflow_run_id"`
	Capability          string                 `json:"capability"`
	Status              ResultEnvelopeStatusV1 `json:"status"`
	ErrorClassification string                 `json:"error_classification,omitempty"`
	ErrorDetails        string                 `json:"error_details,omitempty"`
	CompletedAt         *time.Time             `json:"completed_at,omitempty"`
	IdempotencyKey      string                 `json:"idempotency_key"`
}

type PreparedControlV1 struct {
	Version                 string                  `json:"version"`
	SetID                   ID                      `json:"set_id"`
	ManifestID              ID                      `json:"manifest_id"`
	ProviderTerminalEventID ID                      `json:"provider_terminal_event_id"`
	AcceptedEventID         ID                      `json:"accepted_event_id"`
	ProviderOutcome         ResultProviderOutcomeV1 `json:"provider_outcome"`
	Envelope                ResultEnvelopeV1        `json:"envelope"`
	EnvelopeSHA256          string                  `json:"envelope_sha256"`
	ToolRun                 ToolRun                 `json:"tool_run"`
	Step                    PreparedStepV1          `json:"step"`
	Admission               PreparedAdmissionV1     `json:"admission"`
	ArtifactRetentionNanos  int64                   `json:"artifact_retention_nanos"`
}

var preparedSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func PreparedSetPrefix(setID ID) (string, error) {
	value := string(setID)
	if _, err := ParseID(value); err != nil {
		return "", fmt.Errorf("prepared set identity is not canonical")
	}
	return "prepared/v1/" + value[:2] + "/" + value, nil
}

func PreparedControlKey(setID ID) (string, error) {
	prefix, err := PreparedSetPrefix(setID)
	if err != nil {
		return "", err
	}
	return prefix + "/control.json", nil
}

func PreparedManifestKey(setID ID) (string, error) {
	prefix, err := PreparedSetPrefix(setID)
	if err != nil {
		return "", err
	}
	return prefix + "/manifest.json", nil
}

func PreparedMemberKey(setID ID, ordinal int) (string, error) {
	if ordinal < 0 || ordinal >= ResultArtifactReferenceMaxCount {
		return "", fmt.Errorf("prepared member ordinal is outside bounded set")
	}
	prefix, err := PreparedSetPrefix(setID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/member-%04d", prefix, ordinal), nil
}

func (m PreparedManifestV1) Validate() error {
	if m.Version != PreparedManifestVersionV1 {
		return fmt.Errorf("unsupported prepared manifest version")
	}
	for name, id := range map[string]ID{"set": m.SetID, "manifest": m.ManifestID, "artifact store": m.ArtifactStoreID, "store incarnation": m.StoreIncarnationNonce, "result occurrence": m.ResultOccurrenceID} {
		if _, err := ParseID(string(id)); err != nil {
			return fmt.Errorf("%s identity is not canonical", name)
		}
	}
	providerOwned := m.ProviderAttemptID != nil && *m.ProviderAttemptID != "" && m.FailureFinalizationRecordID == nil
	failureOwned := m.FailureFinalizationRecordID != nil && *m.FailureFinalizationRecordID != "" && m.ProviderAttemptID == nil
	if !providerOwned && !failureOwned {
		return fmt.Errorf("prepared manifest requires exactly one durable owner")
	}
	owner := m.ProviderAttemptID
	if failureOwned {
		owner = m.FailureFinalizationRecordID
	}
	if _, err := ParseID(string(*owner)); err != nil {
		return fmt.Errorf("prepared owner identity is not canonical")
	}
	if m.StoreBackendKind != "local-v1" || m.StoreMarkerFormat != "reconductor-artifact-store" || m.StoreMarkerVersion != 1 {
		return fmt.Errorf("prepared manifest store identity is unsupported")
	}
	controlKey, _ := PreparedControlKey(m.SetID)
	if m.Control.StorageKey != controlKey || m.Control.ContentSizeBytes < 1 || m.Control.ContentSizeBytes > PreparedControlMaxBytes || !preparedSHA256Pattern.MatchString(m.Control.ContentSHA256) {
		return fmt.Errorf("prepared control descriptor is invalid")
	}
	if len(m.Members) < 1 || len(m.Members) > ResultArtifactReferenceMaxCount {
		return fmt.Errorf("prepared manifest member count is outside bounds")
	}
	ids, publications, keys, roles := map[ID]bool{}, map[ID]bool{}, map[string]bool{}, map[ResultArtifactRoleV1]bool{}
	for ordinal, member := range m.Members {
		if member.Ordinal != ordinal {
			return fmt.Errorf("prepared members are not contiguous and ordered")
		}
		if _, err := ParseID(string(member.PublicationID)); err != nil {
			return fmt.Errorf("prepared publication identity is not canonical")
		}
		if _, err := ParseID(string(member.ArtifactID)); err != nil {
			return fmt.Errorf("prepared artifact identity is not canonical")
		}
		preparedKey, _ := PreparedMemberKey(m.SetID, ordinal)
		artifactValue := string(member.ArtifactID)
		finalKey := "v1/" + artifactValue[:2] + "/" + artifactValue
		if member.PreparedKey != preparedKey || member.FinalKey != finalKey {
			return fmt.Errorf("prepared member storage identity is not canonical")
		}
		if ids[member.ArtifactID] || publications[member.PublicationID] || keys[member.PreparedKey] || roles[member.Role] {
			return fmt.Errorf("prepared manifest contains duplicate member identity")
		}
		ids[member.ArtifactID], publications[member.PublicationID], keys[member.PreparedKey], roles[member.Role] = true, true, true, true
		if member.ContentSizeBytes < 0 || !preparedSHA256Pattern.MatchString(member.ContentSHA256) || len(member.ContentType) < 1 || len(member.ContentType) > 255 || len(member.ArtifactType) < 1 || len(member.ArtifactType) > 64 {
			return fmt.Errorf("prepared member metadata is invalid")
		}
		if err := validatePreparedString("content type", member.ContentType, 255); err != nil {
			return err
		}
		if err := validatePreparedString("artifact type", member.ArtifactType, 64); err != nil {
			return err
		}
		if err := (ResultArtifactRefV1{ArtifactID: member.ArtifactID, ArtifactStoreID: m.ArtifactStoreID, StorageKey: member.FinalKey, Role: member.Role, ContentType: member.ContentType, ContentSizeBytes: member.ContentSizeBytes, ContentSHA256: member.ContentSHA256}).Validate(); err != nil {
			return fmt.Errorf("prepared member result reference is invalid: %w", err)
		}
	}
	if !roles[ArtifactRoleSemanticResult] {
		return fmt.Errorf("prepared manifest lacks semantic result member")
	}
	return nil
}

func (m PreparedManifestV1) CanonicalJSON() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	_, canonical, _, _, err := canonicaljson.ParseStrict(encoded)
	if err != nil {
		return nil, err
	}
	if len(canonical) > PreparedManifestMaxBytes {
		return nil, fmt.Errorf("prepared manifest exceeds %d bytes", PreparedManifestMaxBytes)
	}
	return canonical, nil
}

func DecodePreparedManifestV1(raw []byte) (PreparedManifestV1, error) {
	if len(raw) > PreparedManifestMaxBytes {
		return PreparedManifestV1{}, fmt.Errorf("prepared manifest exceeds %d bytes", PreparedManifestMaxBytes)
	}
	_, canonical, _, _, err := canonicaljson.ParseStrict(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return PreparedManifestV1{}, fmt.Errorf("prepared manifest is not canonical: %w", err)
	}
	var manifest PreparedManifestV1
	if err := rejectUnknownPreparedFields(canonical, reflect.TypeOf(manifest)); err != nil {
		return manifest, err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return PreparedManifestV1{}, err
	}
	return manifest, manifest.Validate()
}

func (c PreparedControlV1) Validate() error {
	if c.Version != PreparedControlVersionV1 {
		return fmt.Errorf("unsupported prepared control version")
	}
	for name, id := range map[string]ID{"set": c.SetID, "manifest": c.ManifestID, "provider terminal event": c.ProviderTerminalEventID, "accepted event": c.AcceptedEventID, "provider attempt": c.Admission.ProviderAttemptID, "action request": c.Admission.ActionRequestID, "execution authorization": c.Admission.ExecutionAuthorizationEventID} {
		if _, err := ParseID(string(id)); err != nil {
			return fmt.Errorf("%s identity is not canonical", name)
		}
	}
	if c.Admission.PreparedSetID != c.SetID || c.Admission.StepAttempt < 1 || int64(c.Admission.StepAttempt) > 2147483647 || c.Admission.Provider == "" {
		return fmt.Errorf("prepared admission provenance is invalid")
	}
	if err := validatePreparedString("prepared provider", c.Admission.Provider, DiagnosticMaxBytes); err != nil {
		return err
	}
	if c.Admission.QueueJobID != nil {
		if _, err := ParseID(string(*c.Admission.QueueJobID)); err != nil {
			return fmt.Errorf("prepared queue job identity is not canonical")
		}
	}
	if err := c.Envelope.Validate(); err != nil {
		return fmt.Errorf("prepared control envelope is invalid: %w", err)
	}
	digest, err := EnvelopeDigest(c.Envelope)
	if err != nil || digest != c.EnvelopeSHA256 || !preparedSHA256Pattern.MatchString(c.EnvelopeSHA256) {
		return fmt.Errorf("prepared control envelope digest mismatch")
	}
	if c.Envelope.ResultOccurrenceID == "" || c.Envelope.ProviderAttemptID != c.Admission.ProviderAttemptID || c.Envelope.ActionRequestID != c.Admission.ActionRequestID || c.Envelope.ProviderOutcome != c.ProviderOutcome {
		return fmt.Errorf("prepared control envelope provenance mismatch")
	}
	if c.ToolRun.ID == "" || c.ToolRun.StepRunID != c.Step.ID || c.ToolRun.ProviderAttemptID == nil || *c.ToolRun.ProviderAttemptID != c.Admission.ProviderAttemptID || c.ToolRun.Provider != c.Admission.Provider {
		return fmt.Errorf("prepared control ToolRun provenance mismatch")
	}
	for _, id := range []ID{c.ToolRun.ID, c.ToolRun.StepRunID, c.Step.ID, c.Step.WorkflowRunID} {
		if _, err := ParseID(string(id)); err != nil {
			return fmt.Errorf("prepared control lineage identity is not canonical")
		}
	}
	for _, id := range []*ID{c.ToolRun.StdoutArtifactID, c.ToolRun.StderrArtifactID} {
		if id != nil {
			if _, err := ParseID(string(*id)); err != nil {
				return fmt.Errorf("prepared tool stream identity is not canonical")
			}
		}
	}
	if c.ToolRun.Capability != c.Envelope.CapabilityName || len(c.ToolRun.ArtifactIDs) != len(c.Envelope.Artifacts) {
		return fmt.Errorf("prepared control ToolRun result mismatch")
	}
	if err := ValidateUTF8Bytes("prepared tool capability", c.ToolRun.Capability, 128); err != nil {
		return err
	}
	if err := validatePreparedString("prepared tool version", c.ToolRun.ToolVersion, DiagnosticMaxBytes); err != nil {
		return err
	}
	if err := validatePreparedJSON("prepared sanitized arguments", c.ToolRun.SanitizedArguments); err != nil {
		return err
	}
	if err := validatePreparedJSON("prepared execution environment", c.ToolRun.ExecutionEnvironment); err != nil {
		return err
	}
	for ordinal, reference := range c.Envelope.Artifacts {
		if c.ToolRun.ArtifactIDs[ordinal] != reference.ArtifactID {
			return fmt.Errorf("prepared control ToolRun artifact identity mismatch")
		}
	}
	if c.Step.ID == "" || c.Step.WorkflowRunID == "" || c.Step.Capability != c.Envelope.CapabilityName || c.Step.Status != c.Envelope.Status {
		return fmt.Errorf("prepared control step is invalid")
	}
	if err := ValidateUTF8Bytes("prepared step error classification", c.Step.ErrorClassification, 64); err != nil {
		return err
	}
	if err := ValidateUTF8Bytes("prepared step error details", c.Step.ErrorDetails, SafeMessageMaxBytes); err != nil {
		return err
	}
	if err := validatePreparedString("prepared idempotency key", c.Step.IdempotencyKey, DiagnosticMaxBytes); err != nil {
		return err
	}
	if c.ArtifactRetentionNanos < 0 {
		return fmt.Errorf("prepared control artifact retention is invalid")
	}
	return nil
}

func validatePreparedJSON(name string, raw json.RawMessage) error {
	if len(raw) < 1 || len(raw) > DiagnosticMaxBytes || !json.Valid(raw) {
		return fmt.Errorf("%s is not bounded valid JSON", name)
	}
	_, canonical, _, _, err := canonicaljson.ParseStrict(raw)
	if err != nil || len(canonical) > DiagnosticMaxBytes {
		return fmt.Errorf("%s exceeds canonical JSON bound", name)
	}
	return nil
}

// These are encoded field budgets, not raw UTF-8 budgets. They prevent
// simultaneous escaping expansion from exceeding the frozen document ceiling.
func validatePreparedString(name, value string, max int) error {
	if err := ValidateUTF8Bytes(name, value, max); err != nil {
		return err
	}
	encoded, err := canonicaljson.Marshal(value)
	if err != nil || len(encoded) > max+2 {
		return fmt.Errorf("%s exceeds encoded prepared field bound", name)
	}
	return nil
}

func rejectUnknownPreparedFields(raw []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		if bytes.Equal(raw, []byte("null")) {
			return nil
		}
		typ = typ.Elem()
	}
	if typ == reflect.TypeOf(json.RawMessage{}) || typ == reflect.TypeOf(time.Time{}) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}
		allowed := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" || field.PkgPath != "" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			allowed[name] = field.Type
		}
		for name, value := range fields {
			fieldType, ok := allowed[name]
			if !ok {
				return fmt.Errorf("unknown prepared field %q", name)
			}
			if err := rejectUnknownPreparedFields(value, fieldType); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		for _, item := range items {
			if err := rejectUnknownPreparedFields(item, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c PreparedControlV1) CanonicalJSON() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	_, canonical, _, _, err := canonicaljson.ParseStrict(encoded)
	if err != nil {
		return nil, err
	}
	if len(canonical) > PreparedControlMaxBytes {
		return nil, fmt.Errorf("prepared control exceeds %d bytes", PreparedControlMaxBytes)
	}
	return canonical, nil
}

func DecodePreparedControlV1(raw []byte) (PreparedControlV1, error) {
	if len(raw) > PreparedControlMaxBytes {
		return PreparedControlV1{}, fmt.Errorf("prepared control exceeds %d bytes", PreparedControlMaxBytes)
	}
	_, canonical, _, _, err := canonicaljson.ParseStrict(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return PreparedControlV1{}, fmt.Errorf("prepared control is not canonical: %w", err)
	}
	var control PreparedControlV1
	if err := rejectUnknownPreparedFields(canonical, reflect.TypeOf(control)); err != nil {
		return control, err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&control); err != nil {
		return PreparedControlV1{}, err
	}
	return control, control.Validate()
}
