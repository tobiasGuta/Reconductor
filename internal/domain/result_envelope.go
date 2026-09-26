package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
)

const (
	ResultEnvelopeVersionV1           = "result-envelope/v1"
	ResultEnvelopeMaxBytes            = 65_536
	InlineSemanticJSONMaxBytes        = 16_384
	InlineSemanticJSONMaxNodes        = 4_096
	SemanticJSONMaxDepth              = 64
	ResultArtifactReferenceMaxCount   = 4
	ResultSummaryReferenceVersionV1   = "result-summary-reference/v1"
	SemanticBindingReferenceVersionV1 = "semantic-binding-reference/v1"
	SemanticBindingReferenceSchemaV1  = "urn:reconductor:schema:semantic-binding-reference:v1"
	SemanticOutputVersionV1           = "semantic-output/v1"
	CanonicalJSONVersionV1            = "reconductor-canonical-json/v1"
	DiagnosticEvidenceContentTypeV1   = "application/vnd.reconductor.provider-diagnostic-v1"
)

type ResultEnvelopeStatusV1 string
type ResultProviderOutcomeV1 string
type SemanticOutputModeV1 string
type SemanticCompletenessV1 string
type SemanticProjectionStateV1 string
type ResultArtifactRoleV1 string
type ResultContractLimitSubjectV1 string
type ResultContractLimitUnitV1 string

const (
	ResultStatusSucceeded ResultEnvelopeStatusV1 = "succeeded"
	ResultStatusFailed    ResultEnvelopeStatusV1 = "failed"
	ResultStatusRetryable ResultEnvelopeStatusV1 = "retryable"
	ResultStatusCancelled ResultEnvelopeStatusV1 = "cancelled"

	ResultProviderSucceeded ResultProviderOutcomeV1 = "succeeded"
	ResultProviderFailed    ResultProviderOutcomeV1 = "failed"
	ResultProviderTimeout   ResultProviderOutcomeV1 = "timeout"
	ResultProviderCancelled ResultProviderOutcomeV1 = "cancelled"

	SemanticModeNone         SemanticOutputModeV1      = "none"
	SemanticModeInlineJSON   SemanticOutputModeV1      = "inline_json"
	SemanticModeArtifactJSON SemanticOutputModeV1      = "artifact_json"
	SemanticComplete         SemanticCompletenessV1    = "complete"
	SemanticNotProduced      SemanticCompletenessV1    = "not_produced"
	ProjectionComplete       SemanticProjectionStateV1 = "complete"
	ProjectionNotRequired    SemanticProjectionStateV1 = "not_required"
	ProjectionRejected       SemanticProjectionStateV1 = "rejected"

	ArtifactRoleProviderStdout     ResultArtifactRoleV1 = "provider_stdout"
	ArtifactRoleProviderStderr     ResultArtifactRoleV1 = "provider_stderr"
	ArtifactRoleProviderDiagnostic ResultArtifactRoleV1 = "provider_diagnostic"
	ArtifactRoleSemanticResult     ResultArtifactRoleV1 = "semantic_result"

	LimitSemanticOutput        ResultContractLimitSubjectV1 = "semantic_output"
	LimitBindingSelectedValue  ResultContractLimitSubjectV1 = "binding_selected_value"
	LimitBindingEffectiveInput ResultContractLimitSubjectV1 = "binding_effective_input"
	LimitProjectionItem        ResultContractLimitSubjectV1 = "projection_item"
	LimitPreparedEvidence      ResultContractLimitSubjectV1 = "prepared_evidence"
	LimitBytes                 ResultContractLimitUnitV1    = "bytes"
	LimitItems                 ResultContractLimitUnitV1    = "items"
	LimitDepth                 ResultContractLimitUnitV1    = "depth"
)

type ResultEnvelopeV1 struct {
	Version             string                  `json:"version"`
	ActionRequestID     ID                      `json:"action_request_id"`
	ResultOccurrenceID  ID                      `json:"result_occurrence_id"`
	ProviderAttemptID   ID                      `json:"provider_attempt_id"`
	CapabilityName      string                  `json:"capability_name"`
	CapabilityVersion   string                  `json:"capability_version"`
	Status              ResultEnvelopeStatusV1  `json:"status"`
	ProviderOutcome     ResultProviderOutcomeV1 `json:"provider_outcome"`
	Summary             string                  `json:"summary"`
	PublicationComplete bool                    `json:"publication_complete"`
	SemanticOutput      SemanticOutputV1        `json:"semantic_output"`
	Artifacts           []ResultArtifactRefV1   `json:"artifacts"`
	Error               *ResultErrorV1          `json:"error,omitempty"`
}

type SemanticOutputV1 struct {
	Version            string                    `json:"version"`
	Mode               SemanticOutputModeV1      `json:"mode"`
	Completeness       SemanticCompletenessV1    `json:"completeness"`
	Canonicalization   string                    `json:"canonicalization"`
	ArtifactID         ID                        `json:"artifact_id"`
	ContentSHA256      string                    `json:"content_sha256"`
	ContentSizeBytes   int64                     `json:"content_size_bytes"`
	OutputSchemaSHA256 string                    `json:"output_schema_sha256"`
	NodeCount          uint64                    `json:"node_count"`
	MaximumDepth       uint64                    `json:"maximum_depth"`
	ProjectionState    SemanticProjectionStateV1 `json:"projection_state"`
	InlineJSON         json.RawMessage           `json:"inline_json,omitempty"`
}

type ResultArtifactRefV1 struct {
	ArtifactID       ID                   `json:"artifact_id"`
	ArtifactStoreID  ID                   `json:"artifact_store_id"`
	StorageKey       string               `json:"storage_key"`
	Role             ResultArtifactRoleV1 `json:"role"`
	ContentType      string               `json:"content_type"`
	ContentSizeBytes int64                `json:"content_size_bytes"`
	ContentSHA256    string               `json:"content_sha256"`
}

type ResultErrorV1 struct {
	Code                 string                 `json:"code"`
	Message              string                 `json:"message"`
	Retryable            bool                   `json:"retryable"`
	DiagnosticArtifactID *ID                    `json:"diagnostic_artifact_id,omitempty"`
	Limit                *ResultContractLimitV1 `json:"limit,omitempty"`
}

type ResultContractLimitV1 struct {
	Subject  ResultContractLimitSubjectV1 `json:"subject"`
	Unit     ResultContractLimitUnitV1    `json:"unit"`
	Limit    uint64                       `json:"limit"`
	Observed uint64                       `json:"observed"`
}

type SemanticBindingReferenceV1 struct {
	SchemaID                 string `json:"schema_id"`
	Version                  string `json:"version"`
	SourceProgramID          ID     `json:"source_program_id"`
	SourceWorkflowRunID      ID     `json:"source_workflow_run_id"`
	SourceStepRunID          ID     `json:"source_step_run_id"`
	SourceActionRequestID    ID     `json:"source_action_request_id"`
	SourceResultOccurrenceID ID     `json:"source_result_occurrence_id"`
	SourceProviderAttemptID  ID     `json:"source_provider_attempt_id"`
	SourceArtifactID         ID     `json:"source_artifact_id"`
	ArtifactStoreID          ID     `json:"artifact_store_id"`
	StorageKey               string `json:"storage_key"`
	Selector                 string `json:"selector"`
	ContentSHA256            string `json:"content_sha256"`
	ContentSizeBytes         int64  `json:"content_size_bytes"`
	OutputSchemaSHA256       string `json:"output_schema_sha256"`
}

type SemanticBindingResolutionV1 struct {
	ConsumerProgramID      ID
	ConsumerWorkflowRunID  ID
	ConsumerStepDefinition string
	SourceStepDefinition   string
	Reference              SemanticBindingReferenceV1
}

type ResultSummaryReferenceV1 struct {
	Version            string `json:"version"`
	SourceStepRunID    ID     `json:"source_step_run_id"`
	ActionRequestID    ID     `json:"action_request_id"`
	ResultOccurrenceID ID     `json:"result_occurrence_id"`
	SemanticArtifactID ID     `json:"semantic_artifact_id"`
	SemanticSHA256     string `json:"semantic_sha256"`
	SemanticSizeBytes  int64  `json:"semantic_size_bytes"`
	SafeSummary        string `json:"safe_summary"`
}

type ResultAuditProjectionV1 struct {
	Version            int                    `json:"version"`
	ActionRequestID    ID                     `json:"action_request_id"`
	ResultOccurrenceID ID                     `json:"result_occurrence_id"`
	ProviderAttemptID  ID                     `json:"provider_attempt_id"`
	Status             ResultEnvelopeStatusV1 `json:"status"`
	SemanticMode       SemanticOutputModeV1   `json:"semantic_mode"`
	SemanticArtifactID ID                     `json:"semantic_artifact_id"`
	ArtifactCount      int                    `json:"artifact_count"`
	EnvelopeSHA256     string                 `json:"envelope_sha256"`
}

type QueueResultV1 struct {
	Version         string `json:"version"`
	ActionRequestID ID     `json:"action_request_id"`
	Status          string `json:"status"`
	Summary         string `json:"summary"`
}

var resultCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func DecodeResultEnvelopeV1(raw []byte) (ResultEnvelopeV1, error) {
	var envelope ResultEnvelopeV1
	if err := decodeStrictObject(raw, &envelope); err != nil {
		return envelope, err
	}
	if err := envelope.Validate(); err != nil {
		return ResultEnvelopeV1{}, err
	}
	return envelope, nil
}

func (e ResultEnvelopeV1) CanonicalJSON() ([]byte, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	canonical, err := canonicaljson.Marshal(json.RawMessage(raw))
	if err != nil {
		return nil, err
	}
	if len(canonical) > ResultEnvelopeMaxBytes {
		return nil, fmt.Errorf("result envelope exceeds %d bytes", ResultEnvelopeMaxBytes)
	}
	return canonical, nil
}

func (e ResultEnvelopeV1) Validate() error {
	if e.Version != ResultEnvelopeVersionV1 {
		return fmt.Errorf("unsupported result envelope version %q", e.Version)
	}
	for name, id := range map[string]ID{"action request": e.ActionRequestID, "result occurrence": e.ResultOccurrenceID, "provider attempt": e.ProviderAttemptID} {
		if err := validateResultID(name, id); err != nil {
			return err
		}
	}
	if err := ValidateUTF8Bytes("capability name", e.CapabilityName, 128); err != nil || e.CapabilityName == "" {
		return fmt.Errorf("invalid capability name")
	}
	if err := ValidateUTF8Bytes("capability version", e.CapabilityVersion, 64); err != nil || e.CapabilityVersion == "" {
		return fmt.Errorf("invalid capability version")
	}
	if err := ValidateUTF8Bytes("result summary", e.Summary, SafeMessageMaxBytes); err != nil {
		return err
	}
	if !e.PublicationComplete {
		return fmt.Errorf("persisted result envelope publication is incomplete")
	}
	if err := e.validateStatus(); err != nil {
		return err
	}
	if err := e.SemanticOutput.Validate(); err != nil {
		return err
	}
	if len(e.Artifacts) < 1 || len(e.Artifacts) > ResultArtifactReferenceMaxCount {
		return fmt.Errorf("invalid result artifact count")
	}
	seenIDs, seenRoles, seenKeys := map[ID]bool{}, map[ResultArtifactRoleV1]bool{}, map[string]bool{}
	lastRank := 0
	for i, a := range e.Artifacts {
		if err := a.Validate(); err != nil {
			return fmt.Errorf("artifact %d: %w", i, err)
		}
		rank := artifactRoleRank(a.Role)
		if rank <= lastRank {
			return fmt.Errorf("artifact roles are not in closed order")
		}
		lastRank = rank
		if seenIDs[a.ArtifactID] || seenRoles[a.Role] || seenKeys[string(a.ArtifactStoreID)+"\x00"+a.StorageKey] {
			return fmt.Errorf("duplicate result artifact identity")
		}
		seenIDs[a.ArtifactID] = true
		seenRoles[a.Role] = true
		seenKeys[string(a.ArtifactStoreID)+"\x00"+a.StorageKey] = true
	}
	if !seenRoles[ArtifactRoleSemanticResult] {
		return fmt.Errorf("semantic_result artifact is required")
	}
	if e.SemanticOutput.ArtifactID != semanticArtifactID(e.Artifacts) {
		return fmt.Errorf("semantic output artifact identity mismatch")
	}
	diagnosticID := artifactIDForRole(e.Artifacts, ArtifactRoleProviderDiagnostic)
	if diagnosticID == "" {
		if e.Error != nil && e.Error.DiagnosticArtifactID != nil {
			return fmt.Errorf("diagnostic artifact reference is absent")
		}
	} else if e.Error == nil || e.Error.DiagnosticArtifactID == nil || *e.Error.DiagnosticArtifactID != diagnosticID {
		return fmt.Errorf("diagnostic artifact ID mismatch")
	}
	_, err := e.CanonicalJSON()
	return err
}

func (e ResultEnvelopeV1) validateStatus() error {
	validOutcome := e.ProviderOutcome == ResultProviderSucceeded || e.ProviderOutcome == ResultProviderFailed || e.ProviderOutcome == ResultProviderTimeout || e.ProviderOutcome == ResultProviderCancelled
	if !validOutcome {
		return fmt.Errorf("invalid provider outcome %q", e.ProviderOutcome)
	}
	if e.Status == ResultStatusSucceeded {
		return require(e.ProviderOutcome == ResultProviderSucceeded && e.Error == nil, "succeeded result matrix mismatch")
	}
	if e.Error == nil {
		return fmt.Errorf("nonsuccess result requires error")
	}
	if !resultCodePattern.MatchString(e.Error.Code) || !utf8.ValidString(e.Error.Message) || len(e.Error.Message) < 1 || len(e.Error.Message) > SafeMessageMaxBytes {
		return fmt.Errorf("invalid bounded result error")
	}
	if (e.Error.Code == "result_contract_limit") != (e.Error.Limit != nil) {
		return fmt.Errorf("result contract limit shape mismatch")
	}
	if e.Error.Limit != nil {
		if err := e.Error.Limit.Validate(); err != nil {
			return err
		}
	}
	if e.Error.Code == "result_contract_limit" {
		return require(e.Status == ResultStatusFailed && !e.Error.Retryable, "post-provider result contract limit matrix mismatch")
	}
	switch e.Status {
	case ResultStatusFailed:
		if e.Error.Retryable {
			return fmt.Errorf("failed result cannot be retryable")
		}
		if e.ProviderOutcome == ResultProviderSucceeded || e.ProviderOutcome == ResultProviderCancelled {
			return fmt.Errorf("failed result provider outcome mismatch")
		}
		if e.Error.Code == "provider_contract_invalid" && e.ProviderOutcome != ResultProviderFailed {
			return fmt.Errorf("invalid provider output must have failed provider outcome")
		}
		return nil
	case ResultStatusRetryable:
		return require(e.Error.Retryable && (e.ProviderOutcome == ResultProviderFailed || e.ProviderOutcome == ResultProviderTimeout), "retryable result matrix mismatch")
	case ResultStatusCancelled:
		return require(!e.Error.Retryable && e.ProviderOutcome == ResultProviderCancelled, "cancelled result matrix mismatch")
	default:
		return fmt.Errorf("invalid result status %q", e.Status)
	}
}

func (s SemanticOutputV1) Validate() error {
	if s.Version != SemanticOutputVersionV1 || s.Canonicalization != CanonicalJSONVersionV1 {
		return fmt.Errorf("invalid semantic output version")
	}
	if err := validateResultID("semantic artifact", s.ArtifactID); err != nil {
		return err
	}
	if !validDigest(s.ContentSHA256) || !validDigest(s.OutputSchemaSHA256) || s.ContentSizeBytes < 0 || s.NodeCount < 1 || s.MaximumDepth < 1 {
		return fmt.Errorf("invalid semantic output integrity metadata")
	}
	if s.MaximumDepth > SemanticJSONMaxDepth || s.NodeCount > InlineSemanticJSONMaxNodes {
		if s.ProjectionState != ProjectionRejected {
			return fmt.Errorf("over-limit semantic output must be rejected")
		}
	}
	switch s.Mode {
	case SemanticModeNone:
		if s.Completeness != SemanticNotProduced || s.ProjectionState != ProjectionNotRequired || len(s.InlineJSON) != 0 {
			return fmt.Errorf("invalid none semantic output")
		}
	case SemanticModeInlineJSON:
		if s.Completeness != SemanticComplete || len(s.InlineJSON) == 0 {
			return fmt.Errorf("invalid inline semantic output")
		}
		_, canonical, nodes, depth, err := canonicaljson.ParseStrict(s.InlineJSON)
		if err != nil || !bytes.Equal(canonical, s.InlineJSON) || len(canonical) > InlineSemanticJSONMaxBytes || nodes != s.NodeCount || depth != s.MaximumDepth {
			return fmt.Errorf("inline semantic output is not exact canonical JSON")
		}
	case SemanticModeArtifactJSON:
		if s.Completeness != SemanticComplete || len(s.InlineJSON) != 0 {
			return fmt.Errorf("invalid artifact semantic output")
		}
	default:
		return fmt.Errorf("invalid semantic output mode %q", s.Mode)
	}
	if s.ProjectionState != ProjectionComplete && s.ProjectionState != ProjectionNotRequired && s.ProjectionState != ProjectionRejected {
		return fmt.Errorf("invalid semantic projection state")
	}
	return nil
}

func (a ResultArtifactRefV1) Validate() error {
	if err := validateResultID("artifact", a.ArtifactID); err != nil {
		return err
	}
	if err := validateResultID("artifact store", a.ArtifactStoreID); err != nil {
		return err
	}
	if artifactRoleRank(a.Role) == 0 {
		return fmt.Errorf("invalid artifact role")
	}
	if a.ContentSizeBytes < 0 || !validDigest(a.ContentSHA256) || len(a.ContentType) < 1 || len(a.ContentType) > 255 || !isASCII(a.ContentType) {
		return fmt.Errorf("invalid artifact metadata")
	}
	want := "v1/" + strings.ReplaceAll(string(a.ArtifactID), "-", "")[:2] + "/" + string(a.ArtifactID)
	if a.StorageKey != want {
		return fmt.Errorf("noncanonical artifact storage key")
	}
	return nil
}
func (l ResultContractLimitV1) Validate() error {
	if l.Subject != LimitSemanticOutput && l.Subject != LimitBindingSelectedValue && l.Subject != LimitBindingEffectiveInput && l.Subject != LimitProjectionItem && l.Subject != LimitPreparedEvidence {
		return fmt.Errorf("invalid result limit subject")
	}
	if l.Unit != LimitBytes && l.Unit != LimitItems && l.Unit != LimitDepth {
		return fmt.Errorf("invalid result limit unit")
	}
	if l.Observed <= l.Limit {
		return fmt.Errorf("result limit was not exceeded")
	}
	return nil
}

func (r SemanticBindingReferenceV1) Validate() error {
	if r.SchemaID != SemanticBindingReferenceSchemaV1 || r.Version != SemanticBindingReferenceVersionV1 {
		return fmt.Errorf("invalid semantic binding reference version")
	}
	for n, id := range map[string]ID{"source program": r.SourceProgramID, "source workflow": r.SourceWorkflowRunID, "source step": r.SourceStepRunID, "source action": r.SourceActionRequestID, "source occurrence": r.SourceResultOccurrenceID, "source attempt": r.SourceProviderAttemptID, "source artifact": r.SourceArtifactID, "artifact store": r.ArtifactStoreID} {
		if err := validateResultID(n, id); err != nil {
			return err
		}
	}
	if err := (ResultArtifactRefV1{ArtifactID: r.SourceArtifactID, ArtifactStoreID: r.ArtifactStoreID, StorageKey: r.StorageKey, Role: ArtifactRoleSemanticResult, ContentType: "application/json", ContentSizeBytes: r.ContentSizeBytes, ContentSHA256: r.ContentSHA256}).Validate(); err != nil {
		return err
	}
	if !validDigest(r.OutputSchemaSHA256) {
		return fmt.Errorf("invalid output schema digest")
	}
	if err := ValidateSelector(r.Selector); err != nil {
		return err
	}
	raw, _ := json.Marshal(r)
	canonical, err := canonicaljson.Marshal(json.RawMessage(raw))
	if err != nil || len(canonical) > 2048 {
		return fmt.Errorf("semantic binding reference exceeds bounded contract")
	}
	return nil
}

func ValidateSelector(selector string) error {
	if !utf8.ValidString(selector) || len(selector) < 1 || len(selector) > 1024 {
		return fmt.Errorf("invalid selector length")
	}
	parts := strings.Split(selector, ".")
	if len(parts) < 1 || len(parts) > 32 {
		return fmt.Errorf("invalid selector segment count")
	}
	for _, part := range parts {
		if part == "" || len(part) > 128 {
			return fmt.Errorf("invalid selector segment")
		}
		base := strings.TrimSuffix(part, "[]")
		if base == "" || strings.Contains(base, "[") || strings.Contains(base, "]") || strings.Contains(base, ".") {
			return fmt.Errorf("invalid selector grammar")
		}
		if strings.Contains(part, "[]") && !strings.HasSuffix(part, "[]") {
			return fmt.Errorf("invalid selector suffix")
		}
	}
	return nil
}

func BoundUTF8(value string, maximum int) string {
	if maximum < 0 {
		return ""
	}
	if len(value) <= maximum && utf8.ValidString(value) {
		return value
	}
	if maximum < 3 {
		return ""
	}
	value = strings.ToValidUTF8(value, "�")
	limit := maximum - 3
	if len(value) > limit {
		value = value[:limit]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value + "..."
}
func EnvelopeDigest(e ResultEnvelopeV1) (string, error) {
	b, err := e.CanonicalJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func decodeStrictObject(raw []byte, destination any) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}
func validateResultID(name string, id ID) error {
	parsed, err := ParseID(string(id))
	if err != nil || parsed != id || id == "00000000-0000-0000-0000-000000000000" {
		return fmt.Errorf("%s ID is not canonical nonzero UUID", name)
	}
	return nil
}
func validDigest(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil && strings.ToLower(v) == v
}
func isASCII(v string) bool {
	for i := range []byte(v) {
		if v[i] > 127 {
			return false
		}
	}
	return true
}
func artifactRoleRank(role ResultArtifactRoleV1) int {
	switch role {
	case ArtifactRoleProviderStdout:
		return 1
	case ArtifactRoleProviderStderr:
		return 2
	case ArtifactRoleProviderDiagnostic:
		return 3
	case ArtifactRoleSemanticResult:
		return 4
	default:
		return 0
	}
}
func artifactIDForRole(items []ResultArtifactRefV1, role ResultArtifactRoleV1) ID {
	for _, a := range items {
		if a.Role == role {
			return a.ArtifactID
		}
	}
	return ""
}
func semanticArtifactID(items []ResultArtifactRefV1) ID {
	return artifactIDForRole(items, ArtifactRoleSemanticResult)
}
func require(ok bool, message string) error {
	if !ok {
		return fmt.Errorf("%s", message)
	}
	return nil
}
