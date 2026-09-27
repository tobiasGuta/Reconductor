package resultadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
	"github.com/tobiasGuta/Reconductor/internal/strictjsonschema"
)

type PreparedArtifact struct {
	PublicationID domain.ID
	Reference     domain.ResultArtifactRefV1
	Source        artifact.ReplayableSource
	ArtifactType  string
}

type PreparedSealRecord struct {
	Admission      capability.ResultAdmissionProvenance
	StoreIdentity  artifact.StoreIdentity
	Manifest       domain.PreparedManifestV1
	ManifestSize   int64
	ManifestSHA256 string
	ContentBytes   int64
	Outcome        capability.ProviderInvocationOutcome
}
type CompiledResult struct {
	Envelope                domain.ResultEnvelopeV1
	EnvelopeJSON            json.RawMessage
	EnvelopeSHA256          string
	ToolRun                 domain.ToolRun
	Artifacts               []PreparedArtifact
	AcceptedEventID         domain.ID
	ResultOccurrenceID      domain.ID
	PreparedSetID           domain.ID
	ManifestID              domain.ID
	ProviderTerminalEventID domain.ID
	transientClosers        []interface{ Close() error }
}

func (c *CompiledResult) Close() error {
	if c == nil {
		return nil
	}
	var result error
	for _, closer := range c.transientClosers {
		result = errors.Join(result, closer.Close())
	}
	c.transientClosers = nil
	return result
}

type CompileRequest struct {
	ProgramID               domain.ID
	Action                  domain.ActionRequest
	Manifest                capability.Manifest
	StoreIdentity           artifact.StoreIdentity
	Result                  capability.Result
	ToolRun                 domain.ToolRun
	ProjectorsRequired      bool
	RequirePreparedEvidence bool
	Redactor                *redaction.Redactor
}

func WithProjectionLimit(compiled CompiledResult, limit domain.ResultContractLimitV1) (CompiledResult, error) {
	if err := limit.Validate(); err != nil || limit.Subject != domain.LimitProjectionItem {
		return CompiledResult{}, fmt.Errorf("invalid projection contract limit")
	}
	compiled.Envelope.Status = domain.ResultStatusFailed
	compiled.Envelope.SemanticOutput.ProjectionState = domain.ProjectionRejected
	compiled.Envelope.Error = &domain.ResultErrorV1{Code: "result_contract_limit", Message: "result exceeded bounded control-plane contract", Retryable: false, Limit: &limit}
	canonical, err := compiled.Envelope.CanonicalJSON()
	if err != nil {
		return CompiledResult{}, err
	}
	if err := compiled.Envelope.Validate(); err != nil {
		return CompiledResult{}, err
	}
	sum := sha256.Sum256(canonical)
	compiled.EnvelopeJSON = canonical
	compiled.EnvelopeSHA256 = hex.EncodeToString(sum[:])
	return compiled, nil
}

func Compile(request CompileRequest) (CompiledResult, error) {
	if request.Result.AdmissionProvenance == nil || request.Result.ProviderAttemptID == nil {
		return CompiledResult{}, fmt.Errorf("provider-started result requires admission provenance")
	}
	if request.RequirePreparedEvidence && (request.Result.AdmissionProvenance.PreparedSetID == "" || request.Result.AdmissionProvenance.ManifestID == "" || request.Result.AdmissionProvenance.ProviderTerminalEventID == "" || request.Result.AdmissionProvenance.ReservedCapacityBytes < 1) {
		return CompiledResult{}, fmt.Errorf("prepared-evidence admission provenance is incomplete")
	}
	if *request.Result.ProviderAttemptID != request.Result.AdmissionProvenance.ProviderAttemptID {
		return CompiledResult{}, fmt.Errorf("provider attempt provenance mismatch")
	}
	if request.Action.ID != request.Result.AdmissionProvenance.ActionRequestID {
		return CompiledResult{}, fmt.Errorf("action request provenance mismatch")
	}
	if _, err := domain.ParseID(string(request.ToolRun.ID)); err != nil || request.ToolRun.StepRunID != request.Action.StepRunID || request.ToolRun.Capability != request.Manifest.Name || request.ToolRun.ProviderAttemptID == nil || *request.ToolRun.ProviderAttemptID != *request.Result.ProviderAttemptID {
		return CompiledResult{}, fmt.Errorf("tool run draft does not match authoritative provider result lineage")
	}
	if err := request.StoreIdentity.Validate(); err != nil {
		return CompiledResult{}, err
	}
	if request.Redactor == nil {
		request.Redactor = redaction.New()
	}
	budget := int64(domain.ResultEnvelopeMaxBytes)
	if request.Result.AdmissionProvenance.ReservedCapacityBytes > 0 {
		budget = request.Result.AdmissionProvenance.ReservedCapacityBytes
	}
	if budget < 1 || budget > domain.PreparedSetOutputAuthorityMaxBytes {
		return CompiledResult{}, fmt.Errorf("invalid result byte authority")
	}
	// Defense in depth: direct callers cannot force a full copy/decode before
	// byte admission, even if they bypass Registry and the subprocess runner.
	_ = capability.EnforceOutputBudget(&request.Result, budget)
	if len(request.ToolRun.SanitizedArguments) == 0 {
		request.ToolRun.SanitizedArguments = json.RawMessage(`{}`)
	}
	if len(request.ToolRun.ExecutionEnvironment) == 0 {
		request.ToolRun.ExecutionEnvironment = json.RawMessage(`{}`)
	}
	outputSchema := request.Manifest.OutputSchema
	if len(outputSchema) == 0 {
		// Test-only/in-process compatibility manifests historically omitted a
		// schema. Treat that legacy declaration as the closed empty schema; all
		// production registrations provide an explicit schema.
		outputSchema = json.RawMessage(`{}`)
	}
	outputSchemaValue, outputSchemaCanonical, _, _, err := canonicaljson.ParseStrict(outputSchema)
	if err != nil {
		return CompiledResult{}, fmt.Errorf("canonicalize output schema: %w", err)
	}
	schemaSum := sha256.Sum256(outputSchemaCanonical)
	schemaDigest := hex.EncodeToString(schemaSum[:])
	invalidArtifacts := len(request.Result.Action.ArtifactIDs) > 0
	semanticRaw := request.Result.Action.Output
	invalidSemantic := false
	semanticCanonical := []byte("null")
	nodes, depth := uint64(1), uint64(1)
	if len(semanticRaw) > 0 {
		var semanticValue any
		semanticValue, semanticCanonical, nodes, depth, err = canonicaljson.ParseStrictBounded(semanticRaw, int(budget))
		if err != nil {
			var encodingLimit *canonicaljson.EncodingLimitError
			if errors.As(err, &encodingLimit) {
				_ = capability.RejectOutput(&request.Result, budget)
				semanticRaw = nil
			} else {
				invalidSemantic = true
			}
			semanticCanonical = []byte("null")
			nodes, depth = 1, 1
		} else if err = strictjsonschema.Validate(outputSchemaValue, semanticValue); err != nil {
			invalidSemantic = true
			semanticCanonical = []byte("null")
			nodes, depth = 1, 1
		}
	}
	providerOutcome := request.Result.ProviderOutcome
	if providerOutcome == "" {
		providerOutcome = deriveProviderOutcome(request.Result)
	}
	actionError := request.Result.Action.Error
	if actionError != nil {
		safe := *actionError
		safe.Message = request.Redactor.Text(safe.Message)
		actionError = &safe
	}
	status, errorValue := mapOutcome(providerOutcome, actionError)
	if request.Result.OutputLimit != nil {
		status = domain.ResultStatusFailed
		errorValue = &domain.ResultErrorV1{Code: "result_contract_limit", Message: "provider output exceeded result byte authority", Retryable: false, Limit: request.Result.OutputLimit}
	}
	if invalidSemantic {
		providerOutcome = domain.ResultProviderFailed
		status = domain.ResultStatusFailed
		errorValue = &domain.ResultErrorV1{Code: "provider_contract_invalid", Message: "provider returned invalid semantic output", Retryable: false}
	}
	if invalidArtifacts {
		providerOutcome = domain.ResultProviderFailed
		status = domain.ResultStatusFailed
		errorValue = &domain.ResultErrorV1{Code: "provider_contract_invalid", Message: "provider returned compiler-owned artifact identifiers", Retryable: false}
	}
	projection := domain.ProjectionNotRequired
	if providerOutcome == domain.ResultProviderSucceeded && request.ProjectorsRequired && len(semanticRaw) > 0 {
		projection = domain.ProjectionComplete
	}
	if !invalidSemantic && (depth > domain.SemanticJSONMaxDepth || nodes > domain.InlineSemanticJSONMaxNodes) {
		unit, limit, observed := domain.LimitItems, uint64(domain.InlineSemanticJSONMaxNodes), nodes
		if depth > domain.SemanticJSONMaxDepth {
			unit, limit, observed = domain.LimitDepth, uint64(domain.SemanticJSONMaxDepth), depth
		}
		status = domain.ResultStatusFailed
		projection = domain.ProjectionRejected
		errorValue = &domain.ResultErrorV1{Code: "result_contract_limit", Message: "result exceeded bounded control-plane contract", Retryable: false, Limit: &domain.ResultContractLimitV1{Subject: domain.LimitSemanticOutput, Unit: unit, Limit: limit, Observed: observed}}
	}
	prepared := []PreparedArtifact{}
	ownedSources := []artifact.ReplayableSource{}
	compiledSuccessfully := false
	defer func() {
		if compiledSuccessfully {
			return
		}
		for _, source := range ownedSources {
			if closer, ok := source.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
		}
	}()
	add := func(role domain.ResultArtifactRoleV1, contentType, artifactType string, source artifact.ReplayableSource) domain.ID {
		id := domain.NewID()
		key, _ := artifact.StorageKeyFor(id)
		prepared = append(prepared, PreparedArtifact{PublicationID: domain.NewID(), Reference: domain.ResultArtifactRefV1{ArtifactID: id, ArtifactStoreID: request.StoreIdentity.ArtifactStoreID, StorageKey: key, Role: role, ContentType: contentType, ContentSizeBytes: source.SizeBytes(), ContentSHA256: artifact.DigestString(source.SHA256())}, Source: source, ArtifactType: artifactType})
		return id
	}
	stdout := prepareEvidence(request.Redactor, request.Result.RawStdout)
	stderr := prepareEvidence(request.Redactor, request.Result.RawStderr)
	diagnostic := prepareEvidence(request.Redactor, request.Result.RawDiagnostic)
	invalidOutput := prepareEvidence(request.Redactor, semanticRaw)
	remaining := budget - int64(len(semanticCanonical))
	for _, data := range [][]byte{stdout, stderr, diagnostic} {
		if int64(len(data)) > remaining && request.Result.OutputLimit == nil {
			_ = capability.RejectOutput(&request.Result, budget)
			return Compile(request)
		}
		remaining -= int64(len(data))
	}
	if len(stdout) > 0 {
		source, err := newPreparedSource(stdout)
		if err != nil {
			return CompiledResult{}, err
		}
		ownedSources = append(ownedSources, source)
		add(domain.ArtifactRoleProviderStdout, "application/x-ndjson", "raw-provider-output", source)
	}
	if len(stderr) > 0 {
		source, err := newPreparedSource(stderr)
		if err != nil {
			return CompiledResult{}, err
		}
		ownedSources = append(ownedSources, source)
		add(domain.ArtifactRoleProviderStderr, "text/plain", "raw-provider-output", source)
	}
	sections := []DiagnosticSection{}
	if len(diagnostic) > 0 && !bytes.Contains(stdout, diagnostic) && !bytes.Contains(stderr, diagnostic) {
		source, err := newPreparedSource(diagnostic)
		if err != nil {
			return CompiledResult{}, err
		}
		ownedSources = append(ownedSources, source)
		sections = append(sections, DiagnosticSection{Kind: CompleteDiagnostic, Source: source})
	}
	if invalidSemantic {
		source, err := newPreparedSource(invalidOutput)
		if err != nil {
			return CompiledResult{}, err
		}
		ownedSources = append(ownedSources, source)
		sections = append(sections, DiagnosticSection{Kind: InvalidSemanticOutput, Source: source})
	}
	var diagnosticID domain.ID
	if len(sections) > 0 {
		bundle, err := NewDiagnosticBundleSource(sections)
		if err != nil {
			return CompiledResult{}, err
		}
		diagnosticID = add(domain.ArtifactRoleProviderDiagnostic, domain.DiagnosticEvidenceContentTypeV1, "provider-diagnostic", bundle)
	}
	semanticSource, err := newPreparedSource(semanticCanonical)
	if err != nil {
		return CompiledResult{}, err
	}
	ownedSources = append(ownedSources, semanticSource)
	semanticID := add(domain.ArtifactRoleSemanticResult, "application/json", "normalized-result", semanticSource)
	mode, completeness := domain.SemanticModeNone, domain.SemanticNotProduced
	var inline json.RawMessage
	if len(semanticRaw) > 0 && !invalidSemantic {
		mode, completeness = domain.SemanticModeInlineJSON, domain.SemanticComplete
		if len(semanticCanonical) > domain.InlineSemanticJSONMaxBytes {
			mode = domain.SemanticModeArtifactJSON
		} else {
			inline = append(json.RawMessage(nil), semanticCanonical...)
		}
	}
	if errorValue != nil && diagnosticID != "" {
		id := diagnosticID
		errorValue.DiagnosticArtifactID = &id
	}
	references := make([]domain.ResultArtifactRefV1, len(prepared))
	for i := range prepared {
		references[i] = prepared[i].Reference
	}
	envelope := domain.ResultEnvelopeV1{Version: domain.ResultEnvelopeVersionV1, ActionRequestID: request.Action.ID, ResultOccurrenceID: domain.NewID(), ProviderAttemptID: *request.Result.ProviderAttemptID, CapabilityName: request.Manifest.Name, CapabilityVersion: request.Manifest.Version, Status: status, ProviderOutcome: providerOutcome, Summary: domain.BoundUTF8(request.Redactor.Text(request.Result.Action.Summary), domain.SafeMessageMaxBytes), PublicationComplete: true, SemanticOutput: domain.SemanticOutputV1{Version: domain.SemanticOutputVersionV1, Mode: mode, Completeness: completeness, Canonicalization: domain.CanonicalJSONVersionV1, ArtifactID: semanticID, ContentSHA256: artifact.DigestString(semanticSource.SHA256()), ContentSizeBytes: semanticSource.SizeBytes(), OutputSchemaSHA256: schemaDigest, NodeCount: nodes, MaximumDepth: depth, ProjectionState: projection, InlineJSON: inline}, Artifacts: references, Error: errorValue}
	if invalidSemantic {
		envelope.SemanticOutput.Mode = domain.SemanticModeNone
		envelope.SemanticOutput.Completeness = domain.SemanticNotProduced
		envelope.SemanticOutput.ProjectionState = domain.ProjectionNotRequired
		envelope.SemanticOutput.InlineJSON = nil
	}
	canonical, err := envelope.CanonicalJSON()
	if err != nil {
		return CompiledResult{}, err
	}
	if err := envelope.Validate(); err != nil {
		return CompiledResult{}, err
	}
	sum := sha256.Sum256(canonical)
	request.ToolRun.ArtifactIDs = nil
	request.ToolRun.StdoutArtifactID = nil
	request.ToolRun.StderrArtifactID = nil
	for _, p := range prepared {
		request.ToolRun.ArtifactIDs = append(request.ToolRun.ArtifactIDs, p.Reference.ArtifactID)
		switch p.Reference.Role {
		case domain.ArtifactRoleProviderStdout:
			id := p.Reference.ArtifactID
			request.ToolRun.StdoutArtifactID = &id
		case domain.ArtifactRoleProviderStderr:
			id := p.Reference.ArtifactID
			request.ToolRun.StderrArtifactID = &id
		}
	}
	compiledSuccessfully = true
	closers := make([]interface{ Close() error }, 0, len(ownedSources))
	for _, source := range ownedSources {
		if closer, ok := source.(interface{ Close() error }); ok {
			closers = append(closers, closer)
		}
	}
	return CompiledResult{Envelope: envelope, EnvelopeJSON: canonical, EnvelopeSHA256: hex.EncodeToString(sum[:]), ToolRun: request.ToolRun, Artifacts: prepared, AcceptedEventID: domain.NewID(), ResultOccurrenceID: envelope.ResultOccurrenceID, PreparedSetID: request.Result.AdmissionProvenance.PreparedSetID, ManifestID: request.Result.AdmissionProvenance.ManifestID, ProviderTerminalEventID: request.Result.AdmissionProvenance.ProviderTerminalEventID, transientClosers: closers}, nil
}

type preparedObjectOpener interface {
	OpenPrepared(context.Context, string, int64, [32]byte) (io.ReadCloser, error)
}

type preparedSource struct {
	opener preparedObjectOpener
	key    string
	size   int64
	digest [32]byte
}

func (s preparedSource) Open() (io.ReadCloser, error) {
	return s.opener.OpenPrepared(context.Background(), s.key, s.size, s.digest)
}
func (s preparedSource) SizeBytes() int64 { return s.size }
func (s preparedSource) SHA256() [32]byte { return s.digest }

func (c *CompiledResult) PreparedStageRequest(identity artifact.StoreIdentity, step domain.StepRun, admission capability.ResultAdmissionProvenance, outcome capability.ProviderInvocationOutcome, retention time.Duration) (artifact.PreparedStageRequest, domain.PreparedManifestV1, error) {
	if c == nil || c.PreparedSetID == "" || c.ManifestID == "" || c.ProviderTerminalEventID == "" || c.PreparedSetID != admission.PreparedSetID || c.ManifestID != admission.ManifestID || c.ProviderTerminalEventID != admission.ProviderTerminalEventID {
		return artifact.PreparedStageRequest{}, domain.PreparedManifestV1{}, fmt.Errorf("compiled prepared-evidence identity is incomplete")
	}
	if domain.ResultProviderOutcomeV1(outcome) != c.Envelope.ProviderOutcome {
		return artifact.PreparedStageRequest{}, domain.PreparedManifestV1{}, fmt.Errorf("prepared provider outcome mismatch")
	}
	preparedStep := domain.PreparedStepV1{ID: step.ID, WorkflowRunID: step.WorkflowRunID, Capability: step.Capability, Status: c.Envelope.Status, ErrorClassification: step.ErrorClassification, ErrorDetails: step.ErrorDetails, CompletedAt: step.CompletedAt, IdempotencyKey: step.IdempotencyKey}
	control := domain.PreparedControlV1{Version: domain.PreparedControlVersionV1, SetID: c.PreparedSetID, ManifestID: c.ManifestID, ProviderTerminalEventID: c.ProviderTerminalEventID, AcceptedEventID: c.AcceptedEventID, ProviderOutcome: c.Envelope.ProviderOutcome, Envelope: c.Envelope, EnvelopeSHA256: c.EnvelopeSHA256, ToolRun: c.ToolRun, Step: preparedStep, Admission: domain.PreparedAdmissionV1{ProviderAttemptID: admission.ProviderAttemptID, PreparedSetID: admission.PreparedSetID, ActionRequestID: admission.ActionRequestID, StepAttempt: admission.StepAttempt, QueueJobID: admission.QueueJobID, ExecutionAuthorizationEventID: admission.ExecutionAuthorizationEventID, Provider: admission.Provider}, ArtifactRetentionNanos: int64(retention)}
	controlJSON, err := control.CanonicalJSON()
	if err != nil {
		return artifact.PreparedStageRequest{}, domain.PreparedManifestV1{}, err
	}
	controlSource := newByteSource(controlJSON)
	controlKey, _ := domain.PreparedControlKey(c.PreparedSetID)
	members := make([]domain.PreparedMemberV1, len(c.Artifacts))
	objects := make([]artifact.PreparedStageObject, len(c.Artifacts))
	for ordinal, item := range c.Artifacts {
		preparedKey, _ := domain.PreparedMemberKey(c.PreparedSetID, ordinal)
		members[ordinal] = domain.PreparedMemberV1{Ordinal: ordinal, PublicationID: item.PublicationID, ArtifactID: item.Reference.ArtifactID, PreparedKey: preparedKey, FinalKey: item.Reference.StorageKey, Role: item.Reference.Role, ContentType: item.Reference.ContentType, ArtifactType: item.ArtifactType, ContentSizeBytes: item.Reference.ContentSizeBytes, ContentSHA256: item.Reference.ContentSHA256}
		objects[ordinal] = artifact.PreparedStageObject{StorageKey: preparedKey, ExpectedSize: item.Source.SizeBytes(), ExpectedSHA256: item.Source.SHA256(), Source: item.Source}
	}
	attemptID := admission.ProviderAttemptID
	controlDigest := controlSource.SHA256()
	manifest := domain.PreparedManifestV1{Version: domain.PreparedManifestVersionV1, SetID: c.PreparedSetID, ManifestID: c.ManifestID, ArtifactStoreID: identity.ArtifactStoreID, StoreIncarnationNonce: identity.IncarnationNonce, StoreBackendKind: identity.BackendKind, StoreMarkerFormat: identity.MarkerFormat, StoreMarkerVersion: identity.MarkerVersion, ProviderAttemptID: &attemptID, ResultOccurrenceID: c.ResultOccurrenceID, Control: domain.PreparedObjectRefV1{StorageKey: controlKey, ContentSizeBytes: controlSource.SizeBytes(), ContentSHA256: artifact.DigestString(controlDigest)}, Members: members}
	manifestJSON, err := manifest.CanonicalJSON()
	if err != nil {
		return artifact.PreparedStageRequest{}, domain.PreparedManifestV1{}, err
	}
	manifestKey, _ := domain.PreparedManifestKey(c.PreparedSetID)
	request := artifact.PreparedStageRequest{ReservedCapacityBytes: admission.ReservedCapacityBytes, SetID: c.PreparedSetID, ManifestID: c.ManifestID, Control: artifact.PreparedStageObject{StorageKey: controlKey, ExpectedSize: controlSource.SizeBytes(), ExpectedSHA256: controlDigest, Source: controlSource}, Members: objects, ManifestKey: manifestKey, ManifestJSON: manifestJSON}
	return request, manifest, request.ValidateCapacity()
}

func (c *CompiledResult) TransferPreparedSources(opener preparedObjectOpener, manifest domain.PreparedManifestV1) error {
	if c == nil || opener == nil || manifest.SetID != c.PreparedSetID || len(manifest.Members) != len(c.Artifacts) {
		return fmt.Errorf("prepared source transfer identity mismatch")
	}
	if err := c.Close(); err != nil {
		return err
	}
	for ordinal, member := range manifest.Members {
		digestBytes, err := hex.DecodeString(member.ContentSHA256)
		if err != nil || len(digestBytes) != 32 {
			return fmt.Errorf("prepared member digest is invalid")
		}
		var digest [32]byte
		copy(digest[:], digestBytes)
		c.Artifacts[ordinal].Source = preparedSource{opener: opener, key: member.PreparedKey, size: member.ContentSizeBytes, digest: digest}
	}
	return nil
}

func ReconstructPrepared(inspection artifact.PreparedInspection, opener preparedObjectOpener, reservedCapacity int64) (CompiledResult, capability.ResultAdmissionProvenance, domain.StepRun, time.Duration, capability.ProviderInvocationOutcome, error) {
	manifest, control := inspection.Manifest, inspection.Control
	if opener == nil || reservedCapacity < 1 || manifest.SetID != control.SetID || manifest.ManifestID != control.ManifestID || manifest.ResultOccurrenceID != control.Envelope.ResultOccurrenceID || len(manifest.Members) != len(control.Envelope.Artifacts) {
		return CompiledResult{}, capability.ResultAdmissionProvenance{}, domain.StepRun{}, 0, "", fmt.Errorf("prepared reconstruction identity mismatch")
	}
	artifacts := make([]PreparedArtifact, len(manifest.Members))
	for ordinal, member := range manifest.Members {
		reference := control.Envelope.Artifacts[ordinal]
		if reference.ArtifactID != member.ArtifactID || reference.ArtifactStoreID != manifest.ArtifactStoreID || reference.StorageKey != member.FinalKey || reference.Role != member.Role || reference.ContentType != member.ContentType || reference.ContentSizeBytes != member.ContentSizeBytes || reference.ContentSHA256 != member.ContentSHA256 {
			return CompiledResult{}, capability.ResultAdmissionProvenance{}, domain.StepRun{}, 0, "", fmt.Errorf("prepared member %d does not match envelope", ordinal)
		}
		digest, err := decodeDigest(member.ContentSHA256)
		if err != nil {
			return CompiledResult{}, capability.ResultAdmissionProvenance{}, domain.StepRun{}, 0, "", err
		}
		artifacts[ordinal] = PreparedArtifact{PublicationID: member.PublicationID, Reference: reference, ArtifactType: member.ArtifactType, Source: preparedSource{opener: opener, key: member.PreparedKey, size: member.ContentSizeBytes, digest: digest}}
	}
	admission := capability.ResultAdmissionProvenance{ProviderAttemptID: control.Admission.ProviderAttemptID, PreparedSetID: control.SetID, ManifestID: control.ManifestID, ProviderTerminalEventID: control.ProviderTerminalEventID, ReservedCapacityBytes: reservedCapacity, ActionRequestID: control.Admission.ActionRequestID, StepAttempt: control.Admission.StepAttempt, QueueJobID: control.Admission.QueueJobID, ExecutionAuthorizationEventID: control.Admission.ExecutionAuthorizationEventID, Provider: control.Admission.Provider}
	step := domain.StepRun{ID: control.Step.ID, WorkflowRunID: control.Step.WorkflowRunID, Capability: control.Step.Capability, Status: domain.StepStatus(control.Step.Status), ErrorClassification: control.Step.ErrorClassification, ErrorDetails: control.Step.ErrorDetails, CompletedAt: control.Step.CompletedAt, IdempotencyKey: control.Step.IdempotencyKey}
	compiled := CompiledResult{Envelope: control.Envelope, EnvelopeJSON: mustEnvelopeJSON(control.Envelope), EnvelopeSHA256: control.EnvelopeSHA256, ToolRun: control.ToolRun, Artifacts: artifacts, AcceptedEventID: control.AcceptedEventID, ResultOccurrenceID: control.Envelope.ResultOccurrenceID, PreparedSetID: control.SetID, ManifestID: control.ManifestID, ProviderTerminalEventID: control.ProviderTerminalEventID}
	return compiled, admission, step, time.Duration(control.ArtifactRetentionNanos), capability.ProviderInvocationOutcome(control.ProviderOutcome), nil
}

func decodeDigest(value string) ([32]byte, error) {
	var digest [32]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != len(digest) {
		return digest, fmt.Errorf("prepared digest is invalid")
	}
	copy(digest[:], raw)
	return digest, nil
}

func mustEnvelopeJSON(envelope domain.ResultEnvelopeV1) json.RawMessage {
	raw, _ := envelope.CanonicalJSON()
	return raw
}

func prepareEvidence(r *redaction.Redactor, data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	return []byte(r.Text(string(data)))
}
func deriveProviderOutcome(result capability.Result) domain.ResultProviderOutcomeV1 {
	if result.ToolRun != nil && result.ToolRun.TimedOut {
		return domain.ResultProviderTimeout
	}
	switch result.Action.Status {
	case "succeeded":
		return domain.ResultProviderSucceeded
	case "cancelled":
		return domain.ResultProviderCancelled
	case "timeout":
		return domain.ResultProviderTimeout
	default:
		return domain.ResultProviderFailed
	}
}
func mapOutcome(outcome domain.ResultProviderOutcomeV1, source *domain.StructuredError) (domain.ResultEnvelopeStatusV1, *domain.ResultErrorV1) {
	if outcome == domain.ResultProviderSucceeded {
		return domain.ResultStatusSucceeded, nil
	}
	code, message, retryable := "provider_error", "provider execution failed", false
	if source != nil {
		if source.Classification != "" {
			code = normalizeCode(source.Classification)
		}
		if source.Message != "" {
			message = source.Message
		}
		retryable = source.Retryable
	}
	status := domain.ResultStatusFailed
	if retryable && (outcome == domain.ResultProviderFailed || outcome == domain.ResultProviderTimeout) {
		status = domain.ResultStatusRetryable
	}
	if outcome == domain.ResultProviderCancelled {
		status = domain.ResultStatusCancelled
		retryable = false
		code = "cancelled"
	}
	return status, &domain.ResultErrorV1{Code: code, Message: domain.BoundUTF8(message, domain.SafeMessageMaxBytes), Retryable: retryable}
}
func normalizeCode(value string) string {
	out := make([]byte, 0, len(value))
	for i, b := range []byte(value) {
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		if b >= 'a' && b <= 'z' || i > 0 && b >= '0' && b <= '9' || i > 0 && b == '_' {
			out = append(out, b)
		} else if len(out) > 0 && out[len(out)-1] != '_' {
			out = append(out, '_')
		}
	}
	if len(out) == 0 || out[0] < 'a' || out[0] > 'z' {
		return "provider_error"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return string(bytes.TrimRight(out, "_"))
}
