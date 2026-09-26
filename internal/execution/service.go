package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/normalize"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
	"github.com/tobiasGuta/Reconductor/internal/resultadmission"
)

type Service struct {
	Registry        *capability.Registry
	Store           ResultStore
	Artifacts       artifact.Storage
	ProgramID       domain.ID
	PolicyAuditor   capability.PolicyDecisionRecorder
	ProviderAuditor capability.ProviderInvocationRecorder
}
type ResultStore interface {
	PreviousObservationValues(context.Context, domain.ID, domain.ID, string) ([]string, error)
	LoadEffectiveStepInput(context.Context, domain.ID, domain.ActionRequest) (json.RawMessage, bool, error)
	PersistEffectiveStepInput(context.Context, domain.ID, domain.ActionRequest, json.RawMessage) (json.RawMessage, error)
	PersistPreProviderFailure(context.Context, domain.ID, domain.StepRun, string) error
}

type boundedResultStore interface {
	SealPreparedEvidence(context.Context, resultadmission.PreparedSealRecord) error
	QuarantinePreparedEvidence(context.Context, domain.ID, string) error
	ReserveCompiledResult(context.Context, domain.ID, domain.StepRun, resultadmission.CompiledResult, *capability.ResultAdmissionProvenance, artifact.StoreIdentity) error
	MarkCompiledArtifactPublishing(context.Context, resultadmission.CompiledResult, int) error
	SealCompiledArtifact(context.Context, resultadmission.CompiledResult, int) error
	TerminalizeCompiledResult(context.Context, resultadmission.CompiledResult, domain.PublicationState, string) error
	AdoptCompiledResult(context.Context, domain.ID, domain.StepRun, resultadmission.CompiledResult, *capability.ResultAdmissionProvenance, time.Duration) error
}

type identifiedPublisherStore interface {
	artifact.PublisherStore
	Identity() artifact.StoreIdentity
}

type semanticAuthorityStore interface {
	AuthorizeSemanticBinding(context.Context, domain.SemanticBindingResolutionV1) (artifact.AuthorizedSemanticArtifactV1, error)
}

func (s Service) ResolveSemanticBinding(ctx context.Context, request domain.SemanticBindingResolutionV1) (io.ReadCloser, error) {
	authority, ok := s.Store.(semanticAuthorityStore)
	if !ok {
		return nil, fmt.Errorf("semantic_output_unavailable: authoritative database resolver is required")
	}
	readerStore, ok := s.Artifacts.(interface {
		artifact.SemanticArtifactReader
		Identity() artifact.StoreIdentity
	})
	if !ok {
		return nil, fmt.Errorf("semantic_output_unavailable: authoritative artifact reader is required")
	}
	authorized, err := authority.AuthorizeSemanticBinding(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("semantic_output_unavailable: %w", err)
	}
	if readerStore.Identity() != authorized.StoreIdentity {
		return nil, fmt.Errorf("semantic_output_unavailable: artifact store identity changed")
	}
	if s.Registry == nil {
		return nil, fmt.Errorf("semantic_output_unavailable: capability registry is required")
	}
	implementation, ok := s.Registry.Get(authorized.CapabilityName)
	if !ok || implementation.Manifest().Version != authorized.CapabilityVersion {
		return nil, fmt.Errorf("semantic_output_unavailable: source capability version is unavailable")
	}
	outputSchema := implementation.Manifest().OutputSchema
	if len(outputSchema) == 0 {
		outputSchema = json.RawMessage(`{}`)
	}
	_, canonicalSchema, _, _, err := canonicaljson.ParseStrict(outputSchema)
	if err != nil || artifact.DigestString(sha256.Sum256(canonicalSchema)) != authorized.OutputSchemaSHA256 {
		return nil, fmt.Errorf("semantic_output_unavailable: output schema identity changed")
	}
	reader, err := readerStore.OpenVerified(ctx, authorized.Reference)
	if err != nil {
		return nil, fmt.Errorf("semantic_output_unavailable: %w", err)
	}
	return reader, nil
}

func (s Service) Execute(ctx context.Context, req capability.Request) (returned capability.Result, returnedErr error) {
	defer func() {
		// Project control-facing fields only after compilation has captured the
		// complete admitted diagnostic. Preserve classification and retryability.
		returned.Action.Summary = domain.BoundUTF8(redaction.New().Text(returned.Action.Summary), domain.SafeMessageMaxBytes)
		if returned.Action.Error != nil {
			projected := *returned.Action.Error
			projected.Message = domain.BoundUTF8(redaction.New().Text(projected.Message), domain.SafeMessageMaxBytes)
			returned.Action.Error = &projected
		}
		if returnedErr == nil {
			return
		}
		message := "execution failed; diagnostic evidence is separate from control state"
		if returned.AdmissionProvenance == nil {
			message = domain.BoundUTF8(redaction.New().Text(returnedErr.Error()), domain.SafeMessageMaxBytes)
		}
		if domain.PersistenceUnresolved(returnedErr) {
			message = "result persistence is unresolved; authoritative reconciliation required"
		} else if returned.Envelope != nil && returned.Envelope.Error != nil {
			message = returned.Envelope.Error.Code + ": " + returned.Envelope.Error.Message
		} else if returned.Action.Error != nil && returned.Action.Error.Classification == "result_contract_limit" {
			message = "result_contract_limit: prepared evidence exceeded its authorized reservation"
		}
		returnedErr = &domain.BoundedExecutionError{Err: returnedErr, Message: message}
	}()
	if req.Action.StepAttempt == 0 {
		req.Action.StepAttempt = 1
	}
	req.ProgramID = s.ProgramID
	req.PolicyPhase = "execution"
	req.DecisionRecorder = s.PolicyAuditor
	if req.DecisionRecorder == nil {
		if recorder, ok := s.Store.(capability.PolicyDecisionRecorder); ok {
			req.DecisionRecorder = recorder
		}
	}
	req.InvocationRecorder = s.ProviderAuditor
	if req.InvocationRecorder == nil {
		if recorder, ok := s.Store.(capability.ProviderInvocationRecorder); ok {
			req.InvocationRecorder = recorder
		}
	}
	effectivePersisted := false
	if s.Store != nil && req.Action.StepRunID != "" {
		persisted, found, loadErr := s.Store.LoadEffectiveStepInput(ctx, s.ProgramID, req.Action)
		if loadErr != nil {
			return capability.Result{}, loadErr
		}
		if found {
			req.Action.Input = append(json.RawMessage(nil), persisted...)
			effectivePersisted = true
		}
	}
	if !effectivePersisted && req.Action.Capability == "compare.assets" {
		if s.Store == nil {
			return capability.Result{}, fmt.Errorf("result store is required")
		}
		var input map[string]json.RawMessage
		if err := json.Unmarshal(req.Action.Input, &input); err == nil {
			if previous, ok := input["previous"]; ok && emptyJSONArray(previous) {
				values, loadErr := s.Store.PreviousObservationValues(ctx, s.ProgramID, req.Action.WorkflowRunID, "probe.http")
				if loadErr != nil {
					return capability.Result{}, loadErr
				}
				if values == nil {
					values = []string{}
				}
				encodedPrevious, marshalErr := json.Marshal(values)
				if marshalErr != nil {
					return capability.Result{}, fmt.Errorf("marshal compare.assets history: %w", marshalErr)
				}
				input["previous"] = encodedPrevious
				enriched, marshalErr := json.Marshal(input)
				if marshalErr != nil {
					return capability.Result{}, fmt.Errorf("marshal compare.assets history: %w", marshalErr)
				}
				req.Action.Input = enriched
			}
		}
	}
	if !effectivePersisted && req.Action.Capability == "classify.endpoint" {
		if s.Store == nil {
			return capability.Result{}, fmt.Errorf("result store is required")
		}
		var input map[string]json.RawMessage
		if err := json.Unmarshal(req.Action.Input, &input); err == nil {
			if previous, ok := input["historical_observations"]; !ok || !nonEmptyJSONArray(previous) {
				values, loadErr := s.Store.PreviousObservationValues(ctx, s.ProgramID, req.Action.WorkflowRunID, "probe.http")
				if loadErr != nil {
					return capability.Result{}, loadErr
				}
				history, historyErr := historicalRecords(values)
				if historyErr != nil {
					return capability.Result{}, historyErr
				}
				encodedHistory, marshalErr := json.Marshal(history)
				if marshalErr != nil {
					return capability.Result{}, fmt.Errorf("marshal classify.endpoint history: %w", marshalErr)
				}
				input["historical_observations"] = encodedHistory
				req.Action.Input, marshalErr = json.Marshal(input)
				if marshalErr != nil {
					return capability.Result{}, fmt.Errorf("marshal classify.endpoint input: %w", marshalErr)
				}
			}
		}
	}
	if s.Store != nil && req.Action.StepRunID != "" {
		persisted, persistErr := s.Store.PersistEffectiveStepInput(ctx, s.ProgramID, req.Action, req.Action.Input)
		if persistErr != nil {
			return capability.Result{}, persistErr
		}
		req.Action.Input = append(json.RawMessage(nil), persisted...)
	}
	// The database-returned bytes are authoritative for the workflow save fence.
	// Preserve them before publisher acquisition, which can deterministically fail
	// before provider execution begins.
	returned.EffectiveInput = append(json.RawMessage(nil), req.Action.Input...)
	publisher, ok := s.Artifacts.(identifiedPublisherStore)
	if !ok {
		acquireErr := fmt.Errorf("durable prepared-evidence publisher store is required")
		return s.persistAcquirePublisherFailure(ctx, req, returned, acquireErr)
	}
	guard, acquireErr := publisher.AcquirePublisher(ctx, publisher.Identity())
	if acquireErr != nil {
		return s.persistAcquirePublisherFailure(ctx, req, returned, fmt.Errorf("acquire prepared-evidence publisher authority: %w", acquireErr))
	}
	guardClosed := false
	defer func() {
		if !guardClosed {
			_ = guard.Close()
		}
	}()
	preparedGuard, ok := guard.(artifact.PreparedPublisherGuard)
	if !ok {
		guardClosed = true
		mismatchErr := fmt.Errorf("artifact publisher lacks prepared-evidence capability")
		if closeErr := guard.Close(); closeErr != nil {
			var release *artifact.PublisherReleaseError
			if !errors.As(closeErr, &release) {
				closeErr = &artifact.PublisherReleaseError{Err: closeErr}
			}
			mismatchErr = errors.Join(mismatchErr, closeErr)
		}
		return s.persistAcquirePublisherFailure(ctx, req, returned, mismatchErr)
	}
	preparedIdentity := publisher.Identity()
	req.PreparedStoreIdentity = &preparedIdentity
	req.RequirePreparedEvidence = true
	result, executionErr := s.Registry.Execute(ctx, req)
	result.EffectiveInput = append(json.RawMessage(nil), req.Action.Input...)
	callerCancelled := executionErr != nil && errors.Is(context.Cause(ctx), context.Canceled)
	if callerCancelled {
		result.Action.RequestID = req.Action.ID
		result.Action.Status = "cancelled"
		result.Action.Summary = "capability execution cancelled"
		result.Action.Error = &domain.StructuredError{Classification: "cancelled", Message: context.Canceled.Error(), Retryable: false}
		result.ProviderOutcome = domain.ResultProviderCancelled
	} else if executionErr != nil && result.Action.Error == nil {
		result.Action = domain.ActionResult{RequestID: req.Action.ID, Status: "failed", Summary: "capability execution failed", Error: &domain.StructuredError{Classification: "execution", Message: executionErr.Error(), Retryable: false}}
	}
	tool := result.ToolRun
	if tool == nil {
		now := time.Now().UTC()
		version := "1"
		provider := "platform"
		if implementation, ok := s.Registry.Get(req.Action.Capability); ok {
			version = implementation.Manifest().Version
		}
		if result.AdmissionProvenance != nil {
			provider = result.AdmissionProvenance.Provider
		}
		tool = &domain.ToolRun{ID: domain.NewID(), StepRunID: req.Action.StepRunID, Capability: req.Action.Capability, Provider: provider, ToolVersion: version, SanitizedArguments: json.RawMessage(`{}`), ExecutionEnvironment: json.RawMessage(`{"kind":"in-process"}`), StartedAt: now, CompletedAt: &now}
	}
	if result.ProviderAttemptID != nil {
		attemptID := *result.ProviderAttemptID
		tool.ProviderAttemptID = &attemptID
	}
	persistCtx := ctx
	persistCancel := func() {}
	if ctx.Err() != nil {
		persistCtx, persistCancel = context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	}
	defer persistCancel()
	now := time.Now().UTC()
	if result.AdmissionProvenance != nil {
		boundedStore, ok := s.Store.(boundedResultStore)
		if !ok {
			return result, &domain.UnresolvedPersistenceError{Err: errors.Join(executionErr, fmt.Errorf("compile execution result: bounded result store is required"))}
		}
		quarantineAllocated := func(reason string, cause error) (capability.Result, error) {
			quarantineErr := boundedStore.QuarantinePreparedEvidence(persistCtx, result.AdmissionProvenance.PreparedSetID, reason)
			return result, &domain.UnresolvedPersistenceError{Err: errors.Join(executionErr, cause, quarantineErr)}
		}
		manifest, ok := s.Registry.Get(req.Action.Capability)
		if !ok {
			return quarantineAllocated("capability_manifest_unavailable", fmt.Errorf("compile execution result: capability manifest is unavailable"))
		}
		compiled, compileErr := resultadmission.Compile(resultadmission.CompileRequest{ProgramID: s.ProgramID, Action: req.Action, Manifest: manifest.Manifest(), StoreIdentity: publisher.Identity(), Result: result, ToolRun: *tool, ProjectorsRequired: projectorRequired(req.Action.Capability), RequirePreparedEvidence: true})
		if compileErr != nil {
			return quarantineAllocated("result_compilation_failed", fmt.Errorf("compile execution result: %w", compileErr))
		}
		defer compiled.Close()
		result.Envelope = &compiled.Envelope
		if capture, ok := s.Artifacts.(interface {
			CaptureCompiledPublication(capability.Request, resultadmission.CompiledResult)
		}); ok {
			capture.CaptureCompiledPublication(req, compiled)
		}
		step := stepForEnvelope(req, compiled.Envelope, now)
		outcome := capability.ProviderInvocationOutcome(compiled.Envelope.ProviderOutcome)
		stageRequest, preparedManifest, stageErr := compiled.PreparedStageRequest(publisher.Identity(), step, *result.AdmissionProvenance, outcome, req.Policy.ArtifactRetention)
		if stageErr != nil {
			var capacity *artifact.PreparedCapacityError
			if errors.As(stageErr, &capacity) {
				return s.rejectOversized(persistCtx, boundedStore, result, step, compiled, stageRequest, capacity)
			}
			return quarantineAllocated("prepared_control_failed", fmt.Errorf("compile prepared evidence: %w", stageErr))
		}
		receipt, stageErr := preparedGuard.StagePrepared(persistCtx, stageRequest)
		if stageErr == nil && (!receipt.Durable || receipt.ManifestSize != int64(len(stageRequest.ManifestJSON)) || receipt.ManifestSHA256 != artifact.DigestBytes(stageRequest.ManifestJSON) || receipt.MemberCount != len(stageRequest.Members)) {
			stageErr = fmt.Errorf("prepared staging receipt lacks exact durable anchors")
		}
		if stageErr != nil {
			var capacity *artifact.PreparedCapacityError
			if errors.As(stageErr, &capacity) {
				return s.rejectOversized(persistCtx, boundedStore, result, step, compiled, stageRequest, capacity)
			}
			quarantineErr := boundedStore.QuarantinePreparedEvidence(persistCtx, compiled.PreparedSetID, "prepared_stage_failed")
			return result, &domain.UnresolvedPersistenceError{Err: errors.Join(executionErr, fmt.Errorf("stage prepared evidence: %w", stageErr), quarantineErr)}
		}
		sealRecord := resultadmission.PreparedSealRecord{Admission: *result.AdmissionProvenance, StoreIdentity: publisher.Identity(), Manifest: preparedManifest, ManifestSize: receipt.ManifestSize, ManifestSHA256: artifact.DigestString(receipt.ManifestSHA256), ContentBytes: receipt.ContentBytes + receipt.ManifestSize, Outcome: outcome}
		if sealErr := boundedStore.SealPreparedEvidence(persistCtx, sealRecord); sealErr != nil {
			return result, &domain.UnresolvedPersistenceError{Err: errors.Join(executionErr, fmt.Errorf("seal prepared evidence: %w", sealErr))}
		}
		if transferErr := compiled.TransferPreparedSources(preparedGuard, preparedManifest); transferErr != nil {
			return result, &domain.UnresolvedPersistenceError{Err: errors.Join(executionErr, fmt.Errorf("transfer prepared source ownership: %w", transferErr))}
		}
		pipelineErr := s.publishAndAdopt(persistCtx, boundedStore, guard, req, step, &compiled, result.AdmissionProvenance)
		result.Envelope = &compiled.Envelope
		result.Action.Summary = compiled.Envelope.Summary
		closeErr := guard.Close()
		guardClosed = true
		if closeErr != nil {
			var release *artifact.PublisherReleaseError
			if !errors.As(closeErr, &release) {
				closeErr = &artifact.PublisherReleaseError{Err: closeErr}
			}
		}
		if pipelineErr != nil {
			return result, errors.Join(executionErr, pipelineErr, closeErr)
		}
		if compiled.Envelope.Status != domain.ResultStatusSucceeded && executionErr == nil {
			executionErr = fmt.Errorf("%s: %s", compiled.Envelope.Error.Code, compiled.Envelope.Error.Message)
		}
		if compiled.Envelope.Error != nil && compiled.Envelope.Error.Code == "result_contract_limit" {
			result.Action.Error = &domain.StructuredError{Classification: compiled.Envelope.Error.Code, Message: compiled.Envelope.Error.Message, Retryable: compiled.Envelope.Error.Retryable}
		}
		return result, errors.Join(executionErr, closeErr)
	}
	if domain.PersistenceUnresolved(executionErr) {
		return result, executionErr
	}
	var persistenceErr error
	tool = nil
	step := domain.StepRun{ID: req.Action.StepRunID, WorkflowRunID: req.Action.WorkflowRunID, Capability: req.Action.Capability, Status: domain.StepSucceeded, Output: result.Action.Output, CompletedAt: &now, IdempotencyKey: req.Action.IdempotencyKey}
	if executionErr != nil {
		step.Status = map[bool]domain.StepStatus{true: domain.StepCancelled, false: domain.StepFailed}[callerCancelled]
		if result.Action.Error != nil {
			step.ErrorClassification = result.Action.Error.Classification
			step.ErrorDetails = result.Action.Error.Message
			if result.Action.Error.Retryable && !callerCancelled {
				step.Status = domain.StepRetryable
				step.CompletedAt = nil
			}
		}
	}
	if s.Store == nil {
		persistenceErr = errors.Join(persistenceErr, fmt.Errorf("result store is required"))
	} else {
		if err := s.Store.PersistPreProviderFailure(persistCtx, s.ProgramID, step, result.Action.Summary); err != nil {
			persistenceErr = errors.Join(persistenceErr, err)
		}
	}
	if persistenceErr != nil {
		return result, errors.Join(executionErr, fmt.Errorf("persist execution result: %w", persistenceErr))
	}
	return result, executionErr
}

func (s Service) persistAcquirePublisherFailure(ctx context.Context, req capability.Request, result capability.Result, acquireErr error) (capability.Result, error) {
	result.Action = domain.ActionResult{
		RequestID: req.Action.ID,
		Status:    "failed",
		Summary:   "capability execution failed",
		Error:     &domain.StructuredError{Classification: "execution", Message: acquireErr.Error(), Retryable: false},
	}
	persistCtx := ctx
	persistCancel := func() {}
	if ctx.Err() != nil {
		persistCtx, persistCancel = context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	}
	defer persistCancel()
	now := time.Now().UTC()
	step := domain.StepRun{
		ID:                  req.Action.StepRunID,
		WorkflowRunID:       req.Action.WorkflowRunID,
		Capability:          req.Action.Capability,
		Status:              domain.StepFailed,
		ErrorClassification: result.Action.Error.Classification,
		ErrorDetails:        result.Action.Error.Message,
		CompletedAt:         &now,
		IdempotencyKey:      req.Action.IdempotencyKey,
	}
	if s.Store == nil {
		return result, errors.Join(acquireErr, fmt.Errorf("persist execution result: result store is required"))
	}
	if err := s.Store.PersistPreProviderFailure(persistCtx, s.ProgramID, step, result.Action.Summary); err != nil {
		return result, errors.Join(acquireErr, fmt.Errorf("persist execution result: %w", err))
	}
	return result, acquireErr
}

func (s Service) rejectOversized(ctx context.Context, store boundedResultStore, result capability.Result, step domain.StepRun, compiled resultadmission.CompiledResult, request artifact.PreparedStageRequest, capacity *artifact.PreparedCapacityError) (capability.Result, error) {
	rejector, ok := store.(interface {
		RejectPreparedEvidence(context.Context, domain.ID, domain.StepRun, resultadmission.CompiledResult, capability.ResultAdmissionProvenance, artifact.PreparedStageRequest, domain.ResultContractLimitV1) error
	})
	if !ok {
		return result, &domain.UnresolvedPersistenceError{Err: fmt.Errorf("prepared rejection terminalizer unavailable")}
	}
	if err := rejector.RejectPreparedEvidence(ctx, s.ProgramID, step, compiled, *result.AdmissionProvenance, request, capacity.ResultContractLimit()); err != nil {
		return result, &domain.UnresolvedPersistenceError{Err: err}
	}
	result.Envelope = nil // nonadmission must never masquerade as an accepted result
	result.Action.Status = "failed"
	result.Action.Summary = "prepared evidence exceeded its authorized reservation"
	result.Action.Output = nil
	result.Action.ArtifactIDs = nil
	result.Action.Error = &domain.StructuredError{Classification: "result_contract_limit", Message: result.Action.Summary, Retryable: false}
	result.RawStdout, result.RawStderr, result.RawDiagnostic = nil, nil, nil
	return result, capacity
}

func (s Service) publishAndAdopt(ctx context.Context, store boundedResultStore, guard artifact.PublisherGuard, req capability.Request, step domain.StepRun, compiled *resultadmission.CompiledResult, admission *capability.ResultAdmissionProvenance) error {
	if guard.Identity() != s.Artifacts.(identifiedPublisherStore).Identity() {
		return fmt.Errorf("publisher guard identity changed")
	}
	if err := store.ReserveCompiledResult(ctx, s.ProgramID, step, *compiled, admission, guard.Identity()); err != nil {
		return &domain.UnresolvedPersistenceError{Err: fmt.Errorf("reserve result publication: %w", err)}
	}
	knownFailure := func(cause error) error {
		if domain.PersistenceUnresolved(cause) {
			return cause
		}
		terminalState := domain.PublicationAbandoned
		var unverifiable *artifact.PublicationUnverifiableError
		if errors.As(cause, &unverifiable) {
			terminalState = domain.PublicationQuarantined
		}
		terminalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := store.TerminalizeCompiledResult(terminalCtx, *compiled, terminalState, ""); err != nil {
			return &domain.UnresolvedPersistenceError{Err: errors.Join(cause, fmt.Errorf("terminalize failed publication set: %w", err))}
		}
		if terminalState == domain.PublicationQuarantined {
			return &domain.UnresolvedPersistenceError{Err: cause}
		}
		return cause
	}
	for ordinal, item := range compiled.Artifacts {
		if err := store.MarkCompiledArtifactPublishing(ctx, *compiled, ordinal); err != nil {
			return knownFailure(fmt.Errorf("mark artifact %d publishing: %w", ordinal, err))
		}
		reader, err := item.Source.Open()
		if err != nil {
			return knownFailure(fmt.Errorf("open prepared artifact %d: %w", ordinal, err))
		}
		digestBytes, err := hex.DecodeString(item.Reference.ContentSHA256)
		if err != nil {
			_ = reader.Close()
			return knownFailure(fmt.Errorf("decode artifact %d digest: %w", ordinal, err))
		}
		var digest [32]byte
		copy(digest[:], digestBytes)
		receipt, publishErr := guard.PublishReserved(ctx, artifact.ReservedArtifactV1{PublicationID: item.PublicationID, ArtifactID: item.Reference.ArtifactID, ArtifactStoreID: item.Reference.ArtifactStoreID, StorageKey: item.Reference.StorageKey, ExpectedSize: item.Reference.ContentSizeBytes, ExpectedSHA256: digest}, reader)
		closeErr := reader.Close()
		if publishErr != nil || closeErr != nil {
			cause := errors.Join(publishErr, closeErr)
			if publishErr != nil {
				cause = &artifact.PublicationUnverifiableError{Err: cause}
			}
			return knownFailure(fmt.Errorf("publish artifact %d: %w", ordinal, cause))
		}
		if !receipt.Durable || receipt.SizeBytes != item.Reference.ContentSizeBytes || receipt.SHA256 != digest {
			return knownFailure(&artifact.PublicationUnverifiableError{Err: fmt.Errorf("publish artifact %d returned unverifiable receipt", ordinal)})
		}
		if err := store.SealCompiledArtifact(ctx, *compiled, ordinal); err != nil {
			return knownFailure(fmt.Errorf("seal artifact %d: %w", ordinal, err))
		}
	}
	if err := store.AdoptCompiledResult(ctx, s.ProgramID, step, *compiled, admission, req.Policy.ArtifactRetention); err != nil {
		var limitErr interface {
			error
			ResultContractLimit() domain.ResultContractLimitV1
		}
		if errors.As(err, &limitErr) {
			failed, compileErr := resultadmission.WithProjectionLimit(*compiled, limitErr.ResultContractLimit())
			if compileErr != nil {
				return &domain.UnresolvedPersistenceError{Err: fmt.Errorf("compile failed projection admission: %w", compileErr)}
			}
			failedStep := stepForEnvelope(req, failed.Envelope, time.Now().UTC())
			if adoptErr := store.AdoptCompiledResult(ctx, s.ProgramID, failedStep, failed, admission, req.Policy.ArtifactRetention); adoptErr != nil {
				return &domain.UnresolvedPersistenceError{Err: fmt.Errorf("adopt failed projection result: %w", adoptErr)}
			}
			*compiled = failed
			return nil
		}
		// A failed admission proof (notably an expired live scheduler lease)
		// is not proof of nonadmission. The complete sealed result may remain
		// recoverable under its separate exact-attempt authority.
		return &domain.UnresolvedPersistenceError{Err: fmt.Errorf("adopt result: %w", err)}
	}
	return nil
}

func commitOutcomeUnknown(err error) bool {
	var unknown interface{ CommitOutcomeUnknown() bool }
	return errors.As(err, &unknown) && unknown.CommitOutcomeUnknown()
}

func stepForEnvelope(req capability.Request, envelope domain.ResultEnvelopeV1, now time.Time) domain.StepRun {
	step := domain.StepRun{ID: req.Action.StepRunID, WorkflowRunID: req.Action.WorkflowRunID, Capability: req.Action.Capability, Status: domain.StepStatus(envelope.Status), Output: nil, CompletedAt: &now, IdempotencyKey: req.Action.IdempotencyKey}
	if envelope.Status == domain.ResultStatusRetryable {
		step.CompletedAt = nil
	}
	if envelope.Error != nil {
		step.ErrorClassification = envelope.Error.Code
		step.ErrorDetails = envelope.Error.Message
	}
	return step
}

func projectorRequired(capabilityName string) bool { return capabilityName != "compare.assets" }

func historicalRecords(values []string) ([]any, error) {
	out := make([]any, 0, len(values))
	for index, value := range values {
		record, err := historicalRecord(value)
		if err != nil {
			return nil, fmt.Errorf("historical observation %d: %w", index, err)
		}
		out = append(out, record)
	}
	return out, nil
}

func historicalRecord(raw string) (map[string]any, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("empty observation")
	}
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		target, err := historicalHTTPURL(trimmed)
		if err != nil {
			return nil, err
		}
		return map[string]any{"provider": "httpx", "kind": "url", "target": target, "fields": map[string]any{"value": trimmed}}, nil
	}
	var item map[string]any
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.UseNumber()
	if err := decoder.Decode(&item); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values")
		}
		return nil, err
	}
	if target, _ := item["target"].(string); target != "" {
		normalizedTarget, err := historicalHTTPURL(target)
		if err != nil {
			return nil, err
		}
		item["target"] = normalizedTarget
		if provider, _ := item["provider"].(string); provider == "" {
			item["provider"] = "httpx"
		}
		if kind, _ := item["kind"].(string); kind == "" {
			item["kind"] = "url"
		} else if kind != "url" {
			return nil, fmt.Errorf("record kind %q is not a URL", kind)
		}
		return item, nil
	}
	legacy := firstHistoricalString(item, "value", "url", "input")
	if legacy == "" {
		legacy = historicalHostCandidate(item)
	}
	if legacy == "" {
		return nil, fmt.Errorf("has no target")
	}
	target, err := historicalHTTPURL(legacy)
	if err != nil {
		return nil, err
	}
	upgraded := map[string]any{"provider": "httpx", "kind": "url", "target": target, "fields": item}
	if status, ok := item["status_code"]; ok {
		upgraded["status_code"] = status
	}
	if technologies, ok := item["technologies"]; ok {
		upgraded["technologies"] = technologies
	} else if technologies, ok := item["tech"]; ok {
		upgraded["technologies"] = technologies
	}
	return upgraded, nil
}

func emptyJSONArray(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return false
	}
	var items []json.RawMessage
	return json.Unmarshal(trimmed, &items) == nil && len(items) == 0
}

func nonEmptyJSONArray(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return false
	}
	var items []json.RawMessage
	return json.Unmarshal(trimmed, &items) == nil && len(items) > 0
}

func historicalHTTPURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	if parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", fmt.Errorf("record target must be an absolute HTTP URL")
	}
	return normalize.URL(trimmed)
}

func historicalHostCandidate(item map[string]any) string {
	host := firstHistoricalString(item, "host")
	if host == "" || strings.Contains(host, "://") {
		return host
	}
	scheme := firstHistoricalString(item, "scheme")
	if scheme == "" {
		return ""
	}
	return scheme + "://" + host
}

func firstHistoricalString(item map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := item[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}
