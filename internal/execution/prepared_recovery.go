package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/resultadmission"
)

type preparedRecoveryDatabase interface {
	boundedResultStore
	ListPreparedEvidence(context.Context, domain.ID, domain.ID, int) ([]domain.PreparedSetRecord, error)
	MarkPreparedEvidenceCleaned(context.Context, domain.ID) error
	CompiledPublicationStates(context.Context, resultadmission.CompiledResult) ([]domain.PublicationState, error)
}

// RecoverPreparedEvidence reconciles one bounded database-led batch while the
// store's exclusive authority excludes live publishers. It never invokes a
// capability provider and never allocates replacement identities.
func (s Service) RecoverPreparedEvidence(ctx context.Context, limit int) error {
	store, ok := s.Store.(preparedRecoveryDatabase)
	if !ok {
		return fmt.Errorf("prepared evidence recovery database is required")
	}
	artifactStore, ok := s.Artifacts.(interface {
		identifiedPublisherStore
		artifact.PreparedRecoveryStore
	})
	if !ok {
		return fmt.Errorf("prepared evidence recovery store is required")
	}
	identity := artifactStore.Identity()
	guard, err := artifactStore.AcquirePreparedRecovery(ctx, identity)
	if err != nil {
		return fmt.Errorf("acquire prepared recovery authority: %w", err)
	}
	defer guard.Close()
	records, err := store.ListPreparedEvidence(ctx, identity.ArtifactStoreID, identity.IncarnationNonce, limit)
	if err != nil {
		return err
	}
	var result error
	for _, record := range records {
		if err := s.recoverPreparedRecord(ctx, store, guard, identity, record); err != nil {
			result = errors.Join(result, fmt.Errorf("prepared set %s: %w", record.ID, err))
		}
	}
	closeErr := guard.Close()
	if closeErr == nil {
		if reconciler, ok := s.Store.(interface {
			ReconcileDeferredApprovalRejections(context.Context, int) error
		}); ok {
			result = errors.Join(result, reconciler.ReconcileDeferredApprovalRejections(ctx, limit))
		}
	}
	return errors.Join(result, closeErr)
}

func (s Service) recoverPreparedRecord(ctx context.Context, store preparedRecoveryDatabase, guard artifact.PreparedRecoveryGuard, identity artifact.StoreIdentity, record domain.PreparedSetRecord) error {
	if record.ArtifactStoreID != identity.ArtifactStoreID || record.StoreIncarnationNonce != identity.IncarnationNonce {
		return fmt.Errorf("database/store identity contradiction")
	}
	switch record.State {
	case domain.PreparedQuarantined:
		return nil
	case domain.PreparedResolvedAdopted, domain.PreparedResolvedAbandoned:
		if _, err := guard.DeleteResolvedPrepared(ctx, record); err != nil {
			return err
		}
		return store.MarkPreparedEvidenceCleaned(ctx, record.ID)
	case domain.PreparedAllocated, domain.PreparedSealed:
	default:
		return fmt.Errorf("unsupported recovery lifecycle %s", record.State)
	}
	inspection, err := guard.InspectPrepared(ctx, record.ID)
	if err == nil && !inspection.Durable {
		err = fmt.Errorf("prepared inspection did not establish durability")
	}
	if err != nil {
		quarantineErr := store.QuarantinePreparedEvidence(ctx, record.ID, "prepared_content_unverifiable")
		return errors.Join(err, quarantineErr)
	}
	compiled, admission, step, retention, outcome, err := resultadmission.ReconstructPrepared(inspection, guard, record.ReservedCapacityBytes)
	if err != nil {
		return errors.Join(err, store.QuarantinePreparedEvidence(ctx, record.ID, "prepared_control_contradiction"))
	}
	contentBytes := int64(len(inspection.ManifestJSON) + len(inspection.ControlJSON))
	if record.ReservedCapacityBytes < contentBytes || record.ReservedCapacityBytes > 1<<40 {
		return &domain.UnresolvedPersistenceError{Err: fmt.Errorf("prepared recovery capacity contradiction")}
	}
	for _, member := range inspection.Manifest.Members {
		if member.ContentSizeBytes < 0 || member.ContentSizeBytes > record.ReservedCapacityBytes-contentBytes {
			return &domain.UnresolvedPersistenceError{Err: fmt.Errorf("prepared recovery exceeds authorized capacity")}
		}
		contentBytes += member.ContentSizeBytes
	}
	manifestSum := sha256.Sum256(inspection.ManifestJSON)
	if record.ProviderAttemptID == nil || *record.ProviderAttemptID != admission.ProviderAttemptID || record.ManifestID != admission.ManifestID || record.ID != admission.PreparedSetID || record.ActionRequestID != admission.ActionRequestID || record.StepAttempt != admission.StepAttempt || record.StepRunID != step.ID || record.WorkflowRunID != step.WorkflowRunID || contentBytes > record.ReservedCapacityBytes {
		return &domain.UnresolvedPersistenceError{Err: fmt.Errorf("prepared recovery record/manifest lineage contradiction")}
	}
	ctx = domain.WithPreparedRecoveryRequest(ctx, domain.PreparedRecoveryRequest{SetID: record.ID, ManifestID: record.ManifestID, ProviderAttemptID: admission.ProviderAttemptID, TerminalEventID: admission.ProviderTerminalEventID, ResultOccurrenceID: compiled.ResultOccurrenceID, ActionRequestID: admission.ActionRequestID, StepAttempt: admission.StepAttempt, ManifestSHA256: artifact.DigestString(manifestSum)})
	if record.State == domain.PreparedAllocated {
		seal := resultadmission.PreparedSealRecord{Admission: admission, StoreIdentity: identity, Manifest: inspection.Manifest, ManifestSize: int64(len(inspection.ManifestJSON)), ManifestSHA256: artifact.DigestString(manifestSum), ContentBytes: contentBytes, Outcome: outcome}
		if err := store.SealPreparedEvidence(ctx, seal); err != nil {
			return err
		}
	} else if record.ManifestSizeBytes == nil || record.ManifestSHA256 == nil || record.MemberCount == nil || record.ContentSizeBytes == nil || record.ResultOccurrenceID == nil || *record.ManifestSizeBytes != int64(len(inspection.ManifestJSON)) || *record.ManifestSHA256 != artifact.DigestString(manifestSum) || *record.MemberCount != len(inspection.Manifest.Members) || *record.ContentSizeBytes != contentBytes || *record.ResultOccurrenceID != compiled.ResultOccurrenceID {
		return errors.Join(fmt.Errorf("sealed database/manifest contradiction"), store.QuarantinePreparedEvidence(ctx, record.ID, "sealed_manifest_contradiction"))
	}
	states, err := store.CompiledPublicationStates(ctx, compiled)
	if err != nil {
		return errors.Join(err, store.QuarantinePreparedEvidence(ctx, record.ID, "publication_journal_contradiction"))
	}
	if len(states) == 0 {
		if err := store.ReserveCompiledResult(ctx, record.ProgramID, step, compiled, &admission, identity); err != nil {
			return err
		}
		states = make([]domain.PublicationState, len(compiled.Artifacts))
		for index := range states {
			states[index] = domain.PublicationReserved
		}
	}
	for ordinal, state := range states {
		item := compiled.Artifacts[ordinal]
		digest, err := recoveryDigest(item.Reference.ContentSHA256)
		if err != nil {
			return errors.Join(err, store.QuarantinePreparedEvidence(ctx, record.ID, "publication_digest_contradiction"))
		}
		reserved := artifact.ReservedArtifactV1{PublicationID: item.PublicationID, ArtifactID: item.Reference.ArtifactID, ArtifactStoreID: item.Reference.ArtifactStoreID, StorageKey: item.Reference.StorageKey, ExpectedSize: item.Reference.ContentSizeBytes, ExpectedSHA256: digest}
		switch state {
		case domain.PublicationReserved:
			if err := store.MarkCompiledArtifactPublishing(ctx, compiled, ordinal); err != nil {
				return err
			}
			reader, err := item.Source.Open()
			if err != nil {
				return err
			}
			receipt, publishErr := guard.PublishReserved(ctx, reserved, reader)
			closeErr := reader.Close()
			if publishErr != nil || closeErr != nil || !receipt.Durable || receipt.SizeBytes != reserved.ExpectedSize || receipt.SHA256 != reserved.ExpectedSHA256 {
				return errors.Join(fmt.Errorf("recovery publication has no exact durable receipt"), publishErr, closeErr, store.QuarantinePreparedEvidence(ctx, record.ID, "recovery_publication_unverifiable"))
			}
			if err := store.SealCompiledArtifact(ctx, compiled, ordinal); err != nil {
				return err
			}
		case domain.PublicationPublishing:
			receipt, present, err := guard.VerifyReserved(ctx, reserved)
			if err != nil {
				return errors.Join(err, store.QuarantinePreparedEvidence(ctx, record.ID, "recovery_publication_unverifiable"))
			}
			if !present {
				reader, openErr := item.Source.Open()
				if openErr != nil {
					return openErr
				}
				receipt, err = guard.PublishReserved(ctx, reserved, reader)
				closeErr := reader.Close()
				if err != nil || closeErr != nil {
					return errors.Join(err, closeErr, store.QuarantinePreparedEvidence(ctx, record.ID, "recovery_publication_unverifiable"))
				}
			}
			if !receipt.Durable || receipt.SizeBytes != reserved.ExpectedSize || receipt.SHA256 != reserved.ExpectedSHA256 {
				return errors.Join(fmt.Errorf("recovered publication receipt mismatch"), store.QuarantinePreparedEvidence(ctx, record.ID, "recovery_publication_unverifiable"))
			}
			if err := store.SealCompiledArtifact(ctx, compiled, ordinal); err != nil {
				return err
			}
		case domain.PublicationSealed:
		case domain.PublicationAdopted:
			return errors.Join(fmt.Errorf("adopted journal without atomic prepared resolution"), store.QuarantinePreparedEvidence(ctx, record.ID, "publication_resolution_contradiction"))
		default:
			return errors.Join(fmt.Errorf("terminal publication journal with unresolved prepared set"), store.QuarantinePreparedEvidence(ctx, record.ID, "publication_resolution_contradiction"))
		}
	}
	if err := store.AdoptCompiledResult(ctx, record.ProgramID, step, compiled, &admission, retention); err != nil {
		var limitErr interface {
			error
			ResultContractLimit() domain.ResultContractLimitV1
		}
		if errors.As(err, &limitErr) {
			failed, compileErr := resultadmission.WithProjectionLimit(compiled, limitErr.ResultContractLimit())
			if compileErr != nil {
				return &domain.UnresolvedPersistenceError{Err: errors.Join(err, compileErr)}
			}
			failedStep := step
			failedStep.Status = domain.StepStatus(failed.Envelope.Status)
			if failed.Envelope.Error != nil {
				failedStep.ErrorClassification = failed.Envelope.Error.Code
				failedStep.ErrorDetails = failed.Envelope.Error.Message
			}
			if adoptErr := store.AdoptCompiledResult(ctx, record.ProgramID, failedStep, failed, &admission, retention); adoptErr == nil {
				return nil
			} else if commitOutcomeUnknown(adoptErr) {
				return adoptErr
			} else {
				return &domain.UnresolvedPersistenceError{Err: adoptErr}
			}
		}
		if commitOutcomeUnknown(err) {
			return err
		}
		// Failure to prove admission (including missing live credentials) is
		// not proof of nonadoption and never grants abandonment authority.
		return &domain.UnresolvedPersistenceError{Err: err}
	}
	return nil
}

func recoveryDigest(value string) ([32]byte, error) {
	var digest [32]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != len(digest) {
		return digest, fmt.Errorf("invalid recovered publication digest")
	}
	copy(digest[:], raw)
	return digest, nil
}
