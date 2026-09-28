package database

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

var evidenceViewTxOptions = pgx.TxOptions{
	IsoLevel:   pgx.RepeatableRead,
	AccessMode: pgx.ReadOnly,
}

// AuthorizeEvidenceView authorizes one modern result artifact within one
// selected workflow run. It deliberately does not share the dependency-based
// authorization contract used by AuthorizeSemanticBinding.
func (s *Store) AuthorizeEvidenceView(ctx context.Context, workflowRunID, artifactID domain.ID) (artifact.AuthorizedEvidenceArtifactV1, error) {
	unavailable := func() (artifact.AuthorizedEvidenceArtifactV1, error) {
		return artifact.AuthorizedEvidenceArtifactV1{}, artifact.ErrEvidenceUnavailable
	}
	if _, err := domain.ParseID(string(workflowRunID)); err != nil {
		return unavailable()
	}
	if _, err := domain.ParseID(string(artifactID)); err != nil {
		return unavailable()
	}
	if s == nil || s.Pool == nil {
		return unavailable()
	}

	tx, err := s.Pool.BeginTx(ctx, evidenceViewTxOptions)
	if err != nil {
		return artifact.AuthorizedEvidenceArtifactV1{}, err
	}
	defer tx.Rollback(ctx)

	var (
		programID, workflowTaskID, artifactTaskID                        domain.ID
		artifactRunID, artifactStepID, stepRunID, stepWorkflowRunID      domain.ID
		artifactToolID, toolRunID, toolStepRunID                         domain.ID
		providerAttemptID, publicationID, publicationAttemptID           domain.ID
		publicationOccurrenceID, publicationArtifactID                   domain.ID
		artifactStoreID, publicationStoreID, storeIncarnation            domain.ID
		preparedProviderAttemptID, preparedProgramID, preparedTaskID     domain.ID
		preparedRunID, preparedStepID, preparedActionID                  domain.ID
		preparedStoreID, preparedStoreIncarnation                        domain.ID
		stepDefinitionID, stepCapability, toolCapability, providerName   string
		providerEventType, providerProgramID, providerTaskID             string
		providerRunID, providerStepID, providerActionID                  string
		providerCapability, providerNameFromAttempt                      string
		stepOutput                                                       []byte
		artifactType, artifactContentType, artifactDigest                string
		artifactStorageKey, artifactRedactionState                       string
		publicationStorageKey, publicationContentType, publicationDigest string
		publicationState, preparedOwnerKind, preparedLifecycleState      string
		stdoutArtifactID, stderrArtifactID, preparedResultOccurrenceID   string
		storeBackend, storeMarker                                        string
		artifactSize, publicationSize                                    int64
		artifactAddressingVersion                                        int16
		storeMarkerVersion, publicationOrdinal, publicationCount         int
		adoptedPublicationCount, preparedMemberCount                     int
		artifactSensitive, artifactHasNoLocation, artifactIsCurrent      bool
		artifactContentPresent, artifactCleanupHealthy                   bool
		publicationContentPresent, publicationCleanupHealthy             bool
	)

	err = tx.QueryRow(ctx, `SELECT
		t.program_id,wr.task_id,a.task_id,
		a.workflow_run_id,a.step_run_id,sr.id,sr.workflow_run_id,
		a.tool_run_id,tr.id,tr.step_run_id,
		tr.provider_attempt_id,ap.id,ap.provider_attempt_id,
		ap.result_occurrence_id,ap.artifact_id,
		a.artifact_store_id,ap.artifact_store_id,ast.incarnation_nonce,
		pes.provider_attempt_id,pes.program_id,pes.task_id,pes.workflow_run_id,pes.step_run_id,pes.action_request_id,
		pes.artifact_store_id,pes.store_incarnation_nonce,
		sr.step_definition_id,sr.capability,tr.capability,tr.provider,
		pa.event_type,COALESCE(pa.program_id::text,''),COALESCE(pa.task_id::text,''),
		COALESCE(pa.workflow_run_id::text,''),COALESCE(pa.step_run_id::text,''),COALESCE(pa.action_request_id::text,''),
		COALESCE(pa.capability,''),COALESCE(pa.provider,''),sr.output,
		a.type,a.content_type,a.sha256,a.storage_key,a.redaction_state,
		ap.storage_key,ap.content_type,ap.content_sha256,ap.publication_state,
		pes.owner_kind,pes.lifecycle_state,
		COALESCE(tr.stdout_artifact_id::text,''),COALESCE(tr.stderr_artifact_id::text,''),
		COALESCE(pes.result_occurrence_id::text,''),ast.backend_kind,ast.marker_format,
		a.size,ap.content_size_bytes,a.addressing_version,ast.marker_version,ap.publication_ordinal,
		(SELECT count(*) FROM artifact_publications members
		 WHERE members.provider_attempt_id=ap.provider_attempt_id AND members.result_occurrence_id=ap.result_occurrence_id),
		(SELECT count(*) FROM artifact_publications members
		 WHERE members.provider_attempt_id=ap.provider_attempt_id AND members.result_occurrence_id=ap.result_occurrence_id
		   AND members.publication_state='adopted'),
		COALESCE(pes.member_count,-1),
		a.sensitive,a.storage_location IS NULL,
		(a.expires_at IS NULL OR a.expires_at>statement_timestamp()),
		a.content_deleted_at IS NULL,a.cleanup_quarantined_at IS NULL,
		ap.content_deleted_at IS NULL,ap.cleanup_quarantined_at IS NULL
	FROM artifacts a
	JOIN workflow_runs wr ON wr.id=a.workflow_run_id
	JOIN tasks t ON t.id=wr.task_id
	JOIN step_runs sr ON sr.id=a.step_run_id
	JOIN tool_runs tr ON tr.id=a.tool_run_id
	JOIN audit_events pa ON pa.id=tr.provider_attempt_id
	JOIN artifact_publications ap ON ap.artifact_id=a.id
	JOIN artifact_stores ast ON ast.id=a.artifact_store_id
	JOIN prepared_evidence_sets pes ON pes.provider_attempt_id=tr.provider_attempt_id
	WHERE a.workflow_run_id=$1 AND a.id=$2`, workflowRunID, artifactID).Scan(
		&programID, &workflowTaskID, &artifactTaskID,
		&artifactRunID, &artifactStepID, &stepRunID, &stepWorkflowRunID,
		&artifactToolID, &toolRunID, &toolStepRunID,
		&providerAttemptID, &publicationID, &publicationAttemptID,
		&publicationOccurrenceID, &publicationArtifactID,
		&artifactStoreID, &publicationStoreID, &storeIncarnation,
		&preparedProviderAttemptID, &preparedProgramID, &preparedTaskID, &preparedRunID, &preparedStepID, &preparedActionID,
		&preparedStoreID, &preparedStoreIncarnation,
		&stepDefinitionID, &stepCapability, &toolCapability, &providerName,
		&providerEventType, &providerProgramID, &providerTaskID,
		&providerRunID, &providerStepID, &providerActionID,
		&providerCapability, &providerNameFromAttempt, &stepOutput,
		&artifactType, &artifactContentType, &artifactDigest, &artifactStorageKey, &artifactRedactionState,
		&publicationStorageKey, &publicationContentType, &publicationDigest, &publicationState,
		&preparedOwnerKind, &preparedLifecycleState,
		&stdoutArtifactID, &stderrArtifactID, &preparedResultOccurrenceID, &storeBackend, &storeMarker,
		&artifactSize, &publicationSize, &artifactAddressingVersion, &storeMarkerVersion, &publicationOrdinal,
		&publicationCount, &adoptedPublicationCount, &preparedMemberCount,
		&artifactSensitive, &artifactHasNoLocation, &artifactIsCurrent,
		&artifactContentPresent, &artifactCleanupHealthy,
		&publicationContentPresent, &publicationCleanupHealthy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return unavailable()
	}
	if err != nil {
		return artifact.AuthorizedEvidenceArtifactV1{}, err
	}

	lineageValid := workflowTaskID == artifactTaskID && artifactRunID == workflowRunID &&
		artifactStepID == stepRunID && stepWorkflowRunID == workflowRunID &&
		artifactToolID == toolRunID && toolStepRunID == stepRunID &&
		stepCapability != "" && toolCapability == stepCapability &&
		providerEventType == "provider_invocation_started" &&
		providerProgramID == string(programID) && providerTaskID == string(workflowTaskID) &&
		providerRunID == string(workflowRunID) && providerStepID == string(stepRunID) &&
		providerActionID != "" && providerCapability == stepCapability && providerNameFromAttempt == providerName
	publicationValid := publicationArtifactID == artifactID && publicationAttemptID == providerAttemptID &&
		publicationStoreID == artifactStoreID && publicationStorageKey == artifactStorageKey &&
		publicationContentType == artifactContentType && publicationSize == artifactSize &&
		publicationDigest == artifactDigest && publicationState == string(domain.PublicationAdopted) &&
		publicationContentPresent && publicationCleanupHealthy
	preparedValid := preparedOwnerKind == "provider_attempt" && preparedProviderAttemptID == providerAttemptID &&
		preparedProgramID == programID && preparedTaskID == workflowTaskID && preparedRunID == workflowRunID &&
		preparedStepID == stepRunID && string(preparedActionID) == providerActionID &&
		preparedResultOccurrenceID == string(publicationOccurrenceID) &&
		preparedStoreID == artifactStoreID && preparedStoreIncarnation == storeIncarnation &&
		(preparedLifecycleState == string(domain.PreparedResolvedAdopted) || preparedLifecycleState == string(domain.PreparedCleaned))
	artifactAvailable := artifactAddressingVersion == 1 && artifactHasNoLocation && artifactIsCurrent &&
		artifactContentPresent && artifactCleanupHealthy
	if !lineageValid || !publicationValid || !preparedValid || !artifactAvailable {
		return unavailable()
	}
	if artifactSensitive {
		return artifact.AuthorizedEvidenceArtifactV1{}, artifact.ErrEvidenceRestricted
	}
	if artifactRedactionState != "redacted" {
		return unavailable()
	}

	_, canonicalStepOutput, _, _, err := canonicaljson.ParseStrict(stepOutput)
	if err != nil {
		return unavailable()
	}
	envelope, err := domain.DecodeResultEnvelopeV1(canonicalStepOutput)
	if err != nil || envelope.ActionRequestID != domain.ID(providerActionID) ||
		envelope.ResultOccurrenceID != publicationOccurrenceID || envelope.ProviderAttemptID != providerAttemptID ||
		envelope.CapabilityName != stepCapability || !envelope.PublicationComplete ||
		publicationCount != len(envelope.Artifacts) || adoptedPublicationCount != len(envelope.Artifacts) ||
		preparedMemberCount != len(envelope.Artifacts) {
		return unavailable()
	}

	var reference domain.ResultArtifactRefV1
	referenceIndex := -1
	for index, candidate := range envelope.Artifacts {
		if candidate.ArtifactID == artifactID {
			reference = candidate
			referenceIndex = index
			break
		}
	}
	if referenceIndex < 0 || publicationOrdinal != referenceIndex || !recognizedEvidenceRole(reference.Role) ||
		reference.ArtifactStoreID != artifactStoreID || reference.StorageKey != artifactStorageKey ||
		reference.ContentType != artifactContentType || reference.ContentSizeBytes != artifactSize ||
		reference.ContentSHA256 != artifactDigest {
		return unavailable()
	}
	if err := artifact.ValidateStorageKey(reference.StorageKey, artifactID); err != nil {
		return unavailable()
	}
	if reference.Role == domain.ArtifactRoleProviderStdout && stdoutArtifactID != string(artifactID) {
		return unavailable()
	}
	if reference.Role == domain.ArtifactRoleProviderStderr && stderrArtifactID != string(artifactID) {
		return unavailable()
	}

	storeIdentity := artifact.StoreIdentity{
		ArtifactStoreID:  artifactStoreID,
		IncarnationNonce: storeIncarnation,
		BackendKind:      storeBackend,
		MarkerFormat:     storeMarker,
		MarkerVersion:    storeMarkerVersion,
	}
	if err := storeIdentity.Validate(); err != nil {
		return unavailable()
	}
	if err := tx.Commit(ctx); err != nil {
		return artifact.AuthorizedEvidenceArtifactV1{}, err
	}
	return artifact.AuthorizedEvidenceArtifactV1{
		Reference:            reference,
		StoreIdentity:        storeIdentity,
		ProgramID:            programID,
		TaskID:               workflowTaskID,
		WorkflowRunID:        workflowRunID,
		StepRunID:            stepRunID,
		StepDefinitionID:     stepDefinitionID,
		ToolRunID:            toolRunID,
		ActionRequestID:      domain.ID(providerActionID),
		ProviderAttemptID:    providerAttemptID,
		ResultOccurrenceID:   publicationOccurrenceID,
		PublicationID:        publicationID,
		CapabilityName:       envelope.CapabilityName,
		CapabilityVersion:    envelope.CapabilityVersion,
		ProviderName:         providerName,
		ArtifactType:         artifactType,
		SemanticCompleteness: envelope.SemanticOutput.Completeness,
	}, nil
}

func recognizedEvidenceRole(role domain.ResultArtifactRoleV1) bool {
	switch role {
	case domain.ArtifactRoleProviderStdout,
		domain.ArtifactRoleProviderStderr,
		domain.ArtifactRoleProviderDiagnostic,
		domain.ArtifactRoleSemanticResult:
		return true
	default:
		return false
	}
}
