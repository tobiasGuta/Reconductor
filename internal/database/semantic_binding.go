package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

var ErrSemanticOutputUnavailable = errors.New("semantic_output_unavailable")

func (s *Store) AuthorizeSemanticBinding(ctx context.Context, request domain.SemanticBindingResolutionV1) (artifact.AuthorizedSemanticArtifactV1, error) {
	if err := request.Reference.Validate(); err != nil {
		return artifact.AuthorizedSemanticArtifactV1{}, fmt.Errorf("%w: invalid reference", ErrSemanticOutputUnavailable)
	}
	var (
		programID, workflowRunID, stepRunID, actionRequestID, toolRunID, providerAttemptID domain.ID
		artifactID, artifactStoreID, publicationOccurrenceID, publicationAttemptID         domain.ID
		stepDefinition, capabilityName, storageKey, contentType                            string
		artifactSize                                                                       int64
		artifactDigest, publicationState                                                   string
		stepOutput, materializedDefinition                                                 []byte
		materializationDigest                                                              string
		storeIncarnation                                                                   domain.ID
		storeBackend, storeMarker                                                          string
		storeMarkerVersion                                                                 int
	)
	err := s.Pool.QueryRow(ctx, `SELECT
		t.program_id,wr.id,sr.id,sr.step_definition_id,sr.capability,sr.output,
		pa.action_request_id,tr.id,tr.provider_attempt_id,
		a.id,a.artifact_store_id,a.storage_key,a.content_type,a.size,a.sha256,
		ap.result_occurrence_id,ap.provider_attempt_id,ap.publication_state,
		ast.incarnation_nonce,ast.backend_kind,ast.marker_format,ast.marker_version,
		wr.materialized_definition,wr.materialization_digest
	FROM step_runs sr
	JOIN workflow_runs wr ON wr.id=sr.workflow_run_id
	JOIN tasks t ON t.id=wr.task_id
	JOIN tool_runs tr ON tr.step_run_id=sr.id AND tr.provider_attempt_id=$3
	JOIN audit_events pa ON pa.id=tr.provider_attempt_id AND pa.event_type='provider_invocation_started'
	JOIN artifacts a ON a.step_run_id=sr.id AND a.tool_run_id=tr.id AND a.id=$2
	JOIN artifact_publications ap ON ap.artifact_id=a.id AND ap.provider_attempt_id=tr.provider_attempt_id
	JOIN artifact_stores ast ON ast.id=a.artifact_store_id
	WHERE sr.id=$1
	  AND a.content_deleted_at IS NULL
	  AND a.cleanup_quarantined_at IS NULL
	  AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())`, request.Reference.SourceStepRunID, request.Reference.SourceArtifactID, request.Reference.SourceProviderAttemptID).Scan(
		&programID, &workflowRunID, &stepRunID, &stepDefinition, &capabilityName, &stepOutput,
		&actionRequestID, &toolRunID, &providerAttemptID,
		&artifactID, &artifactStoreID, &storageKey, &contentType, &artifactSize, &artifactDigest,
		&publicationOccurrenceID, &publicationAttemptID, &publicationState,
		&storeIncarnation, &storeBackend, &storeMarker, &storeMarkerVersion,
		&materializedDefinition, &materializationDigest,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return artifact.AuthorizedSemanticArtifactV1{}, ErrSemanticOutputUnavailable
		}
		return artifact.AuthorizedSemanticArtifactV1{}, err
	}
	reference := request.Reference
	if toolRunID == "" || programID != request.ConsumerProgramID || programID != reference.SourceProgramID || workflowRunID != request.ConsumerWorkflowRunID || workflowRunID != reference.SourceWorkflowRunID || stepRunID != reference.SourceStepRunID || stepDefinition != request.SourceStepDefinition || actionRequestID != reference.SourceActionRequestID || providerAttemptID != reference.SourceProviderAttemptID || publicationAttemptID != reference.SourceProviderAttemptID || publicationOccurrenceID != reference.SourceResultOccurrenceID || artifactID != reference.SourceArtifactID || artifactStoreID != reference.ArtifactStoreID || storageKey != reference.StorageKey || artifactSize != reference.ContentSizeBytes || artifactDigest != reference.ContentSHA256 || contentType != "application/json" || publicationState != string(domain.PublicationAdopted) {
		return artifact.AuthorizedSemanticArtifactV1{}, ErrSemanticOutputUnavailable
	}
	envelope, err := domain.DecodeResultEnvelopeV1(stepOutput)
	if err != nil || envelope.ActionRequestID != actionRequestID || envelope.ResultOccurrenceID != publicationOccurrenceID || envelope.ProviderAttemptID != providerAttemptID || envelope.CapabilityName != capabilityName || envelope.SemanticOutput.Mode != domain.SemanticModeArtifactJSON || envelope.SemanticOutput.ArtifactID != artifactID || envelope.SemanticOutput.ContentSHA256 != artifactDigest || envelope.SemanticOutput.ContentSizeBytes != artifactSize || envelope.SemanticOutput.OutputSchemaSHA256 != reference.OutputSchemaSHA256 {
		return artifact.AuthorizedSemanticArtifactV1{}, ErrSemanticOutputUnavailable
	}
	definition, err := workflow.VerifyMaterialization(json.RawMessage(materializedDefinition), materializationDigest)
	if err != nil || !materializedDependency(definition, request.ConsumerStepDefinition, request.SourceStepDefinition) {
		return artifact.AuthorizedSemanticArtifactV1{}, ErrSemanticOutputUnavailable
	}
	return artifact.AuthorizedSemanticArtifactV1{
		Reference:          domain.ResultArtifactRefV1{ArtifactID: artifactID, ArtifactStoreID: artifactStoreID, StorageKey: storageKey, Role: domain.ArtifactRoleSemanticResult, ContentType: contentType, ContentSizeBytes: artifactSize, ContentSHA256: artifactDigest},
		StoreIdentity:      artifact.StoreIdentity{ArtifactStoreID: artifactStoreID, IncarnationNonce: storeIncarnation, BackendKind: storeBackend, MarkerFormat: storeMarker, MarkerVersion: storeMarkerVersion},
		CapabilityName:     envelope.CapabilityName,
		CapabilityVersion:  envelope.CapabilityVersion,
		OutputSchemaSHA256: envelope.SemanticOutput.OutputSchemaSHA256,
	}, nil
}

func materializedDependency(definition workflow.Definition, consumer, source string) bool {
	steps := make(map[string]workflow.Step, len(definition.Steps))
	for _, step := range definition.Steps {
		steps[step.ID] = step
	}
	if _, ok := steps[consumer]; !ok {
		return false
	}
	if _, ok := steps[source]; !ok {
		return false
	}
	seen := map[string]bool{}
	var visit func(string) bool
	visit = func(id string) bool {
		if seen[id] {
			return false
		}
		seen[id] = true
		for _, dependency := range steps[id].DependsOn {
			if dependency == source || visit(dependency) {
				return true
			}
		}
		return false
	}
	return visit(consumer)
}
