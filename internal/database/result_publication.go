package database

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/resultadmission"
)

type ResultCommitUnknownError struct {
	Operation string
	Err       error
}

func (e *ResultCommitUnknownError) Error() string {
	return e.Operation + " commit outcome is unknown: " + e.Err.Error()
}
func (e *ResultCommitUnknownError) Unwrap() error              { return e.Err }
func (e *ResultCommitUnknownError) CommitOutcomeUnknown() bool { return true }

func requireCurrentPreparedAttempt(lineage lockedResultLineage, admission *capability.ResultAdmissionProvenance) error {
	if lineage.stepStatus != domain.StepRunning && lineage.stepStatus != domain.StepRetryable {
		return resultConflict(lineage.scheduled, resultFenceStepNotAdmittingResult, "step does not admit a result")
	}
	if admission == nil || admission.StepAttempt < 1 || admission.StepAttempt != lineage.attemptCount {
		return resultConflict(lineage.scheduled, resultFenceStaleProviderStepAttempt, "result is not from the exact current attempt")
	}
	return nil
}

func (s *Store) PersistPreProviderFailure(ctx context.Context, programID domain.ID, step domain.StepRun, summary string) error {
	if step.Status != domain.StepFailed && step.Status != domain.StepCancelled || step.CompletedAt == nil || len(step.Output) != 0 {
		return fmt.Errorf("invalid bounded pre-provider failure")
	}
	step.ErrorDetails = domain.BoundUTF8(step.ErrorDetails, domain.SafeMessageMaxBytes)
	summary = domain.BoundUTF8(summary, domain.SafeMessageMaxBytes)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	lineage, err := lockResultLineage(ctx, tx, programID, step)
	if err != nil {
		return err
	}
	if lineage.stepStatus != domain.StepRunning && lineage.stepStatus != domain.StepRetryable {
		return resultConflict(lineage.scheduled, resultFenceStepNotAdmittingResult, "step does not admit pre-provider failure")
	}
	if err := ensureNoUnresolvedPrepared(ctx, tx, step.ID); err != nil {
		return err
	}
	if err := lockConflictingResultTools(ctx, tx, step.ID, nil, lineage.scheduled); err != nil {
		return err
	}
	details, _ := json.Marshal(struct {
		Version int               `json:"version"`
		Status  domain.StepStatus `json:"status"`
		Code    string            `json:"error_code"`
	}{1, step.Status, step.ErrorClassification})
	if len(details) > domain.DiagnosticMaxBytes {
		return fmt.Errorf("bounded pre-provider audit exceeds limit")
	}
	tag, err := tx.Exec(ctx, `UPDATE step_runs SET status=$2,output=NULL,error_classification=$3,error_details=$4,completed_at=$5 WHERE id=$1 AND workflow_run_id=$6 AND idempotency_key=$7 AND status=$8`, step.ID, step.Status, step.ErrorClassification, step.ErrorDetails, step.CompletedAt, step.WorkflowRunID, step.IdempotencyKey, lineage.stepStatus)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return resultConflict(lineage.scheduled, resultFenceConcurrentStepChange, "step changed before pre-provider failure persistence")
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,capability,safe_message,details) VALUES($1,'tool_execution','worker','worker',$2,$3,$4,$5,$6,$7,$8)`, domain.NewID(), lineage.taskID, programID, step.WorkflowRunID, step.ID, step.Capability, summary, details)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return &ResultCommitUnknownError{Operation: "pre-provider failure", Err: err}
	}
	return nil
}

func (s *Store) ReserveCompiledResult(ctx context.Context, programID domain.ID, step domain.StepRun, compiled resultadmission.CompiledResult, admission *capability.ResultAdmissionProvenance, identity artifact.StoreIdentity) error {
	if len(compiled.Artifacts) < 1 || len(compiled.Artifacts) > domain.ResultArtifactReferenceMaxCount {
		return fmt.Errorf("invalid compiler publication set")
	}
	if admission == nil || compiled.PreparedSetID == "" || compiled.PreparedSetID != admission.PreparedSetID || compiled.ManifestID != admission.ManifestID {
		return fmt.Errorf("sealed prepared evidence is required before reservation")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var preparedState domain.PreparedEvidenceState
	lineage, err := lockResultLineage(ctx, tx, programID, step)
	if err != nil {
		return err
	}
	var preparedResult domain.ID
	var preparedStore, preparedIncarnation domain.ID
	var preparedMembers int
	if err := tx.QueryRow(ctx, `SELECT lifecycle_state,result_occurrence_id,artifact_store_id,store_incarnation_nonce,member_count FROM prepared_evidence_sets WHERE id=$1 AND manifest_id=$2 AND provider_attempt_id=$3 FOR UPDATE`, compiled.PreparedSetID, compiled.ManifestID, compiled.Envelope.ProviderAttemptID).Scan(&preparedState, &preparedResult, &preparedStore, &preparedIncarnation, &preparedMembers); err != nil {
		return fmt.Errorf("lock sealed prepared evidence: %w", err)
	}
	if preparedState != domain.PreparedSealed || preparedResult != compiled.ResultOccurrenceID || preparedStore != identity.ArtifactStoreID || preparedIncarnation != identity.IncarnationNonce || preparedMembers != len(compiled.Artifacts) {
		return fmt.Errorf("prepared evidence does not exactly match reservation")
	}
	dummy := domain.ActionResult{RequestID: compiled.Envelope.ActionRequestID, Status: string(compiled.Envelope.Status), Summary: compiled.Envelope.Summary}
	tool := compiled.ToolRun
	if err := lockAndValidateProviderResult(ctx, tx, lineage, programID, step, &tool, dummy, admission); err != nil {
		return err
	}
	if lineage.stepStatus != domain.StepRunning && lineage.stepStatus != domain.StepRetryable {
		return resultConflict(lineage.scheduled, resultFenceStepNotAdmittingResult, "step does not admit reservation")
	}
	if err := requireCurrentPreparedAttempt(lineage, admission); err != nil {
		return err
	}
	var registered domain.ArtifactStoreRegistration
	if err := tx.QueryRow(ctx, `SELECT id,incarnation_nonce,backend_kind,marker_format,marker_version FROM artifact_stores WHERE id=$1 FOR SHARE`, identity.ArtifactStoreID).Scan(&registered.ID, &registered.IncarnationNonce, &registered.BackendKind, &registered.MarkerFormat, &registered.MarkerVersion); err != nil {
		return err
	}
	if artifact.StoreIdentityFrom(domain.ArtifactStore{ArtifactStoreRegistration: registered}) != identity {
		return fmt.Errorf("artifact store identity changed before reservation")
	}
	ownerKind := domain.ClaimOwnerDirectCLI
	if admission != nil && admission.QueueJobID != nil {
		ownerKind = domain.ClaimOwnerQueueWorker
	} else if _, ok := scheduledExecutionFenceFromContext(ctx); ok {
		ownerKind = domain.ClaimOwnerScheduler
	}
	ownerID, token := domain.NewID(), domain.NewID()
	for ordinal, item := range compiled.Artifacts {
		sum, err := hex.DecodeString(item.Reference.ContentSHA256)
		if err != nil || len(sum) != 32 {
			return fmt.Errorf("invalid prepared digest")
		}
		tag, err := tx.Exec(ctx, `INSERT INTO artifact_publications(id,provider_attempt_id,publication_ordinal,result_occurrence_id,artifact_id,artifact_store_id,storage_key,content_type,content_size_bytes,content_sha256,publication_state,origin_owner_instance_id,owner_kind,owner_instance_id,publication_token,fence_generation,lease_duration_ms,lease_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'reserved',$11,$12,$11,$13,1,$14::integer,clock_timestamp()+$14::integer * INTERVAL '1 millisecond')`, item.PublicationID, compiled.Envelope.ProviderAttemptID, ordinal, compiled.ResultOccurrenceID, item.Reference.ArtifactID, item.Reference.ArtifactStoreID, item.Reference.StorageKey, item.Reference.ContentType, item.Reference.ContentSizeBytes, item.Reference.ContentSHA256, ownerID, ownerKind, token, int(domain.StepAttemptLeaseDefault/time.Millisecond))
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("reservation did not insert exact publication")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		if matched, reconcileErr := s.compiledPublicationSetMatches(ctx, compiled, domain.PublicationReserved); reconcileErr == nil && matched {
			return nil
		} else {
			return &ResultCommitUnknownError{Operation: "reservation", Err: errors.Join(err, reconcileErr)}
		}
	}
	return nil
}

func (s *Store) compiledPublicationSetMatches(ctx context.Context, compiled resultadmission.CompiledResult, state domain.PublicationState) (bool, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,publication_ordinal,artifact_id,artifact_store_id,storage_key,content_size_bytes,content_sha256,publication_state FROM artifact_publications WHERE provider_attempt_id=$1 AND result_occurrence_id=$2 ORDER BY publication_ordinal`, compiled.Envelope.ProviderAttemptID, compiled.ResultOccurrenceID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		if index >= len(compiled.Artifacts) {
			return false, nil
		}
		var id, artifactID, storeID domain.ID
		var ordinal int
		var key, digest string
		var size int64
		var actual domain.PublicationState
		if err := rows.Scan(&id, &ordinal, &artifactID, &storeID, &key, &size, &digest, &actual); err != nil {
			return false, err
		}
		want := compiled.Artifacts[index]
		if id != want.PublicationID || ordinal != index || artifactID != want.Reference.ArtifactID || storeID != want.Reference.ArtifactStoreID || key != want.Reference.StorageKey || size != want.Reference.ContentSizeBytes || digest != want.Reference.ContentSHA256 || actual != state {
			return false, nil
		}
		index++
	}
	return index == len(compiled.Artifacts), rows.Err()
}

func (s *Store) CompiledPublicationStates(ctx context.Context, compiled resultadmission.CompiledResult) ([]domain.PublicationState, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,publication_ordinal,artifact_id,artifact_store_id,storage_key,content_size_bytes,content_sha256,publication_state FROM artifact_publications WHERE provider_attempt_id=$1 AND result_occurrence_id=$2 ORDER BY publication_ordinal`, compiled.Envelope.ProviderAttemptID, compiled.ResultOccurrenceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := make([]domain.PublicationState, 0, len(compiled.Artifacts))
	for rows.Next() {
		ordinal := len(states)
		if ordinal >= len(compiled.Artifacts) {
			return nil, fmt.Errorf("publication set has extra member")
		}
		var id, artifactID, storeID domain.ID
		var actualOrdinal int
		var key, digest string
		var size int64
		var state domain.PublicationState
		if err := rows.Scan(&id, &actualOrdinal, &artifactID, &storeID, &key, &size, &digest, &state); err != nil {
			return nil, err
		}
		want := compiled.Artifacts[ordinal]
		if id != want.PublicationID || actualOrdinal != ordinal || artifactID != want.Reference.ArtifactID || storeID != want.Reference.ArtifactStoreID || key != want.Reference.StorageKey || size != want.Reference.ContentSizeBytes || digest != want.Reference.ContentSHA256 {
			return nil, fmt.Errorf("publication set member %d identity contradiction", ordinal)
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(states) != 0 && len(states) != len(compiled.Artifacts) {
		return nil, fmt.Errorf("publication set is partial")
	}
	return states, nil
}

func (s *Store) MarkCompiledArtifactPublishing(ctx context.Context, compiled resultadmission.CompiledResult, ordinal int) error {
	return s.transitionCompiledArtifact(ctx, compiled, ordinal, domain.PublicationReserved, domain.PublicationPublishing)
}
func (s *Store) SealCompiledArtifact(ctx context.Context, compiled resultadmission.CompiledResult, ordinal int) error {
	return s.transitionCompiledArtifact(ctx, compiled, ordinal, domain.PublicationPublishing, domain.PublicationSealed)
}
func (s *Store) transitionCompiledArtifact(ctx context.Context, compiled resultadmission.CompiledResult, ordinal int, from, to domain.PublicationState) error {
	if ordinal < 0 || ordinal >= len(compiled.Artifacts) {
		return fmt.Errorf("publication ordinal is outside set")
	}
	item := compiled.Artifacts[ordinal]
	column := "publishing_at"
	if to == domain.PublicationSealed {
		column = "sealed_at"
	}
	query := fmt.Sprintf(`UPDATE artifact_publications SET publication_state=$2,%s=clock_timestamp(),updated_at=clock_timestamp(),row_version=row_version+1 WHERE id=$1 AND provider_attempt_id=$3 AND result_occurrence_id=$4 AND publication_ordinal=$5 AND artifact_id=$6 AND artifact_store_id=$7 AND storage_key=$8 AND content_size_bytes=$9 AND content_sha256=$10 AND publication_state=$11`, column)
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	tag, err := tx.Exec(ctx, query, item.PublicationID, to, compiled.Envelope.ProviderAttemptID, compiled.ResultOccurrenceID, ordinal, item.Reference.ArtifactID, item.Reference.ArtifactStoreID, item.Reference.StorageKey, item.Reference.ContentSizeBytes, item.Reference.ContentSHA256, from)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("publication %d did not transition %s to %s", ordinal, from, to)
	}
	if err := tx.Commit(ctx); err != nil {
		var actual domain.PublicationState
		reconcileErr := s.Pool.QueryRow(ctx, `SELECT publication_state FROM artifact_publications WHERE id=$1 AND provider_attempt_id=$2 AND result_occurrence_id=$3 AND publication_ordinal=$4`, item.PublicationID, compiled.Envelope.ProviderAttemptID, compiled.ResultOccurrenceID, ordinal).Scan(&actual)
		if reconcileErr == nil && actual == to {
			return nil
		}
		return &ResultCommitUnknownError{Operation: string(to) + " publication transition", Err: errors.Join(err, reconcileErr)}
	}
	return nil
}

func (s *Store) TerminalizeCompiledResult(ctx context.Context, compiled resultadmission.CompiledResult, state domain.PublicationState, reason string) error {
	if state != domain.PublicationAbandoned && state != domain.PublicationQuarantined {
		return fmt.Errorf("invalid publication terminalization")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	rows, err := tx.Query(ctx, `SELECT publication_ordinal FROM artifact_publications WHERE provider_attempt_id=$1 AND result_occurrence_id=$2 ORDER BY publication_ordinal FOR UPDATE`, compiled.Envelope.ProviderAttemptID, compiled.ResultOccurrenceID)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var ordinal int
		if err := rows.Scan(&ordinal); err != nil {
			rows.Close()
			return err
		}
		if ordinal != count {
			rows.Close()
			return fmt.Errorf("publication set is not contiguous")
		}
		count++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if count != len(compiled.Artifacts) {
		return fmt.Errorf("publication terminalization set mismatch")
	}
	var quarantine any
	if state == domain.PublicationQuarantined {
		if reason == "" {
			reason = "publication_unverifiable"
		}
		quarantine = reason
	}
	tag, err := tx.Exec(ctx, `UPDATE artifact_publications SET publication_state=$3,abandoned_at=CASE WHEN $3='abandoned' THEN clock_timestamp() END,quarantined_at=CASE WHEN $3='quarantined' THEN clock_timestamp() END,quarantine_reason_code=$4,owner_kind=NULL,owner_instance_id=NULL,publication_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp(),row_version=row_version+1 WHERE provider_attempt_id=$1 AND result_occurrence_id=$2 AND publication_state IN ('reserved','publishing','sealed')`, compiled.Envelope.ProviderAttemptID, compiled.ResultOccurrenceID, state, quarantine)
	if err != nil {
		return err
	}
	if int(tag.RowsAffected()) != count {
		return fmt.Errorf("publication set terminalization was partial")
	}
	preparedTarget := domain.PreparedResolvedAbandoned
	if state == domain.PublicationQuarantined {
		preparedTarget = domain.PreparedQuarantined
	}
	tag, err = tx.Exec(ctx, `UPDATE prepared_evidence_sets SET lifecycle_state=$2,quarantine_reason_code=$3,resolved_at=CASE WHEN $2='RESOLVED_ABANDONED' THEN clock_timestamp() END,quarantined_at=CASE WHEN $2='QUARANTINED' THEN clock_timestamp() END,updated_at=clock_timestamp() WHERE id=$1 AND lifecycle_state='SEALED'`, compiled.PreparedSetID, preparedTarget, quarantine)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("prepared evidence terminalization was partial")
	}
	if err := tx.Commit(ctx); err != nil {
		matched, reconcileErr := s.compiledPublicationSetMatches(ctx, compiled, state)
		var actual domain.PreparedEvidenceState
		preparedErr := s.Pool.QueryRow(ctx, `SELECT lifecycle_state FROM prepared_evidence_sets WHERE id=$1`, compiled.PreparedSetID).Scan(&actual)
		if reconcileErr == nil && preparedErr == nil && matched && actual == preparedTarget {
			return nil
		}
		return &ResultCommitUnknownError{Operation: "publication terminalization", Err: errors.Join(err, reconcileErr, preparedErr)}
	}
	return nil
}

func (s *Store) AdoptCompiledResult(ctx context.Context, programID domain.ID, step domain.StepRun, compiled resultadmission.CompiledResult, admission *capability.ResultAdmissionProvenance, retention time.Duration) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	lineage, err := lockResultLineage(ctx, tx, programID, step)
	if err != nil {
		return err
	}
	if err := requireCurrentPreparedAttempt(lineage, admission); err != nil {
		return err
	}
	dummy := domain.ActionResult{RequestID: compiled.Envelope.ActionRequestID, Status: string(compiled.Envelope.Status), Summary: compiled.Envelope.Summary}
	tool := compiled.ToolRun
	if err := lockAndValidateProviderResult(ctx, tx, lineage, programID, step, &tool, dummy, admission); err != nil {
		return err
	}
	if err := lockConflictingResultTools(ctx, tx, step.ID, &tool, lineage.scheduled); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id,publication_ordinal,artifact_id,artifact_store_id,storage_key,content_type,content_size_bytes,content_sha256,publication_state FROM artifact_publications WHERE provider_attempt_id=$1 AND result_occurrence_id=$2 ORDER BY publication_ordinal FOR UPDATE`, compiled.Envelope.ProviderAttemptID, compiled.ResultOccurrenceID)
	if err != nil {
		return err
	}
	index := 0
	for rows.Next() {
		var id, artifactID, storeID domain.ID
		var ordinal int
		var key, contentType, digest string
		var size int64
		var state domain.PublicationState
		if err := rows.Scan(&id, &ordinal, &artifactID, &storeID, &key, &contentType, &size, &digest, &state); err != nil {
			rows.Close()
			return err
		}
		if index >= len(compiled.Artifacts) {
			rows.Close()
			return fmt.Errorf("publication set has extra member")
		}
		want := compiled.Artifacts[index]
		if ordinal != index || id != want.PublicationID || artifactID != want.Reference.ArtifactID || storeID != want.Reference.ArtifactStoreID || key != want.Reference.StorageKey || contentType != want.Reference.ContentType || size != want.Reference.ContentSizeBytes || digest != want.Reference.ContentSHA256 || state != domain.PublicationSealed {
			rows.Close()
			return fmt.Errorf("publication set member %d does not exactly match sealed compiler set", index)
		}
		index++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if index != len(compiled.Artifacts) {
		return fmt.Errorf("publication set has missing member")
	}
	tag, err := tx.Exec(ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,tool_version,sanitized_arguments,execution_environment,started_at,completed_at,exit_code,timed_out,stdout_artifact_id,stderr_artifact_id,provider_attempt_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(id) DO NOTHING`, tool.ID, tool.StepRunID, tool.Capability, tool.Provider, tool.ToolVersion, tool.SanitizedArguments, tool.ExecutionEnvironment, tool.StartedAt, tool.CompletedAt, tool.ExitCode, tool.TimedOut, tool.StdoutArtifactID, tool.StderrArtifactID, tool.ProviderAttemptID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return resultConflict(lineage.scheduled, resultFenceToolResultConflict, "tool result already exists")
	}
	created := time.Now().UTC()
	var expires *time.Time
	if retention > 0 {
		v := created.Add(retention)
		expires = &v
	}
	artifacts := make([]domain.Artifact, 0, len(compiled.Artifacts))
	for _, item := range compiled.Artifacts {
		storeID, key := item.Reference.ArtifactStoreID, item.Reference.StorageKey
		a := domain.Artifact{ID: item.Reference.ArtifactID, TaskID: lineage.taskID, WorkflowRunID: step.WorkflowRunID, StepRunID: step.ID, ToolRunID: tool.ID, Type: item.ArtifactType, ContentType: item.Reference.ContentType, Size: item.Reference.ContentSizeBytes, SHA256: item.Reference.ContentSHA256, AddressingVersion: 1, ArtifactStoreID: &storeID, StorageKey: &key, CreatedAt: created, ExpiresAt: expires, RedactionState: "redacted"}
		artifacts = append(artifacts, a)
		tag, err := tx.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,created_at,expires_at,redaction_state,sensitive) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,$11,$12,$13,$14,false) ON CONFLICT(id) DO NOTHING`, a.ID, a.TaskID, a.WorkflowRunID, a.StepRunID, a.ToolRunID, a.Type, a.ContentType, a.Size, a.SHA256, a.ArtifactStoreID, a.StorageKey, a.CreatedAt, a.ExpiresAt, a.RedactionState)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return resultConflict(lineage.scheduled, resultFenceArtifactResultConflict, "artifact metadata already exists")
		}
	}
	acceptedID, err := persistProviderResultAcceptedWithID(ctx, tx, compiled.AcceptedEventID, compiled.Envelope.ProviderAttemptID, tool.ID)
	if err != nil {
		return err
	}
	if compiled.Envelope.Status == domain.ResultStatusSucceeded && compiled.Envelope.SemanticOutput.ProjectionState == domain.ProjectionComplete {
		var semantic artifact.ReplayableSource
		for _, item := range compiled.Artifacts {
			if item.Reference.Role == domain.ArtifactRoleSemanticResult {
				semantic = item.Source
				break
			}
		}
		if err := runStreamingResultProjectors(ctx, tx, programID, step, tool, compiled.Envelope, semantic, artifacts, acceptedID); err != nil {
			return err
		}
	}
	audit := domain.ResultAuditProjectionV1{Version: 1, ActionRequestID: compiled.Envelope.ActionRequestID, ResultOccurrenceID: compiled.ResultOccurrenceID, ProviderAttemptID: compiled.Envelope.ProviderAttemptID, Status: compiled.Envelope.Status, SemanticMode: compiled.Envelope.SemanticOutput.Mode, SemanticArtifactID: compiled.Envelope.SemanticOutput.ArtifactID, ArtifactCount: len(compiled.Artifacts), EnvelopeSHA256: compiled.EnvelopeSHA256}
	auditJSON, _ := json.Marshal(audit)
	if len(auditJSON) > domain.DiagnosticMaxBytes {
		return fmt.Errorf("bounded result audit exceeds 4096 bytes")
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,task_id,workflow_run_id,step_run_id,tool_run_id,action_request_id,step_attempt,queue_job_id,provider_attempt_id,capability,provider,safe_message,details) SELECT $1,'tool_execution','worker','worker',wr.task_id,$2,$3,$4,pa.action_request_id,pa.step_attempt,pa.queue_job_id,$5,$6,$7,$8,$9 FROM workflow_runs wr JOIN audit_events pa ON pa.id=$5 AND pa.event_type='provider_invocation_started' WHERE wr.id=$2`, domain.NewID(), step.WorkflowRunID, step.ID, tool.ID, compiled.Envelope.ProviderAttemptID, step.Capability, tool.Provider, compiled.Envelope.Summary, auditJSON)
	if err != nil {
		return err
	}
	attemptCount := lineage.attemptCount
	completed := step.CompletedAt
	if compiled.Envelope.Status == domain.ResultStatusRetryable {
		completed = nil
	}
	errorClass, errorDetails := "", ""
	if compiled.Envelope.Error != nil {
		errorClass = compiled.Envelope.Error.Code
		errorDetails = compiled.Envelope.Error.Message
	}
	tag, err = tx.Exec(ctx, `UPDATE step_runs SET status=$2,output=$3,error_classification=$4,error_details=$5,completed_at=$6,attempt_count=$7 WHERE id=$1 AND workflow_run_id=$8 AND idempotency_key=$9 AND status=$10`, step.ID, compiled.Envelope.Status, compiled.EnvelopeJSON, errorClass, errorDetails, completed, attemptCount, step.WorkflowRunID, step.IdempotencyKey, lineage.stepStatus)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return resultConflict(lineage.scheduled, resultFenceConcurrentStepChange, "step changed before adoption")
	}
	if compiled.Envelope.CapabilityName == "report.changes" {
		reference := domain.ResultSummaryReferenceV1{Version: domain.ResultSummaryReferenceVersionV1, SourceStepRunID: step.ID, ActionRequestID: compiled.Envelope.ActionRequestID, ResultOccurrenceID: compiled.Envelope.ResultOccurrenceID, SemanticArtifactID: compiled.Envelope.SemanticOutput.ArtifactID, SemanticSHA256: compiled.Envelope.SemanticOutput.ContentSHA256, SemanticSizeBytes: compiled.Envelope.SemanticOutput.ContentSizeBytes, SafeSummary: compiled.Envelope.Summary}
		summary, err := json.Marshal(reference)
		if err != nil || len(summary) > domain.WorkflowSummaryMaxBytes {
			return fmt.Errorf("bounded report summary reference is invalid")
		}
		tag, err = tx.Exec(ctx, `UPDATE workflow_runs SET summary=$2 WHERE id=$1`, step.WorkflowRunID, summary)
		if err != nil {
			return fmt.Errorf("persist bounded report summary reference: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("persist bounded report summary reference: workflow run not found")
		}
	}
	tag, err = tx.Exec(ctx, `UPDATE artifact_publications SET publication_state='adopted',adopted_at=clock_timestamp(),owner_kind=NULL,owner_instance_id=NULL,publication_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp(),row_version=row_version+1 WHERE provider_attempt_id=$1 AND result_occurrence_id=$2 AND publication_state='sealed'`, compiled.Envelope.ProviderAttemptID, compiled.ResultOccurrenceID)
	if err != nil {
		return err
	}
	if int(tag.RowsAffected()) != len(compiled.Artifacts) {
		return fmt.Errorf("adoption publication transition was partial")
	}
	tag, err = tx.Exec(ctx, `UPDATE prepared_evidence_sets SET lifecycle_state='RESOLVED_ADOPTED',resolved_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND provider_attempt_id=$2 AND result_occurrence_id=$3 AND lifecycle_state='SEALED'`, compiled.PreparedSetID, compiled.Envelope.ProviderAttemptID, compiled.ResultOccurrenceID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("prepared evidence adoption transition was partial")
	}
	if err := tx.Commit(ctx); err != nil {
		matched, reconcileErr := s.compiledPublicationSetMatches(ctx, compiled, domain.PublicationAdopted)
		var actual domain.PreparedEvidenceState
		preparedErr := s.Pool.QueryRow(ctx, `SELECT lifecycle_state FROM prepared_evidence_sets WHERE id=$1`, compiled.PreparedSetID).Scan(&actual)
		if reconcileErr == nil && preparedErr == nil && matched && actual == domain.PreparedResolvedAdopted {
			return nil
		}
		return &ResultCommitUnknownError{Operation: "adoption", Err: errors.Join(err, reconcileErr, preparedErr)}
	}
	return nil
}
