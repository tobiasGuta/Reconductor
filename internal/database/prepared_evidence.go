package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/resultadmission"
)

type PreparedAdmissionLimitError struct {
	Reason string
}

type PreparedEvidenceStatus struct {
	MaxOpenSets        int
	MaxSetBytes        int64
	MaxUnresolvedBytes int64
	OpenSets           int
	UnresolvedBytes    int64
}

func (s PreparedEvidenceStatus) RequireAdmissionCapacity() error {
	if s.MaxOpenSets < 1 || s.MaxSetBytes < 1 || s.MaxUnresolvedBytes < s.MaxSetBytes || s.OpenSets < 0 || s.UnresolvedBytes < 0 {
		return fmt.Errorf("prepared evidence limits are invalid")
	}
	if s.OpenSets >= s.MaxOpenSets {
		return &PreparedAdmissionLimitError{Reason: "maximum open set count reached; run artifact-store prepared-recover"}
	}
	if s.UnresolvedBytes > s.MaxUnresolvedBytes-s.MaxSetBytes {
		return &PreparedAdmissionLimitError{Reason: "maximum unresolved byte reservation reached; run artifact-store prepared-recover"}
	}
	return nil
}

func (s *Store) PreparedEvidenceStatus(ctx context.Context, storeID domain.ID) (PreparedEvidenceStatus, error) {
	if _, err := domain.ParseID(string(storeID)); err != nil {
		return PreparedEvidenceStatus{}, fmt.Errorf("prepared evidence status requires a canonical store ID")
	}
	var status PreparedEvidenceStatus
	err := s.Pool.QueryRow(ctx, `SELECT limits.max_open_sets,limits.max_set_bytes,limits.max_unresolved_bytes,
		count(sets.id) FILTER (WHERE sets.lifecycle_state<>'CLEANED'),
		COALESCE(sum(sets.reserved_capacity_bytes) FILTER (WHERE sets.lifecycle_state<>'CLEANED'),0)
		FROM artifact_store_prepared_limits limits
		LEFT JOIN prepared_evidence_sets sets ON sets.artifact_store_id=limits.artifact_store_id
		WHERE limits.artifact_store_id=$1
		GROUP BY limits.max_open_sets,limits.max_set_bytes,limits.max_unresolved_bytes`, storeID).Scan(
		&status.MaxOpenSets, &status.MaxSetBytes, &status.MaxUnresolvedBytes, &status.OpenSets, &status.UnresolvedBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return PreparedEvidenceStatus{}, fmt.Errorf("prepared evidence limits are not configured for store %s; run artifact-store prepared-limits", storeID)
	}
	if err != nil {
		return PreparedEvidenceStatus{}, err
	}
	return status, nil
}

func (s *Store) RequirePreparedEvidenceReady(ctx context.Context, storeID domain.ID) (PreparedEvidenceStatus, error) {
	status, err := s.PreparedEvidenceStatus(ctx, storeID)
	if err != nil {
		return PreparedEvidenceStatus{}, err
	}
	if err := status.RequireAdmissionCapacity(); err != nil {
		return status, err
	}
	return status, nil
}

func (s *Store) ConfigurePreparedEvidenceLimits(ctx context.Context, storeID domain.ID, maxOpen int, maxSetBytes, maxUnresolvedBytes int64) error {
	if _, err := domain.ParseID(string(storeID)); err != nil || maxOpen < 1 || maxOpen > 1_000_000 || maxSetBytes < 1 || maxSetBytes > 1<<40 || maxUnresolvedBytes < maxSetBytes || maxUnresolvedBytes > 1<<50 {
		return fmt.Errorf("prepared evidence limits are outside accepted bounds")
	}
	tag, err := s.Pool.Exec(ctx, `INSERT INTO artifact_store_prepared_limits(artifact_store_id,max_open_sets,max_set_bytes,max_unresolved_bytes)
		VALUES($1,$2,$3,$4) ON CONFLICT (artifact_store_id) DO UPDATE SET max_open_sets=EXCLUDED.max_open_sets,max_set_bytes=EXCLUDED.max_set_bytes,max_unresolved_bytes=EXCLUDED.max_unresolved_bytes,updated_at=clock_timestamp()`, storeID, maxOpen, maxSetBytes, maxUnresolvedBytes)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("prepared evidence limit configuration did not affect exact store")
	}
	return nil
}

func (e *PreparedAdmissionLimitError) Error() string {
	return "prepared evidence admission is full: " + e.Reason
}

type PreparedSetRecord = domain.PreparedSetRecord

// Called with the authoritative StepRun locked. A retry must not supersede an
// attempt whose durable evidence still has no authoritative resolution.
func ensureNoUnresolvedPrepared(ctx context.Context, tx pgx.Tx, stepID domain.ID) error {
	var pending bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM prepared_evidence_sets p JOIN step_runs s ON s.id=p.step_run_id
		WHERE s.id=$1 AND p.step_attempt=s.attempt_count AND p.lifecycle_state IN ('ALLOCATED','SEALED','QUARANTINED'))`, stepID).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return &domain.UnresolvedPersistenceError{Err: fmt.Errorf("current attempt has unresolved prepared evidence")}
	}
	return nil
}

func (s *Store) AllocateProviderInvocation(ctx context.Context, record capability.ProviderInvocationStartRecord, identity artifact.StoreIdentity) (capability.ProviderInvocationAdmission, error) {
	if err := identity.Validate(); err != nil {
		return capability.ProviderInvocationAdmission{}, err
	}
	if record.ActionRequestID == "" || record.ExecutionAuthorizationEventID == "" || record.StepAttempt < 1 {
		return capability.ProviderInvocationAdmission{}, fmt.Errorf("prepared provider allocation requires exact action, authorization, and attempt identities")
	}
	attemptID, setID, manifestID := domain.NewID(), domain.NewID(), domain.NewID()
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return capability.ProviderInvocationAdmission{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var registered artifact.StoreIdentity
	step := domain.StepRun{ID: record.StepRunID, WorkflowRunID: record.WorkflowRunID, Capability: record.Capability}
	if err := tx.QueryRow(ctx, `SELECT idempotency_key FROM step_runs WHERE id=$1`, step.ID).Scan(&step.IdempotencyKey); err != nil {
		return capability.ProviderInvocationAdmission{}, err
	}
	lineage, err := lockResultLineage(ctx, tx, record.ProgramID, step)
	if err != nil {
		return capability.ProviderInvocationAdmission{}, err
	}
	if err := requireCurrentPreparedAttempt(lineage, &capability.ResultAdmissionProvenance{StepAttempt: record.StepAttempt}); err != nil {
		return capability.ProviderInvocationAdmission{}, err
	}
	if err := ensureNoUnresolvedPrepared(ctx, tx, step.ID); err != nil {
		return capability.ProviderInvocationAdmission{}, err
	}
	var maxOpen int
	var maxSet, maxUnresolved int64
	err = tx.QueryRow(ctx, `SELECT stores.id,stores.incarnation_nonce,stores.backend_kind,stores.marker_format,stores.marker_version,limits.max_open_sets,limits.max_set_bytes,limits.max_unresolved_bytes
		FROM artifact_store_prepared_limits limits
		JOIN artifact_stores stores ON stores.id=limits.artifact_store_id
		WHERE limits.artifact_store_id=$1
		FOR UPDATE OF limits`, identity.ArtifactStoreID).Scan(&registered.ArtifactStoreID, &registered.IncarnationNonce, &registered.BackendKind, &registered.MarkerFormat, &registered.MarkerVersion, &maxOpen, &maxSet, &maxUnresolved)
	if errors.Is(err, pgx.ErrNoRows) {
		return capability.ProviderInvocationAdmission{}, fmt.Errorf("prepared evidence limits are not configured for store %s", identity.ArtifactStoreID)
	}
	if err != nil {
		return capability.ProviderInvocationAdmission{}, err
	}
	if registered != identity {
		return capability.ProviderInvocationAdmission{}, fmt.Errorf("prepared evidence store identity changed before allocation")
	}
	var openSets int
	var unresolvedBytes int64
	if err := tx.QueryRow(ctx, `SELECT count(*),COALESCE(sum(reserved_capacity_bytes),0) FROM prepared_evidence_sets WHERE artifact_store_id=$1 AND lifecycle_state<>'CLEANED'`, identity.ArtifactStoreID).Scan(&openSets, &unresolvedBytes); err != nil {
		return capability.ProviderInvocationAdmission{}, err
	}
	if openSets >= maxOpen {
		return capability.ProviderInvocationAdmission{}, &PreparedAdmissionLimitError{Reason: "maximum open set count reached; run artifact-store prepared-recover"}
	}
	if maxSet > maxUnresolved-unresolvedBytes {
		return capability.ProviderInvocationAdmission{}, &PreparedAdmissionLimitError{Reason: "maximum unresolved byte reservation reached; run artifact-store prepared-recover"}
	}
	tag, err := insertProviderInvocationStarted(ctx, tx, attemptID, record)
	if err != nil {
		return capability.ProviderInvocationAdmission{}, err
	}
	if tag.RowsAffected() != 1 {
		return capability.ProviderInvocationAdmission{}, fmt.Errorf("execution authorization event is not an exact execution-phase allow for action %s", record.ActionRequestID)
	}
	tag, err = tx.Exec(ctx, `INSERT INTO prepared_evidence_sets(
		id,manifest_id,owner_kind,provider_attempt_id,program_id,task_id,workflow_run_id,step_run_id,
		action_request_id,step_attempt,artifact_store_id,store_incarnation_nonce,lifecycle_state,reserved_capacity_bytes)
		VALUES($1,$2,'provider_attempt',$3,$4,$5,$6,$7,$8,$9,$10,$11,'ALLOCATED',$12)`,
		setID, manifestID, attemptID, record.ProgramID, record.TaskID, record.WorkflowRunID, record.StepRunID,
		record.ActionRequestID, record.StepAttempt, identity.ArtifactStoreID, identity.IncarnationNonce, maxSet)
	if err != nil {
		return capability.ProviderInvocationAdmission{}, err
	}
	if tag.RowsAffected() != 1 {
		return capability.ProviderInvocationAdmission{}, fmt.Errorf("prepared evidence allocation did not insert exact set")
	}
	admission := capability.ProviderInvocationAdmission{ProviderAttemptID: attemptID, PreparedSetID: setID, ManifestID: manifestID, ReservedCapacityBytes: maxSet}
	if err := tx.Commit(ctx); err != nil {
		reconciled, reconcileErr := s.reconcileProviderAllocation(ctx, record, identity, admission)
		if reconcileErr == nil && reconciled.ProviderAttemptID != "" {
			return reconciled, nil
		}
		return capability.ProviderInvocationAdmission{}, &ResultCommitUnknownError{Operation: "provider attempt and prepared-set allocation", Err: errors.Join(err, reconcileErr)}
	}
	return admission, nil
}

func (s *Store) reconcileProviderAllocation(ctx context.Context, record capability.ProviderInvocationStartRecord, identity artifact.StoreIdentity, expected capability.ProviderInvocationAdmission) (capability.ProviderInvocationAdmission, error) {
	var admission capability.ProviderInvocationAdmission
	err := s.Pool.QueryRow(ctx, `SELECT provider_attempt_id,id,manifest_id,reserved_capacity_bytes
		FROM prepared_evidence_sets
		WHERE action_request_id=$1 AND step_attempt=$2 AND program_id=$3 AND task_id=$4 AND workflow_run_id=$5 AND step_run_id=$6
		  AND artifact_store_id=$7 AND store_incarnation_nonce=$8 AND owner_kind='provider_attempt' AND lifecycle_state='ALLOCATED'
		  AND provider_attempt_id=$9 AND id=$10 AND manifest_id=$11 AND reserved_capacity_bytes=$12
		  AND EXISTS (SELECT 1 FROM audit_events a WHERE a.id=$9 AND a.event_type='provider_invocation_started' AND a.execution_authorization_event_id=$13)`,
		record.ActionRequestID, record.StepAttempt, record.ProgramID, record.TaskID, record.WorkflowRunID, record.StepRunID,
		identity.ArtifactStoreID, identity.IncarnationNonce, expected.ProviderAttemptID, expected.PreparedSetID, expected.ManifestID, expected.ReservedCapacityBytes, record.ExecutionAuthorizationEventID).Scan(&admission.ProviderAttemptID, &admission.PreparedSetID, &admission.ManifestID, &admission.ReservedCapacityBytes)
	if err != nil {
		return capability.ProviderInvocationAdmission{}, err
	}
	return admission, nil
}

func (s *Store) SealPreparedEvidence(ctx context.Context, record resultadmission.PreparedSealRecord) error {
	if err := record.StoreIdentity.Validate(); err != nil {
		return err
	}
	if err := record.Manifest.Validate(); err != nil {
		return err
	}
	if record.Manifest.SetID != record.Admission.PreparedSetID || record.Manifest.ManifestID != record.Admission.ManifestID || record.Manifest.ProviderAttemptID == nil || *record.Manifest.ProviderAttemptID != record.Admission.ProviderAttemptID || record.Manifest.ResultOccurrenceID == "" || record.Manifest.ArtifactStoreID != record.StoreIdentity.ArtifactStoreID || record.Manifest.StoreIncarnationNonce != record.StoreIdentity.IncarnationNonce || record.ManifestSize < 1 || record.ManifestSize > domain.PreparedManifestMaxBytes || len(record.ManifestSHA256) != 64 || record.ContentBytes < record.ManifestSize {
		return fmt.Errorf("prepared seal identity or bounds mismatch")
	}
	if record.Admission.ProviderTerminalEventID == "" {
		return fmt.Errorf("prepared seal requires preallocated provider terminal event identity")
	}
	if err := record.Outcome.Validate(); err != nil {
		return err
	}
	if sealed, err := s.preparedSealMatches(ctx, record); err == nil && sealed {
		return nil
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var state domain.PreparedEvidenceState
	if request, recovering := domain.PreparedRecoveryRequestFromContext(ctx); recovering {
		if request.SetID != record.Admission.PreparedSetID || request.ManifestID != record.Admission.ManifestID || request.ManifestSHA256 != record.ManifestSHA256 || request.ResultOccurrenceID != record.Manifest.ResultOccurrenceID || request.TerminalEventID != record.Admission.ProviderTerminalEventID {
			return fmt.Errorf("recovery seal request identity mismatch")
		}
		var step domain.StepRun
		var programID domain.ID
		if err := tx.QueryRow(ctx, `SELECT p.program_id,s.id,s.workflow_run_id,s.capability,s.idempotency_key FROM prepared_evidence_sets p JOIN step_runs s ON s.id=p.step_run_id WHERE p.id=$1`, request.SetID).Scan(&programID, &step.ID, &step.WorkflowRunID, &step.Capability, &step.IdempotencyKey); err != nil {
			return err
		}
		if _, err := lockResultLineage(ctx, tx, programID, step); err != nil {
			return err
		}
	}
	err = tx.QueryRow(ctx, `SELECT lifecycle_state FROM prepared_evidence_sets
		WHERE id=$1 AND manifest_id=$2 AND provider_attempt_id=$3 AND artifact_store_id=$4 AND store_incarnation_nonce=$5 FOR UPDATE`,
		record.Admission.PreparedSetID, record.Admission.ManifestID, record.Admission.ProviderAttemptID, record.StoreIdentity.ArtifactStoreID, record.StoreIdentity.IncarnationNonce).Scan(&state)
	if err != nil {
		return err
	}
	if state != domain.PreparedAllocated {
		return fmt.Errorf("prepared evidence set is %s, not ALLOCATED", state)
	}
	eventType, safeMessage, err := providerTerminalEvent(record.Outcome)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO audit_events(
		id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,
		scheduled_execution_id,scheduler_attempt,provider_attempt_id,capability,provider,safe_message,details)
		SELECT $1,$2,'provider',provider_start.actor,provider_start.task_id,provider_start.program_id,
			provider_start.workflow_run_id,provider_start.step_run_id,provider_start.scheduled_execution_id,
			provider_start.scheduler_attempt,provider_start.id,provider_start.capability,provider_start.provider,$3,'{}'::jsonb
		FROM audit_events provider_start WHERE provider_start.id=$4 AND provider_start.event_type='provider_invocation_started'`,
		record.Admission.ProviderTerminalEventID, eventType, safeMessage, record.Admission.ProviderAttemptID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("provider attempt cannot record exact terminal event")
	}
	manifestKey, _ := domain.PreparedManifestKey(record.Admission.PreparedSetID)
	tag, err = tx.Exec(ctx, `UPDATE prepared_evidence_sets SET lifecycle_state='SEALED',
		result_occurrence_id=$3,provider_terminal_event_id=$4,manifest_storage_key=$5,manifest_size_bytes=$6,
		manifest_sha256=$7,member_count=$8,content_size_bytes=$2,sealed_at=clock_timestamp(),updated_at=clock_timestamp()
		WHERE id=$1 AND lifecycle_state='ALLOCATED' AND reserved_capacity_bytes >= $2`,
		record.Admission.PreparedSetID, record.ContentBytes, record.Manifest.ResultOccurrenceID, record.Admission.ProviderTerminalEventID,
		manifestKey, record.ManifestSize, record.ManifestSHA256, len(record.Manifest.Members))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("prepared evidence set did not transition ALLOCATED to SEALED")
	}
	if err := tx.Commit(ctx); err != nil {
		if sealed, reconcileErr := s.preparedSealMatches(ctx, record); reconcileErr == nil && sealed {
			return nil
		} else {
			return &ResultCommitUnknownError{Operation: "prepared evidence sealing", Err: errors.Join(err, reconcileErr)}
		}
	}
	return nil
}

func (s *Store) preparedSealMatches(ctx context.Context, record resultadmission.PreparedSealRecord) (bool, error) {
	manifestKey, _ := domain.PreparedManifestKey(record.Admission.PreparedSetID)
	var count int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM prepared_evidence_sets sets
		JOIN audit_events terminal ON terminal.id=sets.provider_terminal_event_id AND terminal.provider_attempt_id=sets.provider_attempt_id
		WHERE sets.id=$1 AND sets.manifest_id=$2 AND sets.provider_attempt_id=$3 AND sets.artifact_store_id=$4
		  AND sets.store_incarnation_nonce=$5 AND sets.lifecycle_state='SEALED' AND sets.result_occurrence_id=$6
		  AND sets.provider_terminal_event_id=$7 AND sets.manifest_storage_key=$8 AND sets.manifest_size_bytes=$9
		  AND sets.manifest_sha256=$10 AND sets.member_count=$11 AND sets.content_size_bytes=$12`,
		record.Admission.PreparedSetID, record.Admission.ManifestID, record.Admission.ProviderAttemptID, record.StoreIdentity.ArtifactStoreID,
		record.StoreIdentity.IncarnationNonce, record.Manifest.ResultOccurrenceID, record.Admission.ProviderTerminalEventID, manifestKey,
		record.ManifestSize, record.ManifestSHA256, len(record.Manifest.Members), record.ContentBytes).Scan(&count)
	return count == 1, err
}

func (s *Store) QuarantinePreparedEvidence(ctx context.Context, setID domain.ID, reason string) error {
	if _, err := domain.ParseID(string(setID)); err != nil || reason == "" || len(reason) > 64 {
		return fmt.Errorf("invalid prepared evidence quarantine")
	}
	var current domain.PreparedEvidenceState
	var currentReason *string
	if err := s.Pool.QueryRow(ctx, `SELECT lifecycle_state,quarantine_reason_code FROM prepared_evidence_sets WHERE id=$1`, setID).Scan(&current, &currentReason); err == nil && current == domain.PreparedQuarantined && currentReason != nil && *currentReason == reason {
		return nil
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	tag, err := tx.Exec(ctx, `UPDATE prepared_evidence_sets SET lifecycle_state='QUARANTINED',quarantine_reason_code=$2,quarantined_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND lifecycle_state IN ('ALLOCATED','SEALED')`, setID, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("prepared evidence set was not quarantine-eligible")
	}
	if err := tx.Commit(ctx); err != nil {
		if reconcileErr := s.Pool.QueryRow(ctx, `SELECT lifecycle_state,quarantine_reason_code FROM prepared_evidence_sets WHERE id=$1`, setID).Scan(&current, &currentReason); reconcileErr == nil && current == domain.PreparedQuarantined && currentReason != nil && *currentReason == reason {
			return nil
		} else {
			return &ResultCommitUnknownError{Operation: "prepared evidence quarantine", Err: errors.Join(err, reconcileErr)}
		}
	}
	return nil
}

func (s *Store) PreparedSet(ctx context.Context, setID domain.ID) (PreparedSetRecord, error) {
	var record PreparedSetRecord
	err := s.Pool.QueryRow(ctx, `SELECT id,manifest_id,provider_attempt_id,failure_finalization_record_id,program_id,task_id,
		workflow_run_id,step_run_id,action_request_id,step_attempt,artifact_store_id,store_incarnation_nonce,lifecycle_state,
		reserved_capacity_bytes,result_occurrence_id,provider_terminal_event_id,manifest_storage_key,manifest_size_bytes,
		manifest_sha256,member_count,content_size_bytes,quarantine_reason_code,nonadmission_details FROM prepared_evidence_sets WHERE id=$1`, setID).Scan(
		&record.ID, &record.ManifestID, &record.ProviderAttemptID, &record.FailureFinalizationID, &record.ProgramID, &record.TaskID,
		&record.WorkflowRunID, &record.StepRunID, &record.ActionRequestID, &record.StepAttempt, &record.ArtifactStoreID,
		&record.StoreIncarnationNonce, &record.State, &record.ReservedCapacityBytes, &record.ResultOccurrenceID,
		&record.ProviderTerminalEventID, &record.ManifestStorageKey, &record.ManifestSizeBytes, &record.ManifestSHA256,
		&record.MemberCount, &record.ContentSizeBytes, &record.QuarantineReasonCode, &record.NonadmissionDetails)
	return record, err
}

func (s *Store) ListPreparedEvidence(ctx context.Context, storeID, incarnation domain.ID, limit int) ([]domain.PreparedSetRecord, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("prepared evidence recovery limit is outside bounds")
	}
	rows, err := s.Pool.Query(ctx, `SELECT id,manifest_id,provider_attempt_id,failure_finalization_record_id,program_id,task_id,
		workflow_run_id,step_run_id,action_request_id,step_attempt,artifact_store_id,store_incarnation_nonce,lifecycle_state,
		reserved_capacity_bytes,result_occurrence_id,provider_terminal_event_id,manifest_storage_key,manifest_size_bytes,
		manifest_sha256,member_count,content_size_bytes,quarantine_reason_code,nonadmission_details FROM prepared_evidence_sets
		WHERE artifact_store_id=$1 AND store_incarnation_nonce=$2 AND lifecycle_state IN ('ALLOCATED','SEALED','RESOLVED_ADOPTED','RESOLVED_ABANDONED')
		ORDER BY updated_at,id LIMIT $3`, storeID, incarnation, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]domain.PreparedSetRecord, 0)
	for rows.Next() {
		var record domain.PreparedSetRecord
		if err := rows.Scan(&record.ID, &record.ManifestID, &record.ProviderAttemptID, &record.FailureFinalizationID, &record.ProgramID, &record.TaskID,
			&record.WorkflowRunID, &record.StepRunID, &record.ActionRequestID, &record.StepAttempt, &record.ArtifactStoreID,
			&record.StoreIncarnationNonce, &record.State, &record.ReservedCapacityBytes, &record.ResultOccurrenceID,
			&record.ProviderTerminalEventID, &record.ManifestStorageKey, &record.ManifestSizeBytes, &record.ManifestSHA256,
			&record.MemberCount, &record.ContentSizeBytes, &record.QuarantineReasonCode, &record.NonadmissionDetails); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) MarkPreparedEvidenceCleaned(ctx context.Context, setID domain.ID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	tag, err := tx.Exec(ctx, `UPDATE prepared_evidence_sets SET lifecycle_state='CLEANED',reserved_capacity_bytes=0,cleaned_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$1 AND lifecycle_state IN ('RESOLVED_ADOPTED','RESOLVED_ABANDONED')`, setID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		var state domain.PreparedEvidenceState
		var capacity int64
		if reconcileErr := tx.QueryRow(ctx, `SELECT lifecycle_state,reserved_capacity_bytes FROM prepared_evidence_sets WHERE id=$1`, setID).Scan(&state, &capacity); reconcileErr == nil && state == domain.PreparedCleaned && capacity == 0 {
			return nil
		}
		return fmt.Errorf("prepared evidence set is not resolved-cleanup eligible")
	}
	if err := tx.Commit(ctx); err != nil {
		var state domain.PreparedEvidenceState
		var capacity int64
		reconcileErr := s.Pool.QueryRow(ctx, `SELECT lifecycle_state,reserved_capacity_bytes FROM prepared_evidence_sets WHERE id=$1`, setID).Scan(&state, &capacity)
		if reconcileErr == nil && state == domain.PreparedCleaned && capacity == 0 {
			return nil
		}
		return &ResultCommitUnknownError{Operation: "prepared evidence cleanup", Err: errors.Join(err, reconcileErr)}
	}
	return nil
}
