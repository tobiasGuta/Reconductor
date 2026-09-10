package database

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type ArtifactCleanupClaim = artifact.CleanupClaim

func (s *Store) ClaimExpiredArtifacts(ctx context.Context, storeID domain.ID, limit int) ([]artifact.CleanupClaim, error) {
	if _, err := domain.ParseID(string(storeID)); err != nil {
		return nil, fmt.Errorf("configured artifact store ID is not canonical: %w", err)
	}
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("claim batch limit %d must be between 1 and 1000", limit)
	}

	const claimSQL = `
WITH eligible AS (
    SELECT a.id
    FROM artifacts a
    WHERE a.artifact_store_id = $1
      AND a.addressing_version = 1
      AND a.storage_location IS NULL
      AND a.storage_key = ('v1/' || substr(replace(a.id::text, '-', ''), 1, 2) || '/' || a.id::text)
      AND a.expires_at IS NOT NULL
      AND a.expires_at <= statement_timestamp()
      AND a.content_deleted_at IS NULL
      AND a.cleanup_quarantined_at IS NULL
      AND (a.cleanup_retry_after IS NULL OR a.cleanup_retry_after <= statement_timestamp())
      AND (a.cleanup_claim_token IS NULL OR a.cleanup_claimed_at <= statement_timestamp() - interval '15 minutes')
    ORDER BY a.expires_at ASC, a.id ASC
    LIMIT $2
    FOR UPDATE OF a SKIP LOCKED
)
UPDATE artifacts a
SET cleanup_claim_token = gen_random_uuid(),
    cleanup_claimed_at = statement_timestamp(),
    cleanup_retry_after = NULL,
    cleanup_last_error_code = NULL
FROM eligible
WHERE a.id = eligible.id
RETURNING a.id, a.artifact_store_id, a.storage_key, a.cleanup_claim_token, a.cleanup_claimed_at, a.expires_at`

	rows, err := s.Pool.Query(ctx, claimSQL, storeID, limit)
	if err != nil {
		return nil, fmt.Errorf("claim expired artifacts: %w", err)
	}
	defer rows.Close()

	var claims []artifact.CleanupClaim
	for rows.Next() {
		var item artifact.CleanupClaim
		var storeUUID, tokenUUID domain.ID
		if err := rows.Scan(
			&item.ID,
			&storeUUID,
			&item.StorageKey,
			&tokenUUID,
			&item.CleanupClaimedAt,
			&item.ExpiresAt,
		); err != nil {
			return nil, fmt.Errorf("scan claimed artifact: %w", err)
		}
		item.ArtifactStoreID = storeUUID
		item.CleanupClaimToken = tokenUUID
		claims = append(claims, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claimed artifacts: %w", err)
	}
	return claims, nil
}

func (s *Store) FinalizeArtifactCleanup(ctx context.Context, id domain.ID, storeID domain.ID, token domain.ID, observation string) (bool, error) {
	if _, err := domain.ParseID(string(id)); err != nil {
		return false, fmt.Errorf("artifact ID is not canonical: %w", err)
	}
	if _, err := domain.ParseID(string(storeID)); err != nil {
		return false, fmt.Errorf("artifact store ID is not canonical: %w", err)
	}
	if _, err := domain.ParseID(string(token)); err != nil {
		return false, fmt.Errorf("cleanup claim token is not canonical: %w", err)
	}
	if observation != "removed" && observation != "already_absent" {
		return false, fmt.Errorf("invalid delete observation %q: must be 'removed' or 'already_absent'", observation)
	}

	const finalizeSQL = `
WITH finalized AS (
    UPDATE artifacts
    SET content_deleted_at = statement_timestamp(),
        cleanup_claim_token = NULL,
        cleanup_claimed_at = NULL,
        cleanup_retry_after = NULL,
        cleanup_last_error_code = NULL
    WHERE id = $1
      AND artifact_store_id = $2
      AND cleanup_claim_token = $3
      AND content_deleted_at IS NULL
    RETURNING id, task_id, workflow_run_id, step_run_id, tool_run_id, content_deleted_at
),
inserted_audit AS (
    INSERT INTO audit_events(
        id, occurred_at, event_type, component, actor,
        program_id, task_id, workflow_run_id, step_run_id, tool_run_id,
        safe_message, details
    )
    SELECT
        gen_random_uuid(), f.content_deleted_at, 'artifact_content_deleted', 'artifact-cleanup', 'cli',
        t.program_id, f.task_id, f.workflow_run_id, f.step_run_id, f.tool_run_id,
        'expired artifact content tombstoned',
        jsonb_build_object(
            'artifact_id', f.id,
            'artifact_store_id', $2::uuid,
            'delete_observation', $4::text
        )
    FROM finalized f
    JOIN tasks t ON t.id = f.task_id
    RETURNING id
)
SELECT id FROM finalized`

	var finalizedID domain.ID
	err := s.Pool.QueryRow(ctx, finalizeSQL, id, storeID, token, observation).Scan(&finalizedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("finalize artifact cleanup: %w", err)
	}
	return true, nil
}

func (s *Store) RecordArtifactCleanupRetry(ctx context.Context, id domain.ID, storeID domain.ID, token domain.ID, errorCode string) (bool, error) {
	if _, err := domain.ParseID(string(id)); err != nil {
		return false, fmt.Errorf("artifact ID is not canonical: %w", err)
	}
	if _, err := domain.ParseID(string(storeID)); err != nil {
		return false, fmt.Errorf("artifact store ID is not canonical: %w", err)
	}
	if _, err := domain.ParseID(string(token)); err != nil {
		return false, fmt.Errorf("cleanup claim token is not canonical: %w", err)
	}
	if errorCode != "filesystem_io" && errorCode != "durability_sync" {
		return false, fmt.Errorf("invalid retry error code %q: must be 'filesystem_io' or 'durability_sync'", errorCode)
	}

	const retrySQL = `
UPDATE artifacts
SET cleanup_claim_token = NULL,
    cleanup_claimed_at = NULL,
    cleanup_retry_after = statement_timestamp() + interval '5 minutes',
    cleanup_last_error_code = $4
WHERE id = $1
  AND artifact_store_id = $2
  AND cleanup_claim_token = $3
  AND content_deleted_at IS NULL`

	cmdTag, err := s.Pool.Exec(ctx, retrySQL, id, storeID, token, errorCode)
	if err != nil {
		return false, fmt.Errorf("record artifact cleanup retry: %w", err)
	}
	return cmdTag.RowsAffected() == 1, nil
}

func (s *Store) QuarantineArtifactCleanup(ctx context.Context, id domain.ID, storeID domain.ID, token domain.ID, errorCode string) (bool, error) {
	if _, err := domain.ParseID(string(id)); err != nil {
		return false, fmt.Errorf("artifact ID is not canonical: %w", err)
	}
	if _, err := domain.ParseID(string(storeID)); err != nil {
		return false, fmt.Errorf("artifact store ID is not canonical: %w", err)
	}
	if _, err := domain.ParseID(string(token)); err != nil {
		return false, fmt.Errorf("cleanup claim token is not canonical: %w", err)
	}
	if errorCode != "unexpected_entry_type" {
		return false, fmt.Errorf("invalid quarantine error code %q: must be 'unexpected_entry_type'", errorCode)
	}

	const quarantineSQL = `
WITH quarantined AS (
    UPDATE artifacts
    SET cleanup_claim_token = NULL,
        cleanup_claimed_at = NULL,
        cleanup_retry_after = NULL,
        cleanup_quarantined_at = statement_timestamp(),
        cleanup_last_error_code = $4
    WHERE id = $1
      AND artifact_store_id = $2
      AND cleanup_claim_token = $3
      AND content_deleted_at IS NULL
    RETURNING id, task_id, workflow_run_id, step_run_id, tool_run_id, cleanup_quarantined_at
),
inserted_audit AS (
    INSERT INTO audit_events(
        id, occurred_at, event_type, component, actor,
        program_id, task_id, workflow_run_id, step_run_id, tool_run_id,
        safe_message, details
    )
    SELECT
        gen_random_uuid(), q.cleanup_quarantined_at, 'artifact_quarantined', 'artifact-cleanup', 'cli',
        t.program_id, q.task_id, q.workflow_run_id, q.step_run_id, q.tool_run_id,
        'artifact cleanup quarantined',
        jsonb_build_object(
            'artifact_id', q.id,
            'artifact_store_id', $2::uuid,
            'error_code', $4::text
        )
    FROM quarantined q
    JOIN tasks t ON t.id = q.task_id
    RETURNING id
)
SELECT id FROM quarantined`

	var quarantinedID domain.ID
	err := s.Pool.QueryRow(ctx, quarantineSQL, id, storeID, token, errorCode).Scan(&quarantinedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("quarantine artifact cleanup: %w", err)
	}
	return true, nil
}
