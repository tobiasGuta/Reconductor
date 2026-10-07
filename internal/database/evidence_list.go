package database

import (
	"context"
	"errors"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

// ListEvidenceView discovers candidates only inside one existing run, then
// applies the single-artifact authorization policy to every returned item.
func (s *Store) ListEvidenceView(ctx context.Context, workflowRunID domain.ID) ([]artifact.AuthorizedEvidenceArtifactV1, error) {
	if _, err := domain.ParseID(string(workflowRunID)); err != nil || s == nil || s.Pool == nil {
		return nil, artifact.ErrEvidenceUnavailable
	}

	tx, err := s.Pool.BeginTx(ctx, evidenceViewTxOptions)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM workflow_runs WHERE id=$1)`, workflowRunID).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, artifact.ErrEvidenceUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT id FROM artifacts WHERE workflow_run_id=$1 ORDER BY created_at,id`, workflowRunID)
	if err != nil {
		return nil, err
	}
	var candidates []domain.ID
	for rows.Next() {
		var artifactID domain.ID
		if err := rows.Scan(&artifactID); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, artifactID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	result := make([]artifact.AuthorizedEvidenceArtifactV1, 0, len(candidates))
	for _, artifactID := range candidates {
		authorized, err := s.AuthorizeEvidenceView(ctx, workflowRunID, artifactID)
		switch {
		case err == nil:
			result = append(result, authorized)
		case errors.Is(err, artifact.ErrEvidenceUnavailable), errors.Is(err, artifact.ErrEvidenceRestricted):
			continue
		default:
			return nil, err
		}
	}
	return result, nil
}
