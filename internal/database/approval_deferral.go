package database

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

// The scheduler root is locked first (when present), then workflow and steps,
// as in result admission. Holding the workflow excludes new prepared allocations.
func lockApprovalWorkflow(ctx context.Context, tx pgx.Tx, runID domain.ID) error {
	var id domain.ID
	if err := tx.QueryRow(ctx, `SELECT id FROM workflow_runs WHERE id=$1 FOR UPDATE`, runID).Scan(&id); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id FROM step_runs WHERE workflow_run_id=$1 ORDER BY id FOR UPDATE`, runID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&id); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Same conservative current-attempt predicate used by workflow checkpoint
// admission. ALLOCATED and QUARANTINED remain retained, just as for scheduling.
func hasUnresolvedWorkflowPrepared(ctx context.Context, tx pgx.Tx, runID domain.ID) (bool, error) {
	var pending bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM prepared_evidence_sets p JOIN step_runs s ON s.id=p.step_run_id
		WHERE s.workflow_run_id=$1 AND p.step_attempt=s.attempt_count AND p.lifecycle_state IN ('ALLOCATED','SEALED','QUARANTINED'))`, runID).Scan(&pending)
	return pending, err
}

func commitApprovalDecision(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return &ResultCommitUnknownError{Operation: "approval decision and deferred terminalization", Err: err}
	}
	return nil
}

// The durable rejected approval itself is the pending-work locator. This read
// is only a candidate filter; DecideApproval rechecks under authoritative locks.
// Excluding unresolved candidates prevents retained evidence starving progress.
func (s *Store) ReconcileDeferredApprovalRejections(ctx context.Context, limit int) error {
	if limit < 1 {
		return nil
	}
	rows, err := s.Pool.Query(ctx, `SELECT a.id,COALESCE(a.decided_by,'workflow-operator') FROM approvals a
		JOIN step_runs sr ON sr.id=a.request_id JOIN workflow_runs wr ON wr.id=sr.workflow_run_id
		WHERE a.decision='rejected' AND sr.status='awaiting_approval' AND wr.status IN ('running','paused')
		AND NOT EXISTS(SELECT 1 FROM prepared_evidence_sets p JOIN step_runs sibling ON sibling.id=p.step_run_id
		 WHERE sibling.workflow_run_id=wr.id AND p.step_attempt=sibling.attempt_count AND p.lifecycle_state IN ('ALLOCATED','SEALED','QUARANTINED'))
		ORDER BY a.id LIMIT $1`, limit)
	if err != nil {
		return err
	}
	type candidate struct {
		id    domain.ID
		actor string
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.actor); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, c := range candidates {
		if err := s.DecideApproval(ctx, c.id, "rejected", c.actor); err != nil {
			return err
		}
	}
	return nil
}
