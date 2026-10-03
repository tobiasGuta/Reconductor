package database

import (
	"context"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

// ExactApprovalState is a read-only lifecycle projection. It grants no authority;
// DecideExactApproval remains the sole decision path and rechecks current state.
type ExactApprovalState struct {
	ApprovalID           domain.ID
	Decision, Status     string
	CreatedAt, ExpiresAt time.Time
	RevokedAt            *time.Time
	Decisionable         bool
}

const exactApprovalStateSelect = `SELECT a.id,a.decision,e.created_at,a.expires_at,a.revoked_at,
	clock_timestamp(),d.state FROM approvals a
	JOIN exact_actions e ON e.action_request_id=a.action_request_id
	JOIN exact_dispatch_attempts d ON d.provider_attempt_id=a.bound_provider_attempt_id`

func scanExactApprovalState(scan func(...any) error) (ExactApprovalState, error) {
	var out ExactApprovalState
	var now time.Time
	var dispatch string
	if err := scan(&out.ApprovalID, &out.Decision, &out.CreatedAt, &out.ExpiresAt, &out.RevokedAt, &now, &dispatch); err != nil {
		return out, err
	}
	out.Status = out.Decision
	if out.RevokedAt != nil {
		out.Status = "revoked"
	} else if out.Decision != "rejected" && !out.ExpiresAt.After(now) {
		out.Status = "expired"
	}
	out.Decisionable = out.Status == "pending" && dispatch == "UNDISPATCHED"
	return out, nil
}

func (s *Store) GetExactApprovalState(ctx context.Context, id domain.ID) (ExactApprovalState, error) {
	return scanExactApprovalState(s.Pool.QueryRow(ctx, exactApprovalStateSelect+` WHERE a.id=$1 AND a.approval_kind='exact_action'`, id).Scan)
}

// ListExactApprovalStates uses immutable creation time/id for cursor pagination.
// It returns at most 101 rows; callers display 100 and use the extra as has-more.
// No request target, mutable step input, or raw evidence enters this projection.
func (s *Store) ListExactApprovalStates(ctx context.Context, programID, after domain.ID) ([]ExactApprovalState, error) {
	rows, err := s.Pool.Query(ctx, exactApprovalStateSelect+` WHERE a.approval_kind='exact_action'
	AND ($1='' OR e.program_id=NULLIF($1,'')::uuid)
	AND ($2='' OR (e.created_at,a.id)<(SELECT e2.created_at,a2.id FROM approvals a2
	 JOIN exact_actions e2 ON e2.action_request_id=a2.action_request_id
	 WHERE a2.id=NULLIF($2,'')::uuid AND a2.approval_kind='exact_action'
	 AND ($1='' OR e2.program_id=NULLIF($1,'')::uuid)))
	ORDER BY e.created_at DESC,a.id DESC LIMIT 101`, string(programID), string(after))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ExactApprovalState, 0)
	for rows.Next() {
		item, err := scanExactApprovalState(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
