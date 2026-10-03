package database

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/launchauthority"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/scope"
)

var ErrLaunchAuthorityConflict = errors.New("launch authority changed or is unavailable")

type ProgramLaunchAuthority struct {
	ProgramID      domain.ID
	ActiveScopeID  *domain.ID
	ActivePolicyID *domain.ID
	Epoch          int64
	Status         string
}

func (s *Store) LaunchAuthority(ctx context.Context, programID domain.ID) (ProgramLaunchAuthority, error) {
	var a ProgramLaunchAuthority
	err := s.Pool.QueryRow(ctx, `SELECT program_id,active_scope_id,active_policy_id,authority_epoch,status
		FROM program_launch_authority WHERE program_id=$1`, programID).Scan(&a.ProgramID, &a.ActiveScopeID, &a.ActivePolicyID, &a.Epoch, &a.Status)
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	return a, nil
}

func boundedAuthorityActor(actor, reason string) error {
	if strings.TrimSpace(actor) == "" || len(actor) > 80 || len(reason) > 256 {
		return fmt.Errorf("launch authority actor or reason is invalid")
	}
	return nil
}

// BeginLaunchAuthorityUpdate commits a BLOCKED epoch before candidate material
// is read or parsed. A malformed candidate therefore cannot leave old READY
// exact authority active.
func (s *Store) BeginLaunchAuthorityUpdate(ctx context.Context, programID domain.ID, expectedEpoch int64, actor, reason string) (int64, error) {
	if err := boundedAuthorityActor(actor, reason); err != nil {
		return 0, err
	}
	if expectedEpoch < 0 {
		return 0, ErrLaunchAuthorityConflict
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if err := pinLaunchProgramParent(ctx, tx, programID); err != nil {
		return 0, err
	}
	var epoch int64
	err = tx.QueryRow(ctx, `UPDATE program_launch_authority SET status='BLOCKED',authority_epoch=authority_epoch+1,
		updated_at=clock_timestamp(),updated_by=$3,reason=$4
		WHERE program_id=$1 AND authority_epoch=$2 AND authority_epoch<9223372036854775807
		RETURNING authority_epoch`, programID, expectedEpoch, actor, reason).Scan(&epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrLaunchAuthorityConflict
	}
	if err != nil {
		return 0, err
	}
	if err := launchAudit(ctx, tx, programID, "exact_launch_authority_blocked", actor, map[string]any{"epoch": epoch, "reason": reason}); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return epoch, nil
}

// PublishLaunchAuthority is a managed update. Failed parsing or persistence
// leaves the previously committed BLOCKED state in place.
func (s *Store) PublishLaunchAuthority(ctx context.Context, programID domain.ID, expectedEpoch int64, actor string,
	includes, excludes []scope.Rule, candidate policy.Policy) (ProgramLaunchAuthority, error) {
	blocked, err := s.BeginLaunchAuthorityUpdate(ctx, programID, expectedEpoch, actor, "publication in progress")
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	sc, err := scope.Compile(includes, excludes)
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	scopeBytes, scopeSHA, scopeDigest, err := launchauthority.ScopeFromCompiled(sc)
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	policyBytes, policySHA, err := launchauthority.PolicyFromPolicy(candidate)
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	return s.activateLaunchMaterial(ctx, programID, blocked, actor, scopeBytes, scopeSHA, scopeDigest, policyBytes, policySHA)
}

// ActivateExistingLaunchAuthority permits an explicit rollback to immutable
// material while still advancing the epoch. It never reuses an old epoch.
func (s *Store) ActivateExistingLaunchAuthority(ctx context.Context, programID domain.ID, expectedEpoch int64,
	actor string, scopeID, policyID domain.ID) (ProgramLaunchAuthority, error) {
	blocked, err := s.BeginLaunchAuthorityUpdate(ctx, programID, expectedEpoch, actor, "revision activation in progress")
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	return s.activateLaunchPair(ctx, programID, blocked, actor, scopeID, policyID)
}

func (s *Store) activateLaunchMaterial(ctx context.Context, programID domain.ID, blockedEpoch int64, actor string,
	scopeBytes []byte, scopeSHA, scopeDigest string, policyBytes []byte, policySHA string) (ProgramLaunchAuthority, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	defer tx.Rollback(ctx)
	if err := pinLaunchProgramParent(ctx, tx, programID); err != nil {
		return ProgramLaunchAuthority{}, err
	}
	if err := requireBlockedEpoch(ctx, tx, programID, blockedEpoch); err != nil {
		return ProgramLaunchAuthority{}, err
	}
	scopeID, policyID := domain.NewID(), domain.NewID()
	_, err = tx.Exec(ctx, `INSERT INTO scopes(id,program_id,version,definition,material_schema,evaluator_revision,canonical_material,material_sha256,scope_digest)
		SELECT $1,$2,COALESCE(MAX(version),0)+1,$3::jsonb,$4,$5,$6,$7,$8 FROM scopes WHERE program_id=$2`,
		scopeID, programID, string(scopeBytes), launchauthority.ScopeSchemaV1, launchauthority.ScopeEvaluatorV1, scopeBytes, scopeSHA, scopeDigest)
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO policies(id,program_id,version,definition,material_schema,evaluator_revision,canonical_material,material_sha256)
		SELECT $1,$2,COALESCE(MAX(version),0)+1,$3::jsonb,$4,$5,$6,$7 FROM policies WHERE program_id=$2`,
		policyID, programID, string(policyBytes), launchauthority.PolicySchemaV1, launchauthority.PolicyEvaluatorV1, policyBytes, policySHA)
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	a, err := activatePairTx(ctx, tx, programID, blockedEpoch, actor, scopeID, policyID)
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ProgramLaunchAuthority{}, err
	}
	return a, nil
}

func (s *Store) activateLaunchPair(ctx context.Context, programID domain.ID, blockedEpoch int64, actor string,
	scopeID, policyID domain.ID) (ProgramLaunchAuthority, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	defer tx.Rollback(ctx)
	if err := pinLaunchProgramParent(ctx, tx, programID); err != nil {
		return ProgramLaunchAuthority{}, err
	}
	a, err := activatePairTx(ctx, tx, programID, blockedEpoch, actor, scopeID, policyID)
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ProgramLaunchAuthority{}, err
	}
	return a, nil
}

func activatePairTx(ctx context.Context, tx pgx.Tx, programID domain.ID, blockedEpoch int64, actor string,
	scopeID, policyID domain.ID) (ProgramLaunchAuthority, error) {
	if err := requireBlockedEpoch(ctx, tx, programID, blockedEpoch); err != nil {
		return ProgramLaunchAuthority{}, err
	}
	pending, err := unresolvedExactScopeCandidate(ctx, tx, programID)
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	if pending {
		return ProgramLaunchAuthority{}, fmt.Errorf("%w: scope candidate awaits acknowledgement", ErrLaunchAuthorityConflict)
	}
	var scopeBytes, policyBytes []byte
	var scopeSHA, policySHA, scopeDigest, programDigest, scopeSchema, scopeEval, policySchema, policyEval string
	if err := tx.QueryRow(ctx, `SELECT canonical_material,material_sha256,scope_digest,material_schema,evaluator_revision
		FROM scopes WHERE id=$1 AND program_id=$2 FOR KEY SHARE NOWAIT`, scopeID, programID).Scan(&scopeBytes, &scopeSHA, &scopeDigest, &scopeSchema, &scopeEval); err != nil {
		return ProgramLaunchAuthority{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT canonical_material,material_sha256,material_schema,evaluator_revision
		FROM policies WHERE id=$1 AND program_id=$2 FOR KEY SHARE NOWAIT`, policyID, programID).Scan(&policyBytes, &policySHA, &policySchema, &policyEval); err != nil {
		return ProgramLaunchAuthority{}, err
	}
	if scopeSchema != launchauthority.ScopeSchemaV1 || scopeEval != launchauthority.ScopeEvaluatorV1 || policySchema != launchauthority.PolicySchemaV1 || policyEval != launchauthority.PolicyEvaluatorV1 {
		return ProgramLaunchAuthority{}, fmt.Errorf("unsupported launch material revision")
	}
	sc, err := launchauthority.DecodeScope(scopeBytes, scopeSHA)
	if err != nil {
		return ProgramLaunchAuthority{}, fmt.Errorf("invalid scope material: %w", err)
	}
	if sc.Digest() != scopeDigest {
		return ProgramLaunchAuthority{}, fmt.Errorf("scope material digest differs from stored scope digest")
	}
	if _, err := launchauthority.DecodePolicy(policyBytes, policySHA); err != nil {
		return ProgramLaunchAuthority{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT scope_digest FROM programs WHERE id=$1`, programID).Scan(&programDigest); err != nil {
		return ProgramLaunchAuthority{}, err
	}
	if programDigest != scopeDigest {
		return ProgramLaunchAuthority{}, fmt.Errorf("scope material differs from current program scope")
	}
	var epoch int64
	err = tx.QueryRow(ctx, `UPDATE program_launch_authority SET active_scope_id=$3,active_policy_id=$4,status='READY',
		authority_epoch=authority_epoch+1,updated_at=clock_timestamp(),updated_by=$5,reason='published'
		WHERE program_id=$1 AND authority_epoch=$2 AND status='BLOCKED' AND authority_epoch<9223372036854775807
		RETURNING authority_epoch`, programID, blockedEpoch, scopeID, policyID, actor).Scan(&epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProgramLaunchAuthority{}, ErrLaunchAuthorityConflict
	}
	if err != nil {
		return ProgramLaunchAuthority{}, err
	}
	if err := launchAudit(ctx, tx, programID, "exact_launch_authority_published", actor, map[string]any{
		"epoch": epoch, "scope_id": scopeID, "scope_sha256": scopeSHA, "policy_id": policyID, "policy_sha256": policySHA}); err != nil {
		return ProgramLaunchAuthority{}, err
	}
	return ProgramLaunchAuthority{ProgramID: programID, ActiveScopeID: &scopeID, ActivePolicyID: &policyID, Epoch: epoch, Status: "READY"}, nil
}

// A pending expansion can also carry tighter exclusions. Only acknowledgement
// is a durable resolution in the current scope-version model.
func unresolvedExactScopeCandidate(ctx context.Context, tx pgx.Tx, programID domain.ID) (bool, error) {
	var pending bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM scope_versions
		WHERE program_id=$1 AND expands_scope=true AND acknowledged_at IS NULL)`, programID).Scan(&pending)
	return pending, err
}

func pinLaunchProgramParent(ctx context.Context, tx pgx.Tx, programID domain.ID) error {
	var id domain.ID
	// NOWAIT prevents a reverse wait against an existing scope-version ->
	// program -> authority writer. The caller may retry without external effect.
	return tx.QueryRow(ctx, `SELECT id FROM programs WHERE id=$1 FOR KEY SHARE NOWAIT`, programID).Scan(&id)
}

func requireBlockedEpoch(ctx context.Context, tx pgx.Tx, programID domain.ID, epoch int64) error {
	var status string
	var actual int64
	err := tx.QueryRow(ctx, `SELECT status,authority_epoch FROM program_launch_authority WHERE program_id=$1 FOR UPDATE`, programID).Scan(&status, &actual)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrLaunchAuthorityConflict
	}
	if err != nil {
		return err
	}
	if status != "BLOCKED" || actual != epoch {
		return ErrLaunchAuthorityConflict
	}
	return nil
}

func invalidateLaunchAuthorityTx(ctx context.Context, tx pgx.Tx, programID domain.ID, actor, reason string) error {
	if strings.TrimSpace(actor) == "" || len(actor) > 80 {
		actor = "scope-writer"
	}
	if err := boundedAuthorityActor(actor, reason); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE program_launch_authority SET status='BLOCKED',authority_epoch=authority_epoch+1,
		updated_at=clock_timestamp(),updated_by=$2,reason=$3 WHERE program_id=$1 AND authority_epoch<9223372036854775807`, programID, actor, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrLaunchAuthorityConflict
	}
	return nil
}

func launchAudit(ctx context.Context, tx pgx.Tx, programID domain.ID, eventType, actor string, details any) error {
	_, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,safe_message,details)
		VALUES($1,$2,'platform',$3,$4,$5,$6)`, domain.NewID(), eventType, actor, programID, eventType, mustJSON(details))
	return err
}
