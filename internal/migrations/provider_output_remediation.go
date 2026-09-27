package migrations

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

const providerOutputAuthorityPreMigrationVersion int64 = 20
const providerOutputAuthorityPreMigrationName = "0020_prepared_evidence_ownership.sql"

// ProviderOutputAuthorityRemediation records the one configuration field changed
// by the migration-0021 maintenance operation. The aggregate and set-count limits
// are returned so callers can prove that they were preserved.
type ProviderOutputAuthorityRemediation struct {
	ArtifactStoreID       domain.ID `json:"store_id"`
	PreviousMaxSetBytes   int64     `json:"previous_max_set_bytes"`
	MaxSetBytes           int64     `json:"max_set_bytes"`
	MaxOpenSets           int       `json:"max_open_sets"`
	MaxUnresolvedBytes    int64     `json:"max_unresolved_bytes"`
	SchemaFrontierVersion int64     `json:"schema_frontier_version"`
}

// RemediateProviderOutputAuthority0021 is deliberately narrower than ordinary
// prepared-limit configuration. It operates only at the exact schema-0020
// frontier, only on an existing oversized store configuration, and changes only
// max_set_bytes after proving that durable execution/publication state is drained
// and no oversized prepared evidence would be stranded by migration 0021.
func RemediateProviderOutputAuthority0021(ctx context.Context, db DB, storeID domain.ID, maxSetBytes int64) (ProviderOutputAuthorityRemediation, error) {
	var result ProviderOutputAuthorityRemediation
	if _, err := domain.ParseID(string(storeID)); err != nil {
		return result, fmt.Errorf("migration 0021 remediation requires a canonical configured store ID")
	}
	if maxSetBytes < 1 || maxSetBytes > domain.PreparedSetOutputAuthorityMaxBytes {
		return result, fmt.Errorf("migration 0021 remediation max-set-bytes must be between 1 and %d", domain.PreparedSetOutputAuthorityMaxBytes)
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7212026)`); err != nil {
		return result, fmt.Errorf("acquire migration 0021 remediation lock: %w", err)
	}
	var frontierVersion int64
	var frontierName string
	if err = tx.QueryRow(ctx, `SELECT version,name FROM schema_migrations ORDER BY version DESC LIMIT 1`).Scan(&frontierVersion, &frontierName); err != nil {
		return result, fmt.Errorf("migration 0021 remediation cannot establish schema frontier: %w", err)
	}
	if frontierVersion != providerOutputAuthorityPreMigrationVersion || frontierName != providerOutputAuthorityPreMigrationName {
		return result, fmt.Errorf("migration 0021 remediation requires exact schema frontier %d (%s); found %d (%s)", providerOutputAuthorityPreMigrationVersion, providerOutputAuthorityPreMigrationName, frontierVersion, frontierName)
	}
	// NOWAIT turns evidence of an active writer into an actionable maintenance
	// failure instead of waiting behind a runtime that was supposed to be stopped.
	if _, err = tx.Exec(ctx, `LOCK TABLE step_runs,scheduled_executions,prepared_evidence_sets,artifact_publications IN SHARE MODE NOWAIT`); err != nil {
		return result, fmt.Errorf("migration 0021 remediation could not acquire drained-state locks; stop artifact-producing runtimes and retry: %w", err)
	}
	if _, err = tx.Exec(ctx, `LOCK TABLE artifact_store_prepared_limits IN ACCESS EXCLUSIVE MODE NOWAIT`); err != nil {
		return result, fmt.Errorf("migration 0021 remediation could not lock prepared-store configuration; stop artifact-producing runtimes and retry: %w", err)
	}
	var currentMaxSet int64
	if err = tx.QueryRow(ctx, `SELECT limits.max_open_sets,limits.max_set_bytes,limits.max_unresolved_bytes
		FROM artifact_store_prepared_limits limits
		JOIN artifact_stores stores ON stores.id=limits.artifact_store_id
		WHERE limits.artifact_store_id=$1`, storeID).Scan(&result.MaxOpenSets, &currentMaxSet, &result.MaxUnresolvedBytes); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return result, fmt.Errorf("migration 0021 remediation requires an existing prepared-limit configuration owned by configured store %s", storeID)
		}
		return result, err
	}
	if currentMaxSet <= domain.PreparedSetOutputAuthorityMaxBytes {
		return result, fmt.Errorf("store %s already has migration-0021-compatible max_set_bytes=%d; run platform migrate", storeID, currentMaxSet)
	}
	var activeSteps, activeSchedules, activePrepared, activePublications int64
	if err = tx.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM step_runs WHERE status='running'),
		(SELECT count(*) FROM scheduled_executions WHERE status IN ('claimed','running')),
		(SELECT count(*) FROM prepared_evidence_sets WHERE lifecycle_state IN ('ALLOCATED','SEALED')),
		(SELECT count(*) FROM artifact_publications WHERE publication_state IN ('reserved','publishing','sealed'))`).Scan(
		&activeSteps, &activeSchedules, &activePrepared, &activePublications); err != nil {
		return result, err
	}
	if activeSteps != 0 || activeSchedules != 0 || activePrepared != 0 || activePublications != 0 {
		return result, fmt.Errorf("migration 0021 remediation requires drained execution state: running_steps=%d active_schedules=%d unresolved_prepared_sets=%d unresolved_publications=%d; stop runtimes and use the previous schema-0020-compatible binary to finish recovery", activeSteps, activeSchedules, activePrepared, activePublications)
	}
	var oversizedAllocated, oversizedSealed, oversizedResolved, oversizedQuarantined int64
	if err = tx.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE lifecycle_state='ALLOCATED'),
		count(*) FILTER (WHERE lifecycle_state='SEALED'),
		count(*) FILTER (WHERE lifecycle_state IN ('RESOLVED_ADOPTED','RESOLVED_ABANDONED')),
		count(*) FILTER (WHERE lifecycle_state='QUARANTINED')
		FROM prepared_evidence_sets
		WHERE lifecycle_state<>'CLEANED' AND reserved_capacity_bytes>$1`, domain.PreparedSetOutputAuthorityMaxBytes).Scan(
		&oversizedAllocated, &oversizedSealed, &oversizedResolved, &oversizedQuarantined); err != nil {
		return result, err
	}
	if oversizedAllocated != 0 || oversizedSealed != 0 || oversizedResolved != 0 || oversizedQuarantined != 0 {
		return result, fmt.Errorf("migration 0021 remediation would strand oversized prepared evidence: allocated=%d sealed=%d resolved=%d quarantined=%d; use the previous schema-0020-compatible binary for recovery and cleanup; quarantined evidence has no automatic disposition and must not be deleted or rewritten", oversizedAllocated, oversizedSealed, oversizedResolved, oversizedQuarantined)
	}
	tag, err := tx.Exec(ctx, `UPDATE artifact_store_prepared_limits
		SET max_set_bytes=$2,updated_at=clock_timestamp()
		WHERE artifact_store_id=$1 AND max_set_bytes>$3`, storeID, maxSetBytes, domain.PreparedSetOutputAuthorityMaxBytes)
	if err != nil {
		return result, err
	}
	if tag.RowsAffected() != 1 {
		return result, fmt.Errorf("migration 0021 remediation did not update exactly one oversized configured store")
	}
	if err = tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("commit migration 0021 remediation: %w", err)
	}
	result.ArtifactStoreID = storeID
	result.PreviousMaxSetBytes = currentMaxSet
	result.MaxSetBytes = maxSetBytes
	result.SchemaFrontierVersion = providerOutputAuthorityPreMigrationVersion
	return result, nil
}
