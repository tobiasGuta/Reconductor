LOCK TABLE step_runs, scheduled_executions, prepared_evidence_sets, artifact_publications IN SHARE MODE;
LOCK TABLE artifact_store_prepared_limits IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM step_runs WHERE status='running')
       OR EXISTS (SELECT 1 FROM scheduled_executions WHERE status IN ('claimed','running'))
       OR EXISTS (SELECT 1 FROM prepared_evidence_sets WHERE lifecycle_state IN ('ALLOCATED','SEALED'))
       OR EXISTS (SELECT 1 FROM artifact_publications WHERE publication_state IN ('reserved','publishing','sealed')) THEN
        RAISE EXCEPTION USING
            MESSAGE = 'cannot apply provider output authority ceiling while execution or publication state is active',
            HINT = 'stop artifact-producing runtimes and use the previous schema-0020-compatible binary to finish prepared recovery before retrying migration 0021';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM prepared_evidence_sets
        WHERE lifecycle_state <> 'CLEANED'
          AND reserved_capacity_bytes > 8388608
    ) THEN
        RAISE EXCEPTION USING
            MESSAGE = 'cannot apply provider output authority ceiling: oversized legacy prepared evidence remains',
            HINT = 'use the previous schema-0020-compatible binary for recovery and cleanup; do not delete, resize, resolve, or quarantine evidence to force the migration';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM artifact_store_prepared_limits
        WHERE max_set_bytes > 8388608
    ) THEN
        RAISE EXCEPTION USING
            MESSAGE = 'cannot apply provider output authority ceiling: artifact_store_prepared_limits contains max_set_bytes above 8388608 bytes',
            HINT = 'for each oversized configured store run: platform artifact-store prepared-limits-remediate-0021 --max-set-bytes 8388608 --confirm-artifact-runtimes-stopped; then retry platform migrate';
    END IF;
END
$$;

ALTER TABLE artifact_store_prepared_limits
    DROP CONSTRAINT artifact_store_prepared_limits_set_ck,
    ADD CONSTRAINT artifact_store_prepared_limits_set_ck
        CHECK (max_set_bytes BETWEEN 1 AND 8388608);
