ALTER TABLE scheduled_executions
    DROP CONSTRAINT IF EXISTS scheduled_executions_status_check;

ALTER TABLE scheduled_executions
    ADD CONSTRAINT scheduled_executions_status_check
    CHECK (status IN (
        'pending',
        'claimed',
        'running',
        'paused_for_approval',
        'paused_operator',
        'completed',
        'failed',
        'cancelled',
        'blocked_scope_change',
        'approval_rejected',
        'skipped_overlap',
        'interrupted'
    ));

DROP INDEX IF EXISTS scheduled_executions_active_idx;

CREATE INDEX scheduled_executions_active_idx
    ON scheduled_executions(schedule_id, status)
    WHERE status IN ('claimed','running','paused_for_approval','paused_operator');

CREATE UNIQUE INDEX scheduled_executions_workflow_run_uq
    ON scheduled_executions(workflow_run_id)
    WHERE workflow_run_id IS NOT NULL;
