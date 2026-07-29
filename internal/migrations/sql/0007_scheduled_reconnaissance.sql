CREATE TABLE IF NOT EXISTS schedules (
    id UUID PRIMARY KEY,
    program_id UUID NOT NULL REFERENCES programs(id),
    name TEXT NOT NULL,
    workflow_name TEXT NOT NULL,
    objective TEXT NOT NULL,
    cron_expression TEXT NOT NULL,
    timezone TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    headless BOOLEAN NOT NULL DEFAULT false,
    created_by TEXT NOT NULL,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(program_id, name)
);

CREATE INDEX IF NOT EXISTS schedules_due_idx ON schedules(enabled, next_run_at) WHERE enabled = true;

CREATE TABLE IF NOT EXISTS scheduled_executions (
    id UUID PRIMARY KEY,
    schedule_id UUID NOT NULL REFERENCES schedules(id),
    planned_at TIMESTAMPTZ NOT NULL,
    trigger_source TEXT NOT NULL CHECK (trigger_source IN ('scheduled','run_now','resume')),
    status TEXT NOT NULL CHECK (status IN ('pending','claimed','running','paused_for_approval','completed','failed','cancelled','blocked_scope_change','approval_rejected','skipped_overlap','interrupted')),
    task_id UUID REFERENCES tasks(id),
    workflow_run_id UUID REFERENCES workflow_runs(id),
    scope_version_id UUID REFERENCES scope_versions(id),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_expires_at TIMESTAMPTZ,
    error_classification TEXT NOT NULL DEFAULT '',
    error_summary TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS scheduled_executions_schedule_planned_uq
    ON scheduled_executions(schedule_id, planned_at)
    WHERE trigger_source = 'scheduled';
CREATE INDEX IF NOT EXISTS scheduled_executions_claim_idx
    ON scheduled_executions(status, planned_at, created_at)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS scheduled_executions_active_idx
    ON scheduled_executions(schedule_id, status)
    WHERE status IN ('claimed','running','paused_for_approval');
CREATE INDEX IF NOT EXISTS scheduled_executions_history_idx
    ON scheduled_executions(schedule_id, planned_at DESC, created_at DESC);

CREATE TABLE IF NOT EXISTS change_items (
    id UUID PRIMARY KEY,
    program_id UUID NOT NULL REFERENCES programs(id),
    workflow_run_id UUID NOT NULL REFERENCES workflow_runs(id),
    scheduled_execution_id UUID REFERENCES scheduled_executions(id),
    kind TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    priority TEXT NOT NULL CHECK (priority IN ('high','medium','low')),
    title TEXT NOT NULL,
    safe_summary TEXT NOT NULL,
    reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    previous_value JSONB,
    current_value JSONB,
    source_capabilities TEXT[] NOT NULL DEFAULT '{}',
    evidence_artifact_ids UUID[] NOT NULL DEFAULT '{}',
    observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(workflow_run_id, kind, entity_type, entity_key)
);

CREATE INDEX IF NOT EXISTS change_items_program_priority_idx
    ON change_items(program_id, priority, observed_at DESC);
CREATE INDEX IF NOT EXISTS change_items_run_idx
    ON change_items(workflow_run_id, created_at);

CREATE TABLE IF NOT EXISTS change_reviews (
    id UUID PRIMARY KEY,
    change_item_id UUID NOT NULL REFERENCES change_items(id),
    disposition TEXT NOT NULL CHECK (disposition IN ('unreviewed','interesting','investigating','expected_change','not_relevant','resolved')),
    note TEXT NOT NULL DEFAULT '',
    reviewed_by TEXT NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(change_item_id)
);

CREATE INDEX IF NOT EXISTS change_reviews_disposition_idx
    ON change_reviews(disposition, reviewed_at DESC);
