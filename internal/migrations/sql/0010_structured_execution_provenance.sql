ALTER TABLE audit_events
    ADD COLUMN scheduled_execution_id UUID REFERENCES scheduled_executions(id),
    ADD COLUMN scheduler_attempt INTEGER CHECK (scheduler_attempt > 0),
    ADD COLUMN scope_version_id UUID REFERENCES scope_versions(id);

CREATE INDEX audit_events_execution_trace_idx
    ON audit_events(scheduled_execution_id, occurred_at, id)
    WHERE scheduled_execution_id IS NOT NULL;
