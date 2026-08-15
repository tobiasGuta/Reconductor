ALTER TABLE audit_events
    ADD COLUMN action_request_id UUID,
    ADD COLUMN step_attempt INTEGER CHECK (step_attempt > 0),
    ADD COLUMN queue_job_id UUID,
    ADD COLUMN execution_authorization_event_id UUID REFERENCES audit_events(id),
    ADD COLUMN provider_attempt_id UUID REFERENCES audit_events(id),
    ADD CONSTRAINT audit_events_provider_start_provenance_check CHECK (
        event_type <> 'provider_invocation_started'
        OR (
            action_request_id IS NOT NULL
            AND execution_authorization_event_id IS NOT NULL
            AND provider_attempt_id IS NULL
        )
    ),
    ADD CONSTRAINT audit_events_provider_terminal_provenance_check CHECK (
        event_type NOT IN (
            'provider_invocation_succeeded',
            'provider_invocation_failed',
            'provider_invocation_cancelled'
        )
        OR provider_attempt_id IS NOT NULL
    );

ALTER TABLE tool_runs
    ADD COLUMN provider_attempt_id UUID REFERENCES audit_events(id);

CREATE INDEX audit_events_action_attempt_idx
    ON audit_events(action_request_id, step_attempt, occurred_at, id)
    WHERE action_request_id IS NOT NULL;

CREATE INDEX audit_events_queue_job_idx
    ON audit_events(queue_job_id, occurred_at, id)
    WHERE queue_job_id IS NOT NULL;

CREATE INDEX audit_events_provider_attempt_idx
    ON audit_events(provider_attempt_id, occurred_at, id)
    WHERE provider_attempt_id IS NOT NULL;

CREATE UNIQUE INDEX audit_events_provider_terminal_unique_idx
    ON audit_events(provider_attempt_id)
    WHERE event_type IN (
        'provider_invocation_succeeded',
        'provider_invocation_failed',
        'provider_invocation_cancelled'
    );

CREATE UNIQUE INDEX tool_runs_provider_attempt_unique_idx
    ON tool_runs(provider_attempt_id)
    WHERE provider_attempt_id IS NOT NULL;
