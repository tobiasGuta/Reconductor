CREATE TABLE workflow_attempt_waves (
    wave_id UUID PRIMARY KEY,
    workflow_run_id UUID NOT NULL REFERENCES workflow_runs(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    wave_sequence BIGINT NOT NULL CONSTRAINT workflow_attempt_waves_sequence_ck CHECK (wave_sequence > 0),
    materialization_digest TEXT NOT NULL CONSTRAINT workflow_attempt_waves_digest_ck CHECK (
        octet_length(materialization_digest) = 64 AND materialization_digest ~ '^[0-9a-f]{64}$'
    ),
    member_count INTEGER NOT NULL CONSTRAINT workflow_attempt_waves_member_count_ck CHECK (member_count > 0),
    propagation_state TEXT NOT NULL CONSTRAINT workflow_attempt_waves_propagation_state_ck CHECK (
        propagation_state IN ('not_required','pending','claimed','completed','superseded','manual_review_required')
    ),
    propagation_owner_kind TEXT,
    propagation_owner_instance_id UUID,
    propagation_token UUID,
    propagation_fence_generation BIGINT NOT NULL DEFAULT 0 CONSTRAINT workflow_attempt_waves_propagation_generation_ck CHECK (propagation_fence_generation >= 0),
    propagation_lease_duration_ms INTEGER,
    propagation_lease_expires_at TIMESTAMPTZ,
    propagation_renewal_sequence BIGINT NOT NULL DEFAULT 0 CONSTRAINT workflow_attempt_waves_propagation_renewal_ck CHECK (propagation_renewal_sequence >= 0),
    propagation_last_renewal_id UUID,
    propagation_last_event_id UUID,
    dispatch_state TEXT NOT NULL CONSTRAINT workflow_attempt_waves_dispatch_state_ck CHECK (
        dispatch_state IN ('pending','claimed','completed','cancelled','superseded','manual_review_required')
    ),
    dispatch_owner_kind TEXT,
    dispatch_owner_instance_id UUID,
    dispatch_token UUID,
    dispatch_fence_generation BIGINT NOT NULL DEFAULT 0 CONSTRAINT workflow_attempt_waves_dispatch_generation_ck CHECK (dispatch_fence_generation >= 0),
    dispatch_lease_duration_ms INTEGER,
    dispatch_lease_expires_at TIMESTAMPTZ,
    dispatch_renewal_sequence BIGINT NOT NULL DEFAULT 0 CONSTRAINT workflow_attempt_waves_dispatch_renewal_ck CHECK (dispatch_renewal_sequence >= 0),
    dispatch_last_renewal_id UUID,
    dispatch_last_event_id UUID,
    row_version BIGINT NOT NULL DEFAULT 1 CONSTRAINT workflow_attempt_waves_row_version_ck CHECK (row_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT workflow_attempt_waves_run_sequence_uq UNIQUE (workflow_run_id, wave_sequence),
    CONSTRAINT workflow_attempt_waves_propagation_owner_kind_ck CHECK (
        propagation_owner_kind IS NULL OR propagation_owner_kind IN ('scheduler','queue_worker','direct_cli','recovery','workflow_coordinator')
    ),
    CONSTRAINT workflow_attempt_waves_dispatch_owner_kind_ck CHECK (
        dispatch_owner_kind IS NULL OR dispatch_owner_kind IN ('scheduler','queue_worker','direct_cli','recovery','workflow_coordinator')
    ),
    CONSTRAINT workflow_attempt_waves_propagation_renewal_shape_ck CHECK (
        (propagation_renewal_sequence = 0 AND propagation_last_renewal_id IS NULL)
        OR (propagation_renewal_sequence > 0 AND propagation_last_renewal_id IS NOT NULL)
    ),
    CONSTRAINT workflow_attempt_waves_dispatch_renewal_shape_ck CHECK (
        (dispatch_renewal_sequence = 0 AND dispatch_last_renewal_id IS NULL)
        OR (dispatch_renewal_sequence > 0 AND dispatch_last_renewal_id IS NOT NULL)
    ),
    CONSTRAINT workflow_attempt_waves_propagation_shape_ck CHECK (
        (
            propagation_state = 'claimed'
            AND propagation_owner_kind IS NOT NULL
            AND propagation_owner_instance_id IS NOT NULL
            AND propagation_token IS NOT NULL
            AND propagation_fence_generation > 0
            AND propagation_lease_duration_ms BETWEEN 3000 AND 900000
            AND propagation_lease_expires_at IS NOT NULL
        )
        OR
        (
            propagation_state <> 'claimed'
            AND propagation_owner_kind IS NULL
            AND propagation_owner_instance_id IS NULL
            AND propagation_token IS NULL
            AND propagation_lease_duration_ms IS NULL
            AND propagation_lease_expires_at IS NULL
        )
    ),
    CONSTRAINT workflow_attempt_waves_dispatch_shape_ck CHECK (
        (
            dispatch_state = 'claimed'
            AND dispatch_owner_kind IS NOT NULL
            AND dispatch_owner_instance_id IS NOT NULL
            AND dispatch_token IS NOT NULL
            AND dispatch_fence_generation > 0
            AND dispatch_lease_duration_ms BETWEEN 3000 AND 900000
            AND dispatch_lease_expires_at IS NOT NULL
        )
        OR
        (
            dispatch_state <> 'claimed'
            AND dispatch_owner_kind IS NULL
            AND dispatch_owner_instance_id IS NULL
            AND dispatch_token IS NULL
            AND dispatch_lease_duration_ms IS NULL
            AND dispatch_lease_expires_at IS NULL
        )
    )
);

CREATE INDEX workflow_attempt_waves_propagation_discovery_idx
    ON workflow_attempt_waves(propagation_state, propagation_lease_expires_at, updated_at, wave_id);

CREATE INDEX workflow_attempt_waves_dispatch_discovery_idx
    ON workflow_attempt_waves(dispatch_state, dispatch_lease_expires_at, updated_at, wave_id);

CREATE TABLE workflow_wave_members (
    wave_id UUID NOT NULL REFERENCES workflow_attempt_waves(wave_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    member_ordinal INTEGER NOT NULL CONSTRAINT workflow_wave_members_ordinal_ck CHECK (member_ordinal >= 0),
    step_run_id UUID NOT NULL REFERENCES step_runs(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    step_definition_id TEXT NOT NULL CONSTRAINT workflow_wave_members_definition_ck CHECK (octet_length(step_definition_id) BETWEEN 1 AND 255),
    current_step_attempt INTEGER NOT NULL DEFAULT 0 CONSTRAINT workflow_wave_members_attempt_ck CHECK (current_step_attempt >= 0),
    current_action_request_id UUID,
    member_state TEXT NOT NULL CONSTRAINT workflow_wave_members_state_ck CHECK (
        member_state IN ('planned','active','retry_pending','terminal','recovery_required')
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (wave_id, member_ordinal),
    CONSTRAINT workflow_wave_members_step_uq UNIQUE (wave_id, step_run_id),
    CONSTRAINT workflow_wave_members_attempt_shape_ck CHECK (
        (member_state = 'planned' AND current_step_attempt = 0 AND current_action_request_id IS NULL)
        OR
        (member_state <> 'planned' AND current_step_attempt > 0 AND current_action_request_id IS NOT NULL)
    )
);

CREATE INDEX workflow_wave_members_dispatch_idx
    ON workflow_wave_members(wave_id, member_state, member_ordinal);

CREATE INDEX workflow_wave_members_attempt_idx
    ON workflow_wave_members(step_run_id, current_step_attempt);

CREATE FUNCTION reject_workflow_attempt_wave_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.wave_id, NEW.workflow_run_id, NEW.wave_sequence, NEW.materialization_digest, NEW.member_count, NEW.created_at)
       IS DISTINCT FROM ROW(OLD.wave_id, OLD.workflow_run_id, OLD.wave_sequence, OLD.materialization_digest, OLD.member_count, OLD.created_at) THEN
        RAISE EXCEPTION 'workflow attempt wave identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workflow_attempt_waves_identity_guard
BEFORE UPDATE ON workflow_attempt_waves
FOR EACH ROW EXECUTE FUNCTION reject_workflow_attempt_wave_identity_mutation();

CREATE FUNCTION reject_workflow_wave_member_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'workflow wave members are retained';
    END IF;
    IF ROW(NEW.wave_id, NEW.member_ordinal, NEW.step_run_id, NEW.step_definition_id, NEW.created_at)
       IS DISTINCT FROM ROW(OLD.wave_id, OLD.member_ordinal, OLD.step_run_id, OLD.step_definition_id, OLD.created_at) THEN
        RAISE EXCEPTION 'workflow wave member identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workflow_wave_members_identity_guard
BEFORE UPDATE OR DELETE ON workflow_wave_members
FOR EACH ROW EXECUTE FUNCTION reject_workflow_wave_member_identity_mutation();

CREATE FUNCTION verify_workflow_wave_member_count() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    target_wave_id UUID;
    expected_count INTEGER;
    actual_count INTEGER;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_wave_id := OLD.wave_id;
    ELSE
        target_wave_id := NEW.wave_id;
    END IF;
    SELECT member_count INTO expected_count
    FROM workflow_attempt_waves
    WHERE wave_id = target_wave_id;
    SELECT count(*) INTO actual_count
    FROM workflow_wave_members
    WHERE wave_id = target_wave_id;
    IF expected_count IS NULL OR actual_count <> expected_count THEN
        RAISE EXCEPTION 'workflow wave member count does not match its immutable declaration';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER workflow_wave_members_count_guard
AFTER INSERT OR UPDATE OR DELETE ON workflow_wave_members
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION verify_workflow_wave_member_count();

CREATE CONSTRAINT TRIGGER workflow_attempt_waves_count_guard
AFTER INSERT OR UPDATE ON workflow_attempt_waves
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION verify_workflow_wave_member_count();

CREATE FUNCTION large_result_uuid_values_distinct(input_values UUID[]) RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT count(*) = count(DISTINCT item)
    FROM unnest(input_values) AS items(item)
$$;

CREATE TABLE failure_finalization_records (
    record_id UUID PRIMARY KEY,
    record_version SMALLINT NOT NULL DEFAULT 1 CONSTRAINT failure_finalization_records_version_ck CHECK (record_version = 1),
    row_version BIGINT NOT NULL DEFAULT 1 CONSTRAINT failure_finalization_records_row_version_ck CHECK (row_version > 0),
    program_id UUID NOT NULL REFERENCES programs(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    task_id UUID NOT NULL REFERENCES tasks(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    workflow_run_id UUID NOT NULL REFERENCES workflow_runs(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    step_run_id UUID NOT NULL REFERENCES step_runs(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    step_attempt INTEGER NOT NULL CONSTRAINT failure_finalization_records_step_attempt_ck CHECK (step_attempt BETWEEN 1 AND 2147483647),
    action_request_id UUID NOT NULL,
    result_occurrence_id UUID NOT NULL,
    wave_id UUID NOT NULL,
    wave_member_ordinal INTEGER NOT NULL CONSTRAINT failure_finalization_records_wave_ordinal_ck CHECK (wave_member_ordinal >= 0),
    scheduled_execution_id UUID REFERENCES scheduled_executions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    scheduler_attempt INTEGER,
    queue_job_id UUID,
    execution_authorization_event_id UUID NOT NULL REFERENCES audit_events(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    origin_owner_instance_id UUID NOT NULL,
    claim_token UUID NOT NULL,
    claim_fence_generation BIGINT NOT NULL CONSTRAINT failure_finalization_records_claim_generation_ck CHECK (claim_fence_generation > 0),
    provider_attempt_id UUID,
    provider_terminal_event_id UUID,
    provider_result_accepted_event_id UUID,
    tool_run_id UUID,
    capability TEXT NOT NULL,
    provider TEXT,
    provider_outcome TEXT NOT NULL CONSTRAINT failure_finalization_records_provider_outcome_ck CHECK (
        provider_outcome IN ('not_started','unknown','succeeded','failed','cancelled','timeout')
    ),
    result_persistence_outcome TEXT NOT NULL CONSTRAINT failure_finalization_records_result_outcome_ck CHECK (
        result_persistence_outcome IN ('not_attempted','admission_pending','confirmed_not_committed','commit_unknown','committed')
    ),
    adoption_resolution TEXT NOT NULL CONSTRAINT failure_finalization_records_adoption_resolution_ck CHECK (
        adoption_resolution IN ('not_applicable','unresolved','adopted_verified','nonadoption_abandoned','nonadoption_quarantined','inconsistent')
    ),
    record_state TEXT NOT NULL CONSTRAINT failure_finalization_records_state_ck CHECK (
        record_state IN (
            'prepared','provider_started','provider_terminal','admission_pending','commit_unknown',
            'finalization_required','finalization_charged','step_finalized','finalized',
            'resolved_adopted','resolved_retryable','superseded','manual_review_required'
        )
    ),
    propagation_state TEXT NOT NULL CONSTRAINT failure_finalization_records_propagation_ck CHECK (
        propagation_state IN ('not_applicable','pending','completed')
    ),
    failure_code TEXT,
    reason_code TEXT,
    safe_message TEXT NOT NULL DEFAULT '',
    diagnostic JSONB NOT NULL DEFAULT '{}'::jsonb,
    automatic_attempt_count SMALLINT NOT NULL DEFAULT 0 CONSTRAINT failure_finalization_records_attempt_count_ck CHECK (automatic_attempt_count BETWEEN 0 AND 2),
    finalization_attempt_state TEXT NOT NULL DEFAULT 'not_charged' CONSTRAINT failure_finalization_records_attempt_state_ck CHECK (
        finalization_attempt_state IN ('not_charged','charged','executing','commit_unknown','confirmed_rolled_back','committed','rollback_unknown','exhausted')
    ),
    finalization_charge_version BIGINT NOT NULL DEFAULT 0 CONSTRAINT failure_finalization_records_charge_version_ck CHECK (finalization_charge_version >= 0),
    last_finalization_charge_id UUID,
    finalization_charge_1_id UUID NOT NULL,
    finalization_charge_1_audit_event_id UUID NOT NULL,
    finalization_begin_1_event_id UUID NOT NULL,
    finalization_outcome_1_event_id UUID NOT NULL,
    finalization_charge_2_id UUID NOT NULL,
    finalization_charge_2_audit_event_id UUID NOT NULL,
    finalization_begin_2_event_id UUID NOT NULL,
    finalization_outcome_2_event_id UUID NOT NULL,
    result_commit_unknown_event_id UUID NOT NULL,
    result_commit_resolution_event_id UUID NOT NULL,
    failure_finalization_failed_event_id UUID NOT NULL,
    finalization_execution_charge_number SMALLINT,
    finalization_execution_claim_token UUID,
    finalization_execution_fence_generation BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    resolved_at TIMESTAMPTZ,
    CONSTRAINT failure_finalization_records_step_attempt_uq UNIQUE (step_run_id, step_attempt),
    CONSTRAINT failure_finalization_records_occurrence_uq UNIQUE (result_occurrence_id),
    CONSTRAINT failure_finalization_records_provider_attempt_uq UNIQUE (provider_attempt_id),
    CONSTRAINT failure_finalization_records_terminal_event_uq UNIQUE (provider_terminal_event_id),
    CONSTRAINT failure_finalization_records_accepted_event_uq UNIQUE (provider_result_accepted_event_id),
    CONSTRAINT failure_finalization_records_tool_run_uq UNIQUE (tool_run_id),
    CONSTRAINT failure_finalization_records_record_occurrence_uq UNIQUE (record_id, result_occurrence_id),
    CONSTRAINT failure_finalization_records_claim_identity_uq UNIQUE (record_id, step_run_id, step_attempt),
    CONSTRAINT failure_finalization_records_wave_member_fk FOREIGN KEY (wave_id, wave_member_ordinal)
        REFERENCES workflow_wave_members(wave_id, member_ordinal) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT failure_finalization_records_provider_attempt_fk FOREIGN KEY (provider_attempt_id)
        REFERENCES audit_events(id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT failure_finalization_records_scheduled_shape_ck CHECK (
        (scheduled_execution_id IS NULL AND scheduler_attempt IS NULL)
        OR (scheduled_execution_id IS NOT NULL AND scheduler_attempt > 0)
    ),
    CONSTRAINT failure_finalization_records_provider_shape_ck CHECK (
        (
            provider_attempt_id IS NULL AND provider_terminal_event_id IS NULL
            AND provider_result_accepted_event_id IS NULL AND tool_run_id IS NULL AND provider IS NULL
        )
        OR
        (
            provider_attempt_id IS NOT NULL AND provider_terminal_event_id IS NOT NULL
            AND provider_result_accepted_event_id IS NOT NULL AND tool_run_id IS NOT NULL
            AND provider IS NOT NULL AND octet_length(provider) BETWEEN 1 AND 128
        )
    ),
    CONSTRAINT failure_finalization_records_provider_outcome_shape_ck CHECK (
        (provider_attempt_id IS NULL AND provider_outcome = 'not_started')
        OR (provider_attempt_id IS NOT NULL AND provider_outcome <> 'not_started')
    ),
    CONSTRAINT failure_finalization_records_capability_bytes_ck CHECK (octet_length(capability) BETWEEN 1 AND 128),
    CONSTRAINT failure_finalization_records_failure_code_bytes_ck CHECK (failure_code IS NULL OR octet_length(failure_code) BETWEEN 1 AND 64),
    CONSTRAINT failure_finalization_records_reason_code_bytes_ck CHECK (reason_code IS NULL OR octet_length(reason_code) BETWEEN 1 AND 64),
    CONSTRAINT failure_finalization_records_safe_message_bytes_ck CHECK (octet_length(safe_message) <= 500),
    CONSTRAINT failure_finalization_records_diagnostic_ck CHECK (
        jsonb_typeof(diagnostic) = 'object' AND octet_length(diagnostic::text) <= 4096
    ),
    CONSTRAINT failure_finalization_records_preallocated_ids_ck CHECK (
        large_result_uuid_values_distinct(ARRAY[
            finalization_charge_1_id,
            finalization_charge_1_audit_event_id,
            finalization_begin_1_event_id,
            finalization_outcome_1_event_id,
            finalization_charge_2_id,
            finalization_charge_2_audit_event_id,
            finalization_begin_2_event_id,
            finalization_outcome_2_event_id,
            result_commit_unknown_event_id,
            result_commit_resolution_event_id,
            failure_finalization_failed_event_id
        ])
    ),
    CONSTRAINT failure_finalization_records_attempt_shape_ck CHECK (
        (
            automatic_attempt_count = 0
            AND finalization_attempt_state = 'not_charged'
            AND finalization_charge_version = 0
            AND last_finalization_charge_id IS NULL
        )
        OR
        (
            automatic_attempt_count = 1
            AND finalization_attempt_state IN ('charged','executing','commit_unknown','confirmed_rolled_back','committed','rollback_unknown')
            AND finalization_charge_version = 1
            AND last_finalization_charge_id = finalization_charge_1_id
        )
        OR
        (
            automatic_attempt_count = 2
            AND finalization_attempt_state IN ('charged','executing','commit_unknown','committed','rollback_unknown','exhausted')
            AND finalization_charge_version = 2
            AND last_finalization_charge_id = finalization_charge_2_id
        )
    ),
    CONSTRAINT failure_finalization_records_execution_binding_ck CHECK (
        (
            finalization_attempt_state = 'executing'
            AND finalization_execution_charge_number = automatic_attempt_count
            AND finalization_execution_claim_token IS NOT NULL
            AND finalization_execution_fence_generation > 0
        )
        OR
        (
            finalization_attempt_state = 'commit_unknown'
            AND (
                (
                    finalization_execution_charge_number = automatic_attempt_count
                    AND finalization_execution_claim_token IS NOT NULL
                    AND finalization_execution_fence_generation > 0
                )
                OR
                (
                    finalization_execution_charge_number IS NULL
                    AND finalization_execution_claim_token IS NULL
                    AND finalization_execution_fence_generation IS NULL
                )
            )
        )
        OR
        (
            finalization_attempt_state NOT IN ('executing','commit_unknown')
            AND finalization_execution_charge_number IS NULL
            AND finalization_execution_claim_token IS NULL
            AND finalization_execution_fence_generation IS NULL
        )
    )
);

CREATE INDEX failure_finalization_records_action_request_idx
    ON failure_finalization_records(action_request_id);

CREATE INDEX failure_finalization_records_state_idx
    ON failure_finalization_records(record_state, updated_at, record_id);

CREATE INDEX failure_finalization_records_workflow_propagation_idx
    ON failure_finalization_records(workflow_run_id, propagation_state, record_id);

CREATE INDEX failure_finalization_records_step_result_idx
    ON failure_finalization_records(step_run_id, result_persistence_outcome, record_id);

CREATE TABLE step_attempt_claims (
    step_run_id UUID NOT NULL REFERENCES step_runs(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    step_attempt INTEGER NOT NULL CONSTRAINT step_attempt_claims_attempt_ck CHECK (step_attempt BETWEEN 1 AND 2147483647),
    action_request_id UUID NOT NULL,
    record_id UUID NOT NULL UNIQUE REFERENCES failure_finalization_records(record_id) DEFERRABLE INITIALLY DEFERRED,
    wave_id UUID NOT NULL,
    wave_member_ordinal INTEGER NOT NULL CONSTRAINT step_attempt_claims_wave_ordinal_ck CHECK (wave_member_ordinal >= 0),
    claim_state TEXT NOT NULL CONSTRAINT step_attempt_claims_state_ck CHECK (claim_state IN ('active','recovery_owned','released','terminal')),
    owner_kind TEXT,
    owner_instance_id UUID,
    origin_owner_instance_id UUID NOT NULL,
    claim_token UUID,
    fence_generation BIGINT NOT NULL CONSTRAINT step_attempt_claims_fence_generation_ck CHECK (fence_generation > 0),
    lease_duration_ms INTEGER NOT NULL CONSTRAINT step_attempt_claims_lease_duration_ck CHECK (lease_duration_ms BETWEEN 3000 AND 900000),
    lease_expires_at TIMESTAMPTZ,
    renewal_sequence BIGINT NOT NULL DEFAULT 0 CONSTRAINT step_attempt_claims_renewal_sequence_ck CHECK (renewal_sequence >= 0),
    last_renewal_id UUID,
    last_renewed_at TIMESTAMPTZ,
    last_release_id UUID,
    scheduled_execution_id UUID REFERENCES scheduled_executions(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    scheduler_attempt INTEGER,
    queue_job_id UUID,
    closed_at TIMESTAMPTZ,
    close_reason TEXT,
    row_version BIGINT NOT NULL DEFAULT 1 CONSTRAINT step_attempt_claims_row_version_ck CHECK (row_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (step_run_id, step_attempt),
    CONSTRAINT step_attempt_claims_record_attempt_fk FOREIGN KEY (record_id, step_run_id, step_attempt)
        REFERENCES failure_finalization_records(record_id, step_run_id, step_attempt) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT step_attempt_claims_wave_member_fk FOREIGN KEY (wave_id, wave_member_ordinal)
        REFERENCES workflow_wave_members(wave_id, member_ordinal) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT step_attempt_claims_owner_kind_ck CHECK (
        owner_kind IS NULL OR owner_kind IN ('scheduler','queue_worker','direct_cli','recovery','workflow_coordinator')
    ),
    CONSTRAINT step_attempt_claims_scheduled_shape_ck CHECK (
        (scheduled_execution_id IS NULL AND scheduler_attempt IS NULL)
        OR (scheduled_execution_id IS NOT NULL AND scheduler_attempt > 0)
    ),
    CONSTRAINT step_attempt_claims_renewal_shape_ck CHECK (
        (renewal_sequence = 0 AND last_renewal_id IS NULL AND last_renewed_at IS NULL)
        OR (renewal_sequence > 0 AND last_renewal_id IS NOT NULL AND last_renewed_at IS NOT NULL)
    ),
    CONSTRAINT step_attempt_claims_close_reason_bytes_ck CHECK (close_reason IS NULL OR octet_length(close_reason) BETWEEN 1 AND 64),
    CONSTRAINT step_attempt_claims_state_shape_ck CHECK (
        (
            claim_state IN ('active','recovery_owned')
            AND owner_kind IS NOT NULL AND owner_instance_id IS NOT NULL AND claim_token IS NOT NULL
            AND lease_expires_at IS NOT NULL AND closed_at IS NULL AND close_reason IS NULL
        )
        OR
        (
            claim_state = 'released'
            AND owner_kind IS NULL AND owner_instance_id IS NULL AND claim_token IS NULL AND lease_expires_at IS NULL
            AND closed_at IS NOT NULL AND close_reason IS NOT NULL AND last_release_id IS NOT NULL
        )
        OR
        (
            claim_state = 'terminal'
            AND owner_kind IS NULL AND owner_instance_id IS NULL AND claim_token IS NULL AND lease_expires_at IS NULL
            AND closed_at IS NOT NULL AND close_reason IS NOT NULL
        )
    )
);

CREATE INDEX step_attempt_claims_action_request_idx
    ON step_attempt_claims(action_request_id);

CREATE INDEX step_attempt_claims_scheduled_idx
    ON step_attempt_claims(scheduled_execution_id, scheduler_attempt)
    WHERE scheduled_execution_id IS NOT NULL;

CREATE INDEX step_attempt_claims_queue_idx
    ON step_attempt_claims(queue_job_id)
    WHERE queue_job_id IS NOT NULL;

CREATE INDEX step_attempt_claims_recovery_idx
    ON step_attempt_claims(claim_state, lease_expires_at, step_run_id, step_attempt);

CREATE FUNCTION enforce_failure_finalization_record_identity() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'failure finalization records are retained';
    END IF;
    IF ROW(
        NEW.record_id, NEW.record_version, NEW.program_id, NEW.task_id, NEW.workflow_run_id,
        NEW.step_run_id, NEW.step_attempt, NEW.action_request_id, NEW.result_occurrence_id,
        NEW.wave_id, NEW.wave_member_ordinal, NEW.scheduled_execution_id, NEW.scheduler_attempt,
        NEW.queue_job_id, NEW.execution_authorization_event_id, NEW.origin_owner_instance_id,
        NEW.provider_attempt_id, NEW.provider_terminal_event_id, NEW.provider_result_accepted_event_id,
        NEW.tool_run_id, NEW.capability, NEW.provider,
        NEW.finalization_charge_1_id, NEW.finalization_charge_1_audit_event_id,
        NEW.finalization_begin_1_event_id, NEW.finalization_outcome_1_event_id,
        NEW.finalization_charge_2_id, NEW.finalization_charge_2_audit_event_id,
        NEW.finalization_begin_2_event_id, NEW.finalization_outcome_2_event_id,
        NEW.result_commit_unknown_event_id, NEW.result_commit_resolution_event_id,
        NEW.failure_finalization_failed_event_id, NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.record_id, OLD.record_version, OLD.program_id, OLD.task_id, OLD.workflow_run_id,
        OLD.step_run_id, OLD.step_attempt, OLD.action_request_id, OLD.result_occurrence_id,
        OLD.wave_id, OLD.wave_member_ordinal, OLD.scheduled_execution_id, OLD.scheduler_attempt,
        OLD.queue_job_id, OLD.execution_authorization_event_id, OLD.origin_owner_instance_id,
        OLD.provider_attempt_id, OLD.provider_terminal_event_id, OLD.provider_result_accepted_event_id,
        OLD.tool_run_id, OLD.capability, OLD.provider,
        OLD.finalization_charge_1_id, OLD.finalization_charge_1_audit_event_id,
        OLD.finalization_begin_1_event_id, OLD.finalization_outcome_1_event_id,
        OLD.finalization_charge_2_id, OLD.finalization_charge_2_audit_event_id,
        OLD.finalization_begin_2_event_id, OLD.finalization_outcome_2_event_id,
        OLD.result_commit_unknown_event_id, OLD.result_commit_resolution_event_id,
        OLD.failure_finalization_failed_event_id, OLD.created_at
    ) THEN
        RAISE EXCEPTION 'failure finalization record identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER failure_finalization_records_identity_guard
BEFORE UPDATE OR DELETE ON failure_finalization_records
FOR EACH ROW EXECUTE FUNCTION enforce_failure_finalization_record_identity();

CREATE FUNCTION enforce_step_attempt_claim_identity() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'step attempt claims are retained';
    END IF;
    IF ROW(
        NEW.step_run_id, NEW.step_attempt, NEW.action_request_id, NEW.record_id,
        NEW.wave_id, NEW.wave_member_ordinal, NEW.origin_owner_instance_id,
        NEW.lease_duration_ms, NEW.scheduled_execution_id, NEW.scheduler_attempt,
        NEW.queue_job_id, NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.step_run_id, OLD.step_attempt, OLD.action_request_id, OLD.record_id,
        OLD.wave_id, OLD.wave_member_ordinal, OLD.origin_owner_instance_id,
        OLD.lease_duration_ms, OLD.scheduled_execution_id, OLD.scheduler_attempt,
        OLD.queue_job_id, OLD.created_at
    ) THEN
        RAISE EXCEPTION 'step attempt claim identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER step_attempt_claims_identity_guard
BEFORE UPDATE OR DELETE ON step_attempt_claims
FOR EACH ROW EXECUTE FUNCTION enforce_step_attempt_claim_identity();

CREATE FUNCTION reject_workflow_attempt_wave_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'workflow attempt waves are retained';
END;
$$;

CREATE TRIGGER workflow_attempt_waves_delete_guard
BEFORE DELETE ON workflow_attempt_waves
FOR EACH ROW EXECUTE FUNCTION reject_workflow_attempt_wave_delete();

ALTER TABLE audit_events
    ADD COLUMN failure_finalization_record_id UUID,
    ADD COLUMN result_occurrence_id UUID,
    ADD COLUMN wave_id UUID,
    ADD COLUMN wave_member_ordinal INTEGER,
    ADD COLUMN claim_fence_generation BIGINT,
    ADD COLUMN finalization_attempt_number SMALLINT,
    ADD CONSTRAINT audit_events_failure_finalization_record_fk FOREIGN KEY (failure_finalization_record_id)
        REFERENCES failure_finalization_records(record_id) DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT audit_events_record_occurrence_fk FOREIGN KEY (failure_finalization_record_id, result_occurrence_id)
        REFERENCES failure_finalization_records(record_id, result_occurrence_id) DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT audit_events_wave_fk FOREIGN KEY (wave_id)
        REFERENCES workflow_attempt_waves(wave_id) DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT audit_events_wave_member_fk FOREIGN KEY (wave_id, wave_member_ordinal)
        REFERENCES workflow_wave_members(wave_id, member_ordinal) DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT audit_events_result_occurrence_shape_ck CHECK (
        result_occurrence_id IS NULL OR failure_finalization_record_id IS NOT NULL
    ),
    ADD CONSTRAINT audit_events_wave_member_shape_ck CHECK (
        wave_member_ordinal IS NULL OR (wave_id IS NOT NULL AND wave_member_ordinal >= 0)
    ),
    ADD CONSTRAINT audit_events_claim_fence_generation_ck CHECK (
        claim_fence_generation IS NULL OR claim_fence_generation > 0
    ),
    ADD CONSTRAINT audit_events_finalization_attempt_ck CHECK (
        finalization_attempt_number IS NULL OR finalization_attempt_number BETWEEN 1 AND 2
    ),
    ADD CONSTRAINT audit_events_safe_message_bytes_ck CHECK (octet_length(safe_message) <= 500) NOT VALID,
    ADD CONSTRAINT audit_events_details_bytes_ck CHECK (
        jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 4096
    ) NOT VALID;

CREATE INDEX audit_events_failure_finalization_record_idx
    ON audit_events(failure_finalization_record_id, occurred_at, id)
    WHERE failure_finalization_record_id IS NOT NULL;

CREATE INDEX audit_events_result_occurrence_idx
    ON audit_events(result_occurrence_id, occurred_at, id)
    WHERE result_occurrence_id IS NOT NULL;

CREATE INDEX audit_events_wave_idx
    ON audit_events(wave_id, wave_member_ordinal, occurred_at, id)
    WHERE wave_id IS NOT NULL;

ALTER TABLE audit_events
    DROP CONSTRAINT audit_events_provider_terminal_provenance_check,
    ADD CONSTRAINT audit_events_provider_terminal_provenance_check CHECK (
        event_type NOT IN (
            'provider_invocation_succeeded',
            'provider_invocation_failed',
            'provider_invocation_cancelled',
            'provider_invocation_timed_out'
        )
        OR provider_attempt_id IS NOT NULL
    );

DROP INDEX audit_events_provider_terminal_unique_idx;

CREATE UNIQUE INDEX audit_events_provider_terminal_unique_idx
    ON audit_events(provider_attempt_id)
    WHERE event_type IN (
        'provider_invocation_succeeded',
        'provider_invocation_failed',
        'provider_invocation_cancelled',
        'provider_invocation_timed_out'
    );
