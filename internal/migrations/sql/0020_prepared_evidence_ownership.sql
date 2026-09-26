CREATE TABLE artifact_store_prepared_limits (
    artifact_store_id UUID PRIMARY KEY REFERENCES artifact_stores(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    max_open_sets INTEGER NOT NULL CONSTRAINT artifact_store_prepared_limits_open_ck CHECK (max_open_sets BETWEEN 1 AND 1000000),
    max_set_bytes BIGINT NOT NULL CONSTRAINT artifact_store_prepared_limits_set_ck CHECK (max_set_bytes BETWEEN 1 AND 1099511627776),
    max_unresolved_bytes BIGINT NOT NULL CONSTRAINT artifact_store_prepared_limits_total_ck CHECK (max_unresolved_bytes BETWEEN max_set_bytes AND 1125899906842624),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

ALTER TABLE artifact_stores
    ADD CONSTRAINT artifact_stores_id_incarnation_uq UNIQUE (id, incarnation_nonce);

CREATE TABLE prepared_evidence_sets (
    id UUID PRIMARY KEY,
    manifest_id UUID NOT NULL UNIQUE,
    owner_kind TEXT NOT NULL CONSTRAINT prepared_evidence_sets_owner_kind_ck CHECK (owner_kind IN ('provider_attempt','failure_finalization')),
    provider_attempt_id UUID REFERENCES audit_events(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    failure_finalization_record_id UUID REFERENCES failure_finalization_records(record_id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    program_id UUID NOT NULL REFERENCES programs(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    task_id UUID NOT NULL REFERENCES tasks(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    workflow_run_id UUID NOT NULL REFERENCES workflow_runs(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    step_run_id UUID NOT NULL REFERENCES step_runs(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    action_request_id UUID NOT NULL,
    step_attempt INTEGER NOT NULL CONSTRAINT prepared_evidence_sets_step_attempt_ck CHECK (step_attempt BETWEEN 1 AND 2147483647),
    artifact_store_id UUID NOT NULL,
    store_incarnation_nonce UUID NOT NULL,
    lifecycle_state TEXT NOT NULL CONSTRAINT prepared_evidence_sets_state_ck CHECK (lifecycle_state IN ('ALLOCATED','SEALED','RESOLVED_ADOPTED','RESOLVED_ABANDONED','QUARANTINED','CLEANED')),
    reserved_capacity_bytes BIGINT NOT NULL CONSTRAINT prepared_evidence_sets_reserved_ck CHECK (reserved_capacity_bytes >= 0),
    result_occurrence_id UUID,
    provider_terminal_event_id UUID,
    manifest_storage_key TEXT,
    manifest_size_bytes BIGINT,
    manifest_sha256 TEXT,
    member_count INTEGER,
    content_size_bytes BIGINT,
    quarantine_reason_code TEXT,
    nonadmission_details JSONB,
    allocated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    sealed_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    quarantined_at TIMESTAMPTZ,
    cleaned_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT prepared_evidence_sets_store_fk FOREIGN KEY (artifact_store_id, store_incarnation_nonce)
        REFERENCES artifact_stores(id, incarnation_nonce) ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT prepared_evidence_sets_owner_shape_ck CHECK (
        (owner_kind='provider_attempt' AND provider_attempt_id IS NOT NULL AND failure_finalization_record_id IS NULL)
        OR (owner_kind='failure_finalization' AND provider_attempt_id IS NULL AND failure_finalization_record_id IS NOT NULL)
    ),
    CONSTRAINT prepared_evidence_sets_manifest_size_ck CHECK (manifest_size_bytes IS NULL OR manifest_size_bytes BETWEEN 1 AND 8192),
    CONSTRAINT prepared_evidence_sets_manifest_sha_ck CHECK (manifest_sha256 IS NULL OR manifest_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT prepared_evidence_sets_member_count_ck CHECK (member_count IS NULL OR member_count BETWEEN 1 AND 4),
    CONSTRAINT prepared_evidence_sets_content_size_ck CHECK (content_size_bytes IS NULL OR content_size_bytes >= 0),
    CONSTRAINT prepared_evidence_sets_quarantine_reason_ck CHECK (quarantine_reason_code IS NULL OR octet_length(quarantine_reason_code) BETWEEN 1 AND 64),
    CONSTRAINT prepared_evidence_sets_nonadmission_ck CHECK (nonadmission_details IS NULL OR
        (jsonb_typeof(nonadmission_details)='object' AND octet_length(nonadmission_details::text) <= 4096
         AND COALESCE(nonadmission_details->>'code'='result_contract_limit',false)
         AND COALESCE(nonadmission_details->>'subject'='prepared_evidence',false)
         AND lifecycle_state IN ('RESOLVED_ABANDONED','CLEANED'))),
    CONSTRAINT prepared_evidence_sets_charge_ck CHECK (
        (lifecycle_state='CLEANED' AND reserved_capacity_bytes=0)
        OR (lifecycle_state<>'CLEANED' AND reserved_capacity_bytes>0 AND
            (content_size_bytes IS NULL OR content_size_bytes<=reserved_capacity_bytes))),
    CONSTRAINT prepared_evidence_sets_nonadmission_unsealed_ck CHECK (nonadmission_details IS NULL OR
        (manifest_storage_key IS NULL AND manifest_size_bytes IS NULL AND manifest_sha256 IS NULL
         AND member_count IS NULL AND content_size_bytes IS NULL AND sealed_at IS NULL)),
    CONSTRAINT prepared_evidence_sets_manifest_key_ck CHECK (
        manifest_storage_key IS NULL OR manifest_storage_key=('prepared/v1/' || substr(replace(id::text,'-',''),1,2) || '/' || id::text || '/manifest.json')
    ),
    CONSTRAINT prepared_evidence_sets_state_shape_ck CHECK (
        (nonadmission_details IS NOT NULL AND lifecycle_state IN ('RESOLVED_ABANDONED','CLEANED')
         AND result_occurrence_id IS NOT NULL AND provider_terminal_event_id IS NOT NULL
         AND manifest_storage_key IS NULL AND manifest_size_bytes IS NULL AND manifest_sha256 IS NULL
         AND member_count IS NULL AND content_size_bytes IS NULL AND sealed_at IS NULL
         AND resolved_at IS NOT NULL AND quarantined_at IS NULL AND quarantine_reason_code IS NULL
         AND ((lifecycle_state='CLEANED' AND cleaned_at IS NOT NULL) OR (lifecycle_state='RESOLVED_ABANDONED' AND cleaned_at IS NULL)))
        OR
        (lifecycle_state='ALLOCATED' AND result_occurrence_id IS NULL AND provider_terminal_event_id IS NULL AND manifest_storage_key IS NULL AND manifest_size_bytes IS NULL AND manifest_sha256 IS NULL AND member_count IS NULL AND content_size_bytes IS NULL AND sealed_at IS NULL AND resolved_at IS NULL AND quarantined_at IS NULL AND cleaned_at IS NULL AND quarantine_reason_code IS NULL)
        OR
        (lifecycle_state='SEALED' AND result_occurrence_id IS NOT NULL AND provider_terminal_event_id IS NOT NULL AND manifest_storage_key IS NOT NULL AND manifest_size_bytes IS NOT NULL AND manifest_sha256 IS NOT NULL AND member_count IS NOT NULL AND content_size_bytes IS NOT NULL AND sealed_at IS NOT NULL AND resolved_at IS NULL AND quarantined_at IS NULL AND cleaned_at IS NULL AND quarantine_reason_code IS NULL)
        OR
        (lifecycle_state IN ('RESOLVED_ADOPTED','RESOLVED_ABANDONED') AND result_occurrence_id IS NOT NULL AND provider_terminal_event_id IS NOT NULL AND manifest_storage_key IS NOT NULL AND manifest_size_bytes IS NOT NULL AND manifest_sha256 IS NOT NULL AND member_count IS NOT NULL AND content_size_bytes IS NOT NULL AND sealed_at IS NOT NULL AND resolved_at IS NOT NULL AND quarantined_at IS NULL AND cleaned_at IS NULL AND quarantine_reason_code IS NULL)
        OR
        (lifecycle_state='QUARANTINED' AND quarantined_at IS NOT NULL AND cleaned_at IS NULL AND quarantine_reason_code IS NOT NULL)
        OR
        (lifecycle_state='CLEANED' AND result_occurrence_id IS NOT NULL AND provider_terminal_event_id IS NOT NULL AND manifest_storage_key IS NOT NULL AND manifest_size_bytes IS NOT NULL AND manifest_sha256 IS NOT NULL AND member_count IS NOT NULL AND content_size_bytes IS NOT NULL AND sealed_at IS NOT NULL AND resolved_at IS NOT NULL AND quarantined_at IS NULL AND cleaned_at IS NOT NULL AND quarantine_reason_code IS NULL)
    ),
    CONSTRAINT prepared_evidence_sets_time_order_ck CHECK (
        (sealed_at IS NULL OR sealed_at >= allocated_at)
        AND (resolved_at IS NULL OR (sealed_at IS NOT NULL AND resolved_at >= sealed_at) OR (nonadmission_details IS NOT NULL AND resolved_at>=allocated_at))
        AND (quarantined_at IS NULL OR quarantined_at >= allocated_at)
        AND (cleaned_at IS NULL OR (resolved_at IS NOT NULL AND cleaned_at >= resolved_at))
    )
);

CREATE UNIQUE INDEX prepared_evidence_sets_provider_attempt_uq
    ON prepared_evidence_sets(provider_attempt_id) WHERE provider_attempt_id IS NOT NULL;
CREATE UNIQUE INDEX prepared_evidence_sets_failure_finalization_uq
    ON prepared_evidence_sets(failure_finalization_record_id) WHERE failure_finalization_record_id IS NOT NULL;
CREATE UNIQUE INDEX prepared_evidence_sets_occurrence_uq
    ON prepared_evidence_sets(result_occurrence_id) WHERE result_occurrence_id IS NOT NULL;
CREATE UNIQUE INDEX prepared_evidence_sets_manifest_key_uq
    ON prepared_evidence_sets(artifact_store_id,manifest_storage_key) WHERE manifest_storage_key IS NOT NULL;
CREATE UNIQUE INDEX prepared_evidence_sets_action_attempt_uq
    ON prepared_evidence_sets(action_request_id,step_attempt);
CREATE INDEX prepared_evidence_sets_recovery_idx
    ON prepared_evidence_sets(artifact_store_id,lifecycle_state,updated_at,id)
    WHERE lifecycle_state <> 'CLEANED';

CREATE FUNCTION enforce_prepared_evidence_set_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'prepared evidence set rows are retained';
    END IF;
    IF ROW(NEW.id,NEW.manifest_id,NEW.owner_kind,NEW.provider_attempt_id,NEW.failure_finalization_record_id,
        NEW.program_id,NEW.task_id,NEW.workflow_run_id,NEW.step_run_id,NEW.action_request_id,NEW.step_attempt,
        NEW.artifact_store_id,NEW.store_incarnation_nonce,NEW.allocated_at)
       IS DISTINCT FROM ROW(OLD.id,OLD.manifest_id,OLD.owner_kind,OLD.provider_attempt_id,OLD.failure_finalization_record_id,
        OLD.program_id,OLD.task_id,OLD.workflow_run_id,OLD.step_run_id,OLD.action_request_id,OLD.step_attempt,
        OLD.artifact_store_id,OLD.store_incarnation_nonce,OLD.allocated_at) THEN
        RAISE EXCEPTION 'prepared evidence identity is immutable';
    END IF;
    IF NEW.lifecycle_state=OLD.lifecycle_state THEN
        IF ROW(NEW.result_occurrence_id,NEW.provider_terminal_event_id,NEW.manifest_storage_key,NEW.manifest_size_bytes,
            NEW.manifest_sha256,NEW.member_count,NEW.content_size_bytes,NEW.sealed_at,NEW.resolved_at,
            NEW.quarantined_at,NEW.cleaned_at,NEW.quarantine_reason_code,NEW.nonadmission_details)
           IS DISTINCT FROM ROW(OLD.result_occurrence_id,OLD.provider_terminal_event_id,OLD.manifest_storage_key,OLD.manifest_size_bytes,
            OLD.manifest_sha256,OLD.member_count,OLD.content_size_bytes,OLD.sealed_at,OLD.resolved_at,
            OLD.quarantined_at,OLD.cleaned_at,OLD.quarantine_reason_code,OLD.nonadmission_details) THEN
            RAISE EXCEPTION 'prepared evidence lifecycle facts are immutable within a state';
        END IF;
        IF NEW.reserved_capacity_bytes IS DISTINCT FROM OLD.reserved_capacity_bytes THEN
            RAISE EXCEPTION 'prepared evidence charge is immutable until resolved cleanup';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.lifecycle_state<>'CLEANED' AND NEW.reserved_capacity_bytes IS DISTINCT FROM OLD.reserved_capacity_bytes THEN
        RAISE EXCEPTION 'prepared evidence charge is immutable until resolved cleanup';
    END IF;
    IF OLD.lifecycle_state<>'ALLOCATED' AND
       ROW(NEW.result_occurrence_id,NEW.provider_terminal_event_id,NEW.manifest_storage_key,NEW.manifest_size_bytes,
           NEW.manifest_sha256,NEW.member_count,NEW.content_size_bytes,NEW.sealed_at,NEW.nonadmission_details)
       IS DISTINCT FROM
       ROW(OLD.result_occurrence_id,OLD.provider_terminal_event_id,OLD.manifest_storage_key,OLD.manifest_size_bytes,
           OLD.manifest_sha256,OLD.member_count,OLD.content_size_bytes,OLD.sealed_at,OLD.nonadmission_details) THEN
        RAISE EXCEPTION 'prepared evidence bound anchors are immutable';
    END IF;
    IF OLD.resolved_at IS NOT NULL AND NEW.resolved_at IS DISTINCT FROM OLD.resolved_at THEN
        RAISE EXCEPTION 'prepared evidence resolution time is immutable';
    END IF;
    IF OLD.lifecycle_state='ALLOCATED' AND NEW.lifecycle_state='QUARANTINED' AND
       ROW(NEW.result_occurrence_id,NEW.provider_terminal_event_id,NEW.manifest_storage_key,NEW.manifest_size_bytes,
           NEW.manifest_sha256,NEW.member_count,NEW.content_size_bytes,NEW.sealed_at) IS DISTINCT FROM
       ROW(OLD.result_occurrence_id,OLD.provider_terminal_event_id,OLD.manifest_storage_key,OLD.manifest_size_bytes,
           OLD.manifest_sha256,OLD.member_count,OLD.content_size_bytes,OLD.sealed_at) THEN
        RAISE EXCEPTION 'quarantine cannot fabricate sealed evidence';
    END IF;
    IF OLD.lifecycle_state='ALLOCATED' AND NEW.lifecycle_state='RESOLVED_ABANDONED' AND NEW.nonadmission_details IS NOT NULL THEN RETURN NEW; END IF;
    IF OLD.lifecycle_state='ALLOCATED' AND NEW.lifecycle_state IN ('SEALED','QUARANTINED') THEN RETURN NEW; END IF;
    IF OLD.lifecycle_state='SEALED' AND NEW.lifecycle_state IN ('RESOLVED_ADOPTED','RESOLVED_ABANDONED','QUARANTINED') THEN RETURN NEW; END IF;
    IF OLD.lifecycle_state IN ('RESOLVED_ADOPTED','RESOLVED_ABANDONED') AND NEW.lifecycle_state='CLEANED' THEN RETURN NEW; END IF;
    RAISE EXCEPTION 'illegal prepared evidence transition from % to %', OLD.lifecycle_state, NEW.lifecycle_state;
END;
$$;

CREATE TRIGGER prepared_evidence_sets_transition_guard
BEFORE UPDATE OR DELETE ON prepared_evidence_sets
FOR EACH ROW EXECUTE FUNCTION enforce_prepared_evidence_set_transition();
