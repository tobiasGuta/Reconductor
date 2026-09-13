CREATE TABLE artifact_publications (
    id UUID PRIMARY KEY,
    provider_attempt_id UUID NOT NULL REFERENCES audit_events(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    publication_ordinal INTEGER NOT NULL CONSTRAINT artifact_publications_ordinal_ck CHECK (publication_ordinal >= 0),
    result_occurrence_id UUID NOT NULL,
    artifact_id UUID NOT NULL,
    artifact_store_id UUID NOT NULL REFERENCES artifact_stores(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    storage_key TEXT NOT NULL,
    content_type TEXT NOT NULL,
    content_size_bytes BIGINT NOT NULL CONSTRAINT artifact_publications_content_size_ck CHECK (content_size_bytes >= 0),
    content_sha256 TEXT NOT NULL,
    publication_state TEXT NOT NULL CONSTRAINT artifact_publications_state_ck CHECK (
        publication_state IN ('reserved','publishing','sealed','adopted','abandoned','quarantined')
    ),
    origin_owner_instance_id UUID NOT NULL,
    owner_kind TEXT,
    owner_instance_id UUID,
    publication_token UUID,
    fence_generation BIGINT NOT NULL CONSTRAINT artifact_publications_fence_generation_ck CHECK (fence_generation > 0),
    lease_duration_ms INTEGER NOT NULL CONSTRAINT artifact_publications_lease_duration_ck CHECK (lease_duration_ms BETWEEN 3000 AND 900000),
    lease_expires_at TIMESTAMPTZ,
    reserved_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    publishing_at TIMESTAMPTZ,
    sealed_at TIMESTAMPTZ,
    adopted_at TIMESTAMPTZ,
    abandoned_at TIMESTAMPTZ,
    quarantined_at TIMESTAMPTZ,
    quarantine_reason_code TEXT,
    content_deleted_at TIMESTAMPTZ,
    cleanup_claim_token UUID,
    cleanup_claimed_at TIMESTAMPTZ,
    cleanup_retry_after TIMESTAMPTZ,
    cleanup_last_error_code TEXT,
    cleanup_quarantined_at TIMESTAMPTZ,
    row_version BIGINT NOT NULL DEFAULT 1 CONSTRAINT artifact_publications_row_version_ck CHECK (row_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT artifact_publications_provider_ordinal_uq UNIQUE (provider_attempt_id, publication_ordinal),
    CONSTRAINT artifact_publications_artifact_uq UNIQUE (artifact_id),
    CONSTRAINT artifact_publications_store_key_uq UNIQUE (artifact_store_id, storage_key),
    CONSTRAINT artifact_publications_storage_key_ck CHECK (
        storage_key = ('v1/' || substr(replace(artifact_id::text,'-',''),1,2) || '/' || artifact_id::text)
    ),
    CONSTRAINT artifact_publications_content_type_bytes_ck CHECK (octet_length(content_type) BETWEEN 1 AND 255),
    CONSTRAINT artifact_publications_sha256_ck CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT artifact_publications_owner_kind_ck CHECK (
        owner_kind IS NULL OR owner_kind IN ('scheduler','queue_worker','direct_cli','recovery','workflow_coordinator')
    ),
    CONSTRAINT artifact_publications_current_owner_shape_ck CHECK (
        (
            publication_state IN ('reserved','publishing','sealed')
            AND owner_kind IS NOT NULL
            AND owner_instance_id IS NOT NULL
            AND publication_token IS NOT NULL
            AND lease_expires_at IS NOT NULL
        )
        OR
        (
            publication_state IN ('adopted','abandoned','quarantined')
            AND owner_kind IS NULL
            AND owner_instance_id IS NULL
            AND publication_token IS NULL
            AND lease_expires_at IS NULL
        )
    ),
    CONSTRAINT artifact_publications_state_shape_ck CHECK (
        (
            publication_state = 'reserved'
            AND publishing_at IS NULL AND sealed_at IS NULL
            AND adopted_at IS NULL AND abandoned_at IS NULL AND quarantined_at IS NULL
            AND quarantine_reason_code IS NULL
        )
        OR
        (
            publication_state = 'publishing'
            AND publishing_at IS NOT NULL AND sealed_at IS NULL
            AND adopted_at IS NULL AND abandoned_at IS NULL AND quarantined_at IS NULL
            AND quarantine_reason_code IS NULL
        )
        OR
        (
            publication_state = 'sealed'
            AND publishing_at IS NOT NULL AND sealed_at IS NOT NULL
            AND adopted_at IS NULL AND abandoned_at IS NULL AND quarantined_at IS NULL
            AND quarantine_reason_code IS NULL
        )
        OR
        (
            publication_state = 'adopted'
            AND publishing_at IS NOT NULL AND sealed_at IS NOT NULL AND adopted_at IS NOT NULL
            AND abandoned_at IS NULL AND quarantined_at IS NULL AND quarantine_reason_code IS NULL
        )
        OR
        (
            publication_state = 'abandoned'
            AND adopted_at IS NULL AND abandoned_at IS NOT NULL
            AND quarantined_at IS NULL AND quarantine_reason_code IS NULL
        )
        OR
        (
            publication_state = 'quarantined'
            AND adopted_at IS NULL AND abandoned_at IS NULL
            AND quarantined_at IS NOT NULL AND quarantine_reason_code IS NOT NULL
            AND octet_length(quarantine_reason_code) BETWEEN 1 AND 64
        )
    ),
    CONSTRAINT artifact_publications_time_order_ck CHECK (
        (publishing_at IS NULL OR publishing_at >= reserved_at)
        AND (sealed_at IS NULL OR (publishing_at IS NOT NULL AND sealed_at >= publishing_at))
        AND (adopted_at IS NULL OR (sealed_at IS NOT NULL AND adopted_at >= sealed_at))
        AND (abandoned_at IS NULL OR abandoned_at >= reserved_at)
        AND (quarantined_at IS NULL OR quarantined_at >= reserved_at)
    ),
    CONSTRAINT artifact_publications_cleanup_error_code_ck CHECK (
        cleanup_last_error_code IS NULL
        OR cleanup_last_error_code IN ('filesystem_io','durability_sync','unexpected_entry_type')
    ),
    CONSTRAINT artifact_publications_cleanup_state_shape_ck CHECK (
        (
            publication_state <> 'abandoned'
            AND content_deleted_at IS NULL
            AND cleanup_claim_token IS NULL
            AND cleanup_claimed_at IS NULL
            AND cleanup_retry_after IS NULL
            AND cleanup_last_error_code IS NULL
            AND cleanup_quarantined_at IS NULL
        )
        OR
        (
            publication_state = 'abandoned'
            AND (
                (
                    content_deleted_at IS NULL
                    AND cleanup_claim_token IS NULL AND cleanup_claimed_at IS NULL
                    AND cleanup_retry_after IS NULL AND cleanup_last_error_code IS NULL
                    AND cleanup_quarantined_at IS NULL
                )
                OR
                (
                    content_deleted_at IS NULL
                    AND cleanup_claim_token IS NOT NULL AND cleanup_claimed_at IS NOT NULL
                    AND cleanup_retry_after IS NULL AND cleanup_last_error_code IS NULL
                    AND cleanup_quarantined_at IS NULL
                )
                OR
                (
                    content_deleted_at IS NULL
                    AND cleanup_claim_token IS NULL AND cleanup_claimed_at IS NULL
                    AND cleanup_retry_after IS NOT NULL
                    AND cleanup_last_error_code IN ('filesystem_io','durability_sync')
                    AND cleanup_quarantined_at IS NULL
                )
                OR
                (
                    content_deleted_at IS NOT NULL
                    AND cleanup_claim_token IS NULL AND cleanup_claimed_at IS NULL
                    AND cleanup_retry_after IS NULL AND cleanup_last_error_code IS NULL
                    AND cleanup_quarantined_at IS NULL
                )
                OR
                (
                    content_deleted_at IS NULL
                    AND cleanup_claim_token IS NULL AND cleanup_claimed_at IS NULL
                    AND cleanup_retry_after IS NULL
                    AND cleanup_last_error_code = 'unexpected_entry_type'
                    AND cleanup_quarantined_at IS NOT NULL
                )
            )
        )
    ),
    CONSTRAINT artifact_publications_cleanup_time_ck CHECK (
        content_deleted_at IS NULL OR (abandoned_at IS NOT NULL AND content_deleted_at >= abandoned_at)
    )
);

CREATE INDEX artifact_publications_provider_occurrence_idx
    ON artifact_publications(provider_attempt_id, result_occurrence_id, publication_ordinal);

CREATE INDEX artifact_publications_recovery_idx
    ON artifact_publications(publication_state, lease_expires_at, updated_at, id)
    WHERE publication_state IN ('reserved','publishing','sealed');

CREATE INDEX artifact_publications_cleanup_eligible_idx
    ON artifact_publications(artifact_store_id, abandoned_at, id)
    WHERE publication_state = 'abandoned'
      AND content_deleted_at IS NULL
      AND cleanup_quarantined_at IS NULL;

CREATE FUNCTION reject_artifact_publication_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'artifact publication rows are retained';
    END IF;
    IF ROW(
        NEW.id, NEW.provider_attempt_id, NEW.publication_ordinal, NEW.result_occurrence_id,
        NEW.artifact_id, NEW.artifact_store_id, NEW.storage_key, NEW.content_type,
        NEW.content_size_bytes, NEW.content_sha256, NEW.origin_owner_instance_id, NEW.created_at
    ) IS DISTINCT FROM ROW(
        OLD.id, OLD.provider_attempt_id, OLD.publication_ordinal, OLD.result_occurrence_id,
        OLD.artifact_id, OLD.artifact_store_id, OLD.storage_key, OLD.content_type,
        OLD.content_size_bytes, OLD.content_sha256, OLD.origin_owner_instance_id, OLD.created_at
    ) THEN
        RAISE EXCEPTION 'artifact publication identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifact_publications_identity_guard
BEFORE UPDATE OR DELETE ON artifact_publications
FOR EACH ROW EXECUTE FUNCTION reject_artifact_publication_identity_mutation();

CREATE FUNCTION enforce_artifact_publication_state_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.reserved_at IS DISTINCT FROM OLD.reserved_at THEN
        RAISE EXCEPTION 'artifact publication reserved timestamp is immutable';
    END IF;

    IF NEW.publication_state = OLD.publication_state THEN
        IF ROW(
            NEW.publishing_at, NEW.sealed_at, NEW.adopted_at, NEW.abandoned_at,
            NEW.quarantined_at, NEW.quarantine_reason_code
        ) IS DISTINCT FROM ROW(
            OLD.publishing_at, OLD.sealed_at, OLD.adopted_at, OLD.abandoned_at,
            OLD.quarantined_at, OLD.quarantine_reason_code
        ) THEN
            RAISE EXCEPTION 'artifact publication lifecycle facts are immutable within a state';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.publication_state IN ('adopted','abandoned','quarantined') THEN
        RAISE EXCEPTION 'terminal artifact publication state is immutable';
    END IF;

    IF OLD.publication_state = 'reserved' AND NEW.publication_state = 'publishing' THEN
        IF ROW(NEW.sealed_at, NEW.adopted_at, NEW.abandoned_at, NEW.quarantined_at, NEW.quarantine_reason_code)
           IS DISTINCT FROM ROW(OLD.sealed_at, OLD.adopted_at, OLD.abandoned_at, OLD.quarantined_at, OLD.quarantine_reason_code) THEN
            RAISE EXCEPTION 'artifact publication transition changed unrelated lifecycle facts';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.publication_state = 'publishing' AND NEW.publication_state = 'sealed' THEN
        IF ROW(NEW.publishing_at, NEW.adopted_at, NEW.abandoned_at, NEW.quarantined_at, NEW.quarantine_reason_code)
           IS DISTINCT FROM ROW(OLD.publishing_at, OLD.adopted_at, OLD.abandoned_at, OLD.quarantined_at, OLD.quarantine_reason_code) THEN
            RAISE EXCEPTION 'artifact publication transition changed unrelated lifecycle facts';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.publication_state = 'sealed' AND NEW.publication_state = 'adopted' THEN
        IF ROW(NEW.publishing_at, NEW.sealed_at, NEW.abandoned_at, NEW.quarantined_at, NEW.quarantine_reason_code)
           IS DISTINCT FROM ROW(OLD.publishing_at, OLD.sealed_at, OLD.abandoned_at, OLD.quarantined_at, OLD.quarantine_reason_code) THEN
            RAISE EXCEPTION 'artifact publication transition changed unrelated lifecycle facts';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.publication_state = 'abandoned' AND OLD.publication_state IN ('reserved','publishing','sealed') THEN
        IF ROW(NEW.publishing_at, NEW.sealed_at, NEW.adopted_at, NEW.quarantined_at, NEW.quarantine_reason_code)
           IS DISTINCT FROM ROW(OLD.publishing_at, OLD.sealed_at, OLD.adopted_at, OLD.quarantined_at, OLD.quarantine_reason_code) THEN
            RAISE EXCEPTION 'artifact publication transition changed unrelated lifecycle facts';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.publication_state = 'quarantined' AND OLD.publication_state IN ('reserved','publishing','sealed') THEN
        IF ROW(NEW.publishing_at, NEW.sealed_at, NEW.adopted_at, NEW.abandoned_at)
           IS DISTINCT FROM ROW(OLD.publishing_at, OLD.sealed_at, OLD.adopted_at, OLD.abandoned_at) THEN
            RAISE EXCEPTION 'artifact publication transition changed unrelated lifecycle facts';
        END IF;
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'illegal artifact publication transition from % to %', OLD.publication_state, NEW.publication_state;
END;
$$;

CREATE TRIGGER artifact_publications_state_transition_guard
BEFORE UPDATE OF publication_state, reserved_at, publishing_at, sealed_at, adopted_at, abandoned_at, quarantined_at, quarantine_reason_code
ON artifact_publications
FOR EACH ROW EXECUTE FUNCTION enforce_artifact_publication_state_transition();

CREATE FUNCTION artifact_publication_cleanup_state_class(
    content_deleted_at TIMESTAMPTZ,
    cleanup_claim_token UUID,
    cleanup_retry_after TIMESTAMPTZ,
    cleanup_quarantined_at TIMESTAMPTZ
) RETURNS TEXT
LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    IF content_deleted_at IS NOT NULL THEN
        RETURN 'CONTENT_DELETED';
    ELSIF cleanup_quarantined_at IS NOT NULL THEN
        RETURN 'QUARANTINED';
    ELSIF cleanup_claim_token IS NOT NULL THEN
        RETURN 'CLAIMED';
    ELSIF cleanup_retry_after IS NOT NULL THEN
        RETURN 'RETRY_WAIT';
    ELSE
        RETURN 'UNCLAIMED';
    END IF;
END;
$$;

CREATE FUNCTION enforce_artifact_publication_cleanup_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    old_state TEXT;
    new_state TEXT;
BEGIN
    IF ROW(
        NEW.content_deleted_at, NEW.cleanup_claim_token, NEW.cleanup_claimed_at,
        NEW.cleanup_retry_after, NEW.cleanup_last_error_code, NEW.cleanup_quarantined_at
    ) IS NOT DISTINCT FROM ROW(
        OLD.content_deleted_at, OLD.cleanup_claim_token, OLD.cleanup_claimed_at,
        OLD.cleanup_retry_after, OLD.cleanup_last_error_code, OLD.cleanup_quarantined_at
    ) THEN
        RETURN NEW;
    END IF;

    IF OLD.publication_state <> 'abandoned' OR NEW.publication_state <> 'abandoned' THEN
        RAISE EXCEPTION 'publication cleanup transitions require an already abandoned publication';
    END IF;

    old_state := artifact_publication_cleanup_state_class(
        OLD.content_deleted_at, OLD.cleanup_claim_token, OLD.cleanup_retry_after, OLD.cleanup_quarantined_at
    );
    new_state := artifact_publication_cleanup_state_class(
        NEW.content_deleted_at, NEW.cleanup_claim_token, NEW.cleanup_retry_after, NEW.cleanup_quarantined_at
    );

    IF old_state = 'CONTENT_DELETED' THEN
        RAISE EXCEPTION 'content-deleted publication cleanup is terminal and immutable';
    END IF;
    IF old_state = 'QUARANTINED' THEN
        RAISE EXCEPTION 'cleanup-quarantined publication cleanup is terminal and immutable';
    END IF;

    IF old_state = 'UNCLAIMED' AND new_state = 'CLAIMED' THEN
        RETURN NEW;
    ELSIF old_state = 'RETRY_WAIT' AND new_state = 'CLAIMED' THEN
        RETURN NEW;
    ELSIF old_state = 'CLAIMED' AND new_state = 'CLAIMED' THEN
        IF NEW.cleanup_claim_token IS DISTINCT FROM OLD.cleanup_claim_token THEN
            RETURN NEW;
        END IF;
    ELSIF old_state = 'CLAIMED' AND new_state = 'RETRY_WAIT' THEN
        RETURN NEW;
    ELSIF old_state = 'CLAIMED' AND new_state = 'CONTENT_DELETED' THEN
        RETURN NEW;
    ELSIF old_state = 'CLAIMED' AND new_state = 'QUARANTINED' THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'illegal artifact publication cleanup transition from % to %', old_state, new_state;
END;
$$;

CREATE TRIGGER artifact_publications_cleanup_transition_guard
BEFORE UPDATE OF content_deleted_at, cleanup_claim_token, cleanup_claimed_at, cleanup_retry_after, cleanup_last_error_code, cleanup_quarantined_at
ON artifact_publications
FOR EACH ROW EXECUTE FUNCTION enforce_artifact_publication_cleanup_transition();

CREATE FUNCTION verify_adopted_artifact_publication() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.publication_state = 'adopted' AND NOT EXISTS (
        SELECT 1
        FROM artifacts artifact
        JOIN tool_runs tool ON tool.id = artifact.tool_run_id
        WHERE artifact.id = NEW.artifact_id
          AND artifact.artifact_store_id = NEW.artifact_store_id
          AND artifact.storage_key = NEW.storage_key
          AND artifact.size = NEW.content_size_bytes
          AND artifact.sha256 = NEW.content_sha256
          AND tool.provider_attempt_id = NEW.provider_attempt_id
    ) THEN
        RAISE EXCEPTION 'adopted artifact publication lacks its exact artifact relationship';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER artifact_publications_adoption_guard
AFTER INSERT OR UPDATE ON artifact_publications
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION verify_adopted_artifact_publication();
