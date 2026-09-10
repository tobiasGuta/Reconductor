ALTER TABLE artifacts
    ADD COLUMN content_deleted_at TIMESTAMPTZ,
    ADD COLUMN cleanup_claim_token UUID,
    ADD COLUMN cleanup_claimed_at TIMESTAMPTZ,
    ADD COLUMN cleanup_retry_after TIMESTAMPTZ,
    ADD COLUMN cleanup_last_error_code TEXT,
    ADD COLUMN cleanup_quarantined_at TIMESTAMPTZ;

-- 1. Legacy version-0 artifacts cannot participate in cleanup lifecycle
ALTER TABLE artifacts ADD CONSTRAINT artifacts_cleanup_legacy_v0_null_ck CHECK (
    addressing_version <> 0
    OR (
        content_deleted_at IS NULL
        AND cleanup_claim_token IS NULL
        AND cleanup_claimed_at IS NULL
        AND cleanup_retry_after IS NULL
        AND cleanup_last_error_code IS NULL
        AND cleanup_quarantined_at IS NULL
    )
);

-- 2. Claim token and claimed_at must be set together or both null
ALTER TABLE artifacts ADD CONSTRAINT artifacts_cleanup_claim_pair_ck CHECK (
    (cleanup_claim_token IS NULL AND cleanup_claimed_at IS NULL)
    OR
    (cleanup_claim_token IS NOT NULL AND cleanup_claimed_at IS NOT NULL)
);

-- 3. Exact error taxonomy: only the three reachable, justified error codes
ALTER TABLE artifacts ADD CONSTRAINT artifacts_cleanup_error_code_ck CHECK (
    cleanup_last_error_code IS NULL
    OR cleanup_last_error_code IN ('filesystem_io', 'durability_sync', 'unexpected_entry_type')
);

-- 4. If any cleanup lifecycle field is touched, address must be complete v1 and expires_at must be non-null
ALTER TABLE artifacts ADD CONSTRAINT artifacts_cleanup_lifecycle_address_ck CHECK (
    (
        content_deleted_at IS NULL
        AND cleanup_claim_token IS NULL
        AND cleanup_claimed_at IS NULL
        AND cleanup_retry_after IS NULL
        AND cleanup_last_error_code IS NULL
        AND cleanup_quarantined_at IS NULL
    )
    OR (
        addressing_version = 1
        AND artifact_store_id IS NOT NULL
        AND storage_key IS NOT NULL
        AND storage_location IS NULL
        AND expires_at IS NOT NULL
    )
);

-- 5. Exactly five mutually exclusive legal state shapes
ALTER TABLE artifacts ADD CONSTRAINT artifacts_cleanup_state_shape_ck CHECK (
    -- UNCLAIMED
    (
        content_deleted_at IS NULL
        AND cleanup_claim_token IS NULL
        AND cleanup_claimed_at IS NULL
        AND cleanup_retry_after IS NULL
        AND cleanup_last_error_code IS NULL
        AND cleanup_quarantined_at IS NULL
    )
    OR
    -- CLAIMED
    (
        content_deleted_at IS NULL
        AND cleanup_claim_token IS NOT NULL
        AND cleanup_claimed_at IS NOT NULL
        AND cleanup_retry_after IS NULL
        AND cleanup_last_error_code IS NULL
        AND cleanup_quarantined_at IS NULL
    )
    OR
    -- RETRY_WAIT
    (
        content_deleted_at IS NULL
        AND cleanup_claim_token IS NULL
        AND cleanup_claimed_at IS NULL
        AND cleanup_retry_after IS NOT NULL
        AND cleanup_last_error_code IS NOT NULL
        AND cleanup_last_error_code IN ('filesystem_io', 'durability_sync')
        AND cleanup_quarantined_at IS NULL
    )
    OR
    -- CONTENT_DELETED
    (
        content_deleted_at IS NOT NULL
        AND cleanup_claim_token IS NULL
        AND cleanup_claimed_at IS NULL
        AND cleanup_retry_after IS NULL
        AND cleanup_last_error_code IS NULL
        AND cleanup_quarantined_at IS NULL
    )
    OR
    -- QUARANTINED
    (
        content_deleted_at IS NULL
        AND cleanup_claim_token IS NULL
        AND cleanup_claimed_at IS NULL
        AND cleanup_retry_after IS NULL
        AND cleanup_last_error_code IS NOT NULL
        AND cleanup_last_error_code = 'unexpected_entry_type'
        AND cleanup_quarantined_at IS NOT NULL
    )
);

-- 6. Content deleted timestamp must be on or after expires_at
ALTER TABLE artifacts ADD CONSTRAINT artifacts_cleanup_tombstone_time_ck CHECK (
    content_deleted_at IS NULL
    OR (expires_at IS NOT NULL AND content_deleted_at >= expires_at)
);

-- 7. Retry state requires retryable error code
ALTER TABLE artifacts ADD CONSTRAINT artifacts_cleanup_retry_error_ck CHECK (
    cleanup_retry_after IS NULL
    OR (cleanup_last_error_code IS NOT NULL AND cleanup_last_error_code IN ('filesystem_io', 'durability_sync'))
);

-- 8. Quarantine state requires unexpected_entry_type
ALTER TABLE artifacts ADD CONSTRAINT artifacts_cleanup_quarantine_error_ck CHECK (
    cleanup_quarantined_at IS NULL
    OR (cleanup_last_error_code IS NOT NULL AND cleanup_last_error_code = 'unexpected_entry_type')
);

-- Partial index for eligible claim selection
CREATE INDEX artifacts_cleanup_eligible_idx
ON artifacts(artifact_store_id, expires_at ASC, id ASC)
WHERE addressing_version = 1
  AND expires_at IS NOT NULL
  AND content_deleted_at IS NULL
  AND cleanup_quarantined_at IS NULL;

-- Helper to determine cleanup state class
CREATE FUNCTION artifact_cleanup_state_class(
    content_deleted_at TIMESTAMPTZ,
    cleanup_claim_token UUID,
    cleanup_retry_after TIMESTAMPTZ,
    cleanup_quarantined_at TIMESTAMPTZ
) RETURNS TEXT AS $$
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
$$ LANGUAGE plpgsql IMMUTABLE;

-- Cleanup transition guard trigger
CREATE FUNCTION enforce_artifact_cleanup_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    old_touched BOOLEAN;
    new_touched BOOLEAN;
    old_state TEXT;
    new_state TEXT;
    cleanup_changed BOOLEAN;
BEGIN
    old_touched := (OLD.content_deleted_at IS NOT NULL OR OLD.cleanup_claim_token IS NOT NULL OR OLD.cleanup_claimed_at IS NOT NULL OR OLD.cleanup_retry_after IS NOT NULL OR OLD.cleanup_last_error_code IS NOT NULL OR OLD.cleanup_quarantined_at IS NOT NULL);
    new_touched := (NEW.content_deleted_at IS NOT NULL OR NEW.cleanup_claim_token IS NOT NULL OR NEW.cleanup_claimed_at IS NOT NULL OR NEW.cleanup_retry_after IS NOT NULL OR NEW.cleanup_last_error_code IS NOT NULL OR NEW.cleanup_quarantined_at IS NOT NULL);

    -- Expiry freeze: expires_at is immutable once cleanup lifecycle has been touched or is being assigned
    IF NEW.expires_at IS DISTINCT FROM OLD.expires_at AND (old_touched OR new_touched) THEN
        RAISE EXCEPTION 'expires_at is immutable once artifact cleanup lifecycle is touched';
    END IF;

    cleanup_changed := ROW(OLD.content_deleted_at, OLD.cleanup_claim_token, OLD.cleanup_claimed_at, OLD.cleanup_retry_after, OLD.cleanup_last_error_code, OLD.cleanup_quarantined_at)
        IS DISTINCT FROM ROW(NEW.content_deleted_at, NEW.cleanup_claim_token, NEW.cleanup_claimed_at, NEW.cleanup_retry_after, NEW.cleanup_last_error_code, NEW.cleanup_quarantined_at);

    IF NOT cleanup_changed THEN
        RETURN NEW;
    END IF;

    IF OLD.addressing_version = 0 OR NEW.addressing_version = 0 THEN
        RAISE EXCEPTION 'cleanup lifecycle transitions are prohibited on legacy version-0 artifacts';
    END IF;

    IF NEW.expires_at IS NULL THEN
        RAISE EXCEPTION 'cleanup lifecycle transitions require non-null expires_at';
    END IF;

    old_state := artifact_cleanup_state_class(OLD.content_deleted_at, OLD.cleanup_claim_token, OLD.cleanup_retry_after, OLD.cleanup_quarantined_at);
    new_state := artifact_cleanup_state_class(NEW.content_deleted_at, NEW.cleanup_claim_token, NEW.cleanup_retry_after, NEW.cleanup_quarantined_at);

    IF old_state = 'CONTENT_DELETED' THEN
        RAISE EXCEPTION 'content_deleted artifacts are terminal and immutable';
    END IF;

    IF old_state = 'QUARANTINED' THEN
        RAISE EXCEPTION 'quarantined artifacts are terminal and immutable';
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

    RAISE EXCEPTION 'illegal artifact cleanup transition from % to %', old_state, new_state;
END;
$$;

CREATE TRIGGER artifacts_cleanup_transition_guard
BEFORE UPDATE OF expires_at, content_deleted_at, cleanup_claim_token, cleanup_claimed_at, cleanup_retry_after, cleanup_last_error_code, cleanup_quarantined_at ON artifacts
FOR EACH ROW EXECUTE FUNCTION enforce_artifact_cleanup_transition();
