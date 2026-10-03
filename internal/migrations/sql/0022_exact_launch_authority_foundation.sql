-- Exact-action launch authority is opt-in. Existing programs start blocked until
-- a trusted publisher supplies complete, versioned scope and policy material.
ALTER TABLE scopes
    ADD COLUMN material_schema TEXT,
    ADD COLUMN evaluator_revision TEXT,
    ADD COLUMN canonical_material BYTEA,
    ADD COLUMN material_sha256 TEXT,
    ADD COLUMN scope_digest TEXT;
ALTER TABLE policies
    ADD COLUMN material_schema TEXT,
    ADD COLUMN evaluator_revision TEXT,
    ADD COLUMN canonical_material BYTEA,
    ADD COLUMN material_sha256 TEXT;

ALTER TABLE scopes ADD CONSTRAINT scopes_exact_material_complete CHECK (
    (material_schema IS NULL AND evaluator_revision IS NULL AND canonical_material IS NULL AND material_sha256 IS NULL AND scope_digest IS NULL)
    OR (material_schema IS NOT NULL AND evaluator_revision IS NOT NULL AND canonical_material IS NOT NULL
        AND material_sha256 IS NOT NULL AND material_sha256 ~ '^[0-9a-f]{64}$'
        AND scope_digest IS NOT NULL AND scope_digest ~ '^[0-9a-f]{64}$')
);
ALTER TABLE policies ADD CONSTRAINT policies_exact_material_complete CHECK (
    (material_schema IS NULL AND evaluator_revision IS NULL AND canonical_material IS NULL AND material_sha256 IS NULL)
    OR (material_schema IS NOT NULL AND evaluator_revision IS NOT NULL AND canonical_material IS NOT NULL
        AND material_sha256 IS NOT NULL AND material_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE FUNCTION reject_exact_authority_material_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.canonical_material IS NOT NULL THEN
        RAISE EXCEPTION 'published exact launch material is immutable';
    END IF;
    IF TG_OP='DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER scopes_exact_material_immutable BEFORE UPDATE OR DELETE ON scopes
    FOR EACH ROW EXECUTE FUNCTION reject_exact_authority_material_change();
CREATE TRIGGER policies_exact_material_immutable BEFORE UPDATE OR DELETE ON policies
    FOR EACH ROW EXECUTE FUNCTION reject_exact_authority_material_change();

CREATE TABLE program_launch_authority (
    program_id UUID PRIMARY KEY REFERENCES programs(id) ON DELETE RESTRICT,
    active_scope_id UUID REFERENCES scopes(id) ON DELETE RESTRICT,
    active_policy_id UUID REFERENCES policies(id) ON DELETE RESTRICT,
    authority_epoch BIGINT NOT NULL DEFAULT 0 CHECK (authority_epoch >= 0),
    status TEXT NOT NULL DEFAULT 'BLOCKED' CHECK (status IN ('READY','BLOCKED')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_by TEXT NOT NULL DEFAULT 'migration',
    reason TEXT NOT NULL DEFAULT 'not published',
    CHECK (length(updated_by) BETWEEN 1 AND 80),
    CHECK (length(reason) <= 256),
    CHECK (status <> 'READY' OR (active_scope_id IS NOT NULL AND active_policy_id IS NOT NULL))
);

CREATE FUNCTION preserve_exact_authority_epoch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'exact launch authority identity cannot be deleted';
    END IF;
    IF NEW.program_id IS DISTINCT FROM OLD.program_id THEN
        RAISE EXCEPTION 'exact launch authority program identity is immutable';
    END IF;
    IF NEW.authority_epoch <= OLD.authority_epoch THEN
        RAISE EXCEPTION 'exact launch authority epoch must advance';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER program_launch_authority_epoch BEFORE UPDATE OR DELETE ON program_launch_authority
    FOR EACH ROW EXECUTE FUNCTION preserve_exact_authority_epoch();
INSERT INTO program_launch_authority(program_id)
SELECT id FROM programs ON CONFLICT (program_id) DO NOTHING;

-- Program scope metadata is a legacy write path. Changing its executable
-- semantics invalidates exact authority in the same transaction, after the
-- existing scope-version and program locks. Locator-only repairs do not.
CREATE FUNCTION invalidate_exact_authority_on_program_scope_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.scope_digest IS DISTINCT FROM NEW.scope_digest
       OR OLD.include_rule_digests IS DISTINCT FROM NEW.include_rule_digests
       OR OLD.exclude_rule_digests IS DISTINCT FROM NEW.exclude_rule_digests
       OR OLD.target_plan_digest IS DISTINCT FROM NEW.target_plan_digest THEN
        UPDATE program_launch_authority
           SET status='BLOCKED', authority_epoch=authority_epoch+1,
               updated_at=clock_timestamp(), updated_by='scope-writer',
               reason='program scope semantics changed'
         WHERE program_id=NEW.id;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER programs_exact_scope_invalidation AFTER UPDATE ON programs
    FOR EACH ROW EXECUTE FUNCTION invalidate_exact_authority_on_program_scope_change();

ALTER TABLE approvals
    ADD COLUMN approval_kind TEXT NOT NULL DEFAULT 'workflow_step' CHECK (approval_kind IN ('workflow_step','exact_action')),
    ADD COLUMN action_sha256 TEXT,
    ADD COLUMN review_context_sha256 TEXT,
    ADD COLUMN revoked_at TIMESTAMPTZ,
    ADD COLUMN revoked_by TEXT,
    ADD COLUMN bound_provider_attempt_id UUID REFERENCES audit_events(id) ON DELETE RESTRICT;
ALTER TABLE approvals ADD CONSTRAINT approvals_exact_fields CHECK (
    approval_kind <> 'exact_action' OR
    (action_sha256 IS NOT NULL AND action_sha256 ~ '^[0-9a-f]{64}$'
     AND review_context_sha256 IS NOT NULL AND review_context_sha256 ~ '^[0-9a-f]{64}$'
     AND bound_provider_attempt_id IS NOT NULL)
);
CREATE UNIQUE INDEX approvals_exact_bound_attempt_unique
    ON approvals(bound_provider_attempt_id) WHERE bound_provider_attempt_id IS NOT NULL;

CREATE FUNCTION preserve_exact_approval_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        IF OLD.approval_kind='exact_action' THEN
            RAISE EXCEPTION 'bound exact approval cannot be deleted';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.approval_kind='exact_action' AND
       (OLD.id IS DISTINCT FROM NEW.id OR
        OLD.approval_kind IS DISTINCT FROM NEW.approval_kind OR
        OLD.action_sha256 IS DISTINCT FROM NEW.action_sha256 OR
        OLD.review_context_sha256 IS DISTINCT FROM NEW.review_context_sha256 OR
        OLD.bound_provider_attempt_id IS DISTINCT FROM NEW.bound_provider_attempt_id OR
        OLD.action_request_id IS DISTINCT FROM NEW.action_request_id OR
        OLD.request_id IS DISTINCT FROM NEW.request_id OR
        OLD.task_id IS DISTINCT FROM NEW.task_id) THEN
        RAISE EXCEPTION 'exact approval identity is immutable';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER approvals_exact_identity_immutable BEFORE UPDATE OR DELETE ON approvals
    FOR EACH ROW EXECUTE FUNCTION preserve_exact_approval_identity();

-- X remains the existing provider_invocation_started audit identity. This
-- companion holds only mutable launch state; it cannot mint provider attempts.
CREATE TABLE exact_dispatch_attempts (
    provider_attempt_id UUID PRIMARY KEY REFERENCES audit_events(id) ON DELETE RESTRICT,
    approval_id UUID NOT NULL UNIQUE REFERENCES approvals(id) ON DELETE RESTRICT,
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE RESTRICT,
    action_request_id UUID NOT NULL,
    action_sha256 TEXT NOT NULL CHECK (action_sha256 ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL DEFAULT 'UNDISPATCHED' CHECK (state IN ('UNDISPATCHED','DISPATCH_INTENT')),
    active_scope_id UUID REFERENCES scopes(id) ON DELETE RESTRICT,
    scope_sha256 TEXT,
    active_policy_id UUID REFERENCES policies(id) ON DELETE RESTRICT,
    policy_sha256 TEXT,
    authority_epoch BIGINT,
    scope_evaluator_revision TEXT,
    policy_evaluator_revision TEXT,
    scope_reason TEXT,
    policy_reason TEXT,
    eligibility_checked_at TIMESTAMPTZ,
    dispatch_intent_at TIMESTAMPTZ,
    CHECK (state <> 'DISPATCH_INTENT' OR
      (active_scope_id IS NOT NULL AND scope_sha256 IS NOT NULL AND
       active_policy_id IS NOT NULL AND policy_sha256 IS NOT NULL AND
       authority_epoch IS NOT NULL AND scope_evaluator_revision IS NOT NULL AND
       policy_evaluator_revision IS NOT NULL AND eligibility_checked_at IS NOT NULL AND
       dispatch_intent_at IS NOT NULL))
);

CREATE FUNCTION preserve_exact_dispatch_intent() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	IF TG_OP='DELETE' THEN
		RAISE EXCEPTION 'exact dispatch companion cannot be deleted';
	END IF;
    IF OLD.state='DISPATCH_INTENT' THEN
        RAISE EXCEPTION 'exact dispatch intent is immutable';
    END IF;
    IF OLD.provider_attempt_id IS DISTINCT FROM NEW.provider_attempt_id OR
       OLD.approval_id IS DISTINCT FROM NEW.approval_id OR
       OLD.program_id IS DISTINCT FROM NEW.program_id OR
       OLD.action_request_id IS DISTINCT FROM NEW.action_request_id OR
       OLD.action_sha256 IS DISTINCT FROM NEW.action_sha256 THEN
        RAISE EXCEPTION 'exact dispatch identity is immutable';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER exact_dispatch_intent_immutable BEFORE UPDATE OR DELETE ON exact_dispatch_attempts
    FOR EACH ROW EXECUTE FUNCTION preserve_exact_dispatch_intent();
