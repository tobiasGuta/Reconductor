-- A and R are frozen together. The existing action_request_id is the action
-- identity; provider_invocation_started remains the execution identity X.
CREATE TABLE exact_actions (
    action_request_id UUID PRIMARY KEY,
    bound_provider_attempt_id UUID NOT NULL UNIQUE REFERENCES audit_events(id) ON DELETE RESTRICT,
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE RESTRICT,
    task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE RESTRICT,
    workflow_run_id UUID NOT NULL REFERENCES workflow_runs(id) ON DELETE RESTRICT,
    step_run_id UUID NOT NULL REFERENCES step_runs(id) ON DELETE RESTRICT,
    step_attempt INTEGER NOT NULL CHECK (step_attempt > 0),
    contract_schema TEXT NOT NULL CHECK (contract_schema='exact-action-contract/v1'),
    capability_semantic_revision TEXT NOT NULL CHECK (capability_semantic_revision='v1'),
    canonical_contract BYTEA NOT NULL CHECK (octet_length(canonical_contract) BETWEEN 1 AND 32768),
    action_sha256 TEXT NOT NULL CHECK (action_sha256 ~ '^[0-9a-f]{64}$'),
    review_schema TEXT NOT NULL CHECK (review_schema='exact-review-context/v1'),
    canonical_review_context BYTEA NOT NULL CHECK (octet_length(canonical_review_context) BETWEEN 1 AND 32768),
    review_context_sha256 TEXT NOT NULL CHECK (review_context_sha256 ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 80)
);

CREATE FUNCTION reject_exact_action_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'frozen exact action and review context are immutable';
END $$;
CREATE TRIGGER exact_actions_immutable BEFORE UPDATE OR DELETE ON exact_actions
    FOR EACH ROW EXECUTE FUNCTION reject_exact_action_mutation();

-- Only cited artifacts acquire the stronger identity freeze. Ordinary artifact
-- cleanup and unrelated legacy metadata remain governed by existing rules.
CREATE TABLE exact_action_citations (
    action_request_id UUID NOT NULL REFERENCES exact_actions(action_request_id) ON DELETE RESTRICT,
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    artifact_sha256 TEXT NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (action_request_id, artifact_id)
);
CREATE INDEX exact_action_citations_artifact_idx ON exact_action_citations(artifact_id);

-- The canonical review is the source of truth. The immediate INSERT check
-- rejects invented members; the deferred parent check allows preparation to
-- insert its children later in the same transaction, but rejects an incomplete
-- committed set. ReviewContextV1 forbids duplicate artifact IDs across roles.
CREATE FUNCTION exact_review_citation_pairs(review_bytes BYTEA)
RETURNS TABLE(artifact_id UUID, artifact_sha256 TEXT) LANGUAGE sql STABLE AS $$
    SELECT (member.citation->>'artifact_id')::uuid, member.citation->>'artifact_sha256'
    FROM jsonb_array_elements(
        COALESCE((convert_from(review_bytes, 'UTF8')::jsonb)->'supporting_evidence', '[]'::jsonb) ||
        COALESCE((convert_from(review_bytes, 'UTF8')::jsonb)->'contradictory_evidence', '[]'::jsonb)
    ) AS member(citation)
$$;

CREATE FUNCTION validate_exact_citation_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM exact_actions a,
            LATERAL exact_review_citation_pairs(a.canonical_review_context) c
        WHERE a.action_request_id=NEW.action_request_id
          AND c.artifact_id=NEW.artifact_id AND c.artifact_sha256=NEW.artifact_sha256
    ) THEN
        RAISE EXCEPTION 'exact citation is absent from the frozen review';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER exact_action_citations_insert_member BEFORE INSERT ON exact_action_citations
    FOR EACH ROW EXECUTE FUNCTION validate_exact_citation_insert();

CREATE FUNCTION require_complete_exact_citations() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    expected_count INTEGER;
    actual_count INTEGER;
BEGIN
    SELECT count(*) INTO expected_count
      FROM exact_review_citation_pairs(NEW.canonical_review_context);
    SELECT count(*) INTO actual_count
      FROM exact_action_citations WHERE action_request_id=NEW.action_request_id;
    IF expected_count <> actual_count THEN
        RAISE EXCEPTION 'frozen exact review citation set is incomplete';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER exact_actions_citations_complete
    AFTER INSERT ON exact_actions DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION require_complete_exact_citations();

-- A live pending P and a validated canonical citation form the durable review
-- claim. It ends automatically on decision, revocation, or expiry; no separate
-- claim ID or reconciliation worker is needed.
CREATE FUNCTION exact_review_evidence_protected(requested_artifact_id UUID)
RETURNS BOOLEAN LANGUAGE sql VOLATILE AS $$
    SELECT EXISTS (
        SELECT 1 FROM exact_action_citations c
        JOIN approvals p ON p.action_request_id=c.action_request_id
        WHERE c.artifact_id=requested_artifact_id
          AND p.approval_kind='exact_action' AND p.decision='pending'
          AND p.revoked_at IS NULL AND p.expires_at>clock_timestamp()
    )
$$;

CREATE FUNCTION reject_exact_citation_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'frozen exact review citation is immutable';
END $$;
CREATE TRIGGER exact_action_citations_immutable BEFORE UPDATE OR DELETE ON exact_action_citations
    FOR EACH ROW EXECUTE FUNCTION reject_exact_citation_mutation();

CREATE FUNCTION preserve_cited_artifact_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM exact_action_citations WHERE artifact_id=OLD.id)
       AND ROW(NEW.id,NEW.task_id,NEW.workflow_run_id,NEW.step_run_id,NEW.tool_run_id,NEW.sha256)
           IS DISTINCT FROM ROW(OLD.id,OLD.task_id,OLD.workflow_run_id,OLD.step_run_id,OLD.tool_run_id,OLD.sha256) THEN
        RAISE EXCEPTION 'cited exact review artifact identity is immutable';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER artifacts_exact_citation_identity BEFORE UPDATE OF id,task_id,workflow_run_id,step_run_id,tool_run_id,sha256 ON artifacts
    FOR EACH ROW EXECUTE FUNCTION preserve_cited_artifact_identity();

-- Slice 1 protects P's identity; terminal decisions must also be one-way.
CREATE FUNCTION preserve_exact_approval_decision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.approval_kind='exact_action' AND OLD.decision <> 'pending'
       AND (NEW.decision IS DISTINCT FROM OLD.decision OR
            NEW.decided_at IS DISTINCT FROM OLD.decided_at OR
            NEW.decided_by IS DISTINCT FROM OLD.decided_by) THEN
        RAISE EXCEPTION 'terminal exact approval decision is immutable';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER approvals_exact_decision_immutable BEFORE UPDATE ON approvals
    FOR EACH ROW EXECUTE FUNCTION preserve_exact_approval_decision();
