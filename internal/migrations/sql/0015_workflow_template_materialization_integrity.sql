ALTER TABLE workflow_runs
    ADD COLUMN materialized_definition JSONB,
    ADD COLUMN materialization_digest TEXT,
    ADD COLUMN original_scope_version_id UUID REFERENCES scope_versions(id) ON DELETE RESTRICT;

ALTER TABLE workflow_runs ADD CONSTRAINT workflow_runs_materialization_complete_ck CHECK (
    (
        materialized_definition IS NULL
        AND materialization_digest IS NULL
        AND original_scope_version_id IS NULL
    )
    OR
    (
        materialized_definition IS NOT NULL
        AND jsonb_typeof(materialized_definition)='object'
        AND materialization_digest ~ '^[a-f0-9]{64}$'
        AND original_scope_version_id IS NOT NULL
    )
);

CREATE FUNCTION reject_workflow_definition_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'workflow definitions are immutable';
    END IF;
    IF ROW(NEW.id,NEW.name,NEW.version,NEW.description,NEW.definition,NEW.default_policy_requirements,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.id,OLD.name,OLD.version,OLD.description,OLD.definition,OLD.default_policy_requirements,OLD.created_at) THEN
        RAISE EXCEPTION 'workflow definition identity and semantics are immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workflow_definitions_immutable
BEFORE UPDATE OR DELETE ON workflow_definitions
FOR EACH ROW EXECUTE FUNCTION reject_workflow_definition_mutation();

CREATE FUNCTION require_workflow_run_materialization_on_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.materialized_definition IS NULL
       OR NEW.materialization_digest IS NULL
       OR NEW.original_scope_version_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE='23514',
            MESSAGE='new workflow_runs require complete immutable materialization';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workflow_runs_materialization_required
BEFORE INSERT ON workflow_runs
FOR EACH ROW EXECUTE FUNCTION require_workflow_run_materialization_on_insert();

CREATE FUNCTION reject_workflow_run_lineage_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id,NEW.task_id,NEW.workflow_definition_id,NEW.workflow_version,NEW.previous_run_id,NEW.trigger_source,
           NEW.materialized_definition,NEW.materialization_digest,NEW.original_scope_version_id)
       IS DISTINCT FROM ROW(OLD.id,OLD.task_id,OLD.workflow_definition_id,OLD.workflow_version,OLD.previous_run_id,OLD.trigger_source,
                            OLD.materialized_definition,OLD.materialization_digest,OLD.original_scope_version_id) THEN
        RAISE EXCEPTION 'WorkflowRun identity is immutable; lineage and materialization are immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workflow_runs_lineage_guard
BEFORE UPDATE ON workflow_runs
FOR EACH ROW EXECUTE FUNCTION reject_workflow_run_lineage_mutation();

CREATE FUNCTION reject_task_lineage_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id,NEW.program_id,NEW.workflow_definition_id)
       IS DISTINCT FROM ROW(OLD.id,OLD.program_id,OLD.workflow_definition_id) THEN
        RAISE EXCEPTION 'Task identity is immutable; program and workflow template lineage are immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tasks_lineage_guard
BEFORE UPDATE ON tasks
FOR EACH ROW EXECUTE FUNCTION reject_task_lineage_mutation();
