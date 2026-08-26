CREATE TABLE canonical_concrete_http_resources (
    id UUID PRIMARY KEY,
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE RESTRICT,
    identity_namespace TEXT NOT NULL CHECK (identity_namespace='http-uri-resource-v1'),
    scheme TEXT NOT NULL CHECK (scheme IN ('http','https')),
    host TEXT NOT NULL CHECK (btrim(host) <> '' AND host=lower(host)),
    effective_port INTEGER NOT NULL CHECK (effective_port BETWEEN 1 AND 65535),
    concrete_escaped_path TEXT NOT NULL CHECK (left(concrete_escaped_path,1)='/' AND btrim(concrete_escaped_path) <> ''),
    canonical_query TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(program_id,identity_namespace,scheme,host,effective_port,concrete_escaped_path,canonical_query)
);

CREATE TABLE probe_http_source_records (
    source_locator TEXT PRIMARY KEY CHECK (source_locator ~ '^[a-f0-9]{64}$'),
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE RESTRICT,
    concrete_http_resource_id UUID NOT NULL REFERENCES canonical_concrete_http_resources(id) ON DELETE RESTRICT,
    asset_observation_id UUID NOT NULL,
    provider_result_accepted_event_id UUID NOT NULL REFERENCES audit_events(id) ON DELETE RESTRICT,
    provider_attempt_id UUID NOT NULL REFERENCES audit_events(id) ON DELETE RESTRICT,
    normalized_result_artifact_id UUID,
    authorized_record_index INTEGER NOT NULL CHECK (authorized_record_index >= 0),
    record_digest TEXT NOT NULL CHECK (record_digest ~ '^[a-f0-9]{64}$'),
    request_method_state TEXT NOT NULL CHECK (request_method_state IN ('known','defaulted','unknown')),
    request_method_value TEXT,
    request_content_type_state TEXT NOT NULL CHECK (request_content_type_state IN ('known','defaulted','unknown')),
    request_content_type_value TEXT,
    identity_namespace TEXT NOT NULL CHECK (identity_namespace='http-uri-resource-v1'),
    derivation_version TEXT NOT NULL CHECK (derivation_version='http-resource-derivation-v1'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY(asset_observation_id,provider_result_accepted_event_id)
        REFERENCES asset_observation_emissions(asset_observation_id,provider_result_accepted_event_id)
        ON DELETE RESTRICT,
    CHECK (
        (request_method_state='known' AND request_method_value IS NOT NULL AND btrim(request_method_value)<>'' AND request_method_value=upper(request_method_value))
        OR (request_method_state='defaulted' AND request_method_value='GET')
        OR (request_method_state='unknown' AND request_method_value IS NULL)
    ),
    CHECK (
        (request_content_type_state='known' AND request_content_type_value IS NOT NULL AND request_content_type_value=btrim(request_content_type_value) AND request_content_type_value=lower(request_content_type_value))
        OR (request_content_type_state='defaulted' AND request_content_type_value='')
        OR (request_content_type_state='unknown' AND request_content_type_value IS NULL)
    )
);

CREATE INDEX probe_http_source_records_program_event_idx
    ON probe_http_source_records(program_id,provider_result_accepted_event_id,source_locator);

CREATE INDEX probe_http_source_records_resource_idx
    ON probe_http_source_records(concrete_http_resource_id);

CREATE FUNCTION reject_concrete_http_resource_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id,NEW.program_id,NEW.identity_namespace,NEW.scheme,NEW.host,NEW.effective_port,NEW.concrete_escaped_path,NEW.canonical_query)
       IS DISTINCT FROM ROW(OLD.id,OLD.program_id,OLD.identity_namespace,OLD.scheme,OLD.host,OLD.effective_port,OLD.concrete_escaped_path,OLD.canonical_query) THEN
        RAISE EXCEPTION 'canonical concrete HTTP resource identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER canonical_concrete_http_resources_identity_guard
BEFORE UPDATE ON canonical_concrete_http_resources
FOR EACH ROW EXECUTE FUNCTION reject_concrete_http_resource_identity_mutation();

CREATE FUNCTION validate_probe_http_source_record() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1
    FROM canonical_concrete_http_resources resource
    JOIN asset_observations observation ON observation.id=NEW.asset_observation_id
    JOIN assets asset ON asset.id=observation.asset_id
    JOIN asset_observation_emissions emission
      ON emission.asset_observation_id=NEW.asset_observation_id
     AND emission.provider_result_accepted_event_id=NEW.provider_result_accepted_event_id
    JOIN audit_events accepted_event ON accepted_event.id=NEW.provider_result_accepted_event_id
    JOIN audit_events provider_attempt ON provider_attempt.id=NEW.provider_attempt_id
    JOIN tool_runs accepted_tool ON accepted_tool.id=accepted_event.tool_run_id
    JOIN step_runs accepted_step ON accepted_step.id=accepted_event.step_run_id
    JOIN workflow_runs accepted_workflow ON accepted_workflow.id=accepted_event.workflow_run_id
    JOIN tasks accepted_task ON accepted_task.id=accepted_event.task_id
    JOIN audit_events authorization_event ON authorization_event.id=provider_attempt.execution_authorization_event_id
    WHERE resource.id=NEW.concrete_http_resource_id
      AND resource.program_id=NEW.program_id
      AND resource.identity_namespace=NEW.identity_namespace
      AND asset.program_id=NEW.program_id
      AND asset.type='http_service'
      AND emission.program_id=NEW.program_id
      AND observation.workflow_run_id=accepted_event.workflow_run_id
      AND observation.source_capability='probe.http'
      AND accepted_event.program_id=NEW.program_id
      AND accepted_event.event_type='provider_result_accepted'
      AND accepted_event.capability='probe.http'
      AND accepted_event.provider_attempt_id=NEW.provider_attempt_id
      AND accepted_event.tool_run_id IS NOT NULL
      AND provider_attempt.program_id=NEW.program_id
      AND provider_attempt.event_type='provider_invocation_started'
      AND provider_attempt.capability='probe.http'
	  AND provider_attempt.provider=accepted_event.provider
      AND provider_attempt.workflow_run_id=accepted_event.workflow_run_id
      AND provider_attempt.step_run_id=accepted_event.step_run_id
      AND provider_attempt.task_id IS NOT DISTINCT FROM accepted_event.task_id
      AND provider_attempt.action_request_id IS NOT DISTINCT FROM accepted_event.action_request_id
      AND provider_attempt.step_attempt IS NOT DISTINCT FROM accepted_event.step_attempt
      AND provider_attempt.queue_job_id IS NOT DISTINCT FROM accepted_event.queue_job_id
      AND provider_attempt.scheduled_execution_id IS NOT DISTINCT FROM accepted_event.scheduled_execution_id
      AND provider_attempt.scheduler_attempt IS NOT DISTINCT FROM accepted_event.scheduler_attempt
      AND provider_attempt.execution_authorization_event_id IS NOT DISTINCT FROM accepted_event.execution_authorization_event_id
      AND accepted_tool.provider_attempt_id=NEW.provider_attempt_id
      AND accepted_tool.step_run_id=accepted_event.step_run_id
      AND accepted_tool.capability=accepted_event.capability
      AND accepted_tool.provider=accepted_event.provider
      AND accepted_step.workflow_run_id=accepted_workflow.id
      AND accepted_step.capability=accepted_event.capability
      AND accepted_workflow.task_id=accepted_task.id
      AND accepted_task.program_id=NEW.program_id
      AND authorization_event.event_type='policy_allowed'
      AND authorization_event.details->>'phase'='execution'
      AND authorization_event.task_id IS NOT DISTINCT FROM provider_attempt.task_id
      AND authorization_event.program_id IS NOT DISTINCT FROM provider_attempt.program_id
      AND authorization_event.workflow_run_id IS NOT DISTINCT FROM provider_attempt.workflow_run_id
      AND authorization_event.step_run_id IS NOT DISTINCT FROM provider_attempt.step_run_id
      AND authorization_event.scheduled_execution_id IS NOT DISTINCT FROM provider_attempt.scheduled_execution_id
      AND authorization_event.scheduler_attempt IS NOT DISTINCT FROM provider_attempt.scheduler_attempt
      AND authorization_event.action_request_id IS NOT DISTINCT FROM provider_attempt.action_request_id
      AND authorization_event.step_attempt IS NOT DISTINCT FROM provider_attempt.step_attempt
      AND authorization_event.queue_job_id IS NOT DISTINCT FROM provider_attempt.queue_job_id
      AND authorization_event.capability IS NOT DISTINCT FROM provider_attempt.capability
      AND authorization_event.provider IS NOT DISTINCT FROM provider_attempt.provider
    FOR SHARE OF resource,observation,asset,emission,accepted_event,provider_attempt,accepted_tool,accepted_step,accepted_workflow,accepted_task,authorization_event;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'probe HTTP source record lineage is inconsistent';
    END IF;

    IF NEW.normalized_result_artifact_id IS NOT NULL THEN
        PERFORM 1
        FROM artifacts artifact
        JOIN tasks artifact_task ON artifact_task.id=artifact.task_id
        JOIN audit_events accepted_event ON accepted_event.id=NEW.provider_result_accepted_event_id
        WHERE artifact.id=NEW.normalized_result_artifact_id
          AND artifact.type='normalized-result'
          AND artifact.task_id=accepted_event.task_id
          AND artifact.workflow_run_id=accepted_event.workflow_run_id
          AND artifact.step_run_id=accepted_event.step_run_id
          AND artifact.tool_run_id=accepted_event.tool_run_id
          AND artifact_task.program_id=accepted_event.program_id
        FOR SHARE OF artifact,artifact_task,accepted_event;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'probe HTTP source record normalized-result artifact lineage is inconsistent';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER probe_http_source_records_validate
BEFORE INSERT ON probe_http_source_records
FOR EACH ROW EXECUTE FUNCTION validate_probe_http_source_record();

CREATE FUNCTION reject_probe_http_source_record_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'probe_http_source_records are append-only';
END;
$$;

CREATE TRIGGER probe_http_source_records_immutable
BEFORE UPDATE OR DELETE ON probe_http_source_records
FOR EACH ROW EXECUTE FUNCTION reject_probe_http_source_record_mutation();

CREATE FUNCTION reject_probe_http_source_tool_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id,NEW.step_run_id,NEW.capability,NEW.provider,NEW.provider_attempt_id)
       IS DISTINCT FROM ROW(OLD.id,OLD.step_run_id,OLD.capability,OLD.provider,OLD.provider_attempt_id)
       AND EXISTS (
           SELECT 1
           FROM probe_http_source_records source
           JOIN audit_events accepted_event ON accepted_event.id=source.provider_result_accepted_event_id
           WHERE accepted_event.tool_run_id=OLD.id
       ) THEN
        RAISE EXCEPTION 'source-linked ToolRun identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tool_runs_probe_http_source_identity_guard
BEFORE UPDATE OF id,step_run_id,capability,provider,provider_attempt_id ON tool_runs
FOR EACH ROW EXECUTE FUNCTION reject_probe_http_source_tool_identity_mutation();

CREATE FUNCTION reject_probe_http_source_step_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.workflow_run_id,NEW.capability)
       IS DISTINCT FROM ROW(OLD.workflow_run_id,OLD.capability)
       AND EXISTS (
           SELECT 1
           FROM probe_http_source_records source
           JOIN audit_events accepted_event ON accepted_event.id=source.provider_result_accepted_event_id
           WHERE accepted_event.step_run_id=OLD.id
       ) THEN
        RAISE EXCEPTION 'source-linked StepRun identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER step_runs_probe_http_source_identity_guard
BEFORE UPDATE OF workflow_run_id,capability ON step_runs
FOR EACH ROW EXECUTE FUNCTION reject_probe_http_source_step_identity_mutation();

CREATE FUNCTION reject_probe_http_source_workflow_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.task_id IS DISTINCT FROM OLD.task_id
       AND EXISTS (
           SELECT 1
           FROM probe_http_source_records source
           JOIN audit_events accepted_event ON accepted_event.id=source.provider_result_accepted_event_id
           WHERE accepted_event.workflow_run_id=OLD.id
       ) THEN
        RAISE EXCEPTION 'source-linked WorkflowRun identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER workflow_runs_probe_http_source_identity_guard
BEFORE UPDATE OF task_id ON workflow_runs
FOR EACH ROW EXECUTE FUNCTION reject_probe_http_source_workflow_identity_mutation();

CREATE FUNCTION reject_probe_http_source_task_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.program_id IS DISTINCT FROM OLD.program_id
       AND EXISTS (
           SELECT 1
           FROM probe_http_source_records source
           JOIN audit_events accepted_event ON accepted_event.id=source.provider_result_accepted_event_id
           WHERE accepted_event.task_id=OLD.id
       ) THEN
        RAISE EXCEPTION 'source-linked Task identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tasks_probe_http_source_identity_guard
BEFORE UPDATE OF program_id ON tasks
FOR EACH ROW EXECUTE FUNCTION reject_probe_http_source_task_identity_mutation();

CREATE FUNCTION reject_probe_http_source_artifact_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.id,NEW.task_id,NEW.workflow_run_id,NEW.step_run_id,NEW.tool_run_id,NEW.type)
       IS DISTINCT FROM ROW(OLD.id,OLD.task_id,OLD.workflow_run_id,OLD.step_run_id,OLD.tool_run_id,OLD.type)
       AND EXISTS (
           SELECT 1
           FROM probe_http_source_records source
           WHERE source.normalized_result_artifact_id=OLD.id
       ) THEN
        RAISE EXCEPTION 'source-linked artifact identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifacts_probe_http_source_identity_guard
BEFORE UPDATE OF id,task_id,workflow_run_id,step_run_id,tool_run_id,type ON artifacts
FOR EACH ROW EXECUTE FUNCTION reject_probe_http_source_artifact_identity_mutation();

CREATE FUNCTION reject_probe_http_source_artifact_rebinding() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM probe_http_source_records source
        JOIN audit_events accepted_event ON accepted_event.id=source.provider_result_accepted_event_id
        LEFT JOIN tasks artifact_task ON artifact_task.id=NEW.task_id
        WHERE source.normalized_result_artifact_id=NEW.id
          AND (
              NEW.task_id IS DISTINCT FROM accepted_event.task_id
              OR NEW.workflow_run_id IS DISTINCT FROM accepted_event.workflow_run_id
              OR NEW.step_run_id IS DISTINCT FROM accepted_event.step_run_id
              OR NEW.tool_run_id IS DISTINCT FROM accepted_event.tool_run_id
              OR NEW.type IS DISTINCT FROM 'normalized-result'
              OR artifact_task.program_id IS DISTINCT FROM accepted_event.program_id
          )
    ) THEN
        RAISE EXCEPTION 'source-linked artifact identity cannot be rebound';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifacts_probe_http_source_rebinding_guard
BEFORE INSERT ON artifacts
FOR EACH ROW EXECUTE FUNCTION reject_probe_http_source_artifact_rebinding();
