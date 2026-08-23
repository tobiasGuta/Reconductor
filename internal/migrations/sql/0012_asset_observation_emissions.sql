CREATE TABLE asset_observation_emissions (
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE RESTRICT,
    asset_observation_id UUID NOT NULL REFERENCES asset_observations(id) ON DELETE RESTRICT,
    provider_result_accepted_event_id UUID NOT NULL REFERENCES audit_events(id) ON DELETE RESTRICT,
    PRIMARY KEY(asset_observation_id, provider_result_accepted_event_id)
);

CREATE INDEX asset_observation_emissions_program_event_idx
    ON asset_observation_emissions(program_id, provider_result_accepted_event_id, asset_observation_id);

CREATE FUNCTION validate_asset_observation_emission() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1
    FROM asset_observations observation
    JOIN assets asset ON asset.id=observation.asset_id
    JOIN audit_events accepted_event ON accepted_event.id=NEW.provider_result_accepted_event_id
    WHERE observation.id=NEW.asset_observation_id
      AND asset.program_id=NEW.program_id
      AND accepted_event.program_id=NEW.program_id
      AND observation.workflow_run_id=accepted_event.workflow_run_id
      AND observation.source_capability=accepted_event.capability
      AND accepted_event.event_type='provider_result_accepted'
      AND accepted_event.provider_attempt_id IS NOT NULL
      AND accepted_event.tool_run_id IS NOT NULL
    FOR SHARE OF observation,asset;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'asset observation emission lineage is inconsistent';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER asset_observation_emissions_validate
BEFORE INSERT ON asset_observation_emissions
FOR EACH ROW EXECUTE FUNCTION validate_asset_observation_emission();

CREATE FUNCTION reject_asset_observation_emission_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'asset_observation_emissions are append-only';
END;
$$;

CREATE TRIGGER asset_observation_emissions_immutable
BEFORE UPDATE OR DELETE ON asset_observation_emissions
FOR EACH ROW EXECUTE FUNCTION reject_asset_observation_emission_mutation();

CREATE FUNCTION reject_emitted_asset_observation_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.asset_id,NEW.workflow_run_id,NEW.source_capability,NEW.observed_value)
       IS DISTINCT FROM ROW(OLD.asset_id,OLD.workflow_run_id,OLD.source_capability,OLD.observed_value)
       AND EXISTS (
           SELECT 1
           FROM asset_observation_emissions emission
           WHERE emission.asset_observation_id=OLD.id
       ) THEN
        RAISE EXCEPTION 'emitted asset observation identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER asset_observations_emission_identity_guard
BEFORE UPDATE OF asset_id,workflow_run_id,source_capability,observed_value ON asset_observations
FOR EACH ROW EXECUTE FUNCTION reject_emitted_asset_observation_identity_mutation();

CREATE FUNCTION reject_emitted_asset_identity_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.program_id,NEW.type,NEW.canonical_value)
       IS DISTINCT FROM ROW(OLD.program_id,OLD.type,OLD.canonical_value)
       AND EXISTS (
           SELECT 1
           FROM asset_observation_emissions emission
           JOIN asset_observations observation ON observation.id=emission.asset_observation_id
           WHERE observation.asset_id=OLD.id
       ) THEN
        RAISE EXCEPTION 'emitted asset identity is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER assets_emission_identity_guard
BEFORE UPDATE OF program_id,type,canonical_value ON assets
FOR EACH ROW EXECUTE FUNCTION reject_emitted_asset_identity_mutation();
