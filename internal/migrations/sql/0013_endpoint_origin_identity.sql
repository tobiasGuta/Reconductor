ALTER TABLE endpoints ADD COLUMN origin_scheme TEXT;
ALTER TABLE endpoints ADD COLUMN origin_host TEXT;
ALTER TABLE endpoints ADD COLUMN origin_effective_port INTEGER;

ALTER TABLE endpoints ADD CONSTRAINT endpoints_corrected_row_ck CHECK (
  id IS NOT NULL
  AND program_id IS NOT NULL
  AND exact_url IS NOT NULL
  AND btrim(exact_url) <> ''
  AND route_signature IS NOT NULL
  AND btrim(route_signature) <> ''
  AND left(route_signature, 1) = '/'
  AND method IS NOT NULL
  AND btrim(method) <> ''
  AND method = btrim(method)
  AND method = upper(method)
  AND content_type IS NOT NULL
  AND content_type = btrim(content_type)
  AND content_type = lower(content_type)
  AND parameter_schema IS NOT NULL
  AND jsonb_typeof(parameter_schema) = 'array'
  AND origin_scheme IS NOT NULL
  AND origin_scheme IN ('http', 'https')
  AND origin_host IS NOT NULL
  AND btrim(origin_host) <> ''
  AND origin_effective_port IS NOT NULL
  AND origin_effective_port BETWEEN 1 AND 65535
  AND first_seen IS NOT NULL
  AND last_seen IS NOT NULL
  AND first_seen <= last_seen
) NOT VALID;

CREATE FUNCTION reject_endpoint_identity_mutation() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.id IS DISTINCT FROM NEW.id
     OR OLD.program_id IS DISTINCT FROM NEW.program_id
     OR OLD.origin_scheme IS DISTINCT FROM NEW.origin_scheme
     OR OLD.origin_host IS DISTINCT FROM NEW.origin_host
     OR OLD.origin_effective_port IS DISTINCT FROM NEW.origin_effective_port
     OR OLD.route_signature IS DISTINCT FROM NEW.route_signature
     OR OLD.method IS DISTINCT FROM NEW.method
     OR OLD.content_type IS DISTINCT FROM NEW.content_type
     OR OLD.parameter_schema IS DISTINCT FROM NEW.parameter_schema THEN
    RAISE EXCEPTION 'endpoint identity fields are immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER endpoints_identity_guard
BEFORE UPDATE ON endpoints
FOR EACH ROW EXECUTE FUNCTION reject_endpoint_identity_mutation();

CREATE UNIQUE INDEX endpoints_corrected_identity_uq ON endpoints(
  program_id,
  origin_scheme,
  origin_host,
  origin_effective_port,
  route_signature,
  method,
  content_type,
  parameter_schema
) WHERE origin_scheme IS NOT NULL
  AND origin_host IS NOT NULL
  AND origin_effective_port IS NOT NULL;

DROP INDEX endpoints_identity_uq;
