CREATE TABLE artifact_stores (
    id UUID PRIMARY KEY,
    incarnation_nonce UUID NOT NULL UNIQUE,
    backend_kind TEXT NOT NULL CONSTRAINT artifact_stores_backend_kind_ck CHECK (backend_kind='local-v1'),
    marker_format TEXT NOT NULL CONSTRAINT artifact_stores_marker_format_ck CHECK (marker_format='reconductor-artifact-store'),
    marker_version INTEGER NOT NULL CONSTRAINT artifact_stores_marker_version_ck CHECK (marker_version=1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE artifacts
	ADD COLUMN addressing_version SMALLINT NOT NULL DEFAULT 0,
	ADD COLUMN artifact_store_id UUID,
	ADD COLUMN storage_key TEXT;

ALTER TABLE artifacts ALTER COLUMN storage_location DROP NOT NULL;
ALTER TABLE artifacts ALTER COLUMN addressing_version SET DEFAULT 1;

ALTER TABLE artifacts ADD CONSTRAINT artifacts_addressing_version_ck
    CHECK (addressing_version IN (0,1));
ALTER TABLE artifacts ADD CONSTRAINT artifacts_address_shape_ck CHECK (
    (
        addressing_version=0
        AND artifact_store_id IS NULL
        AND storage_key IS NULL
        AND storage_location IS NOT NULL
    )
    OR
    (
        addressing_version=1
        AND artifact_store_id IS NOT NULL
        AND storage_key IS NOT NULL
        AND storage_location IS NULL
    )
);
ALTER TABLE artifacts ADD CONSTRAINT artifacts_storage_key_v1_ck CHECK (
    addressing_version<>1
    OR storage_key=('v1/' || substr(replace(id::text,'-',''),1,2) || '/' || id::text)
);
ALTER TABLE artifacts ADD CONSTRAINT artifacts_artifact_store_id_fkey
    FOREIGN KEY (artifact_store_id) REFERENCES artifact_stores(id) ON UPDATE RESTRICT ON DELETE RESTRICT;
CREATE UNIQUE INDEX artifacts_store_storage_key_uidx
    ON artifacts(artifact_store_id,storage_key) WHERE addressing_version=1;

CREATE FUNCTION reject_new_legacy_artifact() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.addressing_version=0 THEN
        RAISE EXCEPTION USING
            ERRCODE='23514',
            MESSAGE='new version-0 artifacts are not permitted';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifacts_reject_legacy_insert
BEFORE INSERT ON artifacts
FOR EACH ROW EXECUTE FUNCTION reject_new_legacy_artifact();

CREATE FUNCTION reject_artifact_address_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.addressing_version,NEW.artifact_store_id,NEW.storage_key,NEW.storage_location)
       IS DISTINCT FROM ROW(OLD.addressing_version,OLD.artifact_store_id,OLD.storage_key,OLD.storage_location) THEN
        RAISE EXCEPTION 'Artifact addressing is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifacts_address_guard
BEFORE UPDATE OF addressing_version,artifact_store_id,storage_key,storage_location ON artifacts
FOR EACH ROW EXECUTE FUNCTION reject_artifact_address_mutation();

CREATE FUNCTION reject_artifact_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Artifact metadata deletion is prohibited';
END;
$$;

CREATE TRIGGER artifacts_delete_guard
BEFORE DELETE ON artifacts
FOR EACH ROW EXECUTE FUNCTION reject_artifact_delete();

CREATE FUNCTION reject_artifact_store_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'artifact store registrations are immutable';
    END IF;
    IF ROW(NEW.id,NEW.incarnation_nonce,NEW.backend_kind,NEW.marker_format,NEW.marker_version,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.id,OLD.incarnation_nonce,OLD.backend_kind,OLD.marker_format,OLD.marker_version,OLD.created_at) THEN
        RAISE EXCEPTION 'artifact store registrations are immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifact_stores_immutable
BEFORE UPDATE OR DELETE ON artifact_stores
FOR EACH ROW EXECUTE FUNCTION reject_artifact_store_mutation();
