# Artifact storage ownership

Artifact Store Ownership Foundation Slice 1 binds every new artifact to an explicitly initialized physical local store. `ARTIFACT_STORE_ID` is the durable UUID for one physical artifact namespace. The store marker also contains an independently generated incarnation nonce. The nonce detects accidental marker/database mismatches, but it is not a distributed clone fence: two simultaneously mounted copies with the same marker remain indistinguishable.

The local marker is `.reconductor-artifact-store.json`. `platform artifact-store init` is the only initialization path. It creates the root when absent, exclusively creates the marker, and registers the exact marker identity. Normal workflow, worker, and scheduler startup is validate-only: the configured UUID, marker UUID and nonce, marker format, backend kind, version, and database registration must already agree. `--resume-registration` is limited to completing registration from an existing valid marker. `--allow-nonempty-root` acknowledges an unmarked legacy directory, but still refuses a preexisting reserved `v1` subtree.

Native and Docker storage are distinct. The repository-local `ARTIFACT_ROOT` and the Compose named volume mounted at `/data/artifacts` must use different UUIDs. Native commands read `ARTIFACT_STORE_ID`; Compose maps `DOCKER_ARTIFACT_STORE_ID` to `ARTIFACT_STORE_ID` inside the worker, with no native-ID fallback. Never copy one ID merely because both stores are used by the same database.

Version-1 content keys are exactly:

```text
v1/<first-two-lowercase-hex-characters>/<canonical-lowercase-artifact-uuid>
```

The key contains no filename, extension, lineage, sensitivity, or user/provider input. Files are created exclusively and are never overwritten. A file successfully published before a database failure remains an orphan; reconciliation is not implemented in this slice.

Rows that existed before migration 0016 remain version 0. Their `storage_location` is retained byte-for-byte, and they have no StoreID or storage key. They are historical records only and do not establish ownership of any configured store. After 0016, obsolete writers are incompatible: omitted version-1 ownership fields or an explicit new version-0 insert are rejected. Artifact addresses and store registrations are immutable, and Artifact metadata deletion is rejected.

Automatic retention deletion is temporarily disabled. `POLICY_ARTIFACT_RETENTION`, `expires_at`, and `artifact_retention_applied` record policy and expiry assignment only. Expiry does not mean content or metadata deletion; bytes intentionally accumulate until a future tombstone-based cleanup design is implemented.

## Initialization and rollout

Use operator-generated, canonical lowercase UUIDs; do not commit them. For a native store:

```powershell
$env:ARTIFACT_STORE_ID = '<native-store-uuid>'
go run ./cmd/platform migrate
go run ./cmd/platform artifact-store init
```

For the Compose artifact volume, configure a different value:

```powershell
$env:DOCKER_ARTIFACT_STORE_ID = '<docker-volume-store-uuid>'
docker compose up -d postgres redis
docker compose run --rm --entrypoint /usr/local/bin/platform worker migrate
docker compose run --rm --entrypoint /usr/local/bin/platform worker artifact-store init
docker compose up -d worker
```

For an existing deployment, stop all artifact-producing runtimes and take coordinated database and artifact-root backups before applying 0016. Apply the migration, initialize each physical store with its distinct configured ID, validate the pairing, and only then start the matching runtime. Do not infer ownership from legacy paths and do not initialize over an existing `v1` subtree.

Rollback is not a normal binary downgrade. Once 0016 is applied, an old writer cannot insert artifacts, while a pre-0016 schema cannot represent version-1 addresses. Recover by rolling forward or by restoring a coordinated pre-migration database and artifact backup.

The local backend assumes the configured root and its parent directories are trusted against same-privilege replacement while the process runs. Canonical keys and a final lexical containment check prevent malformed path construction; they do not provide hostile filesystem or TOCTOU confinement.
