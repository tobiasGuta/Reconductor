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

Artifact Store Ownership Foundation Slice 2 introduces the Store-Scoped Tombstone Cleanup Protocol. Retention policy assignment (`POLICY_ARTIFACT_RETENTION`, `expires_at`, and `artifact_retention_applied`) stamps artifact expiration. Once expired (`expires_at <= statement_timestamp()`), physical payload deletion is performed via explicit operator cleanup without destroying database metadata.

## Tombstone cleanup protocol

Tombstone cleanup is explicit and scoped to one physical store:

```powershell
$env:ARTIFACT_STORE_ID = '<native-store-uuid>'
go run ./cmd/platform artifact-store cleanup [--batch-size N]
```

`--batch-size` accepts values between 1 and 1000 (default 100). The command executes one bounded batch and exits, printing structured JSON results. Background daemon cleanup and cross-store reconciliation remain deferred.

### State lifecycle and concurrency

Migration 0017 adds a formal state graph enforced by 8 named CHECK constraints and the `artifacts_cleanup_transition_guard` trigger:

- **Claiming**: Bounded batches are claimed with `ORDER BY expires_at ASC, id ASC LIMIT $2 FOR UPDATE OF a SKIP LOCKED` scoped strictly to `artifact_store_id`. Each claimed row receives an independently generated volatile token (`gen_random_uuid()`) and a claim timestamp. Stale claims (`cleanup_claimed_at <= statement_timestamp() - interval '15 minutes'`) become reclaimable automatically.
- **Token fencing & finalization**: Deletion finalization is guarded by the row's claim token. On successful filesystem deletion, `content_deleted_at = statement_timestamp()` is stamped, claim fields are cleared, and an `artifact_content_deleted` audit event is atomically inserted.
- **Claim token authority & physical deletion**: The cleanup claim token grants DATABASE work-distribution authority and finalization authority. It does NOT grant exclusive operating-system unlink authority, and it is NOT an OS filesystem mutex. Stale physical deletion can safely be duplicated across workers because:
  - Artifact ID is immutable
  - Canonical v1 StorageKey is immutable and bijective with Artifact ID
  - Storage keys are never reused
  - Expiry is immutable after cleanup lifecycle entry
  - Deletion eligibility cannot later be revoked through expiry change
  - Physical absence is idempotent
  - Database finalization remains StoreID + claim-token fenced
- **Transient failures & retry**: Transient filesystem I/O or directory durability sync failures transition the row to `RETRY_WAIT` with `cleanup_retry_after = statement_timestamp() + interval '5 minutes'` and record the error code (`filesystem_io` or `durability_sync`).
- **Terminal quarantine**: Non-retryable filesystem entry-type safety errors (such as non-regular files, symlinks, directories, or unexpected entry types under the trusted root) transition the row to `QUARANTINED`, recording `cleanup_last_error_code` (`unexpected_entry_type`) and atomically emitting an `artifact_quarantined` audit event. Quarantined rows are terminal and require manual operator investigation.
- **Invariant failures**: Artifact ID <-> canonical StorageKey mismatch is an infrastructure / invariant failure. On mismatch:
  - filesystem I/O: NO
  - retry: NO
  - quarantine: NO
  - finalization: NO
  - command/coordinator: STOP
  - claim: LEFT INTACT
  Authoritative database ID/StorageKey invariant mismatch is not quarantined and not scheduled for retry; it immediately stops the command/coordinator with an invariant error without performing filesystem I/O, retry, quarantine, or finalization, leaving the claim intact for 15-minute stale reclamation or operator inspection.
- **Tombstone metadata & evidence preservation**: `content_deleted_at IS NOT NULL` represents the physical tombstone. The artifact row is never deleted from PostgreSQL, guaranteeing that candidate findings, observations, change items, and audit events retain valid evidence references. Excluded from execution projections, tombstoned artifacts remain permanently queryable for audit integrity.

### Filesystem deletion semantics

Filesystem payload deletion uses `Local.DeleteContent`:
- Validates canonical key format and lexical containment within the configured store root.
- Rejects symlinks and directories via `os.Lstat` (`unexpected_entry_type`).
- Handles already-absent files idempotently (`ENOENT`), distinguishing between missing file in an existing parent directory and missing parent directories by walking upward with `os.Lstat` inside the root without following symlinks or creating missing directories.
- Flushes parent directory metadata changes up to the store root where supported by the operating system.

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

## Prepared evidence admission and recovery

Migration 0020 requires explicit capacity limits for every initialized physical store. Limits are durable database configuration, not process-local defaults:

```powershell
go run ./cmd/platform artifact-store prepared-limits --max-open-sets 128 --max-set-bytes 1048576 --max-unresolved-bytes 134217728
```

`max-set-bytes` is the pessimistic reservation and provider-output authority for one attempt. `max-open-sets` and `max-unresolved-bytes` bound all sets that have not reached `CLEANED`, including successfully adopted, abandoned, and quarantined sets. The example values are suitable for local evaluation, not an automatic production sizing decision.

Provider execution allocates one set before invoking the provider. Prepared control, manifest, and evidence bytes are staged durably before final artifact publication. A known oversize result is resolved as nonadmitted; commit-unknown and unverifiable states remain fail closed and are never replayed.

Resolved staged content is removed only by the database-led recovery command. Stop new admission and drain workers, the scheduler, and direct workflow processes so recovery can obtain exclusive store authority, then run bounded batches:

```powershell
go run ./cmd/platform artifact-store prepared-recover --batch-size 100
```

The result reports remaining open-set and reserved-byte occupancy. Repeat as needed. `QUARANTINED` sets are deliberately excluded from automatic deletion and continue to consume capacity until a separately designed, audited operator disposition is available. Recovery never invokes a provider, increments an attempt, or creates replacement execution identities.

Durable publisher and recovery operations currently require Linux with ext, XFS, or Btrfs. Native Windows and other operating systems fail closed; use the Linux worker container on those hosts.

Rollback is not a normal binary downgrade. Once 0016 is applied, an old writer cannot insert artifacts, while a pre-0016 schema cannot represent version-1 addresses. Recover by rolling forward or by restoring a coordinated pre-migration database and artifact backup.

The local backend assumes the configured root and its parent directories are trusted against same-privilege replacement while the process runs. Canonical keys and a final lexical containment check prevent malformed path construction; they do not provide hostile filesystem or TOCTOU confinement.
