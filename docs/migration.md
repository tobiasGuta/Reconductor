# Migration guide

## Database

Run `platform migrate` before starting a worker. Embedded migrations are versioned and transactional. They create normalized platform tables without dropping legacy `findings` or `endpoints` data. Existing finding IDs are inventoried in `legacy_finding_migration`; historical rows require verification before promotion to the new findings lifecycle.

Back up PostgreSQL before the first production migration. The migration requests `pgcrypto` for UUID defaults on legacy endpoint rows, so the database role must be allowed to create that extension.

Migration `0004_scope_target_plans.sql` adds defaulted program targeting metadata, versioned `scope_versions`, and program lineage on audit events. Existing program rows and historical workflow inputs stay readable and are not reinterpreted. Rollback is application-managed; the new tables and columns are not destructively removed.

Migration `0005_policy_enforcement.sql` adds nullable artifact expiry metadata and its collection index. Existing artifact rows remain indefinite (`expires_at IS NULL`); retention applies to newly created artifacts according to the runtime policy.

Migration `0006_verification_verdicts.sql` adds persisted `evidence_verdict` and `impact_verdict` columns to `verification_results`. Existing `rejected` rows are backfilled as `not_observed` and `rejected`; legacy `confirmed`, `inconclusive`, and `manual_review` rows remain conservatively `inconclusive` and `unreviewed` because older verifiers did not reliably distinguish technical behavior from confirmed impact.

Migration `0007_scheduled_reconnaissance.sql` adds `schedules`, `scheduled_executions`, immutable `change_items`, and mutable `change_reviews`. It does not drop, truncate, or delete findings, endpoint records, artifacts, workflow runs, or scope history.

### Endpoint origin identity migration 0013

Migration `0013_endpoint_origin_identity.sql` adds the normalized Endpoint origin tuple, an unvalidated corrected-row structural gate, immutable corrected identity, and origin-local uniqueness. It does not backfill, split, merge, delete, or reinterpret historical Endpoint rows. Existing rows remain legacy origin-null records and cannot receive ordinary aggregate updates or be converted in place.

Migration 0013 requires a coordinated writer drain; mixed pre-Slice-2 and Slice-2 Endpoint writers are unsupported:

1. Stop new workflow admission.
2. Drain and stop old workers and scheduler execution.
3. Stop old in-flight `platform workflow run` and `platform run retry` processes.
4. Prevent old migration-capable processes from starting and auto-migrating.
5. Apply 0013 once with the new binary using explicit `platform migrate`.
6. Inspect the Endpoint origin columns, `endpoints_corrected_row_ck`, `endpoints_identity_guard`, `endpoints_corrected_identity_uq`, removal of `endpoints_identity_uq`, and migration ledger entry.
7. Start only Slice-2-aware binaries and then resume admission.

Any pre-Slice-2 Endpoint writer that reaches the migrated schema must fail closed and create or mutate no Endpoint state. The exact PostgreSQL error may be the corrected-row constraint or failure to infer the removed coarse conflict arbiter; no compatibility shim is provided.

### Concrete HTTP resource lineage migration 0014

Migration `0014_concrete_http_resource_lineage.sql` adds Program-local `canonical_concrete_http_resources` and append-only `probe_http_source_records`. It does not backfill or reinterpret historical observations, accepted results, artifacts, or Endpoint rows. The source table has structural lineage checks from the Program through the emitted HTTP observation, accepted result event, provider attempt, `probe.http` capability, and optional normalized-result artifact; it is not a semantic graph or relationship table.

Deploy 0014 with the Slice-3A binary as one coordinated writer transition: stop new admission, drain old workers and in-flight executions, apply `platform migrate` once, verify the two new tables, source-lineage and immutability triggers, and migration-ledger entry, then start only Slice-3A-aware workers before resuming admission. Pre-v4 `probe.http` outputs remain readable as legacy results with no source rows. A present but malformed v4 source collection fails its result transaction without an accepted or rejected result-fence decision.

### Workflow materialization integrity migration 0015

Migration `0015_workflow_template_materialization_integrity.sql` adds nullable `materialized_definition`, `materialization_digest`, and `original_scope_version_id` columns to `workflow_runs`. Existing rows—including baseline 1.2.0 and continuous 2.2.0—remain unchanged with all three values null. New inserts must supply the complete modern branch; no materialization is guessed or backfilled.

The migration makes every workflow-definition release field immutable: `id`, `name`, `version`, `description`, `definition`, `default_policy_requirements`, and `created_at`. It makes Task `id`, `program_id`, and `workflow_definition_id` immutable, and makes WorkflowRun `id`, `task_id`, `workflow_definition_id`, `workflow_version`, `previous_run_id`, `trigger_source`, `materialized_definition`, `materialization_digest`, and `original_scope_version_id` immutable. Lifecycle fields remain mutable, and semantic no-op writes remain allowed. These guards apply equally to pre-0015 rows and rows inserted after migration. New binaries register the current baseline 1.4.0 and continuous 2.4.0 template UUIDs independently of historical UUIDs, including the base source releases at baseline 1.3.0 and continuous 2.3.0. Stop old writers before applying 0015 because post-migration processes that omit run materialization intentionally fail closed.

A legacy null-materialization run stays visible but returns `ErrWorkflowResumeUnavailable` before state mutation or provider traffic. A valid modern run uses its database snapshot as authority. A genuinely missing initial FileStore checkpoint can be reconstructed only for a non-terminal run with a valid start time and zero StepRuns; malformed/conflicting checkpoints and missing checkpoints after any StepRun return a checkpoint error without traffic.

### Artifact store tombstone cleanup migration 0017

Migration `0017_artifact_store_tombstone_cleanup.sql` introduces the store-scoped tombstone cleanup state graph for version-1 artifacts. It adds 6 nullable columns to `artifacts`: `content_deleted_at`, `cleanup_claim_token`, `cleanup_claimed_at`, `cleanup_retry_after`, `cleanup_last_error_code`, and `cleanup_quarantined_at`.

The migration establishes:
- 8 named CHECK constraints guaranteeing state shape mutual exclusivity (`artifacts_cleanup_state_shape_ck`), claim token/timestamp pairing (`artifacts_cleanup_claim_pair_ck`), valid error codes (`artifacts_cleanup_error_code_ck`), lifecycle addressing rules (`artifacts_cleanup_lifecycle_address_ck`), legacy version-0 nullity (`artifacts_cleanup_legacy_v0_null_ck`), tombstone timestamp ordering (`artifacts_cleanup_tombstone_time_ck`), retry state constraints (`artifacts_cleanup_retry_error_ck`), and quarantine error tracking (`artifacts_cleanup_quarantine_error_ck`).
- A partial structural candidate index `artifacts_cleanup_eligible_idx`:
  - **keys**:
    - `artifact_store_id`
    - `expires_at`
    - `id`
    (indexed as `(artifact_store_id, expires_at ASC, id ASC)`)
  - **structural predicate**:
    `addressing_version = 1 AND expires_at IS NOT NULL AND content_deleted_at IS NULL AND cleanup_quarantined_at IS NULL`
  - **no temporal predicate** (no `expires_at <= CURRENT_TIMESTAMP`)
  - **no retry predicate** (no `cleanup_retry_after IS NULL`)
  Temporal eligibility (expiration time and retry wait) is evaluated authoritatively at claim time, not in the index predicate.
- A BEFORE UPDATE trigger `artifacts_cleanup_transition_guard` enforcing valid state transitions across canonical states (`UNCLAIMED`, `CLAIMED`, `RETRY_WAIT`, `CONTENT_DELETED`, `QUARANTINED`):
  - Valid transitions: `UNCLAIMED -> CLAIMED`, `CLAIMED -> CONTENT_DELETED`, `CLAIMED -> RETRY_WAIT`, `CLAIMED -> QUARANTINED`, `CLAIMED -> CLAIMED` (token renewal during stale-claim takeover), and `RETRY_WAIT -> CLAIMED` (reclaiming after retry interval).
  - Terminal states: `CONTENT_DELETED` and `QUARANTINED` are terminal and immutable.
  - Full expiry-freeze invariant: `expires_at` may change before cleanup lifecycle entry. Once ANY cleanup lifecycle field (`content_deleted_at`, `cleanup_claim_token`, `cleanup_claimed_at`, `cleanup_retry_after`, `cleanup_last_error_code`, or `cleanup_quarantined_at`) is non-null, `expires_at` is immutable forever. The trigger evaluates OLD OR NEW cleanup lifecycle state, so one statement cannot change `expires_at` and enter the cleanup lifecycle simultaneously. Expiry freeze is not merely protection against extending an already tombstoned artifact; it protects the entire cleanup lifecycle once touched.

Applying 0017 requires running `platform migrate`. Existing pre-0017 rows remain fully compatible and default to the unclaimed state (`UNCLAIMED`, where all cleanup lifecycle fields are null). Operators can then run bounded cleanup via `platform artifact-store cleanup [--batch-size N]`.

### Large-result publication journal migration 0018

Migration `0018_large_result_publication_journal.sql` adds the retained artifact-publication journal and its fenced `reserved -> publishing -> sealed -> adopted` lifecycle. Known failures may transition unresolved publications to `abandoned`; unverifiable filesystem outcomes transition to `quarantined`. Terminal rows and publication identity remain immutable. Applying 0018 requires a coordinated old-writer drain because pre-0018 binaries do not create or honor this journal.

### Large-result recovery foundation migration 0019

Migration `0019_large_result_recovery_foundation.sql` adds workflow attempt waves, wave members, step-attempt claims, and failure-finalization records. These records preserve exact attempt, scheduler, provider, and result-occurrence authority across recovery. Recovery must never infer success from Redis delivery state, allocate replacement identities, increment attempts, or replay a provider while persistence outcome is unresolved. Drain old workers and schedulers before applying the migration and start only binaries that require the current schema.

### Prepared-evidence ownership migration 0020

Migration `0020_prepared_evidence_ownership.sql` adds per-store prepared-evidence limits and retained ownership records for durable staged results. After migrating and initializing each physical store, configure its limits before starting artifact-producing processes:

```powershell
go run ./cmd/platform artifact-store prepared-limits --max-open-sets 128 --max-set-bytes 1048576 --max-unresolved-bytes 134217728
```

The values are an explicit local example. Size production limits from the expected provider-result ceiling and maintenance interval. Startup and `platform doctor` fail when limits are absent or cannot admit one additional maximum-sized set.

Resolved prepared sets remain charged until their staged bytes are removed and the database row reaches `CLEANED`. During a drained maintenance window, run bounded recovery and inspect the returned occupancy:

```powershell
go run ./cmd/platform artifact-store prepared-recover --batch-size 100
```

Repeat bounded batches as needed. Quarantined sets are retained and charged for operator investigation. The current native durable-publisher implementation supports Linux ext, XFS, and Btrfs; Windows and other operating systems fail closed and should use the Linux worker container.

### Provider-output authority ceiling migration 0021

Migration `0021_provider_output_authority_ceiling.sql` fixes the per-set provider-output authority at 8,388,608 bytes while leaving `max_open_sets` and `max_unresolved_bytes` independent. It never rewrites an operator's configuration. An oversized configuration, active execution/publication state, or non-cleaned prepared set reserved above 8 MiB makes the migration fail transactionally; version 0021 is not recorded.

Use this maintenance sequence only for an installation whose exact frontier is `20 (0020_prepared_evidence_ownership.sql)`:

1. Stop new admission, workers, schedulers, and every direct `platform workflow run` or `platform run retry` process. Take coordinated PostgreSQL and artifact-store backups. Keep those runtimes stopped until readiness has been verified.
2. Confirm the migration frontier and inspect oversized prepared evidence with read-only queries:

   ```sql
   SELECT version, name
   FROM schema_migrations
   ORDER BY version DESC
   LIMIT 1;

   SELECT artifact_store_id, lifecycle_state, count(*) AS sets,
          sum(reserved_capacity_bytes) AS reserved_bytes
   FROM prepared_evidence_sets
   WHERE lifecycle_state <> 'CLEANED'
     AND reserved_capacity_bytes > 8388608
   GROUP BY artifact_store_id, lifecycle_state
   ORDER BY artifact_store_id, lifecycle_state;
   ```

3. Handle every oversized legacy row according to its retained lifecycle. `ALLOCATED` and `SEALED` rows still need authoritative recovery. `RESOLVED_ADOPTED` and `RESOLVED_ABANDONED` rows are resolved but remain charged until staged content is removed and they reach `CLEANED`. Run the last schema-0020-compatible binary—not the new 8 MiB binary—against the same database and physical StoreID:

   ```powershell
   go run ./cmd/platform artifact-store prepared-recover --batch-size 100
   ```

   Run that example from a checked-out schema-0020 release; otherwise invoke the deployed schema-0020 `platform` binary directly. The schema-0020 implementation accepts the old authority up to 1 TiB, verifies store identity, manifests, digests, attempt lineage, and publication state, and never replays a provider. Repeat bounded batches and the read-only inspection until no oversized non-cleaned row remains. `CLEANED` rows are safe and retain their history with a zero reservation.

   `QUARANTINED` rows are intentionally skipped by automatic recovery and have no supported automatic disposition. An oversized quarantined row is a remaining upgrade blocker: preserve it, do not delete it, resize its reservation, fabricate resolution, or change its identity, and stop the upgrade for operator investigation.

4. For each initialized store whose existing `max_set_bytes` is oversized, configure `ARTIFACT_STORE_ID` for that store and run the new binary's narrow maintenance command:

   ```powershell
   go run ./cmd/platform artifact-store prepared-limits-remediate-0021 --max-set-bytes 8388608 --confirm-artifact-runtimes-stopped
   ```

   The acknowledgement is necessary but not sufficient. The command also takes the migration lock and non-waiting database locks, requires the exact 0020 frontier, requires an existing configuration owned by the configured store, rejects values outside 1..8,388,608, and checks durable execution, schedule, prepared-set, and publication state. It changes only `max_set_bytes`; the open-set and aggregate unresolved-byte limits are returned unchanged in its JSON result. It cannot create a configuration or operate after migration 0021.

5. Retry the migration with the new binary:

   ```powershell
   go run ./cmd/platform migrate
   ```

6. Verify that `schema_migrations` records version 21, then run `go run ./cmd/platform doctor` before restarting any runtime. Ordinary commands continue to require the current schema and cannot execute merely because the configuration correction succeeded.

If remediation or migration fails, its transaction leaves the migration ledger and evidence unchanged. Read the categorized diagnostic, keep runtimes stopped, resolve the reported state with the schema-0020 recovery path where supported, and retry. Do not substitute an ad hoc configuration `UPDATE` or force the migration. After 0021 is current, use the ordinary `artifact-store prepared-limits` command for later configuration changes.

## Environment and Compose

Replace `RATE_LIMIT` with `NUCLEI_RATE_LIMIT` and `CONCURRENCY` with explicit host/template/headless concurrency variables. Add `DATABASE_URL` and `REDIS_PASSWORD`. Compare the complete new `.env.example`; duplicated per-binary parsers no longer exist.

Compose now binds database and Redis ports to localhost and requires a Redis password. Existing named volumes remain compatible. Set non-local credentials through environment injection on shared systems.

## Commands

Old root-level `go run main.go` and separate aggregator/report/dashboard binaries are removed. Use `go run ./cmd/platform ...` and `go run ./cmd/worker`. Reporting reads persisted workflow summaries; workers persist results directly.

The mandatory single `--domain` model is removed. Use `scope plan`, `workflow plan`, then `workflow run --program-id <uuid> --scope <file>`. Deprecated `--domain` is temporarily accepted only as a passive root. Prefer repeatable `--discovery-root` with `--discovery-root-reason`; exact-host programs can select `authorized-web-baseline`.

## Queues

Legacy lists (`scan_jobs`, `scan_results`, `interesting_endpoints`, and `queue:nuclei:*`) do not contain complete task/run/step lineage and are not silently consumed. Before upgrade, stop old producers/workers and export those lists for audit. Recreate still-relevant work as Tasks so it receives scope/policy validation and stable IDs. New work uses the four bounded shared streams documented in the README.

## Behavioral changes

- Internal correlation never modifies target query strings.
- Requested recon stages are validated; missing dependencies are configuration errors.
- Nuclei matches are candidates, not confirmed findings.
- Negative asset/finding state requires complete successful coverage.
- Arbitrary sibling thresholds no longer collapse routes.
- Provider/template updates are opt-in rather than startup side effects.
