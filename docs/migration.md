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
