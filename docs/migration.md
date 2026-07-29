# Migration guide

## Database

Run `platform migrate` before starting a worker. Embedded migrations are versioned and transactional. They create normalized platform tables without dropping legacy `findings` or `endpoints` data. Existing finding IDs are inventoried in `legacy_finding_migration`; historical rows require verification before promotion to the new findings lifecycle.

Back up PostgreSQL before the first production migration. The migration requests `pgcrypto` for UUID defaults on legacy endpoint rows, so the database role must be allowed to create that extension.

Migration `0004_scope_target_plans.sql` adds defaulted program targeting metadata, versioned `scope_versions`, and program lineage on audit events. Existing program rows and historical workflow inputs stay readable and are not reinterpreted. Rollback is application-managed; the new tables and columns are not destructively removed.

Migration `0005_policy_enforcement.sql` adds nullable artifact expiry metadata and its collection index. Existing artifact rows remain indefinite (`expires_at IS NULL`); retention applies to newly created artifacts according to the runtime policy.

Migration `0006_verification_verdicts.sql` adds persisted `evidence_verdict` and `impact_verdict` columns to `verification_results`. Existing `rejected` rows are backfilled as `not_observed` and `rejected`; legacy `confirmed`, `inconclusive`, and `manual_review` rows remain conservatively `inconclusive` and `unreviewed` because older verifiers did not reliably distinguish technical behavior from confirmed impact.

Migration `0007_scheduled_reconnaissance.sql` adds `schedules`, `scheduled_executions`, immutable `change_items`, and mutable `change_reviews`. It does not drop, truncate, or delete findings, endpoint records, artifacts, workflow runs, or scope history.

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
