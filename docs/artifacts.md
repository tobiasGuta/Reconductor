# Artifacts and evidence lineage

`artifact.Storage` currently has a local filesystem implementation and is intentionally small enough for a future S3-compatible backend. Every write requires program, task, workflow run, step run, and tool run IDs.

Metadata records artifact type, content type, byte size, SHA-256, storage location, creation time, sensitivity, and redaction state. Normal data passes through centralized redaction. Sensitive evidence is placed in a separate directory with restrictive permissions and must be explicitly marked.

Command-provider `stdout.jsonl` and `stderr.txt` are stored as `raw-provider-output` artifacts and populate the tool run's stdout/stderr artifact pointers. Normalized `result.json` is stored separately as `normalized-result` and is attached to the action result artifact IDs. Local workflow execution and Redis worker execution use the same execution service, so artifact meaning does not change by delivery mode.

Provider evidence is staged in a durable prepared-evidence set before publication. The persisted StepRun output is a versioned result envelope: bounded semantic JSON can remain inline, while a larger semantic result is referenced by exact artifact ID, store, key, digest, size, and output-schema digest. Downstream workflow bindings authorize that adopted artifact and stream only their selected value. Workflow-facing projections may omit redundant bulk fields, such as Katana response bodies, while complete redacted stdout and normalized provider records remain in evidence artifacts.

Normal logs and notifications must never contain credentials, authorization headers, cookies, JWTs, API keys, webhook URLs, password fields, or user-configured secret names. Notifications should use internal candidate/finding IDs and safe summaries, not credential-bearing curl commands.

## Tombstone state and evidence preservation

Artifact records are permanent and never deleted from the database. When an artifact reaches retention expiration (`expires_at <= statement_timestamp()`) and cleanup is executed, only the physical payload on the filesystem is deleted. The metadata row transitions to the tombstoned state (`content_deleted_at IS NOT NULL`).

This design preserves evidence lineage integrity:
- `candidate_findings`, `asset_observations`, `change_items`, and audit event records can reference evidence artifact IDs indefinitely without risking foreign key violations or dangling IDs.
- Downstream read models (such as execution projections) exclude expired and tombstoned artifacts from user-facing result sets, preventing access to purged payloads while leaving historical lineage verifiable in database audit logs.
