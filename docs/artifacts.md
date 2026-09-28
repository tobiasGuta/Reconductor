# Artifacts and evidence lineage

`artifact.Storage` currently has a local filesystem implementation and is intentionally small enough for a future S3-compatible backend. Every write requires program, task, workflow run, step run, and tool run IDs.

Metadata records artifact type, content type, byte size, SHA-256, storage location, creation time, sensitivity, and redaction state. Normal data passes through centralized redaction. Sensitive evidence is placed in a separate directory with restrictive permissions and must be explicitly marked.

Command-provider `stdout.jsonl` and `stderr.txt` are stored as `raw-provider-output` artifacts and populate the tool run's stdout/stderr artifact pointers. Normalized `result.json` is stored separately as `normalized-result` and is attached to the action result artifact IDs. Local workflow execution and Redis worker execution use the same execution service, so artifact meaning does not change by delivery mode.

Provider evidence is staged in a durable prepared-evidence set before publication. The persisted StepRun output is a versioned result envelope: bounded semantic JSON can remain inline, while a larger semantic result is referenced by exact artifact ID, store, key, digest, size, and output-schema digest. Downstream workflow bindings authorize that adopted artifact and stream only their selected value. Workflow-facing projections may omit redundant bulk fields, such as Katana response bodies, while complete redacted stdout and normalized provider records remain in evidence artifacts.

## Read-only run evidence viewing

Use the run-scoped viewer with the same local operator database access and configured, already initialized artifact store required by other runtime commands:

```text
platform run evidence <workflow-run-id>
platform run evidence <workflow-run-id> <artifact-id>
```

The operator journey is: find the run, list its eligible evidence, select an artifact ID, view the verified content, and then decide whether separate manual validation is warranted. These commands are read-only: they do not initialize or register stores, invoke providers, enqueue work, or change workflow, publication, audit, recovery, or artifact state. They are not a general artifact browser or export API.

The list is derived from authoritative run lineage and includes only artifacts that satisfy the existing adopted-publication, exact-store, role, retention, redaction, and access checks. Sensitive evidence is excluded; unknown runs and cross-run artifact IDs return the same safe unavailable outcome rather than enabling enumeration. Storage keys and filesystem paths are never displayed.

For a selected artifact, the service reads through the pinned local store and verifies the complete recorded object, including EOF and close-time integrity checks, before any evidence content is written. Terminal content is escaped and line-prefixed, with a 65,536-byte display limit applied after expansion. A shortened terminal display still identifies the underlying artifact as completely read and verified; it does not mean the evidence itself was truncated. Missing evidence is unavailable, while corrupt or unverifiable evidence reports verification failure without releasing content.

The viewer presents recorded observations, not vulnerability verdicts. In particular, current HTTPX evidence contains the configured normalized/provider observations and does not promise a complete raw HTTP wire request and response capture.

Normal logs and notifications must never contain credentials, authorization headers, cookies, JWTs, API keys, webhook URLs, password fields, or user-configured secret names. Notifications should use internal candidate/finding IDs and safe summaries, not credential-bearing curl commands.

## Tombstone state and evidence preservation

Artifact records are permanent and never deleted from the database. When an artifact reaches retention expiration (`expires_at <= statement_timestamp()`) and cleanup is executed, only the physical payload on the filesystem is deleted. The metadata row transitions to the tombstoned state (`content_deleted_at IS NOT NULL`).

This design preserves evidence lineage integrity:
- `candidate_findings`, `asset_observations`, `change_items`, and audit event records can reference evidence artifact IDs indefinitely without risking foreign key violations or dangling IDs.
- Downstream read models (such as execution projections) exclude expired and tombstoned artifacts from user-facing result sets, preventing access to purged payloads while leaving historical lineage verifiable in database audit logs.
