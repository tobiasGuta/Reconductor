# Artifacts and evidence lineage

`artifact.Storage` currently has a local filesystem implementation and is intentionally small enough for a future S3-compatible backend. Every write requires program, task, workflow run, step run, and tool run IDs.

Metadata records artifact type, content type, byte size, SHA-256, storage location, creation time, sensitivity, and redaction state. Normal data passes through centralized redaction. Sensitive evidence is placed in a separate directory with restrictive permissions and must be explicitly marked.

Command-provider `stdout.jsonl` and `stderr.txt` are stored as `raw-provider-output` artifacts and populate the tool run's stdout/stderr artifact pointers. Normalized `result.json` is stored separately as `normalized-result` and is attached to the action result artifact IDs. Local workflow execution and Redis worker execution use the same execution service, so artifact meaning does not change by delivery mode.

Normal logs and notifications must never contain credentials, authorization headers, cookies, JWTs, API keys, webhook URLs, password fields, or user-configured secret names. Notifications should use internal candidate/finding IDs and safe summaries, not credential-bearing curl commands.
