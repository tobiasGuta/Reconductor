# Operator console

The Reconductor operator console is a local, read-oriented control plane over the same PostgreSQL records, Redis Streams delivery state, and approval transitions used by the CLI and workers. It does not bypass `ActionRequest`, scope, policy, approval, or provider validation.

Set `CONSOLE_OPERATOR_TOKEN` to a unique 32–256 character bearer-safe secret and `CONSOLE_OPERATOR_ACTOR` to a stable, non-secret audit name (up to 80 characters). For example, generate a token locally with `openssl rand -hex 32` and keep the result in your local environment or secret manager. The console command rejects missing or invalid operator configuration before opening the database or listener. Other platform commands do not require these settings.

Start it with:

```powershell
go run ./cmd/platform console
```

The default address is `http://127.0.0.1:8088`. A different loopback port may be selected with `--listen`, for example `--listen 127.0.0.1:8090`. The accepted HTTP Host and browser Origin must match this configured address in browser-canonical form: HTTP port 80 omits `:80`, while nondefault ports require their explicit number. `localhost` and `[::1]` work only when explicitly selected as the listen host. Non-loopback addresses are rejected. There is no remote or multi-user authorization.

In the browser, enter the operator token in **Operator credential** and select **Unlock actions**. The page verifies it with `GET /api/v1/operator/check`; it retains the token only in the current page's memory and clears the input immediately. Refreshing the page locks actions again. The token is sent as `Authorization: Bearer` on existing mutation requests. Do not paste it into a URL.

## Available views

- Programs and the latest recorded scope posture
- Latest workflow graph from that WorkflowRun's immutable materialized snapshot and live step status, polled every five seconds
- Historical workflow runs and step outcomes
- Approval inbox with explicit approve and reject decisions
- Stable assets and their latest persisted observations
- New, changed, and removed assets through the typed persistent change inbox
- Candidate findings kept separate from verified findings
- Verification results with compatibility, evidence, and impact verdict labels
- Redis pending count, sanitized dead-letter metadata, and manual retry controls
- Persistent schedules, recent scheduled executions, and explicit Run Now enqueue
- Persistent change inbox with review dispositions
- Pending scope expansions with digest-only acknowledgement controls
- Fixed provider execution metadata and safe audit-event identity/message fields

## Exposure boundary

The console read model deliberately omits step input, bindings, provider arguments, raw materialized snapshots, TargetPlan values, artifact storage locations, sensitive artifacts, raw provider stdout and stderr, raw WorkflowRun summaries, arbitrary audit-event details, and the raw latest-changes summary channel. Durable PostgreSQL audit and result evidence is retained; the browser receives only explicitly typed fixed fields such as identities, statuses, timestamps, counts, target-plan digests, and safe audit messages. Dead-letter records expose only the job ID, capability, provider, attempt count, safe error classification, and failure time.

For a modern run, the server emits a sanitized topology projection keyed by WorkflowRun ID from that run's own immutable materialization; topology never comes from another run, the shared template descriptor, or a current builder. Legacy runs without a materialized snapshot are explicitly degraded: the graph can show only recorded StepRuns and labels the full historical topology unavailable.

Every console API mutation requires the configured bearer token, the exact configured Host, JSON, and the console-specific request header. When Origin is present, it must exactly match the configured `http://` origin; an authenticated local API client may omit Origin. The custom header and Origin checks supplement bearer authentication. Existing summary GETs, health, and static assets remain accessible on the local console. Future sensitive GETs can use the same operator gate, as the token verification route does.

The server supplies the configured actor to approval, scheduling, change review, scope acknowledgement, and retry operations. Client `actor` fields in approval decisions, schedule create/update, and change review now fail strict JSON decoding instead of setting audit identity. API clients should remove those fields. The token is not used as the actor or written to audit records. Keep the console on a trusted local machine; this boundary does not protect against code running as the same OS user or a browser extension with page access. Do not place it behind a remote proxy or expose it on a shared interface.

Approving a paused step records the human decision. It does not silently resume or create a workflow. Scheduled executions require an explicit resume action after approval. Run Now creates a pending scheduled execution and returns immediately; the scheduler daemon claims it through the same persistent dispatch path as cron. Dead-letter retry returns the existing validated job to Redis; execution still passes through the normal worker scope, policy, and provider checks.

## Current boundary

This console makes existing local operation usable, including persistent scheduling and change review. It is not a remote authenticated console, role system, multi-operator system, high-availability scheduler, or distributed workflow coordinator.
