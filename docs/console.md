# Operator console

The Reconductor operator console is a local, read-oriented control plane over the same PostgreSQL records, Redis Streams delivery state, and approval transitions used by the CLI and workers. It does not bypass `ActionRequest`, scope, policy, approval, or provider validation.

Start it with:

```powershell
go run ./cmd/platform console
```

The default address is `http://127.0.0.1:8088`. A different loopback port may be selected with `--listen`, for example `--listen 127.0.0.1:8090`. Non-loopback addresses are rejected because this first version does not include remote authentication or multi-user authorization.

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

Approval and retry mutations require JSON, a console-specific request header, and a same-origin browser context. These protections reduce browser-origin request forgery risk; they are not a substitute for authentication. Do not place the console behind a remote proxy or expose it on a shared interface.

Approving a paused step records the human decision. It does not silently resume or create a workflow. Scheduled executions require an explicit resume action after approval. Run Now creates a pending scheduled execution and returns immediately; the scheduler daemon claims it through the same persistent dispatch path as cron. Dead-letter retry returns the existing validated job to Redis; execution still passes through the normal worker scope, policy, and provider checks.

## Current boundary

This console makes existing local operation usable, including persistent scheduling and change review. It is not a remote authenticated console, role system, multi-operator system, high-availability scheduler, or distributed workflow coordinator.
