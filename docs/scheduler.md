# Scheduler

Reconductor includes a persistent, PostgreSQL-backed scheduler for deterministic recurring reconnaissance. It does not add agents, autonomous planning, new scanners, remote console exposure, automatic moderate approval, automatic vulnerability confirmation, or report submission.

## Architecture

Cron due time is materialized into `scheduled_executions(status=pending)`. Scheduler workers claim pending rows with `FOR UPDATE SKIP LOCKED`, then call the shared `internal/orchestration` workflow service used by the CLI. Run Now inserts the same pending row shape and returns immediately.

Each new execution reloads the program's current `scope_reference`, rebuilds the Burp scope and target plan, records the scope snapshot, validates the workflow definition, creates a distinct `Task`, and creates a distinct `WorkflowRun`. Resume reuses the existing task and workflow run. Queue jobs carry the compiled include/exclude rules, so capability workers do not reopen the scope file.

## Cron And Timezones

Schedules use standard five-field cron:

```text
minute hour day-of-month month day-of-week
```

The timezone is stored separately as an IANA name such as `UTC`, `America/New_York`, or `Europe/London`. `next_run_at` is stored in UTC. The scheduler materializes at most one missed occurrence after downtime and advances to the first valid occurrence after the current time, avoiding large historical backlogs.

## Scope And Approvals

Current scope is reloaded before every occurrence. Exclusions and reductions apply immediately. If an unacknowledged expansion is detected, the scheduled execution is marked `blocked_scope_change`; no task, workflow run, provider invocation, or target traffic is created.

Moderate Nuclei remains approval gated. A scheduled run can pause at `awaiting_approval`; approval records the human decision but does not silently resume. Use explicit resume after approval.

## Overlap And Restart Semantics

If the same schedule already has an execution in `claimed`, `running`, or `paused_for_approval`, the new occurrence is recorded as `skipped_overlap`. Claims use short leases. A stale claim without a task can return to pending; a stale execution with task or run lineage becomes `interrupted` for operator review rather than automatically duplicating network traffic.

## Change Inbox

Structured output from `report.changes` and newly persisted Nuclei candidates create immutable `change_items`. Researcher disposition is stored separately in `change_reviews`. Priorities are deterministic and reasoned from structured changes, endpoint classifier signals, source capabilities, and candidate-finding status.

## Configuration

```text
SCHEDULER_POLL_INTERVAL=15s
SCHEDULER_MAX_CONCURRENT_RUNS=1
SCHEDULER_LEASE_TIMEOUT=2m
WORKFLOW_STATE_ROOT=state/runs
SCOPE_ROOT=
```

Use portable logical references such as `scope/example.json`. When `SCOPE_ROOT`
is set, relative references resolve beneath it. For backward compatibility, a
legacy `/scope/example.json` reference maps to
`$SCOPE_ROOT/scope/example.json` only when `SCOPE_ROOT` is explicitly set.
Other absolute paths remain literal and missing files fail without fallback.
Parent traversal in logical references is rejected.

For a local scheduler started from the repository root:

```powershell
$env:SCOPE_ROOT = (Get-Location).Path
go run ./cmd/scheduler
```

The worker image builds `/usr/local/bin/platform-scheduler`, but no scheduler
container is enabled by default. A future scheduler container must mount the
same project/data tree beneath its configured `SCOPE_ROOT`. The worker service
does not require a scope mount.

Repair a legacy locator without network execution:

```powershell
$env:SCOPE_ROOT = (Get-Location).Path
go run ./cmd/platform scope update --program-id <uuid> --scope scope/example.json
```

The repair is accepted only when both the scope digest and target-plan digest
match the stored program. It updates the current program/snapshot locator and
writes an audit event; authorization changes continue through the existing
scope-change review path.

## CLI

```powershell
go run ./cmd/platform schedule create --program-id <uuid> --name weekly-recon --workflow continuous-web-recon --cron "0 9 * * 1" --timezone "America/New_York" --objective "weekly authorized attack-surface review"
go run ./cmd/platform schedule list --program-id <uuid>
go run ./cmd/platform schedule run-now <schedule-id>
go run ./cmd/platform schedule executions --schedule-id <schedule-id>
go run ./cmd/platform schedule resume <scheduled-execution-id>
go run ./cmd/platform changes list --program-id <uuid>
go run ./cmd/platform changes review <change-id> --disposition interesting --note "Review with two accounts" --actor human
```

## Console

The loopback-only console shows schedules, recent scheduled executions, change items, and pending scope expansions. Mutations keep the existing console boundary: loopback binding, same-origin checks, `X-Reconductor-Request: operator-console`, JSON requests, strict unknown-field rejection, request-size limits, CSP, and security headers.

## Current Limitations

The scheduler is a persistent local daemon, not high availability or distributed workflow coordination. It does not automatically recover an interrupted active network scan. It does not authenticate remote users or infer host/container path mappings that were not configured through `SCOPE_ROOT`.
