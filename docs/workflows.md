# Workflows

Workflow definitions contain stable capability names, typed JSON inputs, dependency IDs, bounded retries, timeouts, supported conditions, and explicit output bindings. Validation rejects cycles, unknown capabilities, invalid JSON, missing dependencies, unsupported conditions, and undeclared binding sources. There is no command or script field.

The engine persists before and after each meaningful state transition. A resumed run retains a succeeded step when its normalized input hash is unchanged. It reruns only when the definition opts into input-change reruns or the operator starts an explicit retry. Pause, cancellation, skipped steps, retryable failures, approvals, and terminal states are distinct.

Ready steps execute in deterministic waves. Every step in a wave has satisfied dependencies; independent branches may run concurrently, while their completion transitions are committed in stable topological order. Bindings and conditions must reference a transitive dependency, preventing a custom definition from reading an unordered branch.

`POLICY_CONCURRENCY` bounds parallel steps for one program and also bounds provider-level concurrency. `POLICY_PROVIDER_CONCURRENCY` limits simultaneous invocations of the same provider within a process. `POLICY_HOST_CONCURRENCY` prevents independent steps from concurrently targeting the same normalized host and is also passed to host-aware providers such as Katana and Nuclei. Each parallel wave receives a conservative share of the program rate and provider-concurrency budgets.

`platform task cancel <task-id>` is observed by an active local workflow runner. Cancellation propagates through the running step context into command providers, which terminate their owned process. The final cancelled step and workflow states are persisted with a non-cancelled cleanup context.

## Scope-derived inputs

Every definition receives a deterministic target-plan digest. Exact host rules yield explicit protocol/port URL combinations only when an initial path is authorized. Narrow child-subdomain regexes yield passive discovery roots and wildcard metadata; the base root is not promoted to active scope. Manual discovery roots are passive-only, repeated flags require a reason, and discovered hostnames are filtered before DNSx. A changed plan changes step input hashes, preventing stale successful steps from being silently reused.

## `continuous-web-recon`

Version `2.1.0` runs passive discovery only for planned roots, filters each result, merges authorized discovered URLs with exact seeds, then runs DNSx, an optional authorized port intersection in Naabu, HTTPX, asset comparison, crawling, GAU, endpoint classification, an approved safe Nuclei profile, and a changes report. It supports multiple unrelated domains without `--domain`.

## `authorized-web-baseline`

Version `1.1.0` starts only from scope-derived exact seeds, then resolves, optionally scans a common authorized port intersection, probes, compares, crawls changed assets, classifies endpoints, pauses for Nuclei approval, and reports changes. It needs no discovery root.

HTTP observations are routed deterministically: 2xx assets may be crawled, 2xx/redirect/authentication responses may enter the approved safe scan profile, and other statuses are retained as observations but not scanned.

The classifier receives only each provider's post-scope-filter `authorized_records`. HTTPX supplies response status, content type, redirect, and technology evidence; Katana supplies request and JavaScript relationship evidence; GAU supplies lower-confidence passive observations. Structured HTTP observations from the latest prior completed run are loaded for route-normalized historical comparisons. The complete evidence classification is persisted in the step result and forwarded into the report.

Every scheduled invocation should create a new Task execution and WorkflowRun. The first run treats observed HTTP assets as new. Negative transitions require a complete successful source step; a failed or incomplete scan never marks an asset removed or a finding resolved.

Moderate Nuclei execution pauses without approval. Independent safe branches that are already ready may finish before the workflow enters its paused state. Intrusive, destructive, denial-of-service, brute-force, credential-stuffing, and state-changing behavior is not part of this workflow.

```powershell
go run ./cmd/platform scope plan --scope .\scope\mixed-example.json
go run ./cmd/platform workflow plan --program-id <uuid> --scope .\scope\mixed-example.json --workflow authorized-web-baseline
go run ./cmd/platform workflow run --program-id <uuid> --scope .\scope\mixed-example.json --workflow authorized-web-baseline
```
