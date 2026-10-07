# Workflows

Workflow definitions contain stable capability names, typed JSON inputs, dependency IDs, bounded retries, timeouts, supported conditions, and explicit output bindings. Validation rejects cycles, unknown capabilities, invalid JSON, missing dependencies, unsupported conditions, undeclared binding sources, and bindings or output conditions that reference paths absent from the source capability's output schema. Output-path validation walks nested object properties, array item schemas, local `$defs` references, and the `[]` binding notation. There is no command or script field.

When a semantic result is artifact-backed, a binding carries an immutable reference to the source run, step, action request, result occurrence, provider attempt, artifact store/key, digest, size, schema digest, and selector. Resolution requires the adopted publication and a readable, non-expired, non-tombstoned artifact in the same Program and WorkflowRun. The immutable materialized workflow must prove that the consumer depends on the source; the consumer StepRun itself may not exist yet because steps are created lazily. Only the selected value is materialized, with a 16 KiB ceiling.

Built-in workflow templates are immutable releases. `continuous-web-recon` 2.4.0 and `authorized-web-baseline` 1.4.0 each have a fixed UUID and use materializer revision `web-recon/v1`. A release change requires a workflow version bump and a new template UUID; the materializer revision changes only when materialization semantics change. Source-controlled representative materialization digests guard this release contract without hashing source code.

The database template row contains only the built-in descriptor and static release metadata. At initial WorkflowRun creation, the exact scope-derived definition is canonicalized, digested, and persisted atomically with its original scope version. Resume, retry, process restart, and scheduled continuation use that pinned snapshot; they never call the current builder to reinterpret the run. Current scope and policy still deny or narrow execution, but cannot add targets or rematerialize the stored graph.

Pinned passive-discovery roots retain the stable semantic IDs of the include rules that originally derived them. Immediately before Subfinder or GAU admission, the current scope must still contain at least one of those exact source rules with a provably executable finite protocol, port, and initial-path basis that is not fully vetoed by current exclusions. An unrelated exact-host or wildcard include cannot transfer authority to the pinned root, current-only roots are never injected, and an ambiguous basis fails closed with zero provider traffic.

The engine persists before and after each meaningful state transition. A resumed run retains a succeeded step when its normalized input hash is unchanged. It reruns only when the definition opts into input-change reruns or the operator starts an explicit retry. Pause, cancellation, skipped steps, retryable failures, approvals, and terminal states are distinct.

For steps that add historical observations, execution persists the enriched effective StepRun input before provider admission. That first effective input is authoritative across provider retries and WorkflowRun resume; newer observations cannot change an already-attempted StepRun.

Ready steps execute in deterministic waves. Every step in a wave has satisfied dependencies; independent branches may run concurrently, while their completion transitions are committed in stable topological order. Bindings and conditions must reference a transitive dependency, preventing a custom definition from reading an unordered branch.

`POLICY_CONCURRENCY` bounds parallel steps for one program and also bounds provider-level concurrency. `POLICY_PROVIDER_CONCURRENCY` limits simultaneous invocations of the same provider within a process. `POLICY_HOST_CONCURRENCY` prevents independent steps from concurrently targeting the same normalized host and is also passed to host-aware providers such as Katana and Nuclei. Each parallel wave receives a conservative share of the program rate and provider-concurrency budgets.

`platform task cancel <task-id>` is observed by an active local workflow runner. Cancellation propagates through the running step context into command providers, which terminate their owned process. The final cancelled step and workflow states are persisted with a non-cancelled cleanup context.

## Scope-derived inputs

Every definition receives a deterministic target-plan digest. Exact host rules yield explicit protocol/port URL combinations only when an initial path is authorized. Narrow child-subdomain regexes yield passive discovery roots and wildcard metadata; the base root is not promoted to active scope. Manual discovery roots are passive-only, repeated flags require a reason, and discovered hostnames are filtered before DNSx. A changed plan changes step input hashes, preventing stale successful steps from being silently reused.

## `continuous-web-recon`

Version `2.4.0` runs passive discovery only for planned roots that remain provably authorized after current exclusions, filters each result, merges authorized discovered URLs with exact seeds, then runs DNSx, an optional authorized port intersection in Naabu, HTTPX, asset comparison, crawling, GAU, endpoint classification, a preliminary recon brief, an optional approved safe Nuclei profile, and a scanner-enriched brief. It supports multiple unrelated domains without `--domain`.

## `authorized-web-baseline`

Version `1.4.0` starts only from scope-derived exact seeds, then resolves, optionally scans a common authorized port intersection, probes, compares, crawls changed assets, classifies endpoints, emits a preliminary recon brief, pauses for optional Nuclei approval, and emits a scanner-enriched brief after approved scanner evidence exists. It needs no discovery root.

HTTP observations are routed deterministically: 2xx assets may be crawled, 2xx/redirect/authentication responses may enter the approved safe scan profile, and other statuses are retained as observations but not scanned.

The classifier receives only each provider's post-scope-filter `authorized_records`. For `probe.http` it also receives the parallel platform-owned `authorized_source_records` collection, which is used only for concrete source derivations. HTTPX supplies response status, content type, redirect, and technology evidence; its response content type is never promoted to request semantics. Katana supplies request and JavaScript relationship evidence, but bulk response `body` and `raw` fields are excluded from its workflow-bound projection and remain in the provider evidence artifacts. GAU supplies lower-confidence passive observations. Structured HTTP observations from the latest prior completed run are loaded by the shared execution service for route-normalized historical comparisons in both local and Redis worker modes. Comparison change items retain every detected change while using compact target/status observations for downstream bindings. The complete evidence classification is persisted in the step result and forwarded into the preliminary and enriched reports.

Every scheduled invocation creates a new Task execution and WorkflowRun through the shared orchestration service. Run Now uses the same persistent scheduled-execution queue as cron. The first run treats observed HTTP assets as new. Negative transitions require a complete successful source step; a failed or incomplete scan never marks an asset removed or a finding resolved.

Moderate Nuclei execution pauses without approval. The preliminary recon brief is an independent safe branch after endpoint classification, so the researcher can review endpoint and change intelligence before approving scanner enrichment. Intrusive, destructive, denial-of-service, brute-force, credential-stuffing, and state-changing behavior is not part of this workflow.

```powershell
go run ./cmd/platform scope plan --scope .\scope\mixed-example.json
go run ./cmd/platform workflow plan --program-id <uuid> --scope .\scope\mixed-example.json --workflow authorized-web-baseline
go run ./cmd/platform workflow run --program-id <uuid> --scope .\scope\mixed-example.json --workflow authorized-web-baseline
go run ./cmd/platform schedule create --program-id <uuid> --name weekly-baseline --workflow authorized-web-baseline --cron "0 9 * * 1" --timezone "UTC" --objective "weekly authorized baseline"
go run ./cmd/scheduler
```
