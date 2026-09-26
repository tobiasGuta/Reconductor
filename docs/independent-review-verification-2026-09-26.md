# Independent review verification and corrective engineering

Date: 2026-09-26
Branch: `feat/large-result-publication-admission`
Reviewed and current commit: `70326f162dd76b9eeb6def9bbcaae23fb19b108e`

## Outcome

The Claude Opus 4.6 report was treated as investigation input rather than an authoritative defect list. Seven reported findings were confirmed, two were partially confirmed, and three were not confirmed or were intentional contracts. Confirmed safety and correctness defects were corrected without replaying providers under unresolved persistence, broadening approval, weakening result fencing, or removing output limits.

The unit, package, vet, build, race, PostgreSQL, Redis, and Linux artifact suites pass. The operational Approval/Recovery harness was repaired sufficiently to compile, initialize durable artifact authority, start the real scheduler, publish artifacts on an ext filesystem, and send HTTPX traffic only to its loopback fixture. Full lifecycle completion remains partially validated: pinned HTTPX v1.10.0 buffers stdin-mode results for approximately 30 seconds in the WSL/musl bridge used for this run, and the harness observed two loopback requests but no normalized stdout before the scheduled execution advanced. The large-target stdin contract was deliberately preserved rather than moving authorized targets onto a size-limited process command line solely to make this environment green.

No commit, push, merge, or pull request was performed.

## Baseline and worktree

- `HEAD` exactly matched reviewed commit `70326f1`; there were no intervening commits to reconcile.
- Pre-existing changes were `.gitignore` plus untracked `.agents/` and `agents/`. They were not modified or used as implementation inputs.
- The baseline `go test -count=1 ./...` passed with database/Redis integration tests skipped because their test environment variables were unset.
- Local Compose PostgreSQL 15.13 and Redis 7.4.5 were healthy and bound to loopback.

## Finding verification matrix

| # | Classification | Evidence and disposition |
|---|---|---|
| 1 | CONFIRMED | A resumed approved step installed an unconditional approval callback, authorizing later gates. Approval is now scoped to the exact persisted `StepRun`; `--approve-moderate` is a one-use moderate-risk authorization and cannot approve a later or high-risk gate. Rejection and cancellation remain terminal. |
| 2 | NOT CONFIRMED / DESIGN DECISION | `result_contract_limit` intentionally records the provider's actual outcome separately from admission rejection. Envelope validation explicitly supports this case. Overwriting the provider outcome would destroy provenance, so no production change was made. Existing outcome-matrix tests remain green. |
| 3 | CONFIRMED | A publisher-guard release error after durable adoption was returned as an execution failure, allowing workflow state to contradict committed database state. Post-adoption close failures are now logged while the durable success remains authoritative. |
| 4 | CONFIRMED, report classification corrected | Failures marking an artifact `PUBLISHING` or sealing it were treated as known failures and could abandon recoverable prepared evidence. They now return `UnresolvedPersistenceError` and leave evidence for reconciliation. This does not label every database error `COMMIT_UNKNOWN`; it preserves the narrower unresolved lifecycle fact. |
| 5 | CONFIRMED | Retry transfer used non-atomic sorted-set read, stream append, and removal. One Redis Lua operation now claims each due member by `ZREM` and appends it exactly once. Five concurrent pumps moving ten jobs were verified against real Redis. |
| 6 | PARTIALLY CONFIRMED | Truncated or digest-mismatched exclusive writes left newly created files that blocked exact retry. Definitely unverified new files are now unlinked and the parent synchronized. A correct final file whose directory fsync fails is retained and reported as recovery-required; recovery verifies it rather than deleting possibly durable evidence. Linux failure-injection tests pass on an ext-backed volume. |
| 7 | CONFIRMED | Sorted `SupportedProviders[0]` overrode `Multi`'s configured default. Both local workflow and worker resolution now delegate to the registry default while preserving explicit selections. |
| 8 | CONFIRMED, semantics narrowed | Skipped sources silently erased required bound input, but some built-in bindings are legitimately optional. A versioned `required-by-default/v1` binding contract now skips consumers of unavailable required evidence and requires explicit `OptionalBindings`. New workflow releases use this contract; immediately prior releases retain legacy materialized behavior. |
| 9 | NOT CONFIRMED / DESIGN DECISION | Materialized definitions and scope versions are immutable execution authority. Resuming an existing run should not silently rematerialize it against expanded scope. Scope expansion requires a new authorized execution. No blanket `RerunOnInputChange` change was made. |
| 10 | PARTIALLY CONFIRMED / architectural follow-up | SIGTERM cancellation does mark active scheduler work cancelled, but merely omitting the scheduler transition would not make it recoverable: the engine also persists cancellation, while expired progressed executions are intentionally interrupted to prevent unknown provider replay. No unsafe partial fix was applied. Recoverable active-provider restart needs an explicit reconciliation contract. |
| 11 | NOT CONFIRMED / DESIGN DECISION | Raw output and semantic projections intentionally share one durable result capacity authority. `lines`, authorized records, and normalized records serve different consumers and are independently bounded. Removing representations or accounting would weaken admission guarantees. |
| 12 | CONFIRMED | Task control polling handled pause and cancel but not `TaskRunning`. Both orchestration and the platform watcher now call `Resume`; transition tests cover pause-to-running. |

## Additional defects found during integrated validation

1. Worker lease loss was only logged. The worker now cancels the in-flight execution, performs no Ack/Fail mutation after loss, and leaves the delivery pending. Lease refresh is an atomic Redis Lua check-and-refresh that refuses to steal ownership from a new consumer.
2. `RECON_PROVIDER_UPDATE=false` was parsed but unused. ProjectDiscovery invocation and version-probe arguments now include `-duc` when updates are disabled, and sanitized invocation audit records expose only the boolean `update_check_disabled`.
3. The operational harness no longer compiled because console projections omitted `sanitized_arguments` and audit `details`. The bounded/sanitized fields are selected again.
4. The operational harness did not initialize or capacity-configure the now-required artifact store. It now creates a unique store ID, initializes the store, and configures bounded prepared-evidence limits.
5. Scheduler readiness parsing required an exact log-field count and rejected new prepared-capacity metrics. It now validates the required prefix while allowing additional structured fields.

## Six operational risks

| Risk | Assessment |
|---|---|
| Streaming projector deadlock | Plausible but not reproduced. Parallel result-adoption transactions can acquire overlapping asset locks in provider order. PostgreSQL deadlock detection and unresolved prepared-result recovery limit corruption, but availability contention remains. A canonical locking or per-program adoption serialization design should be evaluated separately. |
| Crash after provider execution but before staging | Confirmed residual architecture risk. The allocated prepared set can be quarantined without bytes after a process crash. Non-idempotent replay remains prohibited; a future provider-to-durable-stream handoff is required to close this window. |
| Historical materialization compatibility | Real release-discipline risk, currently mitigated. Adding optional fields does not break old JSON under `DisallowUnknownFields`; removing/renaming stored fields would. New 2.5.0/1.5.0 releases preserve the immediately prior release tuples and tests verify support. |
| Redis stream growth | Confirmed operational risk, deferred. Jobs are deleted on terminal delivery, but results, events, and dead letters have no retention contract. An arbitrary `MAXLEN` would silently discard delivery/diagnostic data; retention must be configured and documented before trimming is introduced. |
| Scheduler/CLI budget bypass | Disproved. `orchestration.Service.engine` constructs the policy-derived local limiter for direct CLI and scheduler execution. The worker additionally receives its configured limiter. |
| Worker continues after lease loss | Confirmed and fixed. Refresh verifies current consumer ownership atomically, cancellation propagates through budget/provider/persistence work, and no queue finalization occurs after loss. |

## Validation evidence

### Passing

- `go test -count=1 ./...`
- `go vet ./...`
- `go build ./cmd/...`
- `go test -race -count=1 -p=1 ./...` before the final provider-audit additions: all packages passed.
- Final changed-package race pass: providers, command providers, database, queue, worker, workflow, orchestration, execution, artifact, workflows, and platform command all passed.
- Focused Priority A suites: workflow, orchestration, execution, result admission, and domain passed.
- Real PostgreSQL/Redis serialized integration pass:
  - migrations: 10.036s
  - database: 266.077s
  - orchestration: 6.195s
  - scheduler: 16.343s
  - queue: 0.943s
  - worker: 1.964s
- Final real Redis owner-transfer, atomic retry pump, and worker tests passed.
- Linux artifact suite passed in `golang:1.25.13` with an ext-backed temporary Docker volume: `ok .../internal/artifact 0.985s`.
- Operational harness unit checks for ownership labels, generation-isolated readiness, scheduled-execution audit identity, and recovery terminal-state diffs passed with the `operational` tag.
- `git diff --check` reported only repository-wide CRLF conversion warnings, with no whitespace errors.
- Temporary E2E containers, Docker volumes, copied toolchains, WSL directories, and the temporary musl loader were verified absent after cleanup.

`staticcheck` was not installed and was reported as unavailable rather than counted as passing.

### Partial operational E2E

The native Windows run first exposed and drove fixes for the stale console projection, missing artifact-store initialization, and rigid readiness parser. Durable publication itself correctly refuses native Windows filesystems, so the harness was moved to WSL/Linux on an ext filesystem using the pinned local provider binaries and disposable, ownership-labelled PostgreSQL/Redis containers.

Observed runtime evidence:

- Real migrations and artifact-store initialization completed.
- Prepared-evidence limits were visible in the live scheduler readiness event.
- The real scheduler claimed the scheduled execution.
- HTTPX sent exactly two requests to the in-process `127.0.0.1` fixture (HTTPS fallback plus HTTP); no public target traffic occurred.
- The invocation audit proved one target, 24 stdin bytes, the expected provider, a target-plan digest, and `update_check_disabled=true`.
- The pinned HTTPX process produced no stdout before the harness transition; an isolated reproduction showed its stdin mode emits only after approximately 30 seconds in this WSL/musl bridge, while `-u` returns immediately. `/dev/stdin`, `/proc/self/fd/0`, and `-l -` are not viable with this bridge.

Therefore Approval/Recovery completion, downstream classification/report generation, and guarded Nuclei execution are **not claimed as passed** in this environment. The command-line target workaround was rejected because it would violate the existing large-target transport regression and risk OS argument-length failure. A Linux-native CI/host run of `TestApprovalLifecycle` and `TestRecoveryLifecycle` remains the required release evidence.

## Remaining release risks and handoff

1. Obtain a clean Linux-native operational Approval and Recovery pass using the standard pinned tools; do not count the WSL partial run as full E2E success.
2. Define a safe active-provider restart/reconciliation contract before changing scheduler SIGTERM cancellation semantics.
3. Define Redis results/events/dead-letter retention policy before adding stream trimming.
4. Evaluate canonical projector lock ordering or explicit per-program adoption serialization under a dedicated PostgreSQL contention test.
5. Close the pre-staging crash window only with a durable provider-output handoff; do not replay under unknown outcome.

The working tree remains intentionally uncommitted for review.
