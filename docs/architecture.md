# Architecture

The application is split into commands under `cmd/` and business packages under `internal/`. Commands load one typed configuration and call services; they do not duplicate scope, policy, queue, or execution rules.

`ActionRequest` is the execution boundary. The capability registry resolves a stable capability name to a fixed provider implementation. Providers validate typed JSON, verify every target against scope, construct their own argument list, invoke an executable without a shell, and return structured output. Arbitrary executable names and raw command arrays are not part of the contract.

`scope` preserves normalized source rules with stable SHA-256 identities and complete URL evaluation. `targeting` conservatively classifies exact host/IP literals, narrow wildcard roots, protocol/port combinations, paths, exclusions, and ambiguous expressions. Provider-specific adapters parse records independently; malformed or filtered records become decisions and warnings instead of failing a usable batch. Raw redacted stdout/stderr and normalized results are separate artifacts.

The local workflow runner and Redis Streams worker share the same execution service. That service enriches historical inputs, invokes the registry, persists raw stdout, raw stderr, normalized `result.json`, observations, findings, and audit-linked tool metadata with the same artifact roles in both modes. Local mode provides a complete operator-driven workflow. Its ready-node scheduler runs independent DAG branches in bounded deterministic waves, then serializes completion commits in topological order. Process-local program, provider, and normalized-host execution slots guard both workflow steps and worker jobs. Streams provide crash-recoverable distributed capability delivery. Results are acknowledged only after durable persistence.

The loopback-only operator console is a read model and narrow mutation API over the same store and queue. It exposes persisted workflow state, scope posture, observations, finding lifecycle records, sanitized provider metadata, approvals, and dead-letter recovery without returning raw provider output, artifact paths, sensitive artifacts, or complete queued job payloads. It is not a separate execution path and cannot bypass the existing scope, policy, approval, or provider boundaries.

Structured IDs correlate executions internally. The target URL is never changed to carry a task or scan identifier.

The legacy aggregator is no longer required: the executor persists tool runs, artifacts, observations, candidates, and audit events transactionally. This removes a second lossy results-list hop.

## Package map

- `config`: environment defaults and validation
- `domain`: stable data and action contracts
- `migrations`, `database`: versioned PostgreSQL schema and persistence
- `scope`, `policy`: authorization boundaries
- `targeting`, `provideroutput`: deterministic plans and typed provider-record filtering
- `capability`, `providers`: controlled execution registry
- `workflow`, `workflows`: state machine and production definition
- `queue`, `worker`: Redis Streams delivery and recovery
- `artifact`, `redaction`: evidence storage and secret filtering
- `assets`, `normalize`: observations, comparison, endpoint identity
- `findings`: candidate lifecycle and safe verification verdicts
