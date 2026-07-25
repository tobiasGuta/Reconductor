# Capabilities

Active providers accept explicit authorized HTTP URLs; they never invent `https://` for a bare hostname. Subfinder, Chaos, and GAU accept bare domains only as passive roots. Named adapters normalize Subfinder, Chaos, DNSx, Naabu, HTTPX, Katana, GAU, and Nuclei output one record at a time. Protocol, host, port, path, and exclusions are rechecked; malformed records warn and filtered records do not fail the usable batch.

A capability manifest declares its stable name, version, risk, schemas, scope type, approval behavior, retry/idempotency properties, providers, artifact types, symbolic secret requirements, and default timeout.

Every external provider also has a centralized executable probe containing its version arguments, tested compatibility family, configuration variable, and exact worker-image pin. The doctor and runtime executor use the same parser. Missing executables, commands that do not return a semantic version, and versions outside the tested family are rejected before target execution.

External providers receive only validated structured fields. They construct fixed arguments internally and use `exec.CommandContext` directly—never a shell. Target values remain separate arguments, cancellation terminates the process, version information is recorded, and output is redacted before normal persistence.

External provider output uses one closed typed contract: `lines`, `authorized`, `authorized_urls`, `authorized_records`, `filtered`, `records`, `warnings`, `accepted_count`, and `filtered_count`. The manifest publishes that full schema with `additionalProperties: false`, and the runtime rejects nil collections, inconsistent counts, malformed warning entries, and invalid normalized record shapes before persistence.

`discover.subdomains` supports Subfinder by default and Chaos when `CHAOS_KEY` is configured and the provider is explicitly selected. Katana receives `-headless` only when requested and policy-approved. Nuclei runs in a dedicated per-execution process so callback correlation never requires changing the target URL; it receives the centralized rate, host/template/headless concurrency, timeout, severity, include-tag, exclude-tag, and template-directory settings. Takeover is not added implicitly or executed twice.

The internal `targeting.prepare` capability rechecks and deduplicates exact and discovered URLs immediately before active execution. Other internal capabilities classify normalized endpoint identities, compare snapshots, and produce changes-only reports without launching a subprocess. Each internal capability has a dedicated input/output Go type and a closed JSON Schema with required fields and `additionalProperties: false`. Definition validation and runtime validation both reject missing, null, mistyped, semantically invalid, and unexpected fields before capability execution. Redacted raw stdout/stderr and normalized result artifacts are stored separately.

## Endpoint intelligence

`classify.endpoint` version 3 consumes only scope-authorized structured records. Provider outputs retain a separate `authorized_records` collection after the protocol, host, port, path, and exclusion checks; raw normalized records are never bound into the classifier workflow input.

Classification is deterministic and explainable. Each normalized endpoint contains labels, individual weighted signals, an interest score, source confidence, provider sources, technologies, statuses, redirects, JavaScript relationships, and historical behavior. Signals cover:

- exact path and query-name keywords, without substring matches such as `api` inside `capistrano`;
- query parameters and normalized path parameters;
- non-read HTTP methods and API-oriented content types;
- JavaScript source relationships;
- authentication keywords, response statuses, and `WWW-Authenticate` evidence;
- technology fingerprints;
- declared API-schema membership and discovered schema documents;
- response status, redirect destination, and server errors;
- new endpoints, status changes, technology changes, and multi-source corroboration.

Endpoints with a score of at least 2 enter `interesting_endpoints`; all normalized endpoints remain in `classifications`. Confidence is a bounded deterministic evidence score, not a vulnerability probability. The full evidence object is persisted as the normalized step-result artifact and is passed unchanged into the changes report.
