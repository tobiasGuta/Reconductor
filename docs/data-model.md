# Data model

The primary hierarchy is:

```text
Program -> Task -> WorkflowRun -> StepRun -> ToolRun
```

Programs hold engagement identity, scope/policy references, current scope and target-plan digests, normalized include/exclude digests, and warnings. Scope versions retain the sanitized plan, added/removed rule digests, expansion classification, and acknowledgement. Tasks hold a human objective. Each execution creates a distinct WorkflowRun. StepRun stores attempts, structured input/output, idempotency and approval state. ToolRun records provider/version, sanitized arguments, environment, timings, timeout, exit code, and artifact references.

Audit events preserve program scope decisions and task/run/step/tool lineage for scope loads, plan derivation, manual roots, accepted/filtered targets, exclusions, protocol/port rejection, scope changes, and moderate approvals.

Artifacts carry nullable `expires_at` metadata. A null value means explicitly indefinite retention; expired content is removed from local storage before its database row is deleted, and both retention assignment and expiration are audited.

Assets are stable logical identities. Asset observations describe what a capability saw during a particular successful workflow run.

A corrected Endpoint is one Program-scoped, origin-local normalized heuristic route family. Its semantic identity contains the Program, normalized HTTP origin (`origin_scheme`, `origin_host`, and `origin_effective_port`), route signature, method, base request content type, and sorted unique query-parameter names. HTTP and HTTPS are different origins; an omitted port and its scheme default are equivalent, while non-default ports remain distinct. Hosts use lowercase ASCII URL reg-name syntax, preserve a terminal dot, accept underscore, and receive no DNS resolution or implicit IDNA conversion. IPv4 and bracketed IPv6 use canonical parsed forms.

Endpoint path normalization is deliberately conservative for security research. Repeated separators, literal `.` and `..` segments, encoded dot segments, encoded separators, and a trailing slash remain identity-significant. Dynamic classification may decode one segment only to decide whether that whole segment is an identifier; it never creates another path boundary. Query values are retained in the canonical representative URL but do not participate in semantic identity.

`exact_url` is the bytewise/C-collation minimum canonical member admitted to the family, not the first, latest, or complete URL history. `first_seen` and `last_seen` are the minimum and maximum successful classifier StepRun completion times, not claims about external endpoint existence. Occurrence evidence remains in workflow, artifact, and observation history.

Rows created before migration 0013 remain untouched legacy rows with a null origin tuple. They are excluded from corrected uniqueness and are not relation-ready solely because they have an Endpoint UUID. There is no historical origin backfill; future attributable reconstruction must insert a corrected row while preserving the legacy row.

Route signatures generalize integer, UUID, long hex/ObjectID, date/timestamp, and strong high-entropy identifier segments. They do not generalize a path merely because it has several siblings and do not clean security-significant path structure.

Scanner output becomes `candidate_findings`. Verification results persist a compatibility `verdict` plus separate `evidence_verdict` and `impact_verdict` values. Playbooks can mark behavior as `observed` while leaving impact `unreviewed`; promotion to `verified_findings` is blocked unless the latest verification has `evidence_verdict = observed` and `impact_verdict = confirmed`. The scanner does not assert business impact.
