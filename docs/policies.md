# Policies and approvals

Risk levels are `passive`, `low`, `moderate`, `high`, and `forbidden`. Passive/low capabilities are allowed only after scope checks and within configured limits. Moderate actions need workflow or action approval. High actions need explicit per-action approval. Forbidden actions always fail closed.

Policies can restrict capabilities, HTTP methods, authentication, headless mode, directory fuzzing, template tags, payload size, redirects, cross-origin behavior, intrusive checks, rate/concurrency, scan windows, and retention. The current CLI constructs a conservative runtime policy from centralized configuration.

Every registered capability declares trusted policy requirements in its manifest. The registry evaluates those declarations at dispatch and again immediately before execution; workflow input cannot downgrade them. Authentication, directory fuzzing, cross-origin access, and intrusive checks default to denied. A denied action is audited and provider validation or execution is never reached. Failure to persist a configured policy audit also fails closed.

Scan windows are UTC, start-inclusive, and end-exclusive. Accepted forms are `HH:MM-HH:MM UTC` for a daily window and `Mon HH:MM-HH:MM UTC` for a weekly window. Overnight windows such as `Mon 22:00-02:00 UTC` are supported. An empty list is unrestricted; a malformed configured window denies execution.

| Policy property | Authoritative enforcement point | Denial evidence |
| --- | --- | --- |
| `ScanWindows` | capability registry at dispatch and execution | `policy_denied` audit with UTC-window reason |
| `AuthenticationUsage` | trusted capability manifest requirements | `policy_denied` before provider validation |
| `DirectoryFuzzing` | trusted capability manifest requirements | `policy_denied` before provider validation |
| `CrossOrigin` | trusted capability manifest requirements | `policy_denied` before provider validation |
| `IntrusiveChecks` | trusted capability manifest requirements | `policy_denied` before provider validation |
| `ArtifactRetention` | artifact creation and database expiry assignment | `artifact_retention_applied` audit |

`POLICY_ARTIFACT_RETENTION` defaults to `720h`. It currently assigns `expires_at` metadata only; automatic content and Artifact-row deletion are disabled, and expired bytes accumulate. Set it to `0s` only when indefinite retention metadata is explicitly intended. Existing artifacts from before the expiry migration retain a null expiry and are not retroactively changed. See [artifact storage ownership](artifact-storage.md).

Approval records link a request, task, action, risk, reason, decision maker, decision time, and optional expiration. Policy is evaluated before dispatch and again inside the worker immediately before execution.

Redirect scope is evaluated on both the original and destination URL. A permitted source never makes an out-of-scope redirect destination permissible.

Scope expansion is a separate human-control gate. Adding an include or removing an exclude records a pending scope version and blocks workflow execution until the operator reviews the plan and supplies `--acknowledge-scope-expansion`. Passive roots never grant active authorization. Complex regexes remain valid enforcement rules but are not converted into invented targets or ports.
