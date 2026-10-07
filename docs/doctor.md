# Environment diagnostics

`platform doctor` performs passive local readiness checks. It does not run a workflow, send target traffic, update tools, or download templates. It also validates the registered artifact-store marker, durable publisher support for the current operating system and filesystem, configured prepared-evidence limits, and capacity for one additional provider result.

```powershell
go run ./cmd/platform doctor
go run ./cmd/platform doctor --format json
```

The table and JSON formats report whether each component is required, its status, detected version, tested version family and worker pin, resolved path, and a safe diagnostic. The command exits unsuccessfully when a required component is missing, is the wrong binary, is incompatible, is unreachable, is outdated, or cannot be verified. A local Nuclei template install newer than the worker pin is reported as `ahead` and does not fail the doctor run.

Provider checks honor `SUBFINDER_EXECUTABLE`, `CHAOS_EXECUTABLE`, `DNSX_EXECUTABLE`, `NAABU_EXECUTABLE`, `HTTPX_EXECUTABLE`, `KATANA_EXECUTABLE`, `GAU_EXECUTABLE`, and `NUCLEI_EXECUTABLE`. Version probes have a five-second timeout and use provider-specific arguments. Chaos is optional for a local default workflow, but the complete worker image verifies every bundled provider at startup.

## Worker pins

The complete worker image uses one shared provider set because the current Redis consumer group can deliver any capability job to any worker. Splitting the image by capability would first require capability-aware queue routing.

| Provider | Worker pin | Tested local family |
|---|---:|---:|
| Subfinder | `v2.14.0` | `2.x` |
| Chaos | `v0.5.2` | `0.5.x` |
| DNSx | `v1.3.0` | `1.x` |
| Naabu | `v2.6.1` | `2.x` |
| HTTPX | `v1.10.0` | `1.x` |
| Katana | `v1.6.1` | `1.x` |
| GAU | `v2.2.4` | `2.x` |
| Nuclei | `v3.10.0` | `3.x` |
| Nuclei templates | `v10.4.3` | exact snapshot |

Provider pin constants and Docker build arguments have regression coverage so they cannot drift silently.

## Nuclei templates

For the worker image, deterministic template diagnostics use `NUCLEI_TEMPLATE_DIR` with a `.platform-template-version` marker. The marker must contain the expected snapshot version, and the worker image supplies the pinned directory and marker at `/opt/nuclei-templates`.

For local installs, `NUCLEI_TEMPLATE_DIR` is optional. When no platform marker is present, doctor asks Nuclei for the active public template version with `nuclei -tv`, which supports the standard install path such as `C:\Users\<user>\nuclei-templates`.

Template statuses:

| Status | Meaning | Fails doctor |
|---|---|---:|
| `current` | Template version matches the worker pin | no |
| `ahead` | Local template version is newer than the worker pin | no |
| `outdated` | Template version is older than the worker pin | yes |
| `untracked` | Doctor could not prove the active template version | yes |
| `missing` | Template directory or Nuclei probe is unavailable | yes |

`NUCLEI_UPDATE_TEMPLATES` remains disabled by default. Doctor never performs an update or remote freshness check.

## Services

PostgreSQL readiness requires a successful connection, version query, and major version 15 or newer. Redis readiness requires `PING`, server information, and major version 7 or newer. Credentials are used for the checks but are not printed in the report.

The `Prepared evidence` row requires the current schema, an initialized artifact store matching `ARTIFACT_STORE_ID`, a supported durable publisher, configured limits, and enough uncharged capacity for one additional maximum-sized set. Its diagnostic reports current set and byte occupancy. Missing limits are configured explicitly with `platform artifact-store prepared-limits`; full capacity is reclaimed with `platform artifact-store prepared-recover` during a drained maintenance window.
