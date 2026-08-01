# Operational approval and recovery E2E tests

These opt-in tests exercise Reconductor's scheduled approval and safe restart
contracts against one in-process HTTP server bound to a dynamic `127.0.0.1`
port. They create disposable PostgreSQL and Redis containers and use only an
isolated harmless Nuclei template.

The tests are excluded from normal `go test ./...` runs by the `operational`
build tag.

## Prerequisites

- Go 1.25 or newer.
- Windows PowerShell 5.1 or PowerShell 7 on Windows.
- A reachable Docker daemon and Docker CLI.
- These images already present locally:
  - `postgres:15.13-alpine`
  - `redis:7.4.5-alpine`
- Compatible DNSx 1.x, Naabu 2.x, HTTPX 1.x, Katana 1.x, and Nuclei 3.x
  executables on `PATH`, or configured with their normal `*_EXECUTABLE`
  variables.

The harness never pulls images. Provision them explicitly, outside the test,
if required:

```powershell
docker pull postgres:15.13-alpine
docker pull redis:7.4.5-alpine
```

Subfinder, Chaos, GAU, workers, public targets, and the normal Nuclei template
repository are not used.

## Run

From the repository root:

```powershell
.\scripts\test-operational-e2e.ps1
```

The default suite remains `Approval` for compatibility. Select either suite or
both through the constrained selector:

```powershell
.\scripts\test-operational-e2e.ps1 -Suite Approval
.\scripts\test-operational-e2e.ps1 -Suite Recovery
.\scripts\test-operational-e2e.ps1 -Suite All
```

The wrapper maps those three values to fixed test names and does not accept an
arbitrary Go test expression. The default outer timeout is eight minutes. A
warm Approval run normally takes one to three minutes; Recovery targets less
than two minutes; All normally takes two to five minutes:

```powershell
.\scripts\test-operational-e2e.ps1 -Suite All -Timeout ([TimeSpan]::FromMinutes(8))
```

## Recovery boundaries

The Recovery suite uses one disposable environment and one scheduled
execution to verify:

1. Restart while `paused_for_approval` preserves cleared leases, pending
   approval, task/workflow/step lineage, idempotency keys, tool runs, and
   provider request counts.
2. An approval recorded while the scheduler is stopped remains approved but
   does not implicitly resume after restart.
3. An explicit resume requested while the scheduler is stopped produces the
   canonical unclaimed `pending` state. A new scheduler generation then reuses
   the existing execution and lineage, skips previously successful work, and
   invokes the approved isolated Nuclei action exactly once.

The scheduler log is append-only. Each process generation has an independent
readiness offset, owned PID, completion channel, start time, and exit result.
Restart termination targets that PID and its descendants, never an executable
name.

Active-provider crashes are intentionally excluded. Under the current
production contract, a stale claimed or running execution with workflow
lineage becomes terminal `interrupted`; it is not safely resumable. Recovery
after an HTTPX or Nuclei process has started requires a future production
lineage and result-reconciliation change.

## Isolation

The generated Burp-compatible scope authorizes only the selected loopback
port. Provider commands run under the local scheduler with isolated scope,
state, artifact, home, Nuclei configuration, and Nuclei template directories.

The test-only Nuclei guard delegates to the installed Nuclei executable but
fails closed unless:

- validation names the one temporary YAML file;
- scanning names exactly the fixture URL;
- `-t` names only the temporary template directory or file;
- severity is `info`;
- the only included tag is `reconductor-e2e`;
- rate and concurrency limits are one.

The guard enforces `-duc` and `-ni`, disables all supported public template
download sources through environment variables, records structured invocation
metadata, passes an empty stdin to real Nuclei, and permits at most one actual
scan through an exclusive reservation file. The harness deliberately never
uses `platform doctor`, `nuclei -tl`, or `nuclei -tv`.

Platform, scheduler, guard, and provider processes run from the generated
temporary root, so the repository `.env` is not loaded. Proxy, cloud, inherited
Nuclei, and Reconductor control variables are removed before explicit isolated
values are added. PostgreSQL and Redis readiness is checked with direct
`docker exec` argument arrays; no shell command is assembled.

## Skip and failure behavior

The test skips cleanly when the Docker CLI/daemon, a required local image, Go,
or a required provider executable is unavailable. An executable that resolves
but fails its identity/version check is a test failure. Containers that start
but do not become healthy, template validation errors, unexpected Nuclei
arguments, lifecycle timeouts, stale lineage, duplicate tool runs, surviving
owned processes, or any non-loopback request are failures. Missing
prerequisites after disposable resources have started are failures rather than
skips.

## Cleanup and diagnostics

Every run receives unique container names, labels, and a temporary root. The
test and PowerShell wrapper remove only those exact containers and paths and
restore process-level environment values. No named volume or worker container
is created.

To retain state, artifacts, bounded logs, generated scope, and invocation
metadata after a failed run:

```powershell
$env:RECONDUCTOR_E2E_PRESERVE_FAILURE = 'true'
.\scripts\test-operational-e2e.ps1
Remove-Item Env:RECONDUCTOR_E2E_PRESERVE_FAILURE
```

Containers and scheduler processes are still stopped when diagnostics are
preserved. Successful runs and failures without this explicit flag remove the
temporary root.

Cleanup releases test resources in dependency order: the current scheduler
generation and its owned descendants are stopped and awaited, the store and
fixture close, exact ownership-labelled containers are removed, and finally
the validated temporary root is deleted. Cleanup failures fail the test
without suppressing the original test failure.
