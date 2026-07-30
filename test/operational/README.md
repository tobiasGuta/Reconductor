# Operational approval-lifecycle E2E test

This opt-in test exercises Reconductor's complete scheduled approval lifecycle
against one in-process HTTP server bound to a dynamic `127.0.0.1` port. It
creates disposable PostgreSQL and Redis containers, two fresh programs and
schedules, rejects the first Nuclei approval, and approves plus explicitly
resumes the second.

The test is excluded from normal `go test ./...` runs by the `operational`
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

The default outer timeout is eight minutes. A warm run normally takes one to
three minutes:

```powershell
.\scripts\test-operational-e2e.ps1 -Timeout ([TimeSpan]::FromMinutes(10))
```

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
arguments, lifecycle timeouts, or any non-loopback request are failures.

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
