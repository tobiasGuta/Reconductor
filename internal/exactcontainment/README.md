# Unpromoted offline containment foundation

Linux/x86_64 only. This package grants no authority, implements no Runner, and
has no production caller. `ExecuteOffline(ctx, EncodedExecution)` is a diagnostic
integration API for frozen material. It validates the capsule before launch,
requires the fixed `reconductor-exact` credentials and coordinator environment,
and requires a fresh strict-profile probe using the same retained artifacts.
Failure never invokes the runtime directly and never suggests automatic retry.

## Fixed installed artifacts

Trusted deployment tooling must eventually install:

* `/usr/bin/bwrap` (Fedora 0.12.0 profile demonstrated)
* `/usr/libexec/reconductor/exact-containment-launcher` built from `native/launcher.c`
* `/usr/libexec/reconductor/exact-offline-runtime`, static Linux/x86_64 ELF
* `/usr/libexec/reconductor/exact-offline-x86_64.bpf`, the exact frozen policy bytes

All files and parent directories must be root-owned, not group/world writable,
without symlink components. Executables must have all execute bits, no set-ID
bits or file capabilities. Parent traversal and final validation use retained
openat dirfds and fstat; the checked executable is the executed/mounted object.
The launcher and Bubblewrap may use the trusted host ELF loader; only the
sandbox runtime must have no ELF interpreter. Root administrators and host
system loader/libraries remain part of the trusted deployment environment.

The filter must match the internal deterministic policy byte-for-byte. Verified
bytes are copied to a sealed memfd and passed directly to Bubblewrap. No caller
can supply paths, descriptors, policy bytes, hashes, or argument options through
this API. Runtime and launcher release hashes still need a reviewed packaging
manifest before promotion; object identity and root provisioning are enforced
now. Pinning does not make root-owned file contents immutable against root.

## Profile and boundaries

The native source is the single argv authority:

```
/usr/bin/bwrap
 --unshare-user --unshare-pid --unshare-ipc --unshare-uts --unshare-net
 --disable-userns --assert-userns-disabled --uid 0 --gid 0
 --hostname exact-offline --clearenv --cap-drop ALL
 --new-session --die-with-parent --info-fd 7
 --dir /runtime --ro-bind-fd 5 /runtime/exact-runtime
 --remount-ro / --chdir / --seccomp 6
 -- /runtime/exact-runtime
```

Only harmless preflight adds a fixed `--preflight` runtime argument. Neither
capsule bytes nor caller input selects it. No cgroup namespace requirement,
try-option, shared-network option, shell, tool, writable host mount, procfs,
sysfs or device mount exists. Bubblewrap uses temporary setup procfs internally;
that setup root is discarded and is never exposed to the workload. The final
root contains only `/runtime/exact-runtime` and its directory, read-only.
Bubblewrap's isolated loopback initialization is internal; this package adds no
routes or interface configuration. No host/target network is usable.

The coordinator starts the launcher with an explicit empty environment and cwd
`/`. Bubblewrap produces exactly `PWD=/`. This is distinct from the coordinator's
`LANG=C`, `LC_ALL=C`, `TZ=UTC` contract. Native launch establishes and checks NNP,
clears ambient/inheritable/permitted/effective capabilities and closes unintended
FDs with close_range. Self/bwrap/runtime/filter/report occupy FD3..7 during setup;
bwrap consumes/closes them. Runtime entry has only stdin/stdout/stderr, no TTY,
listener, reverse control socket, authority descriptors, or setup-report FD.

A bounded 1024-byte trusted Bubblewrap setup report independently verifies
PID/net/IPC/UTS/mount namespace identities against the coordinator. This is not
runtime output. The fixed runtime also checks UID/GID=0 inside the user namespace,
PID2 behind Bubblewrap's PID1 reaper, SID1, empty effective/permitted/inheritable/
ambient capabilities, NNP=1, seccomp mode 2, cwd, environment, FD inventory and
filesystem visibility. Missing mandatory proof fails closed.

## Seccomp

Foreign audit architectures are killed; x32 and unlisted x86_64 syscalls return
EPERM. The allowlist covers static Go startup, memory, signal/thread support,
read-only observation of the minimal root, bounded protocol pipes, clocks and
exit. Namespace-free thread clone has exactly two accepted Go flag combinations,
with/without CLONE_SETTLS. Fork/vfork and clone3 process creation are denied
(clone3 returns ENOSYS). Open/openat deny write/create/truncate/append/tmpfile;
fcntl and ioctl are narrowly restricted. PRCTL allows only NNP/seccomp/ambient
queries. PID1 wait operations are required because Bubblewrap applies the filter
to its reaper too. Network, mount/pivot, ptrace, BPF/perf, keys, modules, reboot,
swap, namespace creation/joining and unlisted mutations are denied.

Syscall names alone are not semantic confinement. The empty root, dedicated
identity, namespace separation, capabilities, NNP and FD boundary are independent
layers. EXECVE is needed for Bubblewrap's final runtime exec; it is not claimed
as a one-exec filter. There is only one mounted executable and no tools/shell.

## Protocol and lifetime

The offline proof fixture in `testdata/offline` consumes one canonical capsule
to EOF (40960 bytes maximum), derives and validates the frozen digest, and emits
one canonical Completed=false result (256 bytes maximum) then exits. It performs
no exact HTTP or authority operation. Build-time adversarial variants are tests
only. Result success additionally requires input/output EOF and a successful
process exit; Completed=true is rejected by this foundation.

4B4A establishes process containment while the trusted execution supervisor
remains present: namespace isolation, a minimal filesystem, mandatory seccomp,
capability removal, no-new-privileges, FD/environment isolation, bounded IPC and
process-local timeout/cancellation. The concurrent I/O, WNOWAIT-before-reap/group
kill, locked creating OS thread and five-second process-local lifetime follow
the frozen exactprocess model. Stderr is discarded and the setup report is
independently bounded. The filter disallows ordinary process descendants; Go
threads remain permitted. There is no automatic retry.

`--die-with-parent` is retained as best-effort defense in depth for ordinary
post-setup cleanup, not as the authoritative cleanup boundary. Bubblewrap has
an upstream startup race: its newly cloned namespace child can wait on
`child_wait_fd` before establishing its own parent-death binding. Abrupt
coordinator/monitor death in that interval can leave the setup child alive.
The review observed a pre-runtime setup child surviving beyond six seconds;
survival of an already-executing hostile runtime was not demonstrated. This
observation is not evidence of sandbox escape. The post-setup parent-death test
waits for a validated runtime result and does not cover this pre-binding window.

4B4A does not independently guarantee cleanup after abrupt trusted-supervisor
death at every Bubblewrap setup point, aggregate descendant termination,
whole-cgroup termination, or resource cleanup after supervisor crash. Its local
timeout cannot provide cleanup after the supervisor has died. Aggregate
memory/CPU/tasks limits, whole-unit lifecycle ownership and kernel/uninterruptible
task handling remain 4B4B requirements.

No production exactsandbox.Runner may be promoted until 4B4B establishes a
trusted external lifecycle owner capable of terminating the complete execution
unit independently of Bubblewrap's PR_SET_PDEATHSIG behavior. The expected
mechanism is systemd/cgroup-v2 whole-unit ownership or an equivalently reviewed
external supervisor. 4B4A alone is insufficient: promotion requires 4B4A
containment PASS, 4B4B lifecycle/resource supervision PASS and combined review.
This package implements no external-supervision mechanism or readiness claim.

## Tests and opt-in deployment proof

Ordinary tests only compile temporary fixtures, create harmless sentinels and
use unprivileged offline namespaces. They never provision accounts or install
units/artifacts. Private same-package descriptor seams admit test-owned fixtures;
production root ownership checks remain mandatory. Test native builds skip only
admission of unrelated supplementary groups, never containment/hygiene. Their
results do not replace cross-identity production-layout verification.

Set `RECONDUCTOR_REQUIRE_CONTAINMENT=1` to require real positive namespace and
seccomp execution rather than an explicit unsupported-host skip. Repeat hostile
I/O/FD/cleanup tests with `-count=30` and `-race -count=20`.

An opt-in `exactcontainment_deployment` build-tag test is for an independently
provisioned disposable Fedora guest ONLY, running as locked reconductor-exact
with root-owned fixed artifacts, SELinux Enforcing and exactly the coordinator
environment. It installs nothing and does not relax checks. Review/provision
artifacts and packaging before running it; the developer host is not a deployment
fixture. Production placement remains unproven by ordinary tests.

Remaining before promotion: reviewed runtime/launcher artifact release manifest,
disposable cross-identity production-layout preflight, 4B4B aggregate resource
and whole-unit lifecycle proof, production Runner/admission integration review.
4C exact-operation mediation/target networking remains a separate future slice.
