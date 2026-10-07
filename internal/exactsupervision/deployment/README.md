# Fixed deployment contract (4B4B2B-I1, policy only)

This directory contains eight reviewed files: policy metadata/tests, three
explicit slice artifacts, one service-specific policy drop-in, and tmpfiles
provisioning intent. Nothing here installs, enables, starts, or
observes a unit. `contract.json` is descriptive policy, not execution authority
or evidence that a host enforces it. Production admission remains disabled.

There is no legitimate reviewed production exact peer/coordinator entrypoint.
The execution-service template is deliberately absent (P0 option A). Do not
substitute a shell, worker/platform/scheduler executable, offline fixture, or
placeholder. No backend, D-Bus/polkit operation, public evidence issuer, Runner
promotion, helper build/install, or production numerical policy is introduced.

## Topology and persistent observation

```text
reconductor.slice
└── reconductor-exact.slice
    └── reconductor-exact-slot.slice
        └── future reconductor-exact-run@<32-lowercase-hex>.service
```

The slot's exact cgroup path is
`/reconductor.slice/reconductor-exact.slice/reconductor-exact-slot.slice`.
The leaf appends `/reconductor-exact-run@<32hex>.service`.
All three slices are explicit. Normal systemd name-derived parent dependencies
activate the ancestors; there is no alternative placement or service dependency.

The slot alone has `WantedBy=multi-user.target`. Approved future enablement
activates an empty persistent slice, never an execution instance. Installing
these files is distinct from enabling or starting them. No enablement is done
by this slice. `StopWhenUnneeded=no` requires persistence without a sentinel.
`RefuseManualStop=yes` prevents accidental direct manual stops; it does not
prevent dependency-driven shutdown. Default dependencies remain enabled.

The future observer pins the boot and slot object identity. Reload/reexec must
preserve or reverify identity and ownership continuity, not silently rebind
observations. Shutdown disarms admission and ends that generation. Child GC is
allowed; the active parent slot, not an ephemeral child pathname, is authority.

The existing package-owned exactsupervision capacity model is the sole serial
authority. No second admission, queue, or reuse is allowed before the original
final milestone plus a later fresh pinned-slot `populated=0`. Optional PID1
`ConcurrencyHardMax` is recorded only as unimplemented defense in depth. No
concurrency limit is installed here; no soft-limit queuing is selected.

## Future service and privileged cleanup

The future template's selected properties are recorded in the manifest:
`Type=exec`, `ExitType=main`,
`Restart=no`, `RemainAfterExit=no`, `Delegate=no`, `NotifyAccess=none`, and the
fixed slot/user/group. The kill/OOM/failure properties and null standard streams
are explicit in the manifest; `RestartForceExitStatus` must remain empty.

### Fedora type-wide drop-in precedence correction (I1-F2)

The disposable Fedora 44/systemd 259.9 proof observed stock
`service.d/10-timeout-abort.conf` changing the effective loaded value to
`TimeoutStopFailureMode=abort`, despite `kill` in the proof's main template.
This is valid distribution policy, not a Fedora vulnerability or bug. systemd
applies drop-ins after the main unit; differently named files are processed in
lexicographic order, and name-specific directories take precedence over
type-wide directories for equally named files. Main-unit scalar values alone
are insufficient. See the exact
[v259.9 drop-in rules](https://github.com/systemd/systemd/blob/v259.9/man/systemd.unit.xml#L184-L228).

Reconductor therefore carries the name-specific later override
`systemd/reconductor-exact-run@.service.d/90-reconductor-exact-stop-timeout.conf`:

```ini
[Service]
TimeoutStopFailureMode=kill
```

Its package installation path is
`/usr/lib/systemd/system/reconductor-exact-run@.service.d/90-reconductor-exact-stop-timeout.conf`.
Do not modify, delete, mask, replace, or vendor Fedora's stock file. The drop-in
remains dormant until a legitimate future service template exists. Its presence
does not establish production service readiness: there is still no production
exact peer/coordinator or installable `reconductor-exact-run@.service` template.

Future admission must compare the final effective PID1-loaded configuration
after ALL unit and drop-in processing. Require `TimeoutStopFailureMode=kill`
and retain `TimeoutStartFailureMode=kill` and all other frozen mechanics. The
override's existence alone is not proof. Any later or overriding configuration
that changes a required effective value prevents admission.

Distinguish Reconductor-owned reviewed artifacts, reviewed external/vendor
deployment context, and unknown/unapproved drop-ins. The known Fedora file may
be reviewed external context; its proof-run RPM digest is not permanent policy.
Inspect all applicable type-wide, template, instance-specific, dash-prefix and
alias-related drop-ins under `/etc/systemd/system`, `/run/systemd/system`, and
`/usr/lib/systemd/system`. Unknown configuration fails closed even if its current
scalar happens to match. A path allowlist alone is never authority.

Require the owned override's exact path, root-owned protected ancestors, regular
non-symlink file, no group/world write, and reviewed content/hash/provenance.
Reject instance-specific replacement and unexpected same-name overrides in
higher-precedence paths. Verify the final loaded value still equals `kill`;
pending reload or any other loaded-property mismatch remains a rejection.
No verifier or service installation is implemented here. Focused independent
review must precede a NEW clean disposable Fedora proof; the failed guest is not
resumed and its partial observations do not prove execution or cleanup.

The sole future stop-post command is:

```ini
ExecStopPost=-+/usr/libexec/reconductor/exact-cleanup
```

It takes no arguments and no shell, sudo, or systemctl wrapper. `-` can make a
failing command compatible with a successful unit Result; that Result is not
cleanup evidence. `+` supplies privileged startup credentials. The reviewed
static helper preopens its own validated kill FD, reduces privilege, rechecks,
and performs its frozen operation. Do not change its source or add NSS lookups.

Installation must verify static ELF properties (no interpreter or dynamic
dependencies), digest/provenance, root-owned regular file and protected root
ancestors, no group/world write, no set-ID bits or file capabilities, and expected
SELinux labeling. Static linkage does not sanitize libc's pre-main environment.

### systemd v259.9 API-VFS correction (P0-F1)

Retain `ProtectControlGroups=yes`. Omit a standalone `MountAPIVFS` assignment.
An explicit parsed false value does not suppress the namespace-level API-VFS
setup implied by cgroup protection. The ordinary coordinator receives the full
host cgroup hierarchy read-only, without a private cgroup namespace.

For `+`, systemd disables the ordinary per-command protection parameters before
namespace setup, including the API-VFS/cgroup-protection parameters. A cloned
mount namespace can nevertheless exist. Do not require its mount-namespace ID
to equal PID1. The frozen helper instead validates its actual full-root `/proc`,
`/sys/fs/cgroup`, and `/run` views. Root-image/chroot replacements, explicit
bind/tmpfs replacements and namespace joins are prohibited by this contract.

The ordinary coordinator's API setup can create a fresh procfs instance for its
host PID namespace; existing sysfs/runtime mounts are retained by their handlers.
This is not a promise that all API mounts retain PID1's mount IDs. The remaining
hardening choices are recorded with their deferred settings; the complete
combination still requires separate Fedora deployment proof.

Version-pinned evidence:
[effective-setting logic](https://github.com/systemd/systemd/blob/v259.9/src/core/execute.c),
[privileged execution parameters](https://github.com/systemd/systemd/blob/v259.9/src/core/exec-invoke.c),
[API-VFS implication and mount handlers](https://github.com/systemd/systemd/blob/v259.9/src/core/namespace.c).

## Account, anchor, and fresh admission binding

Use trusted administrator/package provisioning, not sysusers in this slice.
Provision static named user and primary group `reconductor-exact`, allocating
nonzero UID/GID without freezing numeric values. Require locked password,
non-login shell, no useful home or operator session, no identity sharing with
authority or other applications, and no unrelated supplementary memberships.
No wheel/docker/operator membership, DB/Redis/evidence credentials, authority
descriptors, or generic cgroup management authority belongs to this identity.

An empty `SupplementaryGroups=` resets unit additions; it does not erase account
database memberships. Verify the actual account and process groups. The main
peer may report its intended primary GID in Linux `getgroups()`; no unrelated
GID is allowed. The cleanup helper independently clears supplementary groups.

The fixed tmpfiles rules express provisioning intent only:

```text
d /run/reconductor-exact 0755 root root -
f /run/reconductor-exact/execution.identity :0600 :reconductor-exact :reconductor-exact -
```

Tmpfiles creates the anchor when absent. The `:` prefixes make its mode, user,
and group creation-only: an existing anchor's mode and ownership are not repaired
into compliance. Existing unsafe or mismatched state remains visible to the
future trusted admission preflight.

Provision after account creation and before admission. No age cleanup, truncating
`f+`, or live-anchor replacement is selected. The parent is root-protected; the
anchor must be a regular one-link file with safe mode and validated full-root
runtime tmpfs/ancestors. Its contents are irrelevant; numeric identity comes only
from `st_uid`/`st_gid`. Tmpfiles does not prove safe existing objects, mount
identity, link count, current binding, or fresh admission-time equality.

The future trusted admission preflight must independently resolve the actual
account/group and verify a regular file, exactly one link, safe mode `0600`,
protected ancestors, and the supported runtime filesystem. It must require BOTH
matching UID and matching primary GID. Any mismatch fails closed before StartUnit.
Do not replace a live anchor or change accounts during an invocation. No
ExecCondition verifier is introduced.

## Authority, environment, and descriptors

The future worker-side boundary validates exactly 32 lowercase ASCII hex bytes
using the existing parser BEFORE StartUnit. All-zero is syntactically valid;
syntax and lifecycle identity do not authorize work. Reject escaped unit names.
Verify deployment integrity and loaded configuration, account/anchor binding,
observer generation, and reserve capacity; reference the fixed instance before
the narrow start operation. Execution callers receive no generic systemctl,
StartUnit/KillUnit, transient-property, manager D-Bus, or mutation privileges.

Verify root-owned unit/artifact identity, the required owned drop-in and exact
reviewed owned/external allowlist, and final effective loaded properties; reject
unknown drop-ins, pending reload or mismatch. No caller may
replace ExecStart/ExecStopPost, slice, identity, environment, or resource policy.
Trusted configuration must remain stable until cleanup.

The peer environment remains exactly `LANG=C`, `LC_ALL=C`, `TZ=UTC`. The future
shared-unit helper environment uses these same fixed trusted assignments.
Reset unit assignments first, exclude EnvironmentFile/PassEnvironment/PAM and
other unreviewed sources, and remove generated variables and default PATH before
exec. `SetLoginEnvironment=no` and `MemoryPressureWatch=skip` are recorded.

The boundary is complete trusted environment-source closure, including a fresh
closed-allowlist check of global service environment. Unknown/unreviewed names
fail admission just like loader/libc tuning inputs. A known-name denylist,
static linkage, or sanitization inside main cannot establish pre-exec safety.
No checker is implemented here.

`StandardInput=null`, `StandardOutput=null`, `StandardError=null`: no TTY,
required journal stream, or authority-bearing standard FD. Exclude leaf socket
activation, OpenFile, named I/O, credential FDs, FD-store inputs, watchdog and
notification FDs, log namespaces and directory-environment features. The helper
closes FDs above 2 fail-closed. Reverse handoff is a separate outbound empty-handed
peer connection: trusted worker/Broker-owned admitted material, one designated
attempt, no reconnect/replay. No action material enters argv, environment,
properties, instance name, or a temporary path. Control IPC never enters sandbox
FDs or mounts. This directory implements none of that transport.

## Observation, failure, and remaining deployment gates

Observer and trusted owner remain outside the slot. Finality requires the
ORIGINAL InvocationID, observed/completed stop-post, terminal `inactive/dead` OR
`failed/failed`, `ControlPID=0`, and no later invocation command possible. Only a
fresh subsequent read of the pinned persistent slot showing `populated=0` can
complete cleanup. Do not broaden states or mint evidence from public facts.

Helper SIGKILL/write return/status, ExecStopPost result, unit Result, UnitRemoved,
child disappearance, an earlier zero, or cgroup.events failure do not attest
cleanup. Ordinary systemd group kill is not the atomic cleanup proof. Helper
failure or incomplete observations leave cleanup UNCONFIRMED with no capacity
reuse. Unexpected reactivation, changed InvocationID, observer loss or post-final
command quarantines supervision. No restart, reset, retry, recovery, resend,
replay, or original-instance reuse is implemented or authorized.

MemoryMax, MemorySwapMax, TasksMax, CPUQuota, RuntimeMaxSec, TimeoutStartSec,
TimeoutStopSec and OOMPolicy are required mechanisms. Runtime/start/stop limits
must be finite. Numerical values belong to 4B4B4, in a future fixed reviewed
drop-in, never caller/transient overrides. Admission stays disabled until those
values and all remaining integration/proof gates are satisfied.

Target stock Fedora SELinux Enforcing; no custom policy or enforcement bypass.
Future proof must inspect actual labels and AVCs. Prior unconfined observer
diagnostics did not prove production observer confinement.

Portable Go semantic tests read only these artifacts; they never call systemd.
Separate Linux/Fedora integration may use `systemd-analyze verify` on the slice
files without installing them, recording the tool version first. That syntax
check is not host enforcement or disposable deployment proof. The future proof
must cover provisioning/binding negatives, artifact integrity, persistence/GC,
serial gating, exec-boundary environment/sentinels/FDs, lifecycle/helper failures,
reload/reexec, Enforcing AVCs, and ordered final-milestone plus slot-zero evidence.
