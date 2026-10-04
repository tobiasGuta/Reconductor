# Exact own-cgroup cleanup source (4B4B2A, unpromoted)

This Linux-only C helper accepts `argc == 1` and ignores even `argv[0]`.
The caller selects no target. Its sole terminal operation is one one-byte
`write(fd, "1", 1)` to its own validated exact execution cgroup's `cgroup.kill`.
No newline is necessary: the kernel interface accepts the single value `1`.
It does not enumerate tasks, migrate processes, change controllers, remove
cgroups, execute commands, or provide generic cgroup/systemd management.

Interface semantics follow the Linux kernel's
[cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html),
descriptor resolution follows
[openat2(2)](https://man7.org/linux/man-pages/man2/openat2.2.html), and the
capability/securebits reduction follows
[capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html).

Only this absolute membership shape is accepted:

```
/reconductor.slice/reconductor-exact.slice/reconductor-exact-slot.slice/reconductor-exact-run@<32 lowercase hex>.service
```

The parent slot and every ancestor, other service/template, extra subgroup,
escaped/traversal path, uppercase or malformed instance are rejected. An
explicitly encoded all-zero 32-character instance is syntactically allowed,
consistent with the frozen Go instance grammar; syntax is not admission.

## Kernel anchors and rechecks

`getpid()` supplies the only PID used to read membership. The fixed `/proc`
and `/sys/fs/cgroup` anchors are opened below `/`, without symlinks or magic
links, and checked for procfs/cgroup2 magic, root ownership and directory type.
The fixed anchor lookup must cross their expected mounts. Every lookup below
those descriptors additionally uses `RESOLVE_NO_XDEV`; all opens use
`openat2` with `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS` and
`RESOLVE_NO_MAGICLINKS`. Missing required kernel semantics fail closed, with
no `openat` fallback. `statx` mount IDs, inode, device and type are mandatory.

Bounded `/proc/<getpid()>/mountinfo` parsing requires exactly one `/proc` and
one `/sys/fs/cgroup` full-root mount, with IDs/devices matching the pinned
anchors and the expected filesystem types. Additional cgroup2 mounts are
rejected. A subtree bind is rejected by mount root and by the required absence
of the non-root-only `cgroup.kill` and `cgroup.type` at the hierarchy root.
The helper compares the kernel-generated cgroup/user/PID namespace link texts
with proc PID1. `readlinkat` reads those texts without opening/following the
magic links. The supported deployment is the trusted PID1 host namespace
view, not a container's private PID1/proc/cgroup namespace arrangement.

Membership must be exactly one newline-terminated `0::/absolute-path` entry;
legacy entries, duplicates, extra lines, control/NUL bytes and truncation
fail. Every fixed ancestor and the execution leaf must be root-owned,
non-writable by group/other, on the pinned cgroup mount, and `domain` type.
Only metadata of their `cgroup.procs`/`cgroup.threads` is checked to exclude
delegation; their contents are never read or written.

Before credential reduction, the leaf's kill file is opened and validated.
A fresh directory lookup below the pinned root must match the original
inode/device/mount/type; a fresh metadata-only kill-file descriptor must match
the opened write descriptor. Those temporary lookup descriptors are closed.
After reduction, membership and mount view are read again, and the original
pinned directory and write FD are revalidated directly. Domain and leaf
membership-interface protection checks are repeated. No target directory or
kill file is reopened by path after reduction. A last membership read and
complete credential verification must pass before the sole terminal write.

These userspace rechecks cannot lock membership atomically against hostile
host root. The future trusted PID1 deployment must exclude process migration,
namespace/mount replacement and delegated execution ancestry: `Delegate=no`,
PID1-owned placement, no writable cgroup membership interfaces for the execution
identity, and no generic cgroup-management authority. An independently privileged
root/PID1 actor can still migrate the helper in the tiny userspace interval;
the helper does not defend against malicious host root. The helper
provides no migration mechanism itself. It must never be setuid or carry file
capabilities: an unprivileged caller cannot obtain cleanup privilege from it.

## Privilege, inputs and failure status

Real/effective/saved UID and GID must be zero. Inherited descriptors above 2
are closed; core dumps and ordinary ptrace access are disabled. No stdin,
stdout or stderr I/O is performed, and closed/replaced standard FDs cannot
select an operation. All paths are absolute or relative to pinned descriptors,
so cwd is irrelevant. C source reads no environment or configuration contents.

## Fixed execution-identity anchor

Future deployment must provision exactly
`/run/reconductor-exact/execution.identity`. This is a fixed inode ownership
anchor, not a configuration file: its contents, length and timestamps have no
semantic meaning and are never read. The target UID/GID come only from its
`st_uid`/`st_gid`. There is no hard-coded deployment UID/GID, build-time identity
macro, NSS/name-service lookup, or argv/environment/stdin/cwd/unit/capsule input
that selects an identity.

Before any exact execution is admitted, future trusted 4B4B2B
provisioning/admission MUST independently establish both
`anchor st_uid == provisioned reconductor-exact UID` and
`anchor st_gid == provisioned reconductor-exact GID` for this protected inode.
Execution MUST NOT start if either the anchor UID differs from the provisioned
execution UID or the anchor GID differs from the provisioned execution GID:
either mismatch MUST fail admission. This is a production admission
prerequisite, not advisory. The native helper validates the protected anchor
and uses its numeric ownership; trusted deployment/admission proves the binding
to the independently provisioned dedicated account. No NSS/account lookup is
added to the helper.

The supported `/run` view is the full-root tmpfs mount in the trusted system
runtime hierarchy. Its mount ID/device/type/root are checked through the same
bounded mountinfo validation as the kernel anchors. `/`, `/run` and
`/run/reconductor-exact` must be root:root directories, not group/other writable,
without setuid/setgid bits or symlink traversal. The anchor must be a regular
file with one hard link, nonzero UID and GID (also excluding the invalid all-ones
ID), no setuid/setgid bits, and no group/other write permission. Owner write is
allowed because contents are ignored; the execution identity cannot replace
the inode in its root-owned non-writable parent.

Descriptor-relative `openat2` traversal pins these objects with `O_PATH` and
`O_CLOEXEC`. The fixed `/run` mount crossing is checked explicitly; every lookup
below `/run` requires `RESOLVE_NO_XDEV` as well as BENEATH/NO_SYMLINKS/NO_MAGICLINKS.
The anchor must share its validated parent's runtime mount and device.
Missing statx fields, unsafe metadata, unexpected mounts, links or object types
fail closed. Immediately before credential reduction, the fixed hierarchy and
anchor pathname are resolved again and compared with the original pinned
identities; the pinned anchor's ownership/mode/link count are checked again.
Replacement or ownership changes reject the invocation. UID/GID remain immutable
local scalars afterward; the anchor is never reopened to choose new credentials.
Privileged deployment must not mutate this anchor during an invocation. No
anchor or account is created on the developer host by this slice.

## Permanent credential reduction

After all privileged namespace/path setup, the exact `cgroup.kill` FD is opened
**while privileged**, before credential reduction. The separate disposable
Fedora 44/cgroup v2/SELinux Enforcing proof selected disposition **B: DROP ROOT
BEFORE WRITE**, with repeated non-root writes and independent post-milestone
slot-zero confirmation. That experiment establishes the design decision; the
corrected production source and fixed anchor require a fresh disposable proof.

The production transition sequence is:

1. Limit effective/permitted capabilities to SETUID, SETGID and SETPCAP;
   inheritable is empty. Clear and verify supplementary groups and clear ambient.
2. Set and verify exact locked securebits: NOROOT, NO_SETUID_FIXUP and
   NO_CAP_AMBIENT_RAISE enabled and locked; KEEP_CAPS disabled and locked.
3. Drop and verify every supported bounding capability. Probe beyond the
   compile-time last capability without wrapping; fail closed if the version-3
   capability representation cannot cover a supported capability.
4. Clear SETPCAP. Set real/effective/saved GID to the anchor GID; immediately
   restore `PR_SET_DUMPABLE=0` and require `PR_GET_DUMPABLE==0`. Set fsgid to
   the anchor GID, immediately repeat that restoration/readback, verify fsgid,
   then clear SETGID.
5. Set real/effective/saved UID to the anchor UID; immediately restore/check
   nondumpability. Set fsuid to the anchor UID, immediately restore/check
   nondumpability again, then verify fsuid.
   NO_SETUID_FIXUP deliberately preserves the last transition capability until
   every restoration/readback above succeeds; KEEP_CAPS remains disabled.
6. Only then explicitly clear every effective/permitted/inheritable capability
   and independently verify E/P/I/ambient/bounding sets are empty. Set
   `PR_SET_NO_NEW_PRIVS=1` and require its readback to equal 1.
7. Verify all four UID/GID identities equal their non-root targets, zero
   supplementary groups, empty E/P/I/ambient/bounding sets, exact securebits and
   NoNewPrivs and nondumpability. Repeat the full verification immediately before
   the terminal write.

Credential syscalls can reset dumpability to `fs.suid_dumpable` internally;
userspace cannot make a credential syscall and the following `prctl` atomic.
The retained SETUID capability prevents ordinary capless matching-identity
processes from passing the capability ptrace check during that reset interval.
Dumpability is restored/read back immediately after every identity setter,
before any transition capability is discarded; it is already zero when the
last capability is cleared. `PR_SET_DUMPABLE(0)` and its readback require no
capability themselves. This ordering removes the capability-free dumpable
window; it does not claim the kernel can never transiently reset the flag.
Malicious privileged host actors remain outside this boundary.

The invalid all-ones fsuid/fsgid calls only query current filesystem identities;
they never request root restoration. After nondumpability restoration/readback,
capability clearing/verification and unprivileged NoNewPrivs setup, only read-only
validation, descriptor closing, unprivileged credential queries and the sole
already-open write remain. No SETUID/SETGID/SETPCAP-dependent operation occurs
after its capability is discarded. Unsupported/incompatible transitions fail
before any terminal write; no privilege reacquisition is attempted.

Fixed exit codes contain no paths, environment, credentials or action material:

| Code | Classification |
|---|---|
| 1 | invalid argument count |
| 2 | procfs validation/read failure |
| 3 | cgroup2/full hierarchy root failure |
| 4 | membership parse/read failure |
| 5 | wrong execution unit shape |
| 6 | filesystem/path/mount view/delegation validation failure |
| 7 | required openat2 semantics unavailable |
| 8 | namespace/membership/object identity mismatch |
| 9 | kill-file open/validation failure |
| 10 | terminal write failed or was short |
| 11 | unexpected cgroup type |
| 12 | privilege setup/reduction failure |
| 13 | descriptor/core-dump hygiene failure |
| 14 | terminal write returned to userspace (no success attestation) |
| 15 | fixed identity-anchor hierarchy/metadata/replacement failure |
| 16 | UID/GID/filesystem-identity transition failure |
| 17 | final credential/capability/securebits verification failure |

A successful write is expected to SIGKILL this helper and all members of its
execution cgroup, including descendants. There is no write retry or recovery.
Neither SIGKILL nor helper status attests cleanup. The persistent-slot observer
must independently establish the original invocation's final lifecycle
milestone followed by a fresh pinned-slot `populated=0`. Helper failure leaves
cleanup unconfirmed and must not cause replay/retry or capacity restoration.

## Independent builds and tests

No Go build imports, embeds or compiles these files. Run on Linux:

```
make -C internal/exactsupervision/native OUT=/tmp/reconductor-cleanup-test test
make -C internal/exactsupervision/native OUT=/tmp/reconductor-cleanup-test sanitize
make -C internal/exactsupervision/native OUT=/tmp/reconductor-cleanup-test analyze
make -C internal/exactsupervision/native OUT=/tmp/reconductor-cleanup-test static
```

The normal artifact is explicitly named `exact-cleanup-dev`: a dynamic PIE
for compiler diagnostics only, **not a production artifact**. This host lacks
static libc. The eventual release must use the `static` target in a trusted
builder with static libc; it has no dynamic fallback and checks for absence
of ELF interpreter and dynamic dependencies. Static/static-PIE linkage removes
reliance on a dynamic ELF interpreter/shared-library loader, but the linked C
runtime can still inspect environment-controlled startup state before `main()`.
Static glibc processes startup tunables, including `GLIBC_TUNABLES`; static
linkage is not itself an environment-sanitization boundary. No libc or toolchain
is vendored and no host-global tools/packages are installed here.
Final release reproducibility, provenance, root ownership, non-writable fixed
installation and mode without setuid/file capabilities remain deployment
verification requirements. No install target is provided.

The trusted deployment must establish a fixed trusted environment **before
exec**, with no caller-controlled variables or untrusted inherited environment.
For the initial deployment, prefer an **empty environment** unless a specific
variable is later proven necessary. Inheritance of `GLIBC_TUNABLES`,
`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `MALLOC_*`, locale-path overrides,
and other loader/libc tuning variables is forbidden. This list is not exhaustive:
the boundary is no untrusted inherited environment, not a variable denylist.

4B4B2B must configure the fixed `ExecStopPost` helper so PID1/systemd establishes
this environment in its execution setup before the helper image starts.
`clearenv()`, `unsetenv()`, or `environ` manipulation inside `cleanup.c` would
occur too late to establish pre-main safety. The startup contract combines the
reviewed static artifact, trusted pre-exec environment, fixed root-owned
artifact/path, and reviewed execution credentials; static linkage alone does
not establish it. This slice adds no systemd unit.

Tests exercise only pure membership/path/mount/identity/domain validators,
fixed identity-anchor metadata, runtime-mount validation and bounded malformed
bytes, plus rejection of an extra argument before
any host lookup. Sanitizers never execute the helper's terminal path. Do not
run the helper with no arguments on the developer host, even as a smoke test.
This host also lacks the ASan/UBSan runtime libraries: the sanitizer target is
provided but cannot link here. Repeat it in an equipped trusted builder before
deployment; no new global tool or package is installed by this slice.

## Deferred proof and integration

A fresh explicitly disposable Fedora re-proof must provision the fixed protected
identity anchor with a dedicated non-root account's ownership (no fixed numeric
UID/GID), build the corrected static artifact
and run it only in temporary exact-shaped, root-owned, nondelegated domain
cgroups. Verify capability/securebits/group state at the write boundary,
stock SELinux Enforcing access, normal-exit and main-SIGKILL survivors,
RuntimeMaxSec/startup failure, expected self-kill and independently observed
post-milestone persistent-slot emptiness. Also exercise missing interfaces,
bad mount/namespace/runtime-anchor views, missing/unsafe/replaced/multi-link
identity anchors, denied writes, type/membership/object changes and
pre-write failures without classifying helper status as attestation. No real
cgroup write, VM creation or production host mutation belongs to this slice.

Later 4B4B2B work must specify/verify fixed PID1-owned units and exclusive
placement/start authority, the protected fixed identity-anchor provisioning,
the helper's trusted static installation, lifecycle
and pinned persistent-slot observation, and private backend promotion into
the frozen supervision contract. Deployment must guarantee a fixed protected
production artifact and ancestors, no setuid/file capabilities, a fixed
`ExecStopPost` path, the trusted pre-exec environment above, and stdin/stdout/
stderr mapped to inert/null endpoints; the helper needs no standard streams.
It must also guarantee `Delegate=no`, PID1-owned placement, no cgroup-management
authority for the execution identity, fixed expected procfs/full-root cgroup2
views, and SELinux Enforcing compatibility. Cleanup attestation remains the
independent final-invocation milestone plus fresh persistent-slot `populated=0`.
This slice introduces no units, D-Bus,
systemctl, polkit, native supervisor, backend, Runner or application wiring,
and chooses no production numerical resource limits.
