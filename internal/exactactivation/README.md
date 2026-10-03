# Fixed worker / dedicated peer deployment foundation (4B4P2)

This package owns deployment validation only. There is no exact initiation,
Broker call, provider registration, handoff invocation, sandbox Runner, target
traffic, or containment/resource-supervision backend. `cmd/worker` is unchanged.
The ordinary worker is **not yet activation-integrated**. Do not install or
enable the conceptual units below with the current executable. No peer service
binary or installable systemd units are introduced in this slice.

## Initial deployment contract

Support one Linux host, one fixed worker authority application, one dedicated
peer identity, and serial exact execution. Additional workers must not claim
exact work without separately reviewed routing. Scheduler, direct workflow/run
retry, console, and generic registry paths remain outside exact execution.

The worker role is fixed; its final UID/GID is not selected here. Before migration
or deployment, verify configuration, artifact-store permissions, publisher
locking/durability, provider binaries/configuration/secrets, and workflow state
permissions under the actual service account. Do not create a symmetric worker
account merely because the peer has one. Do not run the worker as the peer UID,
give it the peer group, or run it as the operator's interactive identity.

## Fixed listener intake API

`AcquireWorkerListener()` is Linux-only and always requires activation. It uses
only standard descriptor 3 (`SD_LISTEN_FDS_START`); there is no FD/path argument,
CLI selector, optional activation flag, or FD scan. Standard environment:

* `LISTEN_PID`: canonical decimal PID matching this process.
* `LISTEN_FDS`: exactly `1`.
* `LISTEN_FDNAMES`: exactly `reconductor-exact-control`.
* `LISTEN_PIDFDID`: optional. If present, require canonical unsigned 64-bit
  decimal and compare against this process's independently opened pidfd inode
  on Linux pidfs. Present-empty, malformed, mismatched or unverifiable identity
  rejects; there is no fallback to PID-only checks when it is supplied. Leading
  zeroes, signs and whitespace reject. This is intentionally stricter than
  libsystemd's general integer parser; systemd's producer emits canonical decimal.

The public adapter permits exactly one acquisition attempt per process. An atomic
claim occurs before any environment read; repeated/concurrent losers reject
without reading/clearing environment, touching FD 3 or invoking lookup. Failure
consumes the attempt permanently: repopulating environment cannot retry it.
The winner consumes these variables, including on rejection. After syntax
validation, it sets and verifies listener `FD_CLOEXEC`, verifies any supplied
PIDFD identity using a temporary CLOEXEC pidfd that is closed on every path,
then performs account lookup and filesystem checks. A future worker startup must
call it during trusted early startup **before** `.env`
loading, configuration processing and child-spawning provider checks; any error
must stop startup. Keep the returned owner alive until shutdown. No production
call site is added because foundation proofs do not require changing worker
startup. Its only exported operation is `Close`; no listener/FD accessor, Accept,
deadline, material, or execution API is provided.

Validate AF_UNIX, SOCK_STREAM, SO_ACCEPTCONN=1, and the exact getsockname pathname
`/run/reconductor-exact/control.sock`. Require a non-symlink socket node owned by
UID 0 and the resolved dedicated primary GID, with exact mode 0660. Check every
parent through `/`: directory, UID 0, no group/other write, no symlink. Production
uses the fixed account names and fixed path. Only package-private test seams
substitute temporary sockets, an unprivileged owner and a temporary ancestor.

Socket filesystem nodes and socket-FD sockfs inodes are different; their inode
numbers must not be compared. These checks assume root-managed deployment with
no concurrent privileged path replacement. They do not prove PID1 provenance
from environment text alone. No unprivileged account may replace the path;
privileged administrators and the service definitions are trusted.

"Exclusive" means the fixed worker is the only **application** acceptor and
deadline writer. PID1 retains its descriptor copy. Closing this owner only closes
the application's FD: no unlink, chmod/chown, rebind, replacement, or socket
shutdown. Startup does not accept even a queued peer and sends no material.

## Conceptual fixed units — not installed or runnable artifacts

After worker integration and permission compatibility verification, deployment
must supply these fixed definitions; no transient units or arbitrary D-Bus unit
construction are allowed:

| Definition | Required relationship |
| --- | --- |
| `reconductor-exact.socket` | `ListenStream=/run/reconductor-exact/control.sock`, `Accept=no`, `Service=reconductor-worker.service`, `FileDescriptorName=reconductor-exact-control`, `SocketUser=root`, `SocketGroup=reconductor-exact`, `SocketMode=0660`. |
| Protected directory | Deployment/PID1 creates `/run/reconductor-exact`, root:root 0755, with protected ancestors. Neither operator, worker nor peer may create/replace/chmod it. |
| `reconductor-worker.service` | Requires/orders after the fixed socket; receives its sole activation FD; runs a fixed root-owned worker binary with a separately verified authority UID/GID and its required Store/Redis/artifact dependencies. |
| `reconductor-exact-peer.service` | Fixed root-owned peer binary, `User=reconductor-exact`, `Group=reconductor-exact`, no additional unit groups; starts after the socket and initiates an empty-handed connection. No worker environment file or authority credentials. |

`Accept=no` does not serialize application work. Future integration must
serialize before Broker admission; rejecting an already-consumed invocation as
busy is insufficient. Connections only supply capacity. Activation/restart must
not select an action, reconstruct dispatch intent, regenerate material, or resend
an ambiguous handoff. Queued capacity is not replay authority.

See upstream [systemd.socket](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html),
[sd_listen_fds](https://www.freedesktop.org/software/systemd/man/latest/sd_listen_fds.html),
and [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).

## Dedicated identity verification

Provision `reconductor-exact` with the same-named dedicated primary group,
nonzero stable UID/GID, locked password and non-login shell. No wheel, docker,
operator or unrelated supplementary memberships; no operator home/desktop
authority. Reserve this identity for the fixed peer service alone.

`VerifyPeerCredentials()` resolves those account names, checks the account's
configured primary group, then reads actual effective UID/GID and `getgroups()`.
It rejects every different supplementary GID, including root's GID, without a
name-based dangerous-group blacklist. Empty groups or repeated copies of the
dedicated primary GID are harmless and accepted. Test UID/GIDs are synthetic;
they do not demonstrate real cross-identity provisioning.

`User=`/`Group=` select credentials after correct provisioning. An empty
`SupplementaryGroups=` only resets unit-added groups; account-database groups
still apply. Verify the actual process. This helper is not a login-lock,
filesystem-access, capabilities, saved-ID or containment preflight; those remain
deployment/containment requirements rather than being inferred from an EUID.

## Coordinator environment, credentials and FDs

Construct the coordinator environment using `PeerEnvironment()` from scratch:
`LANG=C`, `LC_ALL=C`, `TZ=UTC`. `VerifyPeerEnvironment` accepts precisely these
entries once each, with their fixed values. All other entries are rejected,
including empty authority values, malformed entries, duplicate variables, HOME,
desktop/session variables, activation variables, DB/Redis/artifact/approval
credentials and arbitrary future provider secrets. Error text contains neither
variable names nor values. Pass the existing `cfg.Logging.SecretNames` mechanism
as the optional configured-name list; configured secrets also override otherwise
allowed names. The closed allowlist covers new credential names automatically.

No `.env` loading in the peer; no inherited worker environment. Coordinator and
future sandbox environments are separate. This slice chooses no sandbox
environment beyond preserving the previously frozen future `PWD=/` requirement.

The future peer service must start independently under PID1, not as a worker
child with inherited authority. Its initial FD allowlist is explicitly provisioned
stdin/stdout/stderr (null/log channels, not operator terminals) and its newly
opened worker control connection; add no other descriptors without review. No
worker listener, DB/Redis connection, artifact/provider FD, desktop/session FD,
SCM_RIGHTS import, or inherited activation FD. Set control-connection CLOEXEC
before any later backend exec. Control IPC must never enter the sandbox as an
FD, stdio channel, or mounted path. Runtime peer-FD auditing and the future
connection/backend launcher remain deferred; this package does not claim to
enforce their absence merely by validating environment variables.

## Fixed artifact contract

The worker/peer binaries, Bubblewrap/backend helper, fixed runtime and seccomp
policy must eventually be root-owned, non-writable by both service identities,
and located under non-writable protected parent directories. PID1 must execute
fixed trusted binaries. Future runtime/policy loading must open, validate and pin
the trusted artifact identity through use, including required runtime dependencies.
Do not inherit the offline test fixture's mutable-path execution assumption.
No runtime/backend/policy artifact or packaging installation is implemented here.

## Verification and deferred disposable Fedora integration

Ordinary tests create only temporary Unix sockets, inspect synthetic credential
data, and exec the test binary as a harmless probe. The CLOEXEC test first proves
a deliberately non-CLOEXEC FD survives exec, then proves intake removes it. A
queued peer receives zero bytes and remains available to a test-only accept.
Tests need no root, account creation or systemd installation. A restricted
execution sandbox may separately prohibit Unix socket setup; this is unrelated
to Unix account privileges.

No privileged harness is added: there is not yet an activation-integrated worker
or peer diagnostic binary to deploy. Before claiming genuine deployment proof,
use a disposable Fedora VM and a separately reviewed harness to:

1. Provision the locked dedicated test identity and its primary-only group
   memberships; reserve it exclusively for the fixed service.
2. Build a diagnostic peer using `VerifyPeerCredentials` and
   `VerifyPeerEnvironment`, plus an activation-integrated worker diagnostic
   with no Broker/Runner initiation. Install only fixed root-owned artifacts.
3. Supply fixed units as above with the verified worker identity. Run
   `systemd-analyze verify` on their explicit paths, `systemctl daemon-reload`,
   and `systemctl start reconductor-exact.socket`.
4. Check the protected directory/socket using `stat`, `namei -l`, and ACL
   inspection. Start the fixed diagnostic peer service with `systemctl start
   reconductor-exact-peer.service`; verify the activated worker PID/FD and
   runtime credentials from its diagnostics and `/proc/<pid>/status`.
5. Verify wrong UID/GID and an additional supplementary group are rejected;
   primary-GID duplicates are accepted. Check SO_PEERCRED separately from group
   verification. Inspect environment/FD allowlists without printing secrets.
6. Connect queued empty capacity and prove no startup Accept/material release;
   later private one-use handoff tests must preserve retirement/no-resend across
   failures and restarts, with no production Runner.

Before 4B4A deployment claims: review this foundation, integrate early worker
intake, establish actual identity/permissions and root-managed fixed units,
implement the restricted peer diagnostic/coordinator FD boundary, and pass real
Fedora activation/cross-identity tests. Containment, resource supervision and
production Runner promotion remain separately gated. Original-attempt approval
continuation, exact queue/retry fencing, scheduled/direct routing and production
Broker initiation remain later exact-integration work, not prerequisites this
foundation silently implements.
