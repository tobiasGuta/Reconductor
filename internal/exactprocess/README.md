# Slice 4B3: pre-production process/IPC foundation

This package implements no `exactsandbox.Runner`. There is no broker, scheduler,
worker, console, or production command caller. `exchange` is private and used
only by Linux tests. The offline runtime is under `testdata`, builds only during
tests, and performs no networking, shell execution, or child-program execution.
It validates the existing capsule and returns the existing result. Behavioral
faults are test-only compile-time launcher constants, never capsule fields.

The only public operation is `Preflight(ctx)`. It expects a trusted native
artifact at `/usr/libexec/reconductor-exact-preflight`; this slice deliberately
does not install it or provide a production build/dispatch command. Missing
provisioning fails closed. The tests compile the same native source into a
private temporary directory and exercise `preflight` with that artifact. Future
packaging belongs to the complete isolated backend, not an unsandboxed Runner.

## Trusted launch boundary

`openHelper` requires a clean absolute path, refuses a final symlink, validates
regular/executable/non-set-ID/non-group-or-world-writable ownership and ELF
magic, and pins the inode. FIFO opens cannot block artifact validation, and
scripts are rejected. Go invokes `/proc/self/fd/3` with that explicit descriptor, empty
environment, fixed working directory `/`, pipe stdin/stdout, and discarded
stderr. Production helper configuration is fixed; it is not a caller command
API. Deployment must protect the helper directory and all parent directories.

The native launcher immediately applies child-side `close_range(3, UINT_MAX, 0)`.
Failure aborts; there is no CLOEXEC-only or permissive fallback. No Go parent FD
table is mass-closed. Only descriptors 0/1/2 survive to the fixed target. The
helper also clears effective/permitted/inheritable capabilities, sets
no-new-privileges, disables core dumps, and arms parent-death
SIGKILL with a parent check. Go locks the creating OS thread through cleanup
because Linux parent-death signaling tracks that thread's lifetime.

In its default build the C helper can only run two fixed preflight operations:
bounded `/usr/bin/bwrap --help`, or strict disposable namespaces running
`/usr/bin/true`. It pins and validates root-owned bubblewrap before execution.
It rejects root callers and drops all capability sets before unprivileged proof. There is
no production exact runtime branch. Test builds alone compile in a
fixed offline executable and fixed behavioral argument. The descendant fixture
briefly uses FD 4 to report a PID and closes it before runtime execution.

## IPC and lifecycle

Input is copied within the 40,960-byte bound and validated using the frozen
grammar and digest before launch. Original canonical bytes are written fully,
then stdin is closed. Writes handle partial progress. Reads run concurrently,
require EOF, and retain at most the declared limit plus one overflow byte.
Exactly 256 bytes pass the transport ceiling but still require valid frozen
result grammar; this grammar cannot be padded into a different valid protocol.
Parent-side validation independently checks the result and expected digest.
No output is accepted unless input writing, output EOF, and successful process
exit all complete. Child stderr is discarded, not accumulated.

Caller cancellation and an independent five-second ceiling terminate the
process group and close pipes. `waitid(WNOWAIT)` observes exit without reaping
the leader; group termination happens before `Cmd.Wait` releases its PID.
This avoids signaling a subsequently reused process-group ID. Cleanup joins
the writer, reader, exit observer, and direct-child wait before returning.
Normal leader exit also terminates remaining group members, including those
holding stdout open.

Test-only instrumentation shrinks pipes to one page so the large valid capsule
necessarily encounters input backpressure. The same tests cover early output
and cancellation while writes are blocked, independent of host pipe defaults.

This is **not complete hostile-process supervision**. Tests prove cleanup for
the fixed fixture and descendants that remain in its group. A malicious process
can change session/group membership; parent-death signaling does not recursively
kill a tree. Kernel-uninterruptible tasks can delay wait completion. Production
requires a PID-namespace/cgroup or equivalent external whole-sandbox owner,
aggregate resources, and independent owner-death handling. No systemd-only
supervision contract is introduced here.

## Capability preflight

Require actual help entries for strict user/PID/network/IPC/UTS options,
disable/assert user namespaces, clear environment, capability dropping, and
seccomp loading. Version strings, descriptive mentions, and `*-try` flags do
not establish support. Then genuinely run the strict namespace flags with
disable/assert, empty environment, no capabilities, new session, and no host
network. A privileged caller is rejected as evidence of unprivileged support.

The disposable root exposes only `/usr/bin/true` and its exact Fedora x86_64
loader/libc files. No home, checkout, `/run`, host proc/sys/device tree, socket,
target traffic, or persistent host configuration is involved. Disable-userns
changes only its disposable namespace's limit. Other runtime layouts fail
closed and need an explicitly reviewed portability change.

`--unshare-cgroup` is informational, not required. Aggregate cgroup-v2 resource
containment remains mandatory for the future production backend. Preflight
does not install or prove a seccomp filter, resource controller, or complete
production containment profile.

## Verification

Linux tests require `/usr/bin/go` and `/usr/bin/cc` to build temporary fixtures.
No package installation occurs. Native builds use warnings as errors. FD tests
deliberately create inheritable file/directory/socket/pipe sentinels and include
a Go-exec-only negative control. Sensitive environment tests use fake values.

`RECONDUCTOR_REQUIRE_PREFLIGHT=1 go test -count=1 ./internal/exactprocess`
must genuinely pass on the designated Fedora host; unsupported ordinary hosts
may explicitly skip that one capability test. Use the same setting for race
verification. Codex's command sandbox blocks this network-namespace operation,
so designated verification must run on the actual host as the same non-root
user. A skipped probe is not readiness evidence.

Frozen Slices 1–4B remain unchanged. The next production Runner must be the
complete Bubblewrap backend, including mandatory seccomp, FD/environment
isolation, aggregate resource limits, and whole-sandbox cleanup.
