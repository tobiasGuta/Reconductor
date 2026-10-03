// Package exactactivation defines the fixed Linux worker/dedicated-peer
// deployment foundation. It does not initiate exact actions, accept peers,
// construct a Broker, or implement a sandbox Runner.
//
// AcquireWorkerListener is for a future fixed worker startup, before loading
// application environment or spawning any provider checks. It requires the
// standard systemd descriptor 3 and the fixed deployment identity; there is no
// optional activation or caller-selected descriptor/path. The returned owner
// exposes only Close. Exclusive ownership means the worker is the sole
// application acceptor/deadline writer; PID1 retains its socket-unit copy.
// Acquisition allows one attempt per process, consumed even on failure, with
// repeated/concurrent callers rejected before inspecting activation inputs.
// Optional LISTEN_PIDFDID is strictly validated against this process's pidfd
// inode identity; a supplied identity is never downgraded to PID-only checks.
//
// These checks validate deployment inputs, not cryptographic PID1 provenance.
// Root-managed service definitions, accounts, paths and artifacts are the
// prerequisite trust boundary. SO_PEERCRED alone cannot establish provisioning
// or supplementary-group isolation. See README.md for the deployment contract.
package exactactivation
