// Package exacthandoff holds a private reverse Unix handoff foundation.
// It has no public constructor, Runner, service, or production integration.
// Only an invocation holding EncodedExecution may accept idle peer capacity;
// connecting or supplying capsule bytes cannot select work.
//
// SO_PEERCRED identifies capacity credentials, not permit consumption or systemd
// provenance. Current-identity tests do not establish exclusive service identity.
// Future provisioning must supply a dedicated UID/GID used only by the exact
// execution service, a root-managed protected socket path and fixed owner/mode,
// Accept=no socket activation and fixed listener delivery to the eventual Broker
// application. This package does not choose that application. Its listener must
// be exclusively owned: no other acceptor or deadline writer may share it.
//
// A claimed connection is permanently retired after one attempt, including a
// failure before emission. No authority is restored, no capsule is persisted,
// and restart loses in-flight state. A reconnect is empty future capacity, never
// recovery. No SCM_RIGHTS or other ancillary messages belong to the protocol.
//
// This socket is trusted coordinator IPC and must never enter a sandbox as
// stdin, stdout, an extra/runtime/setup FD or a mounted path. Later containment
// must copy bounded material to fresh sandbox stdin and copy bounded output back
// from fresh stdout. Production Runner promotion remains blocked on dedicated
// identity provisioning, containment, resource supervision and promotion review.
package exacthandoff
