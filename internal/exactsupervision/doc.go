// Package exactsupervision defines pure, unpromoted serial supervision contracts.
// It has no host access, launch authority, Runner, or production integration.
//
// The fixed persistent slot holds one ephemeral execution service containing the
// coordinator, launcher, Bubblewrap monitor/reaper, runtime and descendants.
// PID1 and the trusted observer/capacity owner remain outside the slot. A future
// fixed root-owned helper will atomically kill only its own execution cgroup;
// this package implements neither that helper nor systemd operations.
//
// Cleanup requires the original invocation's final lifecycle milestone after
// stop-post, with no later command permitted, followed by a fresh zero read of
// the pinned persistent slot. An ephemeral child's disappearance, UnitRemoved,
// Result, helper SIGKILL, or an earlier zero cannot establish cleanup.
//
// Public identities and LifecycleFacts/PopulationFacts describe candidates.
// They neither establish ownership nor mint trusted observations. Capacity
// construction, observation promotion, final-command completion and sequence
// issuance are package-private. Future Linux observation/backend code belongs
// in this same package and must verify deployment policy, exclusive host-slot
// ownership, the bound invocation and pinned measurements before promotion.
// The pure owner identity does not itself acquire exclusive host ownership.
//
// Each private owner binds one Capacity and issues one shared monotonically
// increasing sequence for lifecycle and population evidence at observation
// time. Evidence binds an immutable opaque owner generation as well as the
// exact boot/slot/invocation. Importers cannot select order or final-command
// completion. Re-labeling stale measurements is forbidden. Sequence exhaustion,
// ownership/observer loss, or evidence mismatch permanently quarantines both
// capacity and issuance. Synthetic promotion exists only in same-package tests.
//
// Capacity copies share its locked state; instance history lasts for that
// Capacity's lifetime. Creating another owner is not recovery. No failure
// restores a permit, replays material, restarts a unit, reconstructs an action
// or authorizes a retry. Production authorization, durable recovery and
// multiple slots remain deferred.
//
// CleanupOutcome establishes cleanup only. It does not claim that a sandbox
// result was validated or that execution completion is accepted. Later
// integration must require an upstream validated result together with the
// matching cleanup attestation before accepting completion.
package exactsupervision
