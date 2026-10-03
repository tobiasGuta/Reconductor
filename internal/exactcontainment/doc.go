// Package exactcontainment is the unpromoted Linux/x86_64 offline containment
// foundation. It grants no authority and implements no exactsandbox.Runner.
// Its fixed native profile never receives options from execution material.
// Containment and process-local timeout/cancellation assume the trusted execution
// supervisor remains present. Bubblewrap's --die-with-parent is best-effort
// defense in depth, not authoritative cleanup: abrupt coordinator death during
// its pre-binding setup interval can leave a pre-runtime namespace child alive.
// The observed setup-child survival is not evidence of sandbox escape; survival
// of an already-executing hostile runtime was not demonstrated. This package
// guarantees neither cleanup at every supervisor-death setup point nor aggregate
// descendant, whole-cgroup, or supervisor-crash resource cleanup. Production
// Runner promotion requires 4B4A containment PASS, 4B4B lifecycle/resource
// supervision PASS and combined review. 4B4B must provide trusted external
// whole-unit ownership independent of Bubblewrap's PR_SET_PDEATHSIG behavior,
// using systemd/cgroup-v2 or an equivalently reviewed external supervisor.
package exactcontainment

import "errors"

var ErrUnavailable = errors.New("mandatory exact containment unavailable")
