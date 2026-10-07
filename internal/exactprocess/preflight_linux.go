//go:build linux

package exactprocess

import (
	"context"
	"fmt"
	"strings"
)

const preflightHelper = "/usr/libexec/reconductor-exact-preflight"

// Capabilities describes only harmless preflight, not complete containment,
// seccomp enforcement, aggregate resources, or production lifecycle readiness.
type Capabilities struct {
	StrictNamespaces             bool
	NestedUserNamespacesDisabled bool
	SeccompOption                bool
	CgroupNamespaceOption        bool // informational, deliberately not mandatory
}

// Preflight invokes only the fixed native preflight helper. No helper is
// installed by this slice: absent provisioning fails closed. Linux tests build
// the same source outside the repository and genuinely exercise the host.
func Preflight(ctx context.Context) (Capabilities, error) {
	return preflight(ctx, preflightHelper)
}

func preflight(ctx context.Context, helper string) (Capabilities, error) {
	required := []string{"--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts", "--disable-userns", "--assert-userns-disabled", "--clearenv", "--cap-drop", "--seccomp"}
	flags := make(map[string]bool)
	_, err := transact(ctx, launch{helper: helper, operation: "--help"}, nil, 64*1024, func(b []byte) error {
		var err error
		flags, err = requiredOptions(b, required)
		return err
	})
	if err != nil {
		return Capabilities{}, fmt.Errorf("%w: options: %w", ErrUnavailable, err)
	}
	_, err = transact(ctx, launch{helper: helper, operation: "--namespace-probe"}, nil, 0, func(b []byte) error {
		if len(b) != 0 {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return Capabilities{}, fmt.Errorf("%w: strict namespace probe: %w", ErrUnavailable, err)
	}
	return Capabilities{StrictNamespaces: true, NestedUserNamespacesDisabled: true, SeccompOption: true, CgroupNamespaceOption: flags["--unshare-cgroup"]}, nil
}

func requiredOptions(help []byte, required []string) (map[string]bool, error) {
	flags := make(map[string]bool)
	for _, line := range strings.Split(string(help), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			flags[fields[0]] = true
		}
	}
	for _, flag := range required {
		if !flags[flag] {
			return nil, fmt.Errorf("%w: required option %s", ErrUnavailable, flag)
		}
	}
	return flags, nil
}
