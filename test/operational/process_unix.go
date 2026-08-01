//go:build operational && !windows

package operational

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
)

func configureOwnedSchedulerProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateOwnedSchedulerTree(_ context.Context, pid int) error {
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("kill owned scheduler process group %d: %w", pid, err)
	}
	return nil
}
