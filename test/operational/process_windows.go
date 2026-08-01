//go:build operational && windows

package operational

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func configureOwnedSchedulerProcess(_ *exec.Cmd) {}

func terminateOwnedSchedulerTree(ctx context.Context, pid int) error {
	output, err := exec.CommandContext(ctx, "taskkill.exe", "/PID", strconv.Itoa(pid), "/T", "/F").CombinedOutput()
	if err != nil {
		return fmt.Errorf("taskkill owned scheduler PID %d: %w (%s)", pid, err, strings.TrimSpace(string(output)))
	}
	return nil
}
