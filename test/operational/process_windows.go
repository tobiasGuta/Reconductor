//go:build operational && windows

package operational

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	processQueryLimitedInformation = 0x1000
	processSynchronize             = 0x00100000
	waitObject0                    = 0
	waitTimeout                    = 258
	errorInvalidParameter          = syscall.Errno(87)
)

var queryFullProcessImageNameW = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW")

func ownedSchedulerPlatformSupported() error { return nil }

func configureOwnedSchedulerProcess(_ *exec.Cmd) error { return nil }

func inspectSchedulerProcess(pid int) (schedulerProcessIdentity, error) {
	handle, identity, err := openSchedulerProcessIdentity(pid)
	if handle != 0 {
		_ = syscall.CloseHandle(handle)
	}
	return identity, err
}

func terminateOwnedSchedulerTree(ctx context.Context, generation *schedulerGeneration) error {
	if generation == nil || generation.PID <= 0 {
		return errors.New("refusing to terminate an invalid scheduler generation")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	handle, live, err := openSchedulerProcessIdentity(generation.PID)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(handle)
	if !generation.ownsExecutable(generation.Executable, live) {
		return fmt.Errorf("refusing to terminate scheduler generation %d because live PID %d identity does not match executable %q and token %q", generation.Number, generation.PID, generation.Executable, generation.Identity)
	}

	// Keep the verified process handle open through taskkill. Windows does not
	// reuse a PID while a handle to that process object remains open, closing the
	// identity-check-to-tree-termination reuse window without a Job Object.
	output, err := exec.CommandContext(ctx, "taskkill.exe", "/PID", strconv.Itoa(generation.PID), "/T", "/F").CombinedOutput()
	if err != nil {
		return fmt.Errorf("taskkill owned scheduler PID %d: %w (%s)", generation.PID, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func openSchedulerProcessIdentity(pid int) (syscall.Handle, schedulerProcessIdentity, error) {
	if pid <= 0 {
		return 0, schedulerProcessIdentity{}, fmt.Errorf("invalid scheduler PID %d", pid)
	}
	handle, err := syscall.OpenProcess(processQueryLimitedInformation|processSynchronize, false, uint32(pid))
	if err != nil {
		if errors.Is(err, errorInvalidParameter) {
			return 0, schedulerProcessIdentity{}, errSchedulerProcessExited
		}
		return 0, schedulerProcessIdentity{}, fmt.Errorf("open scheduler PID %d for identity verification: %w", pid, err)
	}
	fail := func(cause error) (syscall.Handle, schedulerProcessIdentity, error) {
		_ = syscall.CloseHandle(handle)
		return 0, schedulerProcessIdentity{}, cause
	}

	waitResult, err := syscall.WaitForSingleObject(handle, 0)
	if err != nil {
		return fail(fmt.Errorf("query scheduler PID %d wait state: %w", pid, err))
	}
	if waitResult == waitObject0 {
		return fail(errSchedulerProcessExited)
	}
	if waitResult != waitTimeout {
		return fail(fmt.Errorf("query scheduler PID %d returned unexpected wait state %d", pid, waitResult))
	}

	pathBuffer := make([]uint16, 32768)
	pathLength := uint32(len(pathBuffer))
	result, _, callErr := queryFullProcessImageNameW.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&pathBuffer[0])),
		uintptr(unsafe.Pointer(&pathLength)),
	)
	if result == 0 {
		if callErr == syscall.Errno(0) {
			callErr = errors.New("QueryFullProcessImageNameW failed")
		}
		return fail(fmt.Errorf("query scheduler PID %d executable: %w", pid, callErr))
	}

	var creation, exit, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return fail(fmt.Errorf("query scheduler PID %d start time: %w", pid, err))
	}
	rawCreation := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	identity := schedulerProcessIdentity{
		PID:        pid,
		Executable: syscall.UTF16ToString(pathBuffer[:pathLength]),
		Token:      strconv.FormatUint(rawCreation, 10),
		StartedAt:  time.Unix(0, creation.Nanoseconds()).UTC(),
	}
	return handle, identity, nil
}
