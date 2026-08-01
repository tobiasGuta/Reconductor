//go:build operational && !windows

package operational

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func ownedSchedulerPlatformSupported() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("operational scheduler process ownership is unsupported on %s", runtime.GOOS)
	}
	if !reflect.ValueOf(&syscall.SysProcAttr{}).Elem().FieldByName("Setpgid").IsValid() {
		return errors.New("operational scheduler process groups are unavailable")
	}
	return nil
}

func configureOwnedSchedulerProcess(cmd *exec.Cmd) error {
	attributes := &syscall.SysProcAttr{}
	setProcessGroup := reflect.ValueOf(attributes).Elem().FieldByName("Setpgid")
	if !setProcessGroup.IsValid() || !setProcessGroup.CanSet() || setProcessGroup.Kind() != reflect.Bool {
		return errors.New("configure scheduler process group: Setpgid is unavailable")
	}
	setProcessGroup.SetBool(true)
	cmd.SysProcAttr = attributes
	return nil
}

func inspectSchedulerProcess(pid int) (schedulerProcessIdentity, error) {
	if runtime.GOOS != "linux" {
		return schedulerProcessIdentity{}, fmt.Errorf("inspect scheduler process: unsupported operating system %s", runtime.GOOS)
	}
	if pid <= 1 {
		return schedulerProcessIdentity{}, fmt.Errorf("invalid scheduler PID %d", pid)
	}
	firstToken, err := linuxProcessStartToken(pid)
	if err != nil {
		return schedulerProcessIdentity{}, err
	}
	executable, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if errors.Is(err, os.ErrNotExist) {
		return schedulerProcessIdentity{}, errSchedulerProcessExited
	}
	if err != nil {
		return schedulerProcessIdentity{}, fmt.Errorf("read scheduler PID %d executable: %w", pid, err)
	}
	secondToken, err := linuxProcessStartToken(pid)
	if err != nil {
		return schedulerProcessIdentity{}, err
	}
	if firstToken != secondToken {
		return schedulerProcessIdentity{}, fmt.Errorf("scheduler PID %d changed identity while inspected", pid)
	}
	return schedulerProcessIdentity{PID: pid, Executable: executable, Token: firstToken}, nil
}

func terminateOwnedSchedulerTree(ctx context.Context, generation *schedulerGeneration) error {
	if generation == nil || generation.PID <= 1 {
		return errors.New("refusing to terminate an invalid scheduler generation")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	live, err := inspectSchedulerProcess(generation.PID)
	if err != nil {
		return err
	}
	if !generation.ownsExecutable(generation.Executable, live) {
		return fmt.Errorf("refusing to terminate scheduler generation %d because live PID %d identity does not match executable %q and token %q", generation.Number, generation.PID, generation.Executable, generation.Identity)
	}
	stat, err := linuxProcessStat(generation.PID)
	if err != nil {
		return fmt.Errorf("inspect scheduler PID %d process group: %w", generation.PID, err)
	}
	if stat.StartToken != generation.Identity {
		return fmt.Errorf("refusing to terminate scheduler generation %d because PID %d changed identity before process-group termination", generation.Number, generation.PID)
	}
	groupID := stat.ProcessGroup
	if groupID != generation.PID {
		return fmt.Errorf("refusing to terminate scheduler PID %d because process group is %d", generation.PID, groupID)
	}
	runnerStat, err := linuxProcessStat(os.Getpid())
	if err != nil {
		return fmt.Errorf("inspect test runner process group: %w", err)
	}
	if groupID == runnerStat.ProcessGroup || groupID == os.Getpid() {
		return fmt.Errorf("refusing to target test runner process group %d", groupID)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	group, err := os.FindProcess(-groupID)
	if err != nil {
		return fmt.Errorf("open owned scheduler process group %d: %w", groupID, err)
	}
	if err := group.Signal(os.Kill); errors.Is(err, os.ErrProcessDone) {
		return errSchedulerProcessExited
	} else if err != nil {
		return fmt.Errorf("kill owned scheduler process group %d: %w", groupID, err)
	}
	return nil
}

func linuxProcessStartToken(pid int) (string, error) {
	stat, err := linuxProcessStat(pid)
	if err != nil {
		return "", err
	}
	return stat.StartToken, nil
}

type linuxProcessState struct {
	ProcessGroup int
	StartToken   string
}

func linuxProcessStat(pid int) (linuxProcessState, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if errors.Is(err, os.ErrNotExist) {
		return linuxProcessState{}, errSchedulerProcessExited
	}
	if err != nil {
		return linuxProcessState{}, fmt.Errorf("read scheduler PID %d stat record: %w", pid, err)
	}
	text := string(raw)
	closingParen := strings.LastIndex(text, ")")
	if closingParen < 0 {
		return linuxProcessState{}, fmt.Errorf("parse scheduler PID %d stat record", pid)
	}
	fields := strings.Fields(text[closingParen+1:])
	// /proc/<pid>/stat field 5 is pgrp. The slice begins at field 3.
	if len(fields) <= 2 {
		return linuxProcessState{}, fmt.Errorf("parse scheduler PID %d process group", pid)
	}
	processGroup, err := strconv.Atoi(fields[2])
	if err != nil || processGroup <= 1 {
		return linuxProcessState{}, fmt.Errorf("parse scheduler PID %d process group %q", pid, fields[2])
	}
	// /proc/<pid>/stat field 22 is starttime. The slice begins at field 3.
	if len(fields) <= 19 || fields[19] == "" {
		return linuxProcessState{}, fmt.Errorf("parse scheduler PID %d start token", pid)
	}
	return linuxProcessState{ProcessGroup: processGroup, StartToken: fields[19]}, nil
}
