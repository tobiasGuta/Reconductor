//go:build linux && amd64

package exactcontainment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/exactsandbox"
	"golang.org/x/sys/unix"
)

const maxLifetime = 5 * time.Second

type output struct {
	bytes []byte
	err   error
}

// transact bounds every exchange by an independent maximum lifetime. Reads
// and writes proceed concurrently, so early output cannot deadlock input.
// stderr is /dev/null, never an accumulating diagnostics buffer.
func transact(ctx context.Context, a artifacts, probe bool, input []byte, limit int, validate func([]byte) error) (result []byte, err error) {
	if a.launcher == nil || a.bwrap == nil || a.runtime == nil || a.filter == nil || ctx == nil || len(input) > exactsandbox.MaxExecutionBytes || validate == nil || limit < 0 || limit > 64*1024 {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, maxLifetime)
	defer cancel()
	if _, err := a.filter.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer inRead.Close()
	defer inWrite.Close()
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer outRead.Close()
	defer outWrite.Close()
	infoRead, infoWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer infoRead.Close()
	defer infoWrite.Close()
	if a.testPipeCapacity != 0 {
		if a.testPipeCapacity != 4096 {
			return nil, ErrUnavailable
		}
		for _, f := range []*os.File{inWrite, outWrite} {
			if _, e := unix.FcntlInt(f.Fd(), unix.F_SETPIPE_SZ, a.testPipeCapacity); e != nil {
				return nil, e
			}
		}
	}
	// Object FDs are deliberate setup inputs, consumed/closed by bwrap.
	cmd := exec.Command("/proc/self/fd/3")
	if probe {
		cmd.Args = append(cmd.Args, "--preflight")
	}
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stdin, cmd.Stdout = inRead, outWrite
	cmd.ExtraFiles = []*os.File{a.launcher, a.bwrap, a.runtime, a.filter, infoWrite}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Linux PDEATHSIG tracks the creating thread. Keep that thread alive until
	// cleanup completes rather than depending on Go's thread-pool lifetime.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: start: %w", ErrUnavailable, err)
	}
	inRead.Close()
	outWrite.Close()
	infoWrite.Close()
	infoDone := make(chan output, 1)
	go func() { b, e := readBounded(infoRead, 1024); infoDone <- output{b, e} }()
	writeDone := make(chan error, 1)
	readDone := make(chan output, 1)
	exited := make(chan error, 1)
	go func() {
		err := writeAll(inWrite, input)
		closeErr := inWrite.Close() // EOF only after the complete bounded write.
		writeDone <- errors.Join(err, closeErr)
	}()
	go func() { b, err := readBounded(outRead, limit); readDone <- output{b, err} }()
	go func() {
		var info unix.Siginfo
		for {
			err := unix.Waitid(unix.P_PID, cmd.Process.Pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
			if err == unix.EINTR {
				continue
			}
			exited <- err
			return
		}
	}()
	// Do not reap the leader until its group has been killed. WNOWAIT retains
	// the PID, avoiding a kill(-pid) race against a reused process-group ID.
	var wrote, read, dead, informed bool
	killGroup := func() error {
		err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if err == unix.ESRCH {
			return nil
		}
		return err
	}
	defer func() {
		killErr := killGroup()
		inWrite.Close()
		outRead.Close()
		infoRead.Close()
		if !informed {
			<-infoDone
		}
		if !dead {
			err = errors.Join(err, <-exited)
		}
		waitErr := cmd.Wait()
		if !wrote {
			<-writeDone
		}
		if !read {
			<-readDone
		}
		err = errors.Join(err, killErr, waitErr)
		if err != nil {
			result = nil
		}
	}()
	for !wrote || !read || !dead || !informed {
		select {
		case info := <-infoDone:
			informed = true
			infoDone = nil
			if info.err != nil {
				return nil, info.err
			}
			if _, e := verifyNamespaceInfo(info.bytes); e != nil {
				return nil, e
			}

		case e := <-writeDone:
			wrote = true
			writeDone = nil
			if e != nil {
				return nil, fmt.Errorf("%w: input: %w", ErrUnavailable, e)
			}
		case o := <-readDone:
			read = true
			readDone = nil
			if o.err != nil {
				return nil, o.err
			}
			if err := validate(o.bytes); err != nil {
				return nil, err
			}
			result = o.bytes
		case e := <-exited:
			dead = true
			exited = nil
			if e != nil {
				return nil, fmt.Errorf("%w: observe exit: %w", ErrUnavailable, e)
			}
			// Even a successful leader may leave descendants holding pipes open.
			if err := killGroup(); err != nil {
				return nil, err
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// This report comes from pinned Bubblewrap's host-side setup monitor, never
// the runtime. FD7 is closed in both sandbox and monitor before workload exec.
// Compare kernel namespace identities independently of seccomp rejection.
func verifyNamespaceInfo(raw []byte) (int, error) {
	var info map[string]uint64
	if len(raw) > 1024 || json.Unmarshal(raw, &info) != nil {
		return 0, ErrUnavailable
	}
	pid := info["child-pid"]
	if pid <= 1 || pid > 1<<30 {
		return 0, ErrUnavailable
	}
	for _, name := range []string{"pid", "net", "ipc", "uts", "mnt"} {
		var st unix.Stat_t
		if unix.Stat("/proc/self/ns/"+name, &st) != nil || info[name+"-namespace"] == 0 || info[name+"-namespace"] == st.Ino {
			return 0, ErrUnavailable
		}
	}
	return int(pid), nil
}
