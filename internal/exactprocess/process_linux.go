//go:build linux

package exactprocess

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/exactsandbox"
	"golang.org/x/sys/unix"
)

const maxLifetime = 5 * time.Second

// launch is trusted infrastructure, never capsule data. Production constructs
// it only for the fixed preflight helper. Fixture construction is test-only.
// The native helper owns a compile-time executable/argv, not caller commands.
type launch struct {
	helper    string
	operation string
	// Only tests use extra: a short-lived descendant-PID report pipe. The
	// native fixture closes it before runtime exec; it is not runtime input.
	extra []*os.File
	// Tests force a one-page pipe to exercise blocked input deterministically.
	// The production preflight never supplies this instrumentation.
	testPipeCapacity int
}

type output struct {
	bytes []byte
	err   error
}

// exchange grants no authority. It validates frozen material before starting
// even a fixture, passes the original bytes unchanged, and independently
// validates the returned grammar and S binding. There are no production callers.
func exchange(ctx context.Context, l launch, capsule []byte, digest string) (exactsandbox.EncodedResult, error) {
	if len(capsule) > exactsandbox.MaxExecutionBytes {
		return nil, exactsandbox.ErrProtocol
	}
	// Retain a bounded snapshot; never validate one slice then write a mutable
	// caller-owned slice. Future Runner input already provides immutable bytes.
	capsule = append([]byte(nil), capsule...)
	if _, err := exactsandbox.DecodeExecution(capsule, digest); err != nil {
		return nil, err
	}
	return transact(ctx, l, capsule, exactsandbox.MaxResultBytes, func(b []byte) error {
		_, err := exactsandbox.DecodeResult(b, digest)
		return err
	})
}

// openHelper pins the executable inode and rejects symlinks, non-regular files,
// set-ID files, foreign owners and group/world-writable artifacts. The fixed
// production directory must also be provisioned by trusted deployment tooling.
func openHelper(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrProcess
	}
	// NONBLOCK prevents an incorrectly provisioned FIFO from hanging before
	// fstat can reject it. Regular files ignore this flag.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: helper open: %w", ErrUnavailable, err)
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: helper stat: %w", ErrProcess, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0111 == 0 || st.Mode&06022 != 0 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
		f.Close()
		return nil, ErrProcess
	}
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil || string(magic[:]) != "\x7fELF" {
		f.Close()
		return nil, ErrProcess // Never admit shebang scripts or a shell fallback.
	}
	return f, nil
}

// transact bounds every exchange by an independent maximum lifetime. Reads
// and writes proceed concurrently, so early output cannot deadlock input.
// stderr is /dev/null, never an accumulating diagnostics buffer.
func transact(ctx context.Context, l launch, input []byte, limit int, validate func([]byte) error) (result []byte, err error) {
	if ctx == nil || len(input) > exactsandbox.MaxExecutionBytes || validate == nil || limit < 0 || limit > 64*1024 {
		return nil, ErrProcess
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if l.operation != "" && l.operation != "--help" && l.operation != "--namespace-probe" {
		return nil, ErrProcess
	}
	ctx, cancel := context.WithTimeout(ctx, maxLifetime)
	defer cancel()
	helper, err := openHelper(l.helper)
	if err != nil {
		return nil, err
	}
	defer helper.Close()
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
	if l.testPipeCapacity != 0 {
		if l.testPipeCapacity != 4096 {
			return nil, ErrProcess
		}
		for _, f := range []*os.File{inWrite, outWrite} {
			if _, err := unix.FcntlInt(f.Fd(), unix.F_SETPIPE_SZ, l.testPipeCapacity); err != nil {
				return nil, err
			}
		}
	}
	// /proc/self/fd/3 refers to the explicitly passed, pinned native helper.
	// It is closed by that helper before exec of any fixed runtime/tool.
	cmd := exec.Command("/proc/self/fd/3")
	if l.operation != "" {
		cmd.Args = append(cmd.Args, l.operation)
	}
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stdin, cmd.Stdout = inRead, outWrite
	cmd.ExtraFiles = append([]*os.File{helper}, l.extra...)
	cmd.SysProcAttr = &unixSysProcAttr
	// Linux PDEATHSIG tracks the creating thread. Keep that thread alive until
	// cleanup completes rather than depending on Go's thread-pool lifetime.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: start: %w", ErrProcess, err)
	}
	inRead.Close()
	outWrite.Close()
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
	var wrote, read, dead bool
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
	for !wrote || !read || !dead {
		select {
		case e := <-writeDone:
			wrote = true
			writeDone = nil
			if e != nil {
				return nil, fmt.Errorf("%w: input: %w", ErrProcess, e)
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
				return nil, fmt.Errorf("%w: observe exit: %w", ErrProcess, e)
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
