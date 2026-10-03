//go:build linux && amd64

package exactcontainment

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	launcherPath = "/usr/libexec/reconductor/exact-containment-launcher"
	bwrapPath    = "/usr/bin/bwrap"
	runtimePath  = "/usr/libexec/reconductor/exact-offline-runtime"
	filterPath   = "/usr/libexec/reconductor/exact-offline-x86_64.bpf"
)

type artifacts struct {
	launcher, bwrap, runtime, filter *os.File
	// Same-package tests force one-page protocol pipes to observe blocked writers.
	// fixedArtifacts never configures instrumentation; no public hook exists.
	testPipeCapacity int
}

func (a artifacts) close() {
	for _, f := range []*os.File{a.launcher, a.bwrap, a.runtime, a.filter} {
		if f != nil {
			f.Close()
		}
	}
}

// Walk root-owned directories through retained dirfds. No symlink component,
// writable parent, or validate-path/reopen sequence is admitted. The root
// administrator is trusted; service-writable and set-ID/file-cap artifacts are not.
func openTrusted(path string, executable, static bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnavailable
	}
	dir, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { unix.Close(dir) }()
	var root unix.Stat_t
	if unix.Fstat(dir, &root) != nil || root.Uid != 0 || root.Mode&022 != 0 {
		return nil, ErrUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(dir, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, e
		}
		unix.Close(dir)
		dir = next
		var st unix.Stat_t
		if unix.Fstat(dir, &st) != nil || st.Uid != 0 || st.Mode&022 != 0 {
			return nil, ErrUnavailable
		}
	}
	fd, err := unix.Openat(dir, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err = checkArtifact(f, executable, static, true); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// The ownership switch is private and used only by same-package test seams.
// No production function accepts a pathname, descriptor, or expected hash.
func checkArtifact(f *os.File, executable, static, rootOwned bool) error {
	var st unix.Stat_t
	if f == nil || unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size <= 0 || st.Size > 64*1024*1024 || st.Mode&06022 != 0 || (rootOwned && st.Uid != 0) {
		return ErrUnavailable
	}
	if executable && st.Mode&0111 != 0111 {
		return ErrUnavailable
	}
	var cap [64]byte
	n, err := unix.Fgetxattr(int(f.Fd()), "security.capability", cap[:])
	if err != unix.ENODATA && err != unix.ENOTSUP {
		return ErrUnavailable
	}
	if n > 0 {
		return ErrUnavailable
	}
	if executable {
		e, err := elf.NewFile(f)
		if err != nil {
			return ErrUnavailable
		}
		if e.Class != elf.ELFCLASS64 || e.Data != elf.ELFDATA2LSB || e.Machine != elf.EM_X86_64 || (e.Type != elf.ET_EXEC && e.Type != elf.ET_DYN) {
			return ErrUnavailable
		}
		if static {
			for _, p := range e.Progs {
				if p.Type == elf.PT_INTERP {
					return ErrUnavailable
				}
			}
		}
	}
	_, err = f.Seek(0, io.SeekStart)
	return err
}

func fixedArtifacts() (a artifacts, err error) {
	defer func() {
		if err != nil {
			a.close()
			err = fmt.Errorf("%w: artifact verification", ErrUnavailable)
		}
	}()
	if a.launcher, err = openTrusted(launcherPath, true, false); err != nil {
		return
	}
	if a.bwrap, err = openTrusted(bwrapPath, true, false); err != nil {
		return
	}
	if a.runtime, err = openTrusted(runtimePath, true, true); err != nil {
		return
	}
	var source *os.File
	if source, err = openTrusted(filterPath, false, false); err != nil {
		return
	}
	defer source.Close()
	a.filter, err = pinFilter(source)
	return
}

// Freeze the validated policy bytes in a sealed memfd. This also prevents
// another launch's shared file offset from changing Bubblewrap's input.
func pinFilter(source *os.File) (*os.File, error) {
	expected := seccompPolicy()
	actual, err := io.ReadAll(io.NewSectionReader(source, 0, int64(len(expected)+1)))
	if err != nil || !bytes.Equal(actual, expected) {
		return nil, ErrUnavailable
	}
	fd, err := unix.MemfdCreate("exact-offline-seccomp", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "exact-offline-seccomp")
	if _, err = f.Write(actual); err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err == nil {
		_, err = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
