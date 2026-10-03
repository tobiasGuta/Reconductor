//go:build linux && amd64

package exactcontainment

import (
	"encoding/binary"

	"golang.org/x/sys/unix"
)

// The installed artifact must equal this internally frozen, deterministic cBPF
// program byte-for-byte. It is not a caller-configurable policy. Foreign audit
// architectures die; x32 and unlisted x86_64 calls
// return EPERM. Argument guards narrow clone, open/openat, fcntl, ioctl, prctl.
func seccompPolicy() []byte {
	const ld = 0x20
	const jeq = 0x15
	const ret = 0x06
	const and = 0x54
	type ins struct {
		c    uint16
		t, f uint8
		k    uint32
	}
	var p []ins
	add := func(c uint16, t, f uint8, k uint32) { p = append(p, ins{c, t, f, k}) }
	deny := uint32(unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM))
	allow := uint32(unix.SECCOMP_RET_ALLOW)
	add(ld, 0, 0, 4)
	add(jeq, 1, 0, unix.AUDIT_ARCH_X86_64)
	add(ret, 0, 0, unix.SECCOMP_RET_KILL_PROCESS)
	add(ld, 0, 0, 0)
	// Each guarded block returns on every matching path, leaving A=nr otherwise.
	block := func(nr uint32, b []ins) { add(jeq, 0, uint8(len(b)), nr); p = append(p, b...) }
	// Namespace-free Go threads only, never fork/vfork or non-thread clone.
	flags := uint32(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD | unix.CLONE_SYSVSEM)
	block(unix.SYS_CLONE, []ins{{ld, 0, 0, 20}, {jeq, 1, 0, 0}, {ret, 0, 0, deny}, {ld, 0, 0, 16}, {jeq, 2, 0, flags}, {jeq, 1, 0, flags | unix.CLONE_SETTLS}, {ret, 0, 0, deny}, {ret, 0, 0, allow}})
	block(unix.SYS_CLONE3, []ins{{ret, 0, 0, unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)}})
	// Filesystem opens are read-only, with no creation/truncation/tmpfile.
	for _, x := range []struct{ nr, offset uint32 }{{unix.SYS_OPEN, 24}, {unix.SYS_OPENAT, 32}} {
		mask := uint32(unix.O_WRONLY | unix.O_RDWR | unix.O_CREAT | unix.O_TRUNC | unix.O_APPEND | 0x400000)
		block(x.nr, []ins{{ld, 0, 0, x.offset + 4}, {jeq, 1, 0, 0}, {ret, 0, 0, deny}, {ld, 0, 0, x.offset}, {and, 0, 0, mask}, {jeq, 1, 0, 0}, {ret, 0, 0, deny}, {ret, 0, 0, allow}})
	}
	block(unix.SYS_FCNTL, []ins{{ld, 0, 0, 24}, {jeq, 2, 0, unix.F_GETFD}, {jeq, 1, 0, unix.F_GETFL}, {ret, 0, 0, deny}, {ret, 0, 0, allow}})
	block(unix.SYS_IOCTL, []ins{{ld, 0, 0, 24}, {jeq, 1, 0, unix.TCGETS}, {ret, 0, 0, deny}, {ret, 0, 0, allow}})
	block(unix.SYS_PRCTL, []ins{{ld, 0, 0, 16}, {jeq, 6, 0, unix.PR_GET_NO_NEW_PRIVS}, {jeq, 5, 0, unix.PR_GET_SECCOMP}, {jeq, 1, 0, unix.PR_CAP_AMBIENT}, {ret, 0, 0, deny}, {ld, 0, 0, 24}, {jeq, 1, 0, unix.PR_CAP_AMBIENT_IS_SET}, {ret, 0, 0, deny}, {ret, 0, 0, allow}})
	for _, nr := range []uint32{
		unix.SYS_READ, unix.SYS_WRITE, unix.SYS_CLOSE, unix.SYS_FSTAT, unix.SYS_NEWFSTATAT, unix.SYS_STAT, unix.SYS_LSTAT,
		unix.SYS_LSEEK, unix.SYS_PREAD64, unix.SYS_READLINK, unix.SYS_READLINKAT, unix.SYS_GETDENTS64,
		unix.SYS_MMAP, unix.SYS_MPROTECT, unix.SYS_MUNMAP, unix.SYS_BRK, unix.SYS_MADVISE,
		unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN, unix.SYS_SIGALTSTACK,
		unix.SYS_FUTEX, unix.SYS_SCHED_YIELD, unix.SYS_SCHED_GETAFFINITY,
		unix.SYS_CLOCK_GETTIME, unix.SYS_NANOSLEEP, unix.SYS_CLOCK_NANOSLEEP, unix.SYS_PAUSE,
		unix.SYS_GETPID, unix.SYS_GETPPID, unix.SYS_GETTID, unix.SYS_TGKILL, unix.SYS_GETUID, unix.SYS_GETEUID,
		unix.SYS_GETGID, unix.SYS_GETEGID, unix.SYS_GETGROUPS, unix.SYS_CAPGET, unix.SYS_GETCWD, unix.SYS_GETSID,
		unix.SYS_GETRANDOM, unix.SYS_ARCH_PRCTL, unix.SYS_SET_TID_ADDRESS, unix.SYS_SET_ROBUST_LIST,
		unix.SYS_WAIT4, unix.SYS_WAITID, unix.SYS_EXECVE, unix.SYS_EXIT, unix.SYS_EXIT_GROUP,
	} {
		add(jeq, 0, 1, nr)
		add(ret, 0, 0, allow)
	}
	add(ret, 0, 0, deny)
	b := make([]byte, 8*len(p))
	for i, x := range p {
		binary.LittleEndian.PutUint16(b[i*8:], x.c)
		b[i*8+2] = x.t
		b[i*8+3] = x.f
		binary.LittleEndian.PutUint32(b[i*8+4:], x.k)
	}
	return b
}
