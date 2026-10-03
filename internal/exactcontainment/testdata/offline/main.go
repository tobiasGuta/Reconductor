// Fixed offline proof runtime; never a 4C operation implementation. Test modes
// are linker constants, not capsule/argv/environment options. Normal execution
// reads one bounded canonical capsule to EOF and emits Completed=false to EOF.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/tobiasGuta/Reconductor/internal/exactsandbox"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strings"
	"unsafe"
)

var behavior = "normal"
var sentinelRoot = "/host-only-reconductor-proof"

func fail() { os.Exit(79) }
func hang() {
	for {
		unix.RawSyscall(unix.SYS_PAUSE, 0, 0, 0)
	}
}
func rejected(n uintptr, a, b, c uintptr) bool {
	_, _, e := unix.RawSyscall(n, a, b, c)
	return e == unix.EPERM
}
func audit() {
	sid, sidErr := unix.Getsid(0)
	if sidErr != nil || sid != 1 {
		fail()
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 || os.Getpid() != 2 {
		fail()
	}
	if os.Getenv("PWD") != "/" || len(os.Environ()) != 1 {
		fail()
	}
	cwd, err := os.Getwd()
	if err != nil || cwd != "/" {
		fail()
	}
	n, _, e := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0)
	if e != 0 || n != 1 {
		fail()
	}
	n, _, e = unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_SECCOMP, 0, 0, 0, 0, 0)
	if e != 0 || n != 2 {
		fail()
	}
	h := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if unix.Capget(&h, &caps[0]) != nil {
		fail()
	}
	for _, c := range caps {
		if c.Effective != 0 || c.Permitted != 0 || c.Inheritable != 0 {
			fail()
		}
	}
	for i := uintptr(0); i < 64; i++ {
		n, _, e = unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, i, 0, 0, 0)
		if e != unix.EINVAL && (e != 0 || n != 0) {
			fail()
		}
	}
	for fd := uintptr(3); fd < 1024; fd++ {
		_, _, e = unix.RawSyscall(unix.SYS_FCNTL, fd, unix.F_GETFD, 0)
		if e != unix.EBADF {
			fail()
		}
	}
	_, _, e = unix.RawSyscall(unix.SYS_FCNTL, 65537, unix.F_GETFD, 0)
	if e != unix.EBADF {
		fail()
	}
	var tty [64]byte
	for fd := uintptr(0); fd < 3; fd++ {
		_, _, e = unix.RawSyscall(unix.SYS_IOCTL, fd, unix.TCGETS, uintptr(unsafe.Pointer(&tty[0])))
		if e != unix.ENOTTY {
			fail()
		}
	}
	for _, path := range []string{"/proc", "/sys", "/dev", "/home", "/etc", "/run", "/var/lib/reconductor/artifacts", "/mnt/Development/Tools/Reconductor", sentinelRoot + "/repository", sentinelRoot + "/authority", sentinelRoot + "/artifact", sentinelRoot + "/home", sentinelRoot + "/run", sentinelRoot + "/control.sock"} {
		f, e := os.Open(path)
		if f != nil {
			f.Close()
			fail()
		}
		if !os.IsNotExist(e) {
			fail()
		}
	}
	if !rejected(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, 0) || !rejected(unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_STREAM, 0) || !rejected(unix.SYS_SOCKET, unix.AF_UNIX, unix.SOCK_STREAM, 0) {
		fail()
	}
	if unix.Connect(0, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{192, 0, 2, 1}}) != unix.EPERM {
		fail()
	}
	if unix.Connect(0, &unix.SockaddrUnix{Name: sentinelRoot + "/control.sock"}) != unix.EPERM {
		fail()
	}
	if !rejected(unix.SYS_SETNS, 404, unix.CLONE_NEWUSER, 0) {
		fail()
	}
	for _, n := range []uintptr{unix.SYS_CONNECT, unix.SYS_PTRACE, unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_MOUNT, unix.SYS_PIVOT_ROOT, unix.SYS_REBOOT, unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE, unix.SYS_FORK, unix.SYS_VFORK} {
		if !rejected(n, 0, 0, 0) {
			fail()
		}
	}
	if !rejected(unix.SYS_CLONE, unix.CLONE_NEWUSER, 0, 0) || !rejected(unix.SYS_GETPID|0x40000000, 0, 0, 0) {
		fail()
	}
	if !rejected(unix.SYS_UNSHARE, unix.CLONE_NEWUSER, 0, 0) {
		fail()
	}
	if f, e := os.OpenFile("/runtime/new", os.O_CREATE|os.O_WRONLY, 0600); f != nil || e == nil {
		fail()
	}
}
func main() {
	if len(os.Args) == 2 && os.Args[1] == "--preflight" {
		audit()
		if _, e := os.Stdout.WriteString("exact-containment-preflight/v1"); e != nil {
			fail()
		}
		return
	}
	if len(os.Args) != 1 {
		fail()
	}
	audit()
	switch behavior {
	case "ignore-input", "hang":
		hang()
	case "early-exit":
		return
	case "early-output":
		os.Stdout.Write([]byte(strings.Repeat("x", 4096)))
		hang()
	case "fork-hang":
		if !rejected(unix.SYS_FORK, 0, 0, 0) {
			fail()
		}
		hang()
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, exactsandbox.MaxExecutionBytes+1))
	if err != nil || len(raw) > exactsandbox.MaxExecutionBytes {
		fail()
	}
	sum := sha256.Sum256(append([]byte("reconductor-exact-sandbox-execution/v1\x00"), raw...))
	digest := hex.EncodeToString(sum[:])
	if _, err = exactsandbox.DecodeExecution(raw, digest); err != nil {
		fail()
	}
	switch behavior {
	case "partial":
		os.Stdout.WriteString("{")
		return
	case "oversized":
		os.Stdout.WriteString(strings.Repeat("x", 257))
		return
	case "malformed":
		os.Stdout.WriteString("{}")
		return
	case "wrong-digest":
		digest = strings.Repeat("0", 64)
	case "stderr-flood":
		for i := 0; i < 128; i++ {
			os.Stderr.Write(make([]byte, 65536))
		}
	}
	result, err := exactsandbox.EncodeResult(digest, false)
	if err != nil {
		fail()
	}
	if behavior == "trailing" {
		result = append(result, '\n')
	}
	if behavior == "multiple" {
		result = append(result, result...)
	}
	if behavior == "completed" {
		result, err = exactsandbox.EncodeResult(digest, true)
		if err != nil {
			fail()
		}
	}
	if _, err = os.Stdout.Write(result); err != nil {
		fail()
	}
	if behavior == "hold-output" {
		hang()
	}
	if behavior == "hold-after-eof" {
		os.Stdout.Close()
		hang()
	}
}
