//go:build linux

package exactactivation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestActivationEnvironment(t *testing.T) {
	valid := activationEnvironment{pid: "42", count: "1", name: DescriptorName}
	if err := validateActivationEnvironment(valid, 42); err != nil {
		t.Fatal(err)
	}
	for _, env := range []activationEnvironment{
		{}, {pid: "42", count: "0", name: DescriptorName},
		{pid: "42", count: "2", name: DescriptorName},
		{pid: "42", count: "-1", name: DescriptorName},
		{pid: "42", count: "01", name: DescriptorName},
		{pid: "42", count: "1", name: "other"},
		{pid: "42", count: "1", name: DescriptorName + ":other"},
		{pid: "42", count: "1"},
		{pid: "43", count: "1", name: DescriptorName},
		{pid: "042", count: "1", name: DescriptorName},
		{pid: "not-a-pid", count: "1", name: DescriptorName},
		{pid: "42", count: "one", name: DescriptorName},
		{pid: "42", count: "1", name: DescriptorName, pidfdID: "unsupported", pidfdPresent: true},
	} {
		if !errors.Is(validateActivationEnvironment(env, 42), ErrActivation) {
			t.Fatalf("accepted malformed activation: %+v", env)
		}
	}
}

func TestMissingActivationConsumesEnvironment(t *testing.T) {
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PIDFDID"} {
		t.Setenv(name, "")
	}
	if _, err := acquireWorkerListener(&acquisitionState{}, func() (listenerIdentity, error) {
		t.Fatal("lookup reached without activation")
		return listenerIdentity{}, ErrActivation
	}); !errors.Is(err, ErrActivation) {
		t.Fatal("missing activation accepted")
	}
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PIDFDID"} {
		if _, exists := os.LookupEnv(name); exists {
			t.Fatal("activation environment retained")
		}
	}
}

func temporaryListener(t *testing.T) (*net.UnixListener, listenerIdentity) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "control.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	return listener, listenerIdentity{path: path, parentRoot: root, owner: uint32(os.Geteuid()), group: uint32(os.Getegid())}
}

// rawDuplicate is intentionally non-CLOEXEC. It is not mapped via ExtraFiles in
// the inheritance proof: the positive control verifies actual exec inheritance.
func rawDuplicate(t *testing.T, listener *net.UnixListener) int {
	t.Helper()
	file, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD, 20)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

func TestListenerValidation(t *testing.T) {
	listener, identity := temporaryListener(t)
	fd := rawDuplicate(t, listener)
	owner, err := acquireListener(fd, identity)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	// Closing the owner neither unlinks nor globally shuts down PID1's analogue.
	if _, err := os.Stat(identity.path); err != nil {
		t.Fatalf("intake unlinked socket: %v", err)
	}
	conn, err := net.DialTimeout("unix", identity.path, time.Second)
	if err != nil {
		t.Fatalf("intake shut down shared listener: %v", err)
	}
	defer conn.Close()
	for _, mutation := range []string{"path", "owner", "group", "mode", "parent-write", "missing", "symlink", "invalid-parent-root"} {
		t.Run(mutation, func(t *testing.T) {
			ln, id := temporaryListener(t)
			duplicate := rawDuplicate(t, ln)
			defer unix.Close(duplicate)
			switch mutation {
			case "path":
				id.path += ".other"
			case "owner":
				id.owner++
			case "group":
				id.group++
			case "mode":
				if err := os.Chmod(id.path, 0666); err != nil {
					t.Fatal(err)
				}
			case "parent-write":
				if err := os.Chmod(id.parentRoot, 0777); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(id.path); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(id.path, id.path+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(id.path+".moved", id.path); err != nil {
					t.Fatal(err)
				}
			case "invalid-parent-root":
				child := filepath.Join(id.parentRoot, "nested")
				if err := os.Mkdir(child, 0755); err != nil {
					t.Fatal(err)
				}
				id.parentRoot = child // not an ancestor; must fail closed
			}
			if _, err := acquireListener(duplicate, id); !errors.Is(err, ErrActivation) {
				t.Fatalf("accepted %s: %v", mutation, err)
			}
		})
	}
}

func TestSymlinkedParentRejected(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(alias, "control.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false)
	defer ln.Close()
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	fd := rawDuplicate(t, ln)
	defer unix.Close(fd)
	id := listenerIdentity{path: path, parentRoot: root, owner: uint32(os.Geteuid()), group: uint32(os.Getegid())}
	if _, err := acquireListener(fd, id); !errors.Is(err, ErrActivation) {
		t.Fatal("accepted symlinked ancestor")
	}
}

func TestWrongDescriptor(t *testing.T) {
	_, identity := temporaryListener(t)
	for _, kind := range []int{unix.SOCK_DGRAM, unix.SOCK_SEQPACKET} {
		fd, err := unix.Socket(unix.AF_UNIX, kind, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, takeErr := acquireListener(fd, identity)
		_ = unix.Close(fd)
		if !errors.Is(takeErr, ErrActivation) {
			t.Fatal("accepted wrong socket type")
		}
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if _, err := acquireListener(fds[0], identity); !errors.Is(err, ErrActivation) {
		t.Fatal("accepted connected socket")
	}
	file, err := os.CreateTemp(t.TempDir(), "not-a-socket")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := acquireListener(int(file.Fd()), identity); !errors.Is(err, ErrActivation) {
		t.Fatal("accepted regular file")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0) // never bind/connect
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if _, err := acquireListener(fd, identity); !errors.Is(err, ErrActivation) {
		t.Fatal("accepted non-Unix socket")
	}
	if _, err := acquireListener(-1, identity); !errors.Is(err, ErrActivation) {
		t.Fatal("accepted missing descriptor")
	}
}

func TestIntakeDoesNotAcceptOrSend(t *testing.T) {
	listener, identity := temporaryListener(t)
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: identity.path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	owner, err := acquireListener(rawDuplicate(t, listener), identity)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	n, err := peer.Read(b[:])
	var timeout net.Error
	if n != 0 || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("startup sent/closed material: n=%d err=%v", n, err)
	}
	// A test-only accept on the original socket must still receive the queued
	// connection. It proves intake did not consume backlog capacity silently.
	if err := listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal("intake consumed the queued connection", err)
	}
	defer accepted.Close()
	if err := peer.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := accepted.Write([]byte("test-only")); err != nil {
		t.Fatal(err)
	}
	var response [9]byte
	if n, err := peer.Read(response[:]); err != nil || string(response[:n]) != "test-only" {
		t.Fatal("accepted a different connection", err)
	}
}

func TestCLOEXECInheritance(t *testing.T) {
	listener, identity := temporaryListener(t)
	fd := rawDuplicate(t, listener)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	probe := func() string {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestActivationChild$")
		cmd.Env = []string{"GORACE=atexit_sleep_ms=0", "EXACTACTIVATION_CHILD=probe", fmt.Sprintf("TEST_FD=%d", fd), fmt.Sprintf("TEST_DEV=%d", stat.Dev), fmt.Sprintf("TEST_INO=%d", stat.Ino)}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child probe: %v %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if got := probe(); got != "present" {
		t.Fatalf("positive inheritance control failed: %q", got)
	}
	owner, err := acquireListener(fd, identity)
	if err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	defer owner.Close()
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("CLOEXEC missing", err)
	}
	if got := probe(); got != "absent" {
		t.Fatalf("listener inherited after intake: %q", got)
	}
}

func TestSingleActivationDescriptor(t *testing.T) {
	listener, id := temporaryListener(t)
	file, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestActivationChild$")
	cmd.ExtraFiles = []*os.File{file} // only the subprocess test supplies FD 3
	cmd.Env = []string{"GORACE=atexit_sleep_ms=0", "EXACTACTIVATION_CHILD=intake", "TEST_PATH=" + id.path, "TEST_ROOT=" + id.parentRoot}
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "owned" {
		t.Fatalf("activation child: %v %s", err, out)
	}
}

func TestActivationChild(t *testing.T) {
	switch os.Getenv("EXACTACTIVATION_CHILD") {
	case "":
		return
	case "probe":
		fd, err := strconv.Atoi(os.Getenv("TEST_FD"))
		if err != nil {
			os.Exit(2)
		}
		dev, err := strconv.ParseUint(os.Getenv("TEST_DEV"), 10, 64)
		if err != nil {
			os.Exit(2)
		}
		ino, err := strconv.ParseUint(os.Getenv("TEST_INO"), 10, 64)
		if err != nil {
			os.Exit(2)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err == nil && uint64(stat.Dev) == dev && stat.Ino == ino {
			fmt.Println("present")
		} else {
			fmt.Println("absent")
		}
	case "intake":
		env := activationEnvironment{pid: strconv.Itoa(os.Getpid()), count: "1", name: DescriptorName}
		owner, err := acquireActivation(env, os.Getpid(), func() (listenerIdentity, error) {
			flags, err := unix.FcntlInt(activationFD, unix.F_GETFD, 0)
			if err != nil || flags&unix.FD_CLOEXEC == 0 {
				return listenerIdentity{}, ErrActivation
			}
			return listenerIdentity{path: os.Getenv("TEST_PATH"), parentRoot: os.Getenv("TEST_ROOT"), owner: uint32(os.Geteuid()), group: uint32(os.Getegid())}, nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := owner.Close(); err != nil {
			os.Exit(2)
		}
		fmt.Println("owned")
	case "one-shot-concurrent":
		testConcurrentActivationChild(t)
	case "one-shot-failure":
		testFailedActivationChild(t)
	case "public-gate":
		setTestActivation(t)
		if err := os.Setenv("LISTEN_FDS", "invalid"); err != nil {
			t.Fatal(err)
		}
		if owner, err := AcquireWorkerListener(); owner != nil || !errors.Is(err, ErrActivation) {
			t.Fatal("public failure did not reject")
		}
		assertActivationConsumed(t)
		setTestActivation(t)
		if owner, err := AcquireWorkerListener(); owner != nil || !errors.Is(err, ErrActivation) {
			t.Fatal("public gate allowed retry")
		}
		assertTestActivationRetained(t)
		fmt.Println("public gate retained failed attempt")
	case "genuine":
		value, present := os.LookupEnv("LISTEN_PIDFDID")
		own, err := selfPIDFDIdentity()
		if err != nil || !present || value != strconv.FormatUint(own, 10) {
			t.Fatal("genuine PIDFD identity not delivered")
		}
		state := &acquisitionState{}
		owner, err := acquireWorkerListener(state, testListenerLookup(t))
		if err != nil || owner == nil {
			t.Fatal("genuine activation rejected", err)
		}
		assertActivationConsumed(t)
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
		fmt.Println("genuine PID/PIDFD identity accepted; fixture owned; environment consumed")
	case "pidfd-valid":
		setTestActivation(t)
		if os.Getenv("TEST_DETAIL") == "correct" {
			own, err := selfPIDFDIdentity()
			if err != nil {
				t.Fatal("self PIDFD verification unavailable", err)
			}
			if err := os.Setenv("LISTEN_PIDFDID", strconv.FormatUint(own, 10)); err != nil {
				t.Fatal(err)
			}
		}
		owner, err := acquireWorkerListener(&acquisitionState{}, testListenerLookup(t))
		if err != nil || owner == nil {
			t.Fatal("valid activation rejected", err)
		}
		assertActivationConsumed(t)
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
		fmt.Println("valid PIDFD presence contract accepted and consumed")
	default:
		os.Exit(2)
	}
	os.Exit(0)
}

func TestPIDFDIdentityParsing(t *testing.T) {
	for _, value := range []string{"0", "1", "4294967296", "18446744073709551615"} {
		id, err := parsePIDFDIdentity(value)
		if err != nil || strconv.FormatUint(id, 10) != value {
			t.Fatal("full-width canonical decimal rejected")
		}
	}
	// systemd's producer emits canonical decimal. Its general integer receiver
	// also accepts octal leading-zero notation; this contract deliberately does
	// not reinterpret such input as decimal or accept noncanonical spellings.
	for _, value := range []string{"", "-1", "+1", "01", "00", "010", " 1", "1 ", "\t1", "1\n", "0x1", "1x", "1\x00", "18446744073709551616"} {
		if _, err := parsePIDFDIdentity(value); !errors.Is(err, ErrActivation) {
			t.Fatal("noncanonical PIDFD identity accepted")
		}
		env := activationEnvironment{pid: "42", count: "1", name: DescriptorName, pidfdID: value, pidfdPresent: true}
		if !errors.Is(validateActivationEnvironment(env, 42), ErrActivation) {
			t.Fatal("PIDFD syntax bypassed environment validation")
		}
	}
}

func TestPIDFDIdentityVerification(t *testing.T) {
	const own uint64 = 18446744073709551615
	valid := activationEnvironment{pid: "42", count: "1", name: DescriptorName, pidfdID: strconv.FormatUint(own, 10), pidfdPresent: true}
	if err := verifyActivationPIDFD(valid, func() (uint64, error) { return own, nil }); err != nil {
		t.Fatal("matching full-width identity rejected")
	}
	wrong := valid
	wrong.pidfdID = "42" // PID matches, independently derived PIDFD identity does not.
	if !errors.Is(verifyActivationPIDFD(wrong, func() (uint64, error) { return own, nil }), ErrActivation) {
		t.Fatal("matching PID bypassed wrong PIDFD identity")
	}
	for _, failure := range []error{unix.ENOSYS, unix.EPERM, ErrActivation} {
		if !errors.Is(verifyActivationPIDFD(valid, func() (uint64, error) { return 0, failure }), ErrActivation) {
			t.Fatal("unverifiable supplied identity downgraded to PID-only")
		}
	}
	if err := verifyActivationPIDFD(activationEnvironment{}, func() (uint64, error) {
		t.Fatal("absent identity invoked kernel verification")
		return 0, ErrActivation
	}); err != nil {
		t.Fatal("absent PIDFD identity rejected")
	}
	if !errors.Is(verifyActivationPIDFD(activationEnvironment{pidfdPresent: true}, func() (uint64, error) {
		t.Fatal("present-empty identity invoked kernel verification")
		return 0, nil
	}), ErrActivation) {
		t.Fatal("present-empty identity accepted")
	}
}

func TestSelfPIDFDIdentity(t *testing.T) {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		if _, err := selfPIDFDIdentity(); !errors.Is(err, ErrActivation) {
			t.Fatal("unavailable pidfd accepted")
		}
		return // Legacy activation still works on kernels without pidfd_open.
	}
	defer unix.Close(fd)
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Type != unix.PID_FS_MAGIC {
		if _, err := selfPIDFDIdentity(); !errors.Is(err, ErrActivation) {
			t.Fatal("anonymous-inode pidfd accepted as strong identity")
		}
		return
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("kernel pidfd not CLOEXEC")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if own, err := selfPIDFDIdentity(); err != nil || own != stat.Ino {
			t.Fatal("self identity differs from independent kernel observation", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("temporary pidfd leak", err)
	}
}

func runActivationChild(t *testing.T, mode, detail string) {
	t.Helper()
	listener, id := temporaryListener(t)
	file, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestActivationChild$")
	cmd.ExtraFiles = []*os.File{file}
	cmd.Env = []string{"GORACE=atexit_sleep_ms=0", "EXACTACTIVATION_CHILD=" + mode, "TEST_DETAIL=" + detail, "TEST_PATH=" + id.path, "TEST_ROOT=" + id.parentRoot}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("activation child: %v %s", err, out)
	}
}

func TestActivationOneShotConcurrent(t *testing.T) {
	for _, count := range []int{2, 8, 32} {
		t.Run(strconv.Itoa(count), func(t *testing.T) { runActivationChild(t, "one-shot-concurrent", strconv.Itoa(count)) })
	}
}

func TestActivationOneShotFailure(t *testing.T) {
	for _, failure := range []string{"missing", "pid", "count", "name", "pidfd-empty", "pidfd-malformed", "pidfd-negative", "pidfd-overflow", "pidfd-wrong", "pidfd-unverifiable", "fd", "socket", "lookup", "path", "metadata"} {
		t.Run(failure, func(t *testing.T) { runActivationChild(t, "one-shot-failure", failure) })
	}
}

func TestActivationPIDFDIntegration(t *testing.T) {
	for _, mode := range []string{"absent", "correct"} {
		t.Run(mode, func(t *testing.T) { runActivationChild(t, "pidfd-valid", mode) })
	}
}

func TestPublicActivationGate(t *testing.T) { runActivationChild(t, "public-gate", "") }

func setTestActivation(t *testing.T) {
	t.Helper()
	for name, value := range map[string]string{"LISTEN_PID": strconv.Itoa(os.Getpid()), "LISTEN_FDS": "1", "LISTEN_FDNAMES": DescriptorName} {
		if err := os.Setenv(name, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Unsetenv("LISTEN_PIDFDID"); err != nil {
		t.Fatal(err)
	}
}

func assertActivationConsumed(t *testing.T) {
	t.Helper()
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PIDFDID"} {
		if _, present := os.LookupEnv(name); present {
			t.Fatal("activation environment retained")
		}
	}
}

func assertTestActivationRetained(t *testing.T) {
	t.Helper()
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" || os.Getenv("LISTEN_FDNAMES") != DescriptorName {
		t.Fatal("losing acquisition consumed environment")
	}
}

func testListenerLookup(t *testing.T) func() (listenerIdentity, error) {
	t.Helper()
	return func() (listenerIdentity, error) {
		flags, err := unix.FcntlInt(activationFD, unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			return listenerIdentity{}, ErrActivation
		}
		return listenerIdentity{path: os.Getenv("TEST_PATH"), parentRoot: os.Getenv("TEST_ROOT"), owner: uint32(os.Geteuid()), group: uint32(os.Getegid())}, nil
	}
}

func testConcurrentActivationChild(t *testing.T) {
	count, err := strconv.Atoi(os.Getenv("TEST_DETAIL"))
	if err != nil || count < 2 {
		t.Fatal("invalid caller count")
	}
	setTestActivation(t)
	state := &acquisitionState{}
	owners, errs := make([]*WorkerListener, count), make([]error, count)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var lookups atomic.Int32
	lookup := testListenerLookup(t)
	for i := range owners {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			owners[i], errs[i] = acquireWorkerListener(state, func() (listenerIdentity, error) {
				lookups.Add(1)
				return lookup()
			})
		}(i)
	}
	close(start)
	wg.Wait()
	var winner *WorkerListener
	for i, owner := range owners {
		if owner != nil {
			if winner != nil || errs[i] != nil {
				t.Fatal("duplicate activation owners")
			}
			winner = owner
		} else if !errors.Is(errs[i], ErrActivation) {
			t.Fatal("loser did not fail deterministically")
		}
	}
	if winner == nil || lookups.Load() != 1 {
		t.Fatal("expected exactly one owner and one lookup")
	}
	assertActivationConsumed(t)
	setTestActivation(t)
	if owner, err := acquireWorkerListener(state, func() (listenerIdentity, error) {
		t.Fatal("sequential loser reached lookup")
		return listenerIdentity{}, nil
	}); owner != nil || !errors.Is(err, ErrActivation) {
		t.Fatal("successful attempt allowed retry")
	}
	assertTestActivationRetained(t)
	if err := winner.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
	if err != nil || replacement != activationFD {
		t.Fatal("FD 3 was not reused", err)
	}
	defer unix.Close(replacement)
	// All losers are nil; their Close cannot reach the replacement. Even the
	// already-closed winner must not close a newly reused FD number.
	for _, owner := range owners {
		err := owner.Close()
		if owner != nil && !errors.Is(err, os.ErrClosed) || owner == nil && err != nil {
			t.Fatal("unexpected repeat close", err)
		}
	}
	before, err := unix.FcntlInt(activationFD, unix.F_GETFD, 0)
	if err != nil {
		t.Fatal("stale owner closed replacement", err)
	}
	if err := os.Setenv("LISTEN_PIDFDID", "loser-must-not-touch"); err != nil {
		t.Fatal(err)
	}
	if owner, err := acquireWorkerListener(state, func() (listenerIdentity, error) {
		t.Fatal("FD-reuse loser reached lookup")
		return listenerIdentity{}, nil
	}); owner != nil || !errors.Is(err, ErrActivation) {
		t.Fatal("gate accepted replacement descriptor")
	}
	after, err := unix.FcntlInt(activationFD, unix.F_GETFD, 0)
	if err != nil || before != after {
		t.Fatal("loser changed replacement FD flags")
	}
	assertTestActivationRetained(t)
	if os.Getenv("LISTEN_PIDFDID") != "loser-must-not-touch" {
		t.Fatal("loser consumed PIDFD variable")
	}
	fmt.Println("one owner; sequential loser rejects; reused FD 3 preserved")
}

func testFailedActivationChild(t *testing.T) {
	setTestActivation(t)
	lookup := testListenerLookup(t)
	var restoreLimit func()
	switch os.Getenv("TEST_DETAIL") {
	case "missing":
		if err := os.Unsetenv("LISTEN_PID"); err != nil {
			t.Fatal(err)
		}
	case "pid":
		if err := os.Setenv("LISTEN_PID", "0"); err != nil {
			t.Fatal(err)
		}
	case "count":
		if err := os.Setenv("LISTEN_FDS", "2"); err != nil {
			t.Fatal(err)
		}
	case "name":
		if err := os.Setenv("LISTEN_FDNAMES", "wrong"); err != nil {
			t.Fatal(err)
		}
	case "pidfd-empty", "pidfd-malformed", "pidfd-negative", "pidfd-overflow", "pidfd-wrong":
		value := map[string]string{"pidfd-empty": "", "pidfd-malformed": "not-decimal", "pidfd-negative": "-1", "pidfd-overflow": "18446744073709551616", "pidfd-wrong": "0"}[os.Getenv("TEST_DETAIL")]
		if err := os.Setenv("LISTEN_PIDFDID", value); err != nil {
			t.Fatal(err)
		}
	case "pidfd-unverifiable":
		own, err := selfPIDFDIdentity()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Setenv("LISTEN_PIDFDID", strconv.FormatUint(own, 10)); err != nil {
			t.Fatal(err)
		}
		var original unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
			t.Fatal(err)
		}
		limited := original
		limited.Cur = 4 // Child-only: FD 3 works, but pidfd_open must fail EMFILE.
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limited); err != nil {
			t.Fatal(err)
		}
		restoreLimit = func() {
			if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
				t.Fatal(err)
			}
		}
		defer restoreLimit()
		lookup = func() (listenerIdentity, error) {
			t.Fatal("unverifiable PIDFD reached lookup")
			return listenerIdentity{}, nil
		}
	case "fd":
		if err := unix.Close(activationFD); err != nil {
			t.Fatal(err)
		}
	case "socket":
		fd, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Dup3(fd, activationFD, 0); err != nil {
			t.Fatal(err)
		}
		if err := unix.Close(fd); err != nil {
			t.Fatal(err)
		}
	case "lookup":
		lookup = func() (listenerIdentity, error) { return listenerIdentity{}, ErrPeerCredentials }
	case "path":
		original := lookup
		lookup = func() (listenerIdentity, error) { id, err := original(); id.path += ".wrong"; return id, err }
	case "metadata":
		if err := os.Chmod(os.Getenv("TEST_PATH"), 0666); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown failure case")
	}
	state := &acquisitionState{}
	if owner, err := acquireWorkerListener(state, lookup); owner != nil || !errors.Is(err, ErrActivation) {
		t.Fatal("first failure did not reject")
	}
	if restoreLimit != nil {
		restoreLimit()
	}
	assertActivationConsumed(t)
	setTestActivation(t)
	if owner, err := acquireWorkerListener(state, func() (listenerIdentity, error) {
		t.Fatal("failed attempt allowed another lookup")
		return listenerIdentity{}, nil
	}); owner != nil || !errors.Is(err, ErrActivation) {
		t.Fatal("failed attempt allowed retry")
	}
	assertTestActivationRetained(t)
	fmt.Println("failure consumed environment and attempt; retry untouched")
}
