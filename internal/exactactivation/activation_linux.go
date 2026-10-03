//go:build linux

package exactactivation

import (
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const activationFD = 3 // SD_LISTEN_FDS_START; never configurable.

// WorkerListener owns capacity only. No Accept, deadline, raw-FD, material or
// execution API is exposed in this slice. Close neither unlinks the pathname
// nor calls shutdown on the socket shared with PID1.
type WorkerListener struct{ file *os.File }

func (l *WorkerListener) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

type activationEnvironment struct {
	pid, count, name, pidfdID string
	pidfdPresent              bool
}
type acquisitionState struct{ claimed atomic.Bool }

var processAcquisition acquisitionState

type listenerIdentity struct {
	path, parentRoot string
	owner, group     uint32
}

// AcquireWorkerListener must be called before any child-spawning startup work.
// Exactly one attempt is permitted per process, even when it fails. A future
// worker integration must retain the owner until shutdown, without accepting
// during startup. Concurrent or repeated callers fail without touching inputs.
func AcquireWorkerListener() (*WorkerListener, error) {
	return acquireWorkerListener(&processAcquisition, func() (listenerIdentity, error) {
		identity, err := resolvePeerIdentity()
		return listenerIdentity{path: ListenerPath, parentRoot: "/", owner: 0, group: identity.gid}, err
	})
}

// Tests supply isolated state and the existing private deployment lookup seam;
// production always uses the process-global state and fixed deployment lookup.
func acquireWorkerListener(state *acquisitionState, lookup func() (listenerIdentity, error)) (*WorkerListener, error) {
	if !state.claimed.CompareAndSwap(false, true) {
		return nil, ErrActivation
	}
	pidfdID, present := os.LookupEnv("LISTEN_PIDFDID")
	env := activationEnvironment{
		pid: os.Getenv("LISTEN_PID"), count: os.Getenv("LISTEN_FDS"),
		name: os.Getenv("LISTEN_FDNAMES"), pidfdID: pidfdID, pidfdPresent: present,
	}
	// Consume the activation environment even on rejection; do not propagate it
	// to provider subprocesses. Losing callers never read or clear these values.
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PIDFDID"} {
		if err := os.Unsetenv(name); err != nil {
			return nil, ErrActivation
		}
	}
	return acquireActivation(env, os.Getpid(), lookup)
}

// Private lookup seam lets tests use a temporary subtree without provisioning
// accounts or root-owned /run paths. The descriptor is still fixed at 3.
func acquireActivation(env activationEnvironment, pid int, lookup func() (listenerIdentity, error)) (*WorkerListener, error) {
	if err := validateActivationEnvironment(env, pid); err != nil {
		return nil, err
	}
	// Set and verify CLOEXEC before identity lookup, filesystem inspection, or
	// ownership transfer. No child-spawning checks may precede this operation.
	if err := protectDescriptor(activationFD); err != nil {
		return nil, err
	}
	if err := verifyActivationPIDFD(env, selfPIDFDIdentity); err != nil {
		return nil, err
	}
	identity, err := lookup()
	if err != nil {
		return nil, ErrActivation
	}
	return acquireListener(activationFD, identity)
}

func validateActivationEnvironment(env activationEnvironment, pid int) error {
	if pid < 1 || env.pid != strconv.Itoa(pid) || env.count != "1" || env.name != DescriptorName {
		return ErrActivation
	}
	if env.pidfdPresent {
		_, err := parsePIDFDIdentity(env.pidfdID)
		return err
	}
	return nil
}

func parsePIDFDIdentity(value string) (uint64, error) {
	id, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(id, 10) != value {
		return 0, ErrActivation
	}
	return id, nil
}

func verifyActivationPIDFD(env activationEnvironment, self func() (uint64, error)) error {
	if !env.pidfdPresent {
		return nil
	}
	id, err := parsePIDFDIdentity(env.pidfdID)
	if err != nil {
		return err
	}
	own, err := self()
	if err != nil || id != own {
		return ErrActivation
	}
	return nil
}

// systemd 259 supplies the process's pidfs inode identity, not its numeric PID.
// Older anonymous-inode pidfds cannot establish that identity and reject when
// it is supplied. Go's Linux Stat_t.Ino (including fstat64 bindings) is uint64.
func selfPIDFDIdentity() (uint64, error) {
	fd, err := unix.PidfdOpen(os.Getpid(), 0) // kernel creates this CLOEXEC
	if err != nil {
		return 0, ErrActivation
	}
	defer unix.Close(fd)
	if err := protectDescriptor(fd); err != nil {
		return 0, err
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.PID_FS_MAGIC {
		return 0, ErrActivation
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return 0, ErrActivation
	}
	return stat.Ino, nil
}

func protectDescriptor(fd int) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return ErrActivation
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
		return ErrActivation
	}
	flags, err = unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		return ErrActivation
	}
	return nil
}

// acquireListener is a package-private seam for temporary unprivileged sockets.
// Production supplies only descriptor 3 and the fixed root-owned identity.
// Ownership transfers only on success; rejection leaves the descriptor CLOEXEC.
func acquireListener(fd int, identity listenerIdentity) (*WorkerListener, error) {
	if err := protectDescriptor(fd); err != nil {
		return nil, err
	}
	if err := validateListener(fd, identity); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "exact-activated-listener")
	if file == nil {
		return nil, ErrActivation
	}
	return &WorkerListener{file: file}, nil
}

func validateListener(fd int, identity listenerIdentity) error {
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil || domain != unix.AF_UNIX {
		return ErrActivation
	}
	kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_STREAM {
		return ErrActivation
	}
	listening, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil || listening != 1 {
		return ErrActivation
	}
	address, err := unix.Getsockname(fd)
	name, ok := address.(*unix.SockaddrUnix)
	if err != nil || !ok || name.Name != identity.path || !filepath.IsAbs(identity.path) || filepath.Clean(identity.path) != identity.path {
		return ErrActivation
	}
	// The named node is separate from the socket FD's sockfs inode. Never equate
	// those inode numbers. Protected parents forbid unprivileged replacement;
	// concurrent privileged deployment changes are outside this intake contract.
	var node unix.Stat_t
	if err := unix.Lstat(identity.path, &node); err != nil || node.Mode&unix.S_IFMT != unix.S_IFSOCK || node.Mode&07777 != 0660 || node.Uid != identity.owner || node.Gid != identity.group {
		return ErrActivation
	}
	for parent := filepath.Dir(identity.path); ; parent = filepath.Dir(parent) {
		var dir unix.Stat_t
		if err := unix.Lstat(parent, &dir); err != nil || dir.Mode&unix.S_IFMT != unix.S_IFDIR || dir.Uid != identity.owner || dir.Mode&0022 != 0 {
			return ErrActivation
		}
		if parent == identity.parentRoot {
			break
		}
		if parent == "/" {
			return ErrActivation
		}
	}
	return nil
}
