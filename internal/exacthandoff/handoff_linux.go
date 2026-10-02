//go:build linux

package exacthandoff

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/exactsandbox"
	"golang.org/x/sys/unix"
)

const maxHandoffTime = 5 * time.Second

var (
	errUnavailable = errors.New("exact handoff infrastructure unavailable")
	errBusy        = errors.New("exact handoff already active")
	errPeer        = errors.New("exact handoff peer credentials rejected")
	errAncillary   = errors.New("exact handoff ancillary data rejected")
)

// These inputs are trusted infrastructure, never request fields. There is no
// exported construction path until dedicated identity provisioning is reviewed.
type peerIdentity struct{ uid, gid uint32 }
type transport struct {
	listener *net.UnixListener
	peer     *peerIdentity
	active   atomic.Bool
}

// attempt is local to one invocation. No material or retry state lives on the
// transport. Emission is recorded BEFORE the first write, even if it fails.
type attempt struct {
	claimed       bool
	emissionBegun bool
	phase         string
}
type attemptError struct {
	attempt
	cause error
}

func (e *attemptError) Error() string {
	return fmt.Sprintf("exact handoff %s failed: %v", e.phase, e.cause)
}
func (e *attemptError) Unwrap() error { return e.cause }

// handoff is the only execution-material entry point. It deliberately is not a
// Run method and cannot satisfy exactsandbox.Runner. Decoding cannot construct
// its opaque input. No public raw-byte submission API exists.
func (h *transport) handoff(ctx context.Context, execution exactsandbox.EncodedExecution) (exactsandbox.EncodedResult, error) {
	return h.exchange(ctx, execution.Bytes(), execution.Digest())
}

// exchange is the private validated invocation seam: handoff supplies frozen
// bytes and its independently retained S. Material validation precedes Accept
// even for package-local callers. Pure synthetic IO tests use transfer below
// this gate. Validation grants no authority or permission to retry.
func (h *transport) exchange(parent context.Context, input []byte, expectedS string) (result exactsandbox.EncodedResult, err error) {
	if h == nil || h.listener == nil || h.peer == nil {
		return nil, errUnavailable
	}
	if !h.active.CompareAndSwap(false, true) {
		return nil, errBusy
	}
	defer h.active.Store(false)
	if len(input) == 0 || len(input) > exactsandbox.MaxExecutionBytes {
		return nil, exactsandbox.ErrProtocol
	}
	// Validate the retained digest before acquiring capacity, without deriving it
	// from any peer message. EncodeResult also enforces its exact frozen syntax.
	if _, err := exactsandbox.EncodeResult(expectedS, false); err != nil {
		return nil, err
	}
	if _, err := exactsandbox.DecodeExecution(input, expectedS); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, maxHandoffTime)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err := h.listener.SetDeadline(deadline); err != nil {
		return nil, err
	}

	var conn *net.UnixConn
	state := attempt{phase: "accept"}
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = h.listener.SetDeadline(time.Now())
		close(canceled)
	})
	// Join cancellation before restoring the listener and releasing the serial
	// guard, so an old callback can never poison the next invocation's deadline.
	defer func() {
		if !stop() {
			<-canceled
		}
		if conn != nil {
			_ = conn.Close()
		}
		restoreErr := h.listener.SetDeadline(time.Time{})
		if err == nil && restoreErr != nil {
			result, err = nil, restoreErr
		}
		if !time.Now().Before(deadline) {
			err = context.DeadlineExceeded
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			result = nil
			err = &attemptError{attempt: state, cause: err}
		}
	}()

	// Exactly one accept call. Authentication or IO failure retires this selected
	// connection; there is deliberately no loop choosing replacement capacity.
	accepted, acceptErr := h.listener.AcceptUnix()
	if acceptErr != nil {
		return nil, acceptErr
	}
	conn = accepted
	state.claimed = true
	return transfer(ctx, conn, *h.peer, input, expectedS, &state)
}

// transfer is the private claimed-connection portion of one invocation. Tests
// may reduce socket buffers here to force actual kernel write backpressure.
func transfer(ctx context.Context, conn *net.UnixConn, peer peerIdentity, input []byte, expectedS string, state *attempt) (result exactsandbox.EncodedResult, err error) {
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
		_ = conn.Close()
		if ctx.Err() != nil {
			result, err = nil, ctx.Err()
		}
	}()
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errUnavailable
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state.phase = "credentials"
	if err := authenticate(conn, peer); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state.phase = "emission"
	if err := emit(conn, input, state); err != nil {
		return nil, err
	}
	state.phase = "request EOF"
	if err := conn.CloseWrite(); err != nil {
		return nil, err
	}
	state.phase = "result EOF"
	raw, readErr := readResult(conn)
	if readErr != nil {
		return nil, readErr
	}
	state.phase = "result validation"
	if _, err := exactsandbox.DecodeResult(raw, expectedS); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state.phase = "close"
	if err := conn.Close(); err != nil {
		return nil, err
	}
	return raw, nil
}

func authenticate(conn *net.UnixConn, expected peerIdentity) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	if cred == nil || cred.Uid != expected.uid || cred.Gid != expected.gid {
		return errPeer
	}
	return nil
}

func emit(w io.Writer, input []byte, state *attempt) error {
	state.emissionBegun = true
	return writeAll(w, input)
}

func writeAll(w io.Writer, input []byte) error {
	for len(input) > 0 {
		n, err := w.Write(input)
		if n < 0 || n > len(input) {
			return io.ErrShortWrite
		}
		input = input[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// readResult requires EOF, with one overflow byte, and never retains a received
// descriptor. Linux limits SCM_RIGHTS to 253 FDs per message; this control buffer
// covers that maximum. Truncation is rejected as well. The kernel closes rights
// it cannot deliver into the supplied buffer; delivered rights are closed here.
func readResult(conn *net.UnixConn) (exactsandbox.EncodedResult, error) {
	buf := make([]byte, exactsandbox.MaxResultBytes+1)
	oob := make([]byte, unix.CmsgSpace(253*4))
	used := 0
	for {
		n, oobn, flags, _, err := conn.ReadMsgUnix(buf[used:], oob)
		if oobn > 0 || flags&unix.MSG_CTRUNC != 0 {
			closeRights(oob[:oobn])
			return nil, errAncillary
		}
		used += n
		if used > exactsandbox.MaxResultBytes {
			return nil, exactsandbox.ErrProtocol
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return exactsandbox.EncodedResult(buf[:used]), nil
			}
			return nil, err
		}
	}
}

func closeRights(oob []byte) {
	// Parse incrementally so a rejected/truncated suffix cannot suppress cleanup
	// of descriptors in a preceding valid control message. Kernel-delivered rights
	// contain whole int32 descriptors; ignore only an incomplete trailing padding.
	for len(oob) >= unix.CmsgLen(0) {
		header, data, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return
		}
		if header.Level == unix.SOL_SOCKET && header.Type == unix.SCM_RIGHTS {
			message := unix.SocketControlMessage{Header: header, Data: data[:len(data)/4*4]}
			fds, _ := unix.ParseUnixRights(&message)
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
		}
		oob = rest
	}
}
