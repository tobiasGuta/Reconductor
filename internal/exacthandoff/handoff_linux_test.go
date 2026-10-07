//go:build linux

package exacthandoff

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
	"github.com/tobiasGuta/Reconductor/internal/exactsandbox"
	"golang.org/x/sys/unix"
)

// Only test infrastructure creates raw material. The transport seam lets these
// tests preserve the frozen opaque EncodedExecution constructor boundary.
func capsule(t *testing.T) ([]byte, string) {
	t.Helper()
	a := exactaction.ActionContractV1{ContractVersion: exactaction.ContractVersion, ActionID: "A", Ownership: exactaction.Ownership{ProgramID: "P", TaskID: "T", WorkflowRunID: "W", StepRunID: "S", StepAttempt: 1}, Capability: exactaction.Capability{Name: "http.request", SemanticRevision: "v1"}, Request: exactaction.Request{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/offline", Headers: []string{}}, Identity: exactaction.Identity{Kind: "anonymous"}, Limits: exactaction.Limits{MaxRequests: 1}}
	_, h, err := a.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"version": exactsandbox.ExecutionVersion, "provider_attempt_id": "X", "action_sha256": h, "authority_epoch": 2, "action": a})
	if err != nil {
		t.Fatal(err)
	}
	_, raw, _, _, err = canonicaljson.ParseStrictBounded(raw, exactsandbox.MaxExecutionBytes)
	if err != nil {
		t.Fatal(err)
	}
	s := receivedDigest(raw)
	if _, err := exactsandbox.DecodeExecution(raw, s); err != nil {
		t.Fatal(err)
	}
	return raw, s
}
func receivedDigest(raw []byte) string {
	sum := sha256.Sum256(append([]byte("reconductor-exact-sandbox-execution/v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}
func setup(t *testing.T) (*transport, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return &transport{listener: l, peer: &peerIdentity{uint32(os.Getuid()), uint32(os.Getgid())}}, path
}
func dial(path string) (*net.UnixConn, error) {
	return net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
}
func fixture(conn *net.UnixConn) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	raw, err := io.ReadAll(io.LimitReader(conn, exactsandbox.MaxExecutionBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > exactsandbox.MaxExecutionBytes {
		return exactsandbox.ErrProtocol
	}
	s := receivedDigest(raw)
	if _, err := exactsandbox.DecodeExecution(raw, s); err != nil {
		return err
	}
	result, err := exactsandbox.EncodeResult(s, false)
	if err != nil {
		return err
	}
	// Deliberately fragmented output exercises actual stream reassembly.
	for _, b := range result {
		if _, err := conn.Write([]byte{b}); err != nil {
			return err
		}
	}
	return conn.CloseWrite()
}
func startPeer(path string, behavior func(*net.UnixConn) error) <-chan error {
	done := make(chan error, 1)
	go func() {
		conn, err := dial(path)
		if err == nil {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			err = behavior(conn)
		}
		done <- err
	}()
	return done
}
func waitPeer(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("peer did not terminate")
	}
}
func response(t *testing.T, s string) []byte {
	t.Helper()
	b, err := exactsandbox.EncodeResult(s, false)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func readRequest(c *net.UnixConn) ([]byte, error) {
	return io.ReadAll(io.LimitReader(c, exactsandbox.MaxExecutionBytes+1))
}

func TestOneFrame(t *testing.T) {
	h, path := setup(t)
	raw, s := capsule(t)
	done := startPeer(path, fixture)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := h.exchange(ctx, raw, s)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := exactsandbox.DecodeResult(result, s)
	if err != nil || decoded.Completed {
		t.Fatalf("completion mismatch: %+v %v", decoded, err)
	}
	waitPeer(t, done)
	// A fresh independent invocation works after deadline restoration.
	done = startPeer(path, fixture)
	if _, err = h.exchange(ctx, raw, s); err != nil {
		t.Fatal(err)
	}
	waitPeer(t, done)
}

func TestUnavailableAndInvalidBeforeAccept(t *testing.T) {
	raw, s := capsule(t)
	var absent *transport
	if _, err := absent.exchange(context.Background(), raw, s); !errors.Is(err, errUnavailable) {
		t.Fatal(err)
	}
	h, path := setup(t)
	h.peer = nil
	if _, err := h.exchange(context.Background(), raw, s); !errors.Is(err, errUnavailable) {
		t.Fatal(err)
	}
	h.peer = &peerIdentity{uint32(os.Getuid()), uint32(os.Getgid())}
	peer, err := dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	for _, input := range [][]byte{nil, make([]byte, exactsandbox.MaxExecutionBytes+1)} {
		if _, err := h.exchange(context.Background(), input, s); !errors.Is(err, exactsandbox.ErrProtocol) {
			t.Fatal(err)
		}
	}
	if _, err := h.exchange(context.Background(), raw, "bad"); !errors.Is(err, exactsandbox.ErrProtocol) {
		t.Fatal(err)
	}
	if _, err := h.handoff(context.Background(), exactsandbox.EncodedExecution{}); !errors.Is(err, exactsandbox.ErrProtocol) {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	var b [1]byte
	if n, err := peer.Read(b[:]); n != 0 || !isTimeout(err) {
		t.Fatalf("invalid material acquired/sent: %d %v", n, err)
	}
}
func isTimeout(err error) bool { var e net.Error; return errors.As(err, &e) && e.Timeout() }

func TestMalformedMaterialBeforeAccept(t *testing.T) {
	valid, validS := capsule(t)
	decoded, err := exactsandbox.DecodeExecution(valid, validS)
	if err != nil {
		t.Fatal(err)
	}
	wrongBinding := bytes.Replace(valid, []byte(decoded.ActionSHA256()), []byte(strings.Repeat("0", 64)), 1)
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"malformed-json", []byte("{")},
		{"F1-canonical-schema-invalid", []byte("{}")},
		{"wrong-action-binding", wrongBinding},
	} {
		t.Run(test.name, func(t *testing.T) {
			h, path := setup(t)
			peer, err := dial(path)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			s := receivedDigest(test.raw) // Correct matching S, including the original F1 input.
			if _, err := exactsandbox.DecodeExecution(test.raw, s); !errors.Is(err, exactsandbox.ErrProtocol) {
				t.Fatalf("invalid-material precondition: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if result, err := h.exchange(ctx, test.raw, s); result != nil || !errors.Is(err, exactsandbox.ErrProtocol) {
				t.Fatalf("invalid material accepted: %q %v", result, err)
			}
			if err := peer.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if n, err := peer.Read(b[:]); n != 0 || !isTimeout(err) {
				t.Fatalf("invalid material emitted bytes or retired peer: %d %v", n, err)
			}
			// There is exactly one queued peer. Manually accepting it afterward
			// proves exchange never reached Accept; zero output alone would not.
			if err := h.listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			untouched, err := h.listener.AcceptUnix()
			if err != nil {
				t.Fatalf("invalid material consumed queued peer capacity: %v", err)
			}
			defer untouched.Close()
			if err := h.listener.SetDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestExactTransportBounds(t *testing.T) {
	// Inclusive transport ceilings are separate from closed canonical grammar.
	// 40960 synthetic bytes are NOT claimed to be a valid EncodedExecution;
	// likewise 256 bytes must still pass frozen result grammar (and do not here).
	h, path := setup(t)
	raw := bytes.Repeat([]byte{'x'}, exactsandbox.MaxExecutionBytes)
	s := receivedDigest(raw)
	done := startPeer(path, func(c *net.UnixConn) error {
		got, err := readRequest(c)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, raw) {
			return errors.New("inclusive request limit lost bytes")
		}
		b := response(t, s)
		if err := writeAll(c, b); err != nil {
			return err
		}
		return c.CloseWrite()
	})
	// Only the lower claimed-connection IO helper receives synthetic bytes.
	// The invocation seam must reject them before accepting any capacity.
	if err := h.listener.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	conn, err := h.listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := h.listener.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	state := attempt{claimed: true}
	if _, err := transfer(ctx, conn, *h.peer, raw, s, &state); err != nil {
		t.Fatal(err)
	}
	waitPeer(t, done)
	for _, size := range []int{exactsandbox.MaxResultBytes, exactsandbox.MaxResultBytes + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			h, path := setup(t)
			raw, s := capsule(t)
			done := startPeer(path, func(c *net.UnixConn) error {
				if _, err := readRequest(c); err != nil {
					return err
				}
				if err := writeAll(c, bytes.Repeat([]byte{'x'}, size)); err != nil {
					return err
				}
				return c.CloseWrite()
			})
			b, err := h.exchange(context.Background(), raw, s)
			if b != nil || !errors.Is(err, exactsandbox.ErrProtocol) {
				t.Fatalf("bad result accepted: %q %v", b, err)
			}
			var failure *attemptError
			if !errors.As(err, &failure) {
				t.Fatal(err)
			}
			want := "result EOF"
			if size == exactsandbox.MaxResultBytes {
				want = "result validation"
			}
			if failure.phase != want {
				t.Fatalf("limit vs grammar: %s", failure.phase)
			}
			waitPeer(t, done)
		})
	}
}

type fragmentWriter struct {
	state *attempt
	bytes.Buffer
	calls, limit, failAt int
}

func (w *fragmentWriter) Write(b []byte) (int, error) {
	if !w.state.emissionBegun {
		return 0, errors.New("unrecorded emission")
	}
	w.calls++
	if w.failAt > 0 && w.calls == w.failAt {
		return 0, io.ErrClosedPipe
	}
	if len(b) > w.limit {
		b = b[:w.limit]
	}
	return w.Buffer.Write(b)
}
func TestPartialEmission(t *testing.T) {
	for _, failAt := range []int{0, 1, 3} {
		state := attempt{claimed: true}
		w := &fragmentWriter{state: &state, limit: 7, failAt: failAt}
		raw := bytes.Repeat([]byte{'a'}, 100)
		err := emit(w, raw, &state)
		if failAt == 0 {
			if err != nil || !bytes.Equal(w.Bytes(), raw) || w.calls != 15 {
				t.Fatalf("partial writes: %d %v", w.calls, err)
			}
		} else {
			if !errors.Is(err, io.ErrClosedPipe) || w.calls != failAt || w.Len() != (failAt-1)*7 {
				t.Fatalf("restarted/retried: %d %d %v", w.calls, w.Len(), err)
			}
		}
	}
}

func TestHostileResults(t *testing.T) {
	for _, mode := range []string{"exit-after-request", "close-before-result", "malformed", "wrong-S", "trailing", "no-response-EOF", "early-overflow"} {
		t.Run(mode, func(t *testing.T) {
			h, path := setup(t)
			raw, s := capsule(t)
			valid := response(t, s)
			sent := make(chan struct{})
			release := make(chan struct{})
			done := startPeer(path, func(c *net.UnixConn) error {
				if mode == "early-overflow" {
					_, _ = c.Write(bytes.Repeat([]byte{'x'}, 257))
					_ = c.CloseWrite()
					return nil
				}
				got, err := readRequest(c)
				if err != nil {
					return err
				}
				if !bytes.Equal(got, raw) {
					return errors.New("request changed")
				}
				switch mode {
				case "exit-after-request", "close-before-result":
					return nil
				case "malformed":
					_, err = c.Write([]byte("{}"))
				case "wrong-S":
					_, err = c.Write(response(t, strings.Repeat("0", 64)))
				case "trailing":
					_, err = c.Write(append(valid, '\n'))
				case "no-response-EOF":
					if _, err := c.Write(valid); err != nil {
						return err
					}
					close(sent)
					<-release
					return nil
				}
				if err != nil {
					return err
				}
				return c.CloseWrite()
			})
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				b, err := h.exchange(ctx, raw, s)
				if b != nil || err == nil {
					finished <- errors.New("hostile result accepted")
					return
				}
				finished <- err
			}()
			if mode == "no-response-EOF" {
				select {
				case <-sent:
				case <-time.After(time.Second):
					t.Fatal("peer stalled")
				}
				select {
				case err := <-finished:
					t.Fatalf("accepted/rejected before EOF: %v", err)
				case <-time.After(20 * time.Millisecond):
				}
				cancel()
				close(release)
			}
			err := <-finished
			if mode == "no-response-EOF" {
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			} else if !errors.Is(err, exactsandbox.ErrProtocol) && mode != "early-overflow" {
				t.Fatal(err)
			}
			waitPeer(t, done)
		})
	}
}

func TestNoPeerAndAcceptCancellation(t *testing.T) {
	for _, mode := range []string{"before", "during", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			h, path := setup(t)
			raw, s := capsule(t)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
			if mode == "before" {
				cancel()
			}
			done := make(chan error, 1)
			go func() { _, err := h.exchange(ctx, raw, s); done <- err }()
			if mode == "during" {
				waitActive(t, h)
				cancel()
			}
			err := <-done
			cancel()
			want := context.Canceled
			if mode == "deadline" {
				want = context.DeadlineExceeded
			}
			if !errors.Is(err, want) {
				t.Fatal(err)
			}
			peer := startPeer(path, fixture)
			if _, err := h.exchange(context.Background(), raw, s); err != nil {
				t.Fatalf("old deadline poisoned next attempt: %v", err)
			}
			waitPeer(t, peer)
		})
	}
}
func waitActive(t *testing.T, h *transport) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !h.active.Load() {
		if time.Now().After(deadline) {
			t.Fatal("invocation did not start")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPeerClosesBeforeAndDuringRequest(t *testing.T) {
	for _, mode := range []string{"before-request", "during-request"} {
		t.Run(mode, func(t *testing.T) {
			h, path := setup(t)

			raw, s := capsule(t)
			ready := make(chan struct{})
			release := make(chan struct{})
			done := startPeer(path, func(c *net.UnixConn) error {
				if mode == "before-request" {
					_ = c.CloseRead()
					close(ready)
					<-release
					return nil
				}
				var b [1]byte
				if _, err := io.ReadFull(c, b[:]); err != nil {
					return err
				}
				close(ready)
				if mode == "during-request" {
					return nil
				}
				<-release
				return nil
			})
			if mode == "before-request" {
				<-ready
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				b, err := h.exchange(ctx, raw, s)
				if b != nil || err == nil {
					finished <- errors.New("failed input accepted")
				} else {
					finished <- err
				}
			}()
			err := <-finished
			if mode == "before-request" {
				close(release)
			}
			var failure *attemptError
			if !errors.As(err, &failure) || !failure.claimed || !failure.emissionBegun {
				t.Fatalf("wrong emission state: %+v %v", failure, err)
			}
			waitPeer(t, done)
		})
	}
}

func TestCancellationDuringBlockedWrite(t *testing.T) {
	h, path := setup(t)
	peer, err := dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := h.listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetWriteBuffer(4096); err != nil {
		t.Fatal(err)
	}
	raw := bytes.Repeat([]byte{'x'}, exactsandbox.MaxExecutionBytes)
	state := attempt{claimed: true}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := transfer(ctx, conn, *h.peer, raw, receivedDigest(raw), &state); done <- err }()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := io.ReadFull(peer, b[:]); err != nil {
		t.Fatal(err)
	}
	// No result is supplied. The tiny accepted send buffer cannot hold the rest.
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("write survived cancellation")
	}
	if !state.emissionBegun || state.phase != "emission" {
		t.Fatalf("write did not block: %+v", state)
	}
}

func TestConcurrentInvocationAndReadCancellation(t *testing.T) {
	h, path := setup(t)
	raw, s := capsule(t)
	received := make(chan struct{})
	release := make(chan struct{})
	peer := startPeer(path, func(c *net.UnixConn) error {
		if _, err := readRequest(c); err != nil {
			return err
		}
		close(received)
		<-release
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := h.exchange(ctx, raw, s); done <- err }()
	<-received
	if _, err := h.exchange(context.Background(), raw, s); !errors.Is(err, errBusy) {
		t.Fatalf("concurrent invocation admitted: %v", err)
	}
	cancel()
	err := <-done
	close(release)
	waitPeer(t, peer)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var failure *attemptError
	if !errors.As(err, &failure) || failure.phase != "result EOF" {
		t.Fatal(err)
	}
}

func TestCredentialsAndRetirementBeforeEmission(t *testing.T) {
	for _, field := range []string{"uid", "gid"} {
		t.Run(field, func(t *testing.T) {
			h, path := setup(t)
			raw, s := capsule(t)
			if field == "uid" {
				h.peer.uid++
			} else {
				h.peer.gid++
			}
			peer, err := dial(path)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := h.exchange(ctx, raw, s); !errors.Is(err, errPeer) {
				t.Fatal(err)
			} else {
				var f *attemptError
				if !errors.As(err, &f) || !f.claimed || f.emissionBegun {
					t.Fatalf("wrong retirement: %+v", f)
				}
			}
			var b [1]byte
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			if n, err := peer.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("rejected peer received input: %d %v", n, err)
			}
			assertIdleReconnect(t, path)
		})
	}
}
func assertIdleReconnect(t *testing.T, path string) {
	t.Helper()
	c, err := dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	var b [1]byte
	if n, err := c.Read(b[:]); n != 0 || !isTimeout(err) {
		t.Fatalf("reconnect received historical work: %d %v", n, err)
	}
}

func TestAmbiguityNeverReplays(t *testing.T) {
	h, path := setup(t)
	raw, s := capsule(t)
	peer := startPeer(path, func(c *net.UnixConn) error {
		got, err := readRequest(c)
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, got) {
			return errors.New("first delivery changed")
		}
		return nil
	})
	b, err := h.exchange(context.Background(), raw, s)
	if b != nil || err == nil {
		t.Fatal("lost result accepted")
	}
	waitPeer(t, peer)
	assertIdleReconnect(t, path) // No second invocation, reconnect or resend.
}
func TestConnectionCannotBeReused(t *testing.T) {
	h, path := setup(t)
	raw, s := capsule(t)
	done := startPeer(path, func(c *net.UnixConn) error {
		if _, err := readRequest(c); err != nil {
			return err
		}
		if err := writeAll(c, response(t, s)); err != nil {
			return err
		}
		if err := c.CloseWrite(); err != nil {
			return err
		}
		// Its request direction already reached EOF. A second frame never appears;
		// the Broker fully closes after validating the one result.
		var b [1]byte
		n, err := c.Read(b[:])
		if n != 0 || !errors.Is(err, io.EOF) {
			return errors.New("connection reused")
		}
		return nil
	})
	if _, err := h.exchange(context.Background(), raw, s); err != nil {
		t.Fatal(err)
	}
	waitPeer(t, done)
	assertIdleReconnect(t, path)
}

func TestRequestEOFAndPermanentClose(t *testing.T) {
	h, path := setup(t)
	raw, s := capsule(t)
	peer := startPeer(path, fixture)
	conn, err := h.listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeAll(conn, raw); err != nil {
		t.Fatal(err)
	}
	// Complete bytes alone must not release a fixture result before request EOF.
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	var b [1]byte
	if n, err := conn.Read(b[:]); n != 0 || !isTimeout(err) {
		t.Fatalf("fixture responded without request EOF: %d %v", n, err)
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	result, err := readResult(conn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exactsandbox.DecodeResult(result, s); err != nil {
		t.Fatal(err)
	}
	waitPeer(t, peer)

	// The production claimed-connection helper closes its own FD on success.
	peer = startPeer(path, fixture)
	claimed, err := h.listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer claimed.Close()
	state := attempt{claimed: true}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := transfer(ctx, claimed, *h.peer, raw, s, &state); err != nil {
		t.Fatal(err)
	}
	waitPeer(t, peer)
	if _, err := claimed.Write(raw); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("claimed connection remained reusable: %v", err)
	}
}

func TestFragmentedResultReads(t *testing.T) {
	h, path := setup(t)
	_, s := capsule(t)
	valid := response(t, s)
	peer, err := dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := h.listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	type outcome struct {
		b   exactsandbox.EncodedResult
		err error
	}
	done := make(chan outcome, 1)
	go func() { b, err := readResult(conn); done <- outcome{b, err} }()
	if err := writeAll(peer, valid[:17]); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		t.Fatalf("partial result returned: %q %v", got.b, got.err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := writeAll(peer, valid[17:]); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if got.err != nil || !bytes.Equal(got.b, valid) {
		t.Fatalf("fragmented result changed: %q %v", got.b, got.err)
	}
}

func TestAncillaryCleanupKeepsValidPrefix(t *testing.T) {
	sentinel, err := os.CreateTemp(t.TempDir(), "sentinel")
	if err != nil {
		t.Fatal(err)
	}
	defer sentinel.Close()
	fd, err := unix.Dup(int(sentinel.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	// These bytes model a received valid SCM_RIGHTS followed by a bad suffix.
	control := append(unix.UnixRights(fd), make([]byte, unix.CmsgLen(0))...)
	closeRights(control)
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		_ = unix.Close(fd)
		t.Fatalf("valid rights prefix leaked: %v", err)
	}
}

func TestAncillaryRejectedAndClosed(t *testing.T) {
	for _, count := range []int{1, 253} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			h, path := setup(t)
			raw, s := capsule(t)
			sentinel, err := os.CreateTemp(t.TempDir(), "sentinel")
			if err != nil {
				t.Fatal(err)
			}
			defer sentinel.Close()
			info, err := sentinel.Stat()
			if err != nil {
				t.Fatal(err)
			}
			fds := make([]int, count)
			for i := range fds {
				fds[i] = int(sentinel.Fd())
			}
			done := startPeer(path, func(c *net.UnixConn) error {
				if _, err := readRequest(c); err != nil {
					return err
				}
				_, _, err := c.WriteMsgUnix(response(t, s), unix.UnixRights(fds...), nil)
				return err
			})
			b, err := h.exchange(context.Background(), raw, s)
			if b != nil || !errors.Is(err, errAncillary) {
				t.Fatalf("rights accepted: %q %v", b, err)
			}
			waitPeer(t, done)
			entries, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			matching := 0
			for _, entry := range entries {
				stat, err := os.Stat(filepath.Join("/proc/self/fd", entry.Name()))
				if err == nil && os.SameFile(info, stat) {
					matching++
				}
			}
			if matching != 1 {
				t.Fatalf("received descriptors leaked: %d aliases", matching)
			}
		})
	}
}

// This process is a harmless receiver only. Its pathname is test-driver
// infrastructure, not capsule metadata. It does no discovery, child execution
// or network IO beyond the local Unix control channel. It connects empty-handed.
func TestSameUIDPeerProcess(t *testing.T) {
	path := os.Getenv("RECONDUCTOR_HANDOFF_TEST_SOCKET")
	if path == "" {
		return
	}
	c, err := dial(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	var b [1]byte
	if n, err := c.Read(b[:]); n != 0 || !isTimeout(err) {
		t.Fatalf("connection alone received work: %d %v", n, err)
	}
	fmt.Fprintln(os.Stdout, "idle")
	_ = c.SetReadDeadline(time.Time{})
	if err := fixture(c); err != nil {
		t.Fatal(err)
	}
}
func TestSameUIDAlternateProcess(t *testing.T) {
	h, path := setup(t)
	raw, s := capsule(t)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestSameUIDPeerProcess$")
	cmd.Env = []string{"RECONDUCTOR_HANDOFF_TEST_SOCKET=" + path, "GORACE=atexit_sleep_ms=0"}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Always reap the alternate process, including test failures.
	waited := false
	defer func() {
		if !waited {
			cancel()
			_ = cmd.Wait()
		}
	}()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "idle" {
		t.Fatal("alternate process did not remain idle")
	}
	if _, err := h.exchange(ctx, raw, s); err != nil {
		t.Fatal(err)
	}
	// Drain test harness output before Wait, avoiding pipe backpressure.
	_, _ = io.Copy(io.Discard, stdout)
	err = cmd.Wait()
	waited = true
	if err != nil {
		t.Fatalf("alternate process: %v %s", err, stderr.String())
	}
}
