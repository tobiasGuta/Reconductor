//go:build linux && amd64 && !exactcontainment_deployment

package exactcontainment

import (
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
	goruntime "runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
	"github.com/tobiasGuta/Reconductor/internal/exactsandbox"
	"golang.org/x/sys/unix"
)

var fixtureDir, helper string
var runtimes = map[string]string{}

func TestMain(m *testing.M) {
	if os.Getenv("RECONDUCTOR_CONTAINMENT_PARENT_HELPER") == "1" {
		os.Exit(m.Run())
	}
	var err error
	fixtureDir, err = os.MkdirTemp("/tmp", "reconductor-containment-")
	if err != nil {
		panic(err)
	}
	helper = filepath.Join(fixtureDir, "launcher")
	cmd := exec.Command("/usr/bin/cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-DRECONDUCTOR_TEST_IDENTITY", "-o", helper, "native/launcher.c")
	if b, e := cmd.CombinedOutput(); e != nil {
		fmt.Fprintf(os.Stderr, "launcher build: %v %s", e, b)
		os.RemoveAll(fixtureDir)
		os.Exit(1)
	}
	code := m.Run()
	if err = os.RemoveAll(fixtureDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}
func runtimeFixture(t *testing.T, mode string) string {
	t.Helper()
	if f := runtimes[mode]; f != "" {
		return f
	}
	path := filepath.Join(fixtureDir, "runtime-"+mode)
	cmd := exec.Command("/usr/bin/go", "build", "-buildvcs=false", "-trimpath", "-ldflags", "-X main.behavior="+mode+" -X main.sentinelRoot="+fixtureDir, "-o", path, "./testdata/offline")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GIT_OPTIONAL_LOCKS=0")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("fixture build: %v %s", e, b)
	}
	runtimes[mode] = path
	return path
}
func testArtifacts(t *testing.T, mode string) artifacts {
	t.Helper()
	a := artifacts{}
	var e error
	a.launcher, e = os.Open(helper)
	if e != nil {
		t.Fatal(e)
	}
	a.bwrap, e = openTrusted(bwrapPath, true, false)
	if e != nil {
		a.close()
		unavailable(t, e)
	}
	a.runtime, e = os.Open(runtimeFixture(t, mode))
	if e != nil {
		a.close()
		t.Fatal(e)
	}
	for _, f := range []*os.File{a.launcher, a.runtime} {
		if e = checkArtifact(f, true, f == a.runtime, false); e != nil {
			a.close()
			t.Fatal(e)
		}
	}
	path := filepath.Join(t.TempDir(), "policy")
	if e = os.WriteFile(path, seccompPolicy(), 0600); e != nil {
		t.Fatal(e)
	}
	source, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	a.filter, e = pinFilter(source)
	if e != nil {
		a.close()
		t.Fatal(e)
	}
	t.Cleanup(a.close)
	return a
}
func unavailable(t *testing.T, e error) {
	t.Helper()
	if os.Getenv("RECONDUCTOR_REQUIRE_CONTAINMENT") == "1" {
		t.Fatal("required containment unavailable:", e)
	}
	t.Skip("host lacks strict containment:", e)
}
func capable(t *testing.T) {
	t.Helper()
	a := testArtifacts(t, "normal")
	if e := probe(context.Background(), a); e != nil {
		unavailable(t, e)
	}
}
func fixtureCapsule(t *testing.T, large bool) ([]byte, string) {
	t.Helper()
	target := "/offline"
	if large {
		target = "/" + strings.Repeat("x", 8191)
	}
	a := exactaction.ActionContractV1{ContractVersion: exactaction.ContractVersion, ActionID: "A", Ownership: exactaction.Ownership{ProgramID: "P", TaskID: "T", WorkflowRunID: "W", StepRunID: "S", StepAttempt: 1}, Capability: exactaction.Capability{Name: "http.request", SemanticRevision: "v1"}, Request: exactaction.Request{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: target, Headers: []string{}}, Identity: exactaction.Identity{Kind: "anonymous"}, Limits: exactaction.Limits{MaxRequests: 1}}
	_, h, e := a.Freeze()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(map[string]any{"version": exactsandbox.ExecutionVersion, "provider_attempt_id": "X", "action_sha256": h, "authority_epoch": 2, "action": a})
	if e != nil {
		t.Fatal(e)
	}
	_, raw, _, _, e = canonicaljson.ParseStrictBounded(raw, exactsandbox.MaxExecutionBytes)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(append([]byte("reconductor-exact-sandbox-execution/v1\x00"), raw...))
	digest := hex.EncodeToString(sum[:])
	return raw, digest
}
func TestPositiveContainment(t *testing.T) {
	capable(t)
	for _, mode := range []string{"normal", "stderr-flood"} {
		t.Run(mode, func(t *testing.T) {
			a := testArtifacts(t, mode)
			a.testPipeCapacity = 4096
			raw, digest := fixtureCapsule(t, true)
			b, e := exchange(context.Background(), a, raw, digest)
			if e != nil {
				t.Fatal(e)
			}
			r, e := exactsandbox.DecodeResult(b, digest)
			if e != nil || r.Completed {
				t.Fatalf("offline result %v %v", r, e)
			}
		})
	}
}
func TestMalformedInputAndPublicBoundary(t *testing.T) {
	if _, e := ExecuteOffline(context.Background(), exactsandbox.EncodedExecution{}); !errors.Is(e, exactsandbox.ErrProtocol) {
		t.Fatal(e)
	}
	var nilContext context.Context
	if e := Preflight(nilContext); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if _, e := ExecuteOffline(nilContext, exactsandbox.EncodedExecution{}); !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := ExecuteOffline(ctx, exactsandbox.EncodedExecution{}); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	raw, digest := fixtureCapsule(t, false)
	for _, b := range [][]byte{nil, append(raw, '\n'), append(raw, raw...), make([]byte, 40961)} {
		if _, e := exchange(context.Background(), artifacts{}, b, digest); e == nil {
			t.Fatal("invalid input launched")
		}
	}
	if e := Preflight(context.Background()); !errors.Is(e, ErrUnavailable) {
		t.Fatal("ordinary test identity admitted", e)
	}
}
func TestMaliciousRuntime(t *testing.T) {
	capable(t)
	for _, mode := range []string{"ignore-input", "hang", "early-exit", "early-output", "fork-hang", "partial", "oversized", "malformed", "wrong-digest", "trailing", "multiple", "completed", "hold-output", "hold-after-eof"} {
		t.Run(mode, func(t *testing.T) {
			a := testArtifacts(t, mode)
			a.testPipeCapacity = 4096
			raw, digest := fixtureCapsule(t, true)
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			start := time.Now()
			b, e := exchange(ctx, a, raw, digest)
			if e == nil || b != nil {
				t.Fatalf("hostile runtime accepted %q %v", b, e)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("cleanup exceeded bound")
			}
			if mode == "hang" || mode == "ignore-input" || mode == "fork-hang" || mode == "hold-output" || mode == "hold-after-eof" {
				if !errors.Is(e, context.DeadlineExceeded) {
					t.Fatal("deadline lost", e)
				}
			}
		})
	}
}
func TestFDAndEnvironmentIsolation(t *testing.T) {
	capable(t)
	for _, k := range []string{"DATABASE_URL", "REDIS_URL", "API_KEY", "SSH_AUTH_SOCK", "LD_PRELOAD", "LISTEN_PID", "HOME", "PATH", "LANG", "XDG_RUNTIME_DIR"} {
		t.Setenv(k, "fake-authority-sentinel")
	}
	path := filepath.Join(fixtureDir, "authority")
	if e := os.WriteFile(path, []byte("harmless"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	d, e := os.Open(fixtureDir)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	sockets, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(sockets[0])
	defer unix.Close(sockets[1])
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	for i, fd := range []int{int(f.Fd()), int(d.Fd()), sockets[0], int(r.Fd())} {
		if e := unix.Dup3(fd, 400+i, 0); e != nil {
			t.Fatal(e)
		}
		defer unix.Close(400 + i)
	}
	var limit unix.Rlimit
	if e = unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); e != nil {
		t.Fatal(e)
	}
	if limit.Cur > 65537 {
		if e = unix.Dup3(int(f.Fd()), 65537, 0); e != nil {
			t.Fatal(e)
		}
		defer unix.Close(65537)
	}
	ns, e := os.Open("/proc/self/ns/user")
	if e != nil {
		t.Fatal(e)
	}
	defer ns.Close()
	if e = unix.Dup3(int(ns.Fd()), 404, 0); e != nil {
		t.Fatal(e)
	}
	defer unix.Close(404)
	a := testArtifacts(t, "normal")
	raw, digest := fixtureCapsule(t, false)
	if _, e = exchange(context.Background(), a, raw, digest); e != nil {
		t.Fatal(e)
	}
}
func TestRuntimeObjectPinning(t *testing.T) {
	capable(t)
	a := testArtifacts(t, "normal")
	path := filepath.Join(t.TempDir(), "runtime")
	b, e := os.ReadFile(runtimeFixture(t, "normal"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0755); e != nil {
		t.Fatal(e)
	}
	a.runtime.Close()
	a.runtime, e = os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	replacement, e := os.ReadFile(runtimeFixture(t, "early-exit"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path+".new", replacement, 0755); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(path, path+".pinned"); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(path+".new", path); e != nil {
		t.Fatal(e)
	}
	raw, digest := fixtureCapsule(t, false)
	if _, e = exchange(context.Background(), a, raw, digest); e != nil {
		t.Fatal("reopened replacement runtime", e)
	}
}
func TestFilterTrustAndNoFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filter")
	for _, b := range [][]byte{nil, make([]byte, 8), append(seccompPolicy(), 0), append([]byte{0}, seccompPolicy()[1:]...)} {
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		f, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		pin, e := pinFilter(f)
		f.Close()
		if pin != nil {
			pin.Close()
		}
		if e == nil {
			t.Fatal("wrong policy accepted")
		}
	}
	if e := os.WriteFile(path, seccompPolicy(), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	pin, e := pinFilter(f)
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	if _, e = pin.WriteAt([]byte{0}, 0); e != unix.EPERM && !errors.Is(e, unix.EPERM) {
		t.Fatal("policy not sealed", e)
	}
	capable(t)
	a := testArtifacts(t, "normal")
	a.filter.Close()
	if e = os.WriteFile(path, make([]byte, 8), 0600); e != nil {
		t.Fatal(e)
	}
	a.filter, e = os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = probe(context.Background(), a); e == nil {
		t.Fatal("invalid seccomp silently omitted")
	}
}
func TestArtifactRejections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	b, e := os.ReadFile(runtimeFixture(t, "normal"))
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []os.FileMode{0777, 0775, 04755, 06755, 0644} {
		if e = os.WriteFile(path, b, 0755); e != nil {
			t.Fatal(e)
		}
		if e = unix.Chmod(path, uint32(mode)); e != nil {
			t.Fatal(e)
		}
		f, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		e = checkArtifact(f, true, true, false)
		f.Close()
		if e == nil {
			t.Fatal("unsafe artifact mode accepted", mode)
		}
	}
	if _, e = openTrusted(path, true, true); e == nil {
		t.Fatal("untrusted temp parent admitted")
	}
	if _, e = openTrusted(bwrapPath+"/../bwrap", true, false); e == nil {
		t.Fatal("unclean path admitted")
	}
}

func TestNamespaceReportValidation(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("{}"), []byte(`{"child-pid":1}`), []byte(`{"child-pid":2,"net-namespace":0}`), make([]byte, 1025)} {
		if _, e := verifyNamespaceInfo(b); e == nil {
			t.Fatal("incomplete namespace report admitted")
		}
	}
	info := map[string]uint64{"child-pid": 2}
	for _, name := range []string{"pid", "net", "ipc", "uts", "mnt"} {
		var st unix.Stat_t
		if e := unix.Stat("/proc/self/ns/"+name, &st); e != nil {
			t.Fatal(e)
		}
		info[name+"-namespace"] = st.Ino
	}
	b, e := json.Marshal(info)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = verifyNamespaceInfo(b); e == nil {
		t.Fatal("shared host namespaces admitted")
	}
}

func TestCancellationAndIndependentTimeout(t *testing.T) {
	capable(t)
	for _, independent := range []bool{false, true} {
		t.Run(fmt.Sprint(independent), func(t *testing.T) {
			a := testArtifacts(t, "hang")
			raw, digest := fixtureCapsule(t, false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if !independent {
				go func() { time.Sleep(50 * time.Millisecond); cancel() }()
			}
			start := time.Now()
			b, e := exchange(ctx, a, raw, digest)
			want := context.Canceled
			if independent {
				want = context.DeadlineExceeded
			}
			if b != nil || !errors.Is(e, want) {
				t.Fatalf("wrong cancellation %q %v", b, e)
			}
			if time.Since(start) > maxLifetime+2*time.Second {
				t.Fatal("independent timeout exceeded bound")
			}
		})
	}
}

// The helper is a separate coordinator process: killing it cannot kill the
// test process. Only its own child monitor/namespace are observed and cleaned.
// It reports readiness only after the runtime emits a valid result following
// its containment audit, so the parent tests established post-setup behavior.
func TestCoordinatorProcess(t *testing.T) {
	if os.Getenv("RECONDUCTOR_CONTAINMENT_PARENT_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	launcher, e := os.Open(os.Getenv("CONTAINMENT_TEST_LAUNCHER"))
	if e != nil {
		t.Fatal(e)
	}
	defer launcher.Close()
	bwrap, e := openTrusted(bwrapPath, true, false)
	if e != nil {
		t.Fatal(e)
	}
	defer bwrap.Close()
	runtime, e := os.Open(os.Getenv("CONTAINMENT_TEST_RUNTIME"))
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close()
	fd, e := unix.MemfdCreate("parent-death-policy", unix.MFD_CLOEXEC)
	if e != nil {
		t.Fatal(e)
	}
	filter := os.NewFile(uintptr(fd), "policy")
	defer filter.Close()
	if _, e = filter.Write(seccompPolicy()); e != nil {
		t.Fatal(e)
	}
	if _, e = filter.Seek(0, 0); e != nil {
		t.Fatal(e)
	}
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	resultRead, resultWrite, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer resultRead.Close()
	defer resultWrite.Close()
	raw, digest := fixtureCapsule(t, false)
	expected, e := exactsandbox.EncodeResult(digest, false)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Stdout = resultWrite
	cmd.ExtraFiles = []*os.File{launcher, bwrap, runtime, filter, w}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	w.Close()
	resultWrite.Close()
	b, e := readBounded(r, 1024)
	if e != nil {
		t.Fatal(e)
	}
	// The hold-output fixture keeps stdout open after this bounded result. EOF
	// is deliberately not required here; readiness precedes coordinator death.
	result := make([]byte, len(expected))
	if _, e = io.ReadFull(resultRead, result); e != nil {
		t.Fatal(e)
	}
	if _, e = exactsandbox.DecodeResult(result, digest); e != nil || !bytes.Equal(result, expected) {
		t.Fatal("runtime did not establish post-setup readiness", e)
	}
	pid, e := verifyNamespaceInfo(b)
	if e != nil {
		t.Fatal(e)
	}
	record, _ := json.Marshal(map[string]int{"monitor": cmd.Process.Pid, "namespace_init": pid})
	if e = os.WriteFile(os.Getenv("CONTAINMENT_TEST_PID_RECORD"), record, 0600); e != nil {
		t.Fatal(e)
	}
	// Remain alive while our parent deliberately terminates this coordinator.
	cmd.Wait()
}

// TestCoordinatorDeathAfterSetup covers established parent-death behavior only.
// It does not cover Bubblewrap's pre-binding setup race or whole-unit cleanup.
func TestCoordinatorDeathAfterSetup(t *testing.T) {
	capable(t)
	record := filepath.Join(t.TempDir(), "pids.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCoordinatorProcess$")
	cmd.Env = append(os.Environ(), "RECONDUCTOR_CONTAINMENT_PARENT_HELPER=1", "CONTAINMENT_TEST_LAUNCHER="+helper, "CONTAINMENT_TEST_RUNTIME="+runtimeFixture(t, "hold-output"), "CONTAINMENT_TEST_PID_RECORD="+record)
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	var pids map[string]int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, e := os.ReadFile(record)
		if e == nil && json.Unmarshal(b, &pids) == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(pids) != 2 {
		t.Fatal("coordinator did not report contained namespace")
	}
	// The helper recorded these PIDs only after a validated runtime result;
	// setup is established without relying on a warm-up sleep.
	if e := cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	for name, pid := range pids {
		gone := false
		for i := 0; i < 100; i++ {
			b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
			if os.IsNotExist(e) || errors.Is(e, unix.ESRCH) {
				gone = true
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			fields := strings.Fields(string(b[strings.LastIndex(string(b), ")")+1:]))
			if len(fields) < 1 {
				t.Fatal("malformed procfs observation")
			}
			if fields[0] == "Z" || fields[0] == "X" {
				gone = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !gone {
			t.Fatalf("%s remains alive after coordinator death", name)
		}
	}
}

func TestHostFilesystemAndSocketAbsence(t *testing.T) {
	capable(t)
	for _, name := range []string{"repository", "authority", "artifact", "home", "run"} {
		if e := os.WriteFile(filepath.Join(fixtureDir, name), []byte("harmless host-only sentinel"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(fixtureDir, "control.sock"), Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	a := testArtifacts(t, "normal")
	raw, digest := fixtureCapsule(t, false)
	if _, e = exchange(context.Background(), a, raw, digest); e != nil {
		t.Fatal(e)
	}
}

func TestPolicyArtifact(t *testing.T) {
	b, e := os.ReadFile("native/exact-offline-x86_64.bpf")
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(b, seccompPolicy()) {
		t.Fatal("packaged policy differs from frozen internal program")
	}
	t.Logf("seccomp policy bytes=%d sha256=%x", len(b), sha256.Sum256(b))
}
