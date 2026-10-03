//go:build linux

package exactprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
	"github.com/tobiasGuta/Reconductor/internal/exactsandbox"
	"golang.org/x/sys/unix"
)

var fixtureDir, fixtureRuntime string
var fixtureHelpers = map[string]string{}

func TestMain(m *testing.M) {
	var err error
	fixtureDir, err = os.MkdirTemp("/tmp", "reconductor-4b3-fixture-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fixtureRuntime = filepath.Join(fixtureDir, "offline-runtime")
	cmd := exec.Command("/usr/bin/go", "build", "-buildvcs=false", "-o", fixtureRuntime, "./testdata/offline")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GIT_OPTIONAL_LOCKS=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "offline fixture build: %v\n%s", err, b)
		os.RemoveAll(fixtureDir)
		os.Exit(1)
	}
	code := m.Run()
	if err := os.RemoveAll(fixtureDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}

func compileHelper(t *testing.T, mode string, descendant bool) string {
	t.Helper()
	key := fmt.Sprintf("%s-%t", mode, descendant)
	if path := fixtureHelpers[key]; path != "" {
		return path
	}
	path := filepath.Join(fixtureDir, "launcher-"+key)
	args := []string{"-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-o", path, "native/launcher.c"}
	if mode != "preflight" {
		args = append(args, "-DRECONDUCTOR_TEST_RUNTIME="+strconv.Quote(fixtureRuntime), "-DRECONDUCTOR_TEST_BEHAVIOR="+strconv.Quote(mode))
	}
	if descendant {
		args = append(args, "-DRECONDUCTOR_TEST_DESCENDANT=1")
	}
	if b, err := exec.Command("/usr/bin/cc", args...).CombinedOutput(); err != nil {
		t.Fatalf("native boundary build: %v\n%s", err, b)
	}
	fixtureHelpers[key] = path
	return path
}

func fixtureCapsule(t *testing.T, large bool) ([]byte, string) {
	t.Helper()
	target := "/offline?literal=/bin/sh&argv=ignored"
	if large {
		target = "/" + strings.Repeat("a", 8191)
	}
	a := exactaction.ActionContractV1{ContractVersion: exactaction.ContractVersion, ActionID: "A", Ownership: exactaction.Ownership{ProgramID: "P", TaskID: "T", WorkflowRunID: "W", StepRunID: "S", StepAttempt: 1}, Capability: exactaction.Capability{Name: "http.request", SemanticRevision: "v1"}, Request: exactaction.Request{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: target, Headers: []string{}}, Identity: exactaction.Identity{Kind: "anonymous"}, Limits: exactaction.Limits{MaxRequests: 1}}
	_, h, err := a.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]any{"version": exactsandbox.ExecutionVersion, "provider_attempt_id": "X", "action_sha256": h, "authority_epoch": 2, "action": a})
	if err != nil {
		t.Fatal(err)
	}
	_, b, _, _, err = canonicaljson.ParseStrictBounded(b, exactsandbox.MaxExecutionBytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append([]byte("reconductor-exact-sandbox-execution/v1\x00"), b...))
	return b, hex.EncodeToString(sum[:])
}

func TestOfflineExchange(t *testing.T) {
	for _, mode := range []string{"normal", "fragmented", "stderr-flood"} {
		t.Run(mode, func(t *testing.T) {
			l := launch{helper: compileHelper(t, mode, false), testPipeCapacity: 4096}
			input, digest := fixtureCapsule(t, true)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			b, err := exchange(ctx, l, input, digest)
			if err != nil {
				t.Fatal(err)
			}
			r, err := exactsandbox.DecodeResult(b, digest)
			if err != nil || !r.Completed {
				t.Fatalf("fixture boundary violation: %+v %v", r, err)
			}
		})
	}
}

func TestHostileOutputAndLifecycle(t *testing.T) {
	tests := []struct {
		mode string
		want error
	}{
		{"nonzero", nil}, {"exit-before-read", nil}, {"exit-before-output", exactsandbox.ErrProtocol},
		{"close-input", nil}, {"hang-read", context.DeadlineExceeded}, {"hang-after-input", context.DeadlineExceeded},
		{"early-flood", ErrOutputLimit}, {"limit", exactsandbox.ErrProtocol}, {"over-limit", ErrOutputLimit},
		{"wrong-digest", exactsandbox.ErrProtocol}, {"malformed", exactsandbox.ErrProtocol}, {"trailing", exactsandbox.ErrProtocol},
		{"output-no-eof", context.DeadlineExceeded}, {"valid-result-hang", context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			l := launch{helper: compileHelper(t, test.mode, false), testPipeCapacity: 4096}
			input, digest := fixtureCapsule(t, true)
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			start := time.Now()
			b, err := exchange(ctx, l, input, digest)
			if err == nil || b != nil {
				t.Fatalf("hostile fixture accepted: %q %v", b, err)
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("wanted %v, got %v", test.want, err)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("exchange exceeded cleanup bound")
			}
			if test.mode == "nonzero" {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 7 {
					t.Fatalf("exit status lost: %v", err)
				}
			}
		})
	}
}

func TestEnvironmentAndInheritableFDs(t *testing.T) {
	l := launch{helper: compileHelper(t, "normal", false)}
	for _, key := range []string{"SSH_AUTH_SOCK", "DATABASE_URL", "PGPASSWORD", "REDIS_URL", "API_KEY", "AWS_SECRET_ACCESS_KEY", "GIT_ASKPASS", "GIT_CONFIG", "DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "LD_PRELOAD"} {
		t.Setenv(key, "fake-test-secret")
	}
	file, err := unix.Open(filepath.Join(fixtureDir, "sentinel-file"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(file)
	dir, err := unix.Open(fixtureDir, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sockets[0])
	defer unix.Close(sockets[1])
	var pipes [2]int
	if err := unix.Pipe2(pipes[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pipes[0])
	defer unix.Close(pipes[1])
	for i, fd := range []int{file, dir, sockets[0], pipes[0]} {
		if err := unix.Dup3(fd, 400+i, 0); err != nil {
			t.Fatal(err)
		}
		defer unix.Close(400 + i)
		flags, err := unix.FcntlInt(uintptr(400+i), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC != 0 {
			t.Fatal("sentinel is not inheritable", err)
		}
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	if limit.Cur > 65537 {
		if err := unix.Dup3(file, 65537, 0); err != nil {
			t.Fatal(err)
		}
		defer unix.Close(65537)
	} else {
		t.Log("high-number sentinel unsupported by current NOFILE; four sentinel classes remain exercised")
	}
	input, digest := fixtureCapsule(t, false)
	// Negative control: Go exec alone leaks the deliberately non-CLOEXEC FDs.
	negativeCtx, negativeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer negativeCancel()
	cmd := exec.CommandContext(negativeCtx, fixtureRuntime, "fd-control")
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stdin = bytes.NewReader(input)
	negativeRead, negativeWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer negativeRead.Close()
	defer negativeWrite.Close()
	cmd.Stdout = negativeWrite
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	negativeWrite.Close()
	b, readErr := readBounded(negativeRead, exactsandbox.MaxResultBytes)
	if readErr != nil {
		negativeCancel()
	}
	if err := errors.Join(readErr, cmd.Wait()); err != nil {
		t.Fatal(err)
	}
	r, err := exactsandbox.DecodeResult(b, digest)
	if err != nil || r.Completed {
		t.Fatalf("negative control did not detect inherited descriptors: %+v %v", r, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err = exchange(ctx, l, input, digest)
	if err != nil {
		t.Fatal(err)
	}
	r, err = exactsandbox.DecodeResult(b, digest)
	if err != nil || !r.Completed {
		t.Fatalf("FD/environment isolation failed: %+v %v", r, err)
	}
	// Hygiene must not close the parent's own sentinels.
	for _, fd := range []int{400, 401, 402, 403} {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			t.Fatal("parent FD closed", err)
		}
	}
}

func TestCancelAndDescendantCleanup(t *testing.T) {
	for _, mode := range []string{"normal", "hang-read"} {
		t.Run(mode, func(t *testing.T) {
			helper := compileHelper(t, mode, true)
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			if err := r.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			input, digest := fixtureCapsule(t, false)
			done := make(chan error, 1)
			go func() {
				_, err := exchange(ctx, launch{helper: helper, extra: []*os.File{w}}, input, digest)
				done <- err
			}()
			// Close the parent's copy so report EOF is meaningful. Start may not
			// yet have duplicated it, so read just one newline instead of EOF.
			var report []byte
			for len(report) < 32 {
				var b [1]byte
				if _, err := r.Read(b[:]); err != nil {
					t.Fatal(err)
				}
				report = append(report, b[0])
				if b[0] == '\n' {
					break
				}
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(report)))
			if err != nil || pid <= 1 {
				t.Fatalf("invalid descendant report %q", report)
			}
			if mode == "hang-read" {
				cancel()
			}
			err = <-done
			if mode == "normal" && err != nil {
				t.Fatal(err)
			}
			if mode == "hang-read" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			// The descendant can briefly remain a zombie until host init reaps
			// it; a zombie cannot execute or retain FDs. Require dead, not running.
			deadline := time.Now().Add(time.Second)
			for {
				b, readErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				if errors.Is(readErr, os.ErrNotExist) || errors.Is(readErr, unix.ESRCH) {
					break
				}
				if readErr != nil {
					t.Fatal(readErr)
				}
				end := strings.LastIndex(string(b), ") ")
				if end >= 0 && b[end+2] == 'Z' {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("descendant %d still running", pid)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestRejectedInputAndExecutableSelection(t *testing.T) {
	input, digest := fixtureCapsule(t, false)
	for _, raw := range [][]byte{nil, append(append([]byte{}, input...), '\n'), []byte(`{"executable":"/bin/sh","argv":["-c","false"]}`), bytes.Repeat([]byte("x"), exactsandbox.MaxExecutionBytes+1)} {
		if _, err := exchange(context.Background(), launch{helper: "/does/not/exist"}, raw, digest); !errors.Is(err, exactsandbox.ErrProtocol) {
			t.Fatalf("input reached launch: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := exchange(ctx, launch{helper: "/does/not/exist"}, input, digest); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, path := range []string{"sh", "relative/helper", "/tmp/../bin/sh"} {
		if _, err := openHelper(path); !errors.Is(err, ErrProcess) {
			t.Fatal(path, err)
		}
	}
	helper := compileHelper(t, "normal", false)
	link := filepath.Join(t.TempDir(), "helper-link")
	if err := os.Symlink(helper, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openHelper(link); err == nil {
		f.Close()
		t.Fatal("symlink helper accepted")
	}
	if _, err := transact(context.Background(), launch{helper: helper, operation: "/bin/sh"}, nil, 256, func([]byte) error { return nil }); !errors.Is(err, ErrProcess) {
		t.Fatal("argv injection accepted", err)
	}
}

func TestPreflightHost(t *testing.T) {
	helper := compileHelper(t, "preflight", false)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	caps, err := preflight(ctx, helper)
	if err != nil {
		if os.Getenv("RECONDUCTOR_REQUIRE_PREFLIGHT") == "1" {
			t.Fatalf("designated host preflight failed: %v", err)
		}
		t.Skipf("host does not support the strict preflight (arch=%s): %v", runtime.GOARCH, err)
	}
	if !caps.StrictNamespaces || !caps.NestedUserNamespacesDisabled || !caps.SeccompOption {
		t.Fatalf("incomplete capability proof: %+v", caps)
	}
	t.Logf("strict unprivileged namespace preflight passed; cgroup namespace option (optional): %t", caps.CgroupNamespaceOption)
}

func TestPreflightFailsClosed(t *testing.T) {
	if _, err := preflight(context.Background(), "/does/not/exist"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	// A fixture producing protocol bytes cannot masquerade as option help.
	if _, err := preflight(context.Background(), compileHelper(t, "normal", false)); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Preflight(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestHelperArtifactRejection(t *testing.T) {
	artifactDir := t.TempDir()
	for _, name := range []string{"script", "plain"} {
		path := filepath.Join(artifactDir, name)
		text := "not an executable"
		if name == "script" {
			text = "#!/bin/sh\nexit 0\n"
		}
		if err := os.WriteFile(path, []byte(text), 0700); err != nil {
			t.Fatal(err)
		}
		if f, err := openHelper(path); !errors.Is(err, ErrProcess) {
			if f != nil {
				f.Close()
			}
			t.Fatal("non-ELF helper accepted", err)
		}
	}
	fifo := filepath.Join(artifactDir, "helper-fifo")
	if err := unix.Mkfifo(fifo, 0700); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if f, err := openHelper(fifo); !errors.Is(err, ErrProcess) {
		if f != nil {
			f.Close()
		}
		t.Fatal("FIFO helper accepted", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("FIFO open blocked")
	}
	if f, err := openHelper(artifactDir); !errors.Is(err, ErrProcess) {
		if f != nil {
			f.Close()
		}
		t.Fatal("directory helper accepted", err)
	}
	writable := filepath.Join(artifactDir, "writable-helper")
	b, err := os.ReadFile(compileHelper(t, "normal", false))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(writable, b, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0777); err != nil {
		t.Fatal(err)
	}
	if f, err := openHelper(writable); !errors.Is(err, ErrProcess) {
		if f != nil {
			f.Close()
		}
		t.Fatal("writable helper accepted", err)
	}
}

func TestOptionProofRejectsTryAndVersionOnly(t *testing.T) {
	required := []string{"--unshare-net", "--disable-userns", "--seccomp"}
	for _, help := range []string{
		"bubblewrap 0.12.0", "--unshare-net-try\n--disable-userns\n--seccomp",
		"--unshare-net\n--disable-userns-try\n--seccomp",
		"description mentions --unshare-net --disable-userns --seccomp",
	} {
		if _, err := requiredOptions([]byte(help), required); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("insufficient proof accepted %q: %v", help, err)
		}
	}
	flags, err := requiredOptions([]byte("--unshare-net\n--disable-userns\n--seccomp"), required)
	if err != nil || flags["--unshare-cgroup"] {
		t.Fatal("cgroup namespace became mandatory", err)
	}
}

func TestRuntimeRequiresInputEOF(t *testing.T) {
	helper, err := openHelper(compileHelper(t, "normal", false))
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Close()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outR.Close()
	defer outW.Close()
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{helper}
	cmd.Stdin = inR
	cmd.Stdout = outW
	cmd.SysProcAttr = &unixSysProcAttr
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { unix.Kill(-cmd.Process.Pid, unix.SIGKILL); cmd.Wait() }()
	inR.Close()
	outW.Close()
	input, digest := fixtureCapsule(t, false)
	if err := writeAll(inW, input); err != nil {
		t.Fatal(err)
	}
	if err := outR.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := outR.Read(b[:]); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("runtime produced output without input EOF: %d %v", n, err)
	}
	inW.Close()
	if err := outR.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	result, err := readBounded(outR, exactsandbox.MaxResultBytes)
	if err != nil {
		t.Fatal(err)
	}
	r, err := exactsandbox.DecodeResult(result, digest)
	if err != nil || !r.Completed {
		t.Fatalf("EOF did not release one valid result: %+v %v", r, err)
	}
}

func TestEarlyInputEOFRejectedByRuntime(t *testing.T) {
	input, digest := fixtureCapsule(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := transact(ctx, launch{helper: compileHelper(t, "normal", false)}, input[:len(input)/2], 256, func(b []byte) error { _, err := exactsandbox.DecodeResult(b, digest); return err })
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 72 {
		t.Fatalf("partial capsule accepted by runtime: %v", err)
	}
}

func TestIndependentMaximumLifetime(t *testing.T) {
	l := launch{helper: compileHelper(t, "hang-read", false)}
	input, digest := fixtureCapsule(t, false)
	start := time.Now()
	_, err := exchange(context.Background(), l, input, digest)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > maxLifetime+time.Second {
		t.Fatalf("independent timeout failed: %v", err)
	}
}
