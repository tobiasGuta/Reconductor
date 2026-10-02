// This fixture is built only by Linux tests, never by a production command.
// Behavior is a compile-time constant in its native launcher, not capsule or
// environment configuration. It performs no networking or program execution.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/exactsandbox"
)

func hang() {
	for {
		time.Sleep(time.Hour)
	}
}

func main() {
	if len(os.Args) != 2 {
		os.Exit(70)
	}
	mode := os.Args[1]
	switch mode {
	case "exit-before-read":
		return
	case "close-input":
		os.Stdin.Close()
		hang()
	case "hang-read":
		hang()
	case "early-flood":
		for {
			if _, err := os.Stdout.Write(make([]byte, 4096)); err != nil {
				return
			}
		}
	}
	var reader io.Reader = os.Stdin
	if mode == "fragmented" {
		reader = byteReader{os.Stdin}
	}
	raw, err := io.ReadAll(io.LimitReader(reader, exactsandbox.MaxExecutionBytes+1))
	if err != nil || len(raw) > exactsandbox.MaxExecutionBytes {
		os.Exit(71)
	}
	sum := sha256.Sum256(append([]byte("reconductor-exact-sandbox-execution/v1\x00"), raw...))
	digest := hex.EncodeToString(sum[:])
	if _, err := exactsandbox.DecodeExecution(raw, digest); err != nil {
		os.Exit(72)
	}
	switch mode {
	case "nonzero":
		os.Exit(7)
	case "exit-before-output":
		return
	case "hang-after-input":
		hang()
	case "stderr-flood":
		b := make([]byte, 64*1024)
		for i := 0; i < 128; i++ {
			if _, err := os.Stderr.Write(b); err != nil {
				os.Exit(73)
			}
		}
	case "limit":
		os.Stdout.Write([]byte(strings.Repeat("x", exactsandbox.MaxResultBytes)))
		return
	case "over-limit":
		os.Stdout.Write([]byte(strings.Repeat("x", exactsandbox.MaxResultBytes+1)))
		return
	case "wrong-digest":
		digest = strings.Repeat("0", 64)
	case "malformed":
		os.Stdout.Write([]byte("{"))
		return
	}
	clean := len(os.Environ()) == 0
	nnp, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 39 /* PR_GET_NO_NEW_PRIVS */, 0, 0, 0, 0, 0)
	if mode != "fd-control" {
		clean = clean && errno == 0 && nnp == 1
	}
	cwd, err := os.Getwd()
	clean = clean && err == nil && cwd == "/"
	// Deliberately inheritable parent sentinels occupy these numbers. The
	// runtime must see EBADF, regardless of Go's own CLOEXEC conventions.
	for _, fd := range []uintptr{400, 401, 402, 403, 65537} {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
		clean = clean && errno == syscall.EBADF
	}
	result, err := exactsandbox.EncodeResult(digest, clean)
	if err != nil {
		os.Exit(74)
	}
	if mode == "trailing" {
		result = append(result, '\n')
	}
	if mode == "fragmented" {
		for _, b := range result {
			if _, err := os.Stdout.Write([]byte{b}); err != nil {
				os.Exit(75)
			}
		}
	} else if _, err := os.Stdout.Write(result); err != nil {
		os.Exit(75)
	}
	if mode == "output-no-eof" {
		hang()
	}
	if mode == "valid-result-hang" {
		os.Stdout.Close()
		hang()
	}
}

type byteReader struct{ r io.Reader }

func (r byteReader) Read(b []byte) (int, error) {
	if len(b) > 1 {
		b = b[:1]
	}
	return r.r.Read(b)
}
