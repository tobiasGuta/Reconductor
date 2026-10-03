package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
)

func TestOSRunnerBoundedOutput(t *testing.T) {
	const limit = 8192
	for _, stream := range []string{"stdout", "stderr", "both"} {
		for _, total := range []int{limit, limit + 1, 32 << 20} {
			t.Run(fmt.Sprintf("%s/%d", stream, total), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(capability.WithOutputBudget(context.Background(), limit), 5*time.Second)
				defer cancel()
				out, stderr, _, err := (OSRunner{}).Run(ctx, os.Args[0], []string{"-test.run=^TestOutputCaptureProcess$", "--", "capture-helper", stream, strconv.Itoa(total)}, nil)
				var overflow *capability.OutputLimitError
				if total == limit {
					if err != nil || len(out)+len(stderr) != limit {
						t.Fatalf("boundary bytes=%d err=%v", len(out)+len(stderr), err)
					}
				} else if !errors.As(err, &overflow) || overflow.Limit != limit {
					t.Fatalf("overflow classification=%v", err)
				}
				if len(out)+len(stderr) > limit || ctx.Err() != nil {
					t.Fatalf("unbounded capture/wait: %d %v", len(out)+len(stderr), ctx.Err())
				}
			})
		}
	}
}

func TestOSRunnerAuthorityBoundary(t *testing.T) {
	args := []string{"-test.run=^TestOutputCaptureProcess$", "--", "capture-helper", "stdout", "0"}
	if _, _, _, err := runCaptured(context.Background(), os.Args[0], args, nil, domain.PreparedSetOutputAuthorityMaxBytes); err != nil {
		t.Fatalf("exact authority: %v", err)
	}
	if _, _, _, err := runCaptured(context.Background(), os.Args[0], args, nil, domain.PreparedSetOutputAuthorityMaxBytes+1); err == nil || !strings.Contains(err.Error(), "invalid provider output byte authority") {
		t.Fatalf("oversized authority error=%v", err)
	}
}

func TestProviderNormalizationExpansionRejectsWithoutTruncatedSuccess(t *testing.T) {
	for _, raw := range []string{strings.Repeat("x", 600), strings.Repeat("a\n", domain.InlineSemanticJSONMaxNodes+1)} {
		budget := int64(1024)
		if len(raw) > 1024 {
			budget = 16 << 10
		}
		runner := &fakeRunner{stdout: raw}
		p := New(Definition{Name: "resolve.dns", Provider: "helper", Version: "1", BuildArgs: func(Input, policy.Policy) ([]string, error) { return nil, nil }}, runner, nil)
		result, err := p.Execute(capability.WithOutputBudget(context.Background(), budget), capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Input: []byte(`{}`)}})
		if err == nil || result.Action.Error == nil || result.Action.Error.Classification != "result_contract_limit" || result.Action.Error.Retryable || len(result.Action.Output) != 0 {
			t.Fatalf("result=%#v err=%v", result, err)
		}
		if len(raw) > 1024 && (result.OutputLimit.Unit != domain.LimitItems || result.OutputLimit.Observed != domain.InlineSemanticJSONMaxNodes+1) {
			t.Fatal("incorrect record limit facts")
		}
	}
}

func TestOSRunnerVersionOutputIsBounded(t *testing.T) {
	_, err := (OSRunner{}).Version(context.Background(), os.Args[0], []string{"-test.run=^TestOutputCaptureProcess$", "--", "capture-helper", "stderr", "33554432"})
	var overflow *capability.OutputLimitError
	if !errors.As(err, &overflow) || overflow.Limit != domain.DiagnosticMaxBytes {
		t.Fatalf("version overflow=%v", err)
	}
}

func TestProviderPreservesSmallerVersionCaptureAuthority(t *testing.T) {
	runner := &fakeRunner{versionErr: &capability.OutputLimitError{Limit: 128}}
	p := New(Definition{Name: "resolve.dns", Provider: "helper", Version: "1", BuildArgs: func(Input, policy.Policy) ([]string, error) { return nil, nil }}, runner, nil)
	result, err := p.Execute(capability.WithOutputBudget(context.Background(), 128), capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), Input: []byte(`{}`)}})
	var overflow *capability.OutputLimitError
	if !errors.As(err, &overflow) || overflow.Limit != 128 || result.OutputLimit == nil || result.OutputLimit.Limit != 128 || runner.called {
		t.Fatalf("version limit changed or provider ran: result=%#v err=%v called=%v", result, err, runner.called)
	}
}

func TestOutputCaptureProcess(t *testing.T) {
	if len(os.Args) < 4 || os.Args[len(os.Args)-3] != "capture-helper" {
		return
	}
	stream := os.Args[len(os.Args)-2]
	total, _ := strconv.Atoi(os.Args[len(os.Args)-1])
	chunk := bytes.Repeat([]byte("x"), 4096)
	for written := 0; written < total; {
		n := min(len(chunk), total-written)
		dest := os.Stdout
		if stream == "stderr" || stream == "both" && (written/4096)%2 == 1 {
			dest = os.Stderr
		}
		if _, err := dest.Write(chunk[:n]); err != nil {
			time.Sleep(30 * time.Second)
			os.Exit(2)
		}
		written += n
	}
	if total > 8192 {
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}

func TestCaptureRejectedPayloadAllocationDoesNotScale(t *testing.T) {
	for _, size := range []int{1024, 1 << 20, 32 << 20} {
		payload := make([]byte, size) // outside the measured capture operation
		result := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				c := &outputCapture{remaining: 256, limit: 256, cancel: func() {}}
				w := &captureStream{capture: c}
				_, err := w.Write(payload)
				if err == nil || len(w.data) != 256 || cap(w.data) > 256 {
					b.Fatal("capture exceeded byte authority")
				}
			}
		})
		if result.AllocedBytesPerOp() > 1024 {
			t.Fatalf("rejected size=%d capture bytes/op=%d", size, result.AllocedBytesPerOp())
		}
		t.Logf("rejected bytes=%d allocated bytes/op=%d allocations/op=%d", size, result.AllocedBytesPerOp(), result.AllocsPerOp())
	}
}
