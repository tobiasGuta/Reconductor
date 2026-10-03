//go:build operational

package providers

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	commandprovider "github.com/tobiasGuta/Reconductor/internal/providers/command"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
)

type protocolCountingListener struct {
	net.Listener
	plain atomic.Int64
	tls   atomic.Int64
}

func (l *protocolCountingListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &protocolCountingConnection{Conn: connection, listener: l}, nil
}

type protocolCountingConnection struct {
	net.Conn
	listener *protocolCountingListener
	once     sync.Once
}

func (c *protocolCountingConnection) Read(buffer []byte) (int, error) {
	read, err := c.Conn.Read(buffer)
	if read > 0 {
		c.once.Do(func() {
			if buffer[0] == 0x16 {
				c.listener.tls.Add(1)
				return
			}
			c.listener.plain.Add(1)
		})
	}
	return read, err
}

func TestHTTPXProductionInvocationPreservesExplicitProtocolOnWire(t *testing.T) {
	httpx := os.Getenv("HTTPX_EXECUTABLE")
	if httpx == "" {
		var err error
		httpx, err = exec.LookPath("httpx")
		if err != nil {
			t.Skip("httpx is not installed")
		}
	}
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				if request.URL.RequestURI() != "/protocol-scope?source=operational" {
					t.Errorf("request URI=%q", request.URL.RequestURI())
				}
				writer.Header().Set("Content-Type", "text/plain")
				writer.WriteHeader(http.StatusOK)
				_, _ = writer.Write([]byte("loopback only"))
			}))
			wire := &protocolCountingListener{Listener: server.Listener}
			server.Listener = wire
			if scheme == "https" {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()

			target := server.URL + "/protocol-scope?source=operational"
			parsed, err := url.Parse(target)
			if err != nil {
				t.Fatal(err)
			}
			sc, err := platformscope.Compile([]platformscope.Rule{{
				Protocol: "^" + regexp.QuoteMeta(parsed.Scheme) + "$",
				Host:     "^" + regexp.QuoteMeta(parsed.Hostname()) + "$",
				Port:     "^" + regexp.QuoteMeta(parsed.Port()) + "$",
				File:     `^/protocol-scope.*`,
				Enabled:  true,
			}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			input, err := json.Marshal(commandprovider.Input{Targets: []string{target}, PlanDigest: "protocol-wire"})
			if err != nil {
				t.Fatal(err)
			}
			cfg := config.Config{Tools: config.Tools{HTTPX: httpx}, Recon: config.Recon{Timeout: 20 * time.Second, Concurrency: 1}}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			recorder := providerTestProvenanceRecorder{}
			result, executeErr := Registry(cfg).Execute(ctx, capability.Request{
				ProgramID: domain.NewID(),
				Action: domain.ActionRequest{
					ID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(),
					RequestedBy: "operational-test", Capability: "probe.http", Input: input, StepAttempt: 1,
				},
				Provider: "httpx",
				Policy:   policy.Policy{ID: "protocol-wire", AllowedCapabilities: []string{"probe.http"}, Concurrency: 1},
				Scope:    sc, DecisionRecorder: recorder, InvocationRecorder: recorder,
			})
			if executeErr != nil {
				t.Fatalf("execute production HTTPX invocation: %v; result=%#v stderr=%s", executeErr, result.Action, result.RawStderr)
			}
			if result.Action.Status != "succeeded" || result.ProviderAttemptID == nil || result.ToolRun == nil || result.ToolRun.ExitCode == nil || *result.ToolRun.ExitCode != 0 {
				t.Fatalf("result=%#v tool=%#v attempt=%v", result.Action, result.ToolRun, result.ProviderAttemptID)
			}
			var output commandprovider.ProviderOutput
			if err := json.Unmarshal(result.Action.Output, &output); err != nil {
				t.Fatal(err)
			}
			if output.AcceptedCount != 1 || len(output.AuthorizedRecords) != 1 || len(output.AuthorizedSourceRecords) != 1 {
				t.Fatalf("output=%#v, want one admitted record and source record", output)
			}
			record := output.AuthorizedRecords[0]
			if record.Target != target || record.StatusCode != http.StatusOK || requests.Load() < 1 {
				t.Fatalf("record=%#v requests=%d target=%q", record, requests.Load(), target)
			}
			t.Logf("scheme=%s requests=%d plain_connections=%d tls_connections=%d admitted=%d", parsed.Scheme, requests.Load(), wire.plain.Load(), wire.tls.Load(), output.AcceptedCount)
			if parsed.Scheme == "http" {
				if wire.plain.Load() < 1 || wire.tls.Load() != 0 {
					t.Fatalf("HTTP wire counts: plain=%d tls=%d", wire.plain.Load(), wire.tls.Load())
				}
			} else if wire.tls.Load() < 1 || wire.plain.Load() != 0 {
				t.Fatalf("HTTPS wire counts: plain=%d tls=%d", wire.plain.Load(), wire.tls.Load())
			}
		})
	}
}
