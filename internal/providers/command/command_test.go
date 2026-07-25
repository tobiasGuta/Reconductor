package command

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/providercheck"
	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
)

type fakeRunner struct {
	called     bool
	stdout     string
	stderr     string
	args       []string
	stdin      []byte
	exit       int
	err        error
	version    string
	versionErr error
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int, error) {
	f.called = true
	f.args = append([]string(nil), args...)
	f.stdin = append([]byte(nil), stdin...)
	out := f.stdout
	if out == "" {
		out = "one\ntwo\n"
	}
	return []byte(out), []byte(f.stderr), f.exit, f.err
}

func TestFailureDiagnosticIsRedactedBoundedAndKeepsRawStderr(t *testing.T) {
	runCause := errors.New("exit status 1; token=runtime-secret")
	runner := &fakeRunner{stderr: "password=super-sensitive\x00\n" + strings.Repeat("x", 5000), exit: 1, err: runCause}
	p := New(Definition{Name: "probe.http", Provider: "httpx", Executable: "httpx", Version: "1", Risk: policy.Low, BuildArgs: func(i Input, _ policy.Policy) ([]string, error) { return []string{"-u", i.Targets[0]}, nil }}, runner, redaction.New())
	raw, _ := json.Marshal(Input{Targets: []string{"https://example.test"}})
	req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), StepRunID: domain.NewID(), Capability: "probe.http", Input: raw}, Policy: policy.Policy{AllowedCapabilities: []string{"probe.http"}}, Scope: allowScope(true)}
	result, err := p.Execute(context.Background(), req)
	if err == nil || !errors.Is(err, runCause) || !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("error=%v", err)
	}
	if strings.Contains(err.Error(), "runtime-secret") || strings.ContainsRune(err.Error(), '\x00') {
		t.Fatalf("returned error was not sanitized: %q", err)
	}
	if result.Action.Error == nil || strings.Contains(result.Action.Error.Message, "super-sensitive") || strings.Contains(result.Action.Error.Message, "runtime-secret") || len(result.Action.Error.Message) > 3700 {
		t.Fatalf("unsafe diagnostic: %#v", result.Action.Error)
	}
	if !strings.Contains(string(result.RawStderr), "<redacted>") || len(result.RawStderr) < 4000 {
		t.Fatalf("raw stderr was not complete and redacted")
	}
}

func TestPassiveDiscoveryOutputIsFilteredPerRecordBeforeActiveUse(t *testing.T) {
	sc, err := platformscope.Compile([]platformscope.Rule{{Protocol: `^https$`, Host: `^.*\.dev\.example\.com$`, Port: `^443$`, File: `^/.*`, Enabled: true}}, []platformscope.Rule{{Protocol: `^https$`, Host: `^excluded\.dev\.example\.com$`, Port: `^443$`, File: `^/.*`, Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{stdout: "authorized.dev.example.com\nunauthorized.example.com\nexcluded.dev.example.com\nbad host\n"}
	p := New(Definition{Name: "discover.subdomains", Provider: "subfinder", Executable: "subfinder", Version: "2", Risk: policy.Passive, PassiveInput: true, OutputAdapter: "subfinder", BuildArgs: func(i Input, _ policy.Policy) ([]string, error) { return []string{"-d", i.Domains[0]}, nil }}, runner, nil)
	raw, _ := json.Marshal(Input{Domains: []string{"dev.example.com"}})
	req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), StepRunID: domain.NewID(), Capability: "discover.subdomains", Input: raw}, Policy: policy.Policy{AllowedCapabilities: []string{"discover.subdomains"}}, Scope: sc}
	if err := p.Validate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	result, err := p.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var output struct {
		Authorized        []string                `json:"authorized"`
		AuthorizedURLs    []string                `json:"authorized_urls"`
		AuthorizedRecords []provideroutput.Record `json:"authorized_records"`
		Records           []provideroutput.Record `json:"records"`
		Filtered          []map[string]any        `json:"filtered"`
		Warnings          []map[string]any        `json:"warnings"`
	}
	if err := json.Unmarshal(result.Action.Output, &output); err != nil {
		t.Fatal(err)
	}
	if len(output.Authorized) != 1 || output.Authorized[0] != "authorized.dev.example.com" {
		t.Fatalf("authorized=%v output=%s", output.Authorized, result.Action.Output)
	}
	if len(output.AuthorizedURLs) != 1 || output.AuthorizedURLs[0] != "https://authorized.dev.example.com/" {
		t.Fatalf("urls=%v", output.AuthorizedURLs)
	}
	if len(output.AuthorizedRecords) != 1 || output.AuthorizedRecords[0].Target != "authorized.dev.example.com" {
		t.Fatalf("authorized records leaked filtered data: %#v", output.AuthorizedRecords)
	}
	if len(output.Records) != 3 {
		t.Fatalf("raw normalized records=%#v", output.Records)
	}
	if len(output.Filtered) != 2 || len(output.Warnings) != 1 {
		t.Fatalf("filtered=%v warnings=%v", output.Filtered, output.Warnings)
	}
}

func TestProviderManifestPublishesCompleteClosedOutputSchema(t *testing.T) {
	p := New(Definition{Name: "probe.http", Provider: "httpx", Executable: "httpx", Version: "3", Risk: policy.Low, BuildArgs: func(i Input, _ policy.Policy) ([]string, error) { return []string{"-u", i.Targets[0]}, nil }}, &fakeRunner{}, nil)
	manifest := p.Manifest()
	var schema struct {
		AdditionalProperties *bool                      `json:"additionalProperties"`
		Required             []string                   `json:"required"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(manifest.OutputSchema, &schema); err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{}
	for _, field := range schema.Required {
		required[field] = true
	}
	for _, field := range []string{"lines", "authorized", "authorized_urls", "authorized_records", "filtered", "records", "warnings", "accepted_count", "filtered_count"} {
		if _, ok := schema.Properties[field]; !ok || !required[field] {
			t.Fatalf("output schema does not declare required field %q: %s", field, manifest.OutputSchema)
		}
	}
	if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		t.Fatalf("provider output schema is not closed: %s", manifest.OutputSchema)
	}
	if err := validateProviderOutput(ProviderOutput{Lines: []string{}, Authorized: []string{}, AuthorizedURLs: []string{}, AuthorizedRecords: []provideroutput.Record{}, Filtered: []targeting.FilterDecision{}, Records: []provideroutput.Record{}, Warnings: []provideroutput.Warning{}, AcceptedCount: 1}); err == nil {
		t.Fatal("inconsistent provider output counts were accepted")
	}
}
func (f *fakeRunner) Version(context.Context, string, []string) (string, error) {
	if f.version == "" {
		f.version = "1.2.3"
	}
	return f.version, f.versionErr
}

func TestRequiredVersionRejectsSameNameExecutableBeforeTargetExecution(t *testing.T) {
	runner := &fakeRunner{version: "Usage: httpx.exe [OPTIONS] URL\nError: No such option '-version'", versionErr: errors.New("exit status 2")}
	p := New(Definition{Name: "probe.http", Provider: "httpx", Executable: "httpx", Version: "3", Risk: policy.Low, Probe: providercheck.Spec{Name: "httpx", DisplayName: "HTTPX", ExecutableEnv: "HTTPX_EXECUTABLE", VersionArgs: []string{"-version"}, CompatiblePrefix: "1."}, BuildArgs: func(i Input, _ policy.Policy) ([]string, error) { return []string{"-u", i.Targets[0]}, nil }}, runner, nil)
	raw, _ := json.Marshal(Input{Targets: []string{"https://example.test"}})
	req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), StepRunID: domain.NewID(), Capability: "probe.http", Input: raw}, Policy: policy.Policy{AllowedCapabilities: []string{"probe.http"}}, Scope: allowScope(true)}
	result, err := p.Execute(context.Background(), req)
	if err == nil || runner.called {
		t.Fatalf("err=%v target command called=%v", err, runner.called)
	}
	if result.Action.Error == nil || result.Action.Error.Classification != "provider_unavailable" || result.Action.Error.Retryable || !strings.Contains(result.Action.Error.Message, "HTTPX_EXECUTABLE") || !strings.Contains(result.Action.Error.Message, "Usage: httpx.exe") {
		t.Fatalf("unexpected identity failure: %#v", result.Action.Error)
	}
}

type allowScope bool

func (s allowScope) Allows(string) bool { return bool(s) }
func TestProviderValidationAndExecution(t *testing.T) {
	runner := &fakeRunner{}
	p := New(Definition{Name: "probe.http", Provider: "httpx", Executable: "httpx", Version: "1", Risk: policy.Low, Timeout: time.Second, BuildArgs: func(i Input, _ policy.Policy) ([]string, error) { return []string{"-u", i.Targets[0]}, nil }}, runner, nil)
	raw, _ := json.Marshal(Input{Targets: []string{"https://example.test"}})
	req := capability.Request{Action: domain.ActionRequest{ID: domain.NewID(), StepRunID: domain.NewID(), Capability: "probe.http", Input: raw}, Policy: policy.Policy{AllowedCapabilities: []string{"probe.http"}}, Scope: allowScope(true)}
	if err := p.Validate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	result, err := p.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !runner.called || result.ToolRun == nil {
		t.Fatal("provider did not run")
	}
	req.Scope = allowScope(false)
	if err := p.Validate(context.Background(), req); err == nil {
		t.Fatal("out-of-scope target accepted")
	}
}
func TestRejectsUnknownInput(t *testing.T) {
	p := New(Definition{Name: "x", Provider: "x", Executable: "x", Version: "1", BuildArgs: func(Input, policy.Policy) ([]string, error) { return nil, nil }}, &fakeRunner{}, nil)
	req := capability.Request{Action: domain.ActionRequest{Input: json.RawMessage(`{"targets":["https://x"],"command":"whoami"}`)}, Scope: allowScope(true)}
	if err := p.Validate(context.Background(), req); err == nil {
		t.Fatal("unknown command field accepted")
	}
}
