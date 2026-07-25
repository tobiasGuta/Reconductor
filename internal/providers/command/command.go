package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/providercheck"
	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
	"github.com/tobiasGuta/Reconductor/internal/redaction"
	platformscope "github.com/tobiasGuta/Reconductor/internal/scope"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
)

type Input struct {
	Domain     string   `json:"domain,omitempty"`
	Domains    []string `json:"domains,omitempty"`
	Targets    []string `json:"targets,omitempty"`
	Headless   bool     `json:"headless,omitempty"`
	Ports      string   `json:"ports,omitempty"`
	Method     string   `json:"method,omitempty"`
	PlanDigest string   `json:"target_plan_digest,omitempty"`
}

type ProviderOutput struct {
	Lines             []string                   `json:"lines"`
	Authorized        []string                   `json:"authorized"`
	AuthorizedURLs    []string                   `json:"authorized_urls"`
	AuthorizedRecords []provideroutput.Record    `json:"authorized_records"`
	Filtered          []targeting.FilterDecision `json:"filtered"`
	Records           []provideroutput.Record    `json:"records"`
	Warnings          []provideroutput.Warning   `json:"warnings"`
	AcceptedCount     int                        `json:"accepted_count"`
	FilteredCount     int                        `json:"filtered_count"`
}

type Invocation struct {
	Args  []string
	Stdin []byte
}
type Definition struct {
	Name, Description, Provider, Executable, Version string
	Risk                                             policy.Risk
	ScopeType                                        string
	RetrySafe, Idempotent                            bool
	RequiredSecrets                                  []string
	PolicyRequirements                               policy.Requirements
	Timeout                                          time.Duration
	PassiveInput                                     bool
	OutputAdapter                                    string
	BuildArgs                                        func(Input, policy.Policy) ([]string, error)
	BuildInvocation                                  func(Input, policy.Policy) (Invocation, error)
	Probe                                            providercheck.Spec
}
type Runner interface {
	Run(context.Context, string, []string, []byte) (stdout, stderr []byte, exitCode int, err error)
	Version(context.Context, string, []string) (string, error)
}
type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	code := 0
	if err != nil {
		var e *exec.ExitError
		if errors.As(err, &e) {
			code = e.ExitCode()
		} else {
			code = -1
		}
	}
	return out.Bytes(), errOut.Bytes(), code, err
}
func (OSRunner) Version(ctx context.Context, name string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(b)), err
	}
	return strings.TrimSpace(string(b)), nil
}

type Provider struct {
	def      Definition
	runner   Runner
	redactor *redaction.Redactor
}

func New(def Definition, runner Runner, r *redaction.Redactor) *Provider {
	if runner == nil {
		runner = OSRunner{}
	}
	if r == nil {
		r = redaction.New()
	}
	return &Provider{def: def, runner: runner, redactor: r}
}
func (p *Provider) Manifest() capability.Manifest {
	return capability.Manifest{Name: p.def.Name, Description: p.def.Description, Version: p.def.Version, Risk: p.def.Risk, InputSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"domain":{"type":"string"},"domains":{"type":"array","items":{"type":"string"}},"targets":{"type":"array","items":{"type":"string"}},"headless":{"type":"boolean"},"ports":{"type":"string"},"method":{"type":"string"},"target_plan_digest":{"type":"string"}}}`), OutputSchema: json.RawMessage(providerOutputSchema), RequiredScopeType: p.def.ScopeType, ApprovalRequired: p.def.Risk == policy.Moderate || p.def.Risk == policy.High, RetrySafe: p.def.RetrySafe, Idempotent: p.def.Idempotent, SupportedProviders: []string{p.def.Provider}, ProducedArtifactTypes: []string{"raw-provider-output", "normalized-json"}, RequiredSecrets: p.def.RequiredSecrets, PolicyRequirements: p.def.PolicyRequirements, DefaultTimeout: p.def.Timeout}
}
func (p *Provider) ValidateDefinition(raw json.RawMessage) error {
	var in Input
	return strict(raw, &in)
}
func (p *Provider) Validate(_ context.Context, req capability.Request) error {
	var in Input
	if err := strict(req.Action.Input, &in); err != nil {
		return fmt.Errorf("%s input: %w", p.def.Name, err)
	}
	domains := append([]string{}, in.Domains...)
	if in.Domain != "" {
		domains = append(domains, in.Domain)
	}
	if len(domains) == 0 && len(in.Targets) == 0 {
		return fmt.Errorf("domains or targets are required")
	}
	if req.Scope == nil {
		return fmt.Errorf("validated scope is required")
	}
	if req.Policy.MaximumPayloadSize > 0 && int64(len(req.Action.Input)) > req.Policy.MaximumPayloadSize {
		return fmt.Errorf("input exceeds policy maximum payload size")
	}
	if in.Headless && !req.Policy.HeadlessBrowser {
		return fmt.Errorf("headless browser use is denied by policy")
	}
	if in.Method != "" {
		if err := policy.ValidateHTTPMethod(req.Policy, in.Method); err != nil {
			return err
		}
	}
	if len(domains) > 0 && !p.def.PassiveInput {
		return fmt.Errorf("bare domains are permitted only for passive discovery providers")
	}
	for _, root := range domains {
		if err := validatePassiveRoot(root); err != nil {
			return fmt.Errorf("discovery root %q: %w", root, err)
		}
	}
	for _, target := range in.Targets {
		if !strings.Contains(target, "://") {
			return fmt.Errorf("active target %q must be an authorized URL with explicit protocol", target)
		}
		if !req.Scope.Allows(target) {
			return fmt.Errorf("target %q is outside authorized scope", target)
		}
	}
	_, err := p.def.invocation(in, req.Policy)
	return err
}
func (p *Provider) Execute(ctx context.Context, req capability.Request) (capability.Result, error) {
	var in Input
	if err := json.Unmarshal(req.Action.Input, &in); err != nil {
		return capability.Result{}, err
	}
	invocation, err := p.def.invocation(in, req.Policy)
	if err != nil {
		return capability.Result{}, err
	}
	timeout := p.def.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now().UTC()
	versionCtx, versionCancel := context.WithTimeout(runCtx, 5*time.Second)
	versionArgs := p.def.Probe.VersionArgs
	if len(versionArgs) == 0 {
		versionArgs = []string{"-version"}
	}
	version, versionErr := p.runner.Version(versionCtx, p.def.Executable, versionArgs)
	versionCancel()
	if p.def.Probe.Name != "" {
		versionResult := providercheck.EvaluateExecutable(p.def.Probe, p.def.Executable, version, versionErr)
		if versionResult.Status != providercheck.Compatible {
			return p.versionFailure(req, in, invocation, started, versionResult, versionErr)
		}
	}
	stdout, stderr, exit, runErr := p.runner.Run(runCtx, p.def.Executable, invocation.Args, invocation.Stdin)
	completed := time.Now().UTC()
	domains := append([]string{}, in.Domains...)
	if in.Domain != "" {
		domains = append(domains, in.Domain)
	}
	safeArgs, _ := json.Marshal(map[string]any{"provider": p.def.Provider, "target_count": len(in.Targets), "discovery_root_count": len(domains), "stdin_bytes": len(invocation.Stdin), "headless": in.Headless, "target_plan_digest": in.PlanDigest})
	safeStdout := p.redactor.Text(string(stdout))
	safeStderr := p.redactor.Text(string(stderr))
	lines := splitLines(safeStdout)
	normalized := ProviderOutput{Lines: lines, Authorized: lines, AuthorizedURLs: []string{}, AuthorizedRecords: []provideroutput.Record{}, Filtered: []targeting.FilterDecision{}, Records: []provideroutput.Record{}, Warnings: []provideroutput.Warning{}, AcceptedCount: len(lines), FilteredCount: 0}
	if p.def.OutputAdapter != "" {
		detailed, ok := req.Scope.(targeting.DetailedScope)
		if !ok {
			return capability.Result{}, fmt.Errorf("provider %s requires detailed scope evaluation", p.def.Provider)
		}
		batch := provideroutput.Parse(p.def.OutputAdapter, lines)
		accepted, authorizedURLs, authorizedRecords, filtered := filterRecords(detailed, batch.Records)
		normalized = ProviderOutput{Lines: accepted, Authorized: accepted, AuthorizedURLs: authorizedURLs, AuthorizedRecords: authorizedRecords, Filtered: filtered, Records: batch.Records, Warnings: batch.Warnings, AcceptedCount: len(accepted), FilteredCount: len(filtered)}
		lines = accepted
	}
	if err := validateProviderOutput(normalized); err != nil {
		return capability.Result{}, err
	}
	output, _ := json.Marshal(normalized)
	tool := &domain.ToolRun{ID: domain.NewID(), StepRunID: req.Action.StepRunID, Capability: p.def.Name, Provider: p.def.Provider, ToolVersion: p.redactor.Text(version), SanitizedArguments: safeArgs, ExecutionEnvironment: json.RawMessage(`{"kind":"local-process","shell":false}`), StartedAt: started, CompletedAt: &completed, ExitCode: &exit, TimedOut: errors.Is(runCtx.Err(), context.DeadlineExceeded)}
	result := capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "succeeded", Summary: fmt.Sprintf("%s accepted %d normalized records", p.def.Provider, len(lines)), Output: output}, ToolRun: tool, RawStdout: []byte(safeStdout), RawStderr: []byte(safeStderr)}
	if runErr != nil {
		diagnostic := diagnosticSnippet(safeStderr, 3072)
		message := diagnosticSnippet(p.redactor.Text(runErr.Error()), 512)
		if message == "" {
			message = "provider execution failed"
		}
		if diagnostic != "" {
			message += ": " + diagnostic
		}
		result.Action.Status = "failed"
		result.Action.Summary = fmt.Sprintf("%s execution failed", p.def.Provider)
		result.Action.Error = &domain.StructuredError{Classification: classify(runErr, runCtx), Message: message, Retryable: exit < 0 || runCtx.Err() != nil}
		return result, &safeExecutionError{cause: runErr, message: message}
	}
	return result, nil
}

func (p *Provider) versionFailure(req capability.Request, in Input, invocation Invocation, started time.Time, check providercheck.Result, versionErr error) (capability.Result, error) {
	completed := time.Now().UTC()
	exit := -1
	domains := append([]string{}, in.Domains...)
	if in.Domain != "" {
		domains = append(domains, in.Domain)
	}
	safeArgs, _ := json.Marshal(map[string]any{"provider": p.def.Provider, "target_count": len(in.Targets), "discovery_root_count": len(domains), "stdin_bytes": len(invocation.Stdin), "headless": in.Headless, "target_plan_digest": in.PlanDigest})
	detail := diagnosticSnippet(p.redactor.Text(check.Details), 1024)
	message := fmt.Sprintf("%s executable verification failed (%s): expected %s; configure %s with its full path", p.def.Provider, check.Status, check.ExpectedVersion, p.def.Probe.ExecutableEnv)
	if detail != "" {
		message += ": " + detail
	}
	tool := &domain.ToolRun{ID: domain.NewID(), StepRunID: req.Action.StepRunID, Capability: p.def.Name, Provider: p.def.Provider, ToolVersion: detail, SanitizedArguments: safeArgs, ExecutionEnvironment: json.RawMessage(`{"kind":"local-process","shell":false}`), StartedAt: started, CompletedAt: &completed, ExitCode: &exit}
	result := capability.Result{Action: domain.ActionResult{RequestID: req.Action.ID, Status: "failed", Summary: fmt.Sprintf("%s executable verification failed", p.def.Provider), Error: &domain.StructuredError{Classification: "provider_unavailable", Message: message, Retryable: false}}, ToolRun: tool, RawStderr: []byte(detail)}
	return result, &safeExecutionError{cause: versionErr, message: message}
}

type safeExecutionError struct {
	cause   error
	message string
}

func (e *safeExecutionError) Error() string { return e.message }
func (e *safeExecutionError) Unwrap() error { return e.cause }

func (d Definition) invocation(in Input, p policy.Policy) (Invocation, error) {
	if d.BuildInvocation != nil {
		return d.BuildInvocation(in, p)
	}
	if d.BuildArgs == nil {
		return Invocation{}, fmt.Errorf("provider invocation builder is required")
	}
	args, err := d.BuildArgs(in, p)
	return Invocation{Args: args}, err
}
func strict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(v)
}
func splitLines(s string) []string {
	raw := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
func classify(err error, ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "timeout"
	}
	var e *exec.Error
	if errors.As(err, &e) {
		return "provider_unavailable"
	}
	return "provider_error"
}
func diagnosticSnippet(value string, limit int) string {
	if limit < 1 {
		return ""
	}
	var out strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) {
			r = ' '
		}
		size := utf8.RuneLen(r)
		if size < 0 {
			size = 1
		}
		if out.Len()+size > limit {
			break
		}
		out.WriteRune(r)
	}
	return strings.Join(strings.Fields(out.String()), " ")
}
func validatePassiveRoot(raw string) error {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if net.ParseIP(host) != nil {
		return nil
	}
	if host == "" || strings.ContainsAny(host, " /:@") {
		return fmt.Errorf("invalid hostname")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return fmt.Errorf("invalid hostname")
		}
	}
	return nil
}

func filterRecords(sc targeting.DetailedScope, records []provideroutput.Record) ([]string, []string, []provideroutput.Record, []targeting.FilterDecision) {
	accepted := []string{}
	authorizedURLs := []string{}
	authorizedRecords := []provideroutput.Record{}
	filtered := []targeting.FilterDecision{}
	for _, record := range records {
		switch record.Kind {
		case provideroutput.HostRecord:
			r := targeting.FilterDiscoveredHosts(sc, []string{record.Host})
			if len(r.Authorized) > 0 {
				accepted = append(accepted, r.Authorized...)
				authorizedURLs = append(authorizedURLs, r.AuthorizedURLs...)
				authorizedRecords = append(authorizedRecords, record)
			} else {
				filtered = append(filtered, r.Filtered...)
			}
		case provideroutput.URLRecord:
			r := targeting.FilterURLs(sc, []string{record.Target})
			if len(r.Authorized) > 0 {
				accepted = append(accepted, r.Authorized...)
				authorizedURLs = append(authorizedURLs, r.AuthorizedURLs...)
				authorizedRecords = append(authorizedRecords, record)
			} else {
				filtered = append(filtered, r.Filtered...)
			}
		case provideroutput.PortRecord:
			r := targeting.FilterDiscoveredHosts(sc, []string{record.Host})
			matched := false
			for _, raw := range r.AuthorizedURLs {
				u, err := url.Parse(raw)
				if err != nil {
					continue
				}
				port := u.Port()
				if port == "" {
					if u.Scheme == "https" {
						port = "443"
					} else {
						port = "80"
					}
				}
				value, _ := strconv.Atoi(port)
				if value == record.Port {
					matched = true
					accepted = append(accepted, record.Target)
					authorizedRecords = append(authorizedRecords, record)
					break
				}
			}
			if !matched {
				reason := "port_not_authorized"
				if len(r.Filtered) > 0 {
					reason = string(r.Filtered[0].Reason)
				}
				filtered = append(filtered, targeting.FilterDecision{Target: record.Target, Reason: scopeReason(reason)})
			}
		}
	}
	sort.Strings(accepted)
	accepted = dedupe(accepted)
	sort.Strings(authorizedURLs)
	authorizedURLs = dedupe(authorizedURLs)
	sort.SliceStable(authorizedRecords, func(i, j int) bool {
		return authorizedRecords[i].Target < authorizedRecords[j].Target
	})
	return accepted, authorizedURLs, authorizedRecords, filtered
}
func scopeReason(value string) platformscope.Reason { return platformscope.Reason(value) }

func validateProviderOutput(output ProviderOutput) error {
	if output.Lines == nil || output.Authorized == nil || output.AuthorizedURLs == nil || output.AuthorizedRecords == nil || output.Filtered == nil || output.Records == nil || output.Warnings == nil {
		return fmt.Errorf("provider output collections must be non-null")
	}
	if output.AcceptedCount != len(output.Authorized) {
		return fmt.Errorf("provider output accepted_count=%d does not match authorized=%d", output.AcceptedCount, len(output.Authorized))
	}
	if output.FilteredCount != len(output.Filtered) {
		return fmt.Errorf("provider output filtered_count=%d does not match filtered=%d", output.FilteredCount, len(output.Filtered))
	}
	if len(output.Lines) != len(output.Authorized) {
		return fmt.Errorf("provider output lines=%d does not match authorized=%d", len(output.Lines), len(output.Authorized))
	}
	for index, record := range append(append([]provideroutput.Record{}, output.Records...), output.AuthorizedRecords...) {
		if record.Provider == "" || record.Kind == "" || record.Target == "" {
			return fmt.Errorf("provider output record %d requires provider, kind, and target", index)
		}
		switch record.Kind {
		case provideroutput.HostRecord:
			if record.Host == "" {
				return fmt.Errorf("provider output host record %d requires host", index)
			}
		case provideroutput.PortRecord:
			if record.Host == "" || record.Port < 1 || record.Port > 65535 {
				return fmt.Errorf("provider output port record %d requires host and valid port", index)
			}
		case provideroutput.URLRecord:
			u, err := url.Parse(record.Target)
			if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
				return fmt.Errorf("provider output url record %d has invalid HTTP target", index)
			}
		default:
			return fmt.Errorf("provider output record %d has unsupported kind %q", index, record.Kind)
		}
	}
	for index, warning := range output.Warnings {
		if warning.Line < 1 || strings.TrimSpace(warning.Reason) == "" {
			return fmt.Errorf("provider output warning %d requires line and reason", index)
		}
	}
	return nil
}

func dedupe(items []string) []string {
	if len(items) < 2 {
		return items
	}
	out := items[:1]
	for _, v := range items[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

const providerOutputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["lines","authorized","authorized_urls","authorized_records","filtered","records","warnings","accepted_count","filtered_count"],"properties":{"lines":{"type":"array","items":{"type":"string"}},"authorized":{"type":"array","items":{"type":"string"}},"authorized_urls":{"type":"array","items":{"type":"string","format":"uri"}},"authorized_records":{"type":"array","items":{"$ref":"#/$defs/record"}},"filtered":{"type":"array","items":{"$ref":"#/$defs/filter_decision"}},"records":{"type":"array","items":{"$ref":"#/$defs/record"}},"warnings":{"type":"array","items":{"$ref":"#/$defs/warning"}},"accepted_count":{"type":"integer","minimum":0},"filtered_count":{"type":"integer","minimum":0}},"$defs":{"record":{"type":"object","additionalProperties":false,"required":["provider","kind","target"],"properties":{"provider":{"type":"string","minLength":1},"kind":{"enum":["host","port","url"]},"target":{"type":"string","minLength":1},"host":{"type":"string"},"port":{"type":"integer","minimum":0,"maximum":65535},"status_code":{"type":"integer","minimum":0,"maximum":599},"technologies":{"type":"array","items":{"type":"string"}},"fields":{"type":"object"}}},"filter_decision":{"type":"object","additionalProperties":false,"required":["target","accepted","reason"],"properties":{"target":{"type":"string"},"accepted":{"type":"boolean"},"reason":{"type":"string"},"authorized_urls":{"type":"array","items":{"type":"string","format":"uri"}},"source_rule_ids":{"type":"array","items":{"type":"string"}}}},"warning":{"type":"object","additionalProperties":false,"required":["line","reason"],"properties":{"line":{"type":"integer","minimum":1},"reason":{"type":"string","minLength":1}}}}}`
