package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Risk string

const (
	Passive   Risk = "passive"
	Low       Risk = "low"
	Moderate  Risk = "moderate"
	High      Risk = "high"
	Forbidden Risk = "forbidden"
)

type Decision string

const (
	Allow           Decision = "allow"
	RequireApproval Decision = "require_approval"
	Deny            Decision = "deny"
)

type Policy struct {
	ID                   string        `json:"id"`
	AllowedCapabilities  []string      `json:"allowed_capabilities"`
	DeniedCapabilities   []string      `json:"denied_capabilities"`
	RateLimit            int           `json:"rate_limit"`
	Concurrency          int           `json:"concurrency"`
	ProviderConcurrency  int           `json:"provider_concurrency"`
	HostConcurrency      int           `json:"host_concurrency"`
	ScanWindows          []string      `json:"scan_windows"`
	AllowedHTTPMethods   []string      `json:"allowed_http_methods"`
	AuthenticationUsage  bool          `json:"authentication_usage"`
	HeadlessBrowser      bool          `json:"headless_browser"`
	DirectoryFuzzing     bool          `json:"directory_fuzzing"`
	TemplateTags         []string      `json:"template_tags"`
	ExcludedTemplateTags []string      `json:"excluded_template_tags"`
	MaximumPayloadSize   int64         `json:"maximum_payload_size"`
	FollowRedirects      bool          `json:"follow_redirects"`
	CrossOrigin          bool          `json:"cross_origin"`
	IntrusiveChecks      bool          `json:"intrusive_checks"`
	ArtifactRetention    time.Duration `json:"artifact_retention"`
	ModerateApproved     bool          `json:"moderate_approved"`
}
type Evaluation struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}

// Requirements describe behavior implemented by a registered capability.
// They are supplied by trusted capability code, never by workflow input.
type Requirements struct {
	Authentication   bool `json:"authentication"`
	DirectoryFuzzing bool `json:"directory_fuzzing"`
	CrossOrigin      bool `json:"cross_origin"`
	IntrusiveChecks  bool `json:"intrusive_checks"`
}

func Evaluate(p Policy, capability string, risk Risk, approved bool) Evaluation {
	return EvaluateAt(p, capability, risk, approved, Requirements{}, nil, time.Now().UTC())
}

// EvaluateAt is the authoritative policy decision for dispatch and execution.
// Scan windows use UTC and are evaluated again immediately before execution.
func EvaluateAt(p Policy, capability string, risk Risk, approved bool, requirements Requirements, input json.RawMessage, at time.Time) Evaluation {
	if risk == Forbidden {
		return Evaluation{Deny, "forbidden risk level"}
	}
	if contains(p.DeniedCapabilities, capability) {
		return Evaluation{Deny, "capability denied by policy"}
	}
	if len(p.AllowedCapabilities) > 0 && !contains(p.AllowedCapabilities, capability) {
		return Evaluation{Deny, "capability is not allowlisted"}
	}
	if allowed, reason := withinScanWindows(p.ScanWindows, at); !allowed {
		return Evaluation{Deny, reason}
	}
	if requirements.Authentication && !p.AuthenticationUsage {
		return Evaluation{Deny, "authentication usage is denied by policy"}
	}
	if requirements.DirectoryFuzzing && !p.DirectoryFuzzing {
		return Evaluation{Deny, "directory fuzzing is denied by policy"}
	}
	if requirements.CrossOrigin && !p.CrossOrigin {
		return Evaluation{Deny, "cross-origin access is denied by policy"}
	}
	if requirements.IntrusiveChecks && !p.IntrusiveChecks {
		return Evaluation{Deny, "intrusive checks are denied by policy"}
	}
	if p.MaximumPayloadSize > 0 && int64(len(input)) > p.MaximumPayloadSize {
		return Evaluation{Deny, "input exceeds policy maximum payload size"}
	}
	var common struct {
		Headless bool   `json:"headless"`
		Method   string `json:"method"`
	}
	if len(input) > 0 && json.Unmarshal(input, &common) == nil {
		if common.Headless && !p.HeadlessBrowser {
			return Evaluation{Deny, "headless browser use is denied by policy"}
		}
		if common.Method != "" {
			if err := ValidateHTTPMethod(p, common.Method); err != nil {
				return Evaluation{Deny, err.Error()}
			}
		}
	}
	switch risk {
	case Passive, Low:
		return Evaluation{Allow, "allowed within scope and limits"}
	case Moderate:
		if approved || p.ModerateApproved {
			return Evaluation{Allow, "moderate action approved"}
		}
		return Evaluation{RequireApproval, "moderate action requires workflow or action approval"}
	case High:
		if approved {
			return Evaluation{Allow, "high-risk action explicitly approved"}
		}
		return Evaluation{RequireApproval, "high-risk action requires explicit per-action approval"}
	default:
		return Evaluation{Deny, fmt.Sprintf("unknown risk %q", risk)}
	}
}

func withinScanWindows(windows []string, at time.Time) (bool, string) {
	if len(windows) == 0 {
		return true, ""
	}
	at = at.UTC()
	for index, raw := range windows {
		window, err := parseScanWindow(raw)
		if err != nil {
			return false, fmt.Sprintf("scan window %d is invalid: %v", index+1, err)
		}
		if window.contains(at) {
			return true, ""
		}
	}
	return false, "current UTC time is outside configured scan windows"
}

// ValidateScanWindows checks publication-time syntax without requiring the
// current instant to fall within a configured window.
func ValidateScanWindows(windows []string) error {
	for _, raw := range windows {
		if _, err := parseScanWindow(raw); err != nil {
			return err
		}
	}
	return nil
}

// CurrentScanWindowDeadline returns a conservative end of the current UTC
// window. A future executor must check this deadline again after commit.
func CurrentScanWindowDeadline(windows []string, at time.Time) (*time.Time, error) {
	if len(windows) == 0 {
		return nil, nil
	}
	at = at.UTC()
	var earliest *time.Time
	for _, raw := range windows {
		window, err := parseScanWindow(raw)
		if err != nil {
			return nil, err
		}
		if !window.contains(at) {
			continue
		}
		minute := at.Truncate(time.Minute)
		for offset := 1; offset <= 24*60+1; offset++ {
			candidate := minute.Add(time.Duration(offset) * time.Minute)
			if !window.contains(candidate) {
				if earliest == nil || candidate.Before(*earliest) {
					copy := candidate
					earliest = &copy
				}
				break
			}
		}
	}
	if earliest == nil {
		return nil, fmt.Errorf("time is outside configured scan windows")
	}
	return earliest, nil
}

type scanWindow struct {
	weekday *time.Weekday
	start   int
	end     int
}

func parseScanWindow(raw string) (scanWindow, error) {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) < 2 || !strings.EqualFold(fields[len(fields)-1], "UTC") {
		return scanWindow{}, fmt.Errorf("expected HH:MM-HH:MM UTC or Day HH:MM-HH:MM UTC")
	}
	fields = fields[:len(fields)-1]
	var day *time.Weekday
	var span string
	switch len(fields) {
	case 1:
		span = fields[0]
	case 2:
		value, ok := weekdays[strings.ToLower(fields[0])]
		if !ok {
			return scanWindow{}, fmt.Errorf("invalid weekday")
		}
		day = &value
		span = fields[1]
	default:
		return scanWindow{}, fmt.Errorf("invalid format")
	}
	startRaw, endRaw, ok := strings.Cut(span, "-")
	if !ok {
		return scanWindow{}, fmt.Errorf("missing time range")
	}
	start, err := clockMinute(startRaw)
	if err != nil {
		return scanWindow{}, err
	}
	end, err := clockMinute(endRaw)
	if err != nil {
		return scanWindow{}, err
	}
	if start == end {
		return scanWindow{}, fmt.Errorf("start and end must differ")
	}
	return scanWindow{weekday: day, start: start, end: end}, nil
}

var weekdays = map[string]time.Weekday{
	"sun": time.Sunday, "sunday": time.Sunday,
	"mon": time.Monday, "monday": time.Monday,
	"tue": time.Tuesday, "tuesday": time.Tuesday,
	"wed": time.Wednesday, "wednesday": time.Wednesday,
	"thu": time.Thursday, "thursday": time.Thursday,
	"fri": time.Friday, "friday": time.Friday,
	"sat": time.Saturday, "saturday": time.Saturday,
}

func clockMinute(raw string) (int, error) {
	parsed, err := time.Parse("15:04", raw)
	if err != nil {
		return 0, fmt.Errorf("invalid UTC time %q", raw)
	}
	return parsed.Hour()*60 + parsed.Minute(), nil
}

func (w scanWindow) contains(at time.Time) bool {
	minute := at.Hour()*60 + at.Minute()
	day := at.Weekday()
	if w.start < w.end {
		return (w.weekday == nil || day == *w.weekday) && minute >= w.start && minute < w.end
	}
	if minute >= w.start {
		return w.weekday == nil || day == *w.weekday
	}
	previous := (day + 6) % 7
	return minute < w.end && (w.weekday == nil || previous == *w.weekday)
}

// ParallelShare returns a conservative per-step slice of program-wide request
// and provider concurrency budgets. Providers that honor these policy fields
// cannot collectively exceed the configured program budget within a workflow
// execution wave.
func ParallelShare(p Policy, activeSteps int) Policy {
	if activeSteps < 2 {
		return p
	}
	p.RateLimit = share(p.RateLimit, activeSteps)
	p.Concurrency = share(p.Concurrency, activeSteps)
	return p
}

func ProgramParallelism(p Policy) int {
	parallelism := p.Concurrency
	if parallelism < 1 {
		parallelism = 1
	}
	if p.RateLimit > 0 && p.RateLimit < parallelism {
		parallelism = p.RateLimit
	}
	return parallelism
}

func share(value, parts int) int {
	if value < 1 {
		return value
	}
	value /= parts
	if value < 1 {
		return 1
	}
	return value
}
func ValidateHTTPMethod(p Policy, method string) error {
	method = strings.ToUpper(method)
	for _, m := range p.AllowedHTTPMethods {
		if strings.ToUpper(m) == method {
			return nil
		}
	}
	return fmt.Errorf("HTTP method %s denied by policy", method)
}
func contains(items []string, want string) bool {
	for _, v := range items {
		if v == want {
			return true
		}
	}
	return false
}
