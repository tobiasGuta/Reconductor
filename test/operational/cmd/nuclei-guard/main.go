//go:build operational

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	envRealNuclei   = "RECONDUCTOR_E2E_REAL_NUCLEI"
	envFixtureURL   = "RECONDUCTOR_E2E_FIXTURE_URL"
	envTemplateDir  = "RECONDUCTOR_E2E_TEMPLATE_DIR"
	envTemplateFile = "RECONDUCTOR_E2E_TEMPLATE_FILE"
	envLogPath      = "RECONDUCTOR_E2E_INVOCATION_LOG"
	envIsolatedHome = "RECONDUCTOR_E2E_HOME"
)

type guardConfig struct {
	realNuclei   string
	fixtureURL   string
	templateDir  string
	templateFile string
	logPath      string
	isolatedHome string
}

type invocation struct {
	At             time.Time `json:"at"`
	Kind           string    `json:"kind"`
	Accepted       bool      `json:"accepted"`
	OriginalArgs   []string  `json:"original_args"`
	DelegatedArgs  []string  `json:"delegated_args,omitempty"`
	Targets        []string  `json:"targets,omitempty"`
	TemplatePaths  []string  `json:"template_paths,omitempty"`
	RejectionCause string    `json:"rejection_cause,omitempty"`
}

type parsedArgs struct {
	values map[string][]string
	flags  map[string]int
}

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nuclei guard:", err)
		return 2
	}
	original := append([]string(nil), os.Args[1:]...)
	priorScans, err := countAcceptedScans(cfg.logPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nuclei guard: read invocation log:", err)
		return 2
	}
	entry, delegated, err := validateInvocation(original, cfg, priorScans)
	if err != nil {
		recordRejection(cfg.logPath, &entry, err)
		fmt.Fprintln(os.Stderr, "nuclei guard:", err)
		return 2
	}
	if entry.Kind == "scan" {
		if err := reserveScan(cfg.logPath); err != nil {
			recordRejection(cfg.logPath, &entry, err)
			fmt.Fprintln(os.Stderr, "nuclei guard:", err)
			return 2
		}
	}
	entry.At = time.Now().UTC()
	entry.Accepted = true
	entry.DelegatedArgs = append([]string(nil), delegated...)
	if err := appendInvocation(cfg.logPath, entry); err != nil {
		fmt.Fprintln(os.Stderr, "nuclei guard: record invocation:", err)
		return 2
	}

	if err := prepareIsolatedDirectories(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "nuclei guard: prepare isolated directories:", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd := exec.CommandContext(ctx, cfg.realNuclei, delegated...)
	cmd.Dir = cfg.isolatedHome
	cmd.Env = isolatedEnvironment(os.Environ(), cfg)
	// Never forward guard stdin. Nuclei accepts targets from stdin, so even an
	// otherwise valid -u invocation would be bypassable if inherited bytes
	// reached the real process.
	cmd.Stdin = bytes.NewReader(nil)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "nuclei guard: execute real nuclei:", err)
		return 1
	}
	return 0
}

func recordRejection(path string, entry *invocation, cause error) {
	entry.At = time.Now().UTC()
	entry.Accepted = false
	entry.RejectionCause = cause.Error()
	_ = appendInvocation(path, *entry)
}

func loadConfig(getenv func(string) string) (guardConfig, error) {
	cfg := guardConfig{
		realNuclei:   strings.TrimSpace(getenv(envRealNuclei)),
		fixtureURL:   strings.TrimSpace(getenv(envFixtureURL)),
		templateDir:  strings.TrimSpace(getenv(envTemplateDir)),
		templateFile: strings.TrimSpace(getenv(envTemplateFile)),
		logPath:      strings.TrimSpace(getenv(envLogPath)),
		isolatedHome: strings.TrimSpace(getenv(envIsolatedHome)),
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{envRealNuclei, cfg.realNuclei},
		{envFixtureURL, cfg.fixtureURL},
		{envTemplateDir, cfg.templateDir},
		{envTemplateFile, cfg.templateFile},
		{envLogPath, cfg.logPath},
		{envIsolatedHome, cfg.isolatedHome},
	} {
		if field.value == "" {
			return guardConfig{}, fmt.Errorf("%s is required", field.name)
		}
	}
	var err error
	if cfg.realNuclei, err = filepath.Abs(cfg.realNuclei); err != nil {
		return guardConfig{}, fmt.Errorf("resolve real nuclei: %w", err)
	}
	if cfg.templateDir, err = filepath.Abs(cfg.templateDir); err != nil {
		return guardConfig{}, fmt.Errorf("resolve template directory: %w", err)
	}
	if cfg.templateFile, err = filepath.Abs(cfg.templateFile); err != nil {
		return guardConfig{}, fmt.Errorf("resolve template file: %w", err)
	}
	if cfg.logPath, err = filepath.Abs(cfg.logPath); err != nil {
		return guardConfig{}, fmt.Errorf("resolve invocation log: %w", err)
	}
	if cfg.isolatedHome, err = filepath.Abs(cfg.isolatedHome); err != nil {
		return guardConfig{}, fmt.Errorf("resolve isolated home: %w", err)
	}
	return cfg, nil
}

func validateInvocation(args []string, cfg guardConfig, priorScans int) (invocation, []string, error) {
	entry := invocation{OriginalArgs: append([]string(nil), args...)}
	if len(args) == 1 && (args[0] == "-version" || args[0] == "--version") {
		entry.Kind = "version"
		return entry, appendSafetyFlags(args), nil
	}

	parsed, err := parseArguments(args)
	if err != nil {
		entry.Kind = "rejected"
		return entry, nil, err
	}
	entry.Targets = append([]string(nil), parsed.values["-u"]...)
	entry.TemplatePaths = append([]string(nil), parsed.values["-t"]...)

	if parsed.flags["-validate"] == 1 {
		entry.Kind = "validation"
		if len(entry.Targets) != 0 {
			return entry, nil, fmt.Errorf("template validation must not contain targets")
		}
		if err := requireSingleValue(parsed, "-t", cfg.templateFile, true); err != nil {
			return entry, nil, err
		}
		if err := requireSingleValue(parsed, "-severity", "info", false); err != nil {
			return entry, nil, err
		}
		if err := requireSingleValue(parsed, "-tags", "reconductor-e2e", false); err != nil {
			return entry, nil, err
		}
		if len(parsed.values["-etags"]) != 0 {
			return entry, nil, fmt.Errorf("template validation does not accept -etags")
		}
		return entry, appendSafetyFlags(args), nil
	}

	entry.Kind = "scan"
	if parsed.flags["-validate"] != 0 {
		return entry, nil, fmt.Errorf("-validate must appear exactly once for validation")
	}
	if priorScans != 0 {
		return entry, nil, fmt.Errorf("actual Nuclei scan already invoked %d time(s)", priorScans)
	}
	if len(entry.Targets) != 1 || entry.Targets[0] != cfg.fixtureURL {
		return entry, nil, fmt.Errorf("scan requires exactly one target equal to %q", cfg.fixtureURL)
	}
	if err := requireSinglePathValue(parsed, "-t", cfg.templateDir, cfg.templateFile); err != nil {
		return entry, nil, err
	}
	for _, expected := range []string{"-jsonl", "-silent", "-dr"} {
		if parsed.flags[expected] != 1 {
			return entry, nil, fmt.Errorf("scan requires exactly one %s flag", expected)
		}
	}
	for _, field := range []struct {
		flag string
		want string
	}{
		{"-rl", "1"},
		{"-c", "1"},
		{"-bulk-size", "1"},
		{"-headc", "1"},
		{"-severity", "info"},
		{"-tags", "reconductor-e2e"},
		{"-etags", "dos,fuzz,bruteforce,intrusive"},
	} {
		if err := requireSingleValue(parsed, field.flag, field.want, false); err != nil {
			return entry, nil, err
		}
	}
	return entry, appendSafetyFlags(args), nil
}

func parseArguments(args []string) (parsedArgs, error) {
	valueFlags := map[string]bool{
		"-u": true, "-t": true, "-severity": true, "-tags": true, "-etags": true,
		"-rl": true, "-c": true, "-bulk-size": true, "-headc": true,
	}
	boolFlags := map[string]bool{
		"-validate": true, "-jsonl": true, "-silent": true, "-dr": true,
		"-duc": true, "-ni": true,
	}
	parsed := parsedArgs{values: map[string][]string{}, flags: map[string]int{}}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case valueFlags[arg]:
			if index+1 >= len(args) || strings.HasPrefix(args[index+1], "-") {
				return parsedArgs{}, fmt.Errorf("%s requires a value", arg)
			}
			index++
			parsed.values[arg] = append(parsed.values[arg], args[index])
		case boolFlags[arg]:
			parsed.flags[arg]++
			if parsed.flags[arg] > 1 {
				return parsedArgs{}, fmt.Errorf("%s may appear only once", arg)
			}
		default:
			return parsedArgs{}, fmt.Errorf("unexpected Nuclei argument %q", arg)
		}
	}
	return parsed, nil
}

func requireSingleValue(parsed parsedArgs, flag, want string, path bool) error {
	values := parsed.values[flag]
	if len(values) != 1 {
		return fmt.Errorf("%s must appear exactly once", flag)
	}
	if path {
		if !exactIsolatedPath(values[0], want) {
			return fmt.Errorf("%s path %q is not the isolated path %q", flag, values[0], want)
		}
		return nil
	}
	if values[0] != want {
		return fmt.Errorf("%s value %q must equal %q", flag, values[0], want)
	}
	return nil
}

func requireSinglePathValue(parsed parsedArgs, flag string, allowed ...string) error {
	values := parsed.values[flag]
	if len(values) != 1 {
		return fmt.Errorf("%s must appear exactly once", flag)
	}
	for _, candidate := range allowed {
		if exactIsolatedPath(values[0], candidate) {
			return nil
		}
	}
	return fmt.Errorf("%s path %q is outside the isolated template paths", flag, values[0])
}

func appendSafetyFlags(args []string) []string {
	out := append([]string(nil), args...)
	seen := map[string]bool{}
	for _, arg := range args {
		seen[arg] = true
	}
	for _, flag := range []string{"-duc", "-ni"} {
		if !seen[flag] {
			out = append(out, flag)
		}
	}
	return out
}

func isolatedEnvironment(base []string, cfg guardConfig) []string {
	safeBaseKeys := map[string]bool{
		"COMSPEC": true, "PATH": true, "PATHEXT": true, "SYSTEMROOT": true, "WINDIR": true,
	}
	baseValues := map[string]string{}
	for _, item := range base {
		key, value, ok := strings.Cut(item, "=")
		key = strings.ToUpper(key)
		if ok && safeBaseKeys[key] {
			baseValues[key] = value
		}
	}
	overrides := map[string]string{
		"HOME":                 cfg.isolatedHome,
		"USERPROFILE":          cfg.isolatedHome,
		"HOMEDRIVE":            filepath.VolumeName(cfg.isolatedHome),
		"HOMEPATH":             strings.TrimPrefix(cfg.isolatedHome, filepath.VolumeName(cfg.isolatedHome)),
		"APPDATA":              filepath.Join(cfg.isolatedHome, "appdata"),
		"LOCALAPPDATA":         filepath.Join(cfg.isolatedHome, "localappdata"),
		"XDG_CONFIG_HOME":      filepath.Join(cfg.isolatedHome, ".config"),
		"TEMP":                 filepath.Join(cfg.isolatedHome, "tmp"),
		"TMP":                  filepath.Join(cfg.isolatedHome, "tmp"),
		"NO_PROXY":             "127.0.0.1,localhost",
		"no_proxy":             "127.0.0.1,localhost",
		"NUCLEI_CONFIG_DIR":    filepath.Join(cfg.isolatedHome, "nuclei-config"),
		"NUCLEI_TEMPLATES_DIR": cfg.templateDir,
		"DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD": "true",
		"DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD": "true",
		"DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD": "true",
		"DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD":    "true",
		"DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD":  "true",
	}
	for key, value := range overrides {
		baseValues[key] = value
	}
	keys := make([]string, 0, len(baseValues))
	for key := range baseValues {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+baseValues[key])
	}
	return out
}

func exactIsolatedPath(candidate, allowed string) bool {
	if !filepath.IsAbs(candidate) || filepath.Clean(candidate) != candidate || candidate != allowed {
		return false
	}
	candidateInfo, candidateErr := os.Lstat(candidate)
	allowedInfo, allowedErr := os.Lstat(allowed)
	if candidateErr != nil || allowedErr != nil || candidateInfo.Mode()&os.ModeSymlink != 0 || allowedInfo.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return os.SameFile(candidateInfo, allowedInfo)
}

func prepareIsolatedDirectories(cfg guardConfig) error {
	for _, directory := range []string{
		cfg.isolatedHome,
		filepath.Join(cfg.isolatedHome, "nuclei-config"),
		filepath.Join(cfg.isolatedHome, "appdata"),
		filepath.Join(cfg.isolatedHome, "localappdata"),
		filepath.Join(cfg.isolatedHome, ".config"),
		filepath.Join(cfg.isolatedHome, "tmp"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func appendInvocation(path string, entry invocation) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(entry)
}

func countAcceptedScans(path string) (int, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer file.Close()
	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry invocation
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return 0, fmt.Errorf("decode invocation line: %w", err)
		}
		if entry.Accepted && entry.Kind == "scan" {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

func reserveScan(logPath string) error {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return err
	}
	lockPath := logPath + ".scan.lock"
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("actual Nuclei scan was already reserved")
	}
	if err != nil {
		return fmt.Errorf("reserve actual Nuclei scan: %w", err)
	}
	defer file.Close()
	_, err = fmt.Fprintf(file, "%d\n", os.Getpid())
	return err
}
