//go:build operational

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestValidateInvocationAllowsOnlyIsolatedLifecycle(t *testing.T) {
	root := t.TempDir()
	cfg := guardConfig{
		realNuclei:   filepath.Join(root, "nuclei.exe"),
		fixtureURL:   "http://127.0.0.1:33000/",
		templateDir:  filepath.Join(root, "templates"),
		templateFile: filepath.Join(root, "templates", "local-http-200.yaml"),
		logPath:      filepath.Join(root, "invocations.jsonl"),
		isolatedHome: filepath.Join(root, "home"),
	}
	if err := os.MkdirAll(cfg.templateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.templateFile, []byte("id: reconductor-local-approval\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		args       []string
		priorScans int
		kind       string
		wantErr    string
	}{
		{name: "version", args: []string{"-version"}, kind: "version"},
		{name: "validation", args: []string{"-validate", "-t", cfg.templateFile, "-severity", "info", "-tags", "reconductor-e2e"}, kind: "validation"},
		{name: "scan", args: scanArgs(cfg), kind: "scan"},
		{name: "repeated target", args: append(scanArgs(cfg), "-u", cfg.fixtureURL), wantErr: "exactly one target"},
		{name: "repeated template", args: append(scanArgs(cfg), "-t", cfg.templateDir), wantErr: "-t must appear exactly once"},
		{name: "repeated tags", args: append(scanArgs(cfg), "-tags", "reconductor-e2e"), wantErr: "-tags must appear exactly once"},
		{name: "repeated severity", args: append(scanArgs(cfg), "-severity", "info"), wantErr: "-severity must appear exactly once"},
		{name: "external target", args: replaceArg(scanArgs(cfg), cfg.fixtureURL, "https://example.com/"), wantErr: "exactly one target"},
		{name: "second scan", args: scanArgs(cfg), priorScans: 1, wantErr: "already invoked"},
		{name: "wrong template", args: replaceArg(scanArgs(cfg), cfg.templateDir, filepath.Join(root, "other")), wantErr: "outside the isolated"},
		{name: "relative template", args: replaceArg(scanArgs(cfg), cfg.templateDir, "templates"), wantErr: "outside the isolated"},
		{name: "template traversal", args: replaceArg(scanArgs(cfg), cfg.templateDir, cfg.templateDir+string(filepath.Separator)+"child"+string(filepath.Separator)+".."), wantErr: "outside the isolated"},
		{name: "template case trick", args: replaceArg(scanArgs(cfg), cfg.templateDir, strings.ToUpper(cfg.templateDir)), wantErr: "outside the isolated"},
		{name: "wrong severity", args: replaceArg(scanArgs(cfg), "info", "high"), wantErr: "-severity value"},
		{name: "wrong tags", args: replaceArg(scanArgs(cfg), "reconductor-e2e", "cve"), wantErr: "-tags value"},
		{name: "unexpected flag", args: append(scanArgs(cfg), "-headless"), wantErr: "unexpected Nuclei argument"},
		{name: "target alias", args: append(scanArgs(cfg), "-target", cfg.fixtureURL), wantErr: `unexpected Nuclei argument "-target"`},
		{name: "long target alias", args: append(scanArgs(cfg), "--target", cfg.fixtureURL), wantErr: `unexpected Nuclei argument "--target"`},
		{name: "target file", args: append(scanArgs(cfg), "-l", filepath.Join(root, "targets.txt")), wantErr: `unexpected Nuclei argument "-l"`},
		{name: "long target file", args: append(scanArgs(cfg), "-target-file", filepath.Join(root, "targets.txt")), wantErr: `unexpected Nuclei argument "-target-file"`},
		{name: "inline target", args: append(scanArgs(cfg), "-u="+cfg.fixtureURL), wantErr: `unexpected Nuclei argument`},
		{name: "inline template", args: append(scanArgs(cfg), "-t="+cfg.templateDir), wantErr: `unexpected Nuclei argument`},
		{name: "config file", args: append(scanArgs(cfg), "-config", filepath.Join(root, "config.yaml")), wantErr: `unexpected Nuclei argument "-config"`},
		{name: "template list", args: append(scanArgs(cfg), "-tl"), wantErr: `unexpected Nuclei argument "-tl"`},
		{name: "list alias", args: append(scanArgs(cfg), "-list", filepath.Join(root, "targets.txt")), wantErr: `unexpected Nuclei argument "-list"`},
		{name: "workflow", args: append(scanArgs(cfg), "-w", filepath.Join(root, "workflow.yaml")), wantErr: `unexpected Nuclei argument "-w"`},
		{name: "workflow alias", args: append(scanArgs(cfg), "-workflow", filepath.Join(root, "workflow.yaml")), wantErr: `unexpected Nuclei argument "-workflow"`},
		{name: "missing target value", args: []string{"-u"}, wantErr: "-u requires a value"},
		{name: "missing template value", args: []string{"-t"}, wantErr: "-t requires a value"},
		{name: "missing tags value", args: []string{"-tags"}, wantErr: "-tags requires a value"},
		{name: "missing severity value", args: []string{"-severity"}, wantErr: "-severity requires a value"},
		{name: "validation directory", args: []string{"-validate", "-t", cfg.templateDir, "-severity", "info", "-tags", "reconductor-e2e"}, wantErr: "not the isolated path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry, delegated, err := validateInvocation(test.args, cfg, test.priorScans)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error=%v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if entry.Kind != test.kind {
				t.Fatalf("kind=%q want=%q", entry.Kind, test.kind)
			}
			if !contains(delegated, "-duc") || !contains(delegated, "-ni") {
				t.Fatalf("delegated args omit safety flags: %v", delegated)
			}
		})
	}
}

func TestIsolatedEnvironmentReplacesUserTemplateLocations(t *testing.T) {
	root := t.TempDir()
	cfg := guardConfig{isolatedHome: filepath.Join(root, "home"), templateDir: filepath.Join(root, "templates")}
	got := isolatedEnvironment([]string{
		"PATH=test",
		"HOME=C:\\Users\\normal",
		"USERPROFILE=C:\\Users\\normal",
		"NUCLEI_CONFIG_DIR=C:\\Users\\normal\\.config",
		"NUCLEI_TEMPLATES_DIR=C:\\Users\\normal\\nuclei-templates",
		"NUCLEI_SIGNATURE_PRIVATE_KEY=secret",
		"PDCP_API_KEY=secret",
		"HTTP_PROXY=https://proxy.example.test",
		"HTTPS_PROXY=https://proxy.example.test",
		"ALL_PROXY=https://proxy.example.test",
	}, cfg)
	values := environmentMap(got)
	if values["HOME"] != cfg.isolatedHome || values["USERPROFILE"] != cfg.isolatedHome {
		t.Fatalf("home was not isolated: %#v", values)
	}
	if values["NUCLEI_TEMPLATES_DIR"] != cfg.templateDir {
		t.Fatalf("template directory=%q want=%q", values["NUCLEI_TEMPLATES_DIR"], cfg.templateDir)
	}
	for _, key := range []string{
		"DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD",
		"DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD",
		"DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD",
		"DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD",
		"DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD",
	} {
		if values[key] != "true" {
			t.Fatalf("%s=%q want true", key, values[key])
		}
	}
	if reflect.DeepEqual(values["HOME"], `C:\Users\normal`) {
		t.Fatal("normal user home remained in delegated environment")
	}
	for _, key := range []string{"NUCLEI_SIGNATURE_PRIVATE_KEY", "PDCP_API_KEY", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
		if _, ok := values[key]; ok {
			t.Fatalf("unsafe inherited environment variable %s remained", key)
		}
	}
	if values["NO_PROXY"] != "127.0.0.1,localhost" {
		t.Fatalf("loopback proxy bypass was not enforced: %#v", values)
	}
}

func TestInvocationLogCountsOnlyAcceptedScans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard", "invocations.jsonl")
	for _, entry := range []invocation{
		{Kind: "version", Accepted: true},
		{Kind: "validation", Accepted: true},
		{Kind: "scan", Accepted: false},
		{Kind: "scan", Accepted: true},
	} {
		if err := appendInvocation(path, entry); err != nil {
			t.Fatal(err)
		}
	}
	count, err := countAcceptedScans(path)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("accepted scans=%d want=1", count)
	}
}

func TestReserveScanIsExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard", "invocations.jsonl")
	if err := reserveScan(path); err != nil {
		t.Fatal(err)
	}
	if err := reserveScan(path); err == nil || !strings.Contains(err.Error(), "already reserved") {
		t.Fatalf("second reservation error=%v", err)
	}
}

func TestExactIsolatedPathRejectsAliases(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "template.yaml")
	if err := os.WriteFile(allowed, []byte("id: test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !exactIsolatedPath(allowed, allowed) {
		t.Fatal("exact existing path was rejected")
	}
	for _, candidate := range []string{
		filepath.Base(allowed),
		root + string(filepath.Separator) + "child" + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(allowed),
		strings.ToUpper(allowed),
	} {
		if candidate == allowed {
			continue
		}
		if exactIsolatedPath(candidate, allowed) {
			t.Fatalf("path alias %q was accepted", candidate)
		}
	}
	if runtime.GOOS == "windows" && exactIsolatedPath(`\\?\`+allowed, allowed) {
		t.Fatal("extended-length Windows path alias was accepted")
	}
	alias := filepath.Join(root, "alias.yaml")
	if err := os.Symlink(allowed, alias); err != nil {
		if runtime.GOOS == "windows" {
			t.Logf("symlink adversarial case unavailable without Windows symlink privilege: %v", err)
			return
		}
		t.Fatal(err)
	}
	if exactIsolatedPath(alias, allowed) {
		t.Fatal("symlink alias was accepted")
	}
}

func scanArgs(cfg guardConfig) []string {
	return []string{
		"-u", cfg.fixtureURL,
		"-jsonl", "-silent", "-dr",
		"-rl", "1",
		"-c", "1",
		"-bulk-size", "1",
		"-headc", "1",
		"-severity", "info",
		"-tags", "reconductor-e2e",
		"-etags", "dos,fuzz,bruteforce,intrusive",
		"-t", cfg.templateDir,
	}
}

func replaceArg(args []string, old, replacement string) []string {
	out := append([]string(nil), args...)
	for index := range out {
		if out[index] == old {
			out[index] = replacement
			return out
		}
	}
	return out
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func environmentMap(values []string) map[string]string {
	out := map[string]string{}
	for _, item := range values {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			out[strings.ToUpper(key)] = value
		}
	}
	return out
}
