package config

import (
	"strings"
	"testing"
	"time"
)

func TestConsoleOperatorConfiguration(t *testing.T) {
	tests := []struct {
		name, token, actor string
		valid              bool
	}{
		{"missing credential", "", "operator", false},
		{"empty credential", "   ", "operator", false},
		{"short credential", "guessable", "operator", false},
		{"invalid bearer character", strings.Repeat("a", 32) + " ", "operator", false},
		{"missing actor", strings.Repeat("a", 64), "", false},
		{"blank actor", strings.Repeat("a", 64), " ", false},
		{"actor control character", strings.Repeat("a", 64), "operator\nforged", false},
		{"actor NUL", strings.Repeat("a", 64), "operator\x00forged", false},
		{"actor bidirectional control", strings.Repeat("a", 64), "operator\u202eforged", false},
		{"actor too long", strings.Repeat("a", 64), strings.Repeat("b", 81), false},
		{"valid", strings.Repeat("a", 64), "local-operator", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := LoadWith(func(key string) string {
				switch key {
				case "DATABASE_URL":
					return "postgres://local/db"
				case "CONSOLE_OPERATOR_TOKEN":
					return test.token
				case "CONSOLE_OPERATOR_ACTOR":
					return test.actor
				default:
					return ""
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Console.Validate() == nil; got != test.valid {
				t.Fatalf("console validation succeeded=%v, want=%v", got, test.valid)
			}
			if strings.Contains(cfg.String(), test.token) && test.token != "" {
				t.Fatal("configuration summary leaked console credential")
			}
		})
	}
}

func TestLoadAndSecretSafeString(t *testing.T) {
	env := map[string]string{"DATABASE_URL": "postgres://user:secret@localhost/db", "REDIS_ADDR": "localhost:6379", "REDIS_PASSWORD": "redis-secret", "SCOPE_ROOT": `D:\Reconductor`, "NUCLEI_RATE_LIMIT": "17", "HTTPX_EXECUTABLE": `C:\tools\projectdiscovery\httpx.exe`}
	c, err := LoadWith(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Nuclei.RateLimit != 17 {
		t.Fatalf("rate limit=%d", c.Nuclei.RateLimit)
	}
	if c.Policy.DefaultProviderConcurrency != 2 || c.Policy.DefaultHostConcurrency != 1 {
		t.Fatalf("unexpected execution budgets: %#v", c.Policy)
	}
	if c.Policy.ArtifactRetention != 720*time.Hour || c.Policy.AuthenticationUsage || c.Policy.DirectoryFuzzing || c.Policy.CrossOrigin || c.Policy.IntrusiveChecks {
		t.Fatalf("unexpected restrictive policy defaults: %#v", c.Policy)
	}
	if c.Tools.HTTPX != `C:\tools\projectdiscovery\httpx.exe` || c.Tools.DNSx != "dnsx" {
		t.Fatalf("unexpected tool executables: %#v", c.Tools)
	}
	if c.Scope.Root != `D:\Reconductor` {
		t.Fatalf("scope root = %q", c.Scope.Root)
	}
	safe := c.String()
	if strings.Contains(safe, "secret") {
		t.Fatalf("config string leaked a secret: %s", safe)
	}
}
func TestConfigValidation(t *testing.T) {
	tests := []map[string]string{{}, {"DATABASE_URL": "x", "REDIS_ADDR": "missing-port"}, {"DATABASE_URL": "x", "REDIS_ADDR": "localhost:6379", "RECON_HEADLESS": "maybe"}, {"DATABASE_URL": "x", "REDIS_ADDR": "localhost:6379", "NUCLEI_RATE_LIMIT": "0"}, {"DATABASE_URL": "x", "REDIS_ADDR": "localhost:6379", "POLICY_PROVIDER_CONCURRENCY": "0"}, {"DATABASE_URL": "x", "REDIS_ADDR": "localhost:6379", "POLICY_HOST_CONCURRENCY": "0"}, {"DATABASE_URL": "x", "REDIS_ADDR": "localhost:6379", "POLICY_AUTHENTICATION_USAGE": "maybe"}, {"DATABASE_URL": "x", "REDIS_ADDR": "localhost:6379", "POLICY_ARTIFACT_RETENTION": "forever"}, {"DATABASE_URL": "x", "REDIS_ADDR": "localhost:6379", "POLICY_SCAN_WINDOWS": "weekends"}, {"DATABASE_URL": "x", "REDIS_ADDR": "localhost:6379", "RECON_PIPELINE": "sx"}}
	for i, env := range tests {
		if _, err := LoadWith(func(k string) string { return env[k] }); err == nil {
			t.Errorf("case %d expected error", i)
		}
	}
}

func TestStepAttemptLeaseTimeout(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "x", "REDIS_ADDR": "localhost:6379"}
	load := func() (Config, error) {
		return LoadWith(func(key string) string { return base[key] })
	}

	cfg, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StepAttemptLeaseTimeout != 2*time.Minute {
		t.Fatalf("default step attempt lease=%s", cfg.StepAttemptLeaseTimeout)
	}

	for _, test := range []struct {
		value string
		valid bool
	}{
		{value: "3s", valid: true},
		{value: "15m", valid: true},
		{value: "2999ms", valid: false},
		{value: "15m1ms", valid: false},
		{value: "not-a-duration", valid: false},
	} {
		base["STEP_ATTEMPT_LEASE_TIMEOUT"] = test.value
		cfg, err = load()
		if test.valid && (err != nil || cfg.StepAttemptLeaseTimeout <= 0) {
			t.Fatalf("lease %q rejected: config=%#v error=%v", test.value, cfg, err)
		}
		if !test.valid && err == nil {
			t.Fatalf("lease %q unexpectedly accepted", test.value)
		}
	}
}

func TestArtifactStoreIDIsCommandScopedAndDockerVariableIsIgnored(t *testing.T) {
	env := map[string]string{
		"DATABASE_URL":             "postgres://integration",
		"REDIS_ADDR":               "localhost:6379",
		"DOCKER_ARTIFACT_STORE_ID": "00000000-0000-4000-8000-000000000099",
	}
	cfg, err := LoadWith(func(key string) string { return env[key] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ArtifactStorage.StoreID != "" {
		t.Fatalf("Docker-only store ID entered Go configuration: %q", cfg.ArtifactStorage.StoreID)
	}
	if _, err := cfg.ArtifactStorage.RequiredStoreID(); err == nil {
		t.Fatal("artifact-producing execution accepted a missing native StoreID")
	}
	env["ARTIFACT_STORE_ID"] = "00000000-0000-4000-8000-000000000001"
	cfg, err = LoadWith(func(key string) string { return env[key] })
	if err != nil {
		t.Fatal(err)
	}
	if id, err := cfg.ArtifactStorage.RequiredStoreID(); err != nil || id != "00000000-0000-4000-8000-000000000001" {
		t.Fatalf("StoreID=%q error=%v", id, err)
	}
	env["ARTIFACT_STORE_ID"] = "00000000-0000-4000-8000-000000000001 "
	if cfg, err = LoadWith(func(key string) string { return env[key] }); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ArtifactStorage.RequiredStoreID(); err != nil {
		t.Fatalf("trimmed configured StoreID rejected: %v", err)
	}
	env["ARTIFACT_STORE_ID"] = "00000000-0000-4000-8000-00000000000A"
	if cfg, err = LoadWith(func(key string) string { return env[key] }); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ArtifactStorage.RequiredStoreID(); err == nil {
		t.Fatal("noncanonical StoreID accepted")
	}
}
