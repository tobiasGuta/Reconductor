package config

import (
	"strings"
	"testing"
	"time"
)

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
