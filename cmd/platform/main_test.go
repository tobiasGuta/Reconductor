package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

func TestScopePlanCLIProducesJSONWithoutRuntimeConfiguration(t *testing.T) {
	path := filepath.ToSlash(filepath.Join("internal", "targeting", "testdata", "mixed_real_world_scope.json"))
	cfg, err := config.LoadPlanning()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Scope.Root = filepath.Join("..", "..")
	out, err := captureStdout(func() error { return scopeCommand(context.Background(), cfg, []string{"plan", "--scope", path}) })
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		NetworkExecution bool  `json:"network_execution"`
		Exact            []any `json:"exact_active_seeds"`
		Roots            []any `json:"discovery_roots"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(payload.Exact) == 0 || len(payload.Roots) == 0 {
		t.Fatalf("incomplete plan: %s", out)
	}
}

func TestArtifactStoreInitCLIHasOnlyFrozenFlagsAndRequiresStoreID(t *testing.T) {
	cfg := config.Config{ArtifactStorage: config.ArtifactStorage{Driver: "local", Root: t.TempDir()}}
	if err := artifactStoreCommand(context.Background(), cfg, []string{"init"}); err == nil || !strings.Contains(err.Error(), "ARTIFACT_STORE_ID is required") {
		t.Fatalf("missing StoreID error=%v", err)
	}
	if err := artifactStoreCommand(context.Background(), cfg, []string{"init", "unexpected"}); err == nil || !strings.Contains(err.Error(), "accepts no positional arguments") {
		t.Fatalf("positional argument error=%v", err)
	}
	if err := artifactStoreCommand(context.Background(), cfg, []string{"init", "--repair"}); err == nil {
		t.Fatal("unfrozen repair flag was accepted")
	}
	if err := artifactStoreCommand(context.Background(), cfg, []string{"show"}); err == nil {
		t.Fatal("unsupported artifact-store subcommand was accepted")
	}
	encoded, err := json.Marshal(artifactStoreInitOutput{StoreID: "00000000-0000-4000-8000-000000000001", BackendKind: "local-v1", MarkerFormat: "reconductor-artifact-store", MarkerVersion: 1, Status: "initialized"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "nonce") {
		t.Fatalf("successful output exposed nonce field: %s", encoded)
	}
}

func TestArtifactStoreCleanupCLIValidatesBatchSizeAndStoreID(t *testing.T) {
	cfg := config.Config{ArtifactStorage: config.ArtifactStorage{Driver: "local", Root: t.TempDir()}}
	if err := artifactStoreCommand(context.Background(), cfg, []string{"cleanup"}); err == nil || !strings.Contains(err.Error(), "ARTIFACT_STORE_ID is required") {
		t.Fatalf("missing StoreID error=%v", err)
	}
	if err := artifactStoreCommand(context.Background(), cfg, []string{"cleanup", "unexpected"}); err == nil || !strings.Contains(err.Error(), "accepts no positional arguments") {
		t.Fatalf("positional argument error=%v", err)
	}
	if err := artifactStoreCommand(context.Background(), cfg, []string{"cleanup", "--batch-size", "0"}); err == nil || !strings.Contains(err.Error(), "between 1 and 1000") {
		t.Fatalf("zero batch size error=%v", err)
	}
	if err := artifactStoreCommand(context.Background(), cfg, []string{"cleanup", "--batch-size", "-5"}); err == nil || !strings.Contains(err.Error(), "between 1 and 1000") {
		t.Fatalf("negative batch size error=%v", err)
	}
	if err := artifactStoreCommand(context.Background(), cfg, []string{"cleanup", "--batch-size", "1001"}); err == nil || !strings.Contains(err.Error(), "between 1 and 1000") {
		t.Fatalf("oversized batch size error=%v", err)
	}
	for _, flag := range []string{"--unfrozen-flag", "--interval", "--once", "--store-id"} {
		if err := artifactStoreCommand(context.Background(), cfg, []string{"cleanup", flag}); err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
			t.Fatalf("unfrozen cleanup flag %s: %v", flag, err)
		}
	}

	result := artifact.CleanupResult{
		ArtifactStoreID: "00000000-0000-4000-8000-000000000001",
		Claimed:         3,
		Removed:         1,
		AlreadyAbsent:   1,
		RetryScheduled:  0,
		LostClaim:       0,
		Quarantined: []artifact.QuarantinedArtifact{
			{ArtifactID: "00000000-0000-4000-8000-000000000002", ErrorCode: "unexpected_entry_type"},
		},
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"storage_key", "path", "sha256", "size", "content"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("cleanup output exposed forbidden field %q: %s", forbidden, encoded)
		}
	}
	emptyResult := artifact.CleanupResult{
		ArtifactStoreID: "00000000-0000-4000-8000-000000000001",
		Quarantined:     []artifact.QuarantinedArtifact{},
	}
	emptyEncoded, err := json.Marshal(emptyResult)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(emptyEncoded), `"quarantined": []`) && !strings.Contains(string(emptyEncoded), `"quarantined":[]`) {
		t.Fatalf("empty quarantined field did not serialize as empty array: %s", emptyEncoded)
	}
}

func TestArtifactStoreCleanupCLIOneBatchAndConfiguredAuthority(t *testing.T) {
	const storeID = "00000000-0000-4000-8000-000000000001"
	const artifactID = "00000000-0000-4000-8000-000000000002"
	for _, tc := range []struct {
		name string
		args []string
		batch int
	}{
		{"default", []string{"cleanup"}, 100},
		{"minimum", []string{"cleanup", "--batch-size", "1"}, 1},
		{"maximum", []string{"cleanup", "--batch-size", "1000"}, 1000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{ArtifactStorage: config.ArtifactStorage{StoreID: storeID}}
			calls := 0
			out, err := captureStdout(func() error {
				return artifactStoreCommandWithCleanup(context.Background(), cfg, tc.args, func(_ context.Context, gotCfg config.Config, gotID domain.ID, batch int) (artifact.CleanupResult, error) {
					calls++
					if calls != 1 || gotID != storeID || gotCfg.ArtifactStorage.StoreID != storeID || batch != tc.batch {
						t.Fatalf("dispatch calls=%d id=%s batch=%d", calls, gotID, batch)
					}
					// A full batch must still return without requesting another batch.
					return artifact.CleanupResult{ArtifactStoreID: gotID, Claimed: batch, Removed: batch-1, Quarantined: []artifact.QuarantinedArtifact{{ArtifactID: artifactID, ErrorCode: "unexpected_entry_type"}}}, nil
				})
			})
			if err != nil || calls != 1 { t.Fatalf("calls=%d err=%v", calls, err) }
			var result map[string]json.RawMessage
			if err := json.Unmarshal([]byte(out), &result); err != nil { t.Fatal(err) }
			if len(result) != 7 { t.Fatalf("unexpected output fields: %s", out) }
			for _, key := range []string{"artifact_store_id", "claimed", "removed", "already_absent", "retry_scheduled", "lost_claim", "quarantined"} {
				if _, ok := result[key]; !ok { t.Fatalf("missing %s: %s", key, out) }
			}
			var quarantined []map[string]string
			if err := json.Unmarshal(result["quarantined"], &quarantined); err != nil { t.Fatal(err) }
			if len(quarantined) != 1 || len(quarantined[0]) != 2 || quarantined[0]["artifact_id"] != artifactID || quarantined[0]["error_code"] != "unexpected_entry_type" {
				t.Fatalf("quarantine output: %s", out)
			}
		})
	}
	for _, invalidID := range []string{"", "not-a-uuid", "00000000-0000-4000-8000-00000000000A"} {
		cfg := config.Config{ArtifactStorage: config.ArtifactStorage{StoreID: invalidID}}
		err := artifactStoreCommandWithCleanup(context.Background(), cfg, []string{"cleanup"}, func(context.Context, config.Config, domain.ID, int) (artifact.CleanupResult, error) {
			t.Fatal("cleanup called with invalid configured identity")
			return artifact.CleanupResult{}, nil
		})
		if err == nil { t.Fatal("invalid configured identity accepted") }
	}
}

func TestOnlyExplicitAdministrativeCommandAppliesMigrations(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	platformSource := read("main.go")
	if strings.Count(platformSource, ".Migrate(ctx)") != 1 || !strings.Contains(platformSource, `case "migrate":`) {
		t.Fatal("platform schema mutation is not confined to the explicit migrate command")
	}
	if strings.Count(platformSource, "database.Open(ctx") != 2 || !strings.Contains(platformSource, "s.RequireCurrentSchema(ctx)") {
		t.Fatal("ordinary platform database startup does not use the fail-closed schema check")
	}
	for _, path := range []string{filepath.Join("..", "worker", "main.go"), filepath.Join("..", "scheduler", "main.go")} {
		source := read(path)
		if strings.Contains(source, ".Migrate(") || !strings.Contains(source, ".RequireCurrentSchema(ctx)") {
			t.Fatalf("ordinary startup schema contract is not enforced in %s", path)
		}
	}
}

func TestWorkflowPlanCLIAndRepeatedManualRoots(t *testing.T) {
	path := filepath.ToSlash(filepath.Join("internal", "targeting", "testdata", "mixed_real_world_scope.json"))
	cfg, err := config.LoadPlanning()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Scope.Root = filepath.Join("..", "..")
	out, err := captureStdout(func() error {
		return workflowPlan(cfg, providers.Registry(cfg), []string{"--program-id", "00000000-0000-0000-0000-000000000001", "--scope", path, "--discovery-root", "one.example", "--discovery-root", "two.example", "--discovery-root-reason", "passive operator request"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		NetworkExecution bool `json:"network_execution"`
		TargetPlan       struct {
			Roots []any `json:"discovery_roots"`
		} `json:"target_plan"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.NetworkExecution || len(payload.TargetPlan.Roots) < 3 {
		t.Fatalf("unexpected dry run: %s", out)
	}
}

func TestManualDiscoveryRootReasonAndDeprecatedDomainBehavior(t *testing.T) {
	if _, err := manualRoots([]string{"example.com"}, "", ""); err == nil {
		t.Fatal("missing reason accepted")
	}
	roots, err := manualRoots(nil, "", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 || roots[0].Reason == "" {
		t.Fatalf("deprecated domain was not auditable: %#v", roots)
	}
}

func TestWorkflowRunScopeDoesNotRequireDomain(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "targeting", "testdata", "mixed_real_world_scope.json")
	cfg, err := config.LoadPlanning()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database.URL = "://invalid"
	err = workflowRun(context.Background(), cfg, providers.Registry(cfg), []string{"--program-id", "00000000-0000-0000-0000-000000000001", "--scope", path, "--workflow", "authorized-web-baseline"})
	if err == nil {
		t.Fatal("expected database configuration failure")
	}
	if strings.Contains(err.Error(), "--domain") {
		t.Fatalf("domain is still required: %v", err)
	}
}

func TestConsoleListenAddressRequiresLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8088", "localhost:8090", "[::1]:8088"} {
		if err := requireLoopbackAddress(address); err != nil {
			t.Fatalf("loopback address %q rejected: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8088", ":8088", "192.0.2.10:8088", "localhost"} {
		if err := requireLoopbackAddress(address); err == nil {
			t.Fatalf("non-loopback or invalid address %q accepted", address)
		}
	}
}

type cancelledTaskReader struct{}

func (cancelledTaskReader) GetTask(context.Context, domain.ID) (domain.Task, error) {
	return domain.Task{Status: domain.TaskCancelled}, nil
}

func TestTaskCancellationReachesWorkflowControls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	controls := &workflow.Controls{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchTaskControlsInterval(ctx, cancelledTaskReader{}, domain.NewID(), controls, time.Millisecond)
	}()
	select {
	case <-controls.Done():
	case <-time.After(time.Second):
		t.Fatal("cancelled task did not signal workflow controls")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("task watcher did not stop after cancellation")
	}
}

func TestApprovalListJSONUsesCanonicalUUIDStrings(t *testing.T) {
	requestedAt := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	items := []database.ApprovalListItem{{
		ID:              "11111111-2222-4333-8444-555555555555",
		RequestID:       "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		TaskID:          "cc8e2cc2-c879-4157-aa41-e099a1611dbb",
		ActionRequestID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		Risk:            "moderate",
		Reason:          "workflow step run-safe-nuclei-profile",
		RequestedAt:     requestedAt,
		Decision:        "pending",
	}}
	out, err := captureStdout(func() error { return printJSON(items) })
	if err != nil {
		t.Fatal(err)
	}
	var payload []map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 1 {
		t.Fatalf("approvals=%d want=1", len(payload))
	}
	item := payload[0]
	for field, want := range map[string]string{
		"id":                "11111111-2222-4333-8444-555555555555",
		"request_id":        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		"action_request_id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		"task_id":           "cc8e2cc2-c879-4157-aa41-e099a1611dbb",
	} {
		if got, ok := item[field].(string); !ok || got != want {
			t.Fatalf("%s=%#v want UUID string %q", field, item[field], want)
		}
	}
	if item["risk"] != "moderate" || item["reason"] != "workflow step run-safe-nuclei-profile" || item["decision"] != "pending" || item["requested_at"] != requestedAt.Format(time.RFC3339) {
		t.Fatalf("existing approval fields changed: %#v", item)
	}
	for _, field := range []string{"decided_by", "decided_at", "expires_at"} {
		if value, ok := item[field]; !ok || value != nil {
			t.Fatalf("%s=%#v want explicit null", field, value)
		}
	}
	if len(item) != 11 {
		t.Fatalf("approval fields=%d want=11: %#v", len(item), item)
	}
}

func captureStdout(fn func() error) (string, error) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w
	read := make(chan struct {
		text string
		err  error
	}, 1)
	go func() {
		b, readErr := io.ReadAll(r)
		read <- struct {
			text string
			err  error
		}{string(b), readErr}
	}()
	callErr := fn()
	_ = w.Close()
	os.Stdout = old
	result := <-read
	_ = r.Close()
	if callErr != nil {
		return result.text, callErr
	}
	return result.text, result.err
}
