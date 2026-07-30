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
