package database

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/findings"
)

func TestVerificationVerdictsPersistAndGatePromotion(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()

	schema := "verification_" + strings.ReplaceAll(string(domain.NewID()), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop integration schema: %v", err)
		}
	}()

	u, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	store, err := Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	programID, definitionID, taskID, runID, assetID, candidateID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	program := domain.Program{
		ID: programID, Name: "verification-" + string(programID), Platform: "integration", Description: "synthetic local integration data",
		ScopeReference: "synthetic://local", PolicyReference: "integration", ScopeDigest: "scope", IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{},
		TargetPlanDigest: "plan", ScopePlanWarnings: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now,
	}
	snapshot := domain.ScopeSnapshot{ScopeReference: program.ScopeReference, ScopeDigest: program.ScopeDigest, IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: program.TargetPlanDigest, PlanningWarnings: json.RawMessage(`[]`), TargetPlan: json.RawMessage(`{}`), CreatedAt: now}
	if err := store.CreateProgram(ctx, program, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateWorkflowDefinition(ctx, definitionID, "verification-"+string(definitionID), "1", "synthetic", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	task := domain.Task{ID: taskID, ProgramID: programID, Objective: "verify verdict persistence", WorkflowDefinitionID: definitionID, Status: domain.TaskRunning, RequestedBy: "integration-test", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateWorkflowRun(ctx, domain.WorkflowRun{ID: runID, TaskID: taskID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunCompleted, StartedAt: &now, CompletedAt: &now, TriggerSource: "integration-test", Summary: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO assets(id,program_id,type,canonical_value) VALUES($1,$2,'url','https://app.example.test/openapi.json')`, assetID, programID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO candidate_findings(id,task_id,workflow_run_id,target_asset_id,source_capability,template_id,claimed_vulnerability,severity,evidence_artifact_ids,detection_confidence,status) VALUES($1,$2,$3,$4,'scan.nuclei','openapi','OpenAPI exposed','medium','{}',0.7,'verifying')`, candidateID, taskID, runID, assetID); err != nil {
		t.Fatal(err)
	}

	_, err = store.RecordVerification(ctx, candidateID, "playbook", findings.Verification{Playbook: "openapi", Verdict: findings.VerdictManual, EvidenceVerdict: findings.EvidenceObserved, ImpactVerdict: findings.ImpactUnreviewed, Summary: "behavior observed; impact unreviewed"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PromoteVerifiedFinding(ctx, candidateID, "integration-test"); err == nil {
		t.Fatal("candidate promoted without confirmed impact")
	}

	verificationID, err := store.RecordVerification(ctx, candidateID, "human-review", findings.Verification{Playbook: "openapi", Verdict: findings.VerdictConfirmed, EvidenceVerdict: findings.EvidenceObserved, ImpactVerdict: findings.ImpactConfirmed, Summary: "review confirmed sensitive exposed schema impact"}, []domain.ID{domain.ID("00000000-0000-0000-0000-000000000001")})
	if err != nil {
		t.Fatal(err)
	}
	var evidenceVerdict, impactVerdict string
	if err := store.Pool.QueryRow(ctx, `SELECT evidence_verdict,impact_verdict FROM verification_results WHERE id=$1`, verificationID).Scan(&evidenceVerdict, &impactVerdict); err != nil {
		t.Fatal(err)
	}
	if evidenceVerdict != "observed" || impactVerdict != "confirmed" {
		t.Fatalf("stored verdicts evidence=%q impact=%q", evidenceVerdict, impactVerdict)
	}
	verifiedID, err := store.PromoteVerifiedFinding(ctx, candidateID, "integration-test")
	if err != nil {
		t.Fatal(err)
	}
	if verifiedID == "" {
		t.Fatal("verified finding id was not returned")
	}

	console, err := store.ConsoleSnapshot(ctx, programID)
	if err != nil {
		t.Fatal(err)
	}
	if len(console.Verifications) != 2 || console.Verifications[0].EvidenceVerdict != "observed" || console.Verifications[0].ImpactVerdict != "confirmed" {
		t.Fatalf("console verifications missing layered verdicts: %#v", console.Verifications)
	}
	if len(console.Candidates) != 1 || console.Candidates[0].LatestEvidenceVerdict != "observed" || console.Candidates[0].LatestImpactVerdict != "confirmed" {
		t.Fatalf("console candidate missing latest layered verdict: %#v", console.Candidates)
	}
	if len(console.VerifiedFindings) != 1 || console.VerifiedFindings[0].ID != verifiedID {
		t.Fatalf("console verified finding mismatch: %#v", console.VerifiedFindings)
	}
}
