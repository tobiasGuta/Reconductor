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
	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/execution"
	"github.com/tobiasGuta/Reconductor/internal/findings"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
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
	ensureSyntheticWorkflowTemplate(t, store, ctx, definitionID, "verification-"+string(definitionID))
	task := domain.Task{ID: taskID, ProgramID: programID, Objective: "verify verdict persistence", WorkflowDefinitionID: definitionID, Status: domain.TaskRunning, RequestedBy: "integration-test", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	state := &workflow.State{Run: domain.WorkflowRun{ID: runID, TaskID: taskID, WorkflowDefinitionID: definitionID, WorkflowVersion: "1", Status: domain.RunCompleted, StartedAt: &now, CompletedAt: &now, TriggerSource: "integration-test", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{}}
	materializeSyntheticWorkflowState(t, store, ctx, state)
	if err := store.CreateWorkflowRun(ctx, state.Run); err != nil {
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
	topology := console.WorkflowTopologies[runID]
	if topology.Availability != "materialized" || len(topology.Steps) != 0 {
		t.Fatalf("console topology=%#v", topology)
	}
	encodedConsole, err := json.Marshal(console)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedConsole), "materialized_definition") || strings.Contains(string(encodedConsole), `"target_plan":`) {
		t.Fatalf("console response exposed raw materialization: %s", encodedConsole)
	}
	if !strings.Contains(string(encodedConsole), `"target_plan_digest":"plan"`) {
		t.Fatalf("console response omitted legitimate target plan digest: %s", encodedConsole)
	}
}

func TestConsoleUsesPerRunSanitizedTopology(t *testing.T) {
	store, ctx := pre0015IntegrationStore(t, "console_topology")
	now := time.Now().UTC().Truncate(time.Microsecond)
	programID, scopeID, legacyDefinitionID, legacyTaskID, legacyRunID, legacyStepID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,$2,'integration','synthetic://console','integration')`, []any{programID, "console-" + string(programID)}},
		{`INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,target_plan_digest,target_plan) VALUES($1,$2,'synthetic://console','scope','plan','{}')`, []any{scopeID, programID}},
		{`INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements) VALUES($1,'legacy-console','1','legacy','{}','{}')`, []any{legacyDefinitionID}},
		{`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by,created_at,updated_at) VALUES($1,$2,'legacy console',$3,'completed','integration',$4,$4)`, []any{legacyTaskID, programID, legacyDefinitionID, now.Add(-3 * time.Hour)}},
		{`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,completed_at,trigger_source,summary) VALUES($1,$2,$3,'1','completed',$4,$4,'integration','{}')`, []any{legacyRunID, legacyTaskID, legacyDefinitionID, now.Add(-3 * time.Hour)}},
		{`INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,attempt_count,input,output,idempotency_key,approval_state,started_at,completed_at) VALUES($1,$2,'legacy-recorded','legacy.capability','succeeded',1,'{}','{}','legacy-key','not_required',$3,$3)`, []any{legacyStepID, legacyRunID, now.Add(-3 * time.Hour)}},
	} {
		if _, err := store.Pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	ensureTestArtifactStore(t, ctx, store)

	template := workflow.Template{ID: domain.NewID(), Name: "console-modern-" + string(domain.NewID()), Version: "1", Description: "console modern", Materializer: "web-recon/v1", DefaultPolicyRequirements: json.RawMessage(`{}`), CreatedAt: now}
	if err := store.EnsureWorkflowTemplate(ctx, template); err != nil {
		t.Fatal(err)
	}
	createRun := func(program domain.ID, label string, started time.Time, steps []workflow.Step) domain.ID {
		t.Helper()
		var localScopeID domain.ID
		if err := store.Pool.QueryRow(ctx, `SELECT id FROM scope_versions WHERE program_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, program).Scan(&localScopeID); err != nil {
			t.Fatal(err)
		}
		task := domain.Task{ID: domain.NewID(), ProgramID: program, Objective: label, WorkflowDefinitionID: template.ID, Status: domain.TaskRunning, RequestedBy: "integration", CreatedAt: started, UpdatedAt: started}
		if err := store.CreateTask(ctx, task); err != nil {
			t.Fatal(err)
		}
		definition := workflow.Definition{ID: template.ID, Name: template.Name, Version: template.Version, Materializer: template.Materializer, Description: template.Description, Steps: steps, DefaultPolicyRequirements: template.DefaultPolicyRequirements, CreatedAt: template.CreatedAt}
		materialized, digest, err := workflow.Materialize(definition)
		if err != nil {
			t.Fatal(err)
		}
		runID := domain.NewID()
		state := &workflow.State{Run: domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: template.ID, WorkflowVersion: template.Version, Status: domain.RunCompleted, StartedAt: &started, CompletedAt: &started, TriggerSource: "integration", Summary: json.RawMessage(`{}`), MaterializedDefinition: materialized, MaterializationDigest: digest, OriginalScopeVersionID: &localScopeID}, Steps: map[string]*workflow.StepState{}}
		if err := store.SaveWorkflowState(ctx, state); err != nil {
			t.Fatal(err)
		}
		return runID
	}
	olderRunID := createRun(programID, "older", now.Add(-2*time.Hour), []workflow.Step{{ID: "older-only", Capability: "older.capability", Input: json.RawMessage(`{"secret":"CONSOLE_MATERIALIZED_INPUT_SENTINEL"}`), Bindings: map[string]string{"target": "CONSOLE_MATERIALIZED_BINDING_SENTINEL"}, ApprovalRequired: true}})
	latestRunID := createRun(programID, "latest", now.Add(-time.Hour), []workflow.Step{{ID: "latest-only", Capability: "latest.capability", DependsOn: []string{"prior"}, Input: json.RawMessage(`{"secret":"LATEST_RAW_INPUT_MARKER"}`)}})
	toolID, artifactID := domain.NewID(), domain.NewID()
	artifactAddress := withTestArtifactAddress(domain.Artifact{ID: artifactID})
	if _, err := store.Pool.Exec(ctx, `UPDATE scope_versions SET target_plan=$2 WHERE id=$1`, scopeID, json.RawMessage(`{"raw":"CONSOLE_RAW_TARGET_PLAN_SENTINEL"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `UPDATE step_runs SET output=$2 WHERE id=$1`, legacyStepID, json.RawMessage(`{"raw":"CONSOLE_PROVIDER_OUTPUT_SENTINEL"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,tool_version,sanitized_arguments,execution_environment,started_at,completed_at,exit_code,timed_out) VALUES($1,$2,'legacy.capability','sentinel-provider','1',$3,'{}',$4,$4,0,false)`, toolID, legacyStepID, json.RawMessage(`{"raw":"CONSOLE_PROVIDER_ARGS_SENTINEL"}`), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,addressing_version,artifact_store_id,storage_key,created_at,redaction_state,sensitive) VALUES($1,$2,$3,$4,$5,'raw-provider-output','text/plain',1,'sentinel-sha',$6,$7,$8,$9,'redacted',false)`, artifactID, legacyTaskID, legacyRunID, legacyStepID, toolID, artifactAddress.AddressingVersion, artifactAddress.ArtifactStoreID, artifactAddress.StorageKey, now); err != nil {
		t.Fatal(err)
	}

	otherProgramID, otherScopeID := domain.NewID(), domain.NewID()
	if _, err := store.Pool.Exec(ctx, `INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,$2,'integration','synthetic://other','integration')`, otherProgramID, "other-"+string(otherProgramID)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,target_plan_digest,target_plan) VALUES($1,$2,'synthetic://other','scope','plan','{}')`, otherScopeID, otherProgramID); err != nil {
		t.Fatal(err)
	}
	otherRunID := createRun(otherProgramID, "other", now, []workflow.Step{{ID: "other-program", Capability: "isolated.capability", Input: json.RawMessage(`{"secret":"OTHER_PROGRAM_MARKER"}`)}})

	console, err := store.ConsoleSnapshot(ctx, programID)
	if err != nil {
		t.Fatal(err)
	}
	older := console.WorkflowTopologies[olderRunID]
	latest := console.WorkflowTopologies[latestRunID]
	legacy := console.WorkflowTopologies[legacyRunID]
	if older.Availability != "materialized" || len(older.Steps) != 1 || older.Steps[0].ID != "older-only" || !older.Steps[0].ApprovalRequired {
		t.Fatalf("older topology=%#v", older)
	}
	if latest.Availability != "materialized" || len(latest.Steps) != 1 || latest.Steps[0].ID != "latest-only" || len(latest.Steps[0].DependsOn) != 1 || latest.Steps[0].DependsOn[0] != "prior" {
		t.Fatalf("latest topology=%#v", latest)
	}
	if legacy.Availability != "legacy_unavailable" || len(legacy.Steps) != 0 {
		t.Fatalf("legacy topology=%#v", legacy)
	}
	legacyRecorded := false
	for _, step := range console.Steps {
		if step.WorkflowRunID == legacyRunID && step.StepDefinitionID == "legacy-recorded" {
			legacyRecorded = true
		}
	}
	if !legacyRecorded {
		t.Fatalf("legacy persisted StepRun missing: %#v", console.Steps)
	}
	if _, leaked := console.WorkflowTopologies[otherRunID]; leaked {
		t.Fatalf("other Program topology %s leaked", otherRunID)
	}
	encoded, err := json.Marshal(console)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"materialized_definition", `"target_plan":`, `"sanitized_arguments":`, `"storage_location":`, `"storage_key":`,
		"CONSOLE_MATERIALIZED_INPUT_SENTINEL", "CONSOLE_MATERIALIZED_BINDING_SENTINEL", "CONSOLE_RAW_TARGET_PLAN_SENTINEL",
		"CONSOLE_PROVIDER_ARGS_SENTINEL", *artifactAddress.StorageKey, "CONSOLE_PROVIDER_OUTPUT_SENTINEL",
		"LATEST_RAW_INPUT_MARKER", "OTHER_PROGRAM_MARKER",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("console response leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestConsoleProjectionOmitsProviderDerivedPersistencePayloads(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "console-provider-derived-projection")
	now := time.Now().UTC().Truncate(time.Microsecond)
	task := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "console provider-derived projection")
	definition, scopeVersionID := syntheticWorkflowDefinition(t, env.store, env.ctx, task.ID)
	providerOutputInput := json.RawMessage(`{"changes":[],"endpoints":[],"candidate_matches":[],"target_plan_digest":"PROVIDER_OUTPUT_SENTINEL"}`)
	reportInput := json.RawMessage(`{"changes":[],"endpoints":[],"candidate_matches":[],"target_plan_digest":"WORKFLOW_SUMMARY_SENTINEL"}`)
	definition.Steps = []workflow.Step{
		{ID: "provider-output", Capability: "report.changes", Provider: "platform", Input: providerOutputInput, Retry: workflow.RetryPolicy{MaxAttempts: 1}},
		{ID: "report", Capability: "report.changes", Provider: "platform", DependsOn: []string{"provider-output"}, Input: reportInput, Retry: workflow.RetryPolicy{MaxAttempts: 1}},
	}
	cfg, err := config.LoadWith(func(key string) string {
		if key == "DATABASE_URL" {
			return "test"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := providers.Registry(cfg)
	engine := workflow.Engine{
		Registry:  registry,
		Executor:  execution.Service{Registry: registry, Store: env.store, Artifacts: postgresWorkflowRetryArtifacts{}, ProgramID: env.programID},
		Persister: WorkflowPersister{Store: env.store, File: workflow.FileStore{Root: t.TempDir()}},
		Policy:    policy.Policy{ID: "console-projection", AllowedCapabilities: []string{"report.changes"}},
		Scope:     integrationAllowScope{}, OriginalScopeVersionID: scopeVersionID,
	}
	state, err := engine.Run(env.ctx, definition, nil, task, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.Run.Status != domain.RunCompleted {
		t.Fatalf("workflow status=%s", state.Run.Status)
	}
	if _, err := env.store.RecordPolicyDecision(env.ctx, capability.PolicyDecisionRecord{
		ProgramID: env.programID,
		Action:    domain.ActionRequest{ID: domain.NewID(), TaskID: task.ID, WorkflowRunID: state.Run.ID, RequestedBy: "integration", Capability: "report.changes", StepAttempt: 1},
		Provider:  "platform", PolicyID: "console-projection", Phase: "execution",
		Evaluation: policy.Evaluation{Decision: policy.Allow, Reason: "AUDIT_DETAILS_SENTINEL"},
	}); err != nil {
		t.Fatal(err)
	}
	var providerStepRows, reportStepRows, arbitraryAuditRows int
	var storedSummary, reportOutput json.RawMessage
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT summary FROM workflow_runs WHERE id=$1`, state.Run.ID).Scan(&storedSummary); err != nil {
		t.Fatal(err)
	}
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT count(*) FROM step_runs WHERE workflow_run_id=$1 AND output::text LIKE '%PROVIDER_OUTPUT_SENTINEL%'`, state.Run.ID).Scan(&providerStepRows); err != nil {
		t.Fatal(err)
	}
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT output FROM step_runs WHERE id=$1`, state.Steps["report"].Run.ID).Scan(&reportOutput); err != nil {
		t.Fatal(err)
	}
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT count(*) FROM step_runs WHERE workflow_run_id=$1 AND output::text LIKE '%WORKFLOW_SUMMARY_SENTINEL%'`, state.Run.ID).Scan(&reportStepRows); err != nil {
		t.Fatal(err)
	}
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT count(*) FROM audit_events WHERE workflow_run_id=$1 AND details::text LIKE '%AUDIT_DETAILS_SENTINEL%'`, state.Run.ID).Scan(&arbitraryAuditRows); err != nil {
		t.Fatal(err)
	}
	_, canonicalReportOutput, _, _, err := canonicaljson.ParseStrict(reportOutput)
	if err != nil {
		t.Fatalf("canonicalize persisted report envelope: %v", err)
	}
	reportEnvelope, err := domain.DecodeResultEnvelopeV1(canonicalReportOutput)
	if err != nil {
		t.Fatalf("decode persisted report envelope: %v", err)
	}
	var reference domain.ResultSummaryReferenceV1
	if err := json.Unmarshal(storedSummary, &reference); err != nil {
		t.Fatalf("decode persisted report summary reference: %v", err)
	}
	var semanticStepID domain.ID
	var semanticType, semanticSHA256 string
	var semanticSize int64
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT step_run_id,type,sha256,size FROM artifacts WHERE id=$1`, reference.SemanticArtifactID).Scan(&semanticStepID, &semanticType, &semanticSHA256, &semanticSize); err != nil {
		t.Fatal(err)
	}
	if reference.Version != domain.ResultSummaryReferenceVersionV1 || reference.SourceStepRunID != state.Steps["report"].Run.ID || reference.ActionRequestID != reportEnvelope.ActionRequestID || reference.ResultOccurrenceID != reportEnvelope.ResultOccurrenceID || reference.SemanticArtifactID != reportEnvelope.SemanticOutput.ArtifactID || reference.SemanticSHA256 != reportEnvelope.SemanticOutput.ContentSHA256 || reference.SemanticSizeBytes != reportEnvelope.SemanticOutput.ContentSizeBytes || reference.SafeSummary != reportEnvelope.Summary || semanticStepID != state.Steps["report"].Run.ID || semanticType != "normalized-result" || semanticSHA256 != reference.SemanticSHA256 || semanticSize != reference.SemanticSizeBytes {
		t.Fatalf("summary reference=%#v envelope=%#v semantic=%s/%s/%d/%s", reference, reportEnvelope, semanticStepID, semanticType, semanticSize, semanticSHA256)
	}
	for _, forbidden := range []string{"PROVIDER_OUTPUT_SENTINEL", "WORKFLOW_SUMMARY_SENTINEL", "AUDIT_DETAILS_SENTINEL", "storage_key"} {
		if strings.Contains(string(storedSummary), forbidden) {
			t.Fatalf("summary reference leaked %q: %s", forbidden, storedSummary)
		}
	}
	if providerStepRows != 1 || reportStepRows != 1 || arbitraryAuditRows != 1 {
		t.Fatalf("persistence evidence summary=%s provider_steps=%d report_steps=%d arbitrary_audits=%d", storedSummary, providerStepRows, reportStepRows, arbitraryAuditRows)
	}

	snapshot, err := env.store.ConsoleSnapshot(env.ctx, env.programID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, sentinel := range []string{"PROVIDER_OUTPUT_SENTINEL", "WORKFLOW_SUMMARY_SENTINEL", "AUDIT_DETAILS_SENTINEL"} {
		if strings.Contains(string(encoded), sentinel) {
			t.Fatalf("console projection exposed %q: %s", sentinel, encoded)
		}
	}
	var shape map[string]any
	if err := json.Unmarshal(encoded, &shape); err != nil {
		t.Fatal(err)
	}
	if _, present := shape["latest_changes"]; present {
		t.Fatal("console projection retained raw latest_changes")
	}
	for _, rawRun := range shape["runs"].([]any) {
		if _, present := rawRun.(map[string]any)["summary"]; present {
			t.Fatal("console run retained raw summary")
		}
	}
	for _, rawEvent := range shape["audit_events"].([]any) {
		if _, present := rawEvent.(map[string]any)["details"]; present {
			t.Fatal("console audit event retained raw details")
		}
	}
	if len(snapshot.Runs) == 0 || snapshot.Runs[0].ID != state.Run.ID || snapshot.Runs[0].Status != domain.RunCompleted || snapshot.Scope == nil || snapshot.Scope.TargetPlanDigest != "plan" || len(snapshot.Tools) < 2 || len(snapshot.AuditEvents) == 0 || snapshot.AuditEvents[0].ID == "" || snapshot.AuditEvents[0].EventType == "" || snapshot.AuditEvents[0].OccurredAt.Before(now.Add(-time.Hour)) {
		t.Fatalf("fixed console metadata missing: runs=%#v scope=%#v tools=%#v audits=%#v", snapshot.Runs, snapshot.Scope, snapshot.Tools, snapshot.AuditEvents)
	}
}
