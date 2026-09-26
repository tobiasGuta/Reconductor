package database

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
	"github.com/tobiasGuta/Reconductor/internal/workflows"
)

func TestEnsureWorkflowTemplateContracts(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	base := workflow.Template{ID: domain.NewID(), Name: "template-contract-" + string(domain.NewID()), Version: "1.0.0", Description: "immutable", Materializer: "web-recon/v1", DefaultPolicyRequirements: json.RawMessage(`{"allow":true}`), CreatedAt: time.Now().UTC()}
	if err := store.EnsureWorkflowTemplate(ctx, base); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureWorkflowTemplate(ctx, base); err != nil {
		t.Fatalf("exact ensure was not idempotent: %v", err)
	}

	sameID := base
	sameID.Name += "-other"
	if err := store.EnsureWorkflowTemplate(ctx, sameID); !errors.Is(err, workflow.ErrWorkflowTemplateIdentityConflict) {
		t.Fatalf("same UUID identity error=%v", err)
	}
	sameRelease := base
	sameRelease.ID = domain.NewID()
	if err := store.EnsureWorkflowTemplate(ctx, sameRelease); !errors.Is(err, workflow.ErrWorkflowTemplateIdentityConflict) {
		t.Fatalf("same name/version identity error=%v", err)
	}
	changed := base
	changed.Description = "changed"
	if err := store.EnsureWorkflowTemplate(ctx, changed); !errors.Is(err, workflow.ErrWorkflowTemplateDefinitionConflict) {
		t.Fatalf("semantic payload error=%v", err)
	}
	changedCreatedAt := base
	changedCreatedAt.CreatedAt = base.CreatedAt.Add(time.Second)
	if err := store.EnsureWorkflowTemplate(ctx, changedCreatedAt); !errors.Is(err, workflow.ErrWorkflowTemplateDefinitionConflict) {
		t.Fatalf("created_at release error=%v", err)
	}

	concurrent := base
	concurrent.ID = domain.NewID()
	concurrent.Name += "-concurrent"
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.EnsureWorkflowTemplate(ctx, concurrent)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent exact ensure: %v", err)
		}
	}

	left := base
	left.ID = domain.NewID()
	left.Name += "-race"
	right := left
	right.ID = domain.NewID()
	start := make(chan struct{})
	conflicts := make(chan error, 2)
	for _, candidate := range []workflow.Template{left, right} {
		candidate := candidate
		go func() {
			<-start
			conflicts <- store.EnsureWorkflowTemplate(ctx, candidate)
		}()
	}
	close(start)
	var succeeded, rejected int
	for range 2 {
		err := <-conflicts
		if err == nil {
			succeeded++
		} else if errors.Is(err, workflow.ErrWorkflowTemplateIdentityConflict) {
			rejected++
		} else {
			t.Fatalf("concurrent conflict error=%v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent conflict outcomes success=%d rejected=%d", succeeded, rejected)
	}
}

func TestCurrentWorkflowTemplatesUseNewImmutableIDs(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	for _, template := range workflows.Templates() {
		if err := store.EnsureWorkflowTemplate(ctx, template); err != nil {
			t.Fatal(err)
		}
		var id domain.ID
		if err := store.Pool.QueryRow(ctx, `SELECT id FROM workflow_definitions WHERE name=$1 AND version=$2`, template.Name, template.Version).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if id != template.ID {
			t.Fatalf("%s %s id=%s want=%s", template.Name, template.Version, id, template.ID)
		}
	}
	if workflows.BaselineTemplateID == domain.ID("c9479711-b203-4fe1-8528-718888e5a5d2") || workflows.ContinuousTemplateID == domain.ID("d0e5e6a3-bd8a-4b4b-a76b-f6452c30179a") {
		t.Fatal("a current release reused a historical template UUID")
	}
}

func TestWorkflowTemplateUpgradePreservesHistoricalReleaseIdentities(t *testing.T) {
	const (
		oldBaselineID   = domain.ID("c9479711-b203-4fe1-8528-718888e5a5d2")
		oldContinuousID = domain.ID("d0e5e6a3-bd8a-4b4b-a76b-f6452c30179a")
	)
	if workflows.BaselineTemplateID == oldBaselineID || workflows.ContinuousTemplateID == oldContinuousID || workflows.BaselineVersion != "1.5.0" || workflows.ContinuousVersion != "2.5.0" {
		t.Fatalf("current release tuples baseline=(%s,%s) continuous=(%s,%s)", workflows.BaselineTemplateID, workflows.BaselineVersion, workflows.ContinuousTemplateID, workflows.ContinuousVersion)
	}
	for _, test := range []struct {
		name              string
		baselineVersion   string
		continuousVersion string
	}{
		{name: "older_historical_database", baselineVersion: "1.2.0", continuousVersion: "2.2.0"},
		{name: "base_source_database", baselineVersion: "1.3.0", continuousVersion: "2.3.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, ctx := pre0015IntegrationStore(t, "template_upgrade_"+test.name)
			now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
			programID, scopeID := domain.NewID(), domain.NewID()
			baselineTaskID, continuousTaskID := domain.NewID(), domain.NewID()
			baselineRunID, continuousRunID := domain.NewID(), domain.NewID()
			for _, statement := range []struct {
				sql  string
				args []any
			}{
				{`INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,$2,'integration','synthetic://upgrade','integration')`, []any{programID, "upgrade-" + string(programID)}},
				{`INSERT INTO scope_versions(id,program_id,scope_reference,scope_digest,target_plan_digest,target_plan) VALUES($1,$2,'synthetic://upgrade','scope','plan','{}')`, []any{scopeID, programID}},
				{`INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, []any{oldBaselineID, workflows.BaselineName, test.baselineVersion, "historical baseline", json.RawMessage(`{"historical":"baseline"}`), json.RawMessage(`{"historical":true}`), now}},
				{`INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, []any{oldContinuousID, workflows.ContinuousName, test.continuousVersion, "historical continuous", json.RawMessage(`{"historical":"continuous"}`), json.RawMessage(`{"historical":true}`), now.Add(time.Second)}},
				{`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by,created_at,updated_at) VALUES($1,$2,'historical baseline',$3,'completed','integration',$4,$4)`, []any{baselineTaskID, programID, oldBaselineID, now}},
				{`INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by,created_at,updated_at) VALUES($1,$2,'historical continuous',$3,'completed','integration',$4,$4)`, []any{continuousTaskID, programID, oldContinuousID, now}},
				{`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source,summary) VALUES($1,$2,$3,$4,'completed','integration','{}')`, []any{baselineRunID, baselineTaskID, oldBaselineID, test.baselineVersion}},
				{`INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source,summary) VALUES($1,$2,$3,$4,'completed','integration','{}')`, []any{continuousRunID, continuousTaskID, oldContinuousID, test.continuousVersion}},
			} {
				if _, err := store.Pool.Exec(ctx, statement.sql, statement.args...); err != nil {
					t.Fatal(err)
				}
			}
			before := historicalWorkflowIdentitySnapshot(t, store, ctx, oldBaselineID, oldContinuousID, baselineTaskID, continuousTaskID, baselineRunID, continuousRunID)
			if err := store.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			afterMigration := historicalWorkflowIdentitySnapshot(t, store, ctx, oldBaselineID, oldContinuousID, baselineTaskID, continuousTaskID, baselineRunID, continuousRunID)
			if afterMigration != before {
				t.Fatalf("historical identity changed during 0015\nbefore=%s\nafter=%s", before, afterMigration)
			}
			for _, template := range workflows.Templates() {
				if err := store.EnsureWorkflowTemplate(ctx, template); err != nil {
					t.Fatalf("register %s %s: %v", template.Name, template.Version, err)
				}
			}
			afterRegistration := historicalWorkflowIdentitySnapshot(t, store, ctx, oldBaselineID, oldContinuousID, baselineTaskID, continuousTaskID, baselineRunID, continuousRunID)
			if afterRegistration != before {
				t.Fatalf("historical identity changed during current registration\nbefore=%s\nafter=%s", before, afterRegistration)
			}
			var currentCount, historicalNullRuns int
			if err := store.Pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM workflow_definitions WHERE (id=$1 AND name=$2 AND version=$3) OR (id=$4 AND name=$5 AND version=$6)),
				(SELECT count(*) FROM workflow_runs WHERE id IN ($7,$8) AND materialized_definition IS NULL AND materialization_digest IS NULL AND original_scope_version_id IS NULL)`,
				workflows.BaselineTemplateID, workflows.BaselineName, workflows.BaselineVersion, workflows.ContinuousTemplateID, workflows.ContinuousName, workflows.ContinuousVersion, baselineRunID, continuousRunID).Scan(&currentCount, &historicalNullRuns); err != nil {
				t.Fatal(err)
			}
			if currentCount != 2 || historicalNullRuns != 2 {
				t.Fatalf("current releases=%d historical null runs=%d", currentCount, historicalNullRuns)
			}
		})
	}
}

func historicalWorkflowIdentitySnapshot(t *testing.T, store *Store, ctx context.Context, baselineDefinitionID, continuousDefinitionID, baselineTaskID, continuousTaskID, baselineRunID, continuousRunID domain.ID) string {
	t.Helper()
	var snapshot string
	if err := store.Pool.QueryRow(ctx, `SELECT jsonb_build_object(
		'definitions',(SELECT jsonb_agg(jsonb_build_object('id',id,'name',name,'version',version,'description',description,'definition',definition,'requirements',default_policy_requirements,'created_at',created_at) ORDER BY id) FROM workflow_definitions WHERE id IN ($1,$2)),
		'tasks',(SELECT jsonb_agg(jsonb_build_object('id',id,'program_id',program_id,'workflow_definition_id',workflow_definition_id) ORDER BY id) FROM tasks WHERE id IN ($3,$4)),
		'runs',(SELECT jsonb_agg(jsonb_build_object('id',id,'task_id',task_id,'workflow_definition_id',workflow_definition_id,'workflow_version',workflow_version) ORDER BY id) FROM workflow_runs WHERE id IN ($5,$6)))::text`, baselineDefinitionID, continuousDefinitionID, baselineTaskID, continuousTaskID, baselineRunID, continuousRunID).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestWorkflowTemplateRejectsUnknownDescriptorFields(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	id := domain.NewID()
	if _, err := store.Pool.Exec(ctx, `INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements) VALUES($1,$2,'1','strict descriptor',$3,'{}')`, id, "strict-descriptor-"+string(id), json.RawMessage(`{"schema_version":1,"kind":"built-in","materializer":"web-recon/v1","unexpected":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WorkflowTemplate(ctx, id); !errors.Is(err, workflow.ErrTaskWorkflowTemplateUnavailable) {
		t.Fatalf("unknown descriptor field error=%v", err)
	}
}

func TestSameTemplateReleaseMaterializesDistinctProgramPlans(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	template, err := workflows.CurrentTemplate(workflows.ContinuousName)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureWorkflowTemplate(ctx, template); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	type fixture struct {
		program domain.Program
		task    domain.Task
		scopeID domain.ID
		state   *workflow.State
	}
	fixtures := make([]fixture, 0, 2)
	for index, host := range []string{"one.example.test", "two.example.test"} {
		program := domain.Program{ID: domain.NewID(), Name: "materialization-program-" + host, Platform: "integration", ScopeReference: "synthetic://" + host, PolicyReference: "integration", ScopeDigest: "scope-" + host, IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: "plan-" + host, ScopePlanWarnings: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now}
		snapshot := domain.ScopeSnapshot{ScopeReference: program.ScopeReference, ScopeDigest: program.ScopeDigest, IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: program.TargetPlanDigest, PlanningWarnings: json.RawMessage(`[]`), TargetPlan: json.RawMessage(`{}`), CreatedAt: now.Add(time.Duration(index) * time.Second)}
		if err := store.CreateProgram(ctx, program, snapshot); err != nil {
			t.Fatal(err)
		}
		var scopeID domain.ID
		if err := store.Pool.QueryRow(ctx, `SELECT id FROM scope_versions WHERE program_id=$1`, program.ID).Scan(&scopeID); err != nil {
			t.Fatal(err)
		}
		task := domain.Task{ID: domain.NewID(), ProgramID: program.ID, Objective: host, WorkflowDefinitionID: template.ID, Status: domain.TaskRunning, RequestedBy: "test", CreatedAt: now, UpdatedAt: now}
		if err := store.CreateTask(ctx, task); err != nil {
			t.Fatal(err)
		}
		plan := targeting.TargetPlan{ScopeDigest: program.ScopeDigest, Digest: program.TargetPlanDigest, ExactActiveSeeds: []targeting.ActiveSeed{{Host: host, SourceRuleIDs: []string{"exact"}, Endpoints: []targeting.Endpoint{{Protocol: "https", Port: 443, URL: "https://" + host + "/"}}}}}
		definition := workflows.ContinuousWebRecon(plan, false)
		materialized, digest, err := workflow.Materialize(definition)
		if err != nil {
			t.Fatal(err)
		}
		state := &workflow.State{Run: domain.WorkflowRun{ID: domain.NewID(), TaskID: task.ID, WorkflowDefinitionID: template.ID, WorkflowVersion: template.Version, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "test", Summary: json.RawMessage(`{}`), MaterializedDefinition: materialized, MaterializationDigest: digest, OriginalScopeVersionID: &scopeID}, Steps: map[string]*workflow.StepState{}}
		if err := store.SaveWorkflowState(ctx, state); err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, fixture{program: program, task: task, scopeID: scopeID, state: state})
	}
	if fixtures[0].state.Run.WorkflowDefinitionID != fixtures[1].state.Run.WorkflowDefinitionID || fixtures[0].state.Run.MaterializationDigest == fixtures[1].state.Run.MaterializationDigest || fixtures[0].state.Run.OriginalScopeVersionID == nil || fixtures[1].state.Run.OriginalScopeVersionID == nil || *fixtures[0].state.Run.OriginalScopeVersionID == *fixtures[1].state.Run.OriginalScopeVersionID {
		t.Fatalf("materializations were not Program-local: first=%#v second=%#v", fixtures[0].state.Run, fixtures[1].state.Run)
	}
}

func TestInitialWorkflowRunCreationLocksTaskLineage(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	programID, definitionID := createSchedulerIntegrationProgram(t, ctx, store, "initial-run-lock")
	task := createIntegrationTask(t, ctx, store, programID, definitionID, "initial-run-lock")
	now := time.Now().UTC()
	states := []*workflow.State{
		{Run: domain.WorkflowRun{ID: domain.NewID(), TaskID: task.ID, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "test", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{}},
		{Run: domain.WorkflowRun{ID: domain.NewID(), TaskID: task.ID, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "test", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{}},
	}
	for _, state := range states {
		materializeSyntheticWorkflowState(t, store, ctx, state)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, state := range states {
		state := state
		go func() {
			<-start
			results <- store.SaveWorkflowState(ctx, state)
		}()
	}
	close(start)
	var succeeded, active int
	for range 2 {
		err := <-results
		if err == nil {
			succeeded++
		} else if errors.Is(err, workflow.ErrWorkflowRunAlreadyActive) {
			active++
		} else {
			t.Fatalf("fresh start error=%v", err)
		}
	}
	if succeeded != 1 || active != 1 {
		t.Fatalf("fresh start outcomes success=%d already_active=%d", succeeded, active)
	}
	var count int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM workflow_runs WHERE task_id=$1 AND status IN ('pending','running','paused')`, task.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("active run count=%d err=%v", count, err)
	}
}

func TestInitialWorkflowRunFileFailurePreservesDurableSingleLineage(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	programID, definitionID := createSchedulerIntegrationProgram(t, ctx, store, "initial-file-failure")
	task := createIntegrationTask(t, ctx, store, programID, definitionID, "initial-file-failure")
	now := time.Now().UTC()
	state := &workflow.State{Run: domain.WorkflowRun{ID: domain.NewID(), TaskID: task.ID, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "test", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{}}
	materializeSyntheticWorkflowState(t, store, ctx, state)
	badRoot := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(badRoot, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	err := (WorkflowPersister{Store: store, File: workflow.FileStore{Root: badRoot}}).Save(ctx, state)
	if !errors.Is(err, workflow.ErrWorkflowCheckpointUnavailable) {
		t.Fatalf("FileStore failure error=%v", err)
	}
	stored, err := store.LoadWorkflowState(ctx, state.Run.ID)
	if err != nil || stored.Run.ID != state.Run.ID || len(stored.Steps) != 0 {
		t.Fatalf("durable state=%#v err=%v", stored, err)
	}
	duplicate := &workflow.State{Run: domain.WorkflowRun{ID: domain.NewID(), TaskID: task.ID, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "test", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{}}
	materializeSyntheticWorkflowState(t, store, ctx, duplicate)
	if err := store.SaveWorkflowState(ctx, duplicate); !errors.Is(err, workflow.ErrWorkflowRunAlreadyActive) {
		t.Fatalf("duplicate fresh run error=%v", err)
	}
}

func TestInitialWorkflowRunFailsClosedOnConflictingExistingLineage(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	programID, definitionID := createSchedulerIntegrationProgram(t, ctx, store, "initial-lineage-conflict")
	task := createIntegrationTask(t, ctx, store, programID, definitionID, "initial-lineage-conflict")
	now := time.Now().UTC()
	first := &workflow.State{Run: domain.WorkflowRun{ID: domain.NewID(), TaskID: task.ID, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "test", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{}}
	materializeSyntheticWorkflowState(t, store, ctx, first)
	if err := store.SaveWorkflowState(ctx, first); err != nil {
		t.Fatal(err)
	}
	secondID := domain.NewID()
	if _, err := store.Pool.Exec(ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,trigger_source,summary,materialized_definition,materialization_digest,original_scope_version_id)
		SELECT $1,task_id,workflow_definition_id,workflow_version,'paused',started_at,trigger_source,summary,materialized_definition,materialization_digest,original_scope_version_id FROM workflow_runs WHERE id=$2`, secondID, first.Run.ID); err != nil {
		t.Fatal(err)
	}
	third := &workflow.State{Run: domain.WorkflowRun{ID: domain.NewID(), TaskID: task.ID, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "test", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{}}
	materializeSyntheticWorkflowState(t, store, ctx, third)
	if err := store.SaveWorkflowState(ctx, third); !errors.Is(err, workflow.ErrWorkflowRunLineageConflict) {
		t.Fatalf("multiple-active error=%v", err)
	}
}

func TestPendingTaskRemainsPinnedAcrossTemplateUpgrade(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	programID, oldTemplateID := createSchedulerIntegrationProgram(t, ctx, store, "pending-template-upgrade")
	now := time.Now().UTC().Truncate(time.Microsecond)
	oldTask := domain.Task{ID: domain.NewID(), ProgramID: programID, Objective: "old pending task", WorkflowDefinitionID: oldTemplateID, Status: domain.TaskPending, RequestedBy: "test", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateTask(ctx, oldTask); err != nil {
		t.Fatal(err)
	}
	newTemplate := workflow.Template{ID: domain.NewID(), Name: "pending-template-upgrade", Version: "2", Description: "new release", Materializer: "web-recon/v1", DefaultPolicyRequirements: json.RawMessage(`{}`), CreatedAt: now.Add(time.Second)}
	if err := store.EnsureWorkflowTemplate(ctx, newTemplate); err != nil {
		t.Fatal(err)
	}
	var scopeVersionID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT id FROM scope_versions WHERE program_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`, programID).Scan(&scopeVersionID); err != nil {
		t.Fatal(err)
	}
	newDefinition := workflow.Definition{ID: newTemplate.ID, Name: newTemplate.Name, Version: newTemplate.Version, Materializer: newTemplate.Materializer, Description: newTemplate.Description, Steps: []workflow.Step{}, DefaultPolicyRequirements: newTemplate.DefaultPolicyRequirements, CreatedAt: newTemplate.CreatedAt}
	materialized, digest, err := workflow.Materialize(newDefinition)
	if err != nil {
		t.Fatal(err)
	}
	oldTaskState := &workflow.State{Run: domain.WorkflowRun{ID: domain.NewID(), TaskID: oldTask.ID, WorkflowDefinitionID: newTemplate.ID, WorkflowVersion: newTemplate.Version, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "test", Summary: json.RawMessage(`{}`), MaterializedDefinition: materialized, MaterializationDigest: digest, OriginalScopeVersionID: &scopeVersionID}, Steps: map[string]*workflow.StepState{}}
	if err := store.SaveWorkflowState(ctx, oldTaskState); !errors.Is(err, workflow.ErrTaskWorkflowTemplateUnavailable) {
		t.Fatalf("upgraded template on pinned Task error=%v", err)
	}
	var oldRunCount int
	var oldTaskStatus domain.TaskStatus
	if err := store.Pool.QueryRow(ctx, `SELECT status,(SELECT count(*) FROM workflow_runs WHERE task_id=tasks.id) FROM tasks WHERE id=$1`, oldTask.ID).Scan(&oldTaskStatus, &oldRunCount); err != nil || oldTaskStatus != domain.TaskPending || oldRunCount != 0 {
		t.Fatalf("old Task status=%s run count=%d err=%v", oldTaskStatus, oldRunCount, err)
	}
	replacement := domain.Task{ID: domain.NewID(), ProgramID: programID, Objective: "replacement task", WorkflowDefinitionID: newTemplate.ID, Status: domain.TaskRunning, RequestedBy: "test", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateTask(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	replacementState := cloneStateForTask(oldTaskState, replacement.ID)
	if err := store.SaveWorkflowState(ctx, replacementState); err != nil {
		t.Fatalf("replacement Task start: %v", err)
	}
}

func cloneStateForTask(state *workflow.State, taskID domain.ID) *workflow.State {
	run := state.Run
	run.ID = domain.NewID()
	run.TaskID = taskID
	return &workflow.State{Run: run, Steps: map[string]*workflow.StepState{}}
}

func ensureSyntheticWorkflowTemplate(t *testing.T, store *Store, ctx context.Context, id domain.ID, name string) workflow.Template {
	t.Helper()
	template := workflow.Template{
		ID:                        id,
		Name:                      name,
		Version:                   "1",
		Description:               "synthetic",
		Materializer:              "web-recon/v1",
		DefaultPolicyRequirements: json.RawMessage(`{}`),
		CreatedAt:                 time.Now().UTC(),
	}
	if err := store.EnsureWorkflowTemplate(ctx, template); err != nil {
		t.Fatal(err)
	}
	return template
}

func materializeSyntheticWorkflowState(t *testing.T, store *Store, ctx context.Context, state *workflow.State) {
	t.Helper()
	definition, scopeVersionID := syntheticWorkflowDefinition(t, store, ctx, state.Run.TaskID)
	stepNames := make([]string, 0, len(state.Steps))
	for name := range state.Steps {
		stepNames = append(stepNames, name)
	}
	sort.Strings(stepNames)
	for _, name := range stepNames {
		step := state.Steps[name].Run
		definition.Steps = append(definition.Steps, workflow.Step{ID: name, Capability: step.Capability, Input: step.Input, Retry: workflow.RetryPolicy{MaxAttempts: 1}})
	}
	materialized, digest, err := workflow.Materialize(definition)
	if err != nil {
		t.Fatal(err)
	}
	state.Run.WorkflowDefinitionID = definition.ID
	state.Run.WorkflowVersion = definition.Version
	state.Run.MaterializedDefinition = materialized
	state.Run.MaterializationDigest = digest
	state.Run.OriginalScopeVersionID = &scopeVersionID
}

func syntheticWorkflowDefinition(t *testing.T, store *Store, ctx context.Context, taskID domain.ID) (workflow.Definition, domain.ID) {
	t.Helper()
	var definition workflow.Definition
	var scopeVersionID domain.ID
	var descriptorRaw json.RawMessage
	if err := store.Pool.QueryRow(ctx, `SELECT wd.id,wd.name,wd.version,wd.description,wd.definition,wd.default_policy_requirements,wd.created_at,
		(SELECT sv.id FROM scope_versions sv WHERE sv.program_id=t.program_id ORDER BY sv.created_at DESC,sv.id DESC LIMIT 1)
		FROM tasks t JOIN workflow_definitions wd ON wd.id=t.workflow_definition_id WHERE t.id=$1`, taskID).Scan(
		&definition.ID, &definition.Name, &definition.Version, &definition.Description, &descriptorRaw, &definition.DefaultPolicyRequirements, &definition.CreatedAt, &scopeVersionID,
	); err != nil {
		t.Fatal(err)
	}
	descriptor, err := workflow.DecodeTemplateDescriptor(descriptorRaw)
	if err != nil {
		t.Fatal(err)
	}
	definition.Materializer = descriptor.Materializer
	return definition, scopeVersionID
}
