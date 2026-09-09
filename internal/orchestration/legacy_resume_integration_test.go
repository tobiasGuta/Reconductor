package orchestration

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/migrations"
	"github.com/tobiasGuta/Reconductor/internal/providers"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
	"github.com/tobiasGuta/Reconductor/internal/workflows"
)

func TestLegacyNullMaterializationRemainsReadableAndResumeUnavailable(t *testing.T) {
	store, ctx := preMaterializationMigrationStore(t)
	programID, definitionID, taskID, runID := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	if _, err := store.Pool.Exec(ctx, `INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,$2,'integration','synthetic://legacy','integration')`, programID, "legacy-"+string(programID)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements) VALUES($1,'legacy-workflow','1','legacy','{}','{}')`, definitionID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO tasks(id,program_id,objective,workflow_definition_id,status,requested_by) VALUES($1,$2,'legacy resume',$3,'running','integration')`, taskID, programID, definitionID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source,summary) VALUES($1,$2,$3,'1','running','integration','{}')`, runID, taskID, definitionID); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	run, err := store.GetWorkflowRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetWorkflowRun: %v", err)
	}
	if run.MaterializedDefinition != nil || run.MaterializationDigest != "" || run.OriginalScopeVersionID != nil {
		t.Fatalf("legacy domain representation=%#v", run)
	}
	state, err := store.LoadWorkflowState(ctx, runID)
	if err != nil {
		t.Fatalf("LoadWorkflowState: %v", err)
	}
	if state.Run.MaterializedDefinition != nil || state.Run.MaterializationDigest != "" || state.Run.OriginalScopeVersionID != nil {
		t.Fatalf("legacy state representation=%#v", state.Run)
	}

	before := legacyResumeMutationCounts(t, ctx, store, programID, taskID, runID)
	service := Service{Config: config.Config{Scheduler: config.Scheduler{WorkflowStateRoot: t.TempDir()}}, Store: store, Registry: capability.NewRegistry()}
	result, err := service.Run(ctx, WorkflowRequest{ResumeRunID: runID})
	if !errors.Is(err, workflow.ErrWorkflowResumeUnavailable) || result.State == nil || result.State.Run.ID != runID {
		t.Fatalf("resume state=%#v error=%v", result.State, err)
	}
	after := legacyResumeMutationCounts(t, ctx, store, programID, taskID, runID)
	if before != after {
		t.Fatalf("legacy resume mutated durable state: before=%v after=%v", before, after)
	}
}

func TestResumePrerequisiteFailuresCauseNoDurableMutation(t *testing.T) {
	t.Run("corrupt checkpoint", func(t *testing.T) {
		store, ctx := fullOrchestrationIntegrationStore(t)
		_, task, state := createModernResumeFixture(t, ctx, store, nil)
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, string(state.Run.ID)+".json"), []byte(`{"run":{"id":17}}`), 0600); err != nil {
			t.Fatal(err)
		}
		before := orchestrationMutationFingerprint(t, ctx, store, task.ID, state.Run.ID)
		result, err := (Service{Config: config.Config{Scheduler: config.Scheduler{WorkflowStateRoot: root}}, Store: store, Registry: capability.NewRegistry()}).Run(ctx, WorkflowRequest{ResumeRunID: state.Run.ID})
		if !errors.Is(err, workflow.ErrWorkflowCheckpointConflict) || result.State == nil {
			t.Fatalf("state=%#v error=%v", result.State, err)
		}
		after := orchestrationMutationFingerprint(t, ctx, store, task.ID, state.Run.ID)
		if before != after {
			t.Fatalf("corrupt checkpoint mutated durable state: before=%#v after=%#v", before, after)
		}
	})

	t.Run("registry incompatible materialization", func(t *testing.T) {
		store, ctx := fullOrchestrationIntegrationStore(t)
		_, task, state := createModernResumeFixture(t, ctx, store, []workflow.Step{{ID: "missing", Capability: "missing.capability", Input: json.RawMessage(`{}`)}})
		root := t.TempDir()
		if err := (workflow.FileStore{Root: root}).Save(ctx, state); err != nil {
			t.Fatal(err)
		}
		before := orchestrationMutationFingerprint(t, ctx, store, task.ID, state.Run.ID)
		_, err := (Service{Config: config.Config{Scheduler: config.Scheduler{WorkflowStateRoot: root}}, Store: store, Registry: capability.NewRegistry()}).Run(ctx, WorkflowRequest{ResumeRunID: state.Run.ID})
		if err == nil || !strings.Contains(err.Error(), "unknown capability") {
			t.Fatalf("error=%v", err)
		}
		after := orchestrationMutationFingerprint(t, ctx, store, task.ID, state.Run.ID)
		if before != after {
			t.Fatalf("registry failure mutated durable state: before=%#v after=%#v", before, after)
		}
	})
}

func TestFreshPreparationFailureNeverLeavesOrphanRunningTask(t *testing.T) {
	t.Run("artifact initialization", func(t *testing.T) {
		store, ctx := fullOrchestrationIntegrationStore(t)
		programID, cfg := createFreshOrchestrationProgram(t, ctx, store)
		service := Service{Config: cfg, Store: store, Registry: providers.Registry(cfg)}
		_, err := service.Run(ctx, WorkflowRequest{ProgramID: programID, RequestedBy: "integration", AcknowledgeScopeExpansion: true})
		if err == nil || !strings.Contains(err.Error(), "artifact storage is required") {
			t.Fatalf("error=%v", err)
		}
		assertNoOrphanRunningTask(t, ctx, store, programID, 1, 0)
	})

	t.Run("initial checkpoint persistence", func(t *testing.T) {
		store, ctx := fullOrchestrationIntegrationStore(t)
		programID, cfg := createFreshOrchestrationProgram(t, ctx, store)
		cfg.ArtifactStorage.Root = t.TempDir()
		occupied := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(occupied, []byte("occupied"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg.Scheduler.WorkflowStateRoot = occupied
		_, err := (Service{Config: cfg, Store: store, Registry: providers.Registry(cfg), Artifacts: orchestrationTestArtifacts{}}).Run(ctx, WorkflowRequest{ProgramID: programID, RequestedBy: "integration", AcknowledgeScopeExpansion: true})
		if !errors.Is(err, workflow.ErrWorkflowCheckpointUnavailable) {
			t.Fatalf("error=%v", err)
		}
		assertNoOrphanRunningTask(t, ctx, store, programID, 1, 1)
	})
}

func TestResumeMaterializerRevisionFailsClosed(t *testing.T) {
	tests := []struct {
		name               string
		templateRevision   string
		definitionRevision string
		want               error
	}{
		{name: "unsupported release revision", templateRevision: "web-recon/v99", definitionRevision: "web-recon/v99", want: workflow.ErrWorkflowCheckpointConflict},
		{name: "template and definition revision mismatch", templateRevision: "web-recon/v1", definitionRevision: "web-recon/v99", want: workflow.ErrWorkflowCheckpointConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, ctx := fullOrchestrationIntegrationStore(t)
			programID := createRawProgram(t, ctx, store, "materializer")
			now := time.Now().UTC().Truncate(time.Microsecond)
			template := workflow.Template{ID: domain.NewID(), Name: "materializer-" + string(domain.NewID()), Version: "1", Description: "materializer test", Materializer: test.templateRevision, DefaultPolicyRequirements: json.RawMessage(`{}`), CreatedAt: now}
			if test.templateRevision == "web-recon/v1" {
				template, _ = workflows.CurrentTemplate(workflows.ContinuousName)
				if err := store.EnsureWorkflowTemplate(ctx, template); err != nil {
					t.Fatal(err)
				}
			} else {
				descriptor := json.RawMessage(`{"schema_version":1,"kind":"built-in","materializer":"web-recon/v99"}`)
				if _, err := store.Pool.Exec(ctx, `INSERT INTO workflow_definitions(id,name,version,description,definition,default_policy_requirements,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, template.ID, template.Name, template.Version, template.Description, descriptor, template.DefaultPolicyRequirements, template.CreatedAt); err != nil {
					t.Fatal(err)
				}
			}
			task := domain.Task{ID: domain.NewID(), ProgramID: programID, Objective: "materializer", WorkflowDefinitionID: template.ID, Status: domain.TaskRunning, RequestedBy: "integration", CreatedAt: now, UpdatedAt: now}
			if err := store.CreateTask(ctx, task); err != nil {
				t.Fatal(err)
			}
			var scopeID domain.ID
			if err := store.Pool.QueryRow(ctx, `SELECT id FROM scope_versions WHERE program_id=$1`, programID).Scan(&scopeID); err != nil {
				t.Fatal(err)
			}
			definition := workflow.Definition{ID: template.ID, Name: template.Name, Version: template.Version, Materializer: test.definitionRevision, Description: template.Description, Steps: []workflow.Step{}, DefaultPolicyRequirements: template.DefaultPolicyRequirements, CreatedAt: template.CreatedAt}
			materialized, digest, err := workflow.Materialize(definition)
			if err != nil {
				t.Fatal(err)
			}
			runID := domain.NewID()
			if _, err := store.Pool.Exec(ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,trigger_source,summary,materialized_definition,materialization_digest,original_scope_version_id) VALUES($1,$2,$3,$4,'running',$5,'integration','{}',$6,$7,$8)`, runID, task.ID, template.ID, template.Version, now, materialized, digest, scopeID); err != nil {
				t.Fatal(err)
			}
			before := orchestrationMutationFingerprint(t, ctx, store, task.ID, runID)
			_, err = (Service{Config: config.Config{Scheduler: config.Scheduler{WorkflowStateRoot: t.TempDir()}}, Store: store, Registry: capability.NewRegistry()}).Run(ctx, WorkflowRequest{ResumeRunID: runID})
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v", err)
			}
			if after := orchestrationMutationFingerprint(t, ctx, store, task.ID, runID); before != after {
				t.Fatalf("materializer failure mutated state: before=%#v after=%#v", before, after)
			}
		})
	}
}

type durableMutationFingerprint struct {
	TaskStatus       string
	TaskUpdatedAt    string
	RunStatus        string
	RunCompletedAt   string
	ScopeVersions    int64
	AuditEvents      int64
	ProviderAttempts int64
}

func orchestrationMutationFingerprint(t *testing.T, ctx context.Context, store *database.Store, taskID, runID domain.ID) durableMutationFingerprint {
	t.Helper()
	var fingerprint durableMutationFingerprint
	if err := store.Pool.QueryRow(ctx, `SELECT t.status,t.updated_at::text,wr.status,COALESCE(wr.completed_at::text,''),
		(SELECT count(*) FROM scope_versions WHERE program_id=t.program_id),
		(SELECT count(*) FROM audit_events WHERE task_id=t.id OR workflow_run_id=wr.id),
		(SELECT count(*) FROM audit_events WHERE event_type='provider_invocation_started' AND (task_id=t.id OR workflow_run_id=wr.id))
		FROM tasks t JOIN workflow_runs wr ON wr.task_id=t.id WHERE t.id=$1 AND wr.id=$2`, taskID, runID).Scan(
		&fingerprint.TaskStatus, &fingerprint.TaskUpdatedAt, &fingerprint.RunStatus, &fingerprint.RunCompletedAt,
		&fingerprint.ScopeVersions, &fingerprint.AuditEvents, &fingerprint.ProviderAttempts,
	); err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

func fullOrchestrationIntegrationStore(t *testing.T) (*database.Store, context.Context) {
	t.Helper()
	store, ctx := preMaterializationMigrationStore(t)
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterArtifactStore(ctx, orchestrationTestStoreRegistration()); err != nil {
		t.Fatal(err)
	}
	return store, ctx
}

type orchestrationTestArtifacts struct{}

func (orchestrationTestArtifacts) Put(_ context.Context, req artifact.PutRequest) (domain.Artifact, error) {
	id := domain.NewID()
	key, err := artifact.StorageKeyFor(id)
	if err != nil {
		return domain.Artifact{}, err
	}
	storeID := orchestrationTestStoreRegistration().ID
	return domain.Artifact{ID: id, TaskID: req.TaskID, WorkflowRunID: req.WorkflowRunID, StepRunID: req.StepRunID, ToolRunID: req.ToolRunID, Type: req.Type, ContentType: req.ContentType, Size: int64(len(req.Data)), AddressingVersion: 1, ArtifactStoreID: &storeID, StorageKey: &key, CreatedAt: time.Now().UTC()}, nil
}

func orchestrationTestStoreRegistration() domain.ArtifactStoreRegistration {
	return domain.ArtifactStoreRegistration{ID: "00000000-0000-4000-8000-000000009003", IncarnationNonce: "00000000-0000-4000-8000-000000009004", BackendKind: artifact.BackendKind, MarkerFormat: artifact.MarkerFormat, MarkerVersion: artifact.MarkerVersion}
}

func createRawProgram(t *testing.T, ctx context.Context, store *database.Store, label string) domain.ID {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	programID := domain.NewID()
	program := domain.Program{ID: programID, Name: label + "-" + string(programID), Platform: "integration", ScopeReference: "synthetic://" + label, PolicyReference: "integration", ScopeDigest: "scope", IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: "plan", ScopePlanWarnings: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now}
	snapshot := domain.ScopeSnapshot{ScopeReference: program.ScopeReference, ScopeDigest: program.ScopeDigest, IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: program.TargetPlanDigest, PlanningWarnings: json.RawMessage(`[]`), TargetPlan: json.RawMessage(`{}`), CreatedAt: now}
	if err := store.CreateProgram(ctx, program, snapshot); err != nil {
		t.Fatal(err)
	}
	return programID
}

func createModernResumeFixture(t *testing.T, ctx context.Context, store *database.Store, steps []workflow.Step) (domain.ID, domain.Task, *workflow.State) {
	t.Helper()
	programID := createRawProgram(t, ctx, store, "modern-resume")
	template, err := workflows.CurrentTemplate(workflows.ContinuousName)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureWorkflowTemplate(ctx, template); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	task := domain.Task{ID: domain.NewID(), ProgramID: programID, Objective: "modern resume", WorkflowDefinitionID: template.ID, Status: domain.TaskRunning, RequestedBy: "integration", CreatedAt: now, UpdatedAt: now}
	if err := store.CreateTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	var scopeID domain.ID
	if err := store.Pool.QueryRow(ctx, `SELECT id FROM scope_versions WHERE program_id=$1`, programID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	definition := workflow.Definition{ID: template.ID, Name: template.Name, Version: template.Version, Materializer: template.Materializer, Description: template.Description, Steps: append([]workflow.Step(nil), steps...), DefaultPolicyRequirements: template.DefaultPolicyRequirements, CreatedAt: template.CreatedAt}
	materialized, digest, err := workflow.Materialize(definition)
	if err != nil {
		t.Fatal(err)
	}
	state := &workflow.State{Run: domain.WorkflowRun{ID: domain.NewID(), TaskID: task.ID, WorkflowDefinitionID: template.ID, WorkflowVersion: template.Version, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration", Summary: json.RawMessage(`{}`), MaterializedDefinition: materialized, MaterializationDigest: digest, OriginalScopeVersionID: &scopeID}, Steps: map[string]*workflow.StepState{}}
	if err := store.SaveWorkflowState(ctx, state); err != nil {
		t.Fatal(err)
	}
	return programID, task, state
}

func createFreshOrchestrationProgram(t *testing.T, ctx context.Context, store *database.Store) (domain.ID, config.Config) {
	t.Helper()
	root := t.TempDir()
	scopeDir := filepath.Join(root, "scope")
	if err := os.Mkdir(scopeDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scopeDir, "program.json"), []byte(`{"target":{"scope":{"exclude":[],"include":[{"enabled":true,"file":"^/.*","host":"^app\\.example\\.test$","port":"^443$","protocol":"https"}]}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	programID := domain.NewID()
	program := domain.Program{ID: programID, Name: "fresh-" + string(programID), Platform: "integration", ScopeReference: "scope/program.json", PolicyReference: "integration", ScopeDigest: "prior-scope", IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: "prior-plan", ScopePlanWarnings: json.RawMessage(`[]`), CreatedAt: now, UpdatedAt: now}
	snapshot := domain.ScopeSnapshot{ScopeReference: program.ScopeReference, ScopeDigest: program.ScopeDigest, IncludeRuleDigests: []string{}, ExcludeRuleDigests: []string{}, TargetPlanDigest: program.TargetPlanDigest, PlanningWarnings: json.RawMessage(`[]`), TargetPlan: json.RawMessage(`{}`), CreatedAt: now}
	if err := store.CreateProgram(ctx, program, snapshot); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Scope: config.Scope{Root: root}, Scheduler: config.Scheduler{WorkflowStateRoot: filepath.Join(root, "runs")}, ArtifactStorage: config.ArtifactStorage{Root: filepath.Join(root, "artifacts")}, Recon: config.Recon{Timeout: time.Second}, Policy: config.Policy{DefaultRateLimit: 10, DefaultConcurrency: 1, DefaultProviderConcurrency: 1, DefaultHostConcurrency: 1, MaxPayloadBytes: 1 << 20, AllowedMethods: []string{"GET", "HEAD", "OPTIONS"}}}
	return programID, cfg
}

func assertNoOrphanRunningTask(t *testing.T, ctx context.Context, store *database.Store, programID domain.ID, wantTasks, wantRuns int64) {
	t.Helper()
	var tasks, runs, orphans, providerAttempts, pending int64
	if err := store.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM tasks WHERE program_id=$1),
		(SELECT count(*) FROM workflow_runs wr JOIN tasks t ON t.id=wr.task_id WHERE t.program_id=$1),
		(SELECT count(*) FROM tasks t WHERE t.program_id=$1 AND t.status='running' AND NOT EXISTS(SELECT 1 FROM workflow_runs wr WHERE wr.task_id=t.id)),
		(SELECT count(*) FROM audit_events WHERE program_id=$1 AND event_type='provider_invocation_started'),
		(SELECT count(*) FROM tasks WHERE program_id=$1 AND status='pending')`, programID).Scan(&tasks, &runs, &orphans, &providerAttempts, &pending); err != nil {
		t.Fatal(err)
	}
	if tasks != wantTasks || runs != wantRuns || orphans != 0 || providerAttempts != 0 || (wantRuns == 0 && pending != 1) {
		t.Fatalf("tasks=%d runs=%d orphan_running=%d provider_attempts=%d pending=%d", tasks, runs, orphans, providerAttempts, pending)
	}
}

func preMaterializationMigrationStore(t *testing.T) (*database.Store, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "legacy_resume_" + strings.ReplaceAll(string(domain.NewID()), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop integration schema: %v", err)
		}
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	store, err := database.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if _, err := store.Pool.Exec(ctx, `CREATE TABLE schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	versions, err := migrations.Versions()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range versions {
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			t.Fatalf("invalid migration name %q", name)
		}
		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if version >= 15 {
			continue
		}
		body, err := os.ReadFile(filepath.Join("..", "migrations", "sql", name))
		if err != nil {
			t.Fatal(err)
		}
		tx, err := store.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7212026)`); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("acquire migration lock: %v", err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("apply migration %s: %v", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version,name) VALUES($1,$2)`, version, name); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	return store, ctx
}

func legacyResumeMutationCounts(t *testing.T, ctx context.Context, store *database.Store, programID, taskID, runID domain.ID) [5]int64 {
	t.Helper()
	var counts [5]int64
	if err := store.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM scope_versions WHERE program_id=$1),
		(SELECT count(*) FROM tasks WHERE id=$2),
		(SELECT count(*) FROM workflow_runs WHERE id=$3),
		(SELECT count(*) FROM audit_events WHERE task_id=$2 OR workflow_run_id=$3),
		(SELECT count(*) FROM audit_events WHERE event_type='provider_invocation_started' AND (task_id=$2 OR workflow_run_id=$3))`, programID, taskID, runID).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4]); err != nil {
		t.Fatal(err)
	}
	return counts
}
