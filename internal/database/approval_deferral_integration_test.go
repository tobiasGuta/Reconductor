package database

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/targeting"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
	"github.com/tobiasGuta/Reconductor/internal/workflows"
)

func newContinuousApprovalFixture(t *testing.T) (preparedDBFixture, domain.ID, domain.ID) {
	t.Helper()
	env := newRecoveryTestEnvironment(t, "continuous-approval-deferral")
	definition := workflows.ContinuousWebRecon(targeting.TargetPlan{}, false)
	template, _ := workflows.CurrentTemplate(workflows.ContinuousName)
	if err := env.store.EnsureWorkflowTemplate(env.ctx, template); err != nil {
		t.Fatal(err)
	}
	env.definitionID = definition.ID
	material, digest, err := workflow.Materialize(definition)
	if err != nil {
		t.Fatal(err)
	}
	schedule := createIntegrationSchedule(t, env.ctx, env.store, env.programID, "continuous-siblings")
	execution := enqueueAndClaim(t, env.ctx, env.store, schedule.ID, "approval-test", time.Minute)
	task := createIntegrationTask(t, env.ctx, env.store, env.programID, definition.ID, "continuous-siblings")
	if err := env.store.MarkScheduledExecutionTaskCreated(env.ctx, execution.ID, task.ID, "approval-test", execution.AttemptCount); err != nil {
		t.Fatal(err)
	}
	_, scopeID := syntheticWorkflowDefinition(t, env.store, env.ctx, task.ID)
	now := time.Now().UTC()
	runID := domain.NewID()
	state := &workflow.State{Run: domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: definition.ID, WorkflowVersion: definition.Version, Status: domain.RunRunning, StartedAt: &now, TriggerSource: "run_now", Summary: json.RawMessage(`{}`), MaterializedDefinition: material, MaterializationDigest: digest, OriginalScopeVersionID: &scopeID}, Steps: map[string]*workflow.StepState{}}
	var report, nuclei workflow.Step
	for _, step := range definition.Steps {
		run := domain.StepRun{ID: domain.NewID(), WorkflowRunID: runID, StepDefinitionID: step.ID, Capability: step.Capability, Status: domain.StepSucceeded, Input: step.Input, Output: json.RawMessage(`{}`), IdempotencyKey: step.ID, StartedAt: &now, CompletedAt: &now}
		switch step.ID {
		case "generate-recon-brief":
			report = step
			run.Status = domain.StepRunning
			run.CompletedAt = nil
		case "run-safe-nuclei-profile":
			nuclei = step
			run.Status = domain.StepAwaitingApproval
			run.ApprovalState = "pending"
			run.CompletedAt = nil
		case "enrich-recon-brief":
			run.Status = domain.StepPending
			run.StartedAt = nil
			run.CompletedAt = nil
		}
		state.Steps[step.ID] = &workflow.StepState{Run: run, InputHash: workflow.InputDigest(step.Input)}
	}
	if report.ID == "" || !nuclei.ApprovalRequired || !reflect.DeepEqual(report.DependsOn, nuclei.DependsOn) {
		t.Fatal("built-in sibling topology changed")
	}
	fence := ScheduledExecutionFence{ExecutionID: execution.ID, LeaseOwner: "approval-test", Attempt: execution.AttemptCount}
	ctx := WithScheduledExecutionFence(env.ctx, fence)
	if err := env.store.saveWorkflowState(ctx, state, func(c context.Context, s *workflow.State) error {
		return env.store.MarkScheduledExecutionRunning(c, execution.ID, task.ID, runID, &scopeID, "approval-test", execution.AttemptCount)
	}); err != nil {
		t.Fatal(err)
	}
	reportID, nucleiID := state.Steps[report.ID].Run.ID, state.Steps[nuclei.ID].Run.ID
	scheduled := scheduledResultFixture{env: env, lineage: recoveryTestFixture{execution: execution, task: task, runID: runID}, stepID: reportID, idempotencyKey: report.ID, capability: report.Capability, fence: fence}
	action := scheduledProviderAction(scheduled, 1)
	if _, err := env.store.PersistEffectiveStepInput(ctx, env.programID, action, action.Input); err != nil {
		t.Fatal(err)
	}
	f := prepareDBFixture(t, env, scheduled)
	if err := env.store.SealPreparedEvidence(f.context(), f.seal); err != nil {
		t.Fatal(err)
	}
	var approvalID domain.ID
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT id FROM approvals WHERE request_id=$1`, nucleiID).Scan(&approvalID); err != nil {
		t.Fatal(err)
	}
	return f, approvalID, nucleiID
}

type lostApprovalAck struct {
	pgx.Tx
	committed bool
}

func (tx lostApprovalAck) Commit(ctx context.Context) error {
	var err error
	if tx.committed {
		err = tx.Tx.Commit(ctx)
	} else {
		err = tx.Tx.Rollback(ctx)
	}
	if err != nil {
		return err
	}
	return errors.New("injected lost approval transaction acknowledgement")
}

func TestContinuousApprovalRejectionDefersCurrentPreparedResult(t *testing.T) {
	for _, mode := range []string{"normal", "commit_unknown_committed", "commit_unknown_rolled_back"} {
		t.Run(mode, func(t *testing.T) {
			f, approvalID, nucleiID := newContinuousApprovalFixture(t)
			env := f.env
			decide := func() {
				t.Helper()
				if mode != "normal" {
					tx, err := env.store.Pool.Begin(env.ctx)
					if err != nil {
						t.Fatal(err)
					}
					err = decideApprovalTx(env.ctx, lostApprovalAck{Tx: tx, committed: mode == "commit_unknown_committed"}, approvalID, "rejected", "human")
					if !domain.PersistenceUnresolved(err) {
						t.Fatalf("lost ack=%v", err)
					}
				}
				if err := env.store.DecideApproval(env.ctx, approvalID, "rejected", "human"); err != nil {
					t.Fatal(err)
				}
			}
			expireRecoveryLease(t, env, f.fence.ExecutionID, 1)
			var leaseBefore time.Time
			if err := env.store.Pool.QueryRow(env.ctx, `SELECT lease_expires_at FROM scheduled_executions WHERE id=$1`, f.fence.ExecutionID).Scan(&leaseBefore); err != nil {
				t.Fatal(err)
			}
			decide()
			if decision, err := env.store.StepApprovalDecision(env.ctx, nucleiID); err != nil || decision != "rejected" {
				t.Fatalf("human decision=%s err=%v", decision, err)
			}
			reconcileRecovery(t, env)
			var scheduled, run, task, step string
			var attempt int
			var leaseAfter time.Time
			if err := env.store.Pool.QueryRow(env.ctx, `SELECT se.status,se.attempt_count,se.lease_expires_at,wr.status,t.status,sr.status FROM scheduled_executions se JOIN workflow_runs wr ON wr.id=se.workflow_run_id JOIN tasks t ON t.id=wr.task_id JOIN step_runs sr ON sr.id=$2 WHERE se.id=$1`, f.fence.ExecutionID, nucleiID).Scan(&scheduled, &attempt, &leaseAfter, &run, &task, &step); err != nil {
				t.Fatal(err)
			}
			if scheduled != "running" || attempt != 1 || run != "running" || task != "running" || step != "awaiting_approval" || !leaseAfter.Equal(leaseBefore) {
				t.Fatalf("premature terminalization/lease change: %s %d %s %s %s", scheduled, attempt, run, task, step)
			}
			record, err := env.store.PreparedSet(env.ctx, f.admission.PreparedSetID)
			if err != nil || record.State != domain.PreparedSealed || record.ReservedCapacityBytes != f.admission.ReservedCapacityBytes || record.ContentSizeBytes == nil || *record.ContentSizeBytes != f.seal.ContentBytes {
				t.Fatalf("retained evidence/charge=%#v %v", record, err)
			}
			if _, _, claimed, err := env.store.ClaimPendingScheduledExecution(env.ctx, "replacement", time.Minute); err != nil || claimed {
				t.Fatalf("replacement=%v err=%v", claimed, err)
			}
			ctx := f.recoveryContext()
			if err := env.store.ReserveCompiledResult(ctx, env.programID, f.step, f.compiled, &f.admission, f.identity); err != nil {
				t.Fatalf("exact recovery no longer admissible: %v", err)
			}
			for i := range f.compiled.Artifacts {
				if err := env.store.MarkCompiledArtifactPublishing(ctx, f.compiled, i); err != nil {
					t.Fatal(err)
				}
				if err := env.store.SealCompiledArtifact(ctx, f.compiled, i); err != nil {
					t.Fatal(err)
				}
			}
			if err := env.store.AdoptCompiledResult(ctx, env.programID, f.step, f.compiled, &f.admission, time.Hour); err != nil {
				t.Fatal(err)
			}
			if mode != "normal" {
				decide()
			} else if err := env.store.ReconcileDeferredApprovalRejections(env.ctx, 10); err != nil {
				t.Fatal(err)
			}
			assertScheduledStatusAndAttempt(t, env, f.fence.ExecutionID, domain.ScheduledExecutionApprovalRejected, 1)
			assertStepRecoveryStatus(t, env, nucleiID, domain.StepFailed)
			assertStepRecoveryStatus(t, env, f.step.ID, domain.StepSucceeded)
			if err := env.store.Pool.QueryRow(env.ctx, `SELECT wr.status,t.status FROM workflow_runs wr JOIN tasks t ON t.id=wr.task_id WHERE wr.id=$1`, f.step.WorkflowRunID).Scan(&run, &task); err != nil || run != "failed" || task != "failed" {
				t.Fatalf("post-resolution run=%s task=%s err=%v", run, task, err)
			}
			var invocations, decisions int
			if err := env.store.Pool.QueryRow(env.ctx, `SELECT count(*) FILTER (WHERE event_type='provider_invocation_started'),count(*) FILTER (WHERE event_type='moderate_approval_rejected') FROM audit_events WHERE workflow_run_id=$1`, f.step.WorkflowRunID).Scan(&invocations, &decisions); err != nil || invocations != 1 || decisions != 1 {
				t.Fatalf("replay/decision duplication=%d %d %v", invocations, decisions, err)
			}
			record, err = env.store.PreparedSet(env.ctx, f.admission.PreparedSetID)
			if err != nil || record.State != domain.PreparedResolvedAdopted || record.ResultOccurrenceID == nil || *record.ResultOccurrenceID != f.compiled.ResultOccurrenceID {
				t.Fatalf("exact result lost: %#v %v", record, err)
			}
		})
	}
}
