package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

type scheduledResultFixture struct {
	env            recoveryTestEnvironment
	lineage        recoveryTestFixture
	stepID         domain.ID
	idempotencyKey string
	capability     string
	fence          ScheduledExecutionFence
}

type providerResultCollisionCandidate struct {
	fixture   scheduledResultFixture
	action    domain.ActionRequest
	admission *capability.ResultAdmissionProvenance
	step      domain.StepRun
	tool      *domain.ToolRun
	artifacts []domain.Artifact
	result    domain.ActionResult
	before    string
}

func TestScheduledPersistResultFenceAcceptanceAndRejection(t *testing.T) {
	t.Run("current scheduled HTTP result persists atomically", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-current-http", "probe.http")
		output := json.RawMessage(`{"lines":["http://127.0.0.1/"],"authorized_records":[{"provider":"httpx","kind":"url","target":"http://127.0.0.1/","status_code":200}]}`)
		step, tool, artifacts, result := scheduledResultPayload(fixture, output)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, nil); err != nil {
			t.Fatal(err)
		}
		assertResultRowCounts(t, fixture, 1, 1, 1, 0, 1)
		assertStepRecoveryStatus(t, fixture.env, fixture.stepID, domain.StepSucceeded)
	})

	t.Run("current scheduled Nuclei result persists finding evidence", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-current-finding", "scan.nuclei")
		line := `{"template-id":"harmless-info","matched-at":"http://127.0.0.1/","info":{"name":"Harmless local response","severity":"info"}}`
		output, err := json.Marshal(map[string]any{"lines": []string{line}})
		if err != nil {
			t.Fatal(err)
		}
		step, tool, artifacts, result := scheduledResultPayload(fixture, output)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, nil); err != nil {
			t.Fatal(err)
		}
		assertResultRowCounts(t, fixture, 1, 1, 0, 1, 1)
		var changeCount int
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT count(*) FROM change_items WHERE workflow_run_id=$1`, fixture.lineage.runID).Scan(&changeCount); err != nil || changeCount != 1 {
			t.Fatalf("change items=%d err=%v", changeCount, err)
		}
	})

	t.Run("expired live lease rejects before reconciliation", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-expired", "scan.nuclei")
		expireRecoveryLease(t, fixture.env, fixture.lineage.execution.ID, 1)
		assertScheduledValidResultRejectedNoMutation(t, fixture, fixture.context())
		if err := fixture.env.store.HeartbeatScheduledExecution(fixture.env.ctx, fixture.lineage.execution.ID, fixture.fence.LeaseOwner, fixture.fence.Attempt, time.Minute); err == nil {
			t.Fatal("expired owner extended the lease")
		}
		assertStepRecoveryStatus(t, fixture.env, fixture.stepID, domain.StepRunning)
	})

	t.Run("reconciled lineage rejects and preserves closed incomplete tool", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-reconciled", "scan.nuclei")
		toolID := insertRecoveryTool(t, fixture.env, fixture.stepID, false)
		expireRecoveryLease(t, fixture.env, fixture.lineage.execution.ID, 1)
		reconcileRecovery(t, fixture.env)
		var toolBefore string
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT to_jsonb(tool_runs)::text FROM tool_runs WHERE id=$1`, toolID).Scan(&toolBefore); err != nil {
			t.Fatal(err)
		}
		beforeAudit := recoveryAuditRecord(t, fixture.env, fixture.lineage.execution.ID, "scheduled_execution_lineage_interrupted")
		step, tool, artifacts, result := fixture.validPayload()
		tool.ID = toolID
		for index := range artifacts {
			artifacts[index].ToolRunID = toolID
		}
		assertScheduledResultRejectedNoMutation(t, fixture, fixture.context(), step, tool, artifacts, result)
		var toolAfter string
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT to_jsonb(tool_runs)::text FROM tool_runs WHERE id=$1`, toolID).Scan(&toolAfter); err != nil {
			t.Fatal(err)
		}
		if toolAfter != toolBefore {
			t.Fatalf("recovery-closed tool changed\nbefore=%s\nafter=%s", toolBefore, toolAfter)
		}
		afterAudit := recoveryAuditRecord(t, fixture.env, fixture.lineage.execution.ID, "scheduled_execution_lineage_interrupted")
		if fmt.Sprint(beforeAudit) != fmt.Sprint(afterAudit) {
			t.Fatalf("recovery audit changed\nbefore=%v\nafter=%v", beforeAudit, afterAudit)
		}
		var completedAt *time.Time
		var exitCode *int
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT completed_at,exit_code FROM tool_runs WHERE id=$1`, toolID).Scan(&completedAt, &exitCode); err != nil {
			t.Fatal(err)
		}
		if completedAt == nil || exitCode != nil {
			t.Fatalf("recovery-closed tool completed=%v exit=%v", completedAt, exitCode)
		}
	})

	for _, test := range []struct {
		name  string
		fence func(ScheduledExecutionFence) ScheduledExecutionFence
	}{
		{name: "wrong owner", fence: func(f ScheduledExecutionFence) ScheduledExecutionFence { f.LeaseOwner = "other-owner"; return f }},
		{name: "wrong attempt", fence: func(f ScheduledExecutionFence) ScheduledExecutionFence { f.Attempt++; return f }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "result-"+strings.ReplaceAll(test.name, " ", "-"), "scan.nuclei")
			ctx := WithScheduledExecutionFence(fixture.env.ctx, test.fence(fixture.fence))
			assertScheduledValidResultRejectedNoMutation(t, fixture, ctx)
		})
	}

	t.Run("missing scheduled claim fence", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-missing-fence", "scan.nuclei")
		assertScheduledValidResultRejectedNoMutation(t, fixture, fixture.env.ctx)
	})

	t.Run("workflow mismatch", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-workflow-mismatch", "scan.nuclei")
		step, tool, artifacts, result := fixture.validPayload()
		step.WorkflowRunID = domain.NewID()
		assertScheduledResultRejectedNoMutation(t, fixture, fixture.context(), step, tool, artifacts, result)
	})

	t.Run("step belongs to another workflow", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-step-workflow-mismatch", "scan.nuclei")
		otherRunID := domain.NewID()
		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,started_at,trigger_source,summary) VALUES($1,$2,$3,'1','running',clock_timestamp(),'integration','{}')`, otherRunID, fixture.lineage.task.ID, fixture.env.definitionID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE step_runs SET workflow_run_id=$2 WHERE id=$1`, fixture.stepID, otherRunID); err != nil {
			t.Fatal(err)
		}
		assertScheduledValidResultRejectedNoMutation(t, fixture, fixture.context())
	})

	t.Run("idempotency mismatch", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-idempotency-mismatch", "scan.nuclei")
		step, tool, artifacts, result := fixture.validPayload()
		step.IdempotencyKey = "other-idempotency-key"
		assertScheduledResultRejectedNoMutation(t, fixture, fixture.context(), step, tool, artifacts, result)
	})

	for _, status := range []domain.StepStatus{domain.StepSucceeded, domain.StepFailed, domain.StepCancelled, domain.StepPending, domain.StepBlocked, domain.StepAwaitingApproval} {
		t.Run("non-running step "+string(status), func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "result-step-"+string(status), "scan.nuclei")
			if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE step_runs SET status=$2 WHERE id=$1`, fixture.stepID, status); err != nil {
				t.Fatal(err)
			}
			assertScheduledValidResultRejectedNoMutation(t, fixture, fixture.context())
		})
	}

	for _, status := range []domain.ScheduledExecutionStatus{
		domain.ScheduledExecutionInterrupted,
		domain.ScheduledExecutionCompleted,
		domain.ScheduledExecutionFailed,
		domain.ScheduledExecutionCancelled,
		domain.ScheduledExecutionApprovalRejected,
		domain.ScheduledExecutionPausedForApproval,
		domain.ScheduledExecutionPausedOperator,
		domain.ScheduledExecutionPending,
		domain.ScheduledExecutionClaimed,
	} {
		t.Run("scheduled status "+string(status), func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "result-scheduled-"+string(status), "scan.nuclei")
			if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE scheduled_executions SET status=$2 WHERE id=$1`, fixture.lineage.execution.ID, status); err != nil {
				t.Fatal(err)
			}
			assertScheduledValidResultRejectedNoMutation(t, fixture, fixture.context())
		})
	}

	t.Run("later evidence failure rolls back the entire result transaction", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-atomic-rollback", "probe.http")
		step, tool, artifacts, result := fixture.validPayload()
		artifacts[0].Size = -1
		before := resultFenceSnapshot(t, fixture)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, nil); err == nil {
			t.Fatal("invalid artifact size was accepted")
		}
		after := resultFenceSnapshot(t, fixture)
		if after != before {
			t.Fatalf("failed result transaction mutated database\nbefore=%s\nafter=%s", before, after)
		}
	})
}

func TestScheduledProviderStartRequiresExactAuthorizationProvenance(t *testing.T) {
	fixture := newScheduledResultFixture(t, "provider-start-scheduled", "probe.http")
	action := scheduledProviderAction(fixture, 1)
	queueJobID := domain.NewID()
	authorizationID, err := fixture.env.store.RecordPolicyDecision(fixture.context(), capability.PolicyDecisionRecord{ProgramID: fixture.env.programID, Action: action, QueueJobID: &queueJobID, Provider: "fixture-provider", PolicyID: "integration", Phase: "execution", Evaluation: policy.Evaluation{Decision: policy.Allow, Reason: "scheduled provider start test"}})
	if err != nil {
		t.Fatal(err)
	}
	valid := capability.ProviderInvocationStartRecord{ProgramID: fixture.env.programID, TaskID: fixture.lineage.task.ID, WorkflowRunID: fixture.lineage.runID, StepRunID: fixture.stepID, ActionRequestID: action.ID, StepAttempt: action.StepAttempt, QueueJobID: &queueJobID, ExecutionAuthorizationEventID: authorizationID, Capability: fixture.capability, Provider: "fixture-provider", Actor: action.RequestedBy}

	otherStatus := domain.RunRunning
	other := createRecoveryFixture(t, fixture.env, "provider-start-other-scheduled", &otherStatus, domain.TaskRunning, nil)
	otherCtx := WithScheduledExecutionFence(fixture.env.ctx, ScheduledExecutionFence{ExecutionID: other.execution.ID, LeaseOwner: other.execution.LeaseOwner, Attempt: other.execution.AttemptCount})
	wrongAttempt := fixture.fence
	wrongAttempt.Attempt++
	for _, test := range []struct {
		name string
		ctx  context.Context
	}{
		{name: "scheduled execution", ctx: otherCtx},
		{name: "scheduler attempt", ctx: WithScheduledExecutionFence(fixture.env.ctx, wrongAttempt)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := fixture.env.store.RecordProviderInvocationStarted(test.ctx, valid); err == nil {
				t.Fatalf("provider start accepted mismatched %s", test.name)
			}
		})
	}
	if _, err := fixture.env.store.RecordProviderInvocationStarted(fixture.context(), valid); err != nil {
		t.Fatalf("exact scheduled provider start rejected: %v", err)
	}
}

func TestScheduledPersistResultRequiresExactProviderAdmission(t *testing.T) {
	t.Run("valid exact provenance", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "provider-admission-valid", "probe.http")
		action := scheduledProviderAction(fixture, 1)
		queueJobID := domain.NewID()
		admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, &queueJobID, "fixture-provider")
		step, tool, artifacts, result := fixture.validPayload()
		applyScheduledProviderAdmission(tool, &result, admission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission); err != nil {
			t.Fatal(err)
		}
		assertResultRowCounts(t, fixture, 1, 1, 1, 0, 1)
	})

	t.Run("nullable queue and step attempt", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "provider-admission-nullable", "probe.http")
		action := scheduledProviderAction(fixture, 0)
		admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, nil, "fixture-provider")
		step, tool, artifacts, result := fixture.validPayload()
		applyScheduledProviderAdmission(tool, &result, admission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission); err != nil {
			t.Fatal(err)
		}
		var stepAttempt *int
		var queueJobID *domain.ID
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT step_attempt,queue_job_id FROM audit_events WHERE id=$1`, admission.ProviderAttemptID).Scan(&stepAttempt, &queueJobID); err != nil {
			t.Fatal(err)
		}
		if stepAttempt != nil || queueJobID != nil {
			t.Fatalf("unknown optional provenance was synthesized: step_attempt=%v queue_job_id=%v", stepAttempt, queueJobID)
		}
	})

	tests := []struct {
		name    string
		prepare func(*testing.T, scheduledResultFixture, domain.ActionRequest, *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance))
	}{
		{name: "wrong P", prepare: func(t *testing.T, fixture scheduledResultFixture, action domain.ActionRequest, queueJobID *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance)) {
			first := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, queueJobID, "fixture-provider")
			second := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, queueJobID, "fixture-provider")
			return second, func(tool *domain.ToolRun, result *domain.ActionResult, admission *capability.ResultAdmissionProvenance) {
				applyScheduledProviderAdmission(tool, result, admission)
				tool.ProviderAttemptID = &first.ProviderAttemptID
			}
		}},
		{name: "wrong program", prepare: func(t *testing.T, fixture scheduledResultFixture, action domain.ActionRequest, queueJobID *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance)) {
			otherProgramID, _ := createSchedulerIntegrationProgram(t, fixture.env.ctx, fixture.env.store, "provider-admission-other-program-"+string(domain.NewID()))
			return recordScheduledProviderAdmission(t, fixture, fixture.context(), otherProgramID, action, queueJobID, "fixture-provider"), applyScheduledProviderAdmission
		}},
		{name: "wrong task", prepare: func(t *testing.T, fixture scheduledResultFixture, action domain.ActionRequest, queueJobID *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance)) {
			otherStatus := domain.RunRunning
			other := createRecoveryFixture(t, fixture.env, "provider-admission-other-task", &otherStatus, domain.TaskRunning, nil)
			action.TaskID = other.task.ID
			return recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, queueJobID, "fixture-provider"), applyScheduledProviderAdmission
		}},
		{name: "wrong workflow", prepare: func(t *testing.T, fixture scheduledResultFixture, action domain.ActionRequest, queueJobID *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance)) {
			otherStatus := domain.RunRunning
			other := createRecoveryFixture(t, fixture.env, "provider-admission-other-workflow", &otherStatus, domain.TaskRunning, nil)
			action.WorkflowRunID = other.runID
			return recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, queueJobID, "fixture-provider"), applyScheduledProviderAdmission
		}},
		{name: "wrong StepRun", prepare: func(t *testing.T, fixture scheduledResultFixture, action domain.ActionRequest, queueJobID *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance)) {
			otherStatus := domain.RunRunning
			other := createRecoveryFixture(t, fixture.env, "provider-admission-other-step", &otherStatus, domain.TaskRunning, []recoveryStepSpec{{name: "other", status: domain.StepRunning, started: true}})
			action.StepRunID = other.steps["other"]
			return recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, queueJobID, "fixture-provider"), applyScheduledProviderAdmission
		}},
		{name: "wrong ActionRequest", prepare: func(t *testing.T, fixture scheduledResultFixture, action domain.ActionRequest, queueJobID *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance)) {
			admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, queueJobID, "fixture-provider")
			return admission, func(tool *domain.ToolRun, result *domain.ActionResult, admission *capability.ResultAdmissionProvenance) {
				applyScheduledProviderAdmission(tool, result, admission)
				admission.ActionRequestID = domain.NewID()
				result.RequestID = admission.ActionRequestID
			}
		}},
		{name: "wrong step attempt", prepare: func(t *testing.T, fixture scheduledResultFixture, action domain.ActionRequest, queueJobID *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance)) {
			admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, queueJobID, "fixture-provider")
			return admission, func(tool *domain.ToolRun, result *domain.ActionResult, admission *capability.ResultAdmissionProvenance) {
				applyScheduledProviderAdmission(tool, result, admission)
				admission.StepAttempt++
			}
		}},
		{name: "wrong queue job", prepare: func(t *testing.T, fixture scheduledResultFixture, action domain.ActionRequest, queueJobID *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance)) {
			admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, queueJobID, "fixture-provider")
			return admission, func(tool *domain.ToolRun, result *domain.ActionResult, admission *capability.ResultAdmissionProvenance) {
				applyScheduledProviderAdmission(tool, result, admission)
				other := domain.NewID()
				admission.QueueJobID = &other
			}
		}},
		{name: "wrong E", prepare: func(t *testing.T, fixture scheduledResultFixture, action domain.ActionRequest, queueJobID *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance)) {
			admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, queueJobID, "fixture-provider")
			return admission, func(tool *domain.ToolRun, result *domain.ActionResult, admission *capability.ResultAdmissionProvenance) {
				applyScheduledProviderAdmission(tool, result, admission)
				admission.ExecutionAuthorizationEventID = domain.NewID()
			}
		}},
		{name: "wrong capability", prepare: func(t *testing.T, fixture scheduledResultFixture, action domain.ActionRequest, queueJobID *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance)) {
			action.Capability = "alternate.capability"
			return recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, queueJobID, "fixture-provider"), applyScheduledProviderAdmission
		}},
		{name: "wrong provider", prepare: func(t *testing.T, fixture scheduledResultFixture, action domain.ActionRequest, queueJobID *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance)) {
			admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, queueJobID, "fixture-provider")
			return admission, func(tool *domain.ToolRun, result *domain.ActionResult, admission *capability.ResultAdmissionProvenance) {
				applyScheduledProviderAdmission(tool, result, admission)
				admission.Provider = "alternate-provider"
				tool.Provider = admission.Provider
			}
		}},
		{name: "wrong scheduled execution", prepare: func(t *testing.T, fixture scheduledResultFixture, action domain.ActionRequest, queueJobID *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance)) {
			otherStatus := domain.RunRunning
			other := createRecoveryFixture(t, fixture.env, "provider-admission-other-scheduled", &otherStatus, domain.TaskRunning, nil)
			otherCtx := WithScheduledExecutionFence(fixture.env.ctx, ScheduledExecutionFence{ExecutionID: other.execution.ID, LeaseOwner: other.execution.LeaseOwner, Attempt: other.execution.AttemptCount})
			return recordScheduledProviderAdmission(t, fixture, otherCtx, fixture.env.programID, action, queueJobID, "fixture-provider"), applyScheduledProviderAdmission
		}},
		{name: "wrong scheduler attempt", prepare: func(t *testing.T, fixture scheduledResultFixture, action domain.ActionRequest, queueJobID *domain.ID) (*capability.ResultAdmissionProvenance, func(*domain.ToolRun, *domain.ActionResult, *capability.ResultAdmissionProvenance)) {
			wrongFence := fixture.fence
			wrongFence.Attempt++
			return recordScheduledProviderAdmission(t, fixture, WithScheduledExecutionFence(fixture.env.ctx, wrongFence), fixture.env.programID, action, queueJobID, "fixture-provider"), applyScheduledProviderAdmission
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "provider-admission-"+strings.ReplaceAll(test.name, " ", "-"), "probe.http")
			action := scheduledProviderAction(fixture, 1)
			queueJobID := domain.NewID()
			admission, apply := test.prepare(t, fixture, action, &queueJobID)
			step, tool, artifacts, result := fixture.validPayload()
			apply(tool, &result, admission)
			before := resultFenceSnapshot(t, fixture)
			err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission)
			if !errors.Is(err, ErrStaleScheduledExecutionResult) {
				t.Fatalf("PersistResult error=%v want %v", err, ErrStaleScheduledExecutionResult)
			}
			after := resultFenceSnapshot(t, fixture)
			if after != before {
				t.Fatalf("rejected exact-P mismatch mutated database\nbefore=%s\nafter=%s", before, after)
			}
		})
	}
}

func TestProviderResultAcceptedDecisionProvenance(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*domain.StepRun, *domain.ActionResult)
	}{
		{name: "success"},
		{name: "retryable", mutate: makeRetryableResult},
		{name: "terminal failure", mutate: makeTerminalFailedResult},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "result-decision-accepted-"+strings.ReplaceAll(test.name, " ", "-"), "probe.http")
			action := scheduledProviderAction(fixture, 1)
			queueJobID := domain.NewID()
			admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, &queueJobID, "fixture-provider")
			step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
			if test.mutate != nil {
				test.mutate(&step, &result)
			}
			applyScheduledProviderAdmission(tool, &result, admission)

			if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission); err != nil {
				t.Fatal(err)
			}

			decision := loadProviderResultDecision(t, fixture, "provider_result_accepted", admission.ProviderAttemptID, "")
			assertProviderResultDecisionProvenance(t, decision, providerResultDecisionExpectation{
				Actor:                         action.RequestedBy,
				TaskID:                        fixture.lineage.task.ID,
				ProgramID:                     fixture.env.programID,
				WorkflowRunID:                 fixture.lineage.runID,
				StepRunID:                     fixture.stepID,
				ToolRunID:                     &tool.ID,
				ScheduledExecutionID:          fixture.lineage.execution.ID,
				SchedulerAttempt:              fixture.fence.Attempt,
				ActionRequestID:               action.ID,
				StepAttempt:                   action.StepAttempt,
				QueueJobID:                    &queueJobID,
				ExecutionAuthorizationEventID: admission.ExecutionAuthorizationEventID,
				ProviderAttemptID:             admission.ProviderAttemptID,
				Capability:                    fixture.capability,
				Provider:                      admission.Provider,
				SafeMessage:                   "provider result accepted by persistence fence",
				Details:                       `{}`,
			})
			assertProviderResultDecisionCount(t, fixture, admission.ProviderAttemptID, "provider_result_accepted", "", 1)
		})
	}
}

func TestProviderResultAcceptedDecisionFailureRollsBackResult(t *testing.T) {
	fixture := newScheduledResultFixture(t, "result-decision-accepted-rollback", "probe.http")
	admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
	step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
	applyScheduledProviderAdmission(tool, &result, admission)
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `CREATE FUNCTION reject_provider_result_accepted() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.event_type='provider_result_accepted' THEN
				RAISE EXCEPTION 'synthetic accepted decision rejection';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER reject_provider_result_accepted BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_provider_result_accepted()`); err != nil {
		t.Fatal(err)
	}

	before := resultFenceSnapshot(t, fixture)
	err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission)
	if err == nil || !strings.Contains(err.Error(), "synthetic accepted decision rejection") {
		t.Fatalf("accepted decision failure=%v", err)
	}
	if after := resultFenceSnapshot(t, fixture); after != before {
		t.Fatalf("accepted decision failure mutated result\nbefore=%s\nafter=%s", before, after)
	}
	assertProviderResultDecisionCount(t, fixture, admission.ProviderAttemptID, "provider_result_accepted", "", 0)
	assertProviderResultDecisionCount(t, fixture, admission.ProviderAttemptID, "provider_result_rejected", "", 0)
}

func TestProviderResultRejectedReasonCodes(t *testing.T) {
	type rejectionCase struct {
		code    resultFenceReasonCode
		prepare func(*testing.T, scheduledResultFixture, *context.Context, *domain.ID, *domain.StepRun, *domain.ToolRun, *[]domain.Artifact, *domain.ActionResult, *capability.ResultAdmissionProvenance)
	}
	tests := []rejectionCase{
		{code: resultFenceInvalidResultIdentity, prepare: func(_ *testing.T, _ scheduledResultFixture, _ *context.Context, _ *domain.ID, step *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			step.ID = ""
		}},
		{code: resultFenceInvalidScheduledClaim, prepare: func(_ *testing.T, fixture scheduledResultFixture, ctx *context.Context, _ *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			*ctx = WithScheduledExecutionFence(fixture.env.ctx, ScheduledExecutionFence{ExecutionID: fixture.fence.ExecutionID, Attempt: fixture.fence.Attempt})
		}},
		{code: resultFenceScheduledExecutionUnavailable, prepare: func(t *testing.T, fixture scheduledResultFixture, _ *context.Context, _ *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE scheduled_executions SET status='completed' WHERE id=$1`, fixture.lineage.execution.ID); err != nil {
				t.Fatal(err)
			}
		}},
		{code: resultFenceScheduledLineageMismatch, prepare: func(_ *testing.T, _ scheduledResultFixture, _ *context.Context, programID *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			*programID = domain.NewID()
		}},
		{code: resultFenceScheduledClaimMismatch, prepare: func(_ *testing.T, fixture scheduledResultFixture, ctx *context.Context, _ *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			wrong := fixture.fence
			wrong.LeaseOwner = "wrong-owner"
			*ctx = WithScheduledExecutionFence(fixture.env.ctx, wrong)
		}},
		{code: resultFenceScheduledLeaseExpired, prepare: func(t *testing.T, fixture scheduledResultFixture, _ *context.Context, _ *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			expireRecoveryLease(t, fixture.env, fixture.lineage.execution.ID, fixture.fence.Attempt)
		}},
		{code: resultFenceWorkflowLineageMismatch, prepare: func(_ *testing.T, _ scheduledResultFixture, _ *context.Context, _ *domain.ID, step *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			step.IdempotencyKey = "wrong-key"
		}},
		{code: resultFenceWorkflowNotRunning, prepare: func(t *testing.T, fixture scheduledResultFixture, _ *context.Context, _ *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE workflow_runs SET status='failed' WHERE id=$1`, fixture.lineage.runID); err != nil {
				t.Fatal(err)
			}
		}},
		{code: resultFenceInvalidResultState, prepare: func(_ *testing.T, _ scheduledResultFixture, _ *context.Context, _ *domain.ID, step *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			step.Status = domain.StepPending
		}},
		{code: resultFenceToolLineageMismatch, prepare: func(_ *testing.T, _ scheduledResultFixture, _ *context.Context, _ *domain.ID, _ *domain.StepRun, tool *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			tool.StepRunID = domain.NewID()
		}},
		{code: resultFenceProviderProvenanceMismatch, prepare: func(_ *testing.T, _ scheduledResultFixture, _ *context.Context, _ *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, result *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			result.RequestID = domain.NewID()
		}},
		{code: resultFenceStepNotAdmittingResult, prepare: func(t *testing.T, fixture scheduledResultFixture, _ *context.Context, _ *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE step_runs SET status='succeeded',completed_at=clock_timestamp() WHERE id=$1`, fixture.stepID); err != nil {
				t.Fatal(err)
			}
		}},
		{code: resultFenceStaleProviderStepAttempt, prepare: func(t *testing.T, fixture scheduledResultFixture, _ *context.Context, _ *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE step_runs SET attempt_count=2 WHERE id=$1`, fixture.stepID); err != nil {
				t.Fatal(err)
			}
		}},
		{code: resultFenceToolResultConflict, prepare: func(t *testing.T, fixture scheduledResultFixture, _ *context.Context, _ *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at) VALUES($1,$2,$3,'legacy',clock_timestamp())`, domain.NewID(), fixture.stepID, fixture.capability); err != nil {
				t.Fatal(err)
			}
		}},
		{code: resultFenceArtifactIdentityInvalid, prepare: func(_ *testing.T, _ scheduledResultFixture, _ *context.Context, _ *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, artifacts *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			(*artifacts)[0].ID = ""
		}},
		{code: resultFenceArtifactLineageMismatch, prepare: func(_ *testing.T, _ scheduledResultFixture, _ *context.Context, _ *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, artifacts *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			(*artifacts)[0].ToolRunID = domain.NewID()
		}},
		{code: resultFenceArtifactResultConflict, prepare: prepareArtifactResultConflict},
		{code: resultFenceConcurrentStepChange, prepare: func(t *testing.T, fixture scheduledResultFixture, _ *context.Context, _ *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
			if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `CREATE FUNCTION suppress_result_step_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;
				CREATE TRIGGER suppress_result_step_update BEFORE UPDATE OF status ON step_runs FOR EACH ROW WHEN (OLD.id = '`+string(fixture.stepID)+`') EXECUTE FUNCTION suppress_result_step_update()`); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, test := range tests {
		t.Run(string(test.code), func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "result-reason-"+string(test.code), "probe.http")
			action := scheduledProviderAction(fixture, 1)
			admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, nil, "fixture-provider")
			step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
			applyScheduledProviderAdmission(tool, &result, admission)
			ctx := fixture.context()
			programID := fixture.env.programID
			test.prepare(t, fixture, &ctx, &programID, &step, tool, &artifacts, &result, admission)
			before := resultFenceSnapshot(t, fixture)

			err := fixture.env.store.PersistResult(ctx, programID, step, tool, artifacts, result, admission)
			if !errors.Is(err, ErrStaleScheduledExecutionResult) {
				t.Fatalf("rejection error=%v want %v", err, ErrStaleScheduledExecutionResult)
			}
			if after := resultFenceSnapshot(t, fixture); after != before {
				t.Fatalf("rejection mutated result\nbefore=%s\nafter=%s", before, after)
			}
			decision := loadProviderResultDecision(t, fixture, "provider_result_rejected", admission.ProviderAttemptID, string(test.code))
			if decision.Actor != action.RequestedBy || decision.Component != "result_fence" || decision.ProviderAttemptID != admission.ProviderAttemptID || decision.SafeMessage != "provider result rejected by persistence fence" || decision.Details != `{"reason_code": "`+string(test.code)+`"}` {
				t.Fatalf("rejected decision=%#v", decision)
			}
			if strings.Contains(decision.SafeMessage+decision.Details, err.Error()) || strings.Contains(decision.SafeMessage+decision.Details, string(result.Output)) {
				t.Fatalf("rejected decision leaked internal data: %#v", decision)
			}
		})
	}
}

func TestProviderResultRejectedUsesImmutableLineageAndDeduplicates(t *testing.T) {
	fixture := newScheduledResultFixture(t, "result-rejected-immutable", "probe.http")
	action := scheduledProviderAction(fixture, 1)
	queueJobID := domain.NewID()
	admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, &queueJobID, "fixture-provider")
	step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"submitted":"must-not-persist"}`))
	applyScheduledProviderAdmission(tool, &result, admission)
	tool.Provider = "submitted-forged-provider"

	for range 2 {
		err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission)
		if !errors.Is(err, ErrStaleScheduledExecutionResult) {
			t.Fatalf("rejection error=%v", err)
		}
	}
	assertProviderResultDecisionCount(t, fixture, admission.ProviderAttemptID, "provider_result_rejected", string(resultFenceProviderProvenanceMismatch), 1)
	decision := loadProviderResultDecision(t, fixture, "provider_result_rejected", admission.ProviderAttemptID, string(resultFenceProviderProvenanceMismatch))
	assertProviderResultDecisionProvenance(t, decision, providerResultDecisionExpectation{
		Actor:                         action.RequestedBy,
		TaskID:                        fixture.lineage.task.ID,
		ProgramID:                     fixture.env.programID,
		WorkflowRunID:                 fixture.lineage.runID,
		StepRunID:                     fixture.stepID,
		ScheduledExecutionID:          fixture.lineage.execution.ID,
		SchedulerAttempt:              fixture.fence.Attempt,
		ActionRequestID:               action.ID,
		StepAttempt:                   action.StepAttempt,
		QueueJobID:                    &queueJobID,
		ExecutionAuthorizationEventID: admission.ExecutionAuthorizationEventID,
		ProviderAttemptID:             admission.ProviderAttemptID,
		Capability:                    fixture.capability,
		Provider:                      admission.Provider,
		SafeMessage:                   "provider result rejected by persistence fence",
		Details:                       `{"reason_code": "provider_provenance_mismatch"}`,
	})
	if decision.ToolRunID != nil || strings.Contains(decision.Details, "must-not-persist") || strings.Contains(decision.Details, "submitted-forged-provider") {
		t.Fatalf("rejected decision trusted submitted data: %#v", decision)
	}
}

func TestProviderResultDuplicateLinksAuthoritativeToolAndConcurrentRejectionDeduplicates(t *testing.T) {
	fixture := newScheduledResultFixture(t, "result-rejected-authoritative-tool", "probe.http")
	admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
	firstStep, firstTool, firstArtifacts, firstResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
	makeRetryableResult(&firstStep, &firstResult)
	applyScheduledProviderAdmission(firstTool, &firstResult, admission)
	if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, firstStep, firstTool, firstArtifacts, firstResult, admission); err != nil {
		t.Fatal(err)
	}

	duplicateStep, duplicateTool, duplicateArtifacts, duplicateResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
	applyScheduledProviderAdmission(duplicateTool, &duplicateResult, admission)
	ctx, cancel := context.WithTimeout(fixture.context(), 8*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			results <- fixture.env.store.PersistResult(ctx, fixture.env.programID, duplicateStep, duplicateTool, duplicateArtifacts, duplicateResult, admission)
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; !errors.Is(err, ErrStaleScheduledExecutionResult) {
			t.Fatalf("duplicate rejection=%v", err)
		}
	}
	assertProviderResultDecisionCount(t, fixture, admission.ProviderAttemptID, "provider_result_rejected", string(resultFenceToolResultConflict), 1)
	decision := loadProviderResultDecision(t, fixture, "provider_result_rejected", admission.ProviderAttemptID, string(resultFenceToolResultConflict))
	if decision.ToolRunID == nil || *decision.ToolRunID != firstTool.ID {
		t.Fatalf("rejected authoritative tool=%v want=%s", decision.ToolRunID, firstTool.ID)
	}
}

func TestProviderResultRejectedAuditFailurePreservesClassification(t *testing.T) {
	fixture := newScheduledResultFixture(t, "result-rejected-audit-failure", "probe.http")
	admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
	step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
	applyScheduledProviderAdmission(tool, &result, admission)
	result.RequestID = domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `CREATE FUNCTION reject_provider_result_rejected() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.event_type='provider_result_rejected' THEN
				RAISE EXCEPTION 'synthetic rejected decision rejection';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER reject_provider_result_rejected BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_provider_result_rejected()`); err != nil {
		t.Fatal(err)
	}

	before := resultFenceSnapshot(t, fixture)
	err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission)
	if !errors.Is(err, ErrStaleScheduledExecutionResult) || !strings.Contains(err.Error(), "persist provider result rejection") || !strings.Contains(err.Error(), "synthetic rejected decision rejection") {
		t.Fatalf("rejection audit error=%v", err)
	}
	if after := resultFenceSnapshot(t, fixture); after != before {
		t.Fatalf("rejection audit failure mutated result\nbefore=%s\nafter=%s", before, after)
	}
	assertProviderResultDecisionCount(t, fixture, admission.ProviderAttemptID, "provider_result_rejected", string(resultFenceProviderProvenanceMismatch), 0)
}

func TestProviderResultRejectedRequiresVerifiableAdmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*capability.ResultAdmissionProvenance)
	}{
		{name: "incomplete", mutate: func(admission *capability.ResultAdmissionProvenance) { admission.ExecutionAuthorizationEventID = "" }},
		{name: "unknown P", mutate: func(admission *capability.ResultAdmissionProvenance) { admission.ProviderAttemptID = domain.NewID() }},
		{name: "forged action", mutate: func(admission *capability.ResultAdmissionProvenance) { admission.ActionRequestID = domain.NewID() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "result-unverified-"+strings.ReplaceAll(test.name, " ", "-"), "probe.http")
			admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
			originalP := admission.ProviderAttemptID
			step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
			applyScheduledProviderAdmission(tool, &result, admission)
			test.mutate(admission)
			if admission.ProviderAttemptID != originalP {
				tool.ProviderAttemptID = &admission.ProviderAttemptID
			}
			if admission.ActionRequestID != result.RequestID {
				result.RequestID = admission.ActionRequestID
			}
			err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission)
			if !errors.Is(err, ErrStaleScheduledExecutionResult) {
				t.Fatalf("unverified rejection=%v", err)
			}
			assertProviderResultDecisionCount(t, fixture, originalP, "provider_result_rejected", "", 0)
			assertProviderResultDecisionCount(t, fixture, admission.ProviderAttemptID, "provider_result_rejected", "", 0)
		})
	}
}

func TestPersistResultProviderRetryAdmission(t *testing.T) {
	t.Run("P1 retryable followed by P2 success preserves complete attempt evidence", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "provider-retry-success", "probe.http")
		firstOutput := json.RawMessage(`{"lines":["http://127.0.0.1/first"],"authorized":["http://127.0.0.1/first"],"filtered":[{"target":"http://127.0.0.1/blocked-first","reason":"matched_exclusion"}]}`)
		firstAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
		firstStep, firstTool, firstArtifacts, firstResult := scheduledResultPayload(fixture, firstOutput)
		makeRetryableResult(&firstStep, &firstResult)
		applyScheduledProviderAdmission(firstTool, &firstResult, firstAdmission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, firstStep, firstTool, firstArtifacts, firstResult, firstAdmission); err != nil {
			t.Fatal(err)
		}
		assertPersistedStepState(t, fixture, domain.StepRetryable, 1, false)
		assertResultRowCounts(t, fixture, 1, 1, 0, 0, 1)
		assertTargetDecisionCount(t, fixture, 0)

		secondOutput := json.RawMessage(`{"lines":["http://127.0.0.1/second"],"authorized":["http://127.0.0.1/second"],"filtered":[{"target":"http://127.0.0.1/blocked-second","reason":"matched_exclusion"}]}`)
		secondAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 2), nil, "fixture-provider")
		secondStep, secondTool, secondArtifacts, secondResult := scheduledResultPayload(fixture, secondOutput)
		applyScheduledProviderAdmission(secondTool, &secondResult, secondAdmission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, secondStep, secondTool, secondArtifacts, secondResult, secondAdmission); err != nil {
			t.Fatal(err)
		}
		assertPersistedStepState(t, fixture, domain.StepSucceeded, 2, true)
		assertResultRowCounts(t, fixture, 2, 2, 1, 0, 2)
		assertTargetDecisionCount(t, fixture, 2)

		var providerAttempts, artifactTools, executionAttempts int
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
			(SELECT count(DISTINCT provider_attempt_id) FROM tool_runs WHERE step_run_id=$1),
			(SELECT count(DISTINCT tool_run_id) FROM artifacts WHERE step_run_id=$1),
			(SELECT count(DISTINCT provider_attempt_id) FROM audit_events WHERE step_run_id=$1 AND event_type='tool_execution')`, fixture.stepID).Scan(&providerAttempts, &artifactTools, &executionAttempts); err != nil {
			t.Fatal(err)
		}
		if providerAttempts != 2 || artifactTools != 2 || executionAttempts != 2 || firstTool.ID == secondTool.ID || firstAdmission.ProviderAttemptID == secondAdmission.ProviderAttemptID {
			t.Fatalf("attempt linkage providers=%d artifact_tools=%d execution_attempts=%d", providerAttempts, artifactTools, executionAttempts)
		}
	})

	t.Run("same P duplicate and ToolRun ID collision leave no mutation", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "provider-retry-duplicates", "probe.http")
		admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
		step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
		makeRetryableResult(&step, &result)
		applyScheduledProviderAdmission(tool, &result, admission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission); err != nil {
			t.Fatal(err)
		}

		duplicateStep, duplicateTool, duplicateArtifacts, duplicateResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
		applyScheduledProviderAdmission(duplicateTool, &duplicateResult, admission)
		before := resultFenceSnapshot(t, fixture)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, duplicateStep, duplicateTool, duplicateArtifacts, duplicateResult, admission); !errors.Is(err, ErrStaleScheduledExecutionResult) {
			t.Fatalf("same-P duplicate error=%v", err)
		}
		if after := resultFenceSnapshot(t, fixture); after != before {
			t.Fatalf("same-P duplicate mutated database\nbefore=%s\nafter=%s", before, after)
		}

		collisionAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 2), nil, "fixture-provider")
		collisionStep, collisionTool, collisionArtifacts, collisionResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
		collisionTool.ID = tool.ID
		for index := range collisionArtifacts {
			collisionArtifacts[index].ToolRunID = collisionTool.ID
		}
		applyScheduledProviderAdmission(collisionTool, &collisionResult, collisionAdmission)
		before = resultFenceSnapshot(t, fixture)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, collisionStep, collisionTool, collisionArtifacts, collisionResult, collisionAdmission); !errors.Is(err, ErrStaleScheduledExecutionResult) {
			t.Fatalf("ToolRun collision error=%v", err)
		}
		if after := resultFenceSnapshot(t, fixture); after != before {
			t.Fatalf("ToolRun collision mutated database\nbefore=%s\nafter=%s", before, after)
		}
	})

	t.Run("P already used by another StepRun is a scheduled result conflict", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "provider-retry-cross-step-provider-attempt", "probe.http")
		admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
		foreignStepID := domain.NewID()
		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,attempt_count,input,started_at,idempotency_key)
			VALUES($1,$2,'foreign-provider','probe.http','running',1,'{}',clock_timestamp(),$3)`, foreignStepID, fixture.lineage.runID, string(domain.NewID())); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,tool_version,sanitized_arguments,execution_environment,started_at,provider_attempt_id)
			VALUES($1,$2,'probe.http','fixture-provider','1','{}','{}',clock_timestamp(),$3)`, domain.NewID(), foreignStepID, admission.ProviderAttemptID); err != nil {
			t.Fatal(err)
		}

		step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
		applyScheduledProviderAdmission(tool, &result, admission)
		before := resultFenceSnapshot(t, fixture)
		var toolCountBefore int
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT count(*) FROM tool_runs`).Scan(&toolCountBefore); err != nil {
			t.Fatal(err)
		}
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission); !errors.Is(err, ErrStaleScheduledExecutionResult) {
			t.Fatalf("cross-Step P collision error=%v", err)
		}
		if after := resultFenceSnapshot(t, fixture); after != before {
			t.Fatalf("cross-Step P collision mutated database\nbefore=%s\nafter=%s", before, after)
		}
		var toolCountAfter int
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT count(*) FROM tool_runs`).Scan(&toolCountAfter); err != nil {
			t.Fatal(err)
		}
		if toolCountAfter != toolCountBefore {
			t.Fatalf("cross-Step P collision tool count=%d want=%d", toolCountAfter, toolCountBefore)
		}
	})

	t.Run("P1 retryable followed by P2 retryable preserves an open StepRun", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "provider-retry-retryable", "probe.http")
		firstOutput := json.RawMessage(`{"lines":["http://127.0.0.1/first"],"authorized":["http://127.0.0.1/first"],"filtered":[{"target":"http://127.0.0.1/blocked-first","reason":"matched_exclusion"}]}`)
		firstAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
		firstStep, firstTool, firstArtifacts, firstResult := scheduledResultPayload(fixture, firstOutput)
		makeRetryableResult(&firstStep, &firstResult)
		applyScheduledProviderAdmission(firstTool, &firstResult, firstAdmission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, firstStep, firstTool, firstArtifacts, firstResult, firstAdmission); err != nil {
			t.Fatal(err)
		}

		secondOutput := json.RawMessage(`{"lines":["http://127.0.0.1/second"],"authorized":["http://127.0.0.1/second"],"filtered":[{"target":"http://127.0.0.1/blocked-second","reason":"matched_exclusion"}]}`)
		secondAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 2), nil, "fixture-provider")
		secondStep, secondTool, secondArtifacts, secondResult := scheduledResultPayload(fixture, secondOutput)
		makeRetryableResult(&secondStep, &secondResult)
		applyScheduledProviderAdmission(secondTool, &secondResult, secondAdmission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, secondStep, secondTool, secondArtifacts, secondResult, secondAdmission); err != nil {
			t.Fatal(err)
		}

		assertPersistedStepState(t, fixture, domain.StepRetryable, 2, false)
		assertResultRowCounts(t, fixture, 2, 2, 0, 0, 2)
		assertAttemptEvidence(t, fixture, 2)
		assertNoSuccessOnlyDerivedData(t, fixture)
		if firstTool.ID == secondTool.ID || firstAdmission.ProviderAttemptID == secondAdmission.ProviderAttemptID {
			t.Fatal("retryable provider attempts did not retain distinct identities")
		}
	})

	t.Run("P1 retryable followed by P2 terminal failure closes the StepRun", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "provider-retry-terminal-failure", "probe.http")
		firstOutput := json.RawMessage(`{"lines":["http://127.0.0.1/first"],"authorized":["http://127.0.0.1/first"],"filtered":[{"target":"http://127.0.0.1/blocked-first","reason":"matched_exclusion"}]}`)
		firstAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
		firstStep, firstTool, firstArtifacts, firstResult := scheduledResultPayload(fixture, firstOutput)
		makeRetryableResult(&firstStep, &firstResult)
		applyScheduledProviderAdmission(firstTool, &firstResult, firstAdmission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, firstStep, firstTool, firstArtifacts, firstResult, firstAdmission); err != nil {
			t.Fatal(err)
		}

		secondOutput := json.RawMessage(`{"lines":["http://127.0.0.1/second"],"authorized":["http://127.0.0.1/second"],"filtered":[{"target":"http://127.0.0.1/blocked-second","reason":"matched_exclusion"}]}`)
		secondAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 2), nil, "fixture-provider")
		secondStep, secondTool, secondArtifacts, secondResult := scheduledResultPayload(fixture, secondOutput)
		makeTerminalFailedResult(&secondStep, &secondResult)
		applyScheduledProviderAdmission(secondTool, &secondResult, secondAdmission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, secondStep, secondTool, secondArtifacts, secondResult, secondAdmission); err != nil {
			t.Fatal(err)
		}

		assertPersistedStepState(t, fixture, domain.StepFailed, 2, true)
		assertResultRowCounts(t, fixture, 2, 2, 0, 0, 2)
		assertAttemptEvidence(t, fixture, 2)
		assertNoSuccessOnlyDerivedData(t, fixture)
		if firstTool.ID == secondTool.ID || firstAdmission.ProviderAttemptID == secondAdmission.ProviderAttemptID {
			t.Fatal("failed provider attempts did not retain distinct identities")
		}

		lateAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 3), nil, "fixture-provider")
		lateStep, lateTool, lateArtifacts, lateResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
		applyScheduledProviderAdmission(lateTool, &lateResult, lateAdmission)
		before := resultFenceSnapshot(t, fixture)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, lateStep, lateTool, lateArtifacts, lateResult, lateAdmission); !errors.Is(err, ErrStaleScheduledExecutionResult) {
			t.Fatalf("late result after terminal failure error=%v", err)
		}
		if after := resultFenceSnapshot(t, fixture); after != before {
			t.Fatalf("late result after terminal failure mutated database\nbefore=%s\nafter=%s", before, after)
		}
		assertAttemptEvidence(t, fixture, 2)
	})

	t.Run("different P with equal A is admitted without increment", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "provider-retry-equal-attempt", "probe.http")
		firstAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
		firstStep, firstTool, firstArtifacts, firstResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
		makeRetryableResult(&firstStep, &firstResult)
		applyScheduledProviderAdmission(firstTool, &firstResult, firstAdmission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, firstStep, firstTool, firstArtifacts, firstResult, firstAdmission); err != nil {
			t.Fatal(err)
		}
		secondAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
		secondStep, secondTool, secondArtifacts, secondResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
		applyScheduledProviderAdmission(secondTool, &secondResult, secondAdmission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, secondStep, secondTool, secondArtifacts, secondResult, secondAdmission); err != nil {
			t.Fatal(err)
		}
		assertPersistedStepState(t, fixture, domain.StepSucceeded, 1, true)
		assertResultRowCounts(t, fixture, 2, 2, 0, 0, 2)
	})

	t.Run("lower A rejects and null A preserves stored attempt count", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "provider-retry-attempt-order", "probe.http")
		firstAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 2), nil, "fixture-provider")
		firstStep, firstTool, firstArtifacts, firstResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
		makeRetryableResult(&firstStep, &firstResult)
		applyScheduledProviderAdmission(firstTool, &firstResult, firstAdmission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, firstStep, firstTool, firstArtifacts, firstResult, firstAdmission); err != nil {
			t.Fatal(err)
		}
		assertPersistedStepState(t, fixture, domain.StepRetryable, 2, false)

		staleAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
		staleStep, staleTool, staleArtifacts, staleResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
		applyScheduledProviderAdmission(staleTool, &staleResult, staleAdmission)
		before := resultFenceSnapshot(t, fixture)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, staleStep, staleTool, staleArtifacts, staleResult, staleAdmission); !errors.Is(err, ErrStaleScheduledExecutionResult) {
			t.Fatalf("lower attempt error=%v", err)
		}
		if after := resultFenceSnapshot(t, fixture); after != before {
			t.Fatalf("lower attempt mutated database\nbefore=%s\nafter=%s", before, after)
		}

		nullFixture := newScheduledResultFixture(t, "provider-retry-null-attempt", "probe.http")
		if _, err := nullFixture.env.store.Pool.Exec(nullFixture.env.ctx, `UPDATE step_runs SET attempt_count=3 WHERE id=$1`, nullFixture.stepID); err != nil {
			t.Fatal(err)
		}
		nullAdmission := recordScheduledProviderAdmission(t, nullFixture, nullFixture.context(), nullFixture.env.programID, scheduledProviderAction(nullFixture, 0), nil, "fixture-provider")
		nullStep, nullTool, nullArtifacts, nullResult := scheduledResultPayload(nullFixture, json.RawMessage(`{"lines":[]}`))
		makeRetryableResult(&nullStep, &nullResult)
		applyScheduledProviderAdmission(nullTool, &nullResult, nullAdmission)
		if err := nullFixture.env.store.PersistResult(nullFixture.context(), nullFixture.env.programID, nullStep, nullTool, nullArtifacts, nullResult, nullAdmission); err != nil {
			t.Fatal(err)
		}
		assertPersistedStepState(t, nullFixture, domain.StepRetryable, 3, false)
	})

	t.Run("legacy null P remains strict and cannot mix", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "provider-retry-legacy-first", "probe.http")
		legacyStep, legacyTool, legacyArtifacts, legacyResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
		makeRetryableResult(&legacyStep, &legacyResult)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, legacyStep, legacyTool, legacyArtifacts, legacyResult, nil); err != nil {
			t.Fatal(err)
		}
		var legacyDecisions int
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type IN ('provider_result_accepted','provider_result_rejected')`, fixture.stepID).Scan(&legacyDecisions); err != nil {
			t.Fatal(err)
		}
		if legacyDecisions != 0 {
			t.Fatalf("legacy null-P decisions=%d want=0", legacyDecisions)
		}
		exactAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 2), nil, "fixture-provider")
		exactStep, exactTool, exactArtifacts, exactResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
		applyScheduledProviderAdmission(exactTool, &exactResult, exactAdmission)
		before := resultFenceSnapshot(t, fixture)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, exactStep, exactTool, exactArtifacts, exactResult, exactAdmission); !errors.Is(err, ErrStaleScheduledExecutionResult) {
			t.Fatalf("exact P mixed with legacy error=%v", err)
		}
		if after := resultFenceSnapshot(t, fixture); after != before {
			t.Fatalf("exact P mixed with legacy mutated database\nbefore=%s\nafter=%s", before, after)
		}

		exactFixture := newScheduledResultFixture(t, "provider-retry-exact-first", "probe.http")
		firstAdmission := recordScheduledProviderAdmission(t, exactFixture, exactFixture.context(), exactFixture.env.programID, scheduledProviderAction(exactFixture, 1), nil, "fixture-provider")
		firstStep, firstTool, firstArtifacts, firstResult := scheduledResultPayload(exactFixture, json.RawMessage(`{"lines":[]}`))
		makeRetryableResult(&firstStep, &firstResult)
		applyScheduledProviderAdmission(firstTool, &firstResult, firstAdmission)
		if err := exactFixture.env.store.PersistResult(exactFixture.context(), exactFixture.env.programID, firstStep, firstTool, firstArtifacts, firstResult, firstAdmission); err != nil {
			t.Fatal(err)
		}
		lateLegacyStep, lateLegacyTool, lateLegacyArtifacts, lateLegacyResult := scheduledResultPayload(exactFixture, json.RawMessage(`{"lines":[]}`))
		before = resultFenceSnapshot(t, exactFixture)
		if err := exactFixture.env.store.PersistResult(exactFixture.context(), exactFixture.env.programID, lateLegacyStep, lateLegacyTool, lateLegacyArtifacts, lateLegacyResult, nil); !errors.Is(err, ErrStaleScheduledExecutionResult) {
			t.Fatalf("legacy P reopened retryable error=%v", err)
		}
		if after := resultFenceSnapshot(t, exactFixture); after != before {
			t.Fatalf("legacy P reopened retryable mutated database\nbefore=%s\nafter=%s", before, after)
		}
	})

	t.Run("terminal StepRun rejects later new P", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "provider-retry-terminal", "probe.http")
		firstAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
		firstStep, firstTool, firstArtifacts, firstResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
		applyScheduledProviderAdmission(firstTool, &firstResult, firstAdmission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, firstStep, firstTool, firstArtifacts, firstResult, firstAdmission); err != nil {
			t.Fatal(err)
		}
		lateAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 2), nil, "fixture-provider")
		lateStep, lateTool, lateArtifacts, lateResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
		applyScheduledProviderAdmission(lateTool, &lateResult, lateAdmission)
		before := resultFenceSnapshot(t, fixture)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, lateStep, lateTool, lateArtifacts, lateResult, lateAdmission); !errors.Is(err, ErrStaleScheduledExecutionResult) {
			t.Fatalf("late terminal result error=%v", err)
		}
		if after := resultFenceSnapshot(t, fixture); after != before {
			t.Fatalf("late terminal result mutated database\nbefore=%s\nafter=%s", before, after)
		}
	})
}

func TestConcurrentDistinctProviderAttemptsFromRetryableSerialize(t *testing.T) {
	fixture := newScheduledResultFixture(t, "provider-retry-concurrent", "probe.http")
	firstAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
	firstStep, firstTool, firstArtifacts, firstResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":[]}`))
	makeRetryableResult(&firstStep, &firstResult)
	applyScheduledProviderAdmission(firstTool, &firstResult, firstAdmission)
	if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, firstStep, firstTool, firstArtifacts, firstResult, firstAdmission); err != nil {
		t.Fatal(err)
	}

	type candidate struct {
		step      domain.StepRun
		tool      *domain.ToolRun
		artifacts []domain.Artifact
		result    domain.ActionResult
		admission *capability.ResultAdmissionProvenance
	}
	candidates := make([]candidate, 0, 2)
	for index := range 2 {
		admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 2), nil, "fixture-provider")
		step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(fmt.Sprintf(`{"lines":["http://127.0.0.1/%d"]}`, index)))
		applyScheduledProviderAdmission(tool, &result, admission)
		candidates = append(candidates, candidate{step: step, tool: tool, artifacts: artifacts, result: result, admission: admission})
	}
	runCtx, cancel := context.WithTimeout(fixture.context(), 8*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, item := range candidates {
		item := item
		go func() {
			<-start
			results <- fixture.env.store.PersistResult(runCtx, fixture.env.programID, item.step, item.tool, item.artifacts, item.result, item.admission)
		}()
	}
	close(start)
	succeeded, rejected := 0, 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrStaleScheduledExecutionResult):
			rejected++
		default:
			t.Fatalf("concurrent result error=%v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent outcomes succeeded=%d rejected=%d", succeeded, rejected)
	}
	assertPersistedStepState(t, fixture, domain.StepSucceeded, 2, true)
	assertResultRowCounts(t, fixture, 2, 2, 1, 0, 2)
	assertAttemptEvidence(t, fixture, 2)
	var rejectedDecisions int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type='provider_result_rejected'`, fixture.stepID).Scan(&rejectedDecisions); err != nil {
		t.Fatal(err)
	}
	if rejectedDecisions != 1 {
		t.Fatalf("concurrent distinct-P rejected decisions=%d want=1", rejectedDecisions)
	}
}

func TestProviderResultConcurrentGlobalIdentityCollisions(t *testing.T) {
	for _, test := range []struct {
		name         string
		reason       resultFenceReasonCode
		queryPattern string
		apply        func(domain.ID, *providerResultCollisionCandidate)
	}{
		{
			name:         "ToolRun ID",
			reason:       resultFenceToolResultConflict,
			queryPattern: `%INSERT INTO tool_runs(id,step_run_id,%`,
			apply: func(sharedID domain.ID, candidate *providerResultCollisionCandidate) {
				candidate.tool.ID = sharedID
				for index := range candidate.artifacts {
					candidate.artifacts[index].ToolRunID = sharedID
				}
			},
		},
		{
			name:         "artifact ID",
			reason:       resultFenceArtifactResultConflict,
			queryPattern: `%INSERT INTO artifacts(id,task_id,%`,
			apply: func(sharedID domain.ID, candidate *providerResultCollisionCandidate) {
				candidate.artifacts[0].ID = sharedID
				candidate.result.ArtifactIDs[0] = sharedID
				candidate.tool.StdoutArtifactID = &candidate.artifacts[0].ID
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			env := newRecoveryTestEnvironment(t, "provider-result-concurrent-"+strings.ReplaceAll(test.name, " ", "-"))
			installResultIdentityInsertBarrier(t, env)
			secondProgramID, secondDefinitionID := createSchedulerIntegrationProgram(t, env.ctx, env.store, "provider-result-concurrent-second-program-"+strings.ReplaceAll(test.name, " ", "-"))
			environments := []recoveryTestEnvironment{
				env,
				{store: env.store, ctx: env.ctx, programID: secondProgramID, definitionID: secondDefinitionID},
			}
			sharedID := domain.NewID()
			candidates := make([]providerResultCollisionCandidate, 0, 2)
			for index, fixtureEnv := range environments {
				fixture := newScheduledResultFixtureInEnvironment(t, fixtureEnv, fmt.Sprintf("provider-result-concurrent-%s-%d", strings.ReplaceAll(test.name, " ", "-"), index), "probe.http")
				action := scheduledProviderAction(fixture, 1)
				admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, nil, "fixture-provider")
				output := json.RawMessage(fmt.Sprintf(`{"lines":["http://127.0.0.1/%d"],"authorized_records":[{"provider":"httpx","kind":"url","target":"http://127.0.0.1/%d","status_code":200}]}`, index, index))
				step, tool, artifacts, result := scheduledResultPayload(fixture, output)
				applyScheduledProviderAdmission(tool, &result, admission)
				candidate := providerResultCollisionCandidate{fixture: fixture, action: action, admission: admission, step: step, tool: tool, artifacts: artifacts, result: result}
				test.apply(sharedID, &candidate)
				candidate.before = resultFenceSnapshot(t, fixture)
				candidates = append(candidates, candidate)
			}

			release := holdResultIdentityInsertBarrier(t, env, sharedID)
			defer release()
			runCtx, cancel := context.WithTimeout(env.ctx, 10*time.Second)
			defer cancel()
			results := [2]chan error{make(chan error, 1), make(chan error, 1)}
			for index := range candidates {
				index := index
				go func() {
					candidate := candidates[index]
					ctx := WithScheduledExecutionFence(runCtx, candidate.fixture.fence)
					results[index] <- env.store.PersistResult(ctx, candidate.fixture.env.programID, candidate.step, candidate.tool, candidate.artifacts, candidate.result, candidate.admission)
				}()
			}
			waitForConcurrentResultInsertQueries(t, runCtx, env.store, results[0], results[1], test.queryPattern)
			release()

			errorsByCandidate := [2]error{}
			for index := range errorsByCandidate {
				select {
				case errorsByCandidate[index] = <-results[index]:
				case <-runCtx.Done():
					t.Fatalf("concurrent identity results did not finish: %v", runCtx.Err())
				}
			}
			winner, loser := collisionOutcomeIndexes(t, errorsByCandidate, test.reason)
			assertProviderResultCollisionOutcome(t, candidates[winner], candidates[loser], test.reason)
		})
	}
}

func collisionOutcomeIndexes(t *testing.T, outcomes [2]error, reason resultFenceReasonCode) (int, int) {
	t.Helper()
	winner, loser := -1, -1
	for index, err := range outcomes {
		if err == nil {
			if winner != -1 {
				t.Fatalf("concurrent identity collision produced multiple winners: %v", outcomes)
			}
			winner = index
			continue
		}
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			t.Fatalf("concurrent identity collision escaped as PostgreSQL 23505: %v", err)
		}
		rejection, semantic := resultFenceRejection(err)
		if !errors.Is(err, ErrStaleScheduledExecutionResult) || !semantic || rejection.reason != reason {
			t.Fatalf("concurrent identity rejection=%v reason=%v want=%v", err, rejection, reason)
		}
		if loser != -1 {
			t.Fatalf("concurrent identity collision produced multiple rejections: %v", outcomes)
		}
		loser = index
	}
	if winner == -1 || loser == -1 {
		t.Fatalf("concurrent identity outcomes=%v want one winner and one rejection", outcomes)
	}
	return winner, loser
}

func assertProviderResultCollisionOutcome(t *testing.T, winner, loser providerResultCollisionCandidate, reason resultFenceReasonCode) {
	t.Helper()
	if after := resultFenceSnapshot(t, loser.fixture); after != loser.before {
		t.Fatalf("losing identity-collision transaction mutated result state\nbefore=%s\nafter=%s", loser.before, after)
	}
	assertPersistedStepState(t, winner.fixture, domain.StepSucceeded, 1, true)
	assertStepRecoveryStatus(t, loser.fixture.env, loser.fixture.stepID, domain.StepRunning)
	assertResultRowCounts(t, winner.fixture, 1, 1, 1, 0, 1)
	assertResultRowCounts(t, loser.fixture, 0, 0, 0, 0, 0)
	assertProviderResultDecisionCount(t, winner.fixture, winner.admission.ProviderAttemptID, "provider_result_accepted", "", 1)
	assertProviderResultDecisionCount(t, winner.fixture, winner.admission.ProviderAttemptID, "provider_result_rejected", string(reason), 0)
	assertProviderResultDecisionCount(t, loser.fixture, loser.admission.ProviderAttemptID, "provider_result_accepted", "", 0)
	assertProviderResultDecisionCount(t, loser.fixture, loser.admission.ProviderAttemptID, "provider_result_rejected", string(reason), 1)
	decision := loadProviderResultDecision(t, loser.fixture, "provider_result_rejected", loser.admission.ProviderAttemptID, string(reason))
	assertProviderResultDecisionProvenance(t, decision, providerResultDecisionExpectation{
		Actor:                         loser.action.RequestedBy,
		TaskID:                        loser.fixture.lineage.task.ID,
		ProgramID:                     loser.fixture.env.programID,
		WorkflowRunID:                 loser.fixture.lineage.runID,
		StepRunID:                     loser.fixture.stepID,
		ScheduledExecutionID:          loser.fixture.lineage.execution.ID,
		SchedulerAttempt:              loser.fixture.fence.Attempt,
		ActionRequestID:               loser.action.ID,
		StepAttempt:                   loser.action.StepAttempt,
		ExecutionAuthorizationEventID: loser.admission.ExecutionAuthorizationEventID,
		ProviderAttemptID:             loser.admission.ProviderAttemptID,
		Capability:                    loser.fixture.capability,
		Provider:                      loser.admission.Provider,
		SafeMessage:                   "provider result rejected by persistence fence",
		Details:                       `{"reason_code": "` + string(reason) + `"}`,
	})
}

func TestScheduledWorkflowSaveFence(t *testing.T) {
	t.Run("current scheduled attempt saves", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "save-current", "probe.http")
		state := scheduledFixtureState(fixture, domain.RunRunning, domain.StepRunning)
		if err := fixture.env.store.SaveWorkflowState(fixture.context(), state); err != nil {
			t.Fatal(err)
		}
	})

	for _, test := range []struct {
		name    string
		prepare func(scheduledResultFixture)
		ctx     func(scheduledResultFixture) context.Context
	}{
		{name: "expired lease", prepare: func(f scheduledResultFixture) { expireRecoveryLease(t, f.env, f.lineage.execution.ID, 1) }, ctx: func(f scheduledResultFixture) context.Context { return f.context() }},
		{name: "wrong owner", prepare: func(scheduledResultFixture) {}, ctx: func(f scheduledResultFixture) context.Context {
			fence := f.fence
			fence.LeaseOwner = "wrong"
			return WithScheduledExecutionFence(f.env.ctx, fence)
		}},
		{name: "wrong attempt", prepare: func(scheduledResultFixture) {}, ctx: func(f scheduledResultFixture) context.Context {
			fence := f.fence
			fence.Attempt++
			return WithScheduledExecutionFence(f.env.ctx, fence)
		}},
		{name: "missing claim fence", prepare: func(scheduledResultFixture) {}, ctx: func(f scheduledResultFixture) context.Context { return f.env.ctx }},
		{name: "reconciled execution", prepare: func(f scheduledResultFixture) {
			expireRecoveryLease(t, f.env, f.lineage.execution.ID, 1)
			reconcileRecovery(t, f.env)
		}, ctx: func(f scheduledResultFixture) context.Context { return f.context() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "save-"+strings.ReplaceAll(test.name, " ", "-"), "probe.http")
			test.prepare(fixture)
			before := resultFenceSnapshot(t, fixture)
			err := fixture.env.store.SaveWorkflowState(test.ctx(fixture), scheduledFixtureState(fixture, domain.RunCompleted, domain.StepSucceeded))
			if !errors.Is(err, ErrLostScheduledExecutionLease) {
				t.Fatalf("save error=%v want %v", err, ErrLostScheduledExecutionLease)
			}
			after := resultFenceSnapshot(t, fixture)
			if after != before {
				t.Fatalf("rejected workflow save mutated database\nbefore=%s\nafter=%s", before, after)
			}
		})
	}

	t.Run("unscheduled workflow save and result remain supported", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "result-unscheduled")
		now := time.Now().UTC()
		task := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "unscheduled")
		runID, stepID := domain.NewID(), domain.NewID()
		key := "unscheduled-idempotency"
		state := &workflow.State{Run: domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: env.definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{"provider": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "provider", Capability: "probe.http", Status: domain.StepRunning, AttemptCount: 1, Input: json.RawMessage(`{}`), StartedAt: &now, IdempotencyKey: key, ApprovalState: "not_required"}}}}
		if err := env.store.SaveWorkflowState(env.ctx, state); err != nil {
			t.Fatal(err)
		}
		fixture := scheduledResultFixture{env: env, lineage: recoveryTestFixture{task: task, runID: runID}, stepID: stepID, idempotencyKey: key, capability: "probe.http"}
		step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":["http://127.0.0.1/"]}`))
		if err := env.store.PersistResult(env.ctx, env.programID, step, tool, artifacts, result, nil); err != nil {
			t.Fatal(err)
		}
		assertStepRecoveryStatus(t, env, stepID, domain.StepSucceeded)
		var toolCount int
		if err := env.store.Pool.QueryRow(env.ctx, `SELECT count(*) FROM tool_runs WHERE step_run_id=$1`, stepID).Scan(&toolCount); err != nil || toolCount != 1 {
			t.Fatalf("unscheduled tool count=%d err=%v", toolCount, err)
		}
	})

	t.Run("unscheduled result identity conflicts remain strict", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "result-unscheduled-conflict")
		now := time.Now().UTC()
		task := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "unscheduled-conflict")
		runID, stepID := domain.NewID(), domain.NewID()
		state := &workflow.State{
			Run:   domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: env.definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration", Summary: json.RawMessage(`{}`)},
			Steps: map[string]*workflow.StepState{"provider": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "provider", Capability: "probe.http", Status: domain.StepRunning, AttemptCount: 1, Input: json.RawMessage(`{}`), StartedAt: &now, IdempotencyKey: "unscheduled-conflict-key", ApprovalState: "not_required"}}},
		}
		if err := env.store.SaveWorkflowState(env.ctx, state); err != nil {
			t.Fatal(err)
		}
		fixture := scheduledResultFixture{env: env, lineage: recoveryTestFixture{task: task, runID: runID}, stepID: stepID, idempotencyKey: "unscheduled-conflict-key", capability: "probe.http"}
		step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":["http://127.0.0.1/"]}`))
		step.IdempotencyKey = "wrong-key"
		if err := env.store.PersistResult(env.ctx, env.programID, step, tool, artifacts, result, nil); !errors.Is(err, ErrWorkflowResultConflict) {
			t.Fatalf("unscheduled identity error=%v want %v", err, ErrWorkflowResultConflict)
		}
		assertStepRecoveryStatus(t, env, stepID, domain.StepRunning)
		assertResultRowCounts(t, fixture, 0, 0, 0, 0, 0)
	})
}

func TestPersistResultRecoveryConcurrency(t *testing.T) {
	t.Run("result locks first and recovery preserves the accepted terminal evidence", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-race-result-first", "scan.nuclei")
		installPersistResultStepBarrier(t, fixture.env)
		release := holdPersistResultStepBarrier(t, fixture.env, fixture.stepID)
		defer release()

		raceCtx, cancel := context.WithTimeout(fixture.context(), 15*time.Second)
		defer cancel()
		step, tool, artifacts, result := fixture.validPayload()
		persisted := make(chan error, 1)
		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE scheduled_executions SET lease_expires_at=clock_timestamp()+interval '3 seconds' WHERE id=$1`, fixture.lineage.execution.ID); err != nil {
			t.Fatal(err)
		}
		go func() {
			persisted <- fixture.env.store.PersistResult(raceCtx, fixture.env.programID, step, tool, artifacts, result, nil)
		}()
		waitForPostgresLockOrResult(t, raceCtx, fixture.env.store, persisted, `%UPDATE step_runs%SET status=%`)
		waitForScheduledLeaseExpiry(t, raceCtx, fixture)

		recovered := make(chan error, 1)
		go func() {
			recovered <- fixture.env.store.reconcileStaleScheduledExecutions(raceCtx, 1)
		}()
		select {
		case err := <-recovered:
			if err != nil {
				t.Fatal(err)
			}
		case <-raceCtx.Done():
			t.Fatalf("recovery deadlocked behind result persistence: %v", raceCtx.Err())
		}
		assertScheduledRecoveryStatusAndClass(t, fixture.env, fixture.lineage.execution.ID, domain.ScheduledExecutionRunning, "")

		release()
		select {
		case err := <-persisted:
			if err != nil {
				t.Fatal(err)
			}
		case <-raceCtx.Done():
			t.Fatalf("result persistence did not finish: %v", raceCtx.Err())
		}
		assertResultRowCounts(t, fixture, 1, 1, 0, 1, 1)

		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE scheduled_executions SET lease_expires_at=clock_timestamp()+interval '1 minute' WHERE id=$1`, fixture.lineage.execution.ID); err != nil {
			t.Fatal(err)
		}
		if err := fixture.env.store.SaveWorkflowState(fixture.context(), scheduledFixtureState(fixture, domain.RunCompleted, domain.StepSucceeded)); err != nil {
			t.Fatal(err)
		}
		expireRecoveryLease(t, fixture.env, fixture.lineage.execution.ID, 1)
		reconcileRecovery(t, fixture.env)
		assertScheduledRecoveryStatusAndClass(t, fixture.env, fixture.lineage.execution.ID, domain.ScheduledExecutionCompleted, "")
		assertTaskRecoveryStatus(t, fixture.env, fixture.lineage.task.ID, domain.TaskCompleted)
		assertWorkflowRecoveryStatus(t, fixture.env, fixture.lineage.runID, domain.RunCompleted)
		assertStepRecoveryStatus(t, fixture.env, fixture.stepID, domain.StepSucceeded)
		assertResultRowCounts(t, fixture, 1, 1, 0, 1, 1)
		assertRecoveryAuditCount(t, fixture.env, fixture.lineage.execution.ID, "scheduled_execution_terminal_reconciled", 1)
	})

	t.Run("recovery locks first and the late result rejects", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "result-race-recovery-first", "scan.nuclei")
		expireRecoveryLease(t, fixture.env, fixture.lineage.execution.ID, 1)
		tx, err := fixture.env.store.Pool.Begin(fixture.env.ctx)
		if err != nil {
			t.Fatal(err)
		}
		committed := false
		defer func() {
			if !committed {
				_ = tx.Rollback(context.Background())
			}
		}()
		entry, found, err := lockNextStaleScheduledExecution(fixture.env.ctx, tx, nil)
		if err != nil || !found || entry.item.ID != fixture.lineage.execution.ID {
			t.Fatalf("locked recovery entry=%#v found=%v err=%v", entry, found, err)
		}

		raceCtx, cancel := context.WithTimeout(fixture.context(), 8*time.Second)
		defer cancel()
		step, tool, artifacts, result := fixture.validPayload()
		persisted := make(chan error, 1)
		go func() {
			persisted <- fixture.env.store.PersistResult(raceCtx, fixture.env.programID, step, tool, artifacts, result, nil)
		}()
		waitForPostgresLock(t, raceCtx, fixture.env.store, `%WHERE se.id=$1%FOR UPDATE OF se%`)

		lineage, locked, err := lockScheduledExecutionLineage(fixture.env.ctx, tx, entry)
		if err != nil || !locked {
			t.Fatalf("lock recovery lineage locked=%v err=%v", locked, err)
		}
		if err := applyStaleLineageReconciliation(fixture.env.ctx, tx, entry, lineage, classifyStaleLineage(entry, &lineage)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(fixture.env.ctx); err != nil {
			t.Fatal(err)
		}
		committed = true
		select {
		case err := <-persisted:
			if !errors.Is(err, ErrStaleScheduledExecutionResult) {
				t.Fatalf("late result error=%v want %v", err, ErrStaleScheduledExecutionResult)
			}
		case <-raceCtx.Done():
			t.Fatalf("late result did not finish after recovery: %v", raceCtx.Err())
		}
		assertScheduledRecoveryStatusAndClass(t, fixture.env, fixture.lineage.execution.ID, domain.ScheduledExecutionInterrupted, "interrupted")
		assertTaskRecoveryStatus(t, fixture.env, fixture.lineage.task.ID, domain.TaskFailed)
		assertWorkflowRecoveryStatus(t, fixture.env, fixture.lineage.runID, domain.RunFailed)
		assertStepRecoveryStatus(t, fixture.env, fixture.stepID, domain.StepFailed)
		assertResultRowCounts(t, fixture, 0, 0, 0, 0, 0)
		assertRecoveryAuditCount(t, fixture.env, fixture.lineage.execution.ID, "scheduled_execution_lineage_interrupted", 1)
	})
}

func TestConcurrentDuplicatePersistResult(t *testing.T) {
	fixture := newScheduledResultFixture(t, "result-race-duplicate", "probe.http")
	output := json.RawMessage(`{"lines":["http://127.0.0.1/"],"authorized_records":[{"provider":"httpx","kind":"url","target":"http://127.0.0.1/","status_code":200}]}`)
	step, tool, artifacts, result := scheduledResultPayload(fixture, output)
	raceCtx, cancel := context.WithTimeout(fixture.context(), 8*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			select {
			case <-start:
				results <- fixture.env.store.PersistResult(raceCtx, fixture.env.programID, step, tool, artifacts, result, nil)
			case <-raceCtx.Done():
				results <- raceCtx.Err()
			}
		}()
	}
	close(start)
	succeeded, rejected := 0, 0
	for range 2 {
		select {
		case err := <-results:
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrStaleScheduledExecutionResult):
				rejected++
			default:
				t.Fatalf("duplicate result error=%v", err)
			}
		case <-raceCtx.Done():
			t.Fatalf("duplicate result calls did not finish: %v", raceCtx.Err())
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("duplicate result outcomes succeeded=%d rejected=%d", succeeded, rejected)
	}
	assertStepRecoveryStatus(t, fixture.env, fixture.stepID, domain.StepSucceeded)
	assertResultRowCounts(t, fixture, 1, 1, 1, 0, 1)
}

func newScheduledResultFixture(t *testing.T, name, capabilityName string) scheduledResultFixture {
	t.Helper()
	env := newRecoveryTestEnvironment(t, name)
	return newScheduledResultFixtureInEnvironment(t, env, name, capabilityName)
}

func newScheduledResultFixtureInEnvironment(t *testing.T, env recoveryTestEnvironment, name, capabilityName string) scheduledResultFixture {
	t.Helper()
	runStatus := domain.RunRunning
	lineage := createRecoveryFixture(t, env, name, &runStatus, domain.TaskRunning, []recoveryStepSpec{{name: "provider", status: domain.StepRunning, started: true, attemptCount: 1}})
	stepID := lineage.steps["provider"]
	if _, err := env.store.Pool.Exec(env.ctx, `UPDATE step_runs SET capability=$2 WHERE id=$1`, stepID, capabilityName); err != nil {
		t.Fatal(err)
	}
	var key string
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT idempotency_key FROM step_runs WHERE id=$1`, stepID).Scan(&key); err != nil {
		t.Fatal(err)
	}
	return scheduledResultFixture{
		env: env, lineage: lineage, stepID: stepID, idempotencyKey: key, capability: capabilityName,
		fence: ScheduledExecutionFence{ExecutionID: lineage.execution.ID, LeaseOwner: lineage.execution.LeaseOwner, Attempt: lineage.execution.AttemptCount},
	}
}

func (fixture scheduledResultFixture) context() context.Context {
	return WithScheduledExecutionFence(fixture.env.ctx, fixture.fence)
}

func scheduledProviderAction(fixture scheduledResultFixture, stepAttempt int) domain.ActionRequest {
	return domain.ActionRequest{ID: domain.NewID(), TaskID: fixture.lineage.task.ID, WorkflowRunID: fixture.lineage.runID, StepRunID: fixture.stepID, RequestedBy: "integration-test", Capability: fixture.capability, IdempotencyKey: fixture.idempotencyKey, StepAttempt: stepAttempt, Input: json.RawMessage(`{}`)}
}

func recordScheduledProviderAdmission(t *testing.T, fixture scheduledResultFixture, ctx context.Context, programID domain.ID, action domain.ActionRequest, queueJobID *domain.ID, provider string) *capability.ResultAdmissionProvenance {
	t.Helper()
	authorizationID, err := fixture.env.store.RecordPolicyDecision(ctx, capability.PolicyDecisionRecord{ProgramID: programID, Action: action, QueueJobID: queueJobID, Provider: provider, PolicyID: "integration", Phase: "execution", Evaluation: policy.Evaluation{Decision: policy.Allow, Reason: "exact provider admission test"}})
	if err != nil {
		t.Fatal(err)
	}
	providerAttemptID, err := fixture.env.store.RecordProviderInvocationStarted(ctx, capability.ProviderInvocationStartRecord{ProgramID: programID, TaskID: action.TaskID, WorkflowRunID: action.WorkflowRunID, StepRunID: action.StepRunID, ActionRequestID: action.ID, StepAttempt: action.StepAttempt, QueueJobID: queueJobID, ExecutionAuthorizationEventID: authorizationID, Capability: action.Capability, Provider: provider, Actor: action.RequestedBy})
	if err != nil {
		t.Fatal(err)
	}
	var queueJobCopy *domain.ID
	if queueJobID != nil {
		id := *queueJobID
		queueJobCopy = &id
	}
	return &capability.ResultAdmissionProvenance{ProviderAttemptID: providerAttemptID, ActionRequestID: action.ID, StepAttempt: action.StepAttempt, QueueJobID: queueJobCopy, ExecutionAuthorizationEventID: authorizationID, Provider: provider}
}

func applyScheduledProviderAdmission(tool *domain.ToolRun, result *domain.ActionResult, admission *capability.ResultAdmissionProvenance) {
	providerAttemptID := admission.ProviderAttemptID
	tool.ProviderAttemptID = &providerAttemptID
	tool.Provider = admission.Provider
	result.RequestID = admission.ActionRequestID
}

func (fixture scheduledResultFixture) validPayload() (domain.StepRun, *domain.ToolRun, []domain.Artifact, domain.ActionResult) {
	line := `{"template-id":"harmless-info","matched-at":"http://127.0.0.1/","info":{"name":"Harmless local response","severity":"info"}}`
	output, _ := json.Marshal(map[string]any{"lines": []string{line}})
	return scheduledResultPayload(fixture, output)
}

func scheduledResultPayload(fixture scheduledResultFixture, output json.RawMessage) (domain.StepRun, *domain.ToolRun, []domain.Artifact, domain.ActionResult) {
	now := time.Now().UTC()
	toolID, artifactID := domain.NewID(), domain.NewID()
	exitCode := 0
	step := domain.StepRun{ID: fixture.stepID, WorkflowRunID: fixture.lineage.runID, Capability: fixture.capability, Status: domain.StepSucceeded, Output: output, CompletedAt: &now, IdempotencyKey: fixture.idempotencyKey}
	tool := &domain.ToolRun{ID: toolID, StepRunID: fixture.stepID, Capability: fixture.capability, Provider: "fixture", ToolVersion: "1", SanitizedArguments: json.RawMessage(`{}`), ExecutionEnvironment: json.RawMessage(`{"kind":"integration"}`), StartedAt: now.Add(-time.Second), CompletedAt: &now, ExitCode: &exitCode, StdoutArtifactID: &artifactID}
	artifacts := []domain.Artifact{{ID: artifactID, TaskID: fixture.lineage.task.ID, WorkflowRunID: fixture.lineage.runID, StepRunID: fixture.stepID, ToolRunID: toolID, Type: "normalized-result", ContentType: "application/json", Size: int64(len(output)), SHA256: strings.Repeat("a", 64), StorageLocation: "synthetic://result.json", CreatedAt: now, RedactionState: "redacted"}}
	result := domain.ActionResult{RequestID: domain.NewID(), Status: "succeeded", Summary: "fixture result succeeded", Output: output, ArtifactIDs: []domain.ID{artifactID}}
	return step, tool, artifacts, result
}

func makeRetryableResult(step *domain.StepRun, result *domain.ActionResult) {
	step.Status = domain.StepRetryable
	step.CompletedAt = nil
	step.ErrorClassification = "provider_error"
	step.ErrorDetails = "temporary provider failure"
	result.Status = "failed"
	result.Summary = "temporary provider failure"
	result.Error = &domain.StructuredError{Classification: step.ErrorClassification, Message: step.ErrorDetails, Retryable: true}
}

func makeTerminalFailedResult(step *domain.StepRun, result *domain.ActionResult) {
	now := time.Now().UTC()
	step.Status = domain.StepFailed
	step.CompletedAt = &now
	step.ErrorClassification = "provider_error"
	step.ErrorDetails = "terminal provider failure"
	result.Status = "failed"
	result.Summary = "terminal provider failure"
	result.Error = &domain.StructuredError{Classification: step.ErrorClassification, Message: step.ErrorDetails, Retryable: false}
}

func assertPersistedStepState(t *testing.T, fixture scheduledResultFixture, status domain.StepStatus, attemptCount int, completed bool) {
	t.Helper()
	var gotStatus domain.StepStatus
	var gotAttemptCount int
	var completedAt *time.Time
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT status,attempt_count,completed_at FROM step_runs WHERE id=$1`, fixture.stepID).Scan(&gotStatus, &gotAttemptCount, &completedAt); err != nil {
		t.Fatal(err)
	}
	if gotStatus != status || gotAttemptCount != attemptCount || (completedAt != nil) != completed {
		t.Fatalf("step status=%s attempt_count=%d completed_at=%v", gotStatus, gotAttemptCount, completedAt)
	}
}

func assertTargetDecisionCount(t *testing.T, fixture scheduledResultFixture, want int) {
	t.Helper()
	var count int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type IN ('target_accepted','target_filtered','exclusion_matched','protocol_or_port_rejected')`, fixture.stepID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("target decision events=%d want=%d", count, want)
	}
}

func assertAttemptEvidence(t *testing.T, fixture scheduledResultFixture, want int) {
	t.Helper()
	var tools, providerAttempts, artifacts, artifactTools, toolAudits, auditAttempts, auditTools, acceptedDecisions int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
		(SELECT count(*) FROM tool_runs WHERE step_run_id=$1),
		(SELECT count(DISTINCT provider_attempt_id) FROM tool_runs WHERE step_run_id=$1),
		(SELECT count(*) FROM artifacts WHERE step_run_id=$1),
		(SELECT count(DISTINCT tool_run_id) FROM artifacts WHERE step_run_id=$1),
		(SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type='tool_execution'),
		(SELECT count(DISTINCT provider_attempt_id) FROM audit_events WHERE step_run_id=$1 AND event_type='tool_execution'),
		(SELECT count(DISTINCT tool_run_id) FROM audit_events WHERE step_run_id=$1 AND event_type='tool_execution'),
		(SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type='provider_result_accepted')`, fixture.stepID).Scan(&tools, &providerAttempts, &artifacts, &artifactTools, &toolAudits, &auditAttempts, &auditTools, &acceptedDecisions); err != nil {
		t.Fatal(err)
	}
	if tools != want || providerAttempts != want || artifacts != want || artifactTools != want || toolAudits != want || auditAttempts != want || auditTools != want || acceptedDecisions != want {
		t.Fatalf("attempt evidence tools=%d provider_attempts=%d artifacts=%d artifact_tools=%d tool_audits=%d audit_attempts=%d audit_tools=%d accepted_decisions=%d want=%d", tools, providerAttempts, artifacts, artifactTools, toolAudits, auditAttempts, auditTools, acceptedDecisions, want)
	}
}

func assertNoSuccessOnlyDerivedData(t *testing.T, fixture scheduledResultFixture) {
	t.Helper()
	var observations, findings, changes, endpoints, targetDecisions int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
		(SELECT count(*) FROM asset_observations WHERE workflow_run_id=$1),
		(SELECT count(*) FROM candidate_findings WHERE workflow_run_id=$1),
		(SELECT count(*) FROM change_items WHERE workflow_run_id=$1),
		(SELECT count(*) FROM endpoints WHERE program_id=$2),
		(SELECT count(*) FROM audit_events WHERE step_run_id=$3 AND event_type IN ('target_accepted','target_filtered','exclusion_matched','protocol_or_port_rejected'))`, fixture.lineage.runID, fixture.env.programID, fixture.stepID).Scan(&observations, &findings, &changes, &endpoints, &targetDecisions); err != nil {
		t.Fatal(err)
	}
	if observations != 0 || findings != 0 || changes != 0 || endpoints != 0 || targetDecisions != 0 {
		t.Fatalf("success-only data observations=%d findings=%d changes=%d endpoints=%d target_decisions=%d", observations, findings, changes, endpoints, targetDecisions)
	}
}

func scheduledFixtureState(fixture scheduledResultFixture, runStatus domain.RunStatus, stepStatus domain.StepStatus) *workflow.State {
	now := time.Now().UTC()
	var runCompletedAt, stepCompletedAt *time.Time
	if recoveryRunTerminal(runStatus) {
		runCompletedAt = &now
	}
	if recoveryStepTerminal(stepStatus) {
		stepCompletedAt = &now
	}
	return &workflow.State{Run: domain.WorkflowRun{ID: fixture.lineage.runID, TaskID: fixture.lineage.task.ID, WorkflowDefinitionID: fixture.env.definitionID, WorkflowVersion: "1", Status: runStatus, StartedAt: &now, CompletedAt: runCompletedAt, TriggerSource: "run_now", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{"provider": {Run: domain.StepRun{ID: fixture.stepID, WorkflowRunID: fixture.lineage.runID, StepDefinitionID: "provider", Capability: fixture.capability, Status: stepStatus, AttemptCount: 1, Input: json.RawMessage(`{}`), Output: json.RawMessage(`{"preserved":true}`), StartedAt: &now, CompletedAt: stepCompletedAt, IdempotencyKey: fixture.idempotencyKey, ApprovalState: "not_required"}}}}
}

func assertScheduledResultRejectedNoMutation(t *testing.T, fixture scheduledResultFixture, ctx context.Context, step domain.StepRun, tool *domain.ToolRun, artifacts []domain.Artifact, result domain.ActionResult) {
	t.Helper()
	before := resultFenceSnapshot(t, fixture)
	err := fixture.env.store.PersistResult(ctx, fixture.env.programID, step, tool, artifacts, result, nil)
	if !errors.Is(err, ErrStaleScheduledExecutionResult) {
		t.Fatalf("persist result error=%v want %v", err, ErrStaleScheduledExecutionResult)
	}
	after := resultFenceSnapshot(t, fixture)
	if after != before {
		t.Fatalf("rejected result mutated database\nbefore=%s\nafter=%s", before, after)
	}
}

func assertScheduledValidResultRejectedNoMutation(t *testing.T, fixture scheduledResultFixture, ctx context.Context) {
	t.Helper()
	step, tool, artifacts, result := fixture.validPayload()
	assertScheduledResultRejectedNoMutation(t, fixture, ctx, step, tool, artifacts, result)
}

func installResultIdentityInsertBarrier(t *testing.T, env recoveryTestEnvironment) {
	t.Helper()
	if _, err := env.store.Pool.Exec(env.ctx, `CREATE FUNCTION result_identity_insert_barrier() RETURNS trigger AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(hashtext(NEW.id::text));
			RETURN NEW;
		END;
	$$ LANGUAGE plpgsql;
	CREATE TRIGGER result_tool_identity_insert_barrier BEFORE INSERT ON tool_runs FOR EACH ROW EXECUTE FUNCTION result_identity_insert_barrier();
	CREATE TRIGGER result_artifact_identity_insert_barrier BEFORE INSERT ON artifacts FOR EACH ROW EXECUTE FUNCTION result_identity_insert_barrier()`); err != nil {
		t.Fatal(err)
	}
}

func holdResultIdentityInsertBarrier(t *testing.T, env recoveryTestEnvironment, id domain.ID) func() {
	t.Helper()
	_, release := holdResultIdentityInsertBarrierWithPID(t, env, id)
	return release
}

func holdResultIdentityInsertBarrierWithPID(t *testing.T, env recoveryTestEnvironment, id domain.ID) (int32, func()) {
	t.Helper()
	conn, err := env.store.Pool.Acquire(env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var backendPID, key int32
	if err := conn.QueryRow(env.ctx, `SELECT pg_backend_pid(),hashtext($1::text)`, id).Scan(&backendPID, &key); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	if _, err := conn.Exec(env.ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key); err != nil {
			t.Errorf("release result identity advisory lock: %v", err)
		}
		conn.Release()
	}
	return backendPID, release
}

func waitForConcurrentResultInsertBarrier(t *testing.T, ctx context.Context, store *Store, holderPID, firstPID, secondPID int32, first, second <-chan error) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int
		if err := store.Pool.QueryRow(ctx, `SELECT count(*)
			FROM (VALUES ($1::integer),($2::integer)) target(pid)
			WHERE EXISTS (
				SELECT 1
				FROM pg_locks waiting_lock
				JOIN pg_locks held_lock
				  ON held_lock.locktype=waiting_lock.locktype
				 AND held_lock.database IS NOT DISTINCT FROM waiting_lock.database
				 AND held_lock.classid IS NOT DISTINCT FROM waiting_lock.classid
				 AND held_lock.objid IS NOT DISTINCT FROM waiting_lock.objid
				 AND held_lock.objsubid IS NOT DISTINCT FROM waiting_lock.objsubid
				 AND held_lock.mode=waiting_lock.mode
				WHERE waiting_lock.pid=target.pid
				  AND waiting_lock.locktype='advisory'
				  AND NOT waiting_lock.granted
				  AND held_lock.pid=$3
				  AND held_lock.granted
			)`, firstPID, secondPID, holderPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == 2 {
			return
		}
		select {
		case err := <-first:
			t.Fatalf("first observation emission transaction returned before both exact backends reached the advisory-lock barrier: %v", err)
		case err := <-second:
			t.Fatalf("second observation emission transaction returned before both exact backends reached the advisory-lock barrier: %v", err)
		case <-ctx.Done():
			t.Fatalf("both exact observation emission backends did not reach the advisory-lock barrier: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitForConcurrentResultInsertQueries(t *testing.T, ctx context.Context, store *Store, first, second <-chan error, queryPattern string) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int
		if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE pid<>pg_backend_pid()
			  AND wait_event_type='Lock'
			  AND query LIKE $1`, queryPattern).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= 2 {
			return
		}
		select {
		case err := <-first:
			t.Fatalf("first PersistResult returned before both inserts reached the PostgreSQL barrier: %v", err)
		case err := <-second:
			t.Fatalf("second PersistResult returned before both inserts reached the PostgreSQL barrier: %v", err)
		case <-ctx.Done():
			t.Fatalf("both result inserts did not reach the PostgreSQL barrier: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func installPersistResultStepBarrier(t *testing.T, env recoveryTestEnvironment) {
	t.Helper()
	if _, err := env.store.Pool.Exec(env.ctx, `CREATE FUNCTION scheduler_result_step_barrier() RETURNS trigger AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(hashtext(NEW.id::text));
			RETURN NEW;
		END;
	$$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.Pool.Exec(env.ctx, `CREATE TRIGGER scheduler_result_step_barrier BEFORE UPDATE OF status ON step_runs FOR EACH ROW EXECUTE FUNCTION scheduler_result_step_barrier()`); err != nil {
		t.Fatal(err)
	}
}

func holdPersistResultStepBarrier(t *testing.T, env recoveryTestEnvironment, stepID domain.ID) func() {
	t.Helper()
	conn, err := env.store.Pool.Acquire(env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	var key int32
	if err := conn.QueryRow(env.ctx, `SELECT hashtext($1::text)`, stepID).Scan(&key); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	if _, err := conn.Exec(env.ctx, `SELECT pg_advisory_lock($1)`, key); err != nil {
		conn.Release()
		t.Fatal(err)
	}
	released := false
	return func() {
		if released {
			return
		}
		released = true
		if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key); err != nil {
			t.Errorf("release result step advisory lock: %v", err)
		}
		conn.Release()
	}
}

func waitForPostgresLockOrResult(t *testing.T, ctx context.Context, store *Store, persisted <-chan error, queryPattern string) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-persisted:
			t.Fatalf("PersistResult returned before reaching the PostgreSQL lock barrier: %v", err)
		default:
		}

		var waiting bool
		if err := store.Pool.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM pg_stat_activity
			WHERE pid<>pg_backend_pid()
			  AND wait_event_type='Lock'
			  AND query LIKE $1
		)`, queryPattern).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case err := <-persisted:
			t.Fatalf("PersistResult returned before reaching the PostgreSQL lock barrier: %v", err)
		case <-ctx.Done():
			t.Fatalf("database statement did not reach lock barrier: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitForScheduledLeaseExpiry(t *testing.T, ctx context.Context, fixture scheduledResultFixture) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var expired bool
		if err := fixture.env.store.Pool.QueryRow(ctx, `SELECT lease_expires_at<=clock_timestamp() FROM scheduled_executions WHERE id=$1`, fixture.lineage.execution.ID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("scheduled lease did not expire: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func resultFenceSnapshot(t *testing.T, fixture scheduledResultFixture) string {
	t.Helper()
	var snapshot string
	err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT jsonb_build_object(
		'scheduled',(SELECT to_jsonb(se) FROM scheduled_executions se WHERE se.id=$1),
		'task',(SELECT to_jsonb(t) FROM tasks t WHERE t.id=$2),
		'workflow',(SELECT to_jsonb(wr) FROM workflow_runs wr WHERE wr.id=$3),
		'step',(SELECT to_jsonb(sr) FROM step_runs sr WHERE sr.id=$4),
		'tools',(SELECT COALESCE(jsonb_agg(to_jsonb(tr) ORDER BY tr.id),'[]'::jsonb) FROM tool_runs tr WHERE tr.step_run_id=$4),
		'artifacts',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY a.id),'[]'::jsonb) FROM artifacts a WHERE a.workflow_run_id=$3),
		'assets',(SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY a.id),'[]'::jsonb) FROM assets a WHERE a.program_id=$5),
		'observations',(SELECT COALESCE(jsonb_agg(to_jsonb(ao) ORDER BY ao.id),'[]'::jsonb) FROM asset_observations ao JOIN assets a ON a.id=ao.asset_id WHERE a.program_id=$5),
		'observation_emissions',(SELECT COALESCE(jsonb_agg(to_jsonb(emission) ORDER BY emission.asset_observation_id,emission.provider_result_accepted_event_id),'[]'::jsonb) FROM asset_observation_emissions emission JOIN asset_observations observation ON observation.id=emission.asset_observation_id WHERE observation.workflow_run_id=$3),
		'candidates',(SELECT COALESCE(jsonb_agg(to_jsonb(cf) ORDER BY cf.id),'[]'::jsonb) FROM candidate_findings cf WHERE cf.workflow_run_id=$3),
		'changes',(SELECT COALESCE(jsonb_agg(to_jsonb(ci) ORDER BY ci.id),'[]'::jsonb) FROM change_items ci WHERE ci.workflow_run_id=$3),
		'approvals',(SELECT COALESCE(jsonb_agg(to_jsonb(ap) ORDER BY ap.id),'[]'::jsonb) FROM approvals ap WHERE ap.task_id=$2),
		'audits',(SELECT COALESCE(jsonb_agg(to_jsonb(ae) ORDER BY ae.id),'[]'::jsonb) FROM audit_events ae WHERE ae.event_type<>'provider_result_rejected' AND (ae.workflow_run_id=$3 OR (ae.workflow_run_id IS NULL AND ae.task_id=$2)))
	)::text`, fixture.lineage.execution.ID, fixture.lineage.task.ID, fixture.lineage.runID, fixture.stepID, fixture.env.programID).Scan(&snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertResultRowCounts(t *testing.T, fixture scheduledResultFixture, toolWant, artifactWant, observationWant, findingWant, toolAuditWant int) {
	t.Helper()
	var tools, artifacts, observations, findings, toolAudits int
	err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
		(SELECT count(*) FROM tool_runs WHERE step_run_id=$1),
		(SELECT count(*) FROM artifacts WHERE step_run_id=$1),
		(SELECT count(*) FROM asset_observations WHERE workflow_run_id=$2),
		(SELECT count(*) FROM candidate_findings WHERE workflow_run_id=$2),
		(SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type='tool_execution')`, fixture.stepID, fixture.lineage.runID).Scan(&tools, &artifacts, &observations, &findings, &toolAudits)
	if err != nil {
		t.Fatal(err)
	}
	if tools != toolWant || artifacts != artifactWant || observations != observationWant || findings != findingWant || toolAudits != toolAuditWant {
		t.Fatalf("result counts tools=%d artifacts=%d observations=%d findings=%d tool_audits=%d", tools, artifacts, observations, findings, toolAudits)
	}
}

type providerResultDecision struct {
	Component                     string
	Actor                         string
	TaskID                        domain.ID
	ProgramID                     domain.ID
	WorkflowRunID                 domain.ID
	StepRunID                     domain.ID
	ToolRunID                     *domain.ID
	ScheduledExecutionID          domain.ID
	SchedulerAttempt              int
	ActionRequestID               domain.ID
	StepAttempt                   int
	QueueJobID                    *domain.ID
	ExecutionAuthorizationEventID domain.ID
	ProviderAttemptID             domain.ID
	Capability                    string
	Provider                      string
	SafeMessage                   string
	Details                       string
}

type providerResultDecisionExpectation struct {
	Actor                         string
	TaskID                        domain.ID
	ProgramID                     domain.ID
	WorkflowRunID                 domain.ID
	StepRunID                     domain.ID
	ToolRunID                     *domain.ID
	ScheduledExecutionID          domain.ID
	SchedulerAttempt              int
	ActionRequestID               domain.ID
	StepAttempt                   int
	QueueJobID                    *domain.ID
	ExecutionAuthorizationEventID domain.ID
	ProviderAttemptID             domain.ID
	Capability                    string
	Provider                      string
	SafeMessage                   string
	Details                       string
}

func loadProviderResultDecision(t *testing.T, fixture scheduledResultFixture, eventType string, providerAttemptID domain.ID, reason string) providerResultDecision {
	t.Helper()
	var decision providerResultDecision
	err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT component,actor,task_id,program_id,workflow_run_id,step_run_id,tool_run_id,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,execution_authorization_event_id,
		provider_attempt_id,capability,provider,safe_message,details::text
		FROM audit_events
		WHERE event_type=$1 AND provider_attempt_id=$2 AND ($3='' OR details->>'reason_code'=$3)
		ORDER BY occurred_at,id LIMIT 1`, eventType, providerAttemptID, reason).Scan(
		&decision.Component, &decision.Actor, &decision.TaskID, &decision.ProgramID, &decision.WorkflowRunID, &decision.StepRunID, &decision.ToolRunID,
		&decision.ScheduledExecutionID, &decision.SchedulerAttempt, &decision.ActionRequestID, &decision.StepAttempt, &decision.QueueJobID,
		&decision.ExecutionAuthorizationEventID, &decision.ProviderAttemptID, &decision.Capability, &decision.Provider, &decision.SafeMessage, &decision.Details)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func assertProviderResultDecisionProvenance(t *testing.T, got providerResultDecision, want providerResultDecisionExpectation) {
	t.Helper()
	if got.Component != "result_fence" || got.Actor != want.Actor || got.TaskID != want.TaskID || got.ProgramID != want.ProgramID || got.WorkflowRunID != want.WorkflowRunID || got.StepRunID != want.StepRunID || !equalIDPointers(got.ToolRunID, want.ToolRunID) || got.ScheduledExecutionID != want.ScheduledExecutionID || got.SchedulerAttempt != want.SchedulerAttempt || got.ActionRequestID != want.ActionRequestID || got.StepAttempt != want.StepAttempt || !equalIDPointers(got.QueueJobID, want.QueueJobID) || got.ExecutionAuthorizationEventID != want.ExecutionAuthorizationEventID || got.ProviderAttemptID != want.ProviderAttemptID || got.Capability != want.Capability || got.Provider != want.Provider || got.SafeMessage != want.SafeMessage || got.Details != want.Details {
		t.Fatalf("decision=%#v want=%#v", got, want)
	}
}

func equalIDPointers(left, right *domain.ID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func assertProviderResultDecisionCount(t *testing.T, fixture scheduledResultFixture, providerAttemptID domain.ID, eventType, reason string, want int) {
	t.Helper()
	var count int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT count(*) FROM audit_events WHERE provider_attempt_id=$1 AND event_type=$2 AND ($3='' OR details->>'reason_code'=$3)`, providerAttemptID, eventType, reason).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%s provider result decisions for P=%s reason=%q count=%d want=%d", eventType, providerAttemptID, reason, count, want)
	}
}

func prepareArtifactResultConflict(t *testing.T, fixture scheduledResultFixture, _ *context.Context, _ *domain.ID, _ *domain.StepRun, _ *domain.ToolRun, artifacts *[]domain.Artifact, _ *domain.ActionResult, _ *capability.ResultAdmissionProvenance) {
	t.Helper()
	foreignStepID, foreignToolID := domain.NewID(), domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,attempt_count,input,started_at,idempotency_key)
		VALUES($1,$2,'artifact-conflict','probe.http','running',1,'{}',clock_timestamp(),$3)`, foreignStepID, fixture.lineage.runID, string(domain.NewID())); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at) VALUES($1,$2,'probe.http','fixture',clock_timestamp())`, foreignToolID, foreignStepID); err != nil {
		t.Fatal(err)
	}
	a := (*artifacts)[0]
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO artifacts(id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,storage_location,created_at,redaction_state,sensitive)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,false)`, a.ID, a.TaskID, a.WorkflowRunID, foreignStepID, foreignToolID, a.Type, a.ContentType, a.Size, a.SHA256, a.StorageLocation, a.CreatedAt, a.RedactionState); err != nil {
		t.Fatal(err)
	}
}
