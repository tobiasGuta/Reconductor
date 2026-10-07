package database

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/normalize"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
	"github.com/tobiasGuta/Reconductor/internal/resultadmission"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

type preparedDBFixture struct {
	scheduledResultFixture
	identity  artifact.StoreIdentity
	action    domain.ActionRequest
	admission capability.ResultAdmissionProvenance
	compiled  resultadmission.CompiledResult
	seal      resultadmission.PreparedSealRecord
	step      domain.StepRun
}

// Test DB only: no providers, external traffic, or physical artifact store.
func newPreparedDBFixture(t *testing.T, env recoveryTestEnvironment, name string) preparedDBFixture {
	t.Helper()
	f := newScheduledResultFixtureInEnvironment(t, env, name, "compare.assets")
	return prepareDBFixture(t, env, f)
}

func prepareDBFixture(t *testing.T, env recoveryTestEnvironment, f scheduledResultFixture) preparedDBFixture {
	t.Helper()
	identity := artifact.StoreIdentityFrom(ensureTestArtifactStore(t, env.ctx, env.store))
	if err := env.store.ConfigurePreparedEvidenceLimits(env.ctx, identity.ArtifactStoreID, 128, 1<<20, 128<<20); err != nil {
		t.Fatal(err)
	}
	action := scheduledProviderAction(f, 1)
	auth, err := env.store.RecordPolicyDecision(f.context(), capability.PolicyDecisionRecord{ProgramID: env.programID, Action: action, Provider: "fixture", PolicyID: "test", Phase: "execution", Evaluation: policy.Evaluation{Decision: policy.Allow, Reason: "local fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	allocated, err := env.store.AllocateProviderInvocation(f.context(), capability.ProviderInvocationStartRecord{ProgramID: env.programID, TaskID: action.TaskID, WorkflowRunID: action.WorkflowRunID, StepRunID: action.StepRunID, ActionRequestID: action.ID, StepAttempt: 1, ExecutionAuthorizationEventID: auth, Capability: action.Capability, Provider: "fixture", Actor: "test"}, identity)
	if err != nil {
		t.Fatal(err)
	}
	admission := capability.ResultAdmissionProvenance{ProviderAttemptID: allocated.ProviderAttemptID, PreparedSetID: allocated.PreparedSetID, ManifestID: allocated.ManifestID, ReservedCapacityBytes: allocated.ReservedCapacityBytes, ActionRequestID: action.ID, StepAttempt: 1, ExecutionAuthorizationEventID: auth, Provider: "fixture", ProviderTerminalEventID: domain.NewID()}
	now := time.Now().UTC()
	tool := domain.ToolRun{ID: domain.NewID(), StepRunID: action.StepRunID, Capability: action.Capability, Provider: "fixture", ToolVersion: "2", StartedAt: now, CompletedAt: &now, ProviderAttemptID: &admission.ProviderAttemptID, SanitizedArguments: json.RawMessage(`{}`), ExecutionEnvironment: json.RawMessage(`{}`)}
	result := capability.Result{Action: domain.ActionResult{RequestID: action.ID, Status: "succeeded", Summary: "fixture", Output: json.RawMessage(`{}`)}, ProviderAttemptID: &admission.ProviderAttemptID, AdmissionProvenance: &admission, ProviderOutcome: domain.ResultProviderSucceeded}
	compiled, err := resultadmission.Compile(resultadmission.CompileRequest{ProgramID: env.programID, Action: action, Manifest: capability.Manifest{Name: action.Capability, Version: "2", OutputSchema: json.RawMessage(`{}`)}, StoreIdentity: identity, Result: result, ToolRun: tool, RequirePreparedEvidence: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { compiled.Close() })
	step := domain.StepRun{ID: action.StepRunID, WorkflowRunID: action.WorkflowRunID, Capability: action.Capability, IdempotencyKey: action.IdempotencyKey, Status: domain.StepSucceeded, CompletedAt: &now}
	request, manifest, err := compiled.PreparedStageRequest(identity, step, admission, capability.ProviderInvocationSucceeded, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	content := int64(len(request.ManifestJSON)) + request.Control.ExpectedSize
	for _, m := range request.Members {
		content += m.ExpectedSize
	}
	seal := resultadmission.PreparedSealRecord{Admission: admission, StoreIdentity: identity, Manifest: manifest, ManifestSize: int64(len(request.ManifestJSON)), ManifestSHA256: artifact.DigestString(artifact.DigestBytes(request.ManifestJSON)), ContentBytes: content, Outcome: capability.ProviderInvocationSucceeded}
	return preparedDBFixture{f, identity, action, admission, compiled, seal, step}
}
func (f preparedDBFixture) recoveryContext() context.Context {
	return domain.WithPreparedRecoveryRequest(f.env.ctx, domain.PreparedRecoveryRequest{SetID: f.admission.PreparedSetID, ManifestID: f.admission.ManifestID, ProviderAttemptID: f.admission.ProviderAttemptID, TerminalEventID: f.admission.ProviderTerminalEventID, ResultOccurrenceID: f.compiled.ResultOccurrenceID, ActionRequestID: f.action.ID, StepAttempt: 1, ManifestSHA256: f.seal.ManifestSHA256})
}

func TestPreparedProbeHTTPDuplicateRedirectTargetsAdoptAtomically(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "prepared-probe-http-duplicate-redirect-targets")
	now := time.Now().UTC()
	task := createIntegrationTask(t, env.ctx, env.store, env.programID, env.definitionID, "probe-http")
	runID, stepID := domain.NewID(), domain.NewID()
	key := "prepared-probe-http-duplicate-redirect-targets"
	input := json.RawMessage(`{}`)
	state := &workflow.State{Run: domain.WorkflowRun{ID: runID, TaskID: task.ID, WorkflowDefinitionID: env.definitionID, WorkflowVersion: "1", Status: domain.RunRunning, StartedAt: &now, TriggerSource: "integration", Summary: json.RawMessage(`{}`)}, Steps: map[string]*workflow.StepState{"provider": {Run: domain.StepRun{ID: stepID, WorkflowRunID: runID, StepDefinitionID: "provider", Capability: "probe.http", Status: domain.StepRunning, Input: input, StartedAt: &now, IdempotencyKey: key, ApprovalState: "not_required"}, InputHash: workflow.InputDigest(input)}}}
	materializeSyntheticWorkflowState(t, env.store, env.ctx, state)
	if err := env.store.SaveWorkflowState(env.ctx, state); err != nil {
		t.Fatal(err)
	}
	scheduled := scheduledResultFixture{env: env, lineage: recoveryTestFixture{task: task, runID: runID}, stepID: stepID, idempotencyKey: key, capability: "probe.http"}
	identity := artifact.StoreIdentityFrom(ensureTestArtifactStore(t, env.ctx, env.store))
	if err := env.store.ConfigurePreparedEvidenceLimits(env.ctx, identity.ArtifactStoreID, 128, 1<<20, 128<<20); err != nil {
		t.Fatal(err)
	}
	action := scheduledProviderAction(scheduled, 1)
	if _, err := env.store.PersistEffectiveStepInput(env.ctx, env.programID, action, input); err != nil {
		t.Fatal(err)
	}
	authorizationID, err := env.store.RecordPolicyDecision(env.ctx, capability.PolicyDecisionRecord{ProgramID: env.programID, Action: action, Provider: "httpx", PolicyID: "test", Phase: "execution", Evaluation: policy.Evaluation{Decision: policy.Allow, Reason: "local fixture"}})
	if err != nil {
		t.Fatal(err)
	}
	allocated, err := env.store.AllocateProviderInvocation(env.ctx, capability.ProviderInvocationStartRecord{ProgramID: env.programID, TaskID: action.TaskID, WorkflowRunID: action.WorkflowRunID, StepRunID: action.StepRunID, ActionRequestID: action.ID, StepAttempt: 1, ExecutionAuthorizationEventID: authorizationID, Capability: action.Capability, Provider: "httpx", Actor: "test"}, identity)
	if err != nil {
		t.Fatal(err)
	}
	admission := capability.ResultAdmissionProvenance{ProviderAttemptID: allocated.ProviderAttemptID, PreparedSetID: allocated.PreparedSetID, ManifestID: allocated.ManifestID, ReservedCapacityBytes: allocated.ReservedCapacityBytes, ActionRequestID: action.ID, StepAttempt: 1, ExecutionAuthorizationEventID: authorizationID, Provider: "httpx", ProviderTerminalEventID: domain.NewID()}
	records := []provideroutput.Record{
		{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://intl.example.test/", StatusCode: 200, Fields: map[string]any{"input": "http://intl.example.test", "host_ip": "192.0.2.10", "content_length": json.Number("204766"), "knowledgebase": map[string]any{"pHash": json.Number("0")}}},
		{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://intl.example.test/", StatusCode: 200, Fields: map[string]any{"input": "https://intl.example.test", "host_ip": "192.0.2.11"}},
		{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://www.example.test/", StatusCode: 200, Fields: map[string]any{"input": "http://www.example.test", "host_ip": "192.0.2.20"}},
		{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://www.example.test/", StatusCode: 200, Fields: map[string]any{"input": "https://www.example.test", "host_ip": "192.0.2.21"}},
	}
	sources, err := normalize.BuildProbeHTTPSourceRecords(string(env.programID), string(admission.ProviderAttemptID), records, normalize.RequestSemantics{
		Method:      normalize.ValueSemantics{State: normalize.ValueDefaulted, Value: databaseSourceString("GET")},
		ContentType: normalize.ValueSemantics{State: normalize.ValueUnknown},
	})
	if err != nil {
		t.Fatal(err)
	}
	output, err := json.Marshal(map[string]any{
		"lines":                     []string{"https://intl.example.test/", "https://www.example.test/"},
		"authorized":                []string{"https://intl.example.test/", "https://www.example.test/"},
		"authorized_urls":           []string{"https://intl.example.test/", "https://www.example.test/"},
		"authorized_records":        records,
		"authorized_source_records": sources,
		"filtered":                  []any{},
		"records":                   records,
		"warnings":                  []any{},
		"accepted_count":            len(records),
		"filtered_count":            0,
	})
	if err != nil {
		t.Fatal(err)
	}
	tool := domain.ToolRun{ID: domain.NewID(), StepRunID: action.StepRunID, Capability: action.Capability, Provider: "httpx", ToolVersion: "4", StartedAt: now, CompletedAt: &now, ProviderAttemptID: &admission.ProviderAttemptID, SanitizedArguments: json.RawMessage(`{}`), ExecutionEnvironment: json.RawMessage(`{}`)}
	result := capability.Result{Action: domain.ActionResult{RequestID: action.ID, Status: "succeeded", Summary: "httpx accepted four normalized records", Output: output}, ProviderAttemptID: &admission.ProviderAttemptID, AdmissionProvenance: &admission, ProviderOutcome: domain.ResultProviderSucceeded}
	compiled, err := resultadmission.Compile(resultadmission.CompileRequest{ProgramID: env.programID, Action: action, Manifest: capability.Manifest{Name: action.Capability, Version: "4", OutputSchema: json.RawMessage(`{}`)}, StoreIdentity: identity, Result: result, ToolRun: tool, ProjectorsRequired: true, RequirePreparedEvidence: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { compiled.Close() })
	step := domain.StepRun{ID: action.StepRunID, WorkflowRunID: action.WorkflowRunID, Capability: action.Capability, IdempotencyKey: action.IdempotencyKey, Status: domain.StepSucceeded, CompletedAt: &now}
	request, manifest, err := compiled.PreparedStageRequest(identity, step, admission, capability.ProviderInvocationSucceeded, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	contentBytes := int64(len(request.ManifestJSON)) + request.Control.ExpectedSize
	for _, member := range request.Members {
		contentBytes += member.ExpectedSize
	}
	seal := resultadmission.PreparedSealRecord{Admission: admission, StoreIdentity: identity, Manifest: manifest, ManifestSize: int64(len(request.ManifestJSON)), ManifestSHA256: artifact.DigestString(artifact.DigestBytes(request.ManifestJSON)), ContentBytes: contentBytes, Outcome: capability.ProviderInvocationSucceeded}
	if err := env.store.SealPreparedEvidence(env.ctx, seal); err != nil {
		t.Fatal(err)
	}
	if err := env.store.ReserveCompiledResult(env.ctx, env.programID, step, compiled, &admission, identity); err != nil {
		t.Fatal(err)
	}
	for ordinal := range compiled.Artifacts {
		if err := env.store.MarkCompiledArtifactPublishing(env.ctx, compiled, ordinal); err != nil {
			t.Fatal(err)
		}
		if err := env.store.SealCompiledArtifact(env.ctx, compiled, ordinal); err != nil {
			t.Fatal(err)
		}
	}
	if err := env.store.AdoptCompiledResult(env.ctx, env.programID, step, compiled, &admission, time.Hour); err != nil {
		t.Fatal(err)
	}
	var observationCount, sourceCount, resourceCount int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT
		(SELECT count(*) FROM asset_observations WHERE workflow_run_id=$1 AND source_capability='probe.http'),
		(SELECT count(*) FROM probe_http_source_records WHERE program_id=$2 AND provider_attempt_id=$3),
		(SELECT count(*) FROM canonical_concrete_http_resources WHERE program_id=$2)`, scheduled.lineage.runID, env.programID, admission.ProviderAttemptID).Scan(&observationCount, &sourceCount, &resourceCount); err != nil {
		t.Fatal(err)
	}
	if observationCount != 2 || sourceCount != 4 || resourceCount != 2 {
		t.Fatalf("observations=%d sources=%d resources=%d", observationCount, sourceCount, resourceCount)
	}
}

func TestPreparedScheduledRecoveryAndBothSchedulerDeferrals(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "prepared-authority")
	f := newPreparedDBFixture(t, env, "current")
	if err := env.store.SealPreparedEvidence(f.context(), f.seal); err != nil {
		t.Fatal(err)
	}
	if err := env.store.MarkScheduledExecutionFailed(f.context(), f.fence.ExecutionID, f.fence.LeaseOwner, f.fence.Attempt, "test", "test"); !domain.PersistenceUnresolved(err) {
		t.Fatalf("live terminalization=%v", err)
	}
	expireRecoveryLease(t, env, f.fence.ExecutionID, 1)
	reconcileRecovery(t, env)
	var status string
	var attempt int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT status,attempt_count FROM scheduled_executions WHERE id=$1`, f.fence.ExecutionID).Scan(&status, &attempt); err != nil || status != "running" || attempt != 1 {
		t.Fatalf("status=%s attempt=%d err=%v", status, attempt, err)
	}
	if _, _, ok, err := env.store.ClaimPendingScheduledExecution(env.ctx, "replacement", time.Minute); err != nil || ok {
		t.Fatalf("replacement eligible=%v err=%v", ok, err)
	}
	if err := env.store.ReserveCompiledResult(f.context(), env.programID, f.step, f.compiled, &f.admission, f.identity); err == nil {
		t.Fatal("expired live authority admitted")
	}
	ctx := f.recoveryContext()
	var reservationStarted time.Time
	if err := env.store.Pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&reservationStarted); err != nil {
		t.Fatal(err)
	}
	if err := env.store.ReserveCompiledResult(ctx, env.programID, f.step, f.compiled, &f.admission, f.identity); err != nil {
		t.Fatal(err)
	}
	var reservationFinished time.Time
	if err := env.store.Pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&reservationFinished); err != nil {
		t.Fatal(err)
	}
	var publicationCount int
	if err := env.store.Pool.QueryRow(ctx, `SELECT count(*) FROM artifact_publications WHERE provider_attempt_id=$1`, f.admission.ProviderAttemptID).Scan(&publicationCount); err != nil || publicationCount != len(f.compiled.Artifacts) {
		t.Fatalf("reservation member count=%d err=%v", publicationCount, err)
	}
	for ordinal, item := range f.compiled.Artifacts {
		var providerID, occurrenceID, artifactID, storeID domain.ID
		var storedOrdinal, durationMS int
		var storageKey, durationType, expiryType string
		var expiresAt time.Time
		err := env.store.Pool.QueryRow(ctx, `SELECT provider_attempt_id,result_occurrence_id,artifact_id,artifact_store_id,publication_ordinal,storage_key,lease_duration_ms,lease_expires_at,pg_typeof(lease_duration_ms)::text,pg_typeof(lease_expires_at)::text FROM artifact_publications WHERE id=$1`, item.PublicationID).Scan(&providerID, &occurrenceID, &artifactID, &storeID, &storedOrdinal, &storageKey, &durationMS, &expiresAt, &durationType, &expiryType)
		if err != nil {
			t.Fatal(err)
		}
		if providerID != f.admission.ProviderAttemptID || occurrenceID != f.compiled.ResultOccurrenceID || artifactID != item.Reference.ArtifactID || storeID != item.Reference.ArtifactStoreID || storedOrdinal != ordinal || storageKey != item.Reference.StorageKey {
			t.Fatal("reservation replaced exact publication/result/attempt identity")
		}
		if durationType != "integer" || expiryType != "timestamp with time zone" || durationMS != int(domain.StepAttemptLeaseDefault/time.Millisecond) {
			t.Fatalf("reservation lease duration=%d types=%s/%s", durationMS, durationType, expiryType)
		}
		// Bracket the INSERT with database timestamps, avoiding host-clock skew
		// and allowing the actual transaction duration instead of exact equality.
		leaseBase := expiresAt.Add(-time.Duration(durationMS) * time.Millisecond)
		if leaseBase.Before(reservationStarted) || leaseBase.After(reservationFinished) {
			t.Fatalf("lease base %s outside reservation interval [%s, %s]", leaseBase, reservationStarted, reservationFinished)
		}
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
	record, err := env.store.PreparedSet(env.ctx, f.admission.PreparedSetID)
	if err != nil || record.State != domain.PreparedResolvedAdopted || record.ResultOccurrenceID == nil || *record.ResultOccurrenceID != f.compiled.ResultOccurrenceID {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	tx, err := env.store.Pool.Begin(env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(env.ctx)
	if pending, err := hasUnresolvedScheduledPrepared(env.ctx, tx, f.fence.ExecutionID, 1); err != nil || pending {
		t.Fatalf("resolved result still defers: %v %v", pending, err)
	}
}

func TestPreparedRecoveryRejectsSupersededAndTerminalLineage(t *testing.T) {
	for _, mutation := range []string{"step attempt", "scheduler attempt", "terminal step", "terminal workflow", "wrong occurrence", "wrong manifest", "missing provider authority"} {
		t.Run(mutation, func(t *testing.T) {
			env := newRecoveryTestEnvironment(t, "prepared-reject")
			f := newPreparedDBFixture(t, env, "candidate")
			if err := env.store.SealPreparedEvidence(f.context(), f.seal); err != nil {
				t.Fatal(err)
			}
			expireRecoveryLease(t, env, f.fence.ExecutionID, 1)
			var err error
			switch mutation {
			case "step attempt":
				_, err = env.store.Pool.Exec(env.ctx, `UPDATE step_runs SET attempt_count=2 WHERE id=$1`, f.step.ID)
			case "scheduler attempt":
				_, err = env.store.Pool.Exec(env.ctx, `UPDATE scheduled_executions SET attempt_count=2 WHERE id=$1`, f.fence.ExecutionID)
			case "terminal step":
				_, err = env.store.Pool.Exec(env.ctx, `UPDATE step_runs SET status='failed',completed_at=clock_timestamp() WHERE id=$1`, f.step.ID)
			case "terminal workflow":
				_, err = env.store.Pool.Exec(env.ctx, `UPDATE workflow_runs SET status='failed',completed_at=clock_timestamp() WHERE id=$1`, f.step.WorkflowRunID)
			case "wrong occurrence":
				f.compiled.ResultOccurrenceID = domain.NewID()
			case "missing provider authority":
				f.admission.ProviderAttemptID = domain.NewID()
			case "wrong manifest":
				f.seal.ManifestSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := env.store.ReserveCompiledResult(f.recoveryContext(), env.programID, f.step, f.compiled, &f.admission, f.identity); err == nil {
				t.Fatal("contradictory recovery admitted")
			}
			record, err := env.store.PreparedSet(env.ctx, f.admission.PreparedSetID)
			if err != nil || record.State != domain.PreparedSealed {
				t.Fatalf("evidence destroyed: %s %v", record.State, err)
			}
		})
	}
}

func TestPreparedAnchorsAndQuarantineChargeRemainImmutable(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "prepared-immutable")
	f := newPreparedDBFixture(t, env, "anchors")
	if err := env.store.SealPreparedEvidence(f.context(), f.seal); err != nil {
		t.Fatal(err)
	}
	for _, assignment := range []string{"reserved_capacity_bytes=reserved_capacity_bytes-1", "content_size_bytes=content_size_bytes-1", "manifest_size_bytes=manifest_size_bytes-1", "manifest_sha256=repeat('b',64)", "member_count=member_count+1", "result_occurrence_id='00000000-0000-4000-8000-000000000999'", "provider_terminal_event_id='00000000-0000-4000-8000-000000000998'"} {
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE prepared_evidence_sets SET `+assignment+` WHERE id=$1`, f.admission.PreparedSetID); err == nil {
			t.Fatalf("mutable anchor: %s", assignment)
		}
	}
	if err := env.store.QuarantinePreparedEvidence(env.ctx, f.admission.PreparedSetID, "test_unverifiable"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.Pool.Exec(env.ctx, `UPDATE prepared_evidence_sets SET reserved_capacity_bytes=1 WHERE id=$1`, f.admission.PreparedSetID); err == nil {
		t.Fatal("quarantine released charge")
	}
	r, err := env.store.PreparedSet(env.ctx, f.admission.PreparedSetID)
	if err != nil || r.ReservedCapacityBytes != f.admission.ReservedCapacityBytes {
		t.Fatalf("charge=%d err=%v", r.ReservedCapacityBytes, err)
	}
}

func TestFullQuarantinedBatchCannotStarveLaterActionableSet(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "prepared-starvation")
	const batch = 4
	var first preparedDBFixture
	for i := 0; i < batch; i++ {
		f := newPreparedDBFixture(t, env, fmt.Sprintf("quarantine-%d", i))
		first = f
		if err := env.store.QuarantinePreparedEvidence(env.ctx, f.admission.PreparedSetID, "retained"); err != nil {
			t.Fatal(err)
		}
	}
	later := newPreparedDBFixture(t, env, "later-actionable")
	rows, err := env.store.ListPreparedEvidence(env.ctx, first.identity.ArtifactStoreID, first.identity.IncarnationNonce, batch)
	if err != nil || len(rows) != 1 || rows[0].ID != later.admission.PreparedSetID {
		t.Fatalf("actionable rows=%#v err=%v", rows, err)
	}
	var count int
	var charge int64
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT count(*),sum(reserved_capacity_bytes) FROM prepared_evidence_sets WHERE lifecycle_state='QUARANTINED'`).Scan(&count, &charge); err != nil || count != batch || charge != batch*(1<<20) {
		t.Fatalf("retained=%d charge=%d err=%v", count, charge, err)
	}
}

func TestOversizedPreparedKnownNonadmissionBindsOriginalIdentities(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "prepared-oversize")
	f := newPreparedDBFixture(t, env, "oversize")
	req, _, err := f.compiled.PreparedStageRequest(f.identity, f.step, f.admission, capability.ProviderInvocationSucceeded, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	limit := domain.ResultContractLimitV1{Subject: domain.LimitPreparedEvidence, Unit: domain.LimitBytes, Limit: uint64(f.admission.ReservedCapacityBytes), Observed: uint64(f.admission.ReservedCapacityBytes) + 1}
	if err := env.store.RejectPreparedEvidence(f.context(), env.programID, f.step, f.compiled, f.admission, req, limit); err != nil {
		t.Fatal(err)
	}
	record, err := env.store.PreparedSet(env.ctx, f.admission.PreparedSetID)
	if err != nil || record.State != domain.PreparedResolvedAbandoned || record.ResultOccurrenceID == nil || *record.ResultOccurrenceID != f.compiled.ResultOccurrenceID || record.ManifestSHA256 != nil || len(record.NonadmissionDetails) == 0 {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	var accepted int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT count(*) FROM tool_runs WHERE step_run_id=$1`, f.step.ID).Scan(&accepted); err != nil || accepted != 0 {
		t.Fatalf("nonadmission accepted ToolRun=%d err=%v", accepted, err)
	}
	assertStepRecoveryStatus(t, env, f.step.ID, domain.StepFailed)
}

func TestAuditSerializedSizeMatchesPostgresJSONB(t *testing.T) {
	store, ctx := schedulerIntegrationStore(t)
	for _, raw := range []string{`{"a":"<>&\n\"\\","b":[true,null,1e3,1e-3,-0.00]}`, `{"target":"test"}`, `[123.4500,0e3,0.00000,1e-20]`} {
		want, err := auditJSONBTextSize([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		var got int
		if err := store.Pool.QueryRow(ctx, `SELECT octet_length($1::jsonb::text)`, raw).Scan(&got); err != nil || got != want {
			t.Fatalf("raw=%s calculated=%d postgres=%d err=%v", raw, want, got, err)
		}
	}
}
