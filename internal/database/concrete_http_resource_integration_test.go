package database

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/normalize"
	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
)

func TestProbeHTTPSourcePersistenceIsAtomicAndLineageBound(t *testing.T) {
	t.Run("v4 source records bind exact emitted observations", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "concrete-http-source-success", "probe.http")
		action := scheduledProviderAction(fixture, 1)
		admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, nil, "fixture-provider")
		records := []provideroutput.Record{{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://api.example.test:8443/a%2fb?z=2&a=1", StatusCode: 200, Fields: map[string]any{}}}
		sources, err := normalize.BuildProbeHTTPSourceRecords(string(fixture.env.programID), string(admission.ProviderAttemptID), records, normalize.RequestSemantics{
			Method:      normalize.ValueSemantics{State: normalize.ValueKnown, Value: databaseSourceString("POST")},
			ContentType: normalize.ValueSemantics{State: normalize.ValueKnown, Value: databaseSourceString("application/json")},
		})
		if err != nil {
			t.Fatal(err)
		}
		output, err := json.Marshal(map[string]any{"lines": []string{}, "authorized_records": records, "authorized_source_records": sources})
		if err != nil {
			t.Fatal(err)
		}
		step, tool, artifacts, result := scheduledResultPayload(fixture, output)
		applyScheduledProviderAdmission(tool, &result, admission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission); err != nil {
			t.Fatal(err)
		}

		var locator, namespace, path, query, methodState, methodValue, contentState, contentValue string
		var providerAttemptID, acceptedEventID, artifactID domain.ID
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
			source.source_locator,source.identity_namespace,resource.concrete_escaped_path,resource.canonical_query,
			source.request_method_state,source.request_method_value,source.request_content_type_state,source.request_content_type_value,
			source.provider_attempt_id,source.provider_result_accepted_event_id,source.normalized_result_artifact_id
			FROM probe_http_source_records source
			JOIN canonical_concrete_http_resources resource ON resource.id=source.concrete_http_resource_id
			WHERE source.program_id=$1`, fixture.env.programID).Scan(&locator, &namespace, &path, &query, &methodState, &methodValue, &contentState, &contentValue, &providerAttemptID, &acceptedEventID, &artifactID); err != nil {
			t.Fatal(err)
		}
		if locator != sources[0].SourceLocator || namespace != normalize.HTTPURIResourceNamespace || path != "/a%2Fb" || query != "a=1&z=2" || methodState != string(normalize.ValueKnown) || methodValue != "POST" || contentState != string(normalize.ValueKnown) || contentValue != "application/json" || providerAttemptID != admission.ProviderAttemptID || artifactID != artifacts[0].ID {
			t.Fatalf("persisted source row locator=%s namespace=%s path=%s query=%s method=%s/%s content=%s/%s attempt=%s artifact=%s", locator, namespace, path, query, methodState, methodValue, contentState, contentValue, providerAttemptID, artifactID)
		}
		var emissionCount, acceptedCount int
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
			(SELECT count(*) FROM asset_observation_emissions WHERE provider_result_accepted_event_id=$1),
			(SELECT count(*) FROM audit_events WHERE id=$1 AND event_type='provider_result_accepted')`, acceptedEventID).Scan(&emissionCount, &acceptedCount); err != nil {
			t.Fatal(err)
		}
		if emissionCount != 1 || acceptedCount != 1 {
			t.Fatalf("emissions=%d accepted=%d", emissionCount, acceptedCount)
		}
		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE canonical_concrete_http_resources SET host='mutated.example.test' WHERE program_id=$1`, fixture.env.programID); err == nil || !strings.Contains(err.Error(), "identity is immutable") {
			t.Fatalf("resource identity mutation error=%v", err)
		}
		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE probe_http_source_records SET record_digest=$2 WHERE source_locator=$1`, locator, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("source mutation error=%v", err)
		}
	})

	t.Run("malformed v4 source rolls back without accepted or rejected decision", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "concrete-http-source-rollback", "probe.http")
		action := scheduledProviderAction(fixture, 1)
		admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, nil, "fixture-provider")
		records := []provideroutput.Record{{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://api.example.test/", Fields: map[string]any{}}}
		sources, err := normalize.BuildProbeHTTPSourceRecords(string(fixture.env.programID), string(admission.ProviderAttemptID), records, normalize.RequestSemantics{
			Method:      normalize.ValueSemantics{State: normalize.ValueDefaulted, Value: databaseSourceString("GET")},
			ContentType: normalize.ValueSemantics{State: normalize.ValueUnknown},
		})
		if err != nil {
			t.Fatal(err)
		}
		sources[0].SourceLocator = strings.Repeat("0", 64)
		output, err := json.Marshal(map[string]any{"authorized_records": records, "authorized_source_records": sources})
		if err != nil {
			t.Fatal(err)
		}
		step, tool, artifacts, result := scheduledResultPayload(fixture, output)
		applyScheduledProviderAdmission(tool, &result, admission)
		err = fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission)
		if !errors.Is(err, normalize.ErrProbeHTTPSourceContract) {
			t.Fatalf("PersistResult error=%v", err)
		}
		var resources, sourcesPersisted, observations, accepted, rejected int
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
			(SELECT count(*) FROM canonical_concrete_http_resources WHERE program_id=$1),
			(SELECT count(*) FROM probe_http_source_records WHERE program_id=$1),
			(SELECT count(*) FROM asset_observations WHERE workflow_run_id=$2),
			(SELECT count(*) FROM audit_events WHERE provider_attempt_id=$3 AND event_type='provider_result_accepted'),
			(SELECT count(*) FROM audit_events WHERE provider_attempt_id=$3 AND event_type='provider_result_rejected')`, fixture.env.programID, fixture.lineage.runID, admission.ProviderAttemptID).Scan(&resources, &sourcesPersisted, &observations, &accepted, &rejected); err != nil {
			t.Fatal(err)
		}
		if resources != 0 || sourcesPersisted != 0 || observations != 0 || accepted != 0 || rejected != 0 {
			t.Fatalf("rollback resources=%d sources=%d observations=%d accepted=%d rejected=%d", resources, sourcesPersisted, observations, accepted, rejected)
		}
		assertStepRecoveryStatus(t, fixture.env, fixture.stepID, domain.StepRunning)
	})

	t.Run("legacy v3 output has no source lineage", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "concrete-http-source-legacy", "probe.http")
		action := scheduledProviderAction(fixture, 1)
		admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, nil, "fixture-provider")
		output := json.RawMessage(`{"authorized_records":[{"provider":"httpx","kind":"url","target":"https://api.example.test/"}]}`)
		step, tool, artifacts, result := scheduledResultPayload(fixture, output)
		applyScheduledProviderAdmission(tool, &result, admission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission); err != nil {
			t.Fatal(err)
		}
		var resources, sources int
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT (SELECT count(*) FROM canonical_concrete_http_resources WHERE program_id=$1),(SELECT count(*) FROM probe_http_source_records WHERE program_id=$1)`, fixture.env.programID).Scan(&resources, &sources); err != nil {
			t.Fatal(err)
		}
		if resources != 0 || sources != 0 {
			t.Fatalf("legacy resources=%d sources=%d", resources, sources)
		}
	})
}

func TestProbeHTTPFailedAndRetryableV4ResultsPersistWithoutTrustedSources(t *testing.T) {
	for _, test := range []struct {
		name      string
		forged    bool
		retryable bool
	}{
		{name: "terminal empty"},
		{name: "terminal forged", forged: true},
		{name: "retryable empty", retryable: true},
		{name: "retryable forged", retryable: true, forged: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "concrete-http-source-"+strings.ReplaceAll(test.name, " ", "-"), "probe.http")
			action := scheduledProviderAction(fixture, 1)
			admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, nil, "fixture-provider")
			sourceRecords := any([]any{})
			if test.forged {
				sourceRecords = []any{map[string]any{"source_locator": "provider-controlled", "provider_attempt_id": domain.NewID()}}
			}
			output, err := json.Marshal(map[string]any{
				"lines":                     []string{},
				"authorized_records":        []provideroutput.Record{},
				"authorized_source_records": sourceRecords,
			})
			if err != nil {
				t.Fatal(err)
			}
			step, tool, artifacts, result := scheduledResultPayload(fixture, output)
			if test.retryable {
				makeRetryableResult(&step, &result)
			} else {
				makeTerminalFailedResult(&step, &result)
			}
			applyScheduledProviderAdmission(tool, &result, admission)
			if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission); err != nil {
				t.Fatal(err)
			}
			assertResultRowCounts(t, fixture, 1, 1, 0, 0, 1)
			assertProviderResultDecisionCount(t, fixture, admission.ProviderAttemptID, "provider_result_accepted", "", 1)
			var resources, sources, emissions int
			if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
				(SELECT count(*) FROM canonical_concrete_http_resources WHERE program_id=$1),
				(SELECT count(*) FROM probe_http_source_records WHERE program_id=$1),
				(SELECT count(*) FROM asset_observation_emissions emission JOIN asset_observations observation ON observation.id=emission.asset_observation_id WHERE observation.workflow_run_id=$2)`, fixture.env.programID, fixture.lineage.runID).Scan(&resources, &sources, &emissions); err != nil {
				t.Fatal(err)
			}
			if resources != 0 || sources != 0 || emissions != 0 {
				t.Fatalf("untrusted failure lineage persisted resources=%d sources=%d emissions=%d", resources, sources, emissions)
			}
			wantStatus, completed := domain.StepFailed, true
			if test.retryable {
				wantStatus, completed = domain.StepRetryable, false
			}
			assertPersistedStepState(t, fixture, wantStatus, 1, completed)
		})
	}
}

func TestProbeHTTPMalformedV4PreservesExistingResultFencePrecedence(t *testing.T) {
	tests := []struct {
		name    string
		reason  resultFenceReasonCode
		prepare func(*testing.T, scheduledResultFixture, *domain.StepRun, *domain.ToolRun, *[]domain.Artifact)
	}{
		{
			name:   "ToolRun lineage",
			reason: resultFenceToolLineageMismatch,
			prepare: func(_ *testing.T, _ scheduledResultFixture, _ *domain.StepRun, tool *domain.ToolRun, _ *[]domain.Artifact) {
				tool.StepRunID = domain.NewID()
			},
		},
		{
			name:   "StepRun not admitting result",
			reason: resultFenceStepNotAdmittingResult,
			prepare: func(t *testing.T, fixture scheduledResultFixture, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact) {
				if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE step_runs SET status='succeeded',completed_at=clock_timestamp() WHERE id=$1`, fixture.stepID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:   "stale provider step attempt",
			reason: resultFenceStaleProviderStepAttempt,
			prepare: func(t *testing.T, fixture scheduledResultFixture, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact) {
				if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE step_runs SET attempt_count=2 WHERE id=$1`, fixture.stepID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:   "ToolRun result conflict",
			reason: resultFenceToolResultConflict,
			prepare: func(t *testing.T, fixture scheduledResultFixture, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact) {
				if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at) VALUES($1,$2,$3,'legacy',clock_timestamp())`, domain.NewID(), fixture.stepID, fixture.capability); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:   "artifact identity",
			reason: resultFenceArtifactIdentityInvalid,
			prepare: func(_ *testing.T, _ scheduledResultFixture, _ *domain.StepRun, _ *domain.ToolRun, artifacts *[]domain.Artifact) {
				(*artifacts)[0].ID = ""
			},
		},
		{
			name:   "artifact lineage",
			reason: resultFenceArtifactLineageMismatch,
			prepare: func(_ *testing.T, _ scheduledResultFixture, _ *domain.StepRun, _ *domain.ToolRun, artifacts *[]domain.Artifact) {
				(*artifacts)[0].ToolRunID = domain.NewID()
			},
		},
		{
			name:   "artifact result conflict",
			reason: resultFenceArtifactResultConflict,
			prepare: func(t *testing.T, fixture scheduledResultFixture, _ *domain.StepRun, _ *domain.ToolRun, artifacts *[]domain.Artifact) {
				prepareArtifactResultConflict(t, fixture, nil, nil, nil, nil, artifacts, nil, nil)
			},
		},
		{
			name:   "concurrent StepRun change",
			reason: resultFenceConcurrentStepChange,
			prepare: func(t *testing.T, fixture scheduledResultFixture, _ *domain.StepRun, _ *domain.ToolRun, _ *[]domain.Artifact) {
				if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `CREATE FUNCTION suppress_probe_source_result_step_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;
					CREATE TRIGGER suppress_probe_source_result_step_update BEFORE UPDATE OF status ON step_runs FOR EACH ROW WHEN (OLD.id = '`+string(fixture.stepID)+`') EXECUTE FUNCTION suppress_probe_source_result_step_update()`); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "concrete-http-source-precedence-"+strings.ReplaceAll(test.name, " ", "-"), "probe.http")
			action := scheduledProviderAction(fixture, 1)
			admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, nil, "fixture-provider")
			malformed := json.RawMessage(`{"lines":[],"authorized_records":[],"authorized_source_records":[{"source_locator":"malformed"}]}`)
			step, tool, artifacts, result := scheduledResultPayload(fixture, malformed)
			applyScheduledProviderAdmission(tool, &result, admission)
			test.prepare(t, fixture, &step, tool, &artifacts)
			before := probeHTTPSourceStateSnapshot(t, fixture)

			err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission)
			rejection, semantic := resultFenceRejection(err)
			if !errors.Is(err, ErrStaleScheduledExecutionResult) || !semantic || rejection.reason != test.reason {
				t.Fatalf("malformed v4 rejection=%v semantic=%v reason=%v want=%v", err, semantic, rejection, test.reason)
			}
			if after := probeHTTPSourceStateSnapshot(t, fixture); after != before {
				t.Fatalf("malformed v4 rejection mutated state\nbefore=%s\nafter=%s", before, after)
			}
			assertProviderResultDecisionCount(t, fixture, admission.ProviderAttemptID, "provider_result_accepted", "", 0)
			assertOnlyProviderResultRejectedReason(t, fixture, admission.ProviderAttemptID, test.reason)
			assertNoProbeHTTP3AState(t, fixture)
		})
	}
}

func TestProbeHTTPMalformedV4PreservesConcurrentInsertConflictPrecedence(t *testing.T) {
	tests := []struct {
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			env := newRecoveryTestEnvironment(t, "probe-source-precedence-concurrent-"+strings.ReplaceAll(test.name, " ", "-"))
			installResultIdentityInsertBarrier(t, env)
			cleanupResultIdentityInsertBarrier(t, env)
			secondProgramID, secondDefinitionID := createSchedulerIntegrationProgram(t, env.ctx, env.store, "probe-source-precedence-concurrent-second-"+strings.ReplaceAll(test.name, " ", "-"))
			environments := []recoveryTestEnvironment{
				env,
				{store: env.store, ctx: env.ctx, programID: secondProgramID, definitionID: secondDefinitionID},
			}
			candidates := make([]providerResultCollisionCandidate, 0, 2)
			for index, fixtureEnv := range environments {
				name := "probe-source-precedence-valid"
				target := "https://precedence-valid.example.test/"
				if index == 1 {
					name = "probe-source-precedence-malformed"
					target = "https://precedence-malformed.example.test/"
				}
				fixture := newScheduledResultFixtureInEnvironment(t, fixtureEnv, name+"-"+strings.ReplaceAll(test.name, " ", "-"), "probe.http")
				action := scheduledProviderAction(fixture, 1)
				admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, nil, "fixture-provider")
				records := []provideroutput.Record{{Provider: "httpx", Kind: provideroutput.URLRecord, Target: target, StatusCode: 200, Fields: map[string]any{}}}
				envelope := map[string]any{"authorized_records": records}
				if index == 1 {
					envelope["authorized_source_records"] = []any{map[string]any{"source_locator": "malformed"}}
				}
				output, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				step, tool, artifacts, result := scheduledResultPayload(fixture, output)
				applyScheduledProviderAdmission(tool, &result, admission)
				candidates = append(candidates, providerResultCollisionCandidate{fixture: fixture, action: action, admission: admission, step: step, tool: tool, artifacts: artifacts, result: result})
			}

			sharedID := domain.NewID()
			for index := range candidates {
				test.apply(sharedID, &candidates[index])
			}
			malformedBefore := probeHTTPSourceStateSnapshot(t, candidates[1].fixture)
			release := holdResultIdentityInsertBarrier(t, env, sharedID)
			defer release()
			runCtx, cancel := context.WithTimeout(env.ctx, 10*time.Second)
			defer cancel()
			outcomes := make(chan probeHTTPPersistenceOutcome, 2)
			run := func(index int) {
				candidate := candidates[index]
				ctx := WithScheduledExecutionFence(runCtx, candidate.fixture.fence)
				outcomes <- probeHTTPPersistenceOutcome{index: index, err: env.store.PersistResult(ctx, candidate.fixture.env.programID, candidate.step, candidate.tool, candidate.artifacts, candidate.result, candidate.admission)}
			}
			go run(0)
			waitForBlockedDatabaseQueryCount(t, runCtx, env.store, outcomes, test.queryPattern, 1)
			go run(1)
			waitForBlockedDatabaseQueryCount(t, runCtx, env.store, outcomes, test.queryPattern, 2)
			release()

			results := [2]error{}
			for range 2 {
				select {
				case outcome := <-outcomes:
					results[outcome.index] = outcome.err
				case <-runCtx.Done():
					t.Fatalf("concurrent malformed-v4 precedence did not finish: %v", runCtx.Err())
				}
			}
			if results[0] != nil {
				t.Fatalf("valid queued winner failed: %v", results[0])
			}
			rejection, semantic := resultFenceRejection(results[1])
			if !errors.Is(results[1], ErrStaleScheduledExecutionResult) || !semantic || rejection.reason != test.reason {
				t.Fatalf("malformed concurrent rejection=%v semantic=%v reason=%v want=%v", results[1], semantic, rejection, test.reason)
			}
			if after := probeHTTPSourceStateSnapshot(t, candidates[1].fixture); after != malformedBefore {
				t.Fatalf("malformed concurrent rejection mutated state\nbefore=%s\nafter=%s", malformedBefore, after)
			}
			assertProviderResultDecisionCount(t, candidates[0].fixture, candidates[0].admission.ProviderAttemptID, "provider_result_accepted", "", 1)
			assertProviderResultDecisionCount(t, candidates[1].fixture, candidates[1].admission.ProviderAttemptID, "provider_result_accepted", "", 0)
			assertOnlyProviderResultRejectedReason(t, candidates[1].fixture, candidates[1].admission.ProviderAttemptID, test.reason)
			assertNoProbeHTTP3AState(t, candidates[1].fixture)
		})
	}
}

func TestProbeHTTPSourceLateInsertFailureRollsBackAllTransactionLocalState(t *testing.T) {
	fixture := newScheduledResultFixture(t, "concrete-http-source-late-rollback", "probe.http")
	action := scheduledProviderAction(fixture, 1)
	admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, nil, "fixture-provider")
	records := []provideroutput.Record{
		{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://late-rollback.example.test/alpha", StatusCode: 200, Fields: map[string]any{"record": "alpha"}},
		{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://late-rollback.example.test/beta", StatusCode: 200, Fields: map[string]any{"record": "beta"}},
	}
	sources, err := normalize.BuildProbeHTTPSourceRecords(string(fixture.env.programID), string(admission.ProviderAttemptID), records, normalize.RequestSemantics{Method: normalize.ValueSemantics{State: normalize.ValueDefaulted, Value: databaseSourceString("GET")}, ContentType: normalize.ValueSemantics{State: normalize.ValueUnknown}})
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 2 || sources[0].SourceLocator >= sources[1].SourceLocator {
		t.Fatalf("source insertion order is not deterministic: %#v", sources)
	}
	preoccupiedFixture := newScheduledResultFixtureInEnvironment(t, fixture.env, "concrete-http-source-late-preoccupied", "probe.http")
	preoccupied := newDirectProbeHTTPSourceLineageInFixture(t, preoccupiedFixture, false, "probe.http", "fixture-provider", "fixture-provider")
	if err := preoccupied.insertWithLocator(sources[1].SourceLocator, preoccupied.resourceID, preoccupied.observationID, preoccupied.acceptedEventID, preoccupied.providerAttemptID); err != nil {
		t.Fatal(err)
	}
	output, err := json.Marshal(map[string]any{"authorized_records": records, "authorized_source_records": sources})
	if err != nil {
		t.Fatal(err)
	}
	step, tool, artifacts, result := scheduledResultPayload(fixture, output)
	applyScheduledProviderAdmission(tool, &result, admission)
	installProbeHTTPSourceInsertProofBarrier(t, fixture.env)
	holderPID, release := holdResultIdentityInsertBarrierWithPID(t, fixture.env, domain.ID(sources[0].SourceLocator))
	defer release()
	auditSnapshot := func() string {
		var snapshot string
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(event) ORDER BY event.id),'[]'::jsonb)::text FROM audit_events event WHERE event.program_id=$1`, fixture.env.programID).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	auditsBefore := auditSnapshot()
	before := probeHTTPSourceStateSnapshot(t, fixture)
	runCtx, cancel := context.WithTimeout(fixture.context(), 10*time.Second)
	defer cancel()
	resultChannel := make(chan error, 1)
	go func() {
		resultChannel <- fixture.env.store.PersistResult(runCtx, fixture.env.programID, step, tool, artifacts, result, admission)
	}()
	waitingPID := waitForProbeHTTPSourceInsertProof(t, runCtx, fixture.env.store, holderPID, resultChannel)
	if waitingPID == holderPID {
		t.Fatalf("source insert proof reused holder backend pid %d", holderPID)
	}
	release()
	err = <-resultChannel
	if err == nil || !strings.Contains(err.Error(), "probe_http_source_records_pkey") {
		t.Fatalf("late locator conflict error=%v", err)
	}
	after := probeHTTPSourceStateSnapshot(t, fixture)
	if after != before {
		t.Fatalf("late source failure mutated durable state\nbefore=%s\nafter=%s", before, after)
	}
	if auditsAfter := auditSnapshot(); auditsAfter != auditsBefore {
		t.Fatalf("late source failure mutated provider/result audit state\nbefore=%s\nafter=%s", auditsBefore, auditsAfter)
	}
	var earlierSourceCount int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT count(*) FROM probe_http_source_records WHERE source_locator=$1`, sources[0].SourceLocator).Scan(&earlierSourceCount); err != nil {
		t.Fatal(err)
	}
	var conflictingAttemptID domain.ID
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT provider_attempt_id FROM probe_http_source_records WHERE source_locator=$1`, sources[1].SourceLocator).Scan(&conflictingAttemptID); err != nil {
		t.Fatal(err)
	}
	if earlierSourceCount != 0 || conflictingAttemptID != preoccupied.providerAttemptID {
		t.Fatalf("rollback earlier_source=%d conflicting_attempt=%s want=0/%s", earlierSourceCount, conflictingAttemptID, preoccupied.providerAttemptID)
	}
	assertStepRecoveryStatus(t, fixture.env, fixture.stepID, domain.StepRunning)
}

func TestProbeHTTPCanonicalResourceAcquisitionOrderIsAttemptIndependent(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "concrete-http-resource-lock-order")
	firstFixture := newScheduledResultFixtureInEnvironment(t, env, "concrete-http-resource-lock-first", "probe.http")
	secondFixture := newScheduledResultFixtureInEnvironment(t, env, "concrete-http-resource-lock-second", "probe.http")
	firstAdmission := recordScheduledProviderAdmission(t, firstFixture, firstFixture.context(), env.programID, scheduledProviderAction(firstFixture, 1), nil, "fixture-provider")
	secondAdmission := recordScheduledProviderAdmission(t, secondFixture, secondFixture.context(), env.programID, scheduledProviderAction(secondFixture, 1), nil, "fixture-provider")
	semantics := normalize.RequestSemantics{Method: normalize.ValueSemantics{State: normalize.ValueDefaulted, Value: databaseSourceString("GET")}, ContentType: normalize.ValueSemantics{State: normalize.ValueUnknown}}
	firstRecords := []provideroutput.Record{
		{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://lock-order.example.test:443/alpha%2fb?b=2&a=1", StatusCode: 200, Fields: map[string]any{"attempt": "first"}},
		{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://lock-order.example.test:443/beta%2fc?d=4&c=3", StatusCode: 200, Fields: map[string]any{"attempt": "first"}},
	}
	secondRecords := []provideroutput.Record{
		{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://LOCK-ORDER.example.test/alpha%2Fb?a=1&b=2", StatusCode: 200},
		{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://LOCK-ORDER.example.test/beta%2Fc?c=3&d=4", StatusCode: 200},
	}
	firstSources, err := normalize.BuildProbeHTTPSourceRecords(string(env.programID), string(firstAdmission.ProviderAttemptID), firstRecords, semantics)
	if err != nil {
		t.Fatal(err)
	}
	firstOrder := probeSourceCanonicalOrder(t, firstRecords, firstSources)
	var secondSources []normalize.AuthorizedSourceRecord
	for nonce := 0; nonce < 256; nonce++ {
		secondRecords[0].Fields = map[string]any{"attempt": "second", "nonce": nonce}
		secondRecords[1].Fields = map[string]any{"attempt": "second", "nonce": nonce}
		secondSources, err = normalize.BuildProbeHTTPSourceRecords(string(env.programID), string(secondAdmission.ProviderAttemptID), secondRecords, semantics)
		if err != nil {
			t.Fatal(err)
		}
		if secondOrder := probeSourceCanonicalOrder(t, secondRecords, secondSources); len(secondOrder) == 2 && secondOrder[0] == firstOrder[1] && secondOrder[1] == firstOrder[0] {
			break
		}
		secondSources = nil
	}
	if len(secondSources) != 2 {
		t.Fatal("could not construct opposite occurrence-specific source order")
	}
	firstResource, err := normalize.ConcreteHTTPResource(firstRecords[0].Target)
	if err != nil {
		t.Fatal(err)
	}
	secondResource, err := normalize.ConcreteHTTPResource(firstRecords[1].Target)
	if err != nil {
		t.Fatal(err)
	}
	var firstBarrierKey, secondBarrierKey int32
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT hashtext($1),hashtext($2)`, firstResource.ConcreteEscapedPath, secondResource.ConcreteEscapedPath).Scan(&firstBarrierKey, &secondBarrierKey); err != nil {
		t.Fatal(err)
	}
	if firstBarrierKey == secondBarrierKey {
		t.Fatalf("test resource advisory keys collided: %d", firstBarrierKey)
	}
	installConcreteHTTPResourceAcquisitionBarrier(t, env)
	observerConfig := env.store.Pool.Config().ConnConfig.Copy()
	observer, err := pgx.ConnectConfig(env.ctx, observerConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := observer.Close(context.Background()); err != nil {
			t.Errorf("close concrete HTTP resource acquisition observer: %v", err)
		}
	}()
	firstHolderPID, releaseFirstBarrier := holdResultIdentityInsertBarrierWithPID(t, env, domain.ID(firstResource.ConcreteEscapedPath))
	defer releaseFirstBarrier()
	secondHolderPID, releaseSecondBarrier := holdResultIdentityInsertBarrierWithPID(t, env, domain.ID(secondResource.ConcreteEscapedPath))
	defer releaseSecondBarrier()
	type candidate struct {
		fixture   scheduledResultFixture
		admission *capability.ResultAdmissionProvenance
		step      domain.StepRun
		tool      *domain.ToolRun
		artifacts []domain.Artifact
		result    domain.ActionResult
	}
	buildCandidate := func(fixture scheduledResultFixture, admission *capability.ResultAdmissionProvenance, records []provideroutput.Record, sources []normalize.AuthorizedSourceRecord) candidate {
		output, marshalErr := json.Marshal(map[string]any{"authorized_records": records, "authorized_source_records": sources})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		step, tool, artifacts, result := scheduledResultPayload(fixture, output)
		applyScheduledProviderAdmission(tool, &result, admission)
		return candidate{fixture: fixture, admission: admission, step: step, tool: tool, artifacts: artifacts, result: result}
	}
	first := buildCandidate(firstFixture, firstAdmission, firstRecords, firstSources)
	second := buildCandidate(secondFixture, secondAdmission, secondRecords, secondSources)
	firstConn, err := env.store.Pool.Acquire(env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer firstConn.Release()
	secondConn, err := env.store.Pool.Acquire(env.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer secondConn.Release()
	var firstPID, secondPID int32
	if err := firstConn.QueryRow(env.ctx, `SELECT pg_backend_pid()`).Scan(&firstPID); err != nil {
		t.Fatal(err)
	}
	if err := secondConn.QueryRow(env.ctx, `SELECT pg_backend_pid()`).Scan(&secondPID); err != nil {
		t.Fatal(err)
	}
	if firstPID == secondPID {
		t.Fatalf("concurrency proof reused backend pid %d", firstPID)
	}
	runCtx, cancel := context.WithTimeout(env.ctx, 10*time.Second)
	ready := make(chan struct{}, 2)
	start := make(chan struct{})
	results := make(chan error, 2)
	workersDone := make(chan struct{}, 2)
	startReleased := false
	releaseWorkers := func() {
		if startReleased {
			return
		}
		startReleased = true
		close(start)
	}
	defer func() {
		cancel()
		releaseWorkers()
		for range 2 {
			<-workersDone
		}
	}()
	run := func(conn *pgxpool.Conn, item candidate) {
		defer func() { workersDone <- struct{}{} }()
		tx, beginErr := conn.Begin(runCtx)
		if beginErr != nil {
			results <- beginErr
			return
		}
		defer tx.Rollback(context.Background())
		ready <- struct{}{}
		<-start
		ctx := WithScheduledExecutionFence(runCtx, item.fixture.fence)
		if persistErr := persistResultTransaction(ctx, tx, env.programID, item.step, item.tool, item.artifacts, item.result, item.admission); persistErr != nil {
			results <- persistErr
			return
		}
		results <- tx.Commit(ctx)
	}
	go run(firstConn, first)
	go run(secondConn, second)
	readyCount := 0
	for readyCount < 2 {
		select {
		case <-ready:
			readyCount++
		case err := <-results:
			cancel()
			releaseWorkers()
			t.Fatalf("canonical resource worker failed before readiness: %v", err)
		case <-runCtx.Done():
			releaseWorkers()
			t.Fatalf("canonical resource workers did not become ready: %v", runCtx.Err())
		}
	}
	releaseWorkers()
	firstWaitHolder, secondWaitHolder := waitForConcreteHTTPResourceAcquisition(t, runCtx, observer, firstHolderPID, secondHolderPID, firstPID, secondPID, results)
	releaseFirstBarrier()
	releaseSecondBarrier()
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("concurrent source persistence failed: %v", err)
			}
		case <-runCtx.Done():
			t.Fatalf("concurrent source persistence did not finish: %v", runCtx.Err())
		}
	}
	if firstWaitHolder != firstHolderPID || secondWaitHolder != firstHolderPID {
		t.Fatalf("attempt-dependent first resource acquisition holders=%d/%d want stable holder %d (other=%d)", firstWaitHolder, secondWaitHolder, firstHolderPID, secondHolderPID)
	}
	var resources, sources, attempts int
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT
		(SELECT count(*) FROM canonical_concrete_http_resources WHERE program_id=$1 AND host='lock-order.example.test'),
		(SELECT count(*) FROM probe_http_source_records WHERE program_id=$1 AND provider_attempt_id IN ($2,$3)),
		(SELECT count(DISTINCT provider_attempt_id) FROM probe_http_source_records WHERE program_id=$1 AND provider_attempt_id IN ($2,$3))`, env.programID, firstAdmission.ProviderAttemptID, secondAdmission.ProviderAttemptID).Scan(&resources, &sources, &attempts); err != nil {
		t.Fatal(err)
	}
	if resources != 2 || sources != 4 || attempts != 2 {
		t.Fatalf("resource arbitration resources=%d sources=%d attempts=%d pids=%d/%d", resources, sources, attempts, firstPID, secondPID)
	}
	assertProbeHTTPSourceProvenance(t, env, firstRecords, firstSources, firstAdmission)
	assertProbeHTTPSourceProvenance(t, env, secondRecords, secondSources, secondAdmission)
}

func TestProbeHTTPSourceTriggerRejectsDirectLineageSubstitutions(t *testing.T) {
	t.Run("wrong ToolRun StepRun", func(t *testing.T) {
		lineage := newDirectProbeHTTPSourceLineage(t, "direct-source-wrong-step", true, "probe.http", "fixture-provider", "fixture-provider")
		if err := lineage.insert(); err == nil || !strings.Contains(err.Error(), "lineage is inconsistent") {
			t.Fatalf("wrong ToolRun StepRun error=%v", err)
		}
	})
	t.Run("wrong ToolRun capability", func(t *testing.T) {
		lineage := newDirectProbeHTTPSourceLineage(t, "direct-source-wrong-capability", false, "classify.endpoint", "fixture-provider", "fixture-provider")
		if err := lineage.insert(); err == nil || !strings.Contains(err.Error(), "lineage is inconsistent") {
			t.Fatalf("wrong ToolRun capability error=%v", err)
		}
	})
	t.Run("wrong ToolRun provider", func(t *testing.T) {
		lineage := newDirectProbeHTTPSourceLineage(t, "direct-source-wrong-tool-provider", false, "probe.http", "other-provider", "fixture-provider")
		if err := lineage.insert(); err == nil || !strings.Contains(err.Error(), "lineage is inconsistent") {
			t.Fatalf("wrong ToolRun provider error=%v", err)
		}
	})
	t.Run("ProviderAttempt provider mismatch", func(t *testing.T) {
		lineage := newDirectProbeHTTPSourceLineage(t, "direct-source-provider-attempt-provider", false, "probe.http", "accepted-provider", "accepted-provider")
		if err := lineage.insert(); err == nil || !strings.Contains(err.Error(), "lineage is inconsistent") {
			t.Fatalf("ProviderAttempt provider mismatch error=%v", err)
		}
	})
	t.Run("mismatched accepted-event provider attempt", func(t *testing.T) {
		lineage := newDirectProbeHTTPSourceLineage(t, "direct-source-mismatched-attempt", false, "probe.http", "fixture-provider", "fixture-provider")
		otherAction := scheduledProviderAction(lineage.fixture, 2)
		otherAdmission := recordScheduledProviderAdmission(t, lineage.fixture, lineage.fixture.context(), lineage.fixture.env.programID, otherAction, nil, "fixture-provider")
		if err := lineage.insertWith(lineage.resourceID, lineage.observationID, lineage.acceptedEventID, otherAdmission.ProviderAttemptID); err == nil {
			t.Fatal("mismatched accepted-event provider attempt was accepted")
		}
	})
	t.Run("wrong AssetObservation emission pair", func(t *testing.T) {
		lineage := newDirectProbeHTTPSourceLineage(t, "direct-source-wrong-emission", false, "probe.http", "fixture-provider", "fixture-provider")
		observationID := domain.NewID()
		if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `INSERT INTO asset_observations(
			id,asset_id,workflow_run_id,source_capability,observed_value,first_seen_at,observed_at,confidence
		) VALUES($1,$2,$3,'probe.http',$4,clock_timestamp(),clock_timestamp(),1)`, observationID, lineage.assetID, lineage.fixture.lineage.runID, "https://unemitted.example.test/"); err != nil {
			t.Fatal(err)
		}
		if err := lineage.insertWith(lineage.resourceID, observationID, lineage.acceptedEventID, lineage.providerAttemptID); err == nil {
			t.Fatal("wrong AssetObservation/emission pair was accepted")
		}
	})
	t.Run("cross Program resource substitution", func(t *testing.T) {
		lineage := newDirectProbeHTTPSourceLineage(t, "direct-source-cross-program", false, "probe.http", "fixture-provider", "fixture-provider")
		otherProgramID, resourceID := directOtherProgramResource(t, lineage)
		if otherProgramID == lineage.fixture.env.programID {
			t.Fatal("cross-program fixture reused the source program")
		}
		if err := lineage.insertWith(resourceID, lineage.observationID, lineage.acceptedEventID, lineage.providerAttemptID); err == nil || !strings.Contains(err.Error(), "lineage is inconsistent") {
			t.Fatalf("cross-program resource error=%v", err)
		}
	})
}

func TestProbeHTTPSourceTriggerBindsStoredHierarchyAuthorizationAndScheduling(t *testing.T) {
	t.Run("StepRun WorkflowRun hierarchy", func(t *testing.T) {
		lineage := newDirectProbeHTTPSourceLineage(t, "direct-source-step-workflow", false, "probe.http", "fixture-provider", "fixture-provider")
		other := newScheduledResultFixtureInEnvironment(t, lineage.fixture.env, "direct-source-step-workflow-other", "probe.http")
		if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `UPDATE step_runs SET workflow_run_id=$2 WHERE id=$1`, lineage.fixture.stepID, other.lineage.runID); err != nil {
			t.Fatal(err)
		}
		if err := lineage.insert(); err == nil || !strings.Contains(err.Error(), "lineage is inconsistent") {
			t.Fatalf("inconsistent StepRun hierarchy error=%v", err)
		}
	})
	t.Run("WorkflowRun Task hierarchy", func(t *testing.T) {
		lineage := newDirectProbeHTTPSourceLineage(t, "direct-source-workflow-task", false, "probe.http", "fixture-provider", "fixture-provider")
		other := newScheduledResultFixtureInEnvironment(t, lineage.fixture.env, "direct-source-workflow-task-other", "probe.http")
		if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `UPDATE workflow_runs SET task_id=$2 WHERE id=$1`, lineage.fixture.lineage.runID, other.lineage.task.ID); err != nil {
			t.Fatal(err)
		}
		if err := lineage.insert(); err == nil || !strings.Contains(err.Error(), "lineage is inconsistent") {
			t.Fatalf("inconsistent WorkflowRun hierarchy error=%v", err)
		}
	})
	t.Run("Task Program hierarchy", func(t *testing.T) {
		lineage := newDirectProbeHTTPSourceLineage(t, "direct-source-task-program", false, "probe.http", "fixture-provider", "fixture-provider")
		otherProgramID, _ := directOtherProgramResource(t, lineage)
		if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `UPDATE tasks SET program_id=$2 WHERE id=$1`, lineage.fixture.lineage.task.ID, otherProgramID); err != nil {
			t.Fatal(err)
		}
		if err := lineage.insert(); err == nil || !strings.Contains(err.Error(), "lineage is inconsistent") {
			t.Fatalf("inconsistent Task hierarchy error=%v", err)
		}
	})
	t.Run("execution authorization semantics", func(t *testing.T) {
		lineage := newDirectProbeHTTPSourceLineage(t, "direct-source-authorization", false, "probe.http", "fixture-provider", "fixture-provider")
		acceptedEventID, providerAttemptID := lineage.invalidAuthorizationAcceptedEvent(t)
		if err := lineage.insertWith(lineage.resourceID, lineage.observationID, acceptedEventID, providerAttemptID); err == nil || !strings.Contains(err.Error(), "lineage is inconsistent") {
			t.Fatalf("invalid execution authorization error=%v", err)
		}
	})
	for _, field := range []string{"queue_job_id", "scheduled_execution_id", "scheduler_attempt"} {
		t.Run(field+" mismatch", func(t *testing.T) {
			lineage := newDirectProbeHTTPSourceLineage(t, "direct-source-"+field, false, "probe.http", "fixture-provider", "fixture-provider")
			acceptedEventID := lineage.acceptedEventWithSchedulingMismatch(t, field)
			if err := lineage.insertWith(lineage.resourceID, lineage.observationID, acceptedEventID, lineage.providerAttemptID); err == nil || !strings.Contains(err.Error(), "lineage is inconsistent") {
				t.Fatalf("%s mismatch error=%v", field, err)
			}
		})
	}
}

func TestProbeHTTPSourceArtifactLineageAndReferencedIdentityGuards(t *testing.T) {
	t.Run("wrong artifact identity is rejected", func(t *testing.T) {
		lineage := newDirectProbeHTTPSourceLineage(t, "direct-source-artifact-lineage", false, "probe.http", "fixture-provider", "fixture-provider")
		other := newScheduledResultFixtureInEnvironment(t, lineage.fixture.env, "direct-source-artifact-other", "probe.http")
		otherToolID := domain.NewID()
		if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at) VALUES($1,$2,'probe.http','fixture-provider',clock_timestamp())`, otherToolID, other.stepID); err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			name                       string
			taskID, workflowID, stepID domain.ID
			toolID                     domain.ID
			artifactType               string
		}{
			{name: "task", taskID: other.lineage.task.ID, workflowID: lineage.fixture.lineage.runID, stepID: lineage.fixture.stepID, toolID: lineage.toolID, artifactType: "normalized-result"},
			{name: "workflow", taskID: lineage.fixture.lineage.task.ID, workflowID: other.lineage.runID, stepID: lineage.fixture.stepID, toolID: lineage.toolID, artifactType: "normalized-result"},
			{name: "step", taskID: lineage.fixture.lineage.task.ID, workflowID: lineage.fixture.lineage.runID, stepID: other.stepID, toolID: lineage.toolID, artifactType: "normalized-result"},
			{name: "tool", taskID: lineage.fixture.lineage.task.ID, workflowID: lineage.fixture.lineage.runID, stepID: lineage.fixture.stepID, toolID: otherToolID, artifactType: "normalized-result"},
			{name: "type", taskID: lineage.fixture.lineage.task.ID, workflowID: lineage.fixture.lineage.runID, stepID: lineage.fixture.stepID, toolID: lineage.toolID, artifactType: "raw-provider-output"},
		} {
			t.Run(test.name, func(t *testing.T) {
				artifactID := insertDirectSourceArtifact(t, lineage, test.taskID, test.workflowID, test.stepID, test.toolID, test.artifactType)
				if err := lineage.insertWithArtifact(artifactID); err == nil || !strings.Contains(err.Error(), "artifact lineage is inconsistent") {
					t.Fatalf("wrong artifact %s error=%v", test.name, err)
				}
			})
		}
	})

	t.Run("referenced identity is immutable while lifecycle and retention remain available", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "concrete-http-source-identity-guards", "probe.http")
		action := scheduledProviderAction(fixture, 1)
		admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, nil, "fixture-provider")
		records := []provideroutput.Record{{Provider: "httpx", Kind: provideroutput.URLRecord, Target: "https://guarded.example.test/", StatusCode: 200, Fields: map[string]any{}}}
		sources, err := normalize.BuildProbeHTTPSourceRecords(string(fixture.env.programID), string(admission.ProviderAttemptID), records, normalize.RequestSemantics{Method: normalize.ValueSemantics{State: normalize.ValueDefaulted, Value: databaseSourceString("GET")}, ContentType: normalize.ValueSemantics{State: normalize.ValueUnknown}})
		if err != nil {
			t.Fatal(err)
		}
		output, err := json.Marshal(map[string]any{"authorized_records": records, "authorized_source_records": sources})
		if err != nil {
			t.Fatal(err)
		}
		step, tool, artifacts, result := scheduledResultPayload(fixture, output)
		applyScheduledProviderAdmission(tool, &result, admission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission); err != nil {
			t.Fatal(err)
		}
		other := newScheduledResultFixtureInEnvironment(t, fixture.env, "concrete-http-source-identity-other", "probe.http")
		otherAdmission := recordScheduledProviderAdmission(t, other, other.context(), other.env.programID, scheduledProviderAction(other, 1), nil, "fixture-provider")
		otherToolID := domain.NewID()
		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO tool_runs(id,step_run_id,capability,provider,started_at) VALUES($1,$2,'probe.http','fixture-provider',clock_timestamp())`, otherToolID, other.stepID); err != nil {
			t.Fatal(err)
		}
		otherProgramID, _ := directOtherProgramResource(t, directProbeHTTPSourceLineage{fixture: fixture})
		updates := []struct {
			name  string
			query string
			args  []any
		}{
			{name: "ToolRun id", query: `UPDATE tool_runs SET id=$2 WHERE id=$1`, args: []any{tool.ID, domain.NewID()}},
			{name: "ToolRun StepRun", query: `UPDATE tool_runs SET step_run_id=$2 WHERE id=$1`, args: []any{tool.ID, other.stepID}},
			{name: "ToolRun capability", query: `UPDATE tool_runs SET capability='classify.endpoint' WHERE id=$1`, args: []any{tool.ID}},
			{name: "ToolRun provider", query: `UPDATE tool_runs SET provider='other-provider' WHERE id=$1`, args: []any{tool.ID}},
			{name: "ToolRun ProviderAttempt", query: `UPDATE tool_runs SET provider_attempt_id=$2 WHERE id=$1`, args: []any{tool.ID, otherAdmission.ProviderAttemptID}},
			{name: "StepRun WorkflowRun", query: `UPDATE step_runs SET workflow_run_id=$2 WHERE id=$1`, args: []any{fixture.stepID, other.lineage.runID}},
			{name: "StepRun capability", query: `UPDATE step_runs SET capability='classify.endpoint' WHERE id=$1`, args: []any{fixture.stepID}},
			{name: "WorkflowRun Task", query: `UPDATE workflow_runs SET task_id=$2 WHERE id=$1`, args: []any{fixture.lineage.runID, other.lineage.task.ID}},
			{name: "Task Program", query: `UPDATE tasks SET program_id=$2 WHERE id=$1`, args: []any{fixture.lineage.task.ID, otherProgramID}},
			{name: "artifact id", query: `UPDATE artifacts SET id=$2 WHERE id=$1`, args: []any{artifacts[0].ID, domain.NewID()}},
			{name: "artifact Task", query: `UPDATE artifacts SET task_id=$2 WHERE id=$1`, args: []any{artifacts[0].ID, other.lineage.task.ID}},
			{name: "artifact WorkflowRun", query: `UPDATE artifacts SET workflow_run_id=$2 WHERE id=$1`, args: []any{artifacts[0].ID, other.lineage.runID}},
			{name: "artifact StepRun", query: `UPDATE artifacts SET step_run_id=$2 WHERE id=$1`, args: []any{artifacts[0].ID, other.stepID}},
			{name: "artifact ToolRun", query: `UPDATE artifacts SET tool_run_id=$2 WHERE id=$1`, args: []any{artifacts[0].ID, otherToolID}},
			{name: "artifact type", query: `UPDATE artifacts SET type='raw-provider-output' WHERE id=$1`, args: []any{artifacts[0].ID}},
		}
		for _, update := range updates {
			if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, update.query, update.args...); err == nil || !strings.Contains(err.Error(), "identity is immutable") {
				t.Fatalf("%s mutation error=%v", update.name, err)
			}
		}
		for _, statement := range []string{
			`UPDATE tool_runs SET completed_at=clock_timestamp() WHERE id=$1`,
			`UPDATE step_runs SET completed_at=clock_timestamp() WHERE id=$1`,
			`UPDATE workflow_runs SET status='completed' WHERE id=$1`,
			`UPDATE tasks SET status='completed',updated_at=clock_timestamp() WHERE id=$1`,
			`UPDATE artifacts SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`,
		} {
			id := any(tool.ID)
			switch {
			case strings.Contains(statement, "step_runs"):
				id = fixture.stepID
			case strings.Contains(statement, "workflow_runs"):
				id = fixture.lineage.runID
			case strings.Contains(statement, "tasks"):
				id = fixture.lineage.task.ID
			case strings.Contains(statement, "artifacts"):
				id = artifacts[0].ID
			}
			if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, statement, id); err != nil {
				t.Fatalf("allowed lifecycle update failed: %v", err)
			}
		}
		if err := fixture.env.store.DeleteArtifact(fixture.env.ctx, artifacts[0].ID); err != nil {
			t.Fatalf("retention delete: %v", err)
		}
		var artifactCount, sourceCount int
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT (SELECT count(*) FROM artifacts WHERE id=$1),(SELECT count(*) FROM probe_http_source_records WHERE normalized_result_artifact_id=$1)`, artifacts[0].ID).Scan(&artifactCount, &sourceCount); err != nil {
			t.Fatal(err)
		}
		if artifactCount != 0 || sourceCount != 1 {
			t.Fatalf("retention artifact=%d source_occurrences=%d", artifactCount, sourceCount)
		}
		reinsertArtifact := func(artifact domain.Artifact) error {
			_, insertErr := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO artifacts(
				id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,storage_location,created_at,expires_at,redaction_state,sensitive
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, artifact.ID, artifact.TaskID, artifact.WorkflowRunID, artifact.StepRunID, artifact.ToolRunID, artifact.Type, artifact.ContentType, artifact.Size, artifact.SHA256, artifact.StorageLocation, artifact.CreatedAt, artifact.ExpiresAt, artifact.RedactionState, artifact.Sensitive)
			return insertErr
		}
		for _, test := range []struct {
			name   string
			mutate func(*domain.Artifact)
		}{
			{name: "Task", mutate: func(artifact *domain.Artifact) { artifact.TaskID = other.lineage.task.ID }},
			{name: "WorkflowRun", mutate: func(artifact *domain.Artifact) { artifact.WorkflowRunID = other.lineage.runID }},
			{name: "StepRun", mutate: func(artifact *domain.Artifact) { artifact.StepRunID = other.stepID }},
			{name: "ToolRun", mutate: func(artifact *domain.Artifact) { artifact.ToolRunID = otherToolID }},
			{name: "type", mutate: func(artifact *domain.Artifact) { artifact.Type = "raw-provider-output" }},
		} {
			t.Run("same UUID wrong "+test.name, func(t *testing.T) {
				candidate := artifacts[0]
				test.mutate(&candidate)
				if err := reinsertArtifact(candidate); err == nil || !strings.Contains(err.Error(), "cannot be rebound") {
					t.Fatalf("same-UUID %s reinsert error=%v", test.name, err)
				}
			})
		}
		if err := reinsertArtifact(artifacts[0]); err != nil {
			t.Fatalf("same-lineage artifact reinsert: %v", err)
		}
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT (SELECT count(*) FROM artifacts WHERE id=$1),(SELECT count(*) FROM probe_http_source_records WHERE normalized_result_artifact_id=$1)`, artifacts[0].ID).Scan(&artifactCount, &sourceCount); err != nil {
			t.Fatal(err)
		}
		if artifactCount != 1 || sourceCount != 1 {
			t.Fatalf("same-lineage reinsert artifact=%d source_occurrences=%d", artifactCount, sourceCount)
		}
	})
}

type directProbeHTTPSourceLineage struct {
	fixture           scheduledResultFixture
	providerAttemptID domain.ID
	acceptedEventID   domain.ID
	toolID            domain.ID
	resourceID        domain.ID
	assetID           domain.ID
	observationID     domain.ID
}

func newDirectProbeHTTPSourceLineage(t *testing.T, name string, differentToolStep bool, toolCapability, toolProvider, acceptedProvider string) directProbeHTTPSourceLineage {
	t.Helper()
	fixture := newScheduledResultFixture(t, name, "probe.http")
	return newDirectProbeHTTPSourceLineageInFixture(t, fixture, differentToolStep, toolCapability, toolProvider, acceptedProvider)
}

func newDirectProbeHTTPSourceLineageInFixture(t *testing.T, fixture scheduledResultFixture, differentToolStep bool, toolCapability, toolProvider, acceptedProvider string) directProbeHTTPSourceLineage {
	t.Helper()
	action := scheduledProviderAction(fixture, 1)
	queueJobID := domain.NewID()
	admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, action, &queueJobID, "fixture-provider")
	toolStepID := fixture.stepID
	if differentToolStep {
		toolStepID = domain.NewID()
		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO step_runs(
			id,workflow_run_id,step_definition_id,capability,status,input,idempotency_key
		) VALUES($1,$2,'direct-lineage-other-step','probe.http','running','{}'::jsonb,$3)`, toolStepID, fixture.lineage.runID, "direct-lineage-"+string(toolStepID)); err != nil {
			t.Fatal(err)
		}
	}
	toolID := domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO tool_runs(
		id,step_run_id,capability,provider,started_at,provider_attempt_id
	) VALUES($1,$2,$3,$4,clock_timestamp(),$5)`, toolID, toolStepID, toolCapability, toolProvider, admission.ProviderAttemptID); err != nil {
		t.Fatal(err)
	}
	acceptedEventID := domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO audit_events(
		id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,tool_run_id,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,execution_authorization_event_id,provider_attempt_id,
		capability,provider,safe_message,details
	) SELECT $1,'provider_result_accepted','integration','integration',task_id,program_id,workflow_run_id,step_run_id,$2,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,execution_authorization_event_id,$3,'probe.http',$4,
		'direct source trigger fixture','{}'::jsonb
		FROM audit_events WHERE id=$3`, acceptedEventID, toolID, admission.ProviderAttemptID, acceptedProvider); err != nil {
		t.Fatal(err)
	}
	assetID := domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO assets(id,program_id,type,canonical_value) VALUES($1,$2,'http_service',$3)`, assetID, fixture.env.programID, "https://direct-source.example.test/"); err != nil {
		t.Fatal(err)
	}
	observationID := domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO asset_observations(
		id,asset_id,workflow_run_id,source_capability,observed_value,first_seen_at,observed_at,confidence
	) VALUES($1,$2,$3,'probe.http',$4,clock_timestamp(),clock_timestamp(),1)`, observationID, assetID, fixture.lineage.runID, "https://direct-source.example.test/"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO asset_observation_emissions(
		program_id,asset_observation_id,provider_result_accepted_event_id
	) VALUES($1,$2,$3)`, fixture.env.programID, observationID, acceptedEventID); err != nil {
		t.Fatal(err)
	}
	resourceID := domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO canonical_concrete_http_resources(
		id,program_id,identity_namespace,scheme,host,effective_port,concrete_escaped_path,canonical_query
	) VALUES($1,$2,'http-uri-resource-v1','https','direct-source.example.test',443,'/','')`, resourceID, fixture.env.programID); err != nil {
		t.Fatal(err)
	}
	return directProbeHTTPSourceLineage{fixture: fixture, providerAttemptID: admission.ProviderAttemptID, acceptedEventID: acceptedEventID, toolID: toolID, resourceID: resourceID, assetID: assetID, observationID: observationID}
}

func (lineage directProbeHTTPSourceLineage) acceptedEventWithSchedulingMismatch(t *testing.T, field string) domain.ID {
	t.Helper()
	acceptedEventID := domain.NewID()
	if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `INSERT INTO audit_events(
		id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,tool_run_id,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,
		execution_authorization_event_id,provider_attempt_id,capability,provider,safe_message,details
	) SELECT $1,'provider_result_accepted','integration','integration',task_id,program_id,workflow_run_id,step_run_id,$2,
		CASE WHEN $4='scheduled_execution_id' THEN NULL ELSE scheduled_execution_id END,
		CASE WHEN $4='scheduler_attempt' THEN NULL ELSE scheduler_attempt END,
		action_request_id,step_attempt,
		CASE WHEN $4='queue_job_id' THEN NULL ELSE queue_job_id END,
		execution_authorization_event_id,$3,capability,provider,'mismatched scheduling fixture','{}'::jsonb
		FROM audit_events WHERE id=$3`, acceptedEventID, lineage.toolID, lineage.providerAttemptID, field); err != nil {
		t.Fatal(err)
	}
	lineage.insertEmission(t, acceptedEventID)
	return acceptedEventID
}

func (lineage directProbeHTTPSourceLineage) invalidAuthorizationAcceptedEvent(t *testing.T) (domain.ID, domain.ID) {
	t.Helper()
	authorizationID := domain.NewID()
	if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `INSERT INTO audit_events(
		id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,
		capability,provider,safe_message,details
	) SELECT $1,'policy_allowed','policy','integration',task_id,program_id,workflow_run_id,step_run_id,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,
		capability,provider,'non-execution authorization','{"phase":"planning"}'::jsonb
		FROM audit_events WHERE id=$2`, authorizationID, lineage.providerAttemptID); err != nil {
		t.Fatal(err)
	}
	providerAttemptID := domain.NewID()
	if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `INSERT INTO audit_events(
		id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,
		execution_authorization_event_id,capability,provider,safe_message,details
	) SELECT $1,'provider_invocation_started','provider','integration',task_id,program_id,workflow_run_id,step_run_id,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,
		$2,capability,provider,'invalid authorization provider start','{}'::jsonb
		FROM audit_events WHERE id=$3`, providerAttemptID, authorizationID, lineage.providerAttemptID); err != nil {
		t.Fatal(err)
	}
	toolID := domain.NewID()
	if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `INSERT INTO tool_runs(
		id,step_run_id,capability,provider,started_at,provider_attempt_id
	) SELECT $1,step_run_id,capability,provider,clock_timestamp(),$2 FROM audit_events WHERE id=$2`, toolID, providerAttemptID); err != nil {
		t.Fatal(err)
	}
	acceptedEventID := domain.NewID()
	if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `INSERT INTO audit_events(
		id,event_type,component,actor,task_id,program_id,workflow_run_id,step_run_id,tool_run_id,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,
		execution_authorization_event_id,provider_attempt_id,capability,provider,safe_message,details
	) SELECT $1,'provider_result_accepted','integration','integration',task_id,program_id,workflow_run_id,step_run_id,$2,
		scheduled_execution_id,scheduler_attempt,action_request_id,step_attempt,queue_job_id,
		execution_authorization_event_id,$3,capability,provider,'invalid authorization accepted event','{}'::jsonb
		FROM audit_events WHERE id=$3`, acceptedEventID, toolID, providerAttemptID); err != nil {
		t.Fatal(err)
	}
	lineage.insertEmission(t, acceptedEventID)
	return acceptedEventID, providerAttemptID
}

func (lineage directProbeHTTPSourceLineage) insertEmission(t *testing.T, acceptedEventID domain.ID) {
	t.Helper()
	if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `INSERT INTO asset_observation_emissions(
		program_id,asset_observation_id,provider_result_accepted_event_id
	) VALUES($1,$2,$3)`, lineage.fixture.env.programID, lineage.observationID, acceptedEventID); err != nil {
		t.Fatal(err)
	}
}

func (lineage directProbeHTTPSourceLineage) insert() error {
	return lineage.insertWith(lineage.resourceID, lineage.observationID, lineage.acceptedEventID, lineage.providerAttemptID)
}

func (lineage directProbeHTTPSourceLineage) insertWith(resourceID, observationID, acceptedEventID, providerAttemptID domain.ID) error {
	locator := strings.ReplaceAll(string(domain.NewID()), "-", "") + strings.Repeat("0", 32)
	return lineage.insertWithLocatorAndArtifact(locator, resourceID, observationID, acceptedEventID, providerAttemptID, nil)
}

func (lineage directProbeHTTPSourceLineage) insertWithArtifact(artifactID domain.ID) error {
	locator := strings.ReplaceAll(string(domain.NewID()), "-", "") + strings.Repeat("0", 32)
	return lineage.insertWithLocatorAndArtifact(locator, lineage.resourceID, lineage.observationID, lineage.acceptedEventID, lineage.providerAttemptID, &artifactID)
}

func (lineage directProbeHTTPSourceLineage) insertWithLocator(locator string, resourceID, observationID, acceptedEventID, providerAttemptID domain.ID) error {
	return lineage.insertWithLocatorAndArtifact(locator, resourceID, observationID, acceptedEventID, providerAttemptID, nil)
}

func (lineage directProbeHTTPSourceLineage) insertWithLocatorAndArtifact(locator string, resourceID, observationID, acceptedEventID, providerAttemptID domain.ID, artifactID *domain.ID) error {
	_, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `INSERT INTO probe_http_source_records(
		source_locator,program_id,concrete_http_resource_id,asset_observation_id,provider_result_accepted_event_id,
		provider_attempt_id,normalized_result_artifact_id,authorized_record_index,record_digest,request_method_state,request_method_value,
		request_content_type_state,request_content_type_value,identity_namespace,derivation_version
	) VALUES($1,$2,$3,$4,$5,$6,$7,0,$8,'defaulted','GET','unknown',NULL,'http-uri-resource-v1','http-resource-derivation-v1')`,
		locator, lineage.fixture.env.programID, resourceID, observationID, acceptedEventID, providerAttemptID, artifactID, strings.Repeat("a", 64))
	return err
}

func directOtherProgramResource(t *testing.T, lineage directProbeHTTPSourceLineage) (domain.ID, domain.ID) {
	t.Helper()
	programID := domain.NewID()
	if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `INSERT INTO programs(
		id,name,platform,scope_reference,policy_reference
	) VALUES($1,$2,'integration','scope','policy')`, programID, "direct-source-program-"+string(programID)); err != nil {
		t.Fatal(err)
	}
	resourceID := domain.NewID()
	if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `INSERT INTO canonical_concrete_http_resources(
		id,program_id,identity_namespace,scheme,host,effective_port,concrete_escaped_path,canonical_query
	) VALUES($1,$2,'http-uri-resource-v1','https','other-program.example.test',443,'/','')`, resourceID, programID); err != nil {
		t.Fatal(err)
	}
	return programID, resourceID
}

func insertDirectSourceArtifact(t *testing.T, lineage directProbeHTTPSourceLineage, taskID, workflowRunID, stepRunID, toolRunID domain.ID, artifactType string) domain.ID {
	t.Helper()
	artifactID := domain.NewID()
	if _, err := lineage.fixture.env.store.Pool.Exec(lineage.fixture.env.ctx, `INSERT INTO artifacts(
		id,task_id,workflow_run_id,step_run_id,tool_run_id,type,content_type,size,sha256,storage_location,redaction_state
	) VALUES($1,$2,$3,$4,$5,$6,'application/json',2,$7,$8,'redacted')`, artifactID, taskID, workflowRunID, stepRunID, toolRunID, artifactType, strings.Repeat("a", 64), "synthetic://"+string(artifactID)); err != nil {
		t.Fatal(err)
	}
	return artifactID
}

func probeSourceCanonicalOrder(t *testing.T, records []provideroutput.Record, sources []normalize.AuthorizedSourceRecord) []string {
	t.Helper()
	order := make([]string, 0, len(sources))
	for _, source := range sources {
		resource, err := normalize.ConcreteHTTPResource(records[source.AuthorizedRecordIndex].Target)
		if err != nil {
			t.Fatal(err)
		}
		order = append(order, resource.CanonicalURL)
	}
	return order
}

func probeHTTPSourceStateSnapshot(t *testing.T, fixture scheduledResultFixture) string {
	t.Helper()
	base := resultFenceSnapshot(t, fixture)
	var sources string
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT jsonb_build_object(
		'resources',(SELECT COALESCE(jsonb_agg(to_jsonb(resource) ORDER BY resource.id),'[]'::jsonb) FROM canonical_concrete_http_resources resource WHERE resource.program_id=$1),
		'sources',(SELECT COALESCE(jsonb_agg(to_jsonb(source) ORDER BY source.source_locator),'[]'::jsonb) FROM probe_http_source_records source WHERE source.program_id=$1)
	)::text`, fixture.env.programID).Scan(&sources); err != nil {
		t.Fatal(err)
	}
	return base + "\n" + sources
}

type probeHTTPPersistenceOutcome struct {
	index int
	err   error
}

func assertOnlyProviderResultRejectedReason(t *testing.T, fixture scheduledResultFixture, providerAttemptID domain.ID, reason resultFenceReasonCode) {
	t.Helper()
	var total, matching int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
		count(*),count(*) FILTER (WHERE details->>'reason_code'=$2)
		FROM audit_events
		WHERE provider_attempt_id=$1 AND event_type='provider_result_rejected'`, providerAttemptID, string(reason)).Scan(&total, &matching); err != nil {
		t.Fatal(err)
	}
	if total != 1 || matching != 1 {
		t.Fatalf("provider result rejections total=%d matching_%s=%d", total, reason, matching)
	}
}

func assertNoProbeHTTP3AState(t *testing.T, fixture scheduledResultFixture) {
	t.Helper()
	var resources, sources, emissions int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
		(SELECT count(*) FROM canonical_concrete_http_resources WHERE program_id=$1),
		(SELECT count(*) FROM probe_http_source_records WHERE program_id=$1),
		(SELECT count(*) FROM asset_observation_emissions emission JOIN asset_observations observation ON observation.id=emission.asset_observation_id WHERE observation.workflow_run_id=$2)`, fixture.env.programID, fixture.lineage.runID).Scan(&resources, &sources, &emissions); err != nil {
		t.Fatal(err)
	}
	if resources != 0 || sources != 0 || emissions != 0 {
		t.Fatalf("unexpected Slice 3A state resources=%d sources=%d emissions=%d", resources, sources, emissions)
	}
}

func cleanupResultIdentityInsertBarrier(t *testing.T, env recoveryTestEnvironment) {
	t.Helper()
	t.Cleanup(func() {
		if _, err := env.store.Pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS result_tool_identity_insert_barrier ON tool_runs;
			DROP TRIGGER IF EXISTS result_artifact_identity_insert_barrier ON artifacts;
			DROP FUNCTION IF EXISTS result_identity_insert_barrier()`); err != nil {
			t.Errorf("remove result identity insert barrier: %v", err)
		}
	})
}

func waitForBlockedDatabaseQueryCount(t *testing.T, ctx context.Context, store *Store, outcomes <-chan probeHTTPPersistenceOutcome, queryPattern string, want int) {
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
		if waiting >= want {
			return
		}
		select {
		case outcome := <-outcomes:
			t.Fatalf("persistence candidate %d returned before %d queries reached the PostgreSQL barrier: %v", outcome.index, want, outcome.err)
		case <-ctx.Done():
			t.Fatalf("%d persistence queries did not reach the PostgreSQL barrier: %v", want, ctx.Err())
		case <-ticker.C:
		}
	}
}

func installProbeHTTPSourceInsertProofBarrier(t *testing.T, env recoveryTestEnvironment) {
	t.Helper()
	if _, err := env.store.Pool.Exec(env.ctx, `CREATE FUNCTION probe_http_source_insert_proof_barrier() RETURNS trigger AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(hashtext(NEW.source_locator));
			RETURN NEW;
		END;
	$$ LANGUAGE plpgsql;
	CREATE TRIGGER probe_http_source_insert_proof_barrier
	AFTER INSERT ON probe_http_source_records
	FOR EACH ROW EXECUTE FUNCTION probe_http_source_insert_proof_barrier()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := env.store.Pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS probe_http_source_insert_proof_barrier ON probe_http_source_records;
			DROP FUNCTION IF EXISTS probe_http_source_insert_proof_barrier()`); err != nil {
			t.Errorf("remove probe HTTP source insert proof barrier: %v", err)
		}
	})
}

func waitForProbeHTTPSourceInsertProof(t *testing.T, ctx context.Context, store *Store, holderPID int32, result <-chan error) int32 {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waitingPID int32
		if err := store.Pool.QueryRow(ctx, `SELECT COALESCE(max(waiting_lock.pid),0)
			FROM pg_locks waiting_lock
			JOIN pg_locks held_lock
			  ON held_lock.locktype=waiting_lock.locktype
			 AND held_lock.database IS NOT DISTINCT FROM waiting_lock.database
			 AND held_lock.classid IS NOT DISTINCT FROM waiting_lock.classid
			 AND held_lock.objid IS NOT DISTINCT FROM waiting_lock.objid
			 AND held_lock.objsubid IS NOT DISTINCT FROM waiting_lock.objsubid
			 AND held_lock.mode=waiting_lock.mode
			JOIN pg_stat_activity activity ON activity.pid=waiting_lock.pid
			WHERE waiting_lock.locktype='advisory'
			  AND NOT waiting_lock.granted
			  AND held_lock.pid=$1
			  AND held_lock.granted
			  AND activity.query LIKE '%INSERT INTO probe_http_source_records(%'`, holderPID).Scan(&waitingPID); err != nil {
			t.Fatal(err)
		}
		if waitingPID != 0 {
			return waitingPID
		}
		select {
		case err := <-result:
			t.Fatalf("source persistence returned before the successful source INSERT reached its AFTER INSERT barrier: %v", err)
		case <-ctx.Done():
			t.Fatalf("successful source INSERT did not reach its AFTER INSERT barrier: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func installConcreteHTTPResourceAcquisitionBarrier(t *testing.T, env recoveryTestEnvironment) {
	t.Helper()
	if _, err := env.store.Pool.Exec(env.ctx, `CREATE FUNCTION concrete_http_resource_acquisition_barrier() RETURNS trigger AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(hashtext(NEW.concrete_escaped_path));
			RETURN NEW;
		END;
	$$ LANGUAGE plpgsql;
	CREATE TRIGGER concrete_http_resource_acquisition_barrier
	BEFORE INSERT ON canonical_concrete_http_resources
	FOR EACH ROW EXECUTE FUNCTION concrete_http_resource_acquisition_barrier()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := env.store.Pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS concrete_http_resource_acquisition_barrier ON canonical_concrete_http_resources;
			DROP FUNCTION IF EXISTS concrete_http_resource_acquisition_barrier()`); err != nil {
			t.Errorf("remove concrete HTTP resource acquisition barrier: %v", err)
		}
	})
}

func waitForConcreteHTTPResourceAcquisition(t *testing.T, ctx context.Context, observer *pgx.Conn, firstHolderPID, secondHolderPID, firstPID, secondPID int32, results <-chan error) (int32, int32) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var firstWaitHolder, secondWaitHolder int32
		if err := observer.QueryRow(ctx, `SELECT
			COALESCE(max(held_lock.pid) FILTER (WHERE waiting_lock.pid=$1),0),
			COALESCE(max(held_lock.pid) FILTER (WHERE waiting_lock.pid=$2),0)
			FROM pg_locks waiting_lock
			JOIN pg_locks held_lock
			  ON held_lock.locktype=waiting_lock.locktype
			 AND held_lock.database IS NOT DISTINCT FROM waiting_lock.database
			 AND held_lock.classid IS NOT DISTINCT FROM waiting_lock.classid
			 AND held_lock.objid IS NOT DISTINCT FROM waiting_lock.objid
			 AND held_lock.objsubid IS NOT DISTINCT FROM waiting_lock.objsubid
			 AND held_lock.mode=waiting_lock.mode
			JOIN pg_stat_activity activity ON activity.pid=waiting_lock.pid
			WHERE waiting_lock.pid IN ($1,$2)
			  AND held_lock.pid IN ($3,$4)
			  AND waiting_lock.locktype='advisory'
			  AND NOT waiting_lock.granted
			  AND held_lock.granted
			  AND activity.query LIKE '%INSERT INTO canonical_concrete_http_resources(%'`, firstPID, secondPID, firstHolderPID, secondHolderPID).Scan(&firstWaitHolder, &secondWaitHolder); err != nil {
			t.Fatal(err)
		}
		if firstWaitHolder != 0 && secondWaitHolder != 0 {
			return firstWaitHolder, secondWaitHolder
		}
		select {
		case err := <-results:
			t.Fatalf("canonical resource persistence returned before both exact backends reached the acquisition barrier: %v", err)
		case <-ctx.Done():
			t.Fatalf("both exact canonical-resource backends did not reach the acquisition barrier: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func assertProbeHTTPSourceProvenance(t *testing.T, env recoveryTestEnvironment, records []provideroutput.Record, sources []normalize.AuthorizedSourceRecord, admission *capability.ResultAdmissionProvenance) {
	t.Helper()
	var expectedAcceptedEventID domain.ID
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT id FROM audit_events WHERE event_type='provider_result_accepted' AND provider_attempt_id=$1`, admission.ProviderAttemptID).Scan(&expectedAcceptedEventID); err != nil {
		t.Fatal(err)
	}
	for _, source := range sources {
		record := records[source.AuthorizedRecordIndex]
		expectedResource, err := normalize.ConcreteHTTPResource(record.Target)
		if err != nil {
			t.Fatal(err)
		}
		var namespace, scheme, host, escapedPath, canonicalQuery, recordDigest, observedValue string
		var effectivePort, authorizedRecordIndex int
		var providerAttemptID, acceptedEventID, acceptedAttemptID, observationID, emissionObservationID, emissionAcceptedEventID domain.ID
		if err := env.store.Pool.QueryRow(env.ctx, `SELECT
			resource.identity_namespace,resource.scheme,resource.host,resource.effective_port,resource.concrete_escaped_path,resource.canonical_query,
			source.authorized_record_index,source.record_digest,source.provider_attempt_id,source.provider_result_accepted_event_id,
			accepted_event.provider_attempt_id,observation.id,observation.observed_value,
			emission.asset_observation_id,emission.provider_result_accepted_event_id
			FROM probe_http_source_records source
			JOIN canonical_concrete_http_resources resource ON resource.id=source.concrete_http_resource_id
			JOIN audit_events accepted_event ON accepted_event.id=source.provider_result_accepted_event_id
			JOIN asset_observations observation ON observation.id=source.asset_observation_id
			JOIN asset_observation_emissions emission
			  ON emission.asset_observation_id=source.asset_observation_id
			 AND emission.provider_result_accepted_event_id=source.provider_result_accepted_event_id
			WHERE source.source_locator=$1`, source.SourceLocator).Scan(
			&namespace, &scheme, &host, &effectivePort, &escapedPath, &canonicalQuery,
			&authorizedRecordIndex, &recordDigest, &providerAttemptID, &acceptedEventID,
			&acceptedAttemptID, &observationID, &observedValue, &emissionObservationID, &emissionAcceptedEventID,
		); err != nil {
			t.Fatal(err)
		}
		if namespace != expectedResource.IdentityNamespace || scheme != expectedResource.Scheme || host != expectedResource.Host || effectivePort != expectedResource.EffectivePort || escapedPath != expectedResource.ConcreteEscapedPath || canonicalQuery != expectedResource.CanonicalQuery {
			t.Fatalf("locator %s resource=%s/%s/%s/%d/%s?%s want=%#v", source.SourceLocator, namespace, scheme, host, effectivePort, escapedPath, canonicalQuery, expectedResource)
		}
		if authorizedRecordIndex != source.AuthorizedRecordIndex || recordDigest != source.RecordDigest || providerAttemptID != admission.ProviderAttemptID || acceptedAttemptID != admission.ProviderAttemptID || acceptedEventID != expectedAcceptedEventID || observedValue != record.Target || emissionObservationID != observationID || emissionAcceptedEventID != expectedAcceptedEventID {
			t.Fatalf("locator %s provenance index=%d digest=%s attempt=%s accepted_attempt=%s accepted=%s observation=%s/%s emission=%s/%s", source.SourceLocator, authorizedRecordIndex, recordDigest, providerAttemptID, acceptedAttemptID, acceptedEventID, observationID, observedValue, emissionObservationID, emissionAcceptedEventID)
		}
	}
}

func databaseSourceString(value string) *string { return &value }
