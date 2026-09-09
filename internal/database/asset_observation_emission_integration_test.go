package database

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestAssetObservationEmissionCardinality(t *testing.T) {
	t.Run("one exact successful result emits one occurrence", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "observation-emission-one", "probe.http")
		admission, _, _ := persistExactObservationResult(t, fixture, 1, json.RawMessage(`{"lines":["https://one.test/"]}`))
		assertObservationEmissionCounts(t, fixture, 1, 1)
		_, providerAttemptID := loadSingleObservationEmission(t, fixture)
		if providerAttemptID != admission.ProviderAttemptID {
			t.Fatalf("emission provider attempt=%s want=%s", providerAttemptID, admission.ProviderAttemptID)
		}
	})

	t.Run("multiple normalized identities emit one occurrence each", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "observation-emission-many", "probe.http")
		persistExactObservationResult(t, fixture, 1, json.RawMessage(`{"lines":["https://one.test/","https://two.test/"]}`))
		assertObservationEmissionCounts(t, fixture, 2, 2)
	})

	t.Run("duplicate lines emit one occurrence", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "observation-emission-duplicate-lines", "probe.http")
		persistExactObservationResult(t, fixture, 1, json.RawMessage(`{"lines":["https://same.test/","https://same.test/"]}`))
		assertObservationEmissionCounts(t, fixture, 1, 1)
	})

	t.Run("exact success without observations emits no occurrence", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "observation-emission-empty", "probe.http")
		admission, _, _ := persistExactObservationResult(t, fixture, 1, json.RawMessage(`{"lines":[]}`))
		assertObservationEmissionCounts(t, fixture, 0, 0)
		assertProviderResultDecisionCount(t, fixture, admission.ProviderAttemptID, "provider_result_accepted", "", 1)
	})
}

func TestAssetObservationEmissionAttemptIsolation(t *testing.T) {
	t.Run("retryable P1 cannot claim successful P2 observation", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "observation-emission-retry", "probe.http")
		firstAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
		firstStep, firstTool, firstArtifacts, firstResult := scheduledResultPayload(fixture, json.RawMessage(`{"lines":["https://first.test/"]}`))
		makeRetryableResult(&firstStep, &firstResult)
		applyScheduledProviderAdmission(firstTool, &firstResult, firstAdmission)
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, firstStep, firstTool, firstArtifacts, firstResult, firstAdmission); err != nil {
			t.Fatal(err)
		}
		assertObservationEmissionCounts(t, fixture, 0, 0)

		secondAdmission, _, _ := persistExactObservationResult(t, fixture, 2, json.RawMessage(`{"lines":["https://second.test/"]}`))
		assertObservationEmissionCounts(t, fixture, 1, 1)
		_, providerAttemptID := loadSingleObservationEmission(t, fixture)
		if providerAttemptID != secondAdmission.ProviderAttemptID || providerAttemptID == firstAdmission.ProviderAttemptID {
			t.Fatalf("emission provider attempt=%s first=%s second=%s", providerAttemptID, firstAdmission.ProviderAttemptID, secondAdmission.ProviderAttemptID)
		}
	})

	t.Run("separate exact successes do not cross-associate", func(t *testing.T) {
		env := newRecoveryTestEnvironment(t, "observation-emission-separate-successes")
		first := newScheduledResultFixtureInEnvironment(t, env, "observation-emission-separate-first", "probe.http")
		second := newScheduledResultFixtureInEnvironment(t, env, "observation-emission-separate-second", "probe.http")
		firstAdmission, _, _ := persistExactObservationResult(t, first, 1, json.RawMessage(`{"lines":["https://first.test/"]}`))
		secondAdmission, _, _ := persistExactObservationResult(t, second, 1, json.RawMessage(`{"lines":["https://second.test/"]}`))

		rows, err := env.store.Pool.Query(env.ctx, `SELECT observation.observed_value,accepted_event.provider_attempt_id
			FROM asset_observation_emissions emission
			JOIN asset_observations observation ON observation.id=emission.asset_observation_id
			JOIN audit_events accepted_event ON accepted_event.id=emission.provider_result_accepted_event_id
			WHERE emission.program_id=$1`, env.programID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		got := map[string]domain.ID{}
		for rows.Next() {
			var value string
			var providerAttemptID domain.ID
			if err := rows.Scan(&value, &providerAttemptID); err != nil {
				t.Fatal(err)
			}
			got[value] = providerAttemptID
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if got["https://first.test/"] != firstAdmission.ProviderAttemptID || got["https://second.test/"] != secondAdmission.ProviderAttemptID || len(got) != 2 {
			t.Fatalf("emission associations=%v", got)
		}
	})
}

func TestAssetObservationEmissionStatusAndLegacyBoundaries(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*domain.StepRun, *domain.ActionResult)
	}{
		{name: "failed", mutate: makeTerminalFailedResult},
		{name: "retryable", mutate: makeRetryableResult},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "observation-emission-"+test.name, "probe.http")
			admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
			step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":["https://status.test/"]}`))
			test.mutate(&step, &result)
			applyScheduledProviderAdmission(tool, &result, admission)
			if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission); err != nil {
				t.Fatal(err)
			}
			assertObservationEmissionCounts(t, fixture, 0, 0)
			assertProviderResultDecisionCount(t, fixture, admission.ProviderAttemptID, "provider_result_accepted", "", 1)
		})
	}

	t.Run("legacy null admission persists no occurrence", func(t *testing.T) {
		fixture := newScheduledResultFixture(t, "observation-emission-legacy", "probe.http")
		step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":["https://legacy.test/"]}`))
		if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, nil); err != nil {
			t.Fatal(err)
		}
		assertObservationEmissionCounts(t, fixture, 1, 0)
		var accepted int
		if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT count(*) FROM audit_events WHERE step_run_id=$1 AND event_type='provider_result_accepted'`, fixture.stepID).Scan(&accepted); err != nil {
			t.Fatal(err)
		}
		if accepted != 0 {
			t.Fatalf("legacy accepted events=%d", accepted)
		}
	})
}

func TestAssetObservationEmissionFailureRollsBackResult(t *testing.T) {
	for _, test := range []struct {
		name      string
		install   string
		errorText string
	}{
		{
			name: "tool execution failure after observation normalization",
			install: `CREATE FUNCTION reject_tool_execution_for_emission_test() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN
					IF NEW.event_type='tool_execution' THEN RAISE EXCEPTION 'synthetic tool execution rejection'; END IF;
					RETURN NEW;
				END $$;
				CREATE TRIGGER reject_tool_execution_for_emission_test BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_tool_execution_for_emission_test()`,
			errorText: "synthetic tool execution rejection",
		},
		{
			name: "emission insertion failure",
			install: `CREATE FUNCTION reject_observation_emission_for_test() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'synthetic observation emission rejection'; END $$;
				CREATE TRIGGER reject_observation_emission_for_test BEFORE INSERT ON asset_observation_emissions FOR EACH ROW EXECUTE FUNCTION reject_observation_emission_for_test()`,
			errorText: "synthetic observation emission rejection",
		},
		{
			name: "accepted event insertion failure",
			install: `CREATE FUNCTION reject_provider_result_accepted_for_emission_test() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN
					IF NEW.event_type='provider_result_accepted' THEN RAISE EXCEPTION 'synthetic accepted event rejection'; END IF;
					RETURN NEW;
				END $$;
				CREATE TRIGGER reject_provider_result_accepted_for_emission_test BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_provider_result_accepted_for_emission_test()`,
			errorText: "synthetic accepted event rejection",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScheduledResultFixture(t, "observation-emission-failure-"+strings.ReplaceAll(test.name, " ", "-"), "probe.http")
			admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
			step, tool, artifacts, result := scheduledResultPayload(fixture, json.RawMessage(`{"lines":["https://rollback.test/"]}`))
			applyScheduledProviderAdmission(tool, &result, admission)
			if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, test.install); err != nil {
				t.Fatal(err)
			}
			err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission)
			if err == nil || !strings.Contains(err.Error(), test.errorText) {
				t.Fatalf("failure=%v", err)
			}
			assertEmptyObservationResultTransaction(t, fixture, admission.ProviderAttemptID)
		})
	}
}

func TestAssetObservationEmissionStructuralIntegrity(t *testing.T) {
	fixture := newScheduledResultFixture(t, "observation-emission-structure", "probe.http")
	admission, tool, artifacts := persistExactObservationResult(t, fixture, 1, json.RawMessage(`{"lines":["https://structure.test/"]}`))
	var observationID, acceptedEventID domain.ID
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT asset_observation_id,provider_result_accepted_event_id FROM asset_observation_emissions WHERE program_id=$1`, fixture.env.programID).Scan(&observationID, &acceptedEventID); err != nil {
		t.Fatal(err)
	}
	var assetID domain.ID
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT asset_id FROM asset_observations WHERE id=$1`, observationID).Scan(&assetID); err != nil {
		t.Fatal(err)
	}

	otherProgramID := domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO programs(id,name,platform,scope_reference,policy_reference) VALUES($1,$2,'integration','synthetic://local','integration')`, otherProgramID, "observation-emission-other-"+string(otherProgramID)); err != nil {
		t.Fatal(err)
	}
	assertObservationEmissionInsertRejected(t, fixture, otherProgramID, observationID, acceptedEventID, "asset observation emission lineage is inconsistent")

	wrongTypeEventID := domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,workflow_run_id,tool_run_id,provider_attempt_id,capability,safe_message) VALUES($1,'tool_execution','test','integration',$2,$3,$4,$5,'probe.http','wrong type')`, wrongTypeEventID, fixture.env.programID, fixture.lineage.runID, tool.ID, admission.ProviderAttemptID); err != nil {
		t.Fatal(err)
	}
	assertObservationEmissionInsertRejected(t, fixture, fixture.env.programID, observationID, wrongTypeEventID, "asset observation emission lineage is inconsistent")

	otherRunID := domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO workflow_runs(id,task_id,workflow_definition_id,workflow_version,status,trigger_source,materialized_definition,materialization_digest,original_scope_version_id)
		SELECT $1,$2,$3,'1','running','integration',materialized_definition,materialization_digest,original_scope_version_id FROM workflow_runs WHERE id=$4`, otherRunID, fixture.lineage.task.ID, fixture.env.definitionID, fixture.lineage.runID); err != nil {
		t.Fatal(err)
	}
	wrongRunEventID := insertSyntheticAcceptedEvent(t, fixture, tool.ID, admission.ProviderAttemptID, otherRunID, "probe.http")
	assertObservationEmissionInsertRejected(t, fixture, fixture.env.programID, observationID, wrongRunEventID, "asset observation emission lineage is inconsistent")

	wrongCapabilityEventID := insertSyntheticAcceptedEvent(t, fixture, tool.ID, admission.ProviderAttemptID, fixture.lineage.runID, "crawl.web")
	assertObservationEmissionInsertRejected(t, fixture, fixture.env.programID, observationID, wrongCapabilityEventID, "asset observation emission lineage is inconsistent")

	missingProvenanceEventID := domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,workflow_run_id,capability,safe_message) VALUES($1,'provider_result_accepted','test','integration',$2,$3,'probe.http','missing provenance')`, missingProvenanceEventID, fixture.env.programID, fixture.lineage.runID); err != nil {
		t.Fatal(err)
	}
	assertObservationEmissionInsertRejected(t, fixture, fixture.env.programID, observationID, missingProvenanceEventID, "asset observation emission lineage is inconsistent")

	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE asset_observation_emissions SET program_id=program_id WHERE asset_observation_id=$1 AND provider_result_accepted_event_id=$2`, observationID, acceptedEventID); err == nil || !strings.Contains(err.Error(), "asset_observation_emissions are append-only") {
		t.Fatalf("emission update error=%v", err)
	}
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `DELETE FROM asset_observation_emissions WHERE asset_observation_id=$1 AND provider_result_accepted_event_id=$2`, observationID, acceptedEventID); err == nil || !strings.Contains(err.Error(), "asset_observation_emissions are append-only") {
		t.Fatalf("emission delete error=%v", err)
	}

	alternateAssetID := domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO assets(id,program_id,type,canonical_value) VALUES($1,$2,'http_service','https://alternate-asset.test/')`, alternateAssetID, fixture.env.programID); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		sql  string
		args []any
	}{{
		name: "asset_id",
		sql:  `UPDATE asset_observations SET asset_id=$2 WHERE id=$1`,
		args: []any{observationID, alternateAssetID},
	}, {
		name: "workflow_run_id",
		sql:  `UPDATE asset_observations SET workflow_run_id=$2 WHERE id=$1`,
		args: []any{observationID, otherRunID},
	}, {
		name: "source_capability",
		sql:  `UPDATE asset_observations SET source_capability='crawl.web' WHERE id=$1`,
		args: []any{observationID},
	}, {
		name: "observed_value",
		sql:  `UPDATE asset_observations SET observed_value=observed_value||'-changed' WHERE id=$1`,
		args: []any{observationID},
	}, {
		name: "program_id",
		sql:  `UPDATE assets SET program_id=$2 WHERE id=$1`,
		args: []any{assetID, otherProgramID},
	}, {
		name: "type",
		sql:  `UPDATE assets SET type='url' WHERE id=$1`,
		args: []any{assetID},
	}, {
		name: "canonical_value",
		sql:  `UPDATE assets SET canonical_value=canonical_value||'-changed' WHERE id=$1`,
		args: []any{assetID},
	}} {
		if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, test.sql, test.args...); err == nil || !strings.Contains(err.Error(), "emitted asset") {
			t.Fatalf("%s identity update error=%v", test.name, err)
		}
	}
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE asset_observations SET metadata='{"retained":true}',observed_at=clock_timestamp(),evidence_artifact_ids='{}' WHERE id=$1`, observationID); err != nil {
		t.Fatalf("allowed observation aggregate update: %v", err)
	}
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE assets SET updated_at=clock_timestamp() WHERE id=$1`, assetID); err != nil {
		t.Fatalf("allowed asset timestamp update: %v", err)
	}

	var emissions int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT count(*) FROM asset_observation_emissions WHERE asset_observation_id=$1 AND provider_result_accepted_event_id=$2`, observationID, acceptedEventID).Scan(&emissions); err != nil || emissions != 1 {
		t.Fatalf("emissions=%d err=%v", emissions, err)
	}
	_ = artifacts
}

func TestConcurrentAssetObservationEmissionsShareNormalizedIdentity(t *testing.T) {
	fixture := newScheduledResultFixture(t, "observation-emission-concurrent", "probe.http")
	secondStepID := domain.NewID()
	secondKey := string(domain.NewID())
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO step_runs(id,workflow_run_id,step_definition_id,capability,status,attempt_count,input,started_at,idempotency_key) VALUES($1,$2,'provider-second','probe.http','running',1,'{}',clock_timestamp(),$3)`, secondStepID, fixture.lineage.runID, secondKey); err != nil {
		t.Fatal(err)
	}
	secondFixture := fixture
	secondFixture.stepID = secondStepID
	secondFixture.idempotencyKey = secondKey

	firstAdmission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, 1), nil, "fixture-provider")
	secondAdmission := recordScheduledProviderAdmission(t, secondFixture, secondFixture.context(), secondFixture.env.programID, scheduledProviderAction(secondFixture, 1), nil, "fixture-provider")
	output := json.RawMessage(`{"lines":[]}`)
	firstStep, firstTool, firstArtifacts, firstResult := scheduledResultPayload(fixture, output)
	secondStep, secondTool, secondArtifacts, secondResult := scheduledResultPayload(secondFixture, output)
	applyScheduledProviderAdmission(firstTool, &firstResult, firstAdmission)
	applyScheduledProviderAdmission(secondTool, &secondResult, secondAdmission)
	if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, firstStep, firstTool, firstArtifacts, firstResult, firstAdmission); err != nil {
		t.Fatal(err)
	}
	if err := secondFixture.env.store.PersistResult(secondFixture.context(), secondFixture.env.programID, secondStep, secondTool, secondArtifacts, secondResult, secondAdmission); err != nil {
		t.Fatal(err)
	}
	firstAcceptedEventID := loadExactAcceptedEventID(t, fixture, firstAdmission.ProviderAttemptID)
	secondAcceptedEventID := loadExactAcceptedEventID(t, fixture, secondAdmission.ProviderAttemptID)
	if firstAcceptedEventID == secondAcceptedEventID {
		t.Fatalf("provider attempts share accepted event %s", firstAcceptedEventID)
	}

	const sharedValue = "https://shared.test/"
	assetID := domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO assets(id,program_id,type,canonical_value) VALUES($1,$2,'http_service',$3)`, assetID, fixture.env.programID, sharedValue); err != nil {
		t.Fatal(err)
	}

	installAssetObservationEmissionObservationInsertBarrier(t, fixture.env)
	runCtx, cancel := context.WithTimeout(fixture.context(), 10*time.Second)
	defer cancel()
	firstConn, err := fixture.env.store.Pool.Acquire(runCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer firstConn.Release()
	firstTx, err := firstConn.Begin(runCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackResultTransaction(runCtx, firstTx)
	var firstPID int32
	if err := firstTx.QueryRow(runCtx, `SELECT pg_backend_pid()`).Scan(&firstPID); err != nil {
		t.Fatal(err)
	}

	secondConn, err := fixture.env.store.Pool.Acquire(runCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer secondConn.Release()
	secondTx, err := secondConn.Begin(runCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackResultTransaction(runCtx, secondTx)
	var secondPID int32
	if err := secondTx.QueryRow(runCtx, `SELECT pg_backend_pid()`).Scan(&secondPID); err != nil {
		t.Fatal(err)
	}
	if firstPID == secondPID {
		t.Fatalf("observation emission transactions share backend PID %d", firstPID)
	}

	holderPID, release := holdResultIdentityInsertBarrierWithPID(t, fixture.env, domain.ID(sharedValue))
	var workers sync.WaitGroup
	defer func() {
		cancel()
		release()
		workers.Wait()
	}()
	persistEmission := func(tx pgx.Tx, acceptedEventID domain.ID) error {
		observationID := domain.NewID()
		if err := tx.QueryRow(runCtx, `INSERT INTO asset_observations(id,asset_id,workflow_run_id,source_capability,observed_value,metadata,first_seen_at,observed_at,confidence,evidence_artifact_ids) VALUES($1,$2,$3,'probe.http',$4,$5,now(),now(),1.0,$6) ON CONFLICT(asset_id,workflow_run_id,source_capability,observed_value) DO UPDATE SET metadata=EXCLUDED.metadata,observed_at=EXCLUDED.observed_at,evidence_artifact_ids=EXCLUDED.evidence_artifact_ids RETURNING id`, observationID, assetID, fixture.lineage.runID, sharedValue, json.RawMessage(`{"value":"https://shared.test/"}`), []string{}).Scan(&observationID); err != nil {
			return err
		}
		if err := persistAssetObservationEmissions(runCtx, tx, fixture.env.programID, []domain.ID{observationID}, acceptedEventID); err != nil {
			return err
		}
		return tx.Commit(runCtx)
	}
	firstErr := make(chan error, 1)
	secondErr := make(chan error, 1)
	workers.Add(2)
	go func() {
		defer workers.Done()
		firstErr <- persistEmission(firstTx, firstAcceptedEventID)
	}()
	go func() {
		defer workers.Done()
		secondErr <- persistEmission(secondTx, secondAcceptedEventID)
	}()
	waitForConcurrentResultInsertBarrier(t, runCtx, fixture.env.store, holderPID, firstPID, secondPID, firstErr, secondErr)
	release()
	for _, operation := range []struct {
		name   string
		result <-chan error
	}{{"first", firstErr}, {"second", secondErr}} {
		select {
		case err := <-operation.result:
			if err != nil {
				t.Fatalf("%s observation emission: %v", operation.name, err)
			}
		case <-runCtx.Done():
			t.Fatalf("%s observation emission did not finish after releasing the PostgreSQL barrier: %v", operation.name, runCtx.Err())
		}
	}

	var observations int
	var observationID domain.ID
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT count(*),COALESCE(min(observation.id::text),'')
		FROM asset_observations observation
		JOIN assets asset ON asset.id=observation.asset_id
		WHERE observation.workflow_run_id=$1
		  AND observation.source_capability='probe.http'
		  AND observation.observed_value=$2
		  AND asset.program_id=$3
		  AND asset.type='http_service'
		  AND asset.canonical_value=$2`, fixture.lineage.runID, sharedValue, fixture.env.programID).Scan(&observations, &observationID); err != nil {
		t.Fatal(err)
	}
	if observations != 1 {
		t.Fatalf("normalized observations=%d want=1", observations)
	}

	var emissions, firstPair, secondPair, unexpected int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
		count(*),
		count(*) FILTER (WHERE asset_observation_id=$2 AND provider_result_accepted_event_id=$3),
		count(*) FILTER (WHERE asset_observation_id=$2 AND provider_result_accepted_event_id=$4),
		count(*) FILTER (WHERE asset_observation_id<>$2 OR provider_result_accepted_event_id NOT IN ($3,$4))
		FROM asset_observation_emissions
		WHERE program_id=$1`, fixture.env.programID, observationID, firstAcceptedEventID, secondAcceptedEventID).Scan(&emissions, &firstPair, &secondPair, &unexpected); err != nil {
		t.Fatal(err)
	}
	if emissions != 2 || firstPair != 1 || secondPair != 1 || unexpected != 0 {
		t.Fatalf("emissions=%d first_pair=%d second_pair=%d unexpected=%d want=2/1/1/0", emissions, firstPair, secondPair, unexpected)
	}
}

func TestArtifactExpirationPreservesAssetObservationEmission(t *testing.T) {
	fixture := newScheduledResultFixture(t, "observation-emission-artifact-expiration", "probe.http")
	_, _, artifacts := persistExactObservationResult(t, fixture, 1, json.RawMessage(`{"lines":["https://retention.test/"]}`))
	var observationID, acceptedEventID domain.ID
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT asset_observation_id,provider_result_accepted_event_id FROM asset_observation_emissions WHERE program_id=$1`, fixture.env.programID).Scan(&observationID, &acceptedEventID); err != nil {
		t.Fatal(err)
	}
	artifactID := artifacts[0].ID
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `UPDATE artifacts SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, artifactID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `DELETE FROM artifacts WHERE id=$1`, artifactID); err == nil || !strings.Contains(err.Error(), "metadata deletion is prohibited") {
		t.Fatalf("artifact delete error=%v", err)
	}
	var emissions, retainedEvidence, artifactsRemaining int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
		(SELECT count(*) FROM asset_observation_emissions WHERE asset_observation_id=$1 AND provider_result_accepted_event_id=$2),
		(SELECT count(*) FROM asset_observations WHERE id=$1 AND $3=ANY(evidence_artifact_ids)),
		(SELECT count(*) FROM artifacts WHERE id=$3)`, observationID, acceptedEventID, artifactID).Scan(&emissions, &retainedEvidence, &artifactsRemaining); err != nil {
		t.Fatal(err)
	}
	if emissions != 1 || retainedEvidence != 1 || artifactsRemaining != 1 {
		t.Fatalf("emissions=%d retained_evidence=%d artifacts=%d", emissions, retainedEvidence, artifactsRemaining)
	}
}

func persistExactObservationResult(t *testing.T, fixture scheduledResultFixture, stepAttempt int, output json.RawMessage) (*capability.ResultAdmissionProvenance, *domain.ToolRun, []domain.Artifact) {
	t.Helper()
	admission := recordScheduledProviderAdmission(t, fixture, fixture.context(), fixture.env.programID, scheduledProviderAction(fixture, stepAttempt), nil, "fixture-provider")
	step, tool, artifacts, result := scheduledResultPayload(fixture, output)
	applyScheduledProviderAdmission(tool, &result, admission)
	if err := fixture.env.store.PersistResult(fixture.context(), fixture.env.programID, step, tool, artifacts, result, admission); err != nil {
		t.Fatal(err)
	}
	return admission, tool, artifacts
}

func assertObservationEmissionCounts(t *testing.T, fixture scheduledResultFixture, observationsWant, emissionsWant int) {
	t.Helper()
	var observations, emissions int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
		(SELECT count(*) FROM asset_observations WHERE workflow_run_id=$1),
		(SELECT count(*) FROM asset_observation_emissions emission JOIN asset_observations observation ON observation.id=emission.asset_observation_id WHERE observation.workflow_run_id=$1)`, fixture.lineage.runID).Scan(&observations, &emissions); err != nil {
		t.Fatal(err)
	}
	if observations != observationsWant || emissions != emissionsWant {
		t.Fatalf("observations=%d emissions=%d want=%d/%d", observations, emissions, observationsWant, emissionsWant)
	}
}

func loadSingleObservationEmission(t *testing.T, fixture scheduledResultFixture) (domain.ID, domain.ID) {
	t.Helper()
	var observationID, providerAttemptID domain.ID
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT emission.asset_observation_id,accepted_event.provider_attempt_id
		FROM asset_observation_emissions emission
		JOIN asset_observations observation ON observation.id=emission.asset_observation_id
		JOIN audit_events accepted_event ON accepted_event.id=emission.provider_result_accepted_event_id
		WHERE observation.workflow_run_id=$1`, fixture.lineage.runID).Scan(&observationID, &providerAttemptID); err != nil {
		t.Fatal(err)
	}
	return observationID, providerAttemptID
}

func assertEmptyObservationResultTransaction(t *testing.T, fixture scheduledResultFixture, providerAttemptID domain.ID) {
	t.Helper()
	var tools, artifacts, observations, accepted, rejected, emissions int
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT
		(SELECT count(*) FROM tool_runs WHERE step_run_id=$1),
		(SELECT count(*) FROM artifacts WHERE step_run_id=$1),
		(SELECT count(*) FROM asset_observations WHERE workflow_run_id=$2),
		(SELECT count(*) FROM audit_events WHERE provider_attempt_id=$3 AND event_type='provider_result_accepted'),
		(SELECT count(*) FROM audit_events WHERE provider_attempt_id=$3 AND event_type='provider_result_rejected'),
		(SELECT count(*) FROM asset_observation_emissions emission JOIN asset_observations observation ON observation.id=emission.asset_observation_id WHERE observation.workflow_run_id=$2)`, fixture.stepID, fixture.lineage.runID, providerAttemptID).Scan(&tools, &artifacts, &observations, &accepted, &rejected, &emissions); err != nil {
		t.Fatal(err)
	}
	if tools != 0 || artifacts != 0 || observations != 0 || accepted != 0 || rejected != 0 || emissions != 0 {
		t.Fatalf("tools=%d artifacts=%d observations=%d accepted=%d rejected=%d emissions=%d", tools, artifacts, observations, accepted, rejected, emissions)
	}
	assertPersistedStepState(t, fixture, domain.StepRunning, 1, false)
}

func assertObservationEmissionInsertRejected(t *testing.T, fixture scheduledResultFixture, programID, observationID, acceptedEventID domain.ID, message string) {
	t.Helper()
	_, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO asset_observation_emissions(program_id,asset_observation_id,provider_result_accepted_event_id) VALUES($1,$2,$3)`, programID, observationID, acceptedEventID)
	if err == nil || !strings.Contains(err.Error(), message) {
		t.Fatalf("emission insert error=%v", err)
	}
}

func insertSyntheticAcceptedEvent(t *testing.T, fixture scheduledResultFixture, toolID, providerAttemptID, workflowRunID domain.ID, capabilityName string) domain.ID {
	t.Helper()
	eventID := domain.NewID()
	if _, err := fixture.env.store.Pool.Exec(fixture.env.ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,workflow_run_id,tool_run_id,provider_attempt_id,capability,safe_message) VALUES($1,'provider_result_accepted','test','integration',$2,$3,$4,$5,$6,'synthetic accepted')`, eventID, fixture.env.programID, workflowRunID, toolID, providerAttemptID, capabilityName); err != nil {
		t.Fatal(err)
	}
	return eventID
}

func installAssetObservationEmissionObservationInsertBarrier(t *testing.T, env recoveryTestEnvironment) {
	t.Helper()
	if _, err := env.store.Pool.Exec(env.ctx, `CREATE FUNCTION asset_observation_emission_observation_insert_barrier() RETURNS trigger AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(hashtext(NEW.observed_value));
			RETURN NEW;
		END;
	$$ LANGUAGE plpgsql;
	CREATE TRIGGER asset_observation_emission_observation_insert_barrier BEFORE INSERT ON asset_observations FOR EACH ROW EXECUTE FUNCTION asset_observation_emission_observation_insert_barrier()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := env.store.Pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS asset_observation_emission_observation_insert_barrier ON asset_observations;
			DROP FUNCTION IF EXISTS asset_observation_emission_observation_insert_barrier()`); err != nil {
			t.Errorf("remove asset observation emission insert barrier: %v", err)
		}
	})
}

func loadExactAcceptedEventID(t *testing.T, fixture scheduledResultFixture, providerAttemptID domain.ID) domain.ID {
	t.Helper()
	var count int
	var eventID domain.ID
	if err := fixture.env.store.Pool.QueryRow(fixture.env.ctx, `SELECT count(*),COALESCE(min(id::text),'') FROM audit_events WHERE event_type='provider_result_accepted' AND provider_attempt_id=$1`, providerAttemptID).Scan(&count, &eventID); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("provider attempt %s accepted events=%d want=1", providerAttemptID, count)
	}
	return eventID
}
