package database

import (
	"errors"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestAuthorizeEvidenceViewRequiresAdoptedRunScopedEvidence(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "evidence-view")

	t.Run("valid adopted redacted non-sensitive artifact", func(t *testing.T) {
		fixture, reference := adoptedEvidenceFixture(t, env, "valid")
		before := evidenceMutationCounts(t, env)
		authorized, err := env.store.AuthorizeEvidenceView(env.ctx, fixture.step.WorkflowRunID, reference.ArtifactID)
		if err != nil {
			t.Fatal(err)
		}
		if authorized.Reference != reference || authorized.WorkflowRunID != fixture.step.WorkflowRunID ||
			authorized.StepRunID != fixture.step.ID || authorized.ToolRunID != fixture.compiled.ToolRun.ID ||
			authorized.ProviderAttemptID != fixture.admission.ProviderAttemptID ||
			authorized.ResultOccurrenceID != fixture.compiled.ResultOccurrenceID ||
			authorized.StoreIdentity != fixture.identity || authorized.SemanticCompleteness != domain.SemanticComplete {
			t.Fatalf("authorization = %#v", authorized)
		}
		if after := evidenceMutationCounts(t, env); after != before {
			t.Fatalf("read-only authorization mutated rows: before=%v after=%v", before, after)
		}
	})

	t.Run("unknown and cross-run artifact are indistinguishable", func(t *testing.T) {
		fixture, reference := adoptedEvidenceFixture(t, env, "scoped")
		for _, request := range []struct {
			runID, artifactID domain.ID
		}{
			{fixture.step.WorkflowRunID, domain.NewID()},
			{domain.NewID(), reference.ArtifactID},
		} {
			_, err := env.store.AuthorizeEvidenceView(env.ctx, request.runID, request.artifactID)
			if !errors.Is(err, artifact.ErrEvidenceUnavailable) || err.Error() != artifact.ErrEvidenceUnavailable.Error() {
				t.Fatalf("error = %v, want non-disclosing unavailable", err)
			}
		}
	})

	t.Run("same-run sensitive artifact is restricted", func(t *testing.T) {
		fixture, reference := adoptedEvidenceFixture(t, env, "sensitive")
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE artifacts SET sensitive=true,redaction_state='sensitive-unredacted' WHERE id=$1`, reference.ArtifactID); err != nil {
			t.Fatal(err)
		}
		_, err := env.store.AuthorizeEvidenceView(env.ctx, fixture.step.WorkflowRunID, reference.ArtifactID)
		if !errors.Is(err, artifact.ErrEvidenceRestricted) {
			t.Fatalf("error = %v, want restricted", err)
		}
	})

	t.Run("unredacted and expired artifacts are unavailable", func(t *testing.T) {
		for _, test := range []struct {
			name   string
			update string
		}{
			{name: "unredacted", update: `UPDATE artifacts SET redaction_state='unredacted' WHERE id=$1`},
			{name: "expired", update: `UPDATE artifacts SET expires_at=clock_timestamp()-INTERVAL '1 hour' WHERE id=$1`},
		} {
			t.Run(test.name, func(t *testing.T) {
				fixture, reference := adoptedEvidenceFixture(t, env, "unavailable-"+test.name)
				if _, err := env.store.Pool.Exec(env.ctx, test.update, reference.ArtifactID); err != nil {
					t.Fatal(err)
				}
				assertEvidenceUnavailable(t, env, fixture.step.WorkflowRunID, reference.ArtifactID)
			})
		}
	})

	t.Run("prepared-only and sealed-only publications are unavailable", func(t *testing.T) {
		prepared := newPreparedDBFixture(t, env, "prepared-only")
		if err := env.store.SealPreparedEvidence(prepared.context(), prepared.seal); err != nil {
			t.Fatal(err)
		}
		assertEvidenceUnavailable(t, env, prepared.step.WorkflowRunID, prepared.compiled.Artifacts[0].Reference.ArtifactID)

		sealed := newPreparedDBFixture(t, env, "sealed-only")
		ctx := sealed.context()
		if err := env.store.SealPreparedEvidence(ctx, sealed.seal); err != nil {
			t.Fatal(err)
		}
		if err := env.store.ReserveCompiledResult(ctx, env.programID, sealed.step, sealed.compiled, &sealed.admission, sealed.identity); err != nil {
			t.Fatal(err)
		}
		for index := range sealed.compiled.Artifacts {
			if err := env.store.MarkCompiledArtifactPublishing(ctx, sealed.compiled, index); err != nil {
				t.Fatal(err)
			}
			if err := env.store.SealCompiledArtifact(ctx, sealed.compiled, index); err != nil {
				t.Fatal(err)
			}
		}
		assertEvidenceUnavailable(t, env, sealed.step.WorkflowRunID, sealed.compiled.Artifacts[0].Reference.ArtifactID)
	})
}

func TestAuthorizeEvidenceViewRejectsLineageLifecycleAndEnvelopeContradictions(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "evidence-view-negative")

	t.Run("task step and tool lineage", func(t *testing.T) {
		other, _ := adoptedEvidenceFixture(t, env, "lineage-other")
		for _, test := range []struct {
			name   string
			update string
			value  domain.ID
		}{
			{name: "task", update: `UPDATE artifacts SET task_id=$2 WHERE id=$1`, value: other.action.TaskID},
			{name: "step", update: `UPDATE artifacts SET step_run_id=$2 WHERE id=$1`, value: other.step.ID},
			{name: "tool", update: `UPDATE artifacts SET tool_run_id=$2 WHERE id=$1`, value: other.compiled.ToolRun.ID},
		} {
			t.Run(test.name, func(t *testing.T) {
				fixture, reference := adoptedEvidenceFixture(t, env, "wrong-"+test.name)
				if _, err := env.store.Pool.Exec(env.ctx, test.update, reference.ArtifactID, test.value); err != nil {
					t.Fatal(err)
				}
				assertEvidenceUnavailable(t, env, fixture.step.WorkflowRunID, reference.ArtifactID)
			})
		}
	})

	t.Run("provider attempt", func(t *testing.T) {
		fixture, reference := adoptedEvidenceFixture(t, env, "wrong-attempt")
		other := newPreparedDBFixture(t, env, "wrong-attempt-other")
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE tool_runs SET provider_attempt_id=$2 WHERE id=$1`, fixture.compiled.ToolRun.ID, other.admission.ProviderAttemptID); err != nil {
			t.Fatal(err)
		}
		assertEvidenceUnavailable(t, env, fixture.step.WorkflowRunID, reference.ArtifactID)
	})

	t.Run("result occurrence", func(t *testing.T) {
		fixture, reference := adoptedEvidenceFixture(t, env, "wrong-occurrence")
		setTrigger(t, env, "artifact_publications", "artifact_publications_identity_guard", false)
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE artifact_publications SET result_occurrence_id=$2 WHERE artifact_id=$1`, reference.ArtifactID, domain.NewID()); err != nil {
			t.Fatal(err)
		}
		setTrigger(t, env, "artifact_publications", "artifact_publications_identity_guard", true)
		assertEvidenceUnavailable(t, env, fixture.step.WorkflowRunID, reference.ArtifactID)
	})

	t.Run("envelope and publication integrity", func(t *testing.T) {
		fixture, reference := adoptedEvidenceFixture(t, env, "wrong-envelope")
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE step_runs SET output='{}'::jsonb WHERE id=$1`, fixture.step.ID); err != nil {
			t.Fatal(err)
		}
		assertEvidenceUnavailable(t, env, fixture.step.WorkflowRunID, reference.ArtifactID)

		fixture, reference = adoptedEvidenceFixture(t, env, "wrong-publication")
		setTrigger(t, env, "artifact_publications", "artifact_publications_identity_guard", false)
		setTrigger(t, env, "artifact_publications", "artifact_publications_adoption_guard", false)
		if _, err := env.store.Pool.Exec(env.ctx, `UPDATE artifact_publications SET content_sha256=$2 WHERE artifact_id=$1`, reference.ArtifactID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
			t.Fatal(err)
		}
		setTrigger(t, env, "artifact_publications", "artifact_publications_adoption_guard", true)
		setTrigger(t, env, "artifact_publications", "artifact_publications_identity_guard", true)
		assertEvidenceUnavailable(t, env, fixture.step.WorkflowRunID, reference.ArtifactID)
	})

	for _, test := range []struct {
		name   string
		update string
	}{
		{name: "tombstoned", update: `UPDATE artifacts SET expires_at=clock_timestamp()-INTERVAL '2 hours',content_deleted_at=clock_timestamp()-INTERVAL '1 hour' WHERE id=$1`},
		{name: "cleanup quarantined", update: `UPDATE artifacts SET expires_at=clock_timestamp()-INTERVAL '2 hours',cleanup_last_error_code='unexpected_entry_type',cleanup_quarantined_at=clock_timestamp()-INTERVAL '1 hour' WHERE id=$1`},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture, reference := adoptedEvidenceFixture(t, env, test.name)
			setTrigger(t, env, "artifacts", "artifacts_cleanup_transition_guard", false)
			if _, err := env.store.Pool.Exec(env.ctx, test.update, reference.ArtifactID); err != nil {
				t.Fatal(err)
			}
			setTrigger(t, env, "artifacts", "artifacts_cleanup_transition_guard", true)
			assertEvidenceUnavailable(t, env, fixture.step.WorkflowRunID, reference.ArtifactID)
		})
	}
}

type evidenceCounts struct {
	Artifacts, Publications, Audits, Prepared int
}

func evidenceMutationCounts(t *testing.T, env recoveryTestEnvironment) evidenceCounts {
	t.Helper()
	var counts evidenceCounts
	if err := env.store.Pool.QueryRow(env.ctx, `SELECT
		(SELECT count(*) FROM artifacts),
		(SELECT count(*) FROM artifact_publications),
		(SELECT count(*) FROM audit_events),
		(SELECT count(*) FROM prepared_evidence_sets)`).Scan(&counts.Artifacts, &counts.Publications, &counts.Audits, &counts.Prepared); err != nil {
		t.Fatal(err)
	}
	return counts
}

func adoptedEvidenceFixture(t *testing.T, env recoveryTestEnvironment, name string) (preparedDBFixture, domain.ResultArtifactRefV1) {
	t.Helper()
	fixture := newPreparedDBFixture(t, env, name)
	ctx := fixture.context()
	if err := env.store.SealPreparedEvidence(ctx, fixture.seal); err != nil {
		t.Fatal(err)
	}
	if err := env.store.ReserveCompiledResult(ctx, env.programID, fixture.step, fixture.compiled, &fixture.admission, fixture.identity); err != nil {
		t.Fatal(err)
	}
	for index := range fixture.compiled.Artifacts {
		if err := env.store.MarkCompiledArtifactPublishing(ctx, fixture.compiled, index); err != nil {
			t.Fatal(err)
		}
		if err := env.store.SealCompiledArtifact(ctx, fixture.compiled, index); err != nil {
			t.Fatal(err)
		}
	}
	if err := env.store.AdoptCompiledResult(ctx, env.programID, fixture.step, fixture.compiled, &fixture.admission, 0); err != nil {
		t.Fatal(err)
	}
	for _, item := range fixture.compiled.Artifacts {
		if item.Reference.Role == domain.ArtifactRoleSemanticResult {
			return fixture, item.Reference
		}
	}
	t.Fatal("compiled fixture has no semantic artifact")
	return preparedDBFixture{}, domain.ResultArtifactRefV1{}
}

func assertEvidenceUnavailable(t *testing.T, env recoveryTestEnvironment, runID, artifactID domain.ID) {
	t.Helper()
	_, err := env.store.AuthorizeEvidenceView(env.ctx, runID, artifactID)
	if !errors.Is(err, artifact.ErrEvidenceUnavailable) {
		t.Fatalf("error = %v, want unavailable", err)
	}
}

func setTrigger(t *testing.T, env recoveryTestEnvironment, table, trigger string, enabled bool) {
	t.Helper()
	state := "DISABLE"
	if enabled {
		state = "ENABLE"
	}
	if _, err := env.store.Pool.Exec(env.ctx, `ALTER TABLE `+table+` `+state+` TRIGGER `+trigger); err != nil {
		t.Fatal(err)
	}
}
