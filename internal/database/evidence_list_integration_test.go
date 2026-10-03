package database

import (
	"errors"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestListEvidenceViewIsRunScopedAndReusesAuthorization(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "evidence-list")
	first, firstReference := adoptedEvidenceFixture(t, env, "first")
	second, secondReference := adoptedEvidenceFixture(t, env, "second")
	before := evidenceMutationCounts(t, env)

	items, err := env.store.ListEvidenceView(env.ctx, first.step.WorkflowRunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Reference.ArtifactID != firstReference.ArtifactID {
		t.Fatalf("first-run evidence=%#v", items)
	}
	if items[0].Reference.ArtifactID == secondReference.ArtifactID || items[0].WorkflowRunID == second.step.WorkflowRunID {
		t.Fatal("cross-run evidence was enumerated")
	}
	if after := evidenceMutationCounts(t, env); after != before {
		t.Fatalf("list mutated state: before=%v after=%v", before, after)
	}

	if _, err := env.store.ListEvidenceView(env.ctx, domain.NewID()); !errors.Is(err, artifact.ErrEvidenceUnavailable) {
		t.Fatalf("unknown run error=%v", err)
	}
}

func TestListEvidenceViewOmitsRestrictedAndUnadoptedCandidates(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "evidence-list-negative")
	restricted, reference := adoptedEvidenceFixture(t, env, "restricted")
	if _, err := env.store.Pool.Exec(env.ctx, `UPDATE artifacts SET sensitive=true,redaction_state='sensitive-unredacted' WHERE id=$1`, reference.ArtifactID); err != nil {
		t.Fatal(err)
	}
	items, err := env.store.ListEvidenceView(env.ctx, restricted.step.WorkflowRunID)
	if err != nil || len(items) != 0 {
		t.Fatalf("restricted list=%#v error=%v", items, err)
	}

	unadopted := newPreparedDBFixture(t, env, "unadopted")
	ctx := unadopted.context()
	if err := env.store.SealPreparedEvidence(ctx, unadopted.seal); err != nil {
		t.Fatal(err)
	}
	if err := env.store.ReserveCompiledResult(ctx, env.programID, unadopted.step, unadopted.compiled, &unadopted.admission, unadopted.identity); err != nil {
		t.Fatal(err)
	}
	items, err = env.store.ListEvidenceView(env.ctx, unadopted.step.WorkflowRunID)
	if err != nil || len(items) != 0 {
		t.Fatalf("unadopted list=%#v error=%v", items, err)
	}
}
