package database

import "testing"

type evidenceReadState struct {
	Workflow, Steps, Tools, Artifacts, Publications, Prepared, Audits, Scheduled string
}

func captureEvidenceReadState(t *testing.T, env recoveryTestEnvironment, fixture preparedDBFixture) evidenceReadState {
	t.Helper()
	var state evidenceReadState
	err := env.store.Pool.QueryRow(env.ctx, `SELECT
		COALESCE((SELECT to_jsonb(wr)::text FROM workflow_runs wr WHERE wr.id=$1),''),
		COALESCE((SELECT jsonb_agg(to_jsonb(sr) ORDER BY sr.id)::text FROM step_runs sr WHERE sr.workflow_run_id=$1),'[]'),
		COALESCE((SELECT jsonb_agg(to_jsonb(tr) ORDER BY tr.id)::text FROM tool_runs tr JOIN step_runs sr ON sr.id=tr.step_run_id WHERE sr.workflow_run_id=$1),'[]'),
		COALESCE((SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id)::text FROM artifacts a WHERE a.workflow_run_id=$1),'[]'),
		COALESCE((SELECT jsonb_agg(to_jsonb(ap) ORDER BY ap.id)::text FROM artifact_publications ap WHERE ap.provider_attempt_id=$2),'[]'),
		COALESCE((SELECT jsonb_agg(to_jsonb(pes) ORDER BY pes.id)::text FROM prepared_evidence_sets pes WHERE pes.workflow_run_id=$1),'[]'),
		COALESCE((SELECT jsonb_agg(to_jsonb(ae) ORDER BY ae.occurred_at,ae.id)::text FROM audit_events ae WHERE ae.workflow_run_id=$1),'[]'),
		COALESCE((SELECT to_jsonb(se)::text FROM scheduled_executions se WHERE se.id=$3),'')`,
		fixture.step.WorkflowRunID, fixture.admission.ProviderAttemptID, fixture.fence.ExecutionID,
	).Scan(&state.Workflow, &state.Steps, &state.Tools, &state.Artifacts, &state.Publications, &state.Prepared, &state.Audits, &state.Scheduled)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
