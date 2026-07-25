# Future local-AI boundary

No AI component is implemented.

A future local planner may propose only a `PlanProposal`: a human-readable intent, registered capability names, structured candidate inputs, rationale, expected risk, and references to existing scoped assets or observations. Reconductor must validate the proposal, present it for human review, then create trusted task IDs, workflow-run IDs, step-run IDs, idempotency keys, approval states, execution attribution records, and `ActionRequest` values itself.

The planner must not generate trusted IDs, approval states, idempotency keys, execution attribution records, unrestricted shell access, executable selection, raw command arrays, direct provider credentials, migration access, or an approval bypass. `future_ai` is only an attribution value; it grants no additional authority.

`ActionResult` is the return boundary. It contains status, safe summary, structured output, artifact IDs, and a classified error. Large evidence stays in artifact storage rather than planner context.
