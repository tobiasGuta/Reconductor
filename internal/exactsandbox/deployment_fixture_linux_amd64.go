//go:build linux && amd64 && exactcontainment_deployment

package exactsandbox

import "github.com/tobiasGuta/Reconductor/internal/exactaction"

// DeploymentFixtureEncodedExecution supplies one fixed, synthetic capsule ONLY
// for the opt-in disposable deployment test. It grants no authority and accepts
// no caller material. The offline runtime validates it and returns Completed=false
// without performing the represented request. Normal builds exclude this file.
func DeploymentFixtureEncodedExecution() EncodedExecution {
	a := exactaction.ActionContractV1{
		ContractVersion: exactaction.ContractVersion,
		ActionID:        "deployment-fixture-action",
		Ownership: exactaction.Ownership{
			ProgramID: "deployment-fixture-program", TaskID: "deployment-fixture-task",
			WorkflowRunID: "deployment-fixture-workflow", StepRunID: "deployment-fixture-step", StepAttempt: 1,
		},
		Capability: exactaction.Capability{Name: "http.request", SemanticRevision: exactaction.CapabilityRevision},
		Request: exactaction.Request{
			Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443,
			RequestTarget: "/offline", Headers: []string{},
		},
		Identity: exactaction.Identity{Kind: "anonymous"},
		Limits:   exactaction.Limits{MaxRequests: 1},
	}
	_, actionDigest, err := a.Freeze()
	if err != nil {
		panic("invalid fixed deployment action: " + err.Error())
	}
	encoded, err := encodeCapsule(Capsule{wire: executionWire{
		Version: ExecutionVersion, ProviderAttemptID: "deployment-fixture-attempt",
		ActionSHA256: actionDigest, AuthorityEpoch: 0, Action: a,
	}})
	if err != nil {
		panic("invalid fixed deployment capsule: " + err.Error())
	}
	return encoded
}
