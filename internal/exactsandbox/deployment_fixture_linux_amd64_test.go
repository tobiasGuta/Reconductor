//go:build linux && amd64 && exactcontainment_deployment

package exactsandbox_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/exactsandbox"
)

// A compile-time signature check: no execution bytes, contracts, fields, or
// Broker material can be supplied to this fixture surface.
var _ func() exactsandbox.EncodedExecution = exactsandbox.DeploymentFixtureEncodedExecution

const deploymentFixtureDigest = "1f15af824107d452f2ef91bd72b38c8ba29eddc2fe18fc60fc25dfc74499c055"

func TestDeploymentFixtureFixedCanonicalMaterial(t *testing.T) {
	in := exactsandbox.DeploymentFixtureEncodedExecution()
	if in == (exactsandbox.EncodedExecution{}) || len(in.Bytes()) == 0 {
		t.Fatal("zero deployment fixture")
	}
	_, canonical, _, _, err := canonicaljson.ParseStrictBounded(in.Bytes(), exactsandbox.MaxExecutionBytes)
	if err != nil || !bytes.Equal(canonical, in.Bytes()) {
		t.Fatal("fixture is not canonical:", err)
	}
	sum := sha256.Sum256(append([]byte("reconductor-exact-sandbox-execution/v1\x00"), in.Bytes()...))
	if in.Digest() != hex.EncodeToString(sum[:]) || in.Digest() != deploymentFixtureDigest {
		t.Fatal("fixed capsule digest changed:", in.Digest())
	}
	capsule, err := exactsandbox.DecodeExecution(in.Bytes(), in.Digest())
	if err != nil {
		t.Fatal("frozen decoder rejected fixture:", err)
	}
	a := capsule.Action()
	_, actionDigest, err := a.Freeze()
	if err != nil || actionDigest != capsule.ActionSHA256() || actionDigest != "5b346c53e9edc90c7748339bff0af20859d28b365129848319ac1a57e71a2976" {
		t.Fatal("fixed action digest changed:", err)
	}
	// The required epoch field is a zero placeholder, not acquired authority;
	// every lineage ID is synthetic. The frozen schema carries no permit,
	// credentials, review/evidence, or Broker-derived Execution.
	if capsule.AuthorityEpoch() != 0 || capsule.ProviderAttemptID() != "deployment-fixture-attempt" ||
		a.ActionID != "deployment-fixture-action" || a.Ownership.ProgramID != "deployment-fixture-program" ||
		a.Ownership.TaskID != "deployment-fixture-task" || a.Ownership.WorkflowRunID != "deployment-fixture-workflow" ||
		a.Ownership.StepRunID != "deployment-fixture-step" || a.Ownership.StepAttempt != 1 ||
		a.Identity.Kind != "anonymous" || len(a.Request.Headers) != 0 ||
		a.Request.Method != "GET" || a.Request.Scheme != "https" || a.Request.Hostname != "example.test" ||
		a.Request.EffectivePort != 443 || a.Request.RequestTarget != "/offline" ||
		a.Limits.MaxRequests != 1 || a.Limits.FollowRedirects || a.Limits.AutomaticRetries {
		t.Fatal("fixture is not the fixed anonymous offline material")
	}
}

func TestDeploymentFixtureDeterministicAndImmutable(t *testing.T) {
	want := exactsandbox.DeploymentFixtureEncodedExecution()
	for i := 0; i < 100; i++ {
		got := exactsandbox.DeploymentFixtureEncodedExecution()
		if !bytes.Equal(got.Bytes(), want.Bytes()) || got.Digest() != want.Digest() {
			t.Fatal("fixture is not deterministic")
		}
	}
	copy := want.Bytes()
	copy[0] = '!'
	if want.Bytes()[0] != '{' || exactsandbox.DeploymentFixtureEncodedExecution().Digest() != deploymentFixtureDigest {
		t.Fatal("returned bytes can customize the fixture")
	}
}
