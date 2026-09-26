//go:build linux

package artifact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
	"golang.org/x/sys/unix"
)

type durabilitySource string

func (s durabilitySource) Open() (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(string(s))), nil
}
func (s durabilitySource) SizeBytes() int64 { return int64(len(s)) }
func (s durabilitySource) SHA256() [32]byte { return DigestBytes([]byte(s)) }

func durabilityStageFixture(t *testing.T, identity StoreIdentity) PreparedStageRequest {
	t.Helper()
	set, manifestID, attempt, occurrence, artifactID, action, step, run := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	controlKey, _ := domain.PreparedControlKey(set)
	memberKey, _ := domain.PreparedMemberKey(set, 0)
	manifestKey, _ := domain.PreparedManifestKey(set)
	finalKey, _ := StorageKeyFor(artifactID)
	digest := DigestString(DigestBytes([]byte(`{}`)))
	ref := domain.ResultArtifactRefV1{ArtifactID: artifactID, ArtifactStoreID: identity.ArtifactStoreID, StorageKey: finalKey, Role: domain.ArtifactRoleSemanticResult, ContentType: "application/json", ContentSizeBytes: 2, ContentSHA256: digest}
	envelope := domain.ResultEnvelopeV1{Version: domain.ResultEnvelopeVersionV1, ActionRequestID: action, ResultOccurrenceID: occurrence, ProviderAttemptID: attempt, CapabilityName: "test.result", CapabilityVersion: "1", Status: domain.ResultStatusSucceeded, ProviderOutcome: domain.ResultProviderSucceeded, Summary: "fixture", PublicationComplete: true, Artifacts: []domain.ResultArtifactRefV1{ref}, SemanticOutput: domain.SemanticOutputV1{Version: domain.SemanticOutputVersionV1, Mode: domain.SemanticModeArtifactJSON, Completeness: domain.SemanticComplete, Canonicalization: domain.CanonicalJSONVersionV1, ArtifactID: artifactID, ContentSHA256: digest, ContentSizeBytes: 2, OutputSchemaSHA256: digest, NodeCount: 1, MaximumDepth: 1, ProjectionState: domain.ProjectionNotRequired}}
	envelopeDigest, err := domain.EnvelopeDigest(envelope)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	control := domain.PreparedControlV1{Version: domain.PreparedControlVersionV1, SetID: set, ManifestID: manifestID, ProviderTerminalEventID: domain.NewID(), AcceptedEventID: domain.NewID(), ProviderOutcome: domain.ResultProviderSucceeded, Envelope: envelope, EnvelopeSHA256: envelopeDigest, ToolRun: domain.ToolRun{ID: domain.NewID(), StepRunID: step, Capability: "test.result", Provider: "test", ToolVersion: "1", SanitizedArguments: json.RawMessage(`{}`), ExecutionEnvironment: json.RawMessage(`{}`), StartedAt: now, CompletedAt: &now, ArtifactIDs: []domain.ID{artifactID}, ProviderAttemptID: &attempt}, Step: domain.PreparedStepV1{ID: step, WorkflowRunID: run, Capability: "test.result", Status: domain.ResultStatusSucceeded, IdempotencyKey: "fixture", CompletedAt: &now}, Admission: domain.PreparedAdmissionV1{ProviderAttemptID: attempt, PreparedSetID: set, ActionRequestID: action, StepAttempt: 1, ExecutionAuthorizationEventID: domain.NewID(), Provider: "test"}}
	controlJSON, err := control.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	manifest := domain.PreparedManifestV1{Version: domain.PreparedManifestVersionV1, SetID: set, ManifestID: manifestID, ArtifactStoreID: identity.ArtifactStoreID, StoreIncarnationNonce: identity.IncarnationNonce, StoreBackendKind: identity.BackendKind, StoreMarkerFormat: identity.MarkerFormat, StoreMarkerVersion: identity.MarkerVersion, ProviderAttemptID: &attempt, ResultOccurrenceID: occurrence, Control: domain.PreparedObjectRefV1{StorageKey: controlKey, ContentSizeBytes: int64(len(controlJSON)), ContentSHA256: DigestString(DigestBytes(controlJSON))}, Members: []domain.PreparedMemberV1{{Ordinal: 0, PublicationID: domain.NewID(), ArtifactID: artifactID, PreparedKey: memberKey, FinalKey: finalKey, Role: ref.Role, ContentType: ref.ContentType, ArtifactType: "normalized-result", ContentSizeBytes: 2, ContentSHA256: digest}}}
	manifestJSON, err := manifest.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return PreparedStageRequest{ReservedCapacityBytes: 1 << 20, SetID: set, ManifestID: manifestID, ManifestKey: manifestKey, ManifestJSON: manifestJSON, Control: PreparedStageObject{StorageKey: controlKey, ExpectedSize: int64(len(controlJSON)), ExpectedSHA256: DigestBytes(controlJSON), Source: durabilitySource(controlJSON)}, Members: []PreparedStageObject{{StorageKey: memberKey, ExpectedSize: 2, ExpectedSHA256: DigestBytes([]byte(`{}`)), Source: durabilitySource(`{}`)}}}
}

// Each native operation first measures all synchronization points, then fails
// each point in isolation on a fresh temporary store. No successful durable
// result may survive a failed file or ancestor-directory synchronization.
func TestEveryPinnedSynchronizationFailurePropagates(t *testing.T) {
	for _, operation := range []string{"write", "read", "verify", "publish", "unlink", "rmdir", "acquire", "stage", "inspect"} {
		t.Run(operation, func(t *testing.T) {
			execute := func(t *testing.T, failAt int) int {
				local, g := linuxGuard(t)
				set := domain.NewID()
				key, _ := domain.PreparedMemberKey(set, 0)
				data := "exact evidence"
				var stage PreparedStageRequest
				var recovery PreparedRecoveryGuard
				if operation == "stage" || operation == "inspect" {
					stage = durabilityStageFixture(t, g.identity)
				}
				if operation == "inspect" {
					if receipt, err := g.StagePrepared(context.Background(), stage); err != nil || !receipt.Durable {
						t.Fatalf("stage fixture: %v", err)
					}
					g.Close()
					var err error
					recovery, err = local.AcquirePreparedRecovery(context.Background(), local.Identity())
					if err != nil {
						t.Fatal(err)
					}
					defer recovery.Close()
				}
				if operation == "read" || operation == "verify" || operation == "unlink" || operation == "rmdir" {
					if _, err := writePreparedExclusive(g.rootFD, key, strings.NewReader(data), int64(len(data)), DigestBytes([]byte(data)), 1024); err != nil {
						t.Fatal(err)
					}
				}
				if operation == "rmdir" {
					if err := unlinkPrepared(g.rootFD, key); err != nil {
						t.Fatal(err)
					}
				}
				calls := 0
				injected := errors.New("injected durable sync failure")
				original := storeFsync
				storeFsync = func(fd int) error {
					calls++
					if calls == failAt {
						return injected
					}
					return unix.Fsync(fd)
				}
				defer func() { storeFsync = original }()
				var err error
				switch operation {
				case "stage":
					receipt, stageErr := g.StagePrepared(context.Background(), stage)
					err = stageErr
					if failAt != 0 && receipt.Durable {
						t.Fatal("stage falsely durable")
					}
				case "inspect":
					inspection, inspectErr := recovery.InspectPrepared(context.Background(), stage.SetID)
					err = inspectErr
					if failAt != 0 && inspection.Durable {
						t.Fatal("inspection falsely durable")
					}
				case "write":
					_, err = writePreparedExclusive(g.rootFD, key, strings.NewReader(data), int64(len(data)), DigestBytes([]byte(data)), 1024)
				case "read":
					_, err = readPreparedBounded(context.Background(), g.rootFD, key, 1024)
				case "verify":
					var r io.ReadCloser
					r, err = openPreparedVerified(context.Background(), g.rootFD, key, int64(len(data)), DigestBytes([]byte(data)))
					if r != nil {
						_, readErr := io.Copy(io.Discard, r)
						err = errors.Join(err, readErr, r.Close())
					}
				case "publish":
					var receipt PublishedArtifactV1
					receipt, err = g.PublishReserved(context.Background(), reservedFixture(g.identity.ArtifactStoreID, data), strings.NewReader(data))
					if failAt != 0 && receipt.Durable {
						t.Fatal("false durable receipt")
					}
				case "unlink":
					err = unlinkPrepared(g.rootFD, key)
				case "rmdir":
					err = removePreparedSetDirectory(g.rootFD, set)
				case "acquire":
					var acquired PublisherGuard
					acquired, err = local.AcquirePublisher(context.Background(), local.Identity())
					if acquired != nil {
						err = errors.Join(err, acquired.Close())
					}
				}
				if failAt == 0 && err != nil {
					t.Fatal(err)
				}
				if failAt != 0 && !errors.Is(err, injected) {
					t.Fatalf("sync %d did not propagate: %v", failAt, err)
				}
				return calls
			}
			points := execute(t, 0)
			if points == 0 {
				t.Fatal("operation established no durability")
			}
			for point := 1; point <= points; point++ {
				t.Run(fmt.Sprint(point), func(t *testing.T) { execute(t, point) })
			}
		})
	}
}
