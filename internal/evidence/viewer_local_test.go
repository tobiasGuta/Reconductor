package evidence

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestReadComposesWithPinnedLocalStore(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("authoritative pinned reads are Linux-only")
	}
	ctx := context.Background()
	root := t.TempDir()
	registry := &registryFake{stores: map[domain.ID]domain.ArtifactStore{}}
	storeID := domain.NewID()
	if _, err := artifact.InitializeLocal(ctx, root, storeID, registry, artifact.InitializationOptions{}); err != nil {
		t.Fatal(err)
	}
	store, err := artifact.OpenLocal(ctx, root, storeID, registry, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := artifact.PutRequest{
		ProgramID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), ToolRunID: domain.NewID(),
		Type: "normalized-result", ContentType: "application/json", Data: []byte(`{"status":200}`),
	}
	published, err := store.Put(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	authorized := artifact.AuthorizedEvidenceArtifactV1{
		Reference: domain.ResultArtifactRefV1{
			ArtifactID: published.ID, ArtifactStoreID: *published.ArtifactStoreID, StorageKey: *published.StorageKey,
			Role: domain.ArtifactRoleSemanticResult, ContentType: published.ContentType, ContentSizeBytes: published.Size, ContentSHA256: published.SHA256,
		},
		StoreIdentity: store.Identity(), ProgramID: request.ProgramID, TaskID: request.TaskID, WorkflowRunID: request.WorkflowRunID,
		StepRunID: request.StepRunID, StepDefinitionID: "probe", ToolRunID: request.ToolRunID,
		ActionRequestID: domain.NewID(), ProviderAttemptID: domain.NewID(), ResultOccurrenceID: domain.NewID(), PublicationID: domain.NewID(),
		CapabilityName: "probe.http", CapabilityVersion: "1", ProviderName: "httpx", ArtifactType: request.Type, SemanticCompleteness: domain.SemanticComplete,
	}
	service := Service{Authorizer: &authorizerFake{authorized: authorized}, Store: store}
	verified, err := service.Read(ctx, request.WorkflowRunID, published.ID)
	if err != nil || !bytes.Equal(verified.Content, request.Data) {
		t.Fatalf("content=%q error=%v", verified.Content, err)
	}

	path := filepath.Join(root, filepath.FromSlash(*published.StorageKey))
	if err := os.WriteFile(path, []byte(`{"status":201}`), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := service.Read(ctx, request.WorkflowRunID, published.ID)
	if !errors.Is(err, artifact.ErrEvidenceVerificationFailed) || len(result.Content) != 0 {
		t.Fatalf("corrupt result=%#v error=%v", result, err)
	}
	if _, err := store.DeleteContent(ctx, published.ID, *published.StorageKey); err != nil {
		t.Fatal(err)
	}
	result, err = service.Read(ctx, request.WorkflowRunID, published.ID)
	if !errors.Is(err, artifact.ErrEvidenceUnavailable) || len(result.Content) != 0 {
		t.Fatalf("missing result=%#v error=%v", result, err)
	}
}

type registryFake struct {
	stores map[domain.ID]domain.ArtifactStore
}

func (r *registryFake) ArtifactStore(_ context.Context, id domain.ID) (domain.ArtifactStore, error) {
	store, ok := r.stores[id]
	if !ok {
		return domain.ArtifactStore{}, artifact.ErrStoreRegistrationNotFound
	}
	return store, nil
}

func (r *registryFake) RegisterArtifactStore(_ context.Context, registration domain.ArtifactStoreRegistration) (domain.ArtifactStore, error) {
	if _, ok := r.stores[registration.ID]; ok {
		return domain.ArtifactStore{}, errors.New("duplicate artifact store")
	}
	store := domain.ArtifactStore{ArtifactStoreRegistration: registration}
	r.stores[registration.ID] = store
	return store, nil
}
