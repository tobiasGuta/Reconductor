package orchestration

import (
	"context"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/config"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

func TestEngineConstructsWithInjectedModernStorageWithoutRetentionPrerequisite(t *testing.T) {
	storage := engineLivenessArtifacts{}
	service := Service{
		Config:    config.Config{Policy: config.Policy{DefaultRateLimit: 1, DefaultConcurrency: 1, DefaultProviderConcurrency: 1, DefaultHostConcurrency: 1}},
		Store:     &database.Store{},
		Registry:  capability.NewRegistry(),
		Artifacts: storage,
	}
	engine, err := service.engine(context.Background(), domain.Task{ProgramID: domain.NewID()}, engineLivenessScope{}, false, workflow.FileStore{Root: t.TempDir()}, nil, domain.NewID())
	if err != nil {
		t.Fatalf("engine construction error=%v", err)
	}
	if engine.Executor == nil {
		t.Fatal("engine did not construct an executor from injected modern artifact storage")
	}
}

type engineLivenessScope struct{}

func (engineLivenessScope) Allows(string) bool { return true }

type engineLivenessArtifacts struct{}

func (engineLivenessArtifacts) Put(_ context.Context, request artifact.PutRequest) (domain.Artifact, error) {
	id := domain.NewID()
	key, err := artifact.StorageKeyFor(id)
	if err != nil {
		return domain.Artifact{}, err
	}
	storeID := domain.ID("00000000-0000-4000-8000-000000009007")
	return domain.Artifact{ID: id, TaskID: request.TaskID, WorkflowRunID: request.WorkflowRunID, StepRunID: request.StepRunID, ToolRunID: request.ToolRunID, Type: request.Type, ContentType: request.ContentType, Size: int64(len(request.Data)), AddressingVersion: 1, ArtifactStoreID: &storeID, StorageKey: &key}, nil
}
