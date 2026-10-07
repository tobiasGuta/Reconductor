package database

import (
	"errors"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/workflow"
)

func TestAuthorizeSemanticBindingUsesCurrentCleanupLifecycleColumns(t *testing.T) {
	env := newRecoveryTestEnvironment(t, "semantic-binding-cleanup-columns")
	artifactID := domain.NewID()
	storageKey, err := artifact.StorageKeyFor(artifactID)
	if err != nil {
		t.Fatal(err)
	}
	request := domain.SemanticBindingResolutionV1{
		ConsumerProgramID:      domain.NewID(),
		ConsumerWorkflowRunID:  domain.NewID(),
		ConsumerStepDefinition: "consumer",
		SourceStepDefinition:   "source",
		Reference: domain.SemanticBindingReferenceV1{
			SchemaID:                 domain.SemanticBindingReferenceSchemaV1,
			Version:                  domain.SemanticBindingReferenceVersionV1,
			SourceProgramID:          domain.NewID(),
			SourceWorkflowRunID:      domain.NewID(),
			SourceStepRunID:          domain.NewID(),
			SourceActionRequestID:    domain.NewID(),
			SourceResultOccurrenceID: domain.NewID(),
			SourceProviderAttemptID:  domain.NewID(),
			SourceArtifactID:         artifactID,
			ArtifactStoreID:          domain.NewID(),
			StorageKey:               storageKey,
			Selector:                 "authorized_records",
			ContentSHA256:            strings.Repeat("a", 64),
			ContentSizeBytes:         1,
			OutputSchemaSHA256:       strings.Repeat("b", 64),
		},
	}

	_, err = env.store.AuthorizeSemanticBinding(env.ctx, request)
	if !errors.Is(err, ErrSemanticOutputUnavailable) {
		t.Fatalf("AuthorizeSemanticBinding error=%v want %v", err, ErrSemanticOutputUnavailable)
	}
}

func TestMaterializedDependencyAuthorizesConsumerBeforeItsStepRowExists(t *testing.T) {
	definition := workflow.Definition{Steps: []workflow.Step{
		{ID: "source"},
		{ID: "intermediate", DependsOn: []string{"source"}},
		{ID: "consumer", DependsOn: []string{"intermediate"}},
	}}
	if !materializedDependency(definition, "consumer", "source") {
		t.Fatal("materialized transitive dependency was not authorized")
	}
	if materializedDependency(definition, "source", "consumer") {
		t.Fatal("reverse dependency was authorized")
	}
}
