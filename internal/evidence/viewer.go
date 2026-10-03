package evidence

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type Authorizer interface {
	AuthorizeEvidenceView(context.Context, domain.ID, domain.ID) (artifact.AuthorizedEvidenceArtifactV1, error)
}

type AuthorizationLister interface {
	ListEvidenceView(context.Context, domain.ID) ([]artifact.AuthorizedEvidenceArtifactV1, error)
}

type VerifiedStore interface {
	Identity() artifact.StoreIdentity
	OpenVerified(context.Context, domain.ResultArtifactRefV1) (io.ReadCloser, error)
}

type Metadata struct {
	ArtifactID           domain.ID                     `json:"artifact_id"`
	WorkflowRunID        domain.ID                     `json:"workflow_run_id"`
	StepRunID            domain.ID                     `json:"step_run_id"`
	StepDefinitionID     string                        `json:"step_definition_id"`
	ToolRunID            domain.ID                     `json:"tool_run_id"`
	ProviderAttemptID    domain.ID                     `json:"provider_attempt_id"`
	ResultOccurrenceID   domain.ID                     `json:"result_occurrence_id"`
	CapabilityName       string                        `json:"capability"`
	CapabilityVersion    string                        `json:"capability_version"`
	ProviderName         string                        `json:"provider"`
	ArtifactType         string                        `json:"artifact_type"`
	Role                 domain.ResultArtifactRoleV1   `json:"role"`
	ContentType          string                        `json:"content_type"`
	ContentSizeBytes     int64                         `json:"stored_size_bytes"`
	ContentSHA256        string                        `json:"expected_sha256"`
	PublicationState     string                        `json:"publication_state"`
	RedactionState       string                        `json:"redaction_state"`
	AccessStatus         string                        `json:"access_status"`
	IntegrityStatus      string                        `json:"integrity_status"`
	SemanticCompleteness domain.SemanticCompletenessV1 `json:"semantic_completeness"`
}

type Verified struct {
	Metadata Metadata
	Content  []byte
}

type Service struct {
	Authorizer Authorizer
	Lister     AuthorizationLister
	Store      VerifiedStore
}

// List returns only metadata for artifacts that pass the same authoritative
// per-artifact authorization used by Read. It never opens artifact content.
func (s Service) List(ctx context.Context, workflowRunID domain.ID) ([]Metadata, error) {
	if s.Lister == nil || s.Store == nil {
		return nil, artifact.ErrEvidenceUnavailable
	}
	authorized, err := s.Lister.ListEvidenceView(ctx, workflowRunID)
	if err != nil {
		return nil, artifact.ErrEvidenceUnavailable
	}
	items := make([]Metadata, 0, len(authorized))
	for _, item := range authorized {
		if s.Store.Identity() != item.StoreIdentity {
			return nil, artifact.ErrEvidenceUnavailable
		}
		items = append(items, metadataFromAuthorized(item, "not_checked"))
	}
	return items, nil
}

// Read returns content only after the complete object has passed the existing
// verified-reader EOF and Close checks. The database snapshot ends before the
// filesystem open, so cleanup can win that interval; a missing object then
// fails closed. Once OpenVerified acquires the pinned store's shared guard,
// cleanup's exclusive guard cannot remove the object during this read.
func (s Service) Read(ctx context.Context, workflowRunID, artifactID domain.ID) (Verified, error) {
	if s.Authorizer == nil || s.Store == nil {
		return Verified{}, artifact.ErrEvidenceUnavailable
	}
	authorized, err := s.Authorizer.AuthorizeEvidenceView(ctx, workflowRunID, artifactID)
	if err != nil {
		if errors.Is(err, artifact.ErrEvidenceRestricted) {
			return Verified{}, artifact.ErrEvidenceRestricted
		}
		return Verified{}, artifact.ErrEvidenceUnavailable
	}
	if s.Store.Identity() != authorized.StoreIdentity {
		return Verified{}, artifact.ErrEvidenceUnavailable
	}
	if authorized.Reference.ContentSizeBytes < 0 || authorized.Reference.ContentSizeBytes > domain.PreparedSetOutputAuthorityMaxBytes {
		return Verified{}, artifact.ErrEvidenceUnavailable
	}

	reader, err := s.Store.OpenVerified(ctx, authorized.Reference)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Verified{}, artifact.ErrEvidenceUnavailable
		}
		return Verified{}, artifact.ErrEvidenceVerificationFailed
	}
	content, readErr := io.ReadAll(io.LimitReader(reader, domain.PreparedSetOutputAuthorityMaxBytes+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || int64(len(content)) != authorized.Reference.ContentSizeBytes || int64(len(content)) > domain.PreparedSetOutputAuthorityMaxBytes {
		return Verified{}, artifact.ErrEvidenceVerificationFailed
	}

	return Verified{
		Metadata: metadataFromAuthorized(authorized, "verified"),
		Content:  append([]byte(nil), content...),
	}, nil
}

func metadataFromAuthorized(authorized artifact.AuthorizedEvidenceArtifactV1, integrityStatus string) Metadata {
	return Metadata{
		ArtifactID:           authorized.Reference.ArtifactID,
		WorkflowRunID:        authorized.WorkflowRunID,
		StepRunID:            authorized.StepRunID,
		StepDefinitionID:     authorized.StepDefinitionID,
		ToolRunID:            authorized.ToolRunID,
		ProviderAttemptID:    authorized.ProviderAttemptID,
		ResultOccurrenceID:   authorized.ResultOccurrenceID,
		CapabilityName:       authorized.CapabilityName,
		CapabilityVersion:    authorized.CapabilityVersion,
		ProviderName:         authorized.ProviderName,
		ArtifactType:         authorized.ArtifactType,
		Role:                 authorized.Reference.Role,
		ContentType:          authorized.Reference.ContentType,
		ContentSizeBytes:     authorized.Reference.ContentSizeBytes,
		ContentSHA256:        authorized.Reference.ContentSHA256,
		PublicationState:     string(domain.PublicationAdopted),
		RedactionState:       "redacted",
		AccessStatus:         "permitted",
		IntegrityStatus:      integrityStatus,
		SemanticCompleteness: authorized.SemanticCompleteness,
	}
}
