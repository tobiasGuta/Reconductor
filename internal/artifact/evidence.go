package artifact

import (
	"errors"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

var (
	ErrEvidenceUnavailable        = errors.New("evidence_unavailable")
	ErrEvidenceRestricted         = errors.New("evidence_restricted")
	ErrEvidenceVerificationFailed = errors.New("evidence_verification_failed")
)

// AuthorizedEvidenceArtifactV1 is an internal authorization result. Reference
// contains the storage-owned key required by OpenVerified and must not be
// projected directly into operator output.
type AuthorizedEvidenceArtifactV1 struct {
	Reference            domain.ResultArtifactRefV1
	StoreIdentity        StoreIdentity
	ProgramID            domain.ID
	TaskID               domain.ID
	WorkflowRunID        domain.ID
	StepRunID            domain.ID
	StepDefinitionID     string
	ToolRunID            domain.ID
	ActionRequestID      domain.ID
	ProviderAttemptID    domain.ID
	ResultOccurrenceID   domain.ID
	PublicationID        domain.ID
	CapabilityName       string
	CapabilityVersion    string
	ProviderName         string
	ArtifactType         string
	SemanticCompleteness domain.SemanticCompletenessV1
}
