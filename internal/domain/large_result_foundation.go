package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SafeMessageMaxBytes               = 500
	DiagnosticMaxBytes                = 4_096
	FailureFinalizationRecordMaxBytes = 16_384
	WorkflowSummaryMaxBytes           = 16_384
	RunStatusMaxBytes                 = 65_536
	RecoveryCheckpointMaxBytes        = 65_536
	GlobalCheckpointMaxBytes          = 8_388_608
	PGXEncodedMessageMaxBytes         = 8_388_608

	StepAttemptLeaseDefault = 2 * time.Minute
	StepAttemptLeaseMinimum = 3 * time.Second
	StepAttemptLeaseMaximum = 15 * time.Minute
)

type PublicationState string

const (
	PublicationReserved    PublicationState = "reserved"
	PublicationPublishing  PublicationState = "publishing"
	PublicationSealed      PublicationState = "sealed"
	PublicationAdopted     PublicationState = "adopted"
	PublicationAbandoned   PublicationState = "abandoned"
	PublicationQuarantined PublicationState = "quarantined"
)

type FailureFinalizationRecordState string

const (
	FailureRecordPrepared             FailureFinalizationRecordState = "prepared"
	FailureRecordProviderStarted      FailureFinalizationRecordState = "provider_started"
	FailureRecordProviderTerminal     FailureFinalizationRecordState = "provider_terminal"
	FailureRecordAdmissionPending     FailureFinalizationRecordState = "admission_pending"
	FailureRecordCommitUnknown        FailureFinalizationRecordState = "commit_unknown"
	FailureRecordFinalizationRequired FailureFinalizationRecordState = "finalization_required"
	FailureRecordFinalizationCharged  FailureFinalizationRecordState = "finalization_charged"
	FailureRecordStepFinalized        FailureFinalizationRecordState = "step_finalized"
	FailureRecordFinalized            FailureFinalizationRecordState = "finalized"
	FailureRecordResolvedAdopted      FailureFinalizationRecordState = "resolved_adopted"
	FailureRecordResolvedRetryable    FailureFinalizationRecordState = "resolved_retryable"
	FailureRecordSuperseded           FailureFinalizationRecordState = "superseded"
	FailureRecordManualReviewRequired FailureFinalizationRecordState = "manual_review_required"
)

type ProviderOutcome string

const (
	ProviderOutcomeNotStarted ProviderOutcome = "not_started"
	ProviderOutcomeUnknown    ProviderOutcome = "unknown"
	ProviderOutcomeSucceeded  ProviderOutcome = "succeeded"
	ProviderOutcomeFailed     ProviderOutcome = "failed"
	ProviderOutcomeCancelled  ProviderOutcome = "cancelled"
	ProviderOutcomeTimeout    ProviderOutcome = "timeout"
)

type ResultPersistenceOutcome string

const (
	ResultPersistenceNotAttempted       ResultPersistenceOutcome = "not_attempted"
	ResultPersistenceAdmissionPending   ResultPersistenceOutcome = "admission_pending"
	ResultPersistenceConfirmedNotCommit ResultPersistenceOutcome = "confirmed_not_committed"
	ResultPersistenceCommitUnknown      ResultPersistenceOutcome = "commit_unknown"
	ResultPersistenceCommitted          ResultPersistenceOutcome = "committed"
)

type AdoptionResolution string

const (
	AdoptionNotApplicable          AdoptionResolution = "not_applicable"
	AdoptionUnresolved             AdoptionResolution = "unresolved"
	AdoptionVerified               AdoptionResolution = "adopted_verified"
	AdoptionNonadoptionAbandoned   AdoptionResolution = "nonadoption_abandoned"
	AdoptionNonadoptionQuarantined AdoptionResolution = "nonadoption_quarantined"
	AdoptionInconsistent           AdoptionResolution = "inconsistent"
)

type FailurePropagationState string

const (
	FailurePropagationNotApplicable FailurePropagationState = "not_applicable"
	FailurePropagationPending       FailurePropagationState = "pending"
	FailurePropagationCompleted     FailurePropagationState = "completed"
)

type FinalizationAttemptState string

const (
	FinalizationNotCharged          FinalizationAttemptState = "not_charged"
	FinalizationCharged             FinalizationAttemptState = "charged"
	FinalizationExecuting           FinalizationAttemptState = "executing"
	FinalizationCommitUnknown       FinalizationAttemptState = "commit_unknown"
	FinalizationConfirmedRolledBack FinalizationAttemptState = "confirmed_rolled_back"
	FinalizationCommitted           FinalizationAttemptState = "committed"
	FinalizationRollbackUnknown     FinalizationAttemptState = "rollback_unknown"
	FinalizationExhausted           FinalizationAttemptState = "exhausted"
)

type StepAttemptClaimState string

const (
	StepAttemptClaimActive        StepAttemptClaimState = "active"
	StepAttemptClaimRecoveryOwned StepAttemptClaimState = "recovery_owned"
	StepAttemptClaimReleased      StepAttemptClaimState = "released"
	StepAttemptClaimTerminal      StepAttemptClaimState = "terminal"
)

type ClaimOwnerKind string

const (
	ClaimOwnerScheduler           ClaimOwnerKind = "scheduler"
	ClaimOwnerQueueWorker         ClaimOwnerKind = "queue_worker"
	ClaimOwnerDirectCLI           ClaimOwnerKind = "direct_cli"
	ClaimOwnerRecovery            ClaimOwnerKind = "recovery"
	ClaimOwnerWorkflowCoordinator ClaimOwnerKind = "workflow_coordinator"
)

type WaveDispatchState string

const (
	WaveDispatchPending              WaveDispatchState = "pending"
	WaveDispatchClaimed              WaveDispatchState = "claimed"
	WaveDispatchCompleted            WaveDispatchState = "completed"
	WaveDispatchCancelled            WaveDispatchState = "cancelled"
	WaveDispatchSuperseded           WaveDispatchState = "superseded"
	WaveDispatchManualReviewRequired WaveDispatchState = "manual_review_required"
)

type WavePropagationState string

const (
	WavePropagationNotRequired          WavePropagationState = "not_required"
	WavePropagationPending              WavePropagationState = "pending"
	WavePropagationClaimed              WavePropagationState = "claimed"
	WavePropagationCompleted            WavePropagationState = "completed"
	WavePropagationSuperseded           WavePropagationState = "superseded"
	WavePropagationManualReviewRequired WavePropagationState = "manual_review_required"
)

type WaveMemberState string

const (
	WaveMemberPlanned          WaveMemberState = "planned"
	WaveMemberActive           WaveMemberState = "active"
	WaveMemberRetryPending     WaveMemberState = "retry_pending"
	WaveMemberTerminal         WaveMemberState = "terminal"
	WaveMemberRecoveryRequired WaveMemberState = "recovery_required"
)

type LargeResultAuditEventType string

const (
	AuditAttemptRecoveryPrepared           LargeResultAuditEventType = "attempt_recovery_prepared"
	AuditResultCommitUnknown               LargeResultAuditEventType = "result_commit_unknown"
	AuditResultCommitResolved              LargeResultAuditEventType = "result_commit_resolved"
	AuditFailureRecoveryClaimed            LargeResultAuditEventType = "failure_recovery_claimed"
	AuditFailureFinalizationAttemptCharged LargeResultAuditEventType = "failure_finalization_attempt_charged"
	AuditFailureFinalizationAttemptBegun   LargeResultAuditEventType = "failure_finalization_attempt_begun"
	AuditFailureFinalizationCommitted      LargeResultAuditEventType = "failure_finalization_committed"
	AuditFailureFinalizationFailed         LargeResultAuditEventType = "failure_finalization_failed"
	AuditWaveDispatchClaimed               LargeResultAuditEventType = "wave_dispatch_claimed"
	AuditWaveDispatchReleased              LargeResultAuditEventType = "wave_dispatch_released"
	AuditWaveDispatchCompleted             LargeResultAuditEventType = "wave_dispatch_completed"
	AuditWavePropagationClaimed            LargeResultAuditEventType = "wave_propagation_claimed"
	AuditWavePropagationReleased           LargeResultAuditEventType = "wave_propagation_released"
	AuditWavePropagationCompleted          LargeResultAuditEventType = "wave_propagation_completed"
	AuditStepAttemptClaimReleased          LargeResultAuditEventType = "step_attempt_claim_released"
	AuditProviderRetryResolved             LargeResultAuditEventType = "provider_retry_resolved"
)

var (
	publicationStates         = closedValues(PublicationReserved, PublicationPublishing, PublicationSealed, PublicationAdopted, PublicationAbandoned, PublicationQuarantined)
	failureRecordStates       = closedValues(FailureRecordPrepared, FailureRecordProviderStarted, FailureRecordProviderTerminal, FailureRecordAdmissionPending, FailureRecordCommitUnknown, FailureRecordFinalizationRequired, FailureRecordFinalizationCharged, FailureRecordStepFinalized, FailureRecordFinalized, FailureRecordResolvedAdopted, FailureRecordResolvedRetryable, FailureRecordSuperseded, FailureRecordManualReviewRequired)
	providerOutcomes          = closedValues(ProviderOutcomeNotStarted, ProviderOutcomeUnknown, ProviderOutcomeSucceeded, ProviderOutcomeFailed, ProviderOutcomeCancelled, ProviderOutcomeTimeout)
	resultPersistenceOutcomes = closedValues(ResultPersistenceNotAttempted, ResultPersistenceAdmissionPending, ResultPersistenceConfirmedNotCommit, ResultPersistenceCommitUnknown, ResultPersistenceCommitted)
	adoptionResolutions       = closedValues(AdoptionNotApplicable, AdoptionUnresolved, AdoptionVerified, AdoptionNonadoptionAbandoned, AdoptionNonadoptionQuarantined, AdoptionInconsistent)
	failurePropagationStates  = closedValues(FailurePropagationNotApplicable, FailurePropagationPending, FailurePropagationCompleted)
	finalizationAttemptStates = closedValues(FinalizationNotCharged, FinalizationCharged, FinalizationExecuting, FinalizationCommitUnknown, FinalizationConfirmedRolledBack, FinalizationCommitted, FinalizationRollbackUnknown, FinalizationExhausted)
	stepAttemptClaimStates    = closedValues(StepAttemptClaimActive, StepAttemptClaimRecoveryOwned, StepAttemptClaimReleased, StepAttemptClaimTerminal)
	claimOwnerKinds           = closedValues(ClaimOwnerScheduler, ClaimOwnerQueueWorker, ClaimOwnerDirectCLI, ClaimOwnerRecovery, ClaimOwnerWorkflowCoordinator)
	waveDispatchStates        = closedValues(WaveDispatchPending, WaveDispatchClaimed, WaveDispatchCompleted, WaveDispatchCancelled, WaveDispatchSuperseded, WaveDispatchManualReviewRequired)
	wavePropagationStates     = closedValues(WavePropagationNotRequired, WavePropagationPending, WavePropagationClaimed, WavePropagationCompleted, WavePropagationSuperseded, WavePropagationManualReviewRequired)
	waveMemberStates          = closedValues(WaveMemberPlanned, WaveMemberActive, WaveMemberRetryPending, WaveMemberTerminal, WaveMemberRecoveryRequired)
	largeResultAuditEvents    = closedValues(AuditAttemptRecoveryPrepared, AuditResultCommitUnknown, AuditResultCommitResolved, AuditFailureRecoveryClaimed, AuditFailureFinalizationAttemptCharged, AuditFailureFinalizationAttemptBegun, AuditFailureFinalizationCommitted, AuditFailureFinalizationFailed, AuditWaveDispatchClaimed, AuditWaveDispatchReleased, AuditWaveDispatchCompleted, AuditWavePropagationClaimed, AuditWavePropagationReleased, AuditWavePropagationCompleted, AuditStepAttemptClaimReleased, AuditProviderRetryResolved)
)

func closedValues[T ~string](values ...T) map[T]struct{} {
	result := make(map[T]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func validateClosed[T ~string](kind string, value T, allowed map[T]struct{}) error {
	if _, ok := allowed[value]; !ok {
		return fmt.Errorf("invalid %s %q", kind, value)
	}
	return nil
}

func (v PublicationState) Validate() error {
	return validateClosed("publication state", v, publicationStates)
}
func (v FailureFinalizationRecordState) Validate() error {
	return validateClosed("failure finalization record state", v, failureRecordStates)
}
func (v ProviderOutcome) Validate() error {
	return validateClosed("provider outcome", v, providerOutcomes)
}
func (v ResultPersistenceOutcome) Validate() error {
	return validateClosed("result persistence outcome", v, resultPersistenceOutcomes)
}
func (v AdoptionResolution) Validate() error {
	return validateClosed("adoption resolution", v, adoptionResolutions)
}
func (v FailurePropagationState) Validate() error {
	return validateClosed("failure propagation state", v, failurePropagationStates)
}
func (v FinalizationAttemptState) Validate() error {
	return validateClosed("finalization attempt state", v, finalizationAttemptStates)
}
func (v StepAttemptClaimState) Validate() error {
	return validateClosed("step attempt claim state", v, stepAttemptClaimStates)
}
func (v ClaimOwnerKind) Validate() error {
	return validateClosed("claim owner kind", v, claimOwnerKinds)
}
func (v WaveDispatchState) Validate() error {
	return validateClosed("wave dispatch state", v, waveDispatchStates)
}
func (v WavePropagationState) Validate() error {
	return validateClosed("wave propagation state", v, wavePropagationStates)
}
func (v WaveMemberState) Validate() error {
	return validateClosed("wave member state", v, waveMemberStates)
}
func (v LargeResultAuditEventType) Validate() error {
	return validateClosed("large-result audit event type", v, largeResultAuditEvents)
}
func (v WaveMemberState) IsTerminal() bool { return v == WaveMemberTerminal }
func (v WaveMemberState) IsValidNonterminal() bool {
	return v == WaveMemberPlanned || v == WaveMemberActive || v == WaveMemberRetryPending || v == WaveMemberRecoveryRequired
}

type ArtifactPublication struct {
	ID                    ID               `json:"id"`
	ProviderAttemptID     ID               `json:"provider_attempt_id"`
	PublicationOrdinal    int              `json:"publication_ordinal"`
	ResultOccurrenceID    ID               `json:"result_occurrence_id"`
	ArtifactID            ID               `json:"artifact_id"`
	ArtifactStoreID       ID               `json:"artifact_store_id"`
	StorageKey            string           `json:"storage_key"`
	ContentType           string           `json:"content_type"`
	ContentSizeBytes      int64            `json:"content_size_bytes"`
	ContentSHA256         string           `json:"content_sha256"`
	State                 PublicationState `json:"publication_state"`
	OriginOwnerInstanceID ID               `json:"origin_owner_instance_id"`
	OwnerKind             *ClaimOwnerKind  `json:"owner_kind,omitempty"`
	OwnerInstanceID       *ID              `json:"owner_instance_id,omitempty"`
	PublicationToken      *ID              `json:"publication_token,omitempty"`
	FenceGeneration       int64            `json:"fence_generation"`
	LeaseDuration         time.Duration    `json:"lease_duration"`
	LeaseExpiresAt        *time.Time       `json:"lease_expires_at,omitempty"`
	ReservedAt            time.Time        `json:"reserved_at"`
	PublishingAt          *time.Time       `json:"publishing_at,omitempty"`
	SealedAt              *time.Time       `json:"sealed_at,omitempty"`
	AdoptedAt             *time.Time       `json:"adopted_at,omitempty"`
	AbandonedAt           *time.Time       `json:"abandoned_at,omitempty"`
	QuarantinedAt         *time.Time       `json:"quarantined_at,omitempty"`
	QuarantineReasonCode  string           `json:"quarantine_reason_code,omitempty"`
	ContentDeletedAt      *time.Time       `json:"content_deleted_at,omitempty"`
	CleanupClaimToken     *ID              `json:"cleanup_claim_token,omitempty"`
	CleanupClaimedAt      *time.Time       `json:"cleanup_claimed_at,omitempty"`
	CleanupRetryAfter     *time.Time       `json:"cleanup_retry_after,omitempty"`
	CleanupLastErrorCode  string           `json:"cleanup_last_error_code,omitempty"`
	CleanupQuarantinedAt  *time.Time       `json:"cleanup_quarantined_at,omitempty"`
	RowVersion            int64            `json:"row_version"`
	CreatedAt             time.Time        `json:"created_at"`
	UpdatedAt             time.Time        `json:"updated_at"`
}

func (p ArtifactPublication) Validate() error {
	if err := p.State.Validate(); err != nil {
		return err
	}
	if p.ID == "" || p.ProviderAttemptID == "" || p.ResultOccurrenceID == "" || p.ArtifactID == "" || p.ArtifactStoreID == "" || p.OriginOwnerInstanceID == "" {
		return fmt.Errorf("artifact publication requires complete durable identity")
	}
	if p.PublicationOrdinal < 0 || p.ContentSizeBytes < 0 || p.FenceGeneration < 1 || p.RowVersion < 1 {
		return fmt.Errorf("artifact publication has invalid ordinal, size, or row version")
	}
	if p.LeaseDuration < StepAttemptLeaseMinimum || p.LeaseDuration > StepAttemptLeaseMaximum {
		return fmt.Errorf("artifact publication lease must be between %s and %s", StepAttemptLeaseMinimum, StepAttemptLeaseMaximum)
	}
	if err := ValidateUTF8Bytes("content type", p.ContentType, 255); err != nil || p.ContentType == "" {
		if err != nil {
			return err
		}
		return fmt.Errorf("content type is required")
	}
	if !validLowerHexDigest(p.ContentSHA256) {
		return fmt.Errorf("content SHA-256 must be 64 lowercase hexadecimal bytes")
	}
	if _, err := ParseID(string(p.ArtifactID)); err != nil {
		return fmt.Errorf("artifact publication artifact ID: %w", err)
	}
	wantStorageKey := "v1/" + strings.ReplaceAll(string(p.ArtifactID), "-", "")[:2] + "/" + string(p.ArtifactID)
	if p.StorageKey != wantStorageKey {
		return fmt.Errorf("artifact publication storage key does not match its immutable artifact ID")
	}
	owned := p.OwnerKind != nil && p.OwnerInstanceID != nil && p.PublicationToken != nil && p.LeaseExpiresAt != nil
	if p.State == PublicationReserved || p.State == PublicationPublishing || p.State == PublicationSealed {
		if !owned {
			return fmt.Errorf("nonterminal publication requires current ownership")
		}
		if err := p.OwnerKind.Validate(); err != nil {
			return err
		}
	} else if owned || p.OwnerKind != nil || p.OwnerInstanceID != nil || p.PublicationToken != nil || p.LeaseExpiresAt != nil {
		return fmt.Errorf("terminal publication cannot carry current ownership")
	}
	if err := ValidateUTF8Bytes("publication quarantine reason", p.QuarantineReasonCode, 64); err != nil {
		return err
	}
	if p.State == PublicationQuarantined && p.QuarantineReasonCode == "" {
		return fmt.Errorf("quarantined publication requires a reason code")
	}
	if p.State != PublicationQuarantined && p.QuarantineReasonCode != "" {
		return fmt.Errorf("non-quarantined publication cannot carry a quarantine reason")
	}
	if err := validatePublicationTimestampShape(p); err != nil {
		return err
	}
	return validatePublicationCleanupShape(p)
}

type FinalizationAttemptSlot struct {
	ChargeID       ID `json:"charge_id"`
	ChargeAuditID  ID `json:"charge_audit_event_id"`
	BeginEventID   ID `json:"begin_event_id"`
	OutcomeEventID ID `json:"outcome_event_id"`
}

type FailureFinalizationRecord struct {
	RecordID                    ID                             `json:"record_id"`
	RecordVersion               int                            `json:"record_version"`
	RowVersion                  int64                          `json:"row_version"`
	ProgramID                   ID                             `json:"program_id"`
	TaskID                      ID                             `json:"task_id"`
	WorkflowRunID               ID                             `json:"workflow_run_id"`
	StepRunID                   ID                             `json:"step_run_id"`
	StepAttempt                 int                            `json:"step_attempt"`
	ActionRequestID             ID                             `json:"action_request_id"`
	ResultOccurrenceID          ID                             `json:"result_occurrence_id"`
	WaveID                      ID                             `json:"wave_id"`
	WaveMemberOrdinal           int                            `json:"wave_member_ordinal"`
	ScheduledExecutionID        *ID                            `json:"scheduled_execution_id,omitempty"`
	SchedulerAttempt            *int                           `json:"scheduler_attempt,omitempty"`
	QueueJobID                  *ID                            `json:"queue_job_id,omitempty"`
	ExecutionAuthorizationID    ID                             `json:"execution_authorization_event_id"`
	OriginOwnerInstanceID       ID                             `json:"origin_owner_instance_id"`
	ClaimToken                  ID                             `json:"claim_token"`
	ClaimFenceGeneration        int64                          `json:"claim_fence_generation"`
	ProviderAttemptID           *ID                            `json:"provider_attempt_id,omitempty"`
	ProviderTerminalEventID     *ID                            `json:"provider_terminal_event_id,omitempty"`
	ProviderResultAcceptedID    *ID                            `json:"provider_result_accepted_event_id,omitempty"`
	ToolRunID                   *ID                            `json:"tool_run_id,omitempty"`
	Capability                  string                         `json:"capability"`
	Provider                    string                         `json:"provider,omitempty"`
	ProviderOutcome             ProviderOutcome                `json:"provider_outcome"`
	ResultPersistenceOutcome    ResultPersistenceOutcome       `json:"result_persistence_outcome"`
	AdoptionResolution          AdoptionResolution             `json:"adoption_resolution"`
	State                       FailureFinalizationRecordState `json:"record_state"`
	PropagationState            FailurePropagationState        `json:"propagation_state"`
	FailureCode                 string                         `json:"failure_code,omitempty"`
	ReasonCode                  string                         `json:"reason_code,omitempty"`
	SafeMessage                 string                         `json:"safe_message"`
	Diagnostic                  json.RawMessage                `json:"diagnostic"`
	AutomaticAttemptCount       int                            `json:"automatic_attempt_count"`
	FinalizationAttemptState    FinalizationAttemptState       `json:"finalization_attempt_state"`
	FinalizationChargeVersion   int64                          `json:"finalization_charge_version"`
	LastFinalizationChargeID    *ID                            `json:"last_finalization_charge_id,omitempty"`
	FinalizationExecutionCharge *int                           `json:"finalization_execution_charge_number,omitempty"`
	FinalizationExecutionToken  *ID                            `json:"finalization_execution_claim_token,omitempty"`
	FinalizationExecutionFence  *int64                         `json:"finalization_execution_fence_generation,omitempty"`
	Charge1                     FinalizationAttemptSlot        `json:"charge_1"`
	Charge2                     FinalizationAttemptSlot        `json:"charge_2"`
	ResultCommitUnknownEventID  ID                             `json:"result_commit_unknown_event_id"`
	ResultCommitResolutionID    ID                             `json:"result_commit_resolution_event_id"`
	FinalizationFailedEventID   ID                             `json:"failure_finalization_failed_event_id"`
	CreatedAt                   time.Time                      `json:"created_at"`
	UpdatedAt                   time.Time                      `json:"updated_at"`
	ResolvedAt                  *time.Time                     `json:"resolved_at,omitempty"`
}

func (r FailureFinalizationRecord) Validate() error {
	for _, check := range []error{r.ProviderOutcome.Validate(), r.ResultPersistenceOutcome.Validate(), r.AdoptionResolution.Validate(), r.State.Validate(), r.PropagationState.Validate(), r.FinalizationAttemptState.Validate()} {
		if check != nil {
			return check
		}
	}
	if r.RecordVersion != 1 || r.RowVersion < 1 || r.StepAttempt < 1 || r.WaveMemberOrdinal < 0 || r.ClaimFenceGeneration < 1 {
		return fmt.Errorf("failure finalization record has invalid version, attempt, or ordinal")
	}
	if r.RecordID == "" || r.ProgramID == "" || r.TaskID == "" || r.WorkflowRunID == "" || r.StepRunID == "" || r.ActionRequestID == "" || r.ResultOccurrenceID == "" || r.WaveID == "" || r.ExecutionAuthorizationID == "" || r.OriginOwnerInstanceID == "" || r.ClaimToken == "" {
		return fmt.Errorf("failure finalization record requires complete durable identity")
	}
	if (r.ScheduledExecutionID == nil) != (r.SchedulerAttempt == nil) || (r.SchedulerAttempt != nil && *r.SchedulerAttempt < 1) {
		return fmt.Errorf("failure finalization record has invalid scheduled lineage")
	}
	if err := ValidateUTF8Bytes("capability", r.Capability, 128); err != nil || r.Capability == "" {
		if err != nil {
			return err
		}
		return fmt.Errorf("capability is required")
	}
	if err := ValidateUTF8Bytes("provider", r.Provider, 128); err != nil {
		return err
	}
	providerIdentity := r.ProviderAttemptID != nil && r.ProviderTerminalEventID != nil && r.ProviderResultAcceptedID != nil && r.ToolRunID != nil && r.Provider != ""
	providerAbsent := r.ProviderAttemptID == nil && r.ProviderTerminalEventID == nil && r.ProviderResultAcceptedID == nil && r.ToolRunID == nil && r.Provider == ""
	if !providerIdentity && !providerAbsent {
		return fmt.Errorf("failure finalization record has partial provider identity")
	}
	if (providerAbsent && r.ProviderOutcome != ProviderOutcomeNotStarted) || (providerIdentity && r.ProviderOutcome == ProviderOutcomeNotStarted) {
		return fmt.Errorf("failure finalization record provider outcome does not match provider identity")
	}
	if err := ValidateUTF8Bytes("failure code", r.FailureCode, 64); err != nil {
		return err
	}
	if err := ValidateUTF8Bytes("reason code", r.ReasonCode, 64); err != nil {
		return err
	}
	if err := ValidateUTF8Bytes("safe message", r.SafeMessage, SafeMessageMaxBytes); err != nil {
		return err
	}
	if err := ValidateJSONObjectBytes("diagnostic", r.Diagnostic, DiagnosticMaxBytes); err != nil {
		return err
	}
	if err := ValidateFinalizationAttemptShape(r.AutomaticAttemptCount, r.FinalizationAttemptState); err != nil {
		return err
	}
	if err := validateFinalizationSlots(r); err != nil {
		return err
	}
	switch r.AutomaticAttemptCount {
	case 0:
		if r.FinalizationChargeVersion != 0 || r.LastFinalizationChargeID != nil {
			return fmt.Errorf("uncharged finalization cannot carry charge metadata")
		}
	case 1:
		if r.FinalizationChargeVersion != 1 || r.LastFinalizationChargeID == nil || *r.LastFinalizationChargeID != r.Charge1.ChargeID {
			return fmt.Errorf("first finalization charge metadata is inconsistent")
		}
	case 2:
		if r.FinalizationChargeVersion != 2 || r.LastFinalizationChargeID == nil || *r.LastFinalizationChargeID != r.Charge2.ChargeID {
			return fmt.Errorf("second finalization charge metadata is inconsistent")
		}
	}
	if r.FinalizationAttemptState == FinalizationExecuting {
		if r.FinalizationExecutionCharge == nil || *r.FinalizationExecutionCharge != r.AutomaticAttemptCount || r.FinalizationExecutionToken == nil || r.FinalizationExecutionFence == nil || *r.FinalizationExecutionFence < 1 {
			return fmt.Errorf("executing finalization requires the exact current charge, token, and positive fence")
		}
	} else if r.FinalizationAttemptState == FinalizationCommitUnknown {
		completeBinding := r.FinalizationExecutionCharge != nil && *r.FinalizationExecutionCharge == r.AutomaticAttemptCount && r.FinalizationExecutionToken != nil && r.FinalizationExecutionFence != nil && *r.FinalizationExecutionFence > 0
		emptyBinding := r.FinalizationExecutionCharge == nil && r.FinalizationExecutionToken == nil && r.FinalizationExecutionFence == nil
		if !completeBinding && !emptyBinding {
			return fmt.Errorf("commit-unknown finalization has partial execution binding")
		}
	} else if r.FinalizationExecutionCharge != nil || r.FinalizationExecutionToken != nil || r.FinalizationExecutionFence != nil {
		return fmt.Errorf("non-executing finalization cannot carry execution binding")
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("serialize failure finalization record: %w", err)
	}
	return ValidateSerializedBytes("failure finalization record", encoded, FailureFinalizationRecordMaxBytes)
}

type StepAttemptClaim struct {
	StepRunID             ID                    `json:"step_run_id"`
	StepAttempt           int                   `json:"step_attempt"`
	ActionRequestID       ID                    `json:"action_request_id"`
	RecordID              ID                    `json:"record_id"`
	WaveID                ID                    `json:"wave_id"`
	WaveMemberOrdinal     int                   `json:"wave_member_ordinal"`
	State                 StepAttemptClaimState `json:"claim_state"`
	OwnerKind             *ClaimOwnerKind       `json:"owner_kind,omitempty"`
	OwnerInstanceID       *ID                   `json:"owner_instance_id,omitempty"`
	OriginOwnerInstanceID ID                    `json:"origin_owner_instance_id"`
	ClaimToken            *ID                   `json:"claim_token,omitempty"`
	FenceGeneration       int64                 `json:"fence_generation"`
	LeaseDuration         time.Duration         `json:"lease_duration"`
	LeaseExpiresAt        *time.Time            `json:"lease_expires_at,omitempty"`
	RenewalSequence       int64                 `json:"renewal_sequence"`
	LastRenewalID         *ID                   `json:"last_renewal_id,omitempty"`
	LastRenewedAt         *time.Time            `json:"last_renewed_at,omitempty"`
	LastReleaseID         *ID                   `json:"last_release_id,omitempty"`
	ScheduledExecutionID  *ID                   `json:"scheduled_execution_id,omitempty"`
	SchedulerAttempt      *int                  `json:"scheduler_attempt,omitempty"`
	QueueJobID            *ID                   `json:"queue_job_id,omitempty"`
	ClosedAt              *time.Time            `json:"closed_at,omitempty"`
	CloseReason           string                `json:"close_reason,omitempty"`
	RowVersion            int64                 `json:"row_version"`
	CreatedAt             time.Time             `json:"created_at"`
	UpdatedAt             time.Time             `json:"updated_at"`
}

func (c StepAttemptClaim) Validate() error {
	if err := c.State.Validate(); err != nil {
		return err
	}
	for _, identity := range []struct {
		field string
		value ID
	}{
		{"step run ID", c.StepRunID},
		{"action request ID", c.ActionRequestID},
		{"record ID", c.RecordID},
		{"wave ID", c.WaveID},
		{"origin owner instance ID", c.OriginOwnerInstanceID},
	} {
		if err := validateRequiredCanonicalID(identity.field, identity.value); err != nil {
			return err
		}
	}
	for _, identity := range []struct {
		field string
		value *ID
	}{
		{"owner instance ID", c.OwnerInstanceID},
		{"claim token", c.ClaimToken},
		{"last renewal ID", c.LastRenewalID},
		{"last release ID", c.LastReleaseID},
		{"scheduled execution ID", c.ScheduledExecutionID},
		{"queue job ID", c.QueueJobID},
	} {
		if identity.value != nil {
			if err := validateRequiredCanonicalID(identity.field, *identity.value); err != nil {
				return err
			}
		}
	}
	if c.StepAttempt < 1 || c.WaveMemberOrdinal < 0 || c.FenceGeneration < 1 || c.RowVersion < 1 {
		return fmt.Errorf("step attempt claim has invalid attempt, ordinal, generation, or row version")
	}
	if c.LeaseDuration < StepAttemptLeaseMinimum || c.LeaseDuration > StepAttemptLeaseMaximum {
		return fmt.Errorf("step attempt lease must be between %s and %s", StepAttemptLeaseMinimum, StepAttemptLeaseMaximum)
	}
	if (c.ScheduledExecutionID == nil) != (c.SchedulerAttempt == nil) || (c.SchedulerAttempt != nil && *c.SchedulerAttempt < 1) {
		return fmt.Errorf("step attempt claim has invalid scheduled lineage")
	}
	if c.RenewalSequence < 0 ||
		(c.RenewalSequence == 0 && (c.LastRenewalID != nil || c.LastRenewedAt != nil)) ||
		(c.RenewalSequence > 0 && (c.LastRenewalID == nil || c.LastRenewedAt == nil)) {
		return fmt.Errorf("step attempt claim has invalid renewal shape")
	}
	currentOwner := c.OwnerKind != nil && c.OwnerInstanceID != nil && c.ClaimToken != nil && c.LeaseExpiresAt != nil
	switch c.State {
	case StepAttemptClaimActive, StepAttemptClaimRecoveryOwned:
		if !currentOwner || c.ClosedAt != nil || c.CloseReason != "" {
			return fmt.Errorf("owned claim requires current ownership and no closure")
		}
		if err := c.OwnerKind.Validate(); err != nil {
			return err
		}
	case StepAttemptClaimReleased:
		if currentOwner || c.OwnerKind != nil || c.OwnerInstanceID != nil || c.ClaimToken != nil || c.LeaseExpiresAt != nil || c.ClosedAt == nil || c.CloseReason == "" || c.LastReleaseID == nil {
			return fmt.Errorf("released claim has invalid state shape")
		}
	case StepAttemptClaimTerminal:
		if currentOwner || c.OwnerKind != nil || c.OwnerInstanceID != nil || c.ClaimToken != nil || c.LeaseExpiresAt != nil || c.ClosedAt == nil || c.CloseReason == "" {
			return fmt.Errorf("terminal claim has invalid state shape")
		}
	}
	return ValidateUTF8Bytes("claim close reason", c.CloseReason, 64)
}

type WorkflowAttemptWave struct {
	WaveID                ID                   `json:"wave_id"`
	WorkflowRunID         ID                   `json:"workflow_run_id"`
	WaveSequence          int64                `json:"wave_sequence"`
	MaterializationDigest string               `json:"materialization_digest"`
	MemberCount           int                  `json:"member_count"`
	PropagationState      WavePropagationState `json:"propagation_state"`
	PropagationClaim      WaveLeaseClaim       `json:"propagation_claim"`
	DispatchState         WaveDispatchState    `json:"dispatch_state"`
	DispatchClaim         WaveLeaseClaim       `json:"dispatch_claim"`
	RowVersion            int64                `json:"row_version"`
	CreatedAt             time.Time            `json:"created_at"`
	UpdatedAt             time.Time            `json:"updated_at"`
}

type WaveLeaseClaim struct {
	OwnerKind       *ClaimOwnerKind `json:"owner_kind,omitempty"`
	OwnerInstanceID *ID             `json:"owner_instance_id,omitempty"`
	Token           *ID             `json:"token,omitempty"`
	FenceGeneration int64           `json:"fence_generation"`
	LeaseDuration   time.Duration   `json:"lease_duration"`
	LeaseExpiresAt  *time.Time      `json:"lease_expires_at,omitempty"`
	RenewalSequence int64           `json:"renewal_sequence"`
	LastRenewalID   *ID             `json:"last_renewal_id,omitempty"`
	LastEventID     *ID             `json:"last_event_id,omitempty"`
}

type WorkflowWaveMember struct {
	WaveID                 ID              `json:"wave_id"`
	MemberOrdinal          int             `json:"member_ordinal"`
	StepRunID              ID              `json:"step_run_id"`
	StepDefinitionID       string          `json:"step_definition_id"`
	CurrentStepAttempt     int             `json:"current_step_attempt"`
	CurrentActionRequestID *ID             `json:"current_action_request_id,omitempty"`
	State                  WaveMemberState `json:"member_state"`
	CreatedAt              time.Time       `json:"created_at"`
	UpdatedAt              time.Time       `json:"updated_at"`
}

func (w WorkflowAttemptWave) Validate() error {
	if err := w.PropagationState.Validate(); err != nil {
		return err
	}
	if err := w.DispatchState.Validate(); err != nil {
		return err
	}
	if w.WaveID == "" || w.WorkflowRunID == "" || w.WaveSequence < 1 || w.MemberCount < 1 || w.RowVersion < 1 {
		return fmt.Errorf("workflow attempt wave has invalid identity, sequence, member count, or row version")
	}
	if !validLowerHexDigest(w.MaterializationDigest) {
		return fmt.Errorf("materialization digest must be 64 lowercase hexadecimal bytes")
	}
	if err := validateWaveLeaseClaim(w.PropagationState == WavePropagationClaimed, w.PropagationClaim); err != nil {
		return fmt.Errorf("propagation claim: %w", err)
	}
	if err := validateWaveLeaseClaim(w.DispatchState == WaveDispatchClaimed, w.DispatchClaim); err != nil {
		return fmt.Errorf("dispatch claim: %w", err)
	}
	return nil
}

func (m WorkflowWaveMember) Validate() error {
	if err := m.State.Validate(); err != nil {
		return err
	}
	if m.WaveID == "" || m.StepRunID == "" || m.MemberOrdinal < 0 || m.StepDefinitionID == "" {
		return fmt.Errorf("workflow wave member has invalid identity or ordinal")
	}
	if err := ValidateUTF8Bytes("step definition ID", m.StepDefinitionID, 255); err != nil {
		return err
	}
	if m.State == WaveMemberPlanned {
		if m.CurrentStepAttempt != 0 || m.CurrentActionRequestID != nil {
			return fmt.Errorf("planned member cannot carry current attempt identity")
		}
		return nil
	}
	if m.CurrentStepAttempt < 1 || m.CurrentActionRequestID == nil {
		return fmt.Errorf("non-planned member requires current attempt identity")
	}
	return nil
}

func ValidateFinalizationAttemptShape(count int, state FinalizationAttemptState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	switch count {
	case 0:
		if state != FinalizationNotCharged {
			return fmt.Errorf("zero finalization attempts requires not_charged")
		}
	case 1:
		if state == FinalizationNotCharged || state == FinalizationExhausted {
			return fmt.Errorf("one finalization attempt cannot be %s", state)
		}
	case 2:
		if state == FinalizationNotCharged || state == FinalizationConfirmedRolledBack {
			return fmt.Errorf("two finalization attempts cannot be %s", state)
		}
	default:
		return fmt.Errorf("automatic finalization attempt count must be between 0 and 2")
	}
	return nil
}

type LargeResultAuditLinkage struct {
	EventID                     ID                        `json:"event_id"`
	EventType                   LargeResultAuditEventType `json:"event_type"`
	FailureFinalizationRecordID *ID                       `json:"failure_finalization_record_id,omitempty"`
	ResultOccurrenceID          *ID                       `json:"result_occurrence_id,omitempty"`
	WaveID                      *ID                       `json:"wave_id,omitempty"`
	WaveMemberOrdinal           *int                      `json:"wave_member_ordinal,omitempty"`
	ClaimFenceGeneration        *int64                    `json:"claim_fence_generation,omitempty"`
	FinalizationAttemptNumber   *int                      `json:"finalization_attempt_number,omitempty"`
	SafeMessage                 string                    `json:"safe_message"`
	Details                     json.RawMessage           `json:"details"`
}

func (a LargeResultAuditLinkage) Validate() error {
	if a.EventID == "" {
		return fmt.Errorf("large-result audit event requires a caller-preallocated ID")
	}
	if err := a.EventType.Validate(); err != nil {
		return err
	}
	if a.ResultOccurrenceID != nil && a.FailureFinalizationRecordID == nil {
		return fmt.Errorf("result occurrence audit linkage requires its failure finalization record")
	}
	if a.WaveMemberOrdinal != nil && (a.WaveID == nil || *a.WaveMemberOrdinal < 0) {
		return fmt.Errorf("wave member audit linkage requires its wave and non-negative ordinal")
	}
	if a.ClaimFenceGeneration != nil && *a.ClaimFenceGeneration < 1 {
		return fmt.Errorf("claim fence generation must be positive")
	}
	if a.FinalizationAttemptNumber != nil && (*a.FinalizationAttemptNumber < 1 || *a.FinalizationAttemptNumber > 2) {
		return fmt.Errorf("finalization attempt number must be 1 or 2")
	}
	if err := ValidateUTF8Bytes("audit safe message", a.SafeMessage, SafeMessageMaxBytes); err != nil {
		return err
	}
	return ValidateJSONObjectBytes("audit details", a.Details, DiagnosticMaxBytes)
}

func validateFinalizationSlots(r FailureFinalizationRecord) error {
	values := []ID{
		r.Charge1.ChargeID, r.Charge1.ChargeAuditID, r.Charge1.BeginEventID, r.Charge1.OutcomeEventID,
		r.Charge2.ChargeID, r.Charge2.ChargeAuditID, r.Charge2.BeginEventID, r.Charge2.OutcomeEventID,
		r.ResultCommitUnknownEventID, r.ResultCommitResolutionID, r.FinalizationFailedEventID,
	}
	seen := make(map[ID]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return fmt.Errorf("finalization slots require every fixed preallocated identity")
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("fixed finalization identities must be distinct")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateWaveLeaseClaim(claimed bool, claim WaveLeaseClaim) error {
	owned := claim.OwnerKind != nil && claim.OwnerInstanceID != nil && claim.Token != nil && claim.LeaseExpiresAt != nil
	if claimed {
		if !owned || claim.FenceGeneration < 1 || claim.LeaseDuration < StepAttemptLeaseMinimum || claim.LeaseDuration > StepAttemptLeaseMaximum {
			return fmt.Errorf("claimed state requires complete owner, positive fence, and bounded lease")
		}
		if err := claim.OwnerKind.Validate(); err != nil {
			return err
		}
	} else if owned || claim.OwnerKind != nil || claim.OwnerInstanceID != nil || claim.Token != nil || claim.LeaseExpiresAt != nil || claim.LeaseDuration != 0 {
		return fmt.Errorf("unclaimed state cannot carry current ownership")
	}
	if claim.FenceGeneration < 0 || claim.RenewalSequence < 0 {
		return fmt.Errorf("wave claim generation and renewal sequence cannot be negative")
	}
	if (claim.RenewalSequence == 0 && claim.LastRenewalID != nil) || (claim.RenewalSequence > 0 && claim.LastRenewalID == nil) {
		return fmt.Errorf("wave claim renewal sequence and last renewal ID must be paired")
	}
	return nil
}

func validatePublicationTimestampShape(p ArtifactPublication) error {
	if p.ReservedAt.IsZero() {
		return fmt.Errorf("artifact publication requires its reserved timestamp")
	}
	switch p.State {
	case PublicationReserved:
		if p.PublishingAt != nil || p.SealedAt != nil || p.AdoptedAt != nil || p.AbandonedAt != nil || p.QuarantinedAt != nil {
			return fmt.Errorf("reserved publication has contradictory lifecycle timestamps")
		}
	case PublicationPublishing:
		if p.PublishingAt == nil || p.SealedAt != nil || p.AdoptedAt != nil || p.AbandonedAt != nil || p.QuarantinedAt != nil {
			return fmt.Errorf("publishing publication has invalid lifecycle timestamps")
		}
	case PublicationSealed:
		if p.PublishingAt == nil || p.SealedAt == nil || p.AdoptedAt != nil || p.AbandonedAt != nil || p.QuarantinedAt != nil {
			return fmt.Errorf("sealed publication has invalid lifecycle timestamps")
		}
	case PublicationAdopted:
		if p.PublishingAt == nil || p.SealedAt == nil || p.AdoptedAt == nil || p.AbandonedAt != nil || p.QuarantinedAt != nil {
			return fmt.Errorf("adopted publication has invalid lifecycle timestamps")
		}
	case PublicationAbandoned:
		if p.AdoptedAt != nil || p.AbandonedAt == nil || p.QuarantinedAt != nil {
			return fmt.Errorf("abandoned publication has invalid lifecycle timestamps")
		}
	case PublicationQuarantined:
		if p.AdoptedAt != nil || p.AbandonedAt != nil || p.QuarantinedAt == nil {
			return fmt.Errorf("quarantined publication has invalid lifecycle timestamps")
		}
	}
	if p.PublishingAt != nil && p.PublishingAt.Before(p.ReservedAt) {
		return fmt.Errorf("publication publishing timestamp precedes reservation")
	}
	if p.SealedAt != nil && (p.PublishingAt == nil || p.SealedAt.Before(*p.PublishingAt)) {
		return fmt.Errorf("publication sealed timestamp precedes publishing")
	}
	if p.AdoptedAt != nil && (p.SealedAt == nil || p.AdoptedAt.Before(*p.SealedAt)) {
		return fmt.Errorf("publication adopted timestamp precedes sealing")
	}
	if p.AbandonedAt != nil && p.AbandonedAt.Before(p.ReservedAt) {
		return fmt.Errorf("publication abandoned timestamp precedes reservation")
	}
	if p.QuarantinedAt != nil && p.QuarantinedAt.Before(p.ReservedAt) {
		return fmt.Errorf("publication quarantined timestamp precedes reservation")
	}
	return nil
}

func validateRequiredCanonicalID(field string, value ID) error {
	if _, err := ParseID(string(value)); err != nil {
		return fmt.Errorf("%s must be a canonical lowercase UUID: %w", field, err)
	}
	return nil
}

func validatePublicationCleanupShape(p ArtifactPublication) error {
	cleanupTouched := p.ContentDeletedAt != nil || p.CleanupClaimToken != nil || p.CleanupClaimedAt != nil || p.CleanupRetryAfter != nil || p.CleanupLastErrorCode != "" || p.CleanupQuarantinedAt != nil
	if p.State != PublicationAbandoned {
		if cleanupTouched {
			return fmt.Errorf("only abandoned unadopted content can carry publication cleanup metadata")
		}
		return nil
	}
	if p.ContentDeletedAt != nil && p.AbandonedAt != nil && p.ContentDeletedAt.Before(*p.AbandonedAt) {
		return fmt.Errorf("publication content deletion timestamp precedes abandonment")
	}
	if (p.CleanupClaimToken == nil) != (p.CleanupClaimedAt == nil) {
		return fmt.Errorf("publication cleanup claim token and timestamp must be paired")
	}
	states := 0
	if !cleanupTouched {
		states++
	}
	if p.CleanupClaimToken != nil && p.CleanupRetryAfter == nil && p.ContentDeletedAt == nil && p.CleanupLastErrorCode == "" && p.CleanupQuarantinedAt == nil {
		states++
	}
	if p.CleanupRetryAfter != nil && p.CleanupClaimToken == nil && p.ContentDeletedAt == nil && (p.CleanupLastErrorCode == "filesystem_io" || p.CleanupLastErrorCode == "durability_sync") && p.CleanupQuarantinedAt == nil {
		states++
	}
	if p.ContentDeletedAt != nil && p.CleanupClaimToken == nil && p.CleanupRetryAfter == nil && p.CleanupLastErrorCode == "" && p.CleanupQuarantinedAt == nil {
		states++
	}
	if p.CleanupQuarantinedAt != nil && p.CleanupClaimToken == nil && p.CleanupRetryAfter == nil && p.ContentDeletedAt == nil && p.CleanupLastErrorCode == "unexpected_entry_type" {
		states++
	}
	if states != 1 {
		return fmt.Errorf("abandoned publication has invalid cleanup state shape")
	}
	return nil
}

func ValidateUTF8Bytes(field, value string, maximum int) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s must be valid UTF-8", field)
	}
	if len(value) > maximum {
		return fmt.Errorf("%s exceeds %d UTF-8 bytes", field, maximum)
	}
	return nil
}

func ValidateJSONObjectBytes(field string, value json.RawMessage, maximum int) error {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 {
		return fmt.Errorf("%s must be a JSON object", field)
	}
	if len(trimmed) > maximum {
		return fmt.Errorf("%s exceeds %d bytes", field, maximum)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil || object == nil {
		return fmt.Errorf("%s must be a JSON object", field)
	}
	return nil
}

func ValidateSerializedBytes(field string, value []byte, maximum int) error {
	if len(value) > maximum {
		return fmt.Errorf("%s exceeds %d bytes", field, maximum)
	}
	return nil
}

func validLowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, b := range []byte(value) {
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return false
		}
	}
	return true
}
