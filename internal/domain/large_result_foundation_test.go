package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLargeResultClosedStates(t *testing.T) {
	tests := []struct {
		name    string
		valid   func() error
		invalid func() error
	}{
		{"publication", PublicationReserved.Validate, func() error { return PublicationState("other").Validate() }},
		{"record", FailureRecordResolvedRetryable.Validate, func() error { return FailureFinalizationRecordState("other").Validate() }},
		{"provider", ProviderOutcomeTimeout.Validate, func() error { return ProviderOutcome("other").Validate() }},
		{"result persistence", ResultPersistenceCommitUnknown.Validate, func() error { return ResultPersistenceOutcome("other").Validate() }},
		{"adoption", AdoptionNonadoptionQuarantined.Validate, func() error { return AdoptionResolution("other").Validate() }},
		{"record propagation", FailurePropagationPending.Validate, func() error { return FailurePropagationState("other").Validate() }},
		{"finalization", FinalizationExecuting.Validate, func() error { return FinalizationAttemptState("other").Validate() }},
		{"claim", StepAttemptClaimReleased.Validate, func() error { return StepAttemptClaimState("other").Validate() }},
		{"owner", ClaimOwnerRecovery.Validate, func() error { return ClaimOwnerKind("other").Validate() }},
		{"dispatch", WaveDispatchClaimed.Validate, func() error { return WaveDispatchState("other").Validate() }},
		{"wave propagation", WavePropagationClaimed.Validate, func() error { return WavePropagationState("other").Validate() }},
		{"member", WaveMemberRetryPending.Validate, func() error { return WaveMemberState("other").Validate() }},
		{"audit", AuditWavePropagationReleased.Validate, func() error { return LargeResultAuditEventType("other").Validate() }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.valid(); err != nil {
				t.Fatalf("valid value rejected: %v", err)
			}
			if err := test.invalid(); err == nil {
				t.Fatal("unknown value accepted")
			}
		})
	}
	if !WaveMemberPlanned.IsValidNonterminal() || !WaveMemberRetryPending.IsValidNonterminal() || WaveMemberRetryPending.IsTerminal() {
		t.Fatal("planned/retry_pending closure semantics are not preserved")
	}
	if _, exists := publicationStates[PublicationState("cleanup_quarantined")]; exists {
		t.Fatal("cleanup quarantine entered the publication state registry")
	}
}

func TestFinalizationAttemptCountIsBoundedAtTwo(t *testing.T) {
	for _, test := range []struct {
		count int
		state FinalizationAttemptState
		valid bool
	}{
		{0, FinalizationNotCharged, true},
		{1, FinalizationCharged, true},
		{1, FinalizationConfirmedRolledBack, true},
		{2, FinalizationExecuting, true},
		{2, FinalizationExhausted, true},
		{2, FinalizationConfirmedRolledBack, false},
		{3, FinalizationCharged, false},
	} {
		err := ValidateFinalizationAttemptShape(test.count, test.state)
		if test.valid && err != nil {
			t.Fatalf("(%d,%s) rejected: %v", test.count, test.state, err)
		}
		if !test.valid && err == nil {
			t.Fatalf("(%d,%s) accepted", test.count, test.state)
		}
	}
}

func TestStepAttemptClaimStateShapes(t *testing.T) {
	now := time.Now().UTC()
	ownerKind := ClaimOwnerRecovery
	ownerID, token, releaseID := NewID(), NewID(), NewID()
	base := StepAttemptClaim{
		StepRunID: NewID(), StepAttempt: 1, ActionRequestID: NewID(), RecordID: NewID(),
		WaveID: NewID(), WaveMemberOrdinal: 0, OriginOwnerInstanceID: NewID(),
		FenceGeneration: 1, LeaseDuration: StepAttemptLeaseDefault, RowVersion: 1,
	}
	active := base
	active.State, active.OwnerKind, active.OwnerInstanceID, active.ClaimToken, active.LeaseExpiresAt = StepAttemptClaimActive, &ownerKind, &ownerID, &token, &now
	if err := active.Validate(); err != nil {
		t.Fatalf("active claim: %v", err)
	}
	released := base
	released.State, released.ClosedAt, released.CloseReason, released.LastReleaseID = StepAttemptClaimReleased, &now, "handoff", &releaseID
	if err := released.Validate(); err != nil {
		t.Fatalf("released claim: %v", err)
	}
	terminal := base
	terminal.State, terminal.ClosedAt, terminal.CloseReason = StepAttemptClaimTerminal, &now, "result_adopted"
	if err := terminal.Validate(); err != nil {
		t.Fatalf("terminal claim: %v", err)
	}
	broken := released
	broken.ClaimToken = &token
	if err := broken.Validate(); err == nil {
		t.Fatal("released claim with a current token was accepted")
	}
}

func TestStepAttemptClaimRequiresCanonicalDurableIdentity(t *testing.T) {
	now := time.Now().UTC()
	ownerKind := ClaimOwnerRecovery
	ownerID, token := NewID(), NewID()
	valid := StepAttemptClaim{
		StepRunID: NewID(), StepAttempt: 1, ActionRequestID: NewID(), RecordID: NewID(),
		WaveID: NewID(), WaveMemberOrdinal: 0, State: StepAttemptClaimActive,
		OwnerKind: &ownerKind, OwnerInstanceID: &ownerID, OriginOwnerInstanceID: NewID(), ClaimToken: &token,
		FenceGeneration: 1, LeaseDuration: StepAttemptLeaseDefault, LeaseExpiresAt: &now, RowVersion: 1,
	}
	for _, test := range []struct {
		name   string
		mutate func(*StepAttemptClaim)
	}{
		{"step run ID", func(claim *StepAttemptClaim) { claim.StepRunID = "" }},
		{"action request ID", func(claim *StepAttemptClaim) { claim.ActionRequestID = "" }},
		{"record ID", func(claim *StepAttemptClaim) { claim.RecordID = "" }},
		{"wave ID", func(claim *StepAttemptClaim) { claim.WaveID = "" }},
		{"origin owner instance ID", func(claim *StepAttemptClaim) { claim.OriginOwnerInstanceID = "" }},
		{"noncanonical identity", func(claim *StepAttemptClaim) { claim.StepRunID = "not-a-uuid" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim := valid
			test.mutate(&claim)
			if err := claim.Validate(); err == nil {
				t.Fatal("claim with invalid durable identity was accepted")
			}
		})
	}
}

func TestStepAttemptClaimRenewalPairing(t *testing.T) {
	now := time.Now().UTC()
	ownerKind := ClaimOwnerRecovery
	ownerID, token, renewalID := NewID(), NewID(), NewID()
	base := StepAttemptClaim{
		StepRunID: NewID(), StepAttempt: 1, ActionRequestID: NewID(), RecordID: NewID(),
		WaveID: NewID(), WaveMemberOrdinal: 0, State: StepAttemptClaimActive,
		OwnerKind: &ownerKind, OwnerInstanceID: &ownerID, OriginOwnerInstanceID: NewID(), ClaimToken: &token,
		FenceGeneration: 1, LeaseDuration: StepAttemptLeaseDefault, LeaseExpiresAt: &now, RowVersion: 1,
	}
	for _, test := range []struct {
		name      string
		sequence  int64
		withID    bool
		withTime  bool
		wantValid bool
	}{
		{"zero neither", 0, false, false, true},
		{"zero only ID", 0, true, false, false},
		{"zero only timestamp", 0, false, true, false},
		{"zero both", 0, true, true, false},
		{"positive both", 1, true, true, true},
		{"positive neither", 1, false, false, false},
		{"positive only ID", 1, true, false, false},
		{"positive only timestamp", 1, false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim := base
			claim.RenewalSequence = test.sequence
			if test.withID {
				claim.LastRenewalID = &renewalID
			}
			if test.withTime {
				claim.LastRenewedAt = &now
			}
			err := claim.Validate()
			if test.wantValid && err != nil {
				t.Fatalf("valid renewal shape rejected: %v", err)
			}
			if !test.wantValid && err == nil {
				t.Fatal("invalid renewal shape accepted")
			}
		})
	}
}

func TestFrozenUTF8ByteBounds(t *testing.T) {
	if err := ValidateUTF8Bytes("safe message", strings.Repeat("é", 250), SafeMessageMaxBytes); err != nil {
		t.Fatalf("exact 500-byte UTF-8 string rejected: %v", err)
	}
	if err := ValidateUTF8Bytes("safe message", strings.Repeat("é", 251), SafeMessageMaxBytes); err == nil {
		t.Fatal("502-byte UTF-8 string accepted")
	}
	if err := ValidateJSONObjectBytes("diagnostic", json.RawMessage(`{"ok":true}`), DiagnosticMaxBytes); err != nil {
		t.Fatal(err)
	}
	if err := ValidateJSONObjectBytes("diagnostic", json.RawMessage(`[]`), DiagnosticMaxBytes); err == nil {
		t.Fatal("non-object diagnostic accepted")
	}
	for name, bound := range map[string]int{
		"failure finalization record": FailureFinalizationRecordMaxBytes,
		"workflow summary":            WorkflowSummaryMaxBytes,
		"run status":                  RunStatusMaxBytes,
		"recovery checkpoint":         RecoveryCheckpointMaxBytes,
		"global checkpoint":           GlobalCheckpointMaxBytes,
		"pgx encoded message":         PGXEncodedMessageMaxBytes,
	} {
		if err := ValidateSerializedBytes(name, make([]byte, bound), bound); err != nil {
			t.Fatalf("%s exact bound rejected: %v", name, err)
		}
		if err := ValidateSerializedBytes(name, make([]byte, bound+1), bound); err == nil {
			t.Fatalf("%s over-bound value accepted", name)
		}
	}
}

func TestPrimaryLifecycleStatesRemainFrozen(t *testing.T) {
	if TaskStatus("paused_operator") == TaskPaused || RunStatus("paused_operator") == RunPaused || StepStatus("recovery_required") == StepRetryable {
		t.Fatal("large-result state leaked into a primary lifecycle status")
	}
	if len([]TaskStatus{TaskPending, TaskRunning, TaskPaused, TaskCompleted, TaskFailed, TaskCancelled}) != 6 ||
		len([]RunStatus{RunPending, RunRunning, RunPaused, RunCompleted, RunFailed, RunCancelled}) != 6 ||
		len([]StepStatus{StepPending, StepBlocked, StepAwaitingApproval, StepQueued, StepRunning, StepSucceeded, StepFailed, StepRetryable, StepSkipped, StepCancelled}) != 10 {
		t.Fatal("primary lifecycle registry changed")
	}
}

func TestLargeResultAuditLinkageRequiresPreallocatedBoundedIdentity(t *testing.T) {
	recordID, occurrenceID, waveID := NewID(), NewID(), NewID()
	ordinal, fence, attempt := 0, int64(1), 2
	linkage := LargeResultAuditLinkage{
		EventID:                     NewID(),
		EventType:                   AuditFailureFinalizationAttemptBegun,
		FailureFinalizationRecordID: &recordID,
		ResultOccurrenceID:          &occurrenceID,
		WaveID:                      &waveID,
		WaveMemberOrdinal:           &ordinal,
		ClaimFenceGeneration:        &fence,
		FinalizationAttemptNumber:   &attempt,
		SafeMessage:                 "finalization attempt begun",
		Details:                     json.RawMessage(`{"bounded":true}`),
	}
	if err := linkage.Validate(); err != nil {
		t.Fatal(err)
	}
	linkage.EventID = ""
	if err := linkage.Validate(); err == nil {
		t.Fatal("audit linkage without caller-preallocated ID was accepted")
	}
}

func TestArtifactPublicationUsesSeparateCleanupOnlyBeforeAdoption(t *testing.T) {
	publication := validArtifactPublication(PublicationAbandoned)
	if err := publication.Validate(); err != nil {
		t.Fatalf("unclaimed abandoned publication: %v", err)
	}
	retryAt := time.Now().UTC()
	publication.CleanupRetryAfter = &retryAt
	publication.CleanupLastErrorCode = "filesystem_io"
	if err := publication.Validate(); err != nil {
		t.Fatalf("retry-wait abandoned publication: %v", err)
	}
	adopted := validArtifactPublication(PublicationAdopted)
	adopted.CleanupRetryAfter = publication.CleanupRetryAfter
	adopted.CleanupLastErrorCode = publication.CleanupLastErrorCode
	if err := adopted.Validate(); err == nil {
		t.Fatal("adopted publication duplicated cleanup metadata owned by artifacts")
	}
}

func TestArtifactPublicationTimestampShapesMatchSQL(t *testing.T) {
	for _, state := range []PublicationState{
		PublicationReserved,
		PublicationPublishing,
		PublicationSealed,
		PublicationAdopted,
		PublicationAbandoned,
		PublicationQuarantined,
	} {
		t.Run(string(state), func(t *testing.T) {
			if err := validArtifactPublication(state).Validate(); err != nil {
				t.Fatalf("valid %s publication rejected: %v", state, err)
			}
		})
	}

	missing := validArtifactPublication(PublicationAdopted)
	missing.AdoptedAt = nil
	if err := missing.Validate(); err == nil {
		t.Fatal("adopted publication without adopted_at was accepted")
	}

	contradictory := validArtifactPublication(PublicationReserved)
	later := contradictory.ReservedAt.Add(time.Second)
	contradictory.PublishingAt = &later
	if err := contradictory.Validate(); err == nil {
		t.Fatal("reserved publication with publishing_at was accepted")
	}

	outOfOrder := validArtifactPublication(PublicationPublishing)
	earlier := outOfOrder.ReservedAt.Add(-time.Second)
	outOfOrder.PublishingAt = &earlier
	if err := outOfOrder.Validate(); err == nil {
		t.Fatal("publication with out-of-order timestamps was accepted")
	}

	terminalConflict := validArtifactPublication(PublicationAbandoned)
	terminalConflict.AdoptedAt = &later
	if err := terminalConflict.Validate(); err == nil {
		t.Fatal("abandoned publication with adopted_at was accepted")
	}
}

func TestWaveRenewalPairing(t *testing.T) {
	renewalID := NewID()
	base := WorkflowAttemptWave{
		WaveID: NewID(), WorkflowRunID: NewID(), WaveSequence: 1,
		MaterializationDigest: strings.Repeat("a", 64), MemberCount: 1,
		PropagationState: WavePropagationPending, DispatchState: WaveDispatchPending, RowVersion: 1,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("zero-sequence wave rejected: %v", err)
	}

	for _, test := range []struct {
		name      string
		configure func(*WorkflowAttemptWave)
		wantValid bool
	}{
		{"propagation positive paired", func(wave *WorkflowAttemptWave) {
			wave.PropagationClaim.RenewalSequence, wave.PropagationClaim.LastRenewalID = 1, &renewalID
		}, true},
		{"propagation positive missing ID", func(wave *WorkflowAttemptWave) { wave.PropagationClaim.RenewalSequence = 1 }, false},
		{"propagation zero with ID", func(wave *WorkflowAttemptWave) { wave.PropagationClaim.LastRenewalID = &renewalID }, false},
		{"dispatch positive paired", func(wave *WorkflowAttemptWave) {
			wave.DispatchClaim.RenewalSequence, wave.DispatchClaim.LastRenewalID = 1, &renewalID
		}, true},
		{"dispatch positive missing ID", func(wave *WorkflowAttemptWave) { wave.DispatchClaim.RenewalSequence = 1 }, false},
		{"dispatch zero with ID", func(wave *WorkflowAttemptWave) { wave.DispatchClaim.LastRenewalID = &renewalID }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			wave := base
			test.configure(&wave)
			err := wave.Validate()
			if test.wantValid && err != nil {
				t.Fatalf("valid wave renewal shape rejected: %v", err)
			}
			if !test.wantValid && err == nil {
				t.Fatal("invalid wave renewal shape accepted")
			}
		})
	}
}

func TestWorkflowWaveMemberDefinitionByteBound(t *testing.T) {
	base := WorkflowWaveMember{
		WaveID: NewID(), MemberOrdinal: 0, StepRunID: NewID(),
		CurrentStepAttempt: 0, State: WaveMemberPlanned,
	}
	for _, test := range []struct {
		name      string
		value     string
		wantValid bool
	}{
		{"empty", "", false},
		{"255 ASCII bytes", strings.Repeat("a", 255), true},
		{"256 ASCII bytes", strings.Repeat("a", 256), false},
		{"254 multibyte bytes", strings.Repeat("é", 127), true},
		{"256 multibyte bytes", strings.Repeat("é", 128), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			member := base
			member.StepDefinitionID = test.value
			err := member.Validate()
			if test.wantValid && err != nil {
				t.Fatalf("valid step definition rejected: %v", err)
			}
			if !test.wantValid && err == nil {
				t.Fatal("invalid step definition accepted")
			}
		})
	}
}

func validArtifactPublication(state PublicationState) ArtifactPublication {
	reservedAt := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	publishingAt := reservedAt.Add(time.Second)
	sealedAt := publishingAt.Add(time.Second)
	terminalAt := sealedAt.Add(time.Second)
	leaseExpiresAt := reservedAt.Add(StepAttemptLeaseDefault)
	ownerKind := ClaimOwnerRecovery
	ownerID, token := NewID(), NewID()
	artifactID := NewID()
	publication := ArtifactPublication{
		ID: NewID(), ProviderAttemptID: NewID(), ResultOccurrenceID: NewID(), ArtifactID: artifactID,
		ArtifactStoreID: NewID(), StorageKey: "v1/" + strings.ReplaceAll(string(artifactID), "-", "")[:2] + "/" + string(artifactID),
		ContentType: "text/plain", ContentSizeBytes: 1, ContentSHA256: strings.Repeat("a", 64),
		State: state, OriginOwnerInstanceID: NewID(), OwnerKind: &ownerKind, OwnerInstanceID: &ownerID,
		PublicationToken: &token, FenceGeneration: 1, LeaseDuration: StepAttemptLeaseDefault,
		LeaseExpiresAt: &leaseExpiresAt, ReservedAt: reservedAt, RowVersion: 1,
	}
	switch state {
	case PublicationPublishing:
		publication.PublishingAt = &publishingAt
	case PublicationSealed:
		publication.PublishingAt, publication.SealedAt = &publishingAt, &sealedAt
	case PublicationAdopted:
		publication.PublishingAt, publication.SealedAt, publication.AdoptedAt = &publishingAt, &sealedAt, &terminalAt
	case PublicationAbandoned:
		publication.AbandonedAt = &terminalAt
	case PublicationQuarantined:
		publication.QuarantinedAt = &terminalAt
		publication.QuarantineReasonCode = "unsafe_physical_identity"
	}
	if state == PublicationAdopted || state == PublicationAbandoned || state == PublicationQuarantined {
		publication.OwnerKind = nil
		publication.OwnerInstanceID = nil
		publication.PublicationToken = nil
		publication.LeaseExpiresAt = nil
	}
	return publication
}
