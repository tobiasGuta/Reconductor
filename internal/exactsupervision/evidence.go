package exactsupervision

// observationOrder is issued only by the package-owned observer. Public Order
// accessors return descriptive numbers, never an evidence-construction token.
type observationOrder uint64

// ownerGeneration is an immutable, non-zero-sized in-process identity. Evidence
// keeps it alive, preventing identity reuse while that evidence exists.
type ownerGeneration struct{ established bool }

type ActiveState uint8

const (
	ActiveUnknown ActiveState = iota
	Activating
	Active
	Deactivating
	Inactive
	Failed
)

type SubState uint8

const (
	SubUnknown SubState = iota
	StartPre
	Start
	StartPost
	Running
	Stop
	StopSIGTERM
	StopSIGKILL
	StopPost
	FinalSIGTERM
	FinalSIGKILL
	Dead
	FailedState
	AutoRestart
	AutoRestartQueued
	DeadBeforeAutoRestart
	FailedBeforeAutoRestart
)

// LifecycleFacts are descriptive candidates, not trusted evidence. They cannot
// assert final command completion, observation order or observer ownership.
// Result, UnitRemoved and helper exit status are deliberately omitted.
type LifecycleFacts struct {
	ActiveState ActiveState
	SubState    SubState
	ControlPID  uint32
}

// LifecycleSnapshot is opaque package-issued evidence. Its zero is invalid.
type LifecycleSnapshot struct {
	invocation      ExecutionInvocation
	owner           *ownerGeneration
	order           observationOrder
	facts           LifecycleFacts
	noLaterCommands bool
}

func (s LifecycleSnapshot) Invocation() ExecutionInvocation { return s.invocation }
func (s LifecycleSnapshot) Order() uint64                   { return uint64(s.order) }
func (s LifecycleSnapshot) Facts() LifecycleFacts           { return s.facts }
func (s LifecycleSnapshot) validate() error {
	if s.owner == nil || !s.owner.established {
		return ErrUntrustedEvidence
	}
	if err := s.invocation.validate(); err != nil {
		return err
	}
	if s.order == 0 {
		return ErrObservationOutOfOrder
	}
	if !s.facts.valid() || s.noLaterCommands && !s.facts.terminal() {
		return ErrInvalidLifecycle
	}
	return nil
}

func (f LifecycleFacts) terminal() bool {
	return f.ActiveState == Inactive && f.SubState == Dead || f.ActiveState == Failed && f.SubState == FailedState
}

func (f LifecycleFacts) reactivating() bool {
	return f.SubState == AutoRestart || f.SubState == AutoRestartQueued || f.SubState == DeadBeforeAutoRestart || f.SubState == FailedBeforeAutoRestart
}

func (f LifecycleFacts) valid() bool {
	switch f.SubState {
	case StartPre, Start, StartPost, AutoRestart, AutoRestartQueued:
		return f.ActiveState == Activating
	case Running:
		return f.ActiveState == Active
	case Stop, StopSIGTERM, StopSIGKILL, StopPost, FinalSIGTERM, FinalSIGKILL:
		return f.ActiveState == Deactivating
	case Dead, DeadBeforeAutoRestart:
		return f.ActiveState == Inactive
	case FailedState, FailedBeforeAutoRestart:
		return f.ActiveState == Failed
	default:
		return false
	}
}

// PopulationFacts are descriptive candidates. Caller-selected emptiness cannot
// initialize capacity or confirm cleanup.
type PopulationFacts struct {
	Slot      SlotGeneration
	Populated bool
}

// PopulationObservation is opaque package-issued evidence. Its zero is invalid.
type PopulationObservation struct {
	slot      SlotGeneration
	owner     *ownerGeneration
	order     observationOrder
	populated bool
}

func (o PopulationObservation) Slot() SlotGeneration { return o.slot }
func (o PopulationObservation) Order() uint64        { return uint64(o.order) }
func (o PopulationObservation) Populated() bool      { return o.populated }
func (o PopulationObservation) validate() error {
	if o.owner == nil || !o.owner.established {
		return ErrUntrustedEvidence
	}
	if err := o.slot.validate(); err != nil {
		return err
	}
	if o.order == 0 {
		return ErrObservationOutOfOrder
	}
	return nil
}

// FinalMilestone can only be produced by this package from ordered evidence for
// one invocation and owner. A terminal snapshot alone cannot construct it.
type FinalMilestone struct {
	stopPost LifecycleSnapshot
	terminal LifecycleSnapshot
}

func (m FinalMilestone) StopPost() LifecycleSnapshot { return m.stopPost }
func (m FinalMilestone) Terminal() LifecycleSnapshot { return m.terminal }
func (m FinalMilestone) valid() bool {
	f := m.terminal.facts
	return m.stopPost.validate() == nil && m.terminal.validate() == nil &&
		m.stopPost.owner == m.terminal.owner &&
		m.stopPost.invocation == m.terminal.invocation &&
		m.stopPost.facts.SubState == StopPost && m.stopPost.order < m.terminal.order &&
		f.terminal() && f.ControlPID == 0 && m.terminal.noLaterCommands
}

type CleanupClassification uint8

const (
	Unconfirmed CleanupClassification = iota
	Confirmed
	AttestationVersion = "exact-supervision-cleanup/v1"
)

// CleanupAttestation has no public constructor and contains no action or result
// bytes. It certifies ordered cleanup evidence, never execution authority.
type CleanupAttestation struct {
	version    string
	invocation ExecutionInvocation
	final      FinalMilestone
	zero       PopulationObservation
}

func (a CleanupAttestation) Version() string                 { return a.version }
func (a CleanupAttestation) Invocation() ExecutionInvocation { return a.invocation }
func (a CleanupAttestation) Final() FinalMilestone           { return a.final }
func (a CleanupAttestation) Zero() PopulationObservation     { return a.zero }
func (a CleanupAttestation) Classification() CleanupClassification {
	if a.version == AttestationVersion && a.invocation.validate() == nil && a.final.valid() &&
		a.final.terminal.invocation == a.invocation && a.zero.validate() == nil &&
		a.zero.owner == a.final.terminal.owner &&
		a.zero.slot == a.invocation.slot && !a.zero.populated && a.zero.order > a.final.terminal.order {
		return Confirmed
	}
	return Unconfirmed
}

// CleanupOutcome reports cleanup only, not sandbox result validity or accepted
// execution completion. Later integration must compose upstream result
// validation with cleanup confirmation. Waiting does not release capacity;
// an unsuccessful ConfirmCleanup decision or lost evidence quarantines it.
type CleanupOutcome struct {
	attestation CleanupAttestation
	reason      error
}

func (o CleanupOutcome) Classification() CleanupClassification { return o.attestation.Classification() }
func (o CleanupOutcome) Reason() error                         { return o.reason }
func (o CleanupOutcome) Attestation() (CleanupAttestation, bool) {
	return o.attestation, o.Classification() == Confirmed
}
