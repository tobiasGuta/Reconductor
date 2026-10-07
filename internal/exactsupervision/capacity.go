package exactsupervision

import "sync"

type CapacityState uint8

const (
	// Quarantined is also the zero/uninitialized capacity state.
	Quarantined CapacityState = iota
	Ready
	ExecutionActive
	CleanupPending
)

// Capacity copies share one locked state rather than forking serial ownership.
// A zero Capacity fails closed. There is no reset, recovery or retry operation.
type Capacity struct{ core *capacityCore }

type capacityCore struct {
	mu            sync.Mutex
	slot          SlotGeneration
	state         CapacityState
	used          map[InstanceID]struct{}
	current       ExecutionInvocation
	last          observationOrder
	stopPost      LifecycleSnapshot
	lastLifecycle LifecycleSnapshot
	final         FinalMilestone
	owner         *ownerGeneration
	issued        observationOrder
	initialized   bool
	lost          bool
	outcome       CleanupOutcome
}

// observerOwner is the package-private issuance boundary for the future backend.
// Copies share one core and sequence. No public constructor establishes host
// ownership; future same-package Linux code must verify deployment, exclusive
// ownership and pinned measurements before using these private methods.
type observerOwner struct{ core *capacityCore }

func newObserverOwner(slot SlotGeneration) (observerOwner, error) {
	if err := slot.validate(); err != nil {
		return observerOwner{}, err
	}
	return observerOwner{&capacityCore{
		slot: slot, owner: &ownerGeneration{established: true},
		state: Quarantined, outcome: CleanupOutcome{reason: ErrCapacityQuarantined},
	}}, nil
}

// newCapacity binds this owner once to its latest initial trusted empty read.
// It is not host-ownership acquisition or recovery of a quarantined generation.
func (o observerOwner) newCapacity(idle PopulationObservation) (Capacity, error) {
	if o.core == nil {
		return Capacity{}, ErrCapacityQuarantined
	}
	s := o.core
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lost {
		return Capacity{}, ErrCapacityQuarantined
	}
	if s.initialized {
		return Capacity{}, ErrCapacityBusy
	}
	if err := idle.validate(); err != nil {
		return Capacity{}, s.quarantine(err)
	}
	if err := s.slot.match(idle.slot); err != nil {
		return Capacity{}, s.quarantine(err)
	}
	if idle.owner != s.owner {
		return Capacity{}, s.quarantine(ErrWrongOwner)
	}
	if idle.order != s.issued {
		return Capacity{}, s.quarantine(ErrObservationOutOfOrder)
	}
	if idle.populated {
		return Capacity{}, s.quarantine(ErrSlotStillPopulated)
	}
	s.initialized, s.state, s.last = true, Ready, idle.order
	s.used = make(map[InstanceID]struct{})
	s.outcome = CleanupOutcome{reason: ErrNotFinal}
	return Capacity{s}, nil
}

// nextOrder is called with the core lock at the actual observation boundary.
// Exhaustion permanently closes the owner, including before capacity binding.
func (s *capacityCore) nextOrder() (observationOrder, error) {
	if s.lost {
		return 0, ErrCapacityQuarantined
	}
	if s.issued == ^observationOrder(0) {
		return 0, s.quarantine(ErrObservationOrderExhausted)
	}
	s.issued++
	return s.issued, nil
}

func (o observerOwner) population(f PopulationFacts) (PopulationObservation, error) {
	if o.core == nil {
		return PopulationObservation{}, ErrCapacityQuarantined
	}
	s := o.core
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lost {
		return PopulationObservation{}, ErrCapacityQuarantined
	}
	if err := s.slot.match(f.Slot); err != nil {
		return PopulationObservation{}, s.quarantine(err)
	}
	order, err := s.nextOrder()
	if err != nil {
		return PopulationObservation{}, err
	}
	return PopulationObservation{slot: s.slot, owner: s.owner, order: order, populated: f.Populated}, nil
}

func (o observerOwner) lifecycle(inv ExecutionInvocation, f LifecycleFacts) (LifecycleSnapshot, error) {
	return o.issueLifecycle(inv, f, false)
}

// finalLifecycle is a private backend handoff only after verified policy,
// exclusive start ownership and original-invocation final command completion.
// Terminal raw facts alone never assert this predicate. This pure foundation
// does not implement or claim those host verifications.
func (o observerOwner) finalLifecycle(inv ExecutionInvocation, f LifecycleFacts) (LifecycleSnapshot, error) {
	return o.issueLifecycle(inv, f, true)
}

func (o observerOwner) issueLifecycle(inv ExecutionInvocation, f LifecycleFacts, noLaterCommands bool) (LifecycleSnapshot, error) {
	if o.core == nil {
		return LifecycleSnapshot{}, ErrCapacityQuarantined
	}
	s := o.core
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lost {
		return LifecycleSnapshot{}, ErrCapacityQuarantined
	}
	if !s.initialized {
		return LifecycleSnapshot{}, s.quarantine(ErrCapacityQuarantined)
	}
	if err := s.matchCurrent(inv); err != nil {
		return LifecycleSnapshot{}, err
	}
	if !f.valid() {
		return LifecycleSnapshot{}, s.quarantine(ErrInvalidLifecycle)
	}
	if noLaterCommands && (!f.terminal() || f.ControlPID != 0) {
		return LifecycleSnapshot{}, s.quarantine(ErrNotFinal)
	}
	order, err := s.nextOrder()
	if err != nil {
		return LifecycleSnapshot{}, err
	}
	return LifecycleSnapshot{invocation: inv, owner: s.owner, order: order, facts: f, noLaterCommands: noLaterCommands}, nil
}

func (c Capacity) State() CapacityState {
	if c.core == nil {
		return Quarantined
	}
	c.core.mu.Lock()
	defer c.core.mu.Unlock()
	return c.core.state
}

func (c Capacity) Outcome() CleanupOutcome {
	if c.core == nil {
		return CleanupOutcome{reason: ErrCapacityQuarantined}
	}
	c.core.mu.Lock()
	defer c.core.mu.Unlock()
	return c.core.outcome
}

func (c Capacity) Begin(inv ExecutionInvocation) error {
	if c.core == nil {
		return ErrCapacityQuarantined
	}
	s := c.core
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == Quarantined {
		return ErrCapacityQuarantined
	}
	if s.state != Ready {
		return ErrCapacityBusy
	}
	if err := s.slot.match(inv.slot); err != nil {
		return s.quarantine(err)
	}
	if err := inv.validate(); err != nil {
		return s.quarantine(err)
	}
	if _, ok := s.used[inv.instance]; ok {
		return ErrInstanceReuse
	}
	s.used[inv.instance] = struct{}{}
	s.current, s.state = inv, ExecutionActive
	s.stopPost, s.final = LifecycleSnapshot{}, FinalMilestone{}
	s.lastLifecycle = LifecycleSnapshot{}
	s.outcome = CleanupOutcome{reason: ErrNotFinal}
	return nil
}

// WorkTerminated withholds serial capacity until cleanup is confirmed. Stop
// lifecycle observations also transition active work to cleanup pending.
func (c Capacity) WorkTerminated(inv ExecutionInvocation) error {
	return c.withCurrent(inv, func(s *capacityCore) error {
		s.state = CleanupPending
		return nil
	})
}

func (c Capacity) withCurrent(inv ExecutionInvocation, f func(*capacityCore) error) error {
	if c.core == nil {
		return ErrCapacityQuarantined
	}
	s := c.core
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.matchCurrent(inv); err != nil {
		return err
	}
	return f(s)
}

func (c Capacity) ObserveLifecycle(o LifecycleSnapshot) error {
	return c.withCurrent(o.invocation, func(s *capacityCore) error {
		if err := o.validate(); err != nil {
			return s.quarantine(err)
		}
		if o.owner != s.owner {
			return s.quarantine(ErrWrongOwner)
		}
		if err := s.advance(o.order); err != nil {
			return err
		}
		f := o.facts
		// WorkTerminated is an application event: the unit may still be running
		// while its coordinator finishes. Reactivation requires observed unit
		// teardown, not merely the capacity owner's cleanup-pending state.
		stoppingSeen := s.lastLifecycle.order != 0 && s.lastLifecycle.facts.ActiveState == Deactivating
		if f.reactivating() || stoppingSeen && (f.ActiveState == Activating || f.ActiveState == Active) {
			return s.quarantine(ErrReactivation)
		}
		if s.final.valid() {
			if f != s.final.terminal.facts || !o.noLaterCommands {
				return s.quarantine(ErrReactivation)
			}
			return nil // A later matching terminal snapshot cannot rebind the milestone.
		}
		if s.lastLifecycle.order != 0 && f.SubState < s.lastLifecycle.facts.SubState {
			return s.quarantine(ErrObservationOutOfOrder)
		}
		s.lastLifecycle = o
		if f.ActiveState == Deactivating {
			s.state = CleanupPending
		}
		if f.SubState == StopPost {
			s.stopPost = o
		}
		if f.terminal() {
			m := FinalMilestone{s.stopPost, o}
			if !m.valid() {
				return s.quarantine(ErrNotFinal)
			}
			s.state, s.final = CleanupPending, m
			s.outcome = CleanupOutcome{reason: ErrMissingSlotObservation}
		}
		return nil
	})
}

// ObservePopulation records diagnostic ordering, never confirms cleanup. Early
// zero cannot later be recycled by ConfirmCleanup. Unowned population while
// READY means exclusivity has been lost and permanently quarantines capacity.
func (c Capacity) ObservePopulation(o PopulationObservation) error {
	if c.core == nil {
		return ErrCapacityQuarantined
	}
	s := c.core
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.population(o); err != nil {
		return err
	}
	if s.state == Ready && o.populated {
		return s.quarantine(ErrSlotStillPopulated)
	}
	return nil
}

// ConfirmCleanup is the only transition back to READY. Every unsuccessful
// decision quarantines capacity, rather than suggesting a retry or restoration.
func (c Capacity) ConfirmCleanup(o PopulationObservation) CleanupOutcome {
	if c.core == nil {
		return CleanupOutcome{reason: ErrCapacityQuarantined}
	}
	s := c.core
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == Quarantined {
		return s.outcome
	}
	if err := s.population(o); err != nil {
		return s.outcome
	}
	if s.state != CleanupPending || !s.final.valid() {
		s.quarantine(ErrNotFinal)
		return s.outcome
	}
	if o.populated {
		s.quarantine(ErrSlotStillPopulated)
		return s.outcome
	}
	a := CleanupAttestation{AttestationVersion, s.current, s.final, o}
	if a.Classification() != Confirmed {
		s.quarantine(ErrObservationOutOfOrder)
		return s.outcome
	}
	s.outcome = CleanupOutcome{attestation: a}
	s.state, s.current = Ready, ExecutionInvocation{}
	return s.outcome
}

func (c Capacity) ObserverLost() error {
	if c.core == nil {
		return ErrCapacityQuarantined
	}
	c.core.mu.Lock()
	defer c.core.mu.Unlock()
	return c.core.quarantine(ErrObserverLost)
}

// OwnershipLost reports loss of the designated owner independently of observer
// transport loss. It permanently closes both capacity and evidence issuance.
func (c Capacity) OwnershipLost() error {
	if c.core == nil {
		return ErrCapacityQuarantined
	}
	c.core.mu.Lock()
	defer c.core.mu.Unlock()
	return c.core.quarantine(ErrOwnershipLost)
}

type EvidenceLoss uint8

const (
	LifecycleEvidenceLost EvidenceLoss = iota + 1
	FinalSlotObservationLost
)

// EvidenceLost explicitly closes an attempt whose required evidence cannot be
// obtained. Merely waiting in CleanupPending does not imply loss or a deadline.
func (c Capacity) EvidenceLost(loss EvidenceLoss) error {
	if c.core == nil {
		return ErrCapacityQuarantined
	}
	c.core.mu.Lock()
	defer c.core.mu.Unlock()
	switch loss {
	case LifecycleEvidenceLost:
		return c.core.quarantine(ErrNotFinal)
	case FinalSlotObservationLost:
		return c.core.quarantine(ErrMissingSlotObservation)
	default:
		return c.core.quarantine(ErrObservationOutOfOrder)
	}
}

// ObserveSlot detects boot change or replacement even while capacity is idle.
func (c Capacity) ObserveSlot(slot SlotGeneration) error {
	if c.core == nil {
		return ErrCapacityQuarantined
	}
	c.core.mu.Lock()
	defer c.core.mu.Unlock()
	if c.core.state == Quarantined {
		return ErrCapacityQuarantined
	}
	if err := c.core.slot.match(slot); err != nil {
		return c.core.quarantine(err)
	}
	return nil
}

func (s *capacityCore) matchCurrent(inv ExecutionInvocation) error {
	if s.state == Quarantined {
		return ErrCapacityQuarantined
	}
	if err := s.slot.match(inv.slot); err != nil {
		return s.quarantine(err)
	}
	if s.state == Ready || inv != s.current {
		return s.quarantine(ErrWrongInvocation)
	}
	return nil
}

func (s *capacityCore) population(o PopulationObservation) error {
	if s.state == Quarantined {
		return ErrCapacityQuarantined
	}
	if err := o.validate(); err != nil {
		return s.quarantine(err)
	}
	if err := s.slot.match(o.slot); err != nil {
		return s.quarantine(err)
	}
	if o.owner != s.owner {
		return s.quarantine(ErrWrongOwner)
	}
	return s.advance(o.order)
}

func (s *capacityCore) advance(order observationOrder) error {
	if order == 0 || order <= s.last || order > s.issued {
		return s.quarantine(ErrObservationOutOfOrder)
	}
	s.last = order
	return nil
}

func (s *capacityCore) quarantine(reason error) error {
	if s.lost {
		return ErrCapacityQuarantined
	}
	s.state, s.lost = Quarantined, true
	s.outcome = CleanupOutcome{reason: reason}
	return reason
}
