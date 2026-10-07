package exactsupervision

import (
	"errors"
	"sync"
	"testing"
)

func cgroupFacts() CgroupFacts {
	return CgroupFacts{ControlGroup: SlotControlGroup, Device: DeviceID{Minor: 28}, Inode: 123, MountID: 41, KernelCgroupID: 123}
}
func bootID(t *testing.T, other bool) BootID {
	t.Helper()
	raw := "12345678-9abc-def0-1234-56789abcdef0"
	if other {
		raw = "22345678-9abc-def0-1234-56789abcdef0"
	}
	id, err := ParseBootID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func instanceID(t *testing.T, other bool) InstanceID {
	t.Helper()
	raw := "123456789abcdef0123456789abcdef0"
	if other {
		raw = "223456789abcdef0123456789abcdef0"
	}
	id, err := ParseInstanceID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func invocationID(t *testing.T, other bool) InvocationID {
	t.Helper()
	raw := "abcdef0123456789abcdef0123456789"
	if other {
		raw = "bbcdef0123456789abcdef0123456789"
	}
	id, err := ParseInvocationID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func makeSlot(t *testing.T, boot BootID, facts CgroupFacts) SlotGeneration {
	t.Helper()
	cg, err := NewCgroupIdentity(facts)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := NewSlotGeneration(boot, cg)
	if err != nil {
		t.Fatal(err)
	}
	return slot
}
func slot(t *testing.T) SlotGeneration { return makeSlot(t, bootID(t, false), cgroupFacts()) }
func makeInvocation(t *testing.T, instance InstanceID, id InvocationID, slot SlotGeneration) ExecutionInvocation {
	t.Helper()
	inv, err := NewExecutionInvocation(instance, id, slot)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}
func invocation(t *testing.T, other bool) ExecutionInvocation {
	return makeInvocation(t, instanceID(t, other), invocationID(t, other), slot(t))
}

func owner(t *testing.T, slot SlotGeneration) observerOwner {
	t.Helper()
	o, err := newObserverOwner(slot)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func capacityForSlot(t *testing.T, slot SlotGeneration) Capacity {
	t.Helper()
	o := owner(t, slot)
	idle, err := o.population(PopulationFacts{Slot: slot})
	if err != nil {
		t.Fatal(err)
	}
	c, err := o.newCapacity(idle)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func capacity(t *testing.T) Capacity { return capacityForSlot(t, slot(t)) }
func active(t *testing.T) (Capacity, ExecutionInvocation) {
	t.Helper()
	c, inv := capacity(t), invocation(t, false)
	if err := c.Begin(inv); err != nil {
		t.Fatal(err)
	}
	return c, inv
}

// Synthetic promotion is confined to these same-package _test.go helpers.
func population(t *testing.T, c Capacity, pop bool) PopulationObservation {
	t.Helper()
	o, err := (observerOwner(c)).population(PopulationFacts{Slot: c.core.slot, Populated: pop})
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func snapshot(t *testing.T, c Capacity, inv ExecutionInvocation, f LifecycleFacts) LifecycleSnapshot {
	t.Helper()
	o, err := (observerOwner(c)).lifecycle(inv, f)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func stopPost(t *testing.T, c Capacity, inv ExecutionInvocation) LifecycleSnapshot {
	return snapshot(t, c, inv, LifecycleFacts{ActiveState: Deactivating, SubState: StopPost, ControlPID: 42})
}
func final(t *testing.T, c Capacity, inv ExecutionInvocation) LifecycleSnapshot {
	t.Helper()
	o, err := (observerOwner(c)).finalLifecycle(inv, LifecycleFacts{ActiveState: Inactive, SubState: Dead})
	if err != nil {
		t.Fatal(err)
	}
	return o
}
func lifecycleFinal(t *testing.T, c Capacity, inv ExecutionInvocation) {
	t.Helper()
	if err := c.WorkTerminated(inv); err != nil {
		t.Fatal(err)
	}
	if err := c.ObserveLifecycle(stopPost(t, c, inv)); err != nil {
		t.Fatal(err)
	}
	if err := c.ObserveLifecycle(final(t, c, inv)); err != nil {
		t.Fatal(err)
	}
}
func assertQuarantined(t *testing.T, c Capacity, reason error) {
	t.Helper()
	out := c.Outcome()
	if c.State() != Quarantined || out.Classification() != Unconfirmed || !errors.Is(out.Reason(), reason) {
		t.Fatalf("not quarantined: state=%v classification=%v reason=%v, want %v", c.State(), out.Classification(), out.Reason(), reason)
	}
	if _, ok := out.Attestation(); ok {
		t.Fatal("unconfirmed outcome exposed attestation")
	}
	if err := c.Begin(invocation(t, true)); !errors.Is(err, ErrCapacityQuarantined) {
		t.Fatal("quarantine allowed start", err)
	}
	if err := c.ObserveSlot(slot(t)); !errors.Is(err, ErrCapacityQuarantined) {
		t.Fatal("matching slot revived capacity", err)
	}
	if later := c.ConfirmCleanup(PopulationObservation{}); later.Classification() != Unconfirmed || !errors.Is(later.Reason(), reason) {
		t.Fatal("later cleanup decision recovered quarantine", later)
	}
	if _, err := (observerOwner(c)).population(PopulationFacts{Slot: slot(t)}); !errors.Is(err, ErrCapacityQuarantined) {
		t.Fatal("quarantine allowed new issuance", err)
	}
}

func TestConfirmedCleanupAndSharedCapacity(t *testing.T) {
	c, inv := active(t)
	copy := c
	if err := copy.ObservePopulation(population(t, c, true)); err != nil {
		t.Fatal(err)
	}
	post := stopPost(t, c, inv)
	if err := c.ObserveLifecycle(post); err != nil {
		t.Fatal(err)
	}
	terminal := final(t, c, inv)
	if err := c.ObserveLifecycle(terminal); err != nil {
		t.Fatal(err)
	}
	if c.State() != CleanupPending || c.Outcome().Classification() != Unconfirmed || !errors.Is(c.Outcome().Reason(), ErrMissingSlotObservation) {
		t.Fatal("final lifecycle alone released capacity")
	}
	zero := population(t, c, false)
	out := copy.ConfirmCleanup(zero)
	if out.Classification() != Confirmed || out.Reason() != nil || c.State() != Ready {
		t.Fatal("confirmed cleanup rejected", out, c.State())
	}
	a, ok := out.Attestation()
	if !ok || a.Version() != AttestationVersion || a.Invocation() != inv || a.Zero() != zero || a.Final().Terminal() != terminal || a.Final().StopPost() != post {
		t.Fatal("attestation lost bindings", a)
	}
	facts := a.Final().Terminal().Facts()
	facts.ControlPID = 99
	if a.Classification() != Confirmed || a.Final().Terminal().Facts().ControlPID != 0 {
		t.Fatal("accessor mutated attestation")
	}
	if err := c.Begin(makeInvocation(t, inv.InstanceID(), invocationID(t, true), inv.Slot())); !errors.Is(err, ErrInstanceReuse) {
		t.Fatal("same instance accepted", err)
	}
	if err := copy.Begin(invocation(t, true)); err != nil || c.State() != ExecutionActive || c.Outcome().Classification() != Unconfirmed {
		t.Fatal("next instance or copy violated", err)
	}
}

func TestEarlyZeroCannotBeRecycled(t *testing.T) {
	c, inv := active(t)
	early := population(t, c, false)
	if err := c.ObservePopulation(early); err != nil {
		t.Fatal(err)
	}
	lifecycleFinal(t, c, inv)
	if c.State() != CleanupPending || c.Outcome().Classification() != Unconfirmed {
		t.Fatal("early zero confirmed")
	}
	if c.ConfirmCleanup(early).Classification() != Unconfirmed {
		t.Fatal("recycled zero confirmed")
	}
	assertQuarantined(t, c, ErrObservationOutOfOrder)

	c, inv = active(t)
	if err := c.ObservePopulation(population(t, c, false)); err != nil {
		t.Fatal(err)
	}
	if err := c.ObservePopulation(population(t, c, true)); err != nil {
		t.Fatal(err)
	}
	lifecycleFinal(t, c, inv)
	if c.ConfirmCleanup(population(t, c, false)).Classification() != Confirmed {
		t.Fatal("later separately issued zero rejected")
	}
}

func TestWorkTerminationDoesNotPretendUnitIsTerminal(t *testing.T) {
	c, inv := active(t)
	if err := c.WorkTerminated(inv); err != nil {
		t.Fatal(err)
	}
	if err := c.ObserveLifecycle(snapshot(t, c, inv, LifecycleFacts{ActiveState: Active, SubState: Running})); err != nil {
		t.Fatal(err)
	}
	if c.State() != CleanupPending || c.Outcome().Classification() != Unconfirmed {
		t.Fatal("running coordinator released capacity")
	}
	lifecycleFinal(t, c, inv)
	if c.ConfirmCleanup(population(t, c, false)).Classification() != Confirmed {
		t.Fatal("genuine teardown rejected")
	}
}

func TestTerminalMilestoneRequirements(t *testing.T) {
	for _, pair := range []LifecycleFacts{{ActiveState: Inactive, SubState: Dead}, {ActiveState: Failed, SubState: FailedState}} {
		c, inv := active(t)
		if err := c.ObserveLifecycle(stopPost(t, c, inv)); err != nil {
			t.Fatal(err)
		}
		terminal, err := (observerOwner(c)).finalLifecycle(inv, pair)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.ObserveLifecycle(terminal); err != nil {
			t.Fatal(err)
		}
		if c.ConfirmCleanup(population(t, c, false)).Classification() != Confirmed {
			t.Fatal("valid terminal rejected")
		}
	}
	for _, mode := range []string{"control-PID-live", "commands-unproven", "missing-stop-post", "inactive-autorestart", "failed-autorestart", "activating-autorestart", "queued-autorestart"} {
		t.Run(mode, func(t *testing.T) {
			c, inv := active(t)
			if mode != "missing-stop-post" {
				if err := c.ObserveLifecycle(stopPost(t, c, inv)); err != nil {
					t.Fatal(err)
				}
			}
			f := LifecycleFacts{ActiveState: Inactive, SubState: Dead}
			want := ErrNotFinal
			switch mode {
			case "control-PID-live":
				f.ControlPID = 7
			case "inactive-autorestart":
				f.SubState = DeadBeforeAutoRestart
				want = ErrReactivation
			case "failed-autorestart":
				f.ActiveState, f.SubState = Failed, FailedBeforeAutoRestart
				want = ErrReactivation
			case "activating-autorestart":
				f.ActiveState, f.SubState = Activating, AutoRestart
				want = ErrReactivation
			case "queued-autorestart":
				f.ActiveState, f.SubState = Activating, AutoRestartQueued
				want = ErrReactivation
			}
			var observed LifecycleSnapshot
			if mode == "missing-stop-post" {
				observed = final(t, c, inv)
			} else {
				observed = snapshot(t, c, inv, f)
			}
			if err := c.ObserveLifecycle(observed); !errors.Is(err, want) {
				t.Fatal("milestone mismatch", err, want)
			}
			assertQuarantined(t, c, want)
		})
	}
	for _, f := range []LifecycleFacts{{}, {ActiveState: Active, SubState: Dead}, {ActiveState: Inactive, SubState: FailedState}, {ActiveState: 255, SubState: Start}, {ActiveState: Active, SubState: 255}} {
		c, inv := active(t)
		if _, err := (observerOwner(c)).lifecycle(inv, f); !errors.Is(err, ErrInvalidLifecycle) {
			t.Error("invalid lifecycle issued", f, err)
		}
		assertQuarantined(t, c, ErrInvalidLifecycle)
	}
	c, inv := active(t)
	if _, err := (observerOwner(c)).finalLifecycle(inv, LifecycleFacts{ActiveState: Inactive, SubState: Dead, ControlPID: 7}); !errors.Is(err, ErrNotFinal) {
		t.Fatal("private final promotion accepted nonzero PID", err)
	}
	assertQuarantined(t, c, ErrNotFinal)
}

func TestCleanupFailureNeverReleasesCapacity(t *testing.T) {
	for _, mode := range []string{"not-final", "populated", "duplicate", "missing-read", "lost-lifecycle", "observer", "owner"} {
		t.Run(mode, func(t *testing.T) {
			c, inv := active(t)
			want := ErrNotFinal
			if mode != "not-final" && mode != "lost-lifecycle" {
				lifecycleFinal(t, c, inv)
			}
			switch mode {
			case "not-final":
				c.ConfirmCleanup(population(t, c, false))
			case "populated":
				want = ErrSlotStillPopulated
				c.ConfirmCleanup(population(t, c, true))
			case "duplicate":
				want = ErrObservationOutOfOrder
				zero := population(t, c, false)
				if err := c.ObservePopulation(zero); err != nil {
					t.Fatal(err)
				}
				c.ConfirmCleanup(zero)
			case "missing-read":
				want = ErrMissingSlotObservation
				c.EvidenceLost(FinalSlotObservationLost)
			case "lost-lifecycle":
				c.EvidenceLost(LifecycleEvidenceLost)
			case "observer":
				want = ErrObserverLost
				c.ObserverLost()
			case "owner":
				want = ErrOwnershipLost
				c.OwnershipLost()
			}
			assertQuarantined(t, c, want)
		})
	}
}

func TestSerialStatesAndConcurrentStarts(t *testing.T) {
	c, inv := active(t)
	if err := c.Begin(invocation(t, true)); !errors.Is(err, ErrCapacityBusy) || c.State() != ExecutionActive {
		t.Fatal(err)
	}
	if err := c.WorkTerminated(inv); err != nil {
		t.Fatal(err)
	}
	if err := c.Begin(invocation(t, true)); !errors.Is(err, ErrCapacityBusy) || c.State() != CleanupPending {
		t.Fatal(err)
	}
	c.ObserverLost()
	assertQuarantined(t, c, ErrObserverLost)

	c = capacity(t)
	copy := c
	gate := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i, candidate := range []Capacity{c, copy} {
		inv := invocation(t, i == 1)
		wg.Add(1)
		go func(candidate Capacity, inv ExecutionInvocation) {
			defer wg.Done()
			<-gate
			results <- candidate.Begin(inv)
		}(candidate, inv)
	}
	close(gate)
	wg.Wait()
	close(results)
	success, busy := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrCapacityBusy) {
			busy++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || busy != 1 || copy.State() != ExecutionActive {
		t.Fatal("copy/concurrent admission forked", success, busy)
	}
}
