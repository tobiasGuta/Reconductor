package exactsupervision

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestSlotReplacementAcrossCapacityStates(t *testing.T) {
	changes := []struct {
		name   string
		mutate func(*CgroupFacts)
	}{
		{"device-major", func(f *CgroupFacts) { f.Device.Major++ }},
		{"device-minor", func(f *CgroupFacts) { f.Device.Minor++ }},
		{"inode", func(f *CgroupFacts) { f.Inode++ }},
		{"mount", func(f *CgroupFacts) { f.MountID++ }},
		{"kernel-ID", func(f *CgroupFacts) { f.KernelCgroupID++ }},
		{"kernel-ID-disappeared", func(f *CgroupFacts) { f.KernelCgroupID = 0 }},
	}
	for _, state := range []string{"ready", "active", "pending"} {
		for _, change := range changes {
			t.Run(state+"/"+change.name, func(t *testing.T) {
				c := capacity(t)
				if state != "ready" {
					inv := invocation(t, false)
					if err := c.Begin(inv); err != nil {
						t.Fatal(err)
					}
					if state == "pending" {
						lifecycleFinal(t, c, inv)
					}
				}
				facts := cgroupFacts()
				change.mutate(&facts)
				if err := c.ObserveSlot(makeSlot(t, bootID(t, false), facts)); !errors.Is(err, ErrWrongSlot) {
					t.Fatal(err)
				}
				assertQuarantined(t, c, ErrWrongSlot)
			})
		}
		t.Run(state+"/boot", func(t *testing.T) {
			c := capacity(t)
			if state != "ready" {
				inv := invocation(t, false)
				if err := c.Begin(inv); err != nil {
					t.Fatal(err)
				}
				if state == "pending" {
					lifecycleFinal(t, c, inv)
				}
			}
			if err := c.ObserveSlot(makeSlot(t, bootID(t, true), cgroupFacts())); !errors.Is(err, ErrWrongBoot) {
				t.Fatal(err)
			}
			assertQuarantined(t, c, ErrWrongBoot)
		})
	}
	f := cgroupFacts()
	f.KernelCgroupID = 0
	c := capacityForSlot(t, makeSlot(t, bootID(t, false), f))
	if err := c.ObserveSlot(slot(t)); !errors.Is(err, ErrWrongSlot) {
		t.Fatal("availability rebound slot", err)
	}
	assertQuarantined(t, c, ErrWrongSlot)
}

func TestInvocationMismatch(t *testing.T) {
	for _, mode := range []string{"same-unit-new-invocation", "other-unit-same-invocation", "other-boot", "other-slot"} {
		t.Run(mode, func(t *testing.T) {
			c, inv := active(t)
			other := inv
			want := ErrWrongInvocation
			switch mode {
			case "same-unit-new-invocation":
				other = makeInvocation(t, inv.InstanceID(), invocationID(t, true), inv.Slot())
			case "other-unit-same-invocation":
				other = makeInvocation(t, instanceID(t, true), inv.InvocationID(), inv.Slot())
			case "other-boot":
				other = makeInvocation(t, inv.InstanceID(), inv.InvocationID(), makeSlot(t, bootID(t, true), cgroupFacts()))
				want = ErrWrongBoot
			case "other-slot":
				f := cgroupFacts()
				f.Inode++
				other = makeInvocation(t, inv.InstanceID(), inv.InvocationID(), makeSlot(t, bootID(t, false), f))
				want = ErrWrongSlot
			}
			if other == inv {
				t.Fatal("substitution preserved equality")
			}
			otherCapacity := capacityForSlot(t, other.Slot())
			if err := otherCapacity.Begin(other); err != nil {
				t.Fatal(err)
			}
			if err := c.ObserveLifecycle(stopPost(t, otherCapacity, other)); !errors.Is(err, want) {
				t.Fatal("substitution accepted", err)
			}
			assertQuarantined(t, c, want)
		})
	}
}

func TestPopulationDecisionBindings(t *testing.T) {
	for _, mode := range []string{"wrong-boot", "wrong-slot", "populated", "old-order", "duplicate", "zero-value"} {
		t.Run(mode, func(t *testing.T) {
			c, inv := active(t)
			early := population(t, c, false)
			lifecycleFinal(t, c, inv)
			var zero PopulationObservation
			want := ErrObservationOutOfOrder
			switch mode {
			case "wrong-boot":
				other := capacityForSlot(t, makeSlot(t, bootID(t, true), cgroupFacts()))
				zero = population(t, other, false)
				want = ErrWrongBoot
			case "wrong-slot":
				f := cgroupFacts()
				f.MountID++
				other := capacityForSlot(t, makeSlot(t, bootID(t, false), f))
				zero = population(t, other, false)
				want = ErrWrongSlot
			case "populated":
				zero = population(t, c, true)
				want = ErrSlotStillPopulated
			case "old-order":
				zero = early
			case "duplicate":
				zero = population(t, c, false)
				if err := c.ObservePopulation(zero); err != nil {
					t.Fatal(err)
				}
			case "zero-value":
				want = ErrUntrustedEvidence
			}
			out := c.ConfirmCleanup(zero)
			if out.Classification() != Unconfirmed || !errors.Is(out.Reason(), want) {
				t.Fatal("bad zero confirmed", out.Reason())
			}
			assertQuarantined(t, c, want)
		})
	}
}

func TestRequiredEventPermutations(t *testing.T) {
	for a := 0; a < 3; a++ {
		for b := 0; b < 3; b++ {
			if a == b {
				continue
			}
			z := 3 - a - b
			t.Run(fmt.Sprintf("%d%d%d", a, b, z), func(t *testing.T) {
				c, inv := active(t)
				// Issuance follows observation chronology; delivery may be reordered.
				post, terminal := stopPost(t, c, inv), final(t, c, inv)
				zero := population(t, c, false)
				confirmed := false
				for _, event := range []int{a, b, z} {
					switch event {
					case 0:
						c.ObserveLifecycle(post)
					case 1:
						c.ObserveLifecycle(terminal)
					case 2:
						confirmed = c.ConfirmCleanup(zero).Classification() == Confirmed
					}
				}
				valid := a == 0 && b == 1 && z == 2
				if confirmed != valid || (c.State() == Ready) != valid {
					t.Fatal("invalid ordering confirmed", confirmed, c.State())
				}
			})
		}
	}
}

func TestOwnershipAndObserverLossAtEveryPosition(t *testing.T) {
	for _, loss := range []string{"observer", "owner"} {
		for position := 0; position <= 5; position++ {
			t.Run(fmt.Sprintf("%s/%d", loss, position), func(t *testing.T) {
				c, inv := capacity(t), invocation(t, false)
				if position >= 1 {
					if err := c.Begin(inv); err != nil {
						t.Fatal(err)
					}
				}
				if position >= 2 {
					if err := c.ObservePopulation(population(t, c, false)); err != nil {
						t.Fatal(err)
					}
				}
				if position >= 3 {
					if err := c.WorkTerminated(inv); err != nil {
						t.Fatal(err)
					}
				}
				if position >= 4 {
					if err := c.ObserveLifecycle(stopPost(t, c, inv)); err != nil {
						t.Fatal(err)
					}
				}
				if position >= 5 {
					if err := c.ObserveLifecycle(final(t, c, inv)); err != nil {
						t.Fatal(err)
					}
				}
				want := ErrObserverLost
				var err error
				if loss == "owner" {
					want = ErrOwnershipLost
					err = c.OwnershipLost()
				} else {
					err = c.ObserverLost()
				}
				if !errors.Is(err, want) {
					t.Fatal(err)
				}
				assertQuarantined(t, c, want)
			})
		}
	}
}

func TestLifecycleRegressionAndPostFinalMutation(t *testing.T) {
	for _, mode := range []string{"phase-regressed", "running-again", "control-PID-after-final", "terminal-changed", "commands-unproven-after-final", "same-terminal"} {
		t.Run(mode, func(t *testing.T) {
			c, inv := active(t)
			if err := c.ObserveLifecycle(stopPost(t, c, inv)); err != nil {
				t.Fatal(err)
			}
			if mode != "phase-regressed" && mode != "running-again" {
				if err := c.ObserveLifecycle(final(t, c, inv)); err != nil {
					t.Fatal(err)
				}
			}
			f := LifecycleFacts{ActiveState: Inactive, SubState: Dead}
			want := ErrReactivation
			trustedFinal := false
			switch mode {
			case "phase-regressed":
				f = LifecycleFacts{ActiveState: Deactivating, SubState: StopSIGTERM}
				want = ErrObservationOutOfOrder
			case "running-again":
				f = LifecycleFacts{ActiveState: Active, SubState: Running}
			case "control-PID-after-final":
				f.ControlPID = 77
			case "terminal-changed":
				f.ActiveState, f.SubState = Failed, FailedState
				trustedFinal = true
			case "same-terminal":
				want = nil
				trustedFinal = true
			}
			var observed LifecycleSnapshot
			if trustedFinal {
				var err error
				observed, err = (observerOwner(c)).finalLifecycle(inv, f)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				observed = snapshot(t, c, inv, f)
			}
			if err := c.ObserveLifecycle(observed); !errors.Is(err, want) {
				t.Fatal("bad lifecycle accepted", err, want)
			}
			if want != nil {
				assertQuarantined(t, c, want)
			} else if c.ConfirmCleanup(population(t, c, false)).Classification() != Confirmed {
				t.Fatal("matching terminal broke confirmation")
			}
		})
	}
}

func TestLifetimeHistoryAndCrossExecutionStaleZero(t *testing.T) {
	c := capacity(t)
	var firstZero PopulationObservation
	for _, inv := range []ExecutionInvocation{invocation(t, false), invocation(t, true)} {
		if err := c.Begin(inv); err != nil {
			t.Fatal(err)
		}
		lifecycleFinal(t, c, inv)
		zero := population(t, c, false)
		if firstZero.owner == nil {
			firstZero = zero
		}
		if c.ConfirmCleanup(zero).Classification() != Confirmed {
			t.Fatal("sequential cleanup failed")
		}
	}
	if err := c.Begin(invocation(t, false)); !errors.Is(err, ErrInstanceReuse) {
		t.Fatal("history lost", err)
	}
	if err := c.ObservePopulation(firstZero); !errors.Is(err, ErrObservationOutOfOrder) {
		t.Fatal("stale token accepted", err)
	}
	assertQuarantined(t, c, ErrObservationOutOfOrder)
}

func TestCrossOwnerEvidenceRejectsIdenticalVisibleIdentity(t *testing.T) {
	for _, mode := range []string{"lifecycle", "terminal", "population"} {
		t.Run(mode, func(t *testing.T) {
			a, inv := active(t)
			b, other := active(t)
			if inv != other || a.core.owner == b.core.owner {
				t.Fatal("test did not use equal visible identity and distinct owners")
			}
			if mode == "lifecycle" {
				evidence := stopPost(t, a, inv)
				if err := b.ObserveLifecycle(evidence); !errors.Is(err, ErrWrongOwner) {
					t.Fatal("cross-owner lifecycle accepted", err)
				}
			} else if mode == "terminal" {
				if err := a.ObserveLifecycle(stopPost(t, a, inv)); err != nil {
					t.Fatal(err)
				}
				if err := b.ObserveLifecycle(stopPost(t, b, other)); err != nil {
					t.Fatal(err)
				}
				if err := b.ObserveLifecycle(final(t, a, inv)); !errors.Is(err, ErrWrongOwner) {
					t.Fatal("cross-owner terminal accepted", err)
				}
			} else {
				lifecycleFinal(t, a, inv)
				lifecycleFinal(t, b, other)
				if out := b.ConfirmCleanup(population(t, a, false)); out.Classification() != Unconfirmed || !errors.Is(out.Reason(), ErrWrongOwner) {
					t.Fatal("cross-owner zero accepted", out)
				}
			}
			assertQuarantined(t, b, ErrWrongOwner)
			// Quarantining B cannot invalidate the independently owned A.
			if mode == "terminal" {
				if err := a.ObserveLifecycle(final(t, a, inv)); err != nil {
					t.Fatal(err)
				}
			} else if mode != "population" {
				lifecycleFinal(t, a, inv)
			}
			if a.ConfirmCleanup(population(t, a, false)).Classification() != Confirmed {
				t.Fatal("other owner damaged A")
			}
		})
	}
}

func TestPackageIssuedOrderAndOutOfOrderDelivery(t *testing.T) {
	c, inv := active(t)
	post := stopPost(t, c, inv)
	zero := population(t, c, false)
	terminal := final(t, c, inv)
	if post.Order() != 2 || zero.Order() != 3 || terminal.Order() != 4 {
		t.Fatal("order not strict/shared", post.Order(), zero.Order(), terminal.Order())
	}
	if err := c.ObserveLifecycle(post); err != nil {
		t.Fatal(err)
	}
	if err := c.ObserveLifecycle(terminal); err != nil {
		t.Fatal(err)
	}
	if c.ConfirmCleanup(zero).Classification() != Unconfirmed {
		t.Fatal("earlier issued zero confirmed")
	}
	assertQuarantined(t, c, ErrObservationOutOfOrder)

	c, inv = active(t)
	post = stopPost(t, c, inv)
	newer := population(t, c, true)
	if err := c.ObservePopulation(newer); err != nil {
		t.Fatal(err)
	}
	if err := c.ObserveLifecycle(post); !errors.Is(err, ErrObservationOutOfOrder) {
		t.Fatal("late older lifecycle accepted", err)
	}
	assertQuarantined(t, c, ErrObservationOutOfOrder)
}

func TestConcurrentIssuanceSharesOneSequence(t *testing.T) {
	c, _ := active(t)
	first, second := observerOwner(c), observerOwner(c)
	const count = 32
	orders := make(chan uint64, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for n := 0; n < count; n++ {
		o := first
		if n%2 == 1 {
			o = second
		}
		wg.Add(1)
		go func(o observerOwner) {
			defer wg.Done()
			p, err := o.population(PopulationFacts{Slot: c.core.slot, Populated: true})
			if err != nil {
				errs <- err
				return
			}
			orders <- p.Order()
		}(o)
	}
	wg.Wait()
	close(orders)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	seen := map[uint64]bool{}
	for order := range orders {
		if order == 0 || seen[order] {
			t.Fatal("zero/duplicate issued", order)
		}
		seen[order] = true
	}
	for order := uint64(2); order <= count+1; order++ {
		if !seen[order] {
			t.Fatal("sequence skipped", order)
		}
	}
}

func TestSequenceOverflowPermanentlyQuarantines(t *testing.T) {
	for _, kind := range []string{"population", "lifecycle"} {
		t.Run(kind, func(t *testing.T) {
			c, inv := active(t)
			c.core.mu.Lock()
			c.core.issued = ^observationOrder(0) - 1
			c.core.mu.Unlock()
			p := population(t, c, true)
			if p.Order() != ^uint64(0) {
				t.Fatal("last representable order wrong", p.Order())
			}
			if err := c.ObservePopulation(p); err != nil {
				t.Fatal(err)
			}
			o := observerOwner(c)
			var err error
			if kind == "population" {
				var next PopulationObservation
				next, err = o.population(PopulationFacts{Slot: inv.Slot()})
				if next.owner != nil || next.Order() != 0 {
					t.Fatal("overflow returned evidence")
				}
			} else {
				var next LifecycleSnapshot
				next, err = o.lifecycle(inv, LifecycleFacts{ActiveState: Active, SubState: Running})
				if next.owner != nil || next.Order() != 0 {
					t.Fatal("overflow returned evidence")
				}
			}
			if !errors.Is(err, ErrObservationOrderExhausted) {
				t.Fatal("overflow did not close", err)
			}
			assertQuarantined(t, c, ErrObservationOrderExhausted)
			if _, err := o.newCapacity(p); !errors.Is(err, ErrCapacityQuarantined) {
				t.Fatal("owner rebound after overflow", err)
			}
		})
	}
	o := owner(t, slot(t))
	o.core.issued = ^observationOrder(0)
	if _, err := o.population(PopulationFacts{Slot: slot(t)}); !errors.Is(err, ErrObservationOrderExhausted) {
		t.Fatal("unbound overflow allowed", err)
	}
	if _, err := o.newCapacity(PopulationObservation{}); !errors.Is(err, ErrCapacityQuarantined) {
		t.Fatal("unbound exhausted owner recovered", err)
	}
}

func TestOwnerBindsOnceAndRequiresLatestInitialRead(t *testing.T) {
	o := owner(t, slot(t))
	idle, err := o.population(PopulationFacts{Slot: slot(t)})
	if err != nil {
		t.Fatal(err)
	}
	c, err := o.newCapacity(idle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.newCapacity(idle); !errors.Is(err, ErrCapacityBusy) || c.State() != Ready {
		t.Fatal("owner cloned capacity", err)
	}
	c.OwnershipLost()
	if _, err := o.newCapacity(idle); !errors.Is(err, ErrCapacityQuarantined) {
		t.Fatal("owner recovered", err)
	}

	o = owner(t, slot(t))
	old, err := o.population(PopulationFacts{Slot: slot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.population(PopulationFacts{Slot: slot(t), Populated: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := o.newCapacity(old); !errors.Is(err, ErrObservationOutOfOrder) {
		t.Fatal("stale initial zero accepted", err)
	}

	o = owner(t, slot(t))
	foreign := population(t, capacity(t), false)
	if _, err := o.newCapacity(foreign); !errors.Is(err, ErrWrongOwner) {
		t.Fatal("foreign initial observation accepted", err)
	}
}

func TestAttestationOwnerAndVersionRevalidation(t *testing.T) {
	c, inv := active(t)
	lifecycleFinal(t, c, inv)
	a, ok := c.ConfirmCleanup(population(t, c, false)).Attestation()
	if !ok {
		t.Fatal("missing attestation")
	}
	other, otherInv := active(t)
	lifecycleFinal(t, other, otherInv)
	foreign := population(t, other, false)
	for _, mutate := range []func(*CleanupAttestation){
		func(x *CleanupAttestation) { x.zero = foreign },
		func(x *CleanupAttestation) { x.final.stopPost.owner = foreign.owner },
		func(x *CleanupAttestation) { x.version = "other" },
		func(x *CleanupAttestation) { x.zero.order = x.final.terminal.order },
		func(x *CleanupAttestation) { x.zero.order = 0 },
		func(x *CleanupAttestation) { x.zero.owner = nil },
	} {
		copy := a
		mutate(&copy)
		if copy.Classification() != Unconfirmed || a.Classification() != Confirmed {
			t.Fatal("attestation accepted mutation or shared mutable fields")
		}
	}
}

func TestFailClosedInitialAndZeroValues(t *testing.T) {
	var c Capacity
	if c.State() != Quarantined || c.Outcome().Classification() != Unconfirmed {
		t.Fatal("zero capacity usable")
	}
	for _, err := range []error{c.Begin(invocation(t, false)), c.WorkTerminated(invocation(t, false)), c.ObserveLifecycle(LifecycleSnapshot{}), c.ObservePopulation(PopulationObservation{}), c.ObserveSlot(slot(t)), c.ObserverLost(), c.OwnershipLost(), c.EvidenceLost(FinalSlotObservationLost)} {
		if !errors.Is(err, ErrCapacityQuarantined) {
			t.Fatal("zero operation allowed", err)
		}
	}
	if out := c.ConfirmCleanup(PopulationObservation{}); out.Classification() != Unconfirmed || !errors.Is(out.Reason(), ErrCapacityQuarantined) {
		t.Fatal("zero cleanup usable")
	}
	if (CleanupAttestation{}).Classification() != Unconfirmed || (FinalMilestone{}).valid() {
		t.Fatal("zero evidence usable")
	}
	if err := (LifecycleSnapshot{}).validate(); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatal("zero lifecycle valid", err)
	}
	if err := (PopulationObservation{}).validate(); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatal("zero population valid", err)
	}
	var o observerOwner
	if _, err := o.population(PopulationFacts{Slot: slot(t)}); !errors.Is(err, ErrCapacityQuarantined) {
		t.Fatal("zero owner issued", err)
	}
	if _, err := o.lifecycle(invocation(t, false), LifecycleFacts{ActiveState: Active, SubState: Running}); !errors.Is(err, ErrCapacityQuarantined) {
		t.Fatal("zero owner issued", err)
	}
	if _, err := o.newCapacity(PopulationObservation{}); !errors.Is(err, ErrCapacityQuarantined) {
		t.Fatal("zero owner bound", err)
	}
	if _, err := newObserverOwner(SlotGeneration{}); err == nil {
		t.Fatal("zero slot accepted")
	}
	o = owner(t, slot(t))
	nonempty, err := o.population(PopulationFacts{Slot: slot(t), Populated: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.newCapacity(nonempty); !errors.Is(err, ErrSlotStillPopulated) {
		t.Fatal("initial nonempty accepted", err)
	}
	o = owner(t, slot(t))
	if _, err := o.newCapacity(PopulationObservation{}); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatal("initial zero evidence accepted", err)
	}
	c = capacity(t)
	if err := c.ObservePopulation(population(t, c, true)); !errors.Is(err, ErrSlotStillPopulated) {
		t.Fatal("unowned population accepted", err)
	}
	assertQuarantined(t, c, ErrSlotStillPopulated)
}

func TestCandidateFactsWithoutIssuanceCannotConfirm(t *testing.T) {
	c, inv := active(t)
	// Same-package tests can populate private fields to test validation, but
	// importing packages can only create the descriptive facts below.
	rawFinal := LifecycleFacts{ActiveState: Inactive, SubState: Dead}
	unissued := LifecycleSnapshot{invocation: inv, order: 2, facts: rawFinal, noLaterCommands: true}
	if err := c.ObserveLifecycle(unissued); !errors.Is(err, ErrUntrustedEvidence) {
		t.Fatal("unissued final accepted", err)
	}
	assertQuarantined(t, c, ErrUntrustedEvidence)

	c, inv = active(t)
	lifecycleFinal(t, c, inv)
	rawZero := PopulationFacts{Slot: inv.Slot(), Populated: false}
	unissuedZero := PopulationObservation{slot: rawZero.Slot, populated: rawZero.Populated, order: ^observationOrder(0)}
	if out := c.ConfirmCleanup(unissuedZero); out.Classification() != Unconfirmed || !errors.Is(out.Reason(), ErrUntrustedEvidence) {
		t.Fatal("unissued large-order zero confirmed", out)
	}
	assertQuarantined(t, c, ErrUntrustedEvidence)
}

func TestPrivateIssuanceFailuresCloseOwner(t *testing.T) {
	o := owner(t, slot(t))
	if _, err := o.lifecycle(invocation(t, false), LifecycleFacts{ActiveState: Active, SubState: Running}); !errors.Is(err, ErrCapacityQuarantined) {
		t.Fatal("unbound lifecycle issued", err)
	}
	if _, err := o.population(PopulationFacts{Slot: slot(t)}); !errors.Is(err, ErrCapacityQuarantined) {
		t.Fatal("unbound failed owner recovered", err)
	}
	for _, mode := range []string{"boot", "slot", "invocation", "nonterminal-final"} {
		t.Run(mode, func(t *testing.T) {
			c, inv := active(t)
			o := observerOwner(c)
			want := ErrWrongBoot
			var err error
			switch mode {
			case "boot":
				_, err = o.population(PopulationFacts{Slot: makeSlot(t, bootID(t, true), cgroupFacts())})
			case "slot":
				f := cgroupFacts()
				f.Inode++
				want = ErrWrongSlot
				_, err = o.population(PopulationFacts{Slot: makeSlot(t, bootID(t, false), f)})
			case "invocation":
				want = ErrWrongInvocation
				_, err = o.lifecycle(makeInvocation(t, inv.InstanceID(), invocationID(t, true), inv.Slot()), LifecycleFacts{ActiveState: Active, SubState: Running})
			case "nonterminal-final":
				want = ErrNotFinal
				_, err = o.finalLifecycle(inv, LifecycleFacts{ActiveState: Active, SubState: Running})
			}
			if !errors.Is(err, want) {
				t.Fatal("issuance failed open", err, want)
			}
			assertQuarantined(t, c, want)
		})
	}
}

func TestInvalidOrderCannotUseOwnerIdentityAlone(t *testing.T) {
	for _, mode := range []string{"zero", "unissued-large"} {
		t.Run(mode, func(t *testing.T) {
			c, inv := active(t)
			lifecycleFinal(t, c, inv)
			zero := population(t, c, false)
			// Corrupt a copy in this private test; no public order setter exists.
			if mode == "zero" {
				zero.order = 0
			} else {
				zero.order++
			}
			if out := c.ConfirmCleanup(zero); out.Classification() != Unconfirmed || !errors.Is(out.Reason(), ErrObservationOutOfOrder) {
				t.Fatal("unissued order confirmed", out)
			}
			assertQuarantined(t, c, ErrObservationOutOfOrder)
		})
	}
}
