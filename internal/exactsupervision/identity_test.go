package exactsupervision_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	s "github.com/tobiasGuta/Reconductor/internal/exactsupervision"
)

func TestInstanceAndObservedUnitNames(t *testing.T) {
	for _, raw := range []string{strings.Repeat("0", 32), "0123456789abcdef0123456789abcdef"} {
		id, err := s.ParseInstanceID(raw)
		if err != nil || id.String() != raw || id.UnitName() != "reconductor-exact-run@"+raw+".service" {
			t.Fatalf("valid instance: %v %v", id, err)
		}
		again, err := s.ParseObservedUnitName(id.UnitName())
		if err != nil || again != id {
			t.Fatalf("unit round trip: %v %v", again, err)
		}
	}
	bad := []string{"", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("a", 31) + "/", strings.Repeat("a", 31) + "\\", "0123456789abcdef0123456789abcde\n", "0123456789abcdef0123456789abcdeé", "https://example.test/0123456789ab", strings.Repeat("a", 28) + "\\x2f"}
	for _, raw := range bad {
		if _, err := s.ParseInstanceID(raw); !errors.Is(err, s.ErrInvalidInstanceID) {
			t.Errorf("accepted instance %q: %v", raw, err)
		}
	}
	base := "reconductor-exact-run@0123456789abcdef0123456789abcdef.service"
	for _, raw := range []string{"", strings.Replace(base, "exact-run", "p5-run", 1), strings.Replace(base, ".service", ".slice", 1), base + ".service", base + "\n", "/" + base, strings.Replace(base, "@", "\\x40", 1), strings.ToUpper(base), "reconductor-exact-run@.service"} {
		if _, err := s.ParseObservedUnitName(raw); !errors.Is(err, s.ErrInvalidUnitName) {
			t.Errorf("accepted unit %q: %v", raw, err)
		}
	}
	if (s.InstanceID{}).UnitName() != "" {
		t.Fatal("zero instance derived a unit")
	}
}

func TestBootAndInvocationCanonicalForms(t *testing.T) {
	boot := "12345678-9abc-def0-1234-56789abcdef0"
	b, err := s.ParseBootID(boot)
	if err != nil || b.String() != boot {
		t.Fatal(b, err)
	}
	for _, raw := range []string{"", strings.ToUpper(boot), strings.ReplaceAll(boot, "-", ""), boot + "\n", "00000000-0000-0000-0000-000000000000", strings.Replace(boot, "-", "_", 1), "1234567g-9abc-def0-1234-56789abcdef0", "12345678--abc-def0-1234-56789abcdef0"} {
		if _, err := s.ParseBootID(raw); !errors.Is(err, s.ErrInvalidBootID) {
			t.Errorf("accepted boot %q: %v", raw, err)
		}
	}
	raw := "123456789abcdef0123456789abcdef0"
	id, err := s.ParseInvocationID(raw)
	if err != nil || id.String() != raw {
		t.Fatal(id, err)
	}
	for _, bad := range []string{"", strings.Repeat("0", 32), strings.ToUpper(raw), raw + "\n", boot, raw[:31], "g" + raw[1:]} {
		if _, err := s.ParseInvocationID(bad); !errors.Is(err, s.ErrInvalidInvocationID) {
			t.Errorf("accepted invocation %q: %v", bad, err)
		}
	}
}

func TestCgroupValidationAndValueImmutability(t *testing.T) {
	f := cgroupFacts()
	id, err := s.NewCgroupIdentity(f)
	if err != nil {
		t.Fatal(err)
	}
	f.Inode++
	copy := id.Facts()
	copy.MountID++
	if id.Facts() != cgroupFacts() {
		t.Fatal("caller mutation changed bound identity")
	}
	for _, mutate := range []func(*s.CgroupFacts){
		func(f *s.CgroupFacts) { f.ControlGroup = "/system.slice" },
		func(f *s.CgroupFacts) { f.ControlGroup += "/" },
		func(f *s.CgroupFacts) { f.ControlGroup += "/../reconductor-exact-slot.slice" },
		func(f *s.CgroupFacts) { f.ControlGroup = "/reconductor-exact-slot.slice" },
		func(f *s.CgroupFacts) { f.Device = s.DeviceID{} },
		func(f *s.CgroupFacts) { f.Inode = 0 },
		func(f *s.CgroupFacts) { f.MountID = 0 },
	} {
		bad := cgroupFacts()
		mutate(&bad)
		if _, err := s.NewCgroupIdentity(bad); !errors.Is(err, s.ErrWrongSlot) {
			t.Errorf("accepted malformed slot: %+v %v", bad, err)
		}
	}
	optional := cgroupFacts()
	optional.KernelCgroupID = 0
	if _, err := s.NewCgroupIdentity(optional); err != nil {
		t.Fatal("unavailable optional cgroup ID rejected:", err)
	}
	if _, err := s.NewSlotGeneration(s.BootID{}, id); !errors.Is(err, s.ErrInvalidBootID) {
		t.Fatal("zero boot accepted", err)
	}
	if _, err := s.NewSlotGeneration(bootID(t, false), s.CgroupIdentity{}); !errors.Is(err, s.ErrWrongSlot) {
		t.Fatal("zero cgroup accepted", err)
	}
	if _, err := s.NewExecutionInvocation(s.InstanceID{}, invocationID(t, false), slot(t)); !errors.Is(err, s.ErrInvalidInstanceID) {
		t.Fatal("zero instance accepted", err)
	}
	if _, err := s.NewExecutionInvocation(instanceID(t, false), s.InvocationID{}, slot(t)); !errors.Is(err, s.ErrInvalidInvocationID) {
		t.Fatal("zero invocation accepted", err)
	}
	inv := invocation(t, false)
	if inv.BootID() != inv.Slot().BootID() || inv.UnitName() != inv.InstanceID().UnitName() || inv.Slot().UnitName() != s.SlotUnitName {
		t.Fatal("identity derivation was not bound")
	}
}

func TestFrozenPolicyMetadata(t *testing.T) {
	p := s.FixedDeploymentPolicy()
	if p.Type() != "exec" || p.ExitType() != "main" || p.Restart() != "no" || p.RemainAfterExit() || p.Delegate() || p.NotifyAccess() != "none" || !p.RestartForceExitStatusMustBeEmpty() || !p.ReactivationMustBeExcluded() {
		t.Fatal("deployment lifecycle contract changed")
	}
	want := [8]s.ResourceMechanism{s.MemoryMax, s.MemorySwapMax, s.TasksMax, s.CPUQuota, s.RuntimeMaxSec, s.TimeoutStartSec, s.TimeoutStopSec, s.OOMPolicy}
	got := p.ResourceMechanisms()
	if got != want {
		t.Fatal("resource mechanisms changed", got)
	}
	got[0] = s.OOMPolicy
	if p.ResourceMechanisms() != want {
		t.Fatal("resource metadata mutated")
	}
}

func cgroupFacts() s.CgroupFacts {
	return s.CgroupFacts{ControlGroup: s.SlotControlGroup, Device: s.DeviceID{Minor: 28}, Inode: 123, MountID: 41, KernelCgroupID: 123}
}
func bootID(t *testing.T, other bool) s.BootID {
	t.Helper()
	raw := "12345678-9abc-def0-1234-56789abcdef0"
	if other {
		raw = "22345678-9abc-def0-1234-56789abcdef0"
	}
	id, err := s.ParseBootID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func instanceID(t *testing.T, other bool) s.InstanceID {
	t.Helper()
	raw := "123456789abcdef0123456789abcdef0"
	if other {
		raw = "223456789abcdef0123456789abcdef0"
	}
	id, err := s.ParseInstanceID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func invocationID(t *testing.T, other bool) s.InvocationID {
	t.Helper()
	raw := "abcdef0123456789abcdef0123456789"
	if other {
		raw = "bbcdef0123456789abcdef0123456789"
	}
	id, err := s.ParseInvocationID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func makeSlot(t *testing.T, boot s.BootID, facts s.CgroupFacts) s.SlotGeneration {
	t.Helper()
	cg, err := s.NewCgroupIdentity(facts)
	if err != nil {
		t.Fatal(err)
	}
	slot, err := s.NewSlotGeneration(boot, cg)
	if err != nil {
		t.Fatal(err)
	}
	return slot
}
func slot(t *testing.T) s.SlotGeneration { return makeSlot(t, bootID(t, false), cgroupFacts()) }
func makeInvocation(t *testing.T, instance s.InstanceID, id s.InvocationID, slot s.SlotGeneration) s.ExecutionInvocation {
	t.Helper()
	inv, err := s.NewExecutionInvocation(instance, id, slot)
	if err != nil {
		t.Fatal(err)
	}
	return inv
}
func invocation(t *testing.T, other bool) s.ExecutionInvocation {
	return makeInvocation(t, instanceID(t, other), invocationID(t, other), slot(t))
}

func TestPublicCandidatesCannotBecomeTrustedEvidence(t *testing.T) {
	lifecycle := s.LifecycleFacts{ActiveState: s.Inactive, SubState: s.Dead, ControlPID: 0}
	population := s.PopulationFacts{Slot: slot(t), Populated: false}
	if reflect.TypeOf(lifecycle).ConvertibleTo(reflect.TypeOf(s.LifecycleSnapshot{})) ||
		reflect.TypeOf(population).ConvertibleTo(reflect.TypeOf(s.PopulationObservation{})) {
		t.Fatal("candidate facts can be converted to trusted evidence")
	}
	for _, typ := range []reflect.Type{
		reflect.TypeOf(s.LifecycleSnapshot{}), reflect.TypeOf(s.PopulationObservation{}),
		reflect.TypeOf(s.FinalMilestone{}), reflect.TypeOf(s.CleanupAttestation{}),
		reflect.TypeOf(s.CleanupOutcome{}), reflect.TypeOf(s.Capacity{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).PkgPath == "" {
				t.Fatalf("%v has externally writable field %s", typ, typ.Field(i).Name)
			}
		}
	}
	allowed := map[string]bool{
		"State": true, "Outcome": true, "Begin": true, "WorkTerminated": true,
		"ObserveLifecycle": true, "ObservePopulation": true, "ConfirmCleanup": true,
		"ObserverLost": true, "OwnershipLost": true, "EvidenceLost": true, "ObserveSlot": true,
	}
	capacityType := reflect.TypeOf(s.Capacity{})
	for i := 0; i < capacityType.NumMethod(); i++ {
		if name := capacityType.Method(i).Name; !allowed[name] {
			t.Fatalf("unexpected capacity authority method %s", name)
		}
	}
	if _, exists := reflect.TypeOf(s.CleanupOutcome{}).MethodByName("ResultAccepted"); exists {
		t.Fatal("cleanup claims sandbox result validation")
	}
	// Public facts and parsed identity remain usable for description only. No
	// public capacity constructor or evidence issuer is required by this surface.
	var c s.Capacity
	if err := c.Begin(invocation(t, false)); !errors.Is(err, s.ErrCapacityQuarantined) {
		t.Fatal("zero capacity began", err)
	}
	if err := c.ObserveLifecycle(s.LifecycleSnapshot{}); !errors.Is(err, s.ErrCapacityQuarantined) {
		t.Fatal("zero lifecycle admitted", err)
	}
	if c.ConfirmCleanup(s.PopulationObservation{}).Classification() != s.Unconfirmed || c.State() != s.Quarantined {
		t.Fatal("candidate/zero evidence released capacity")
	}
}
