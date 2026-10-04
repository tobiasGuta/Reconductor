package exactsupervision

import "strings"

const (
	SlotUnitName = "reconductor-exact-slot.slice"
	// systemd derives slice ancestry from the hyphenated slice name.
	SlotControlGroup = "/reconductor.slice/reconductor-exact.slice/reconductor-exact-slot.slice"
	executionPrefix  = "reconductor-exact-run@"
	executionSuffix  = ".service"
)

// InstanceID contains exactly 16 opaque bytes in lowercase hexadecimal. Its
// zero value is invalid; the explicitly parsed all-zero byte string is allowed.
// Trusted callers must not derive it from targets, approvals, credentials or
// capsule data. Syntax validation cannot establish that semantic provenance.
type InstanceID struct{ canonical string }

func ParseInstanceID(s string) (InstanceID, error) {
	if !hex32(s) {
		return InstanceID{}, ErrInvalidInstanceID
	}
	return InstanceID{s}, nil
}

func (id InstanceID) String() string { return id.canonical }
func (id InstanceID) UnitName() string {
	if !hex32(id.canonical) {
		return ""
	}
	return executionPrefix + id.canonical + executionSuffix
}

func ParseObservedUnitName(s string) (InstanceID, error) {
	if len(s) != len(executionPrefix)+32+len(executionSuffix) || !strings.HasPrefix(s, executionPrefix) || !strings.HasSuffix(s, executionSuffix) {
		return InstanceID{}, ErrInvalidUnitName
	}
	id, err := ParseInstanceID(s[len(executionPrefix) : len(executionPrefix)+32])
	if err != nil || id.UnitName() != s {
		return InstanceID{}, ErrInvalidUnitName
	}
	return id, nil
}

// BootID uses the lowercase 8-4-4-4-12 UUID form, with nonzero opaque bytes.
type BootID struct{ canonical string }

func ParseBootID(s string) (BootID, error) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return BootID{}, ErrInvalidBootID
	}
	raw := s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	if !hex32(raw) || raw == strings.Repeat("0", 32) {
		return BootID{}, ErrInvalidBootID
	}
	return BootID{s}, nil
}

func (id BootID) String() string { return id.canonical }

// InvocationID is systemd's nonzero 16-byte ID in lowercase hexadecimal.
type InvocationID struct{ canonical string }

func ParseInvocationID(s string) (InvocationID, error) {
	if !hex32(s) || s == strings.Repeat("0", 32) {
		return InvocationID{}, ErrInvalidInvocationID
	}
	return InvocationID{s}, nil
}

func (id InvocationID) String() string { return id.canonical }

func hex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := range s {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

// DeviceID is the filesystem's observed device major/minor pair.
type DeviceID struct{ Major, Minor uint32 }

// CgroupFacts are trusted measurements, copied by NewCgroupIdentity. Zero
// KernelCgroupID means unavailable. Once bound, even availability must match;
// adding or dropping a kernel ID cannot transparently rebind an existing slot.
type CgroupFacts struct {
	ControlGroup   string
	Device         DeviceID
	Inode          uint64
	MountID        uint64
	KernelCgroupID uint64
}

type CgroupIdentity struct{ facts CgroupFacts }

func NewCgroupIdentity(f CgroupFacts) (CgroupIdentity, error) {
	if f.ControlGroup != SlotControlGroup || f.Device == (DeviceID{}) || f.Inode == 0 || f.MountID == 0 {
		return CgroupIdentity{}, ErrWrongSlot
	}
	return CgroupIdentity{f}, nil
}

func (id CgroupIdentity) Facts() CgroupFacts { return id.facts }

// SlotGeneration identifies the pinned, fixed slot object within one boot.
// All identity types are immutable value types with exact comparable equality.
type SlotGeneration struct {
	boot   BootID
	cgroup CgroupIdentity
}

func NewSlotGeneration(boot BootID, cg CgroupIdentity) (SlotGeneration, error) {
	if _, err := ParseBootID(boot.String()); err != nil {
		return SlotGeneration{}, err
	}
	if _, err := NewCgroupIdentity(cg.Facts()); err != nil {
		return SlotGeneration{}, err
	}
	return SlotGeneration{boot, cg}, nil
}

func (s SlotGeneration) BootID() BootID         { return s.boot }
func (s SlotGeneration) UnitName() string       { return SlotUnitName }
func (s SlotGeneration) Cgroup() CgroupIdentity { return s.cgroup }
func (s SlotGeneration) validate() error {
	_, err := NewSlotGeneration(s.boot, s.cgroup)
	return err
}

func (s SlotGeneration) match(other SlotGeneration) error {
	if s.boot != other.boot {
		return ErrWrongBoot
	}
	if err := other.validate(); err != nil || s != other {
		return ErrWrongSlot
	}
	return nil
}

// ExecutionInvocation binds the derived unit, original invocation and slot.
// Its boot and unit name are derived, never independent caller arguments.
type ExecutionInvocation struct {
	instance   InstanceID
	invocation InvocationID
	slot       SlotGeneration
}

func NewExecutionInvocation(instance InstanceID, invocation InvocationID, slot SlotGeneration) (ExecutionInvocation, error) {
	if !hex32(instance.String()) {
		return ExecutionInvocation{}, ErrInvalidInstanceID
	}
	if _, err := ParseInvocationID(invocation.String()); err != nil {
		return ExecutionInvocation{}, err
	}
	if err := slot.validate(); err != nil {
		return ExecutionInvocation{}, err
	}
	return ExecutionInvocation{instance, invocation, slot}, nil
}

func (e ExecutionInvocation) InstanceID() InstanceID     { return e.instance }
func (e ExecutionInvocation) UnitName() string           { return e.instance.UnitName() }
func (e ExecutionInvocation) InvocationID() InvocationID { return e.invocation }
func (e ExecutionInvocation) BootID() BootID             { return e.slot.boot }
func (e ExecutionInvocation) Slot() SlotGeneration       { return e.slot }
func (e ExecutionInvocation) validate() error {
	_, err := NewExecutionInvocation(e.instance, e.invocation, e.slot)
	return err
}
