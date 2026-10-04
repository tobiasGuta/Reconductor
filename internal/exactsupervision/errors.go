package exactsupervision

import "errors"

var (
	ErrInvalidInstanceID         = errors.New("invalid exact supervision instance ID")
	ErrInvalidUnitName           = errors.New("invalid exact supervision unit name")
	ErrInvalidBootID             = errors.New("invalid exact supervision boot ID")
	ErrInvalidInvocationID       = errors.New("invalid exact supervision invocation ID")
	ErrWrongBoot                 = errors.New("exact supervision boot mismatch")
	ErrWrongSlot                 = errors.New("exact supervision slot mismatch")
	ErrWrongInvocation           = errors.New("exact supervision invocation mismatch")
	ErrInvalidLifecycle          = errors.New("invalid exact supervision lifecycle")
	ErrNotFinal                  = errors.New("exact supervision lifecycle not final")
	ErrReactivation              = errors.New("exact supervision reactivation observed")
	ErrMissingSlotObservation    = errors.New("missing final exact supervision slot observation")
	ErrSlotStillPopulated        = errors.New("exact supervision slot still populated")
	ErrObservationOutOfOrder     = errors.New("exact supervision observation order ambiguous")
	ErrCapacityBusy              = errors.New("exact supervision capacity busy")
	ErrCapacityQuarantined       = errors.New("exact supervision capacity quarantined")
	ErrInstanceReuse             = errors.New("exact supervision instance already used")
	ErrObserverLost              = errors.New("exact supervision observer lost")
	ErrOwnershipLost             = errors.New("exact supervision ownership lost")
	ErrUntrustedEvidence         = errors.New("exact supervision evidence not package-issued")
	ErrWrongOwner                = errors.New("exact supervision owner generation mismatch")
	ErrObservationOrderExhausted = errors.New("exact supervision observation order exhausted")
)
