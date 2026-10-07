package domain

import "errors"

// PersistenceUnresolved is deliberately independent of database/caller packages.
// It must be checked before cancellation rewriting, retries or terminalization.
func PersistenceUnresolved(err error) bool {
	var unresolved interface{ PersistenceUnresolved() bool }
	if errors.As(err, &unresolved) && unresolved.PersistenceUnresolved() {
		return true
	}
	var unknown interface{ CommitOutcomeUnknown() bool }
	return errors.As(err, &unknown) && unknown.CommitOutcomeUnknown()
}

type UnresolvedPersistenceError struct{ Err error }

func (e *UnresolvedPersistenceError) Error() string {
	return "result persistence is unresolved; authoritative reconciliation required"
}
func (e *UnresolvedPersistenceError) Unwrap() error               { return e.Err }
func (e *UnresolvedPersistenceError) PersistenceUnresolved() bool { return true }

// BoundedExecutionError preserves typed causes for errors.Is/As without copying
// provider diagnostics into workflow events, checkpoints or queue details.
type BoundedExecutionError struct {
	Err     error
	Message string
}

func (e *BoundedExecutionError) Error() string { return BoundUTF8(e.Message, SafeMessageMaxBytes) }
func (e *BoundedExecutionError) Unwrap() error { return e.Err }
