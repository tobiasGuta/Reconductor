package domain

import "context"

// PreparedRecoveryRequest carries exact evidence identities, NOT scheduler or
// execution authority. Database admission must re-prove all durable facts under
// its lineage locks. Only the recovery path installs it after durable inspection.
type PreparedRecoveryRequest struct {
	SetID, ManifestID, ProviderAttemptID, TerminalEventID, ResultOccurrenceID ID
	ActionRequestID                                                           ID
	StepAttempt                                                               int
	ManifestSHA256                                                            string
}
type preparedRecoveryRequestKey struct{}

func WithPreparedRecoveryRequest(ctx context.Context, request PreparedRecoveryRequest) context.Context {
	return context.WithValue(ctx, preparedRecoveryRequestKey{}, request)
}
func PreparedRecoveryRequestFromContext(ctx context.Context) (PreparedRecoveryRequest, bool) {
	request, ok := ctx.Value(preparedRecoveryRequestKey{}).(PreparedRecoveryRequest)
	return request, ok
}
