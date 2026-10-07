package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/normalize"
	"github.com/tobiasGuta/Reconductor/internal/policy"
	"github.com/tobiasGuta/Reconductor/internal/strictjsonschema"
)

type Manifest struct {
	Name                              string              `json:"name"`
	Description                       string              `json:"description"`
	Version                           string              `json:"version"`
	Risk                              policy.Risk         `json:"risk"`
	InputSchema                       json.RawMessage     `json:"input_schema"`
	OutputSchema                      json.RawMessage     `json:"output_schema"`
	RequiredScopeType                 string              `json:"required_scope_type"`
	ApprovalRequired                  bool                `json:"approval_required"`
	RetrySafe                         bool                `json:"retry_safe"`
	Idempotent                        bool                `json:"idempotent"`
	SupportedProviders                []string            `json:"supported_providers"`
	ProducedArtifactTypes             []string            `json:"produced_artifact_types"`
	RequiredSecrets                   []string            `json:"required_secrets"`
	PolicyRequirements                policy.Requirements `json:"policy_requirements"`
	DefaultTimeout                    time.Duration       `json:"default_timeout"`
	SupportsSemanticBindingReferences bool                `json:"supports_semantic_binding_references"`
}
type Request struct {
	Action                  domain.ActionRequest       `json:"action"`
	ProgramID               domain.ID                  `json:"program_id"`
	Provider                string                     `json:"provider"`
	Approved                bool                       `json:"approved"`
	Policy                  policy.Policy              `json:"policy"`
	Scope                   Scope                      `json:"scope"`
	PolicyPhase             string                     `json:"-"`
	DecisionRecorder        PolicyDecisionRecorder     `json:"-"`
	InvocationRecorder      ProviderInvocationRecorder `json:"-"`
	QueueJobID              *domain.ID                 `json:"-"`
	PreparedStoreIdentity   *artifact.StoreIdentity    `json:"-"`
	RequirePreparedEvidence bool                       `json:"-"`
}

type PolicyDecisionRecord struct {
	ProgramID    domain.ID            `json:"program_id"`
	Action       domain.ActionRequest `json:"action"`
	QueueJobID   *domain.ID           `json:"-"`
	Provider     string               `json:"provider"`
	PolicyID     string               `json:"policy_id"`
	Phase        string               `json:"phase"`
	Requirements policy.Requirements  `json:"requirements"`
	Evaluation   policy.Evaluation    `json:"evaluation"`
}

type PolicyDecisionRecorder interface {
	RecordPolicyDecision(context.Context, PolicyDecisionRecord) (domain.ID, error)
}

type ProviderInvocationStartRecord struct {
	ProgramID                     domain.ID
	TaskID                        domain.ID
	WorkflowRunID                 domain.ID
	StepRunID                     domain.ID
	ActionRequestID               domain.ID
	StepAttempt                   int
	QueueJobID                    *domain.ID
	ExecutionAuthorizationEventID domain.ID
	Capability                    string
	Provider                      string
	Actor                         string
}

type ProviderInvocationOutcome string

const (
	ProviderInvocationSucceeded ProviderInvocationOutcome = "succeeded"
	ProviderInvocationFailed    ProviderInvocationOutcome = "failed"
	ProviderInvocationCancelled ProviderInvocationOutcome = "cancelled"
	ProviderInvocationTimedOut  ProviderInvocationOutcome = "timeout"
)

func (o ProviderInvocationOutcome) Validate() error {
	switch o {
	case ProviderInvocationSucceeded, ProviderInvocationFailed, ProviderInvocationCancelled, ProviderInvocationTimedOut:
		return nil
	default:
		return fmt.Errorf("invalid provider invocation outcome %q", o)
	}
}

type ProviderInvocationTerminalRecord struct {
	ProviderAttemptID domain.ID
	ProgramID         domain.ID
	TaskID            domain.ID
	WorkflowRunID     domain.ID
	StepRunID         domain.ID
	Capability        string
	Provider          string
	Actor             string
	Outcome           ProviderInvocationOutcome
}

type ProviderInvocationRecorder interface {
	RecordProviderInvocationStarted(context.Context, ProviderInvocationStartRecord) (domain.ID, error)
	RecordProviderInvocationTerminal(context.Context, ProviderInvocationTerminalRecord) error
}
type ProviderInvocationAdmission struct {
	ProviderAttemptID     domain.ID
	PreparedSetID         domain.ID
	ManifestID            domain.ID
	ReservedCapacityBytes int64
}
type PreparedProviderInvocationAllocator interface {
	AllocateProviderInvocation(context.Context, ProviderInvocationStartRecord, artifact.StoreIdentity) (ProviderInvocationAdmission, error)
}
type ResultAdmissionProvenance struct {
	ProviderAttemptID             domain.ID
	PreparedSetID                 domain.ID
	ManifestID                    domain.ID
	ProviderTerminalEventID       domain.ID
	ReservedCapacityBytes         int64
	ActionRequestID               domain.ID
	StepAttempt                   int
	QueueJobID                    *domain.ID
	ExecutionAuthorizationEventID domain.ID
	Provider                      string
}
type Result struct {
	OutputLimit         *domain.ResultContractLimitV1  `json:"-"`
	Action              domain.ActionResult            `json:"action"`
	EffectiveInput      json.RawMessage                `json:"effective_input,omitempty"`
	ToolRun             *domain.ToolRun                `json:"tool_run,omitempty"`
	RawStdout           []byte                         `json:"-"`
	RawStderr           []byte                         `json:"-"`
	RawDiagnostic       []byte                         `json:"-"`
	Envelope            *domain.ResultEnvelopeV1       `json:"-"`
	ProviderOutcome     domain.ResultProviderOutcomeV1 `json:"-"`
	ProviderAttemptID   *domain.ID                     `json:"-"`
	AdmissionProvenance *ResultAdmissionProvenance     `json:"-"`
	TerminalAuditError  error                          `json:"-"`
}
type Scope interface{ Allows(string) bool }
type Capability interface {
	Manifest() Manifest
	Validate(context.Context, Request) error
	Execute(context.Context, Request) (Result, error)
}
type DefinitionValidator interface{ ValidateDefinition(json.RawMessage) error }
type Registry struct {
	items map[string]Capability
	now   func() time.Time
}

type Multi struct {
	manifest        Manifest
	defaultProvider string
	providers       map[string]Capability
}

func NewMulti(defaultProvider string, providers map[string]Capability) (*Multi, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("at least one provider is required")
	}
	base, ok := providers[defaultProvider]
	if !ok {
		return nil, fmt.Errorf("default provider %q is not registered", defaultProvider)
	}
	m := base.Manifest()
	m.SupportedProviders = nil
	for name, p := range providers {
		providerManifest := p.Manifest()
		if providerManifest.Name != m.Name {
			return nil, fmt.Errorf("provider %s implements %s, expected %s", name, providerManifest.Name, m.Name)
		}
		m.PolicyRequirements = mergeRequirements(m.PolicyRequirements, providerManifest.PolicyRequirements)
		m.SupportedProviders = append(m.SupportedProviders, name)
	}
	sort.Strings(m.SupportedProviders)
	return &Multi{manifest: m, defaultProvider: defaultProvider, providers: providers}, nil
}

func mergeRequirements(a, b policy.Requirements) policy.Requirements {
	return policy.Requirements{Authentication: a.Authentication || b.Authentication, DirectoryFuzzing: a.DirectoryFuzzing || b.DirectoryFuzzing, CrossOrigin: a.CrossOrigin || b.CrossOrigin, IntrusiveChecks: a.IntrusiveChecks || b.IntrusiveChecks}
}
func (m *Multi) Manifest() Manifest { return m.manifest }
func (m *Multi) provider(name string) (Capability, error) {
	if name == "" {
		name = m.defaultProvider
	}
	p, ok := m.providers[name]
	if !ok {
		return nil, fmt.Errorf("provider %q is not supported for %s", name, m.manifest.Name)
	}
	return p, nil
}
func (m *Multi) Validate(ctx context.Context, r Request) error {
	p, err := m.provider(r.Provider)
	if err != nil {
		return err
	}
	return p.Validate(ctx, r)
}
func (m *Multi) Execute(ctx context.Context, r Request) (Result, error) {
	p, err := m.provider(r.Provider)
	if err != nil {
		return Result{}, err
	}
	return p.Execute(ctx, r)
}
func (m *Multi) ValidateDefinition(raw json.RawMessage) error {
	p, err := m.provider(m.defaultProvider)
	if err != nil {
		return err
	}
	if v, ok := p.(DefinitionValidator); ok {
		return v.ValidateDefinition(raw)
	}
	return nil
}

func NewRegistry() *Registry { return &Registry{items: map[string]Capability{}, now: time.Now} }
func (r *Registry) Register(c Capability) error {
	m := c.Manifest()
	if m.Name == "" || m.Version == "" {
		return fmt.Errorf("capability name and version are required")
	}
	if _, ok := r.items[m.Name]; ok {
		return fmt.Errorf("capability %s already registered", m.Name)
	}
	r.items[m.Name] = c
	return nil
}
func (r *Registry) Get(name string) (Capability, bool) { c, ok := r.items[name]; return c, ok }
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.items))
	for n := range r.items {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
func (r *Registry) Execute(ctx context.Context, req Request) (Result, error) {
	trustedQueueJobID := copyIDPointer(req.QueueJobID)
	req.Provider = r.providerName(req.Action.Capability, req.Provider)
	if req.PolicyPhase != "" && req.PolicyPhase != "execution" {
		return Result{}, fmt.Errorf("provider execution requires execution policy phase")
	}
	authorizationReq := req
	authorizationReq.QueueJobID = copyIDPointer(trustedQueueJobID)
	c, authorizationEventID, err := r.authorize(ctx, authorizationReq, true)
	if err != nil {
		return Result{}, err
	}
	validationReq := req
	validationReq.QueueJobID = copyIDPointer(trustedQueueJobID)
	if err := c.Validate(ctx, validationReq); err != nil {
		return Result{}, err
	}
	if req.InvocationRecorder == nil {
		return Result{}, fmt.Errorf("provider invocation recorder is required")
	}
	startRecord := ProviderInvocationStartRecord{
		ProgramID:                     req.ProgramID,
		TaskID:                        req.Action.TaskID,
		WorkflowRunID:                 req.Action.WorkflowRunID,
		StepRunID:                     req.Action.StepRunID,
		ActionRequestID:               req.Action.ID,
		StepAttempt:                   req.Action.StepAttempt,
		QueueJobID:                    copyIDPointer(trustedQueueJobID),
		ExecutionAuthorizationEventID: authorizationEventID,
		Capability:                    req.Action.Capability,
		Provider:                      req.Provider,
		Actor:                         req.Action.RequestedBy,
	}
	var preparedAdmission ProviderInvocationAdmission
	var attemptID domain.ID
	if req.RequirePreparedEvidence {
		allocator, ok := req.InvocationRecorder.(PreparedProviderInvocationAllocator)
		if !ok || req.PreparedStoreIdentity == nil {
			return Result{}, fmt.Errorf("durable prepared-evidence allocator is required")
		}
		preparedAdmission, err = allocator.AllocateProviderInvocation(ctx, startRecord, *req.PreparedStoreIdentity)
		attemptID = preparedAdmission.ProviderAttemptID
	} else {
		attemptID, err = req.InvocationRecorder.RecordProviderInvocationStarted(ctx, startRecord)
	}
	if err != nil {
		return Result{}, fmt.Errorf("persist provider invocation start: %w", err)
	}
	if attemptID == "" {
		return Result{}, fmt.Errorf("persist provider invocation start: durable event id is required")
	}
	executionReq := req
	executionReq.QueueJobID = copyIDPointer(trustedQueueJobID)
	budget := int64(domain.ResultEnvelopeMaxBytes)
	if req.RequirePreparedEvidence {
		budget = preparedAdmission.ReservedCapacityBytes
		if budget < 1 || budget > domain.PreparedSetOutputAuthorityMaxBytes {
			return Result{}, &domain.UnresolvedPersistenceError{Err: fmt.Errorf("invalid allocated output byte authority")}
		}
	}
	providerCtx := ctx
	if req.RequirePreparedEvidence {
		providerCtx = WithOutputBudget(ctx, budget)
	}
	result, providerErr := c.Execute(providerCtx, executionReq)
	if limitErr := EnforceOutputBudget(&result, budget); limitErr != nil {
		providerErr = limitErr
	}
	if providerErr != nil && len(result.RawDiagnostic) == 0 {
		message := providerErr.Error()
		if int64(len(message)) > budget {
			providerErr = RejectOutput(&result, budget)
		} else {
			result.RawDiagnostic = []byte(message)
		}
	}
	if providerErr == nil && result.Action.Status == "succeeded" && req.Action.Capability == "probe.http" {
		// Check numeric/escape expansion before source-record canonicalization.
		_, _, _, _, preflightErr := canonicaljson.ParseStrictBounded(result.Action.Output, int(budget))
		var decorated json.RawMessage
		decorateErr := preflightErr
		if decorateErr == nil {
			decorated, decorateErr = normalize.AttachProbeHTTPSourceRecordsBounded(result.Action.Output, string(req.ProgramID), string(attemptID), req.Action.Input, int(budget))
		}
		if decorateErr != nil {
			var encodingLimit *canonicaljson.EncodingLimitError
			if errors.As(decorateErr, &encodingLimit) {
				providerErr = RejectOutput(&result, budget)
			} else {
				if len(result.RawDiagnostic) == 0 {
					result.RawDiagnostic = append([]byte(nil), decorateErr.Error()...)
				}
				result.Action.Status = "failed"
				result.Action.Error = &domain.StructuredError{Classification: "source_contract", Message: "probe HTTP source lineage could not be derived", Retryable: false}
				providerErr = fmt.Errorf("decorate probe.http source lineage: %w", decorateErr)
			}
		} else {
			result.Action.Output = decorated
		}
	}
	if limitErr := EnforceOutputBudget(&result, budget); limitErr != nil {
		providerErr = limitErr
	}
	if providerErr == nil && len(result.Action.Output) > 0 {
		semanticValue, _, _, _, semanticErr := canonicaljson.ParseStrictBounded(result.Action.Output, int(budget))
		if semanticErr == nil && len(c.Manifest().OutputSchema) > 0 {
			var schemaValue any
			schemaValue, _, _, _, semanticErr = canonicaljson.ParseStrict(c.Manifest().OutputSchema)
			if semanticErr == nil {
				semanticErr = strictjsonschema.Validate(schemaValue, semanticValue)
			}
		}
		if semanticErr != nil {
			var limitErr *canonicaljson.EncodingLimitError
			if errors.As(semanticErr, &limitErr) {
				providerErr = RejectOutput(&result, budget)
			} else {
				result.Action.Status = "failed"
				result.Action.Error = &domain.StructuredError{Classification: "provider_contract_invalid", Message: "provider returned invalid semantic output", Retryable: false}
				providerErr = fmt.Errorf("provider returned invalid semantic output: %w", semanticErr)
			}
		}
	}
	result.Action.RequestID = req.Action.ID
	if result.ToolRun != nil {
		result.ToolRun.Provider = req.Provider
	}
	result.ProviderAttemptID = &attemptID
	result.AdmissionProvenance = &ResultAdmissionProvenance{
		ProviderAttemptID:             attemptID,
		PreparedSetID:                 preparedAdmission.PreparedSetID,
		ManifestID:                    preparedAdmission.ManifestID,
		ReservedCapacityBytes:         preparedAdmission.ReservedCapacityBytes,
		ActionRequestID:               req.Action.ID,
		StepAttempt:                   req.Action.StepAttempt,
		QueueJobID:                    copyIDPointer(trustedQueueJobID),
		ExecutionAuthorizationEventID: authorizationEventID,
		Provider:                      req.Provider,
	}
	result.TerminalAuditError = nil
	terminalOutcome := classifyProviderInvocation(ctx, result, providerErr)
	result.ProviderOutcome = domain.ResultProviderOutcomeV1(terminalOutcome)
	if req.RequirePreparedEvidence {
		result.AdmissionProvenance.ProviderTerminalEventID = domain.NewID()
		return result, providerErr
	}
	terminalErr := req.InvocationRecorder.RecordProviderInvocationTerminal(ctx, ProviderInvocationTerminalRecord{
		ProviderAttemptID: attemptID,
		ProgramID:         req.ProgramID,
		TaskID:            req.Action.TaskID,
		WorkflowRunID:     req.Action.WorkflowRunID,
		StepRunID:         req.Action.StepRunID,
		Capability:        req.Action.Capability,
		Provider:          req.Provider,
		Actor:             req.Action.RequestedBy,
		Outcome:           terminalOutcome,
	})
	if terminalErr != nil {
		result.TerminalAuditError = fmt.Errorf("persist provider invocation terminal: %w", terminalErr)
	}
	return result, providerErr
}

func (r *Registry) providerName(capabilityName, requested string) string {
	if requested != "" {
		return requested
	}
	implementation, ok := r.Get(capabilityName)
	if !ok {
		return requested
	}
	if multi, ok := implementation.(*Multi); ok && multi.defaultProvider != "" {
		return multi.defaultProvider
	}
	if supported := implementation.Manifest().SupportedProviders; len(supported) > 0 {
		return supported[0]
	}
	return capabilityName
}

// ProviderName resolves an omitted provider through the registry's configured
// default while preserving an explicit provider selection.
func (r *Registry) ProviderName(capabilityName, requested string) string {
	return r.providerName(capabilityName, requested)
}

// Validate authorizes and validates an action without executing its provider.
func (r *Registry) Validate(ctx context.Context, req Request) error {
	trustedQueueJobID := copyIDPointer(req.QueueJobID)
	authorizationReq := req
	authorizationReq.QueueJobID = copyIDPointer(trustedQueueJobID)
	c, _, err := r.authorize(ctx, authorizationReq, false)
	if err != nil {
		return err
	}
	validationReq := req
	validationReq.QueueJobID = copyIDPointer(trustedQueueJobID)
	return c.Validate(ctx, validationReq)
}

func copyIDPointer(id *domain.ID) *domain.ID {
	if id == nil {
		return nil
	}
	value := *id
	return &value
}

func (r *Registry) authorize(ctx context.Context, req Request, requireDecisionRecord bool) (Capability, domain.ID, error) {
	c, ok := r.Get(req.Action.Capability)
	if !ok {
		return nil, "", fmt.Errorf("unknown capability %q", req.Action.Capability)
	}
	manifest := c.Manifest()
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	eval := policy.EvaluateAt(req.Policy, manifest.Name, manifest.Risk, req.Approved, manifest.PolicyRequirements, req.Action.Input, now().UTC())
	phase := req.PolicyPhase
	if phase == "" {
		phase = "execution"
	}
	var eventID domain.ID
	if req.DecisionRecorder != nil {
		record := PolicyDecisionRecord{ProgramID: req.ProgramID, Action: req.Action, QueueJobID: req.QueueJobID, Provider: req.Provider, PolicyID: req.Policy.ID, Phase: phase, Requirements: manifest.PolicyRequirements, Evaluation: eval}
		var err error
		eventID, err = req.DecisionRecorder.RecordPolicyDecision(ctx, record)
		if err != nil {
			return nil, "", fmt.Errorf("persist policy decision: %w", err)
		}
		if eventID == "" {
			return nil, "", fmt.Errorf("persist policy decision: durable event id is required")
		}
	} else if requireDecisionRecord {
		return nil, "", fmt.Errorf("execution policy decision recorder is required")
	}
	if eval.Decision != policy.Allow {
		return nil, "", fmt.Errorf("policy %s: %s", eval.Decision, eval.Reason)
	}
	return c, eventID, nil
}

func classifyProviderInvocation(ctx context.Context, result Result, err error) ProviderInvocationOutcome {
	status := strings.ToLower(strings.TrimSpace(result.Action.Status))
	if status == "succeeded" && result.Action.Error == nil && err == nil {
		return ProviderInvocationSucceeded
	}
	if providerResultTimedOut(result) || (status == "" && errors.Is(err, context.DeadlineExceeded)) {
		return ProviderInvocationTimedOut
	}
	if status == "cancelled" || status == "canceled" || providerResultCancelled(result) || (status == "" && errors.Is(err, context.Canceled)) {
		return ProviderInvocationCancelled
	}
	if err != nil || result.Action.Error != nil || status == "failed" {
		return ProviderInvocationFailed
	}
	if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		return ProviderInvocationTimedOut
	}
	if errors.Is(context.Cause(ctx), context.Canceled) {
		return ProviderInvocationCancelled
	}
	return ProviderInvocationSucceeded
}

func providerResultCancelled(result Result) bool {
	if result.Action.Error == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(result.Action.Error.Classification)) {
	case "cancelled", "canceled", "context_canceled":
		return true
	}
	return false
}

func providerResultTimedOut(result Result) bool {
	switch strings.ToLower(strings.TrimSpace(result.Action.Status)) {
	case "timeout", "timed_out":
		return true
	}
	if result.ToolRun != nil && result.ToolRun.TimedOut {
		return true
	}
	if result.Action.Error == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(result.Action.Error.Classification)) {
	case "timeout", "timed_out", "deadline_exceeded":
		return true
	default:
		return false
	}
}
func (r *Registry) ValidateDefinitionInput(name string, raw json.RawMessage) error {
	c, ok := r.Get(name)
	if !ok {
		return fmt.Errorf("unknown capability %q", name)
	}
	if v, ok := c.(DefinitionValidator); ok {
		return v.ValidateDefinition(raw)
	}
	return nil
}
