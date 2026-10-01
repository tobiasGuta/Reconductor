package console

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/database"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
)

type exactApprovalStore interface {
	ListExactApprovalStates(context.Context, domain.ID, domain.ID) ([]database.ExactApprovalState, error)
	GetExactApprovalState(context.Context, domain.ID) (database.ExactApprovalState, error)
	GetExactApprovalReview(context.Context, domain.ID) (database.ExactApprovalReview, error)
	DecideExactApproval(context.Context, domain.ID, string, string, string, string) error
}

// DTOs intentionally enumerate safe review fields, never internal DB structs.
type exactStateDTO struct {
	ApprovalID   domain.ID  `json:"approval_id"`
	Status       string     `json:"status"`
	Decision     string     `json:"decision"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
	Decisionable bool       `json:"decisionable"`
}
type exactRequestDTO struct {
	Scheme        string   `json:"scheme"`
	Method        string   `json:"method"`
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	RequestTarget string   `json:"request_target"`
	Identity      string   `json:"identity"`
	Headers       []string `json:"headers"`
	Body          string   `json:"body"`
	MaxRequests   int      `json:"max_requests"`
	Redirects     bool     `json:"redirects"`
	Retries       bool     `json:"retries"`
}
type exactCitationDTO struct {
	Role                string    `json:"role"`
	ArtifactID          domain.ID `json:"artifact_id"`
	FrozenSHA256        string    `json:"frozen_sha256"`
	Locator             string    `json:"locator"`
	CurrentAvailability string    `json:"current_availability"`
}
type exactReviewDTO struct {
	Version                 string             `json:"version"`
	SourceKind              string             `json:"source_kind"`
	SourceProvider          string             `json:"source_provider"`
	SourceModel             string             `json:"source_model"`
	Purpose                 string             `json:"purpose"`
	ExpectedPositiveOutcome string             `json:"expected_positive_outcome"`
	ExpectedNegativeOutcome string             `json:"expected_negative_outcome"`
	Assumptions             []string           `json:"assumptions"`
	MissingEvidence         []string           `json:"missing_evidence"`
	Citations               []exactCitationDTO `json:"citations"`
}
type exactDetailDTO struct {
	exactStateDTO
	ContractVersion    string          `json:"contract_version"`
	ActionID           domain.ID       `json:"action_id"`
	ProgramID          domain.ID       `json:"program_id"`
	TaskID             domain.ID       `json:"task_id"`
	WorkflowRunID      domain.ID       `json:"workflow_run_id"`
	StepRunID          domain.ID       `json:"step_run_id"`
	StepAttempt        int             `json:"step_attempt"`
	Capability         string          `json:"capability"`
	CapabilityRevision string          `json:"capability_revision"`
	ProviderAttemptID  domain.ID       `json:"provider_attempt_id"`
	ActionHash         string          `json:"action_hash"`
	ReviewHash         string          `json:"review_hash"`
	Request            exactRequestDTO `json:"request"`
	Review             exactReviewDTO  `json:"review"`
	EvidenceAvailable  bool            `json:"evidence_available"`
}

func exactStateProjection(v database.ExactApprovalState) exactStateDTO {
	return exactStateDTO{v.ApprovalID, v.Status, v.Decision, v.CreatedAt, v.ExpiresAt, v.RevokedAt, v.Decisionable}
}
func loadExactDetail(ctx context.Context, store exactApprovalStore, id domain.ID) (exactDetailDTO, error) {
	v, err := store.GetExactApprovalReview(ctx, id)
	if err != nil {
		return exactDetailDTO{}, err
	}
	state, err := store.GetExactApprovalState(ctx, id)
	if err != nil {
		return exactDetailDTO{}, err
	}
	r := v.Action.Request
	out := exactDetailDTO{exactStateDTO: exactStateProjection(state), ContractVersion: v.Action.ContractVersion, ActionID: v.Action.ActionID, ActionHash: v.ActionSHA256, ReviewHash: v.ReviewContextSHA256,
		ProgramID: v.Action.Ownership.ProgramID, TaskID: v.Action.Ownership.TaskID, WorkflowRunID: v.Action.Ownership.WorkflowRunID, StepRunID: v.Action.Ownership.StepRunID, StepAttempt: v.Action.Ownership.StepAttempt, Capability: v.Action.Capability.Name, CapabilityRevision: v.Action.Capability.SemanticRevision, ProviderAttemptID: v.ProviderAttemptID,
		Request: exactRequestDTO{r.Scheme, r.Method, r.Hostname, r.EffectivePort, r.RequestTarget, v.Action.Identity.Kind, append([]string{}, r.Headers...), "none", v.Action.Limits.MaxRequests, v.Action.Limits.FollowRedirects, v.Action.Limits.AutomaticRetries},
		Review:  exactReviewDTO{Version: v.Review.ReviewVersion, SourceKind: v.Review.ProposalSource.Kind, SourceProvider: v.Review.ProposalSource.Provider, SourceModel: v.Review.ProposalSource.Model, Purpose: v.Review.Purpose, ExpectedPositiveOutcome: v.Review.ExpectedPositiveOutcome, ExpectedNegativeOutcome: v.Review.ExpectedNegativeOutcome, Assumptions: append([]string{}, v.Review.Assumptions...), MissingEvidence: append([]string{}, v.Review.MissingEvidence...), Citations: []exactCitationDTO{}}, EvidenceAvailable: true}
	availability := make(map[domain.ID]string, len(v.CitationAvailability))
	for _, item := range v.CitationAvailability {
		availability[item.ArtifactID] = item.Status
	}
	for _, group := range []struct {
		role      string
		citations []exactaction.Citation
	}{{"supporting", v.Review.SupportingEvidence}, {"contradictory", v.Review.ContradictoryEvidence}} {
		for _, citation := range group.citations {
			status := availability[citation.ArtifactID]
			if status != "available" && status != "restricted" {
				status = "unavailable"
			}
			out.EvidenceAvailable = out.EvidenceAvailable && status == "available"
			out.Review.Citations = append(out.Review.Citations, exactCitationDTO{group.role, citation.ArtifactID, citation.ArtifactSHA256, citation.Locator, status})
		}
	}
	return out, nil
}

func (s *Server) exactApprovals(w http.ResponseWriter, r *http.Request) {
	store, ok := s.store.(exactApprovalStore)
	if !ok {
		writeError(w, 503, "exact review unavailable")
		return
	}
	items, err := store.ListExactApprovalStates(r.Context(), domain.ID(r.URL.Query().Get("program_id")), domain.ID(r.URL.Query().Get("after")))
	if err != nil {
		writeError(w, 503, "exact review list unavailable")
		return
	}
	next := ""
	if len(items) > 100 {
		items = items[:100]
		next = string(items[99].ApprovalID)
	}
	list := make([]exactStateDTO, 0, len(items))
	for _, item := range items {
		list = append(list, exactStateProjection(item))
	}
	writeJSON(w, 200, struct {
		Items      []exactStateDTO `json:"items"`
		NextCursor string          `json:"next_cursor"`
	}{list, next})
}
func (s *Server) exactApprovalDetail(w http.ResponseWriter, r *http.Request) {
	store, ok := s.store.(exactApprovalStore)
	if !ok {
		writeError(w, 503, "exact review unavailable")
		return
	}
	detail, err := loadExactDetail(r.Context(), store, domain.ID(r.PathValue("id")))
	if err != nil {
		exactReadError(w, err)
		return
	}
	writeJSON(w, 200, detail)
}
func exactReadError(w http.ResponseWriter, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, 404, "exact approval not found")
	} else {
		writeError(w, 503, "frozen exact review unavailable")
	}
}

func (s *Server) decideExactApproval(w http.ResponseWriter, r *http.Request) {
	if !s.validOperatorRequest(r) {
		writeError(w, 403, "operator request validation failed")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeError(w, 400, "content type must be application/json")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeError(w, 400, "request body must be valid JSON")
		return
	}
	value, _, _, _, err := canonicaljson.ParseStrict(raw)
	if err != nil {
		writeError(w, 400, "request body must be valid JSON")
		return
	}
	fields, ok := value.(map[string]any)
	if !ok || len(fields) != 3 || fields["decision"] == nil || fields["action_hash"] == nil || fields["review_hash"] == nil {
		writeError(w, 400, "invalid exact decision fields")
		return
	}
	var body struct {
		Decision   string `json:"decision"`
		ActionHash string `json:"action_hash"`
		ReviewHash string `json:"review_hash"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&body); err != nil || (body.Decision != "approved" && body.Decision != "rejected") {
		writeError(w, 400, "invalid exact decision fields")
		return
	}
	store, ok := s.store.(exactApprovalStore)
	if !ok {
		writeError(w, 503, "exact review unavailable")
		return
	}
	id := domain.ID(r.PathValue("id"))
	detail, err := loadExactDetail(r.Context(), store, id)
	if err != nil {
		exactReadError(w, err)
		return
	}
	status := http.StatusConflict
	message := "Exact decision was not accepted. Review the current state."
	if body.ActionHash == detail.ActionHash && body.ReviewHash == detail.ReviewHash {
		if err = store.DecideExactApproval(r.Context(), id, body.ActionHash, body.ReviewHash, body.Decision, s.operator.actor); err == nil {
			status = 200
			message = "Authorization decision recorded. No request was executed."
		}
	}
	// Reload even after a rejected/stale decision. No optimistic state or dispatch.
	detail, err = loadExactDetail(r.Context(), store, id)
	if err != nil {
		exactReadError(w, err)
		return
	}
	writeJSONStatus(w, status, struct {
		Message string         `json:"message"`
		Review  exactDetailDTO `json:"review"`
	}{message, detail})
}
