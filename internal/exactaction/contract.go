// Package exactaction defines the deliberately small, non-networked v1 action
// and review languages. Neither value performs an HTTP request.
package exactaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

const (
	ContractVersion    = "exact-action-contract/v1"
	ReviewVersion      = "exact-review-context/v1"
	CapabilityRevision = "v1"
	MaxContractBytes   = 32 * 1024
	MaxReviewBytes     = 32 * 1024
)

type Ownership struct {
	ProgramID     domain.ID `json:"program_id"`
	TaskID        domain.ID `json:"task_id"`
	WorkflowRunID domain.ID `json:"workflow_run_id"`
	StepRunID     domain.ID `json:"step_run_id"`
	StepAttempt   int       `json:"step_attempt"`
}
type Capability struct {
	Name             string `json:"name"`
	SemanticRevision string `json:"semantic_revision"`
}
type Request struct {
	Method        string   `json:"method"`
	Scheme        string   `json:"scheme"`
	Hostname      string   `json:"hostname"`
	EffectivePort int      `json:"effective_port"`
	RequestTarget string   `json:"request_target"`
	Headers       []string `json:"headers"`
}
type Identity struct {
	Kind string `json:"kind"`
}
type Limits struct {
	MaxRequests      int  `json:"max_requests"`
	FollowRedirects  bool `json:"follow_redirects"`
	AutomaticRetries bool `json:"automatic_retries"`
}
type ActionContractV1 struct {
	ContractVersion string     `json:"contract_version"`
	ActionID        domain.ID  `json:"action_id"`
	Ownership       Ownership  `json:"ownership"`
	Capability      Capability `json:"capability"`
	Request         Request    `json:"request"`
	Identity        Identity   `json:"identity"`
	Limits          Limits     `json:"limits"`
}
type ProposedRequest struct {
	Method, Scheme, Hostname, RequestTarget string
	EffectivePort                           int
}

var hostLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func (a ActionContractV1) Validate() error {
	if a.ContractVersion != ContractVersion || a.ActionID == "" || a.Ownership.ProgramID == "" || a.Ownership.TaskID == "" || a.Ownership.WorkflowRunID == "" || a.Ownership.StepRunID == "" || a.Ownership.StepAttempt < 1 || a.Capability.Name != "http.request" || a.Capability.SemanticRevision != CapabilityRevision {
		return fmt.Errorf("unsupported or incomplete exact action lineage")
	}
	r := a.Request
	if (r.Method != "GET" && r.Method != "HEAD") || r.Scheme != "https" || r.EffectivePort < 1 || r.EffectivePort > 65535 || r.Headers == nil || len(r.Headers) != 0 || a.Identity.Kind != "anonymous" || a.Limits.MaxRequests != 1 || a.Limits.FollowRedirects || a.Limits.AutomaticRetries {
		return fmt.Errorf("unsupported exact HTTP authority")
	}
	if len(r.Hostname) == 0 || len(r.Hostname) > 253 || strings.ToLower(r.Hostname) != r.Hostname || strings.HasSuffix(r.Hostname, ".") {
		return fmt.Errorf("invalid exact hostname")
	}
	for _, label := range strings.Split(r.Hostname, ".") {
		if !hostLabel.MatchString(label) {
			return fmt.Errorf("invalid exact hostname label")
		}
	}
	if len(r.RequestTarget) == 0 || len(r.RequestTarget) > 8192 || !strings.HasPrefix(r.RequestTarget, "/") || strings.HasPrefix(r.RequestTarget, "//") {
		return fmt.Errorf("invalid origin-form request target")
	}
	for i := 0; i < len(r.RequestTarget); i++ {
		c := r.RequestTarget[i]
		if !allowedTargetByte(c) {
			return fmt.Errorf("unsupported request-target byte")
		}
		if c == '%' {
			if i+2 >= len(r.RequestTarget) || !isHex(r.RequestTarget[i+1]) || !isHex(r.RequestTarget[i+2]) {
				return fmt.Errorf("malformed percent escape")
			}
			i += 2
		}
	}
	return nil
}
func isHex(b byte) bool { return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F' }
func allowedTargetByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		strings.ContainsRune("-._~!$&'()*+,;=:@/?%", rune(b))
}

func (a ActionContractV1) Freeze() ([]byte, string, error) {
	if err := a.Validate(); err != nil {
		return nil, "", err
	}
	return encode(a, MaxContractBytes, "reconductor-exact-action/v1\x00")
}
func DecodeContract(raw []byte, digest string) (ActionContractV1, error) {
	var a ActionContractV1
	if err := decode(raw, digest, MaxContractBytes, "reconductor-exact-action/v1\x00", &a); err != nil {
		return a, err
	}
	return a, a.Validate()
}

type ProposalSource struct {
	Kind     string `json:"kind"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
}
type Citation struct {
	ArtifactID     domain.ID `json:"artifact_id"`
	ArtifactSHA256 string    `json:"artifact_sha256"`
	Locator        string    `json:"locator"`
}
type ReviewContextV1 struct {
	ReviewVersion           string         `json:"review_version"`
	ProposalSource          ProposalSource `json:"proposal_source"`
	Purpose                 string         `json:"purpose"`
	ExpectedPositiveOutcome string         `json:"expected_positive_outcome"`
	ExpectedNegativeOutcome string         `json:"expected_negative_outcome"`
	Assumptions             []string       `json:"assumptions"`
	MissingEvidence         []string       `json:"missing_evidence"`
	SupportingEvidence      []Citation     `json:"supporting_evidence"`
	ContradictoryEvidence   []Citation     `json:"contradictory_evidence"`
}

func (r ReviewContextV1) Validate() error {
	if r.ReviewVersion != ReviewVersion || !boundedString(r.ProposalSource.Kind, 1, 80) || len(r.ProposalSource.Provider) > 80 || len(r.ProposalSource.Model) > 120 || !boundedString(r.Purpose, 1, 2048) || !boundedString(r.ExpectedPositiveOutcome, 1, 2048) || !boundedString(r.ExpectedNegativeOutcome, 1, 2048) || r.Assumptions == nil || r.MissingEvidence == nil || r.SupportingEvidence == nil || r.ContradictoryEvidence == nil || len(r.Assumptions) > 16 || len(r.MissingEvidence) > 16 || len(r.SupportingEvidence) > 32 || len(r.ContradictoryEvidence) > 32 {
		return fmt.Errorf("invalid or unbounded review context")
	}
	for _, value := range append(append([]string{}, r.Assumptions...), r.MissingEvidence...) {
		if !boundedString(value, 1, 512) {
			return fmt.Errorf("invalid review entry")
		}
	}
	seen := map[domain.ID]bool{}
	for _, c := range append(append([]Citation{}, r.SupportingEvidence...), r.ContradictoryEvidence...) {
		if c.ArtifactID == "" || !hashString(c.ArtifactSHA256) || !boundedString(c.Locator, 1, 512) || seen[c.ArtifactID] {
			return fmt.Errorf("invalid or duplicate review citation")
		}
		seen[c.ArtifactID] = true
	}
	return nil
}
func boundedString(s string, min, max int) bool {
	return len(s) >= min && len(s) <= max && strings.TrimSpace(s) != ""
}
func hashString(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == strings.ToLower(s)
}
func (r ReviewContextV1) Freeze() ([]byte, string, error) {
	if err := r.Validate(); err != nil {
		return nil, "", err
	}
	return encode(r, MaxReviewBytes, "reconductor-exact-review/v1\x00")
}
func DecodeReview(raw []byte, digest string) (ReviewContextV1, error) {
	var r ReviewContextV1
	if err := decode(raw, digest, MaxReviewBytes, "reconductor-exact-review/v1\x00", &r); err != nil {
		return r, err
	}
	return r, r.Validate()
}
func encode(value any, bound int, domain string) ([]byte, string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	_, canonical, nodes, depth, err := canonicaljson.ParseStrictBounded(raw, bound)
	if err != nil {
		return nil, "", err
	}
	if nodes > 1024 || depth > 8 {
		return nil, "", fmt.Errorf("exact value structure exceeds bound")
	}
	sum := sha256.Sum256(append([]byte(domain), canonical...))
	return canonical, hex.EncodeToString(sum[:]), nil
}
func decode(raw []byte, digest string, bound int, domain string, destination any) error {
	_, canonical, nodes, depth, err := canonicaljson.ParseStrictBounded(raw, bound)
	if err != nil {
		return err
	}
	if nodes > 1024 || depth > 8 || !bytes.Equal(raw, canonical) {
		return fmt.Errorf("exact value is not bounded canonical JSON")
	}
	if !hashString(digest) {
		return fmt.Errorf("invalid exact hash")
	}
	sum := sha256.Sum256(append([]byte(domain), raw...))
	if hex.EncodeToString(sum[:]) != digest {
		return fmt.Errorf("exact hash mismatch")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	reencoded, _, err := encode(destination, bound, domain)
	if err != nil || !bytes.Equal(raw, reencoded) {
		return fmt.Errorf("exact value does not match closed typed representation")
	}
	return nil
}
