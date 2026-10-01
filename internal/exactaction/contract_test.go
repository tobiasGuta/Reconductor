package exactaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func testContract() ActionContractV1 {
	return ActionContractV1{ContractVersion: ContractVersion, ActionID: domain.NewID(), Ownership: Ownership{ProgramID: domain.NewID(), TaskID: domain.NewID(), WorkflowRunID: domain.NewID(), StepRunID: domain.NewID(), StepAttempt: 1}, Capability: Capability{Name: "http.request", SemanticRevision: CapabilityRevision}, Request: Request{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: "/orders/%2F?id=1&id=2?", Headers: []string{}}, Identity: Identity{Kind: "anonymous"}, Limits: Limits{MaxRequests: 1}}
}
func testReview() ReviewContextV1 {
	return ReviewContextV1{ReviewVersion: ReviewVersion, ProposalSource: ProposalSource{Kind: "test", Provider: "model", Model: "revision"}, Purpose: "read one path", ExpectedPositiveOutcome: "status observed", ExpectedNegativeOutcome: "request denied", Assumptions: []string{"scope contains path"}, MissingEvidence: []string{"response"}, SupportingEvidence: []Citation{{ArtifactID: domain.NewID(), ArtifactSHA256: strings.Repeat("a", 64), Locator: "line 1"}}, ContradictoryEvidence: []Citation{}}
}
func TestActionHashMutationMatrix(t *testing.T) {
	base := testContract()
	raw, hash, err := base.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeContract(raw, hash); err != nil || decoded.Request.RequestTarget != base.Request.RequestTarget {
		t.Fatalf("decode=%v %v", decoded, err)
	}
	changes := map[string]func(*ActionContractV1){
		"method":                func(a *ActionContractV1) { a.Request.Method = "HEAD" },
		"hostname":              func(a *ActionContractV1) { a.Request.Hostname = "other.test" },
		"port":                  func(a *ActionContractV1) { a.Request.EffectivePort = 8443 },
		"path":                  func(a *ActionContractV1) { a.Request.RequestTarget = "/orders/one?id=1&id=2?" },
		"query order":           func(a *ActionContractV1) { a.Request.RequestTarget = "/orders/%2F?id=2&id=1?" },
		"trailing question":     func(a *ActionContractV1) { a.Request.RequestTarget = "/orders/%2F?id=1&id=2" },
		"escape representation": func(a *ActionContractV1) { a.Request.RequestTarget = "/orders/%2f?id=1&id=2?" },
		"action id":             func(a *ActionContractV1) { a.ActionID = domain.NewID() },
		"program":               func(a *ActionContractV1) { a.Ownership.ProgramID = domain.NewID() },
		"task":                  func(a *ActionContractV1) { a.Ownership.TaskID = domain.NewID() },
		"run":                   func(a *ActionContractV1) { a.Ownership.WorkflowRunID = domain.NewID() },
		"step":                  func(a *ActionContractV1) { a.Ownership.StepRunID = domain.NewID() },
		"attempt":               func(a *ActionContractV1) { a.Ownership.StepAttempt++ },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			a := base
			change(&a)
			_, next, err := a.Freeze()
			if err != nil || next == hash {
				t.Fatalf("hash=%q err=%v", next, err)
			}
		})
	}
	reject := map[string]func(*ActionContractV1){
		"headers":             func(a *ActionContractV1) { a.Request.Headers = []string{"x:y"} },
		"redirects":           func(a *ActionContractV1) { a.Limits.FollowRedirects = true },
		"retries":             func(a *ActionContractV1) { a.Limits.AutomaticRetries = true },
		"request count":       func(a *ActionContractV1) { a.Limits.MaxRequests = 2 },
		"identity":            func(a *ActionContractV1) { a.Identity.Kind = "account" },
		"http":                func(a *ActionContractV1) { a.Request.Scheme = "http" },
		"mixed host":          func(a *ActionContractV1) { a.Request.Hostname = "Example.test" },
		"unicode host":        func(a *ActionContractV1) { a.Request.Hostname = "éxample.test" },
		"fragment":            func(a *ActionContractV1) { a.Request.RequestTarget = "/path#frag" },
		"absolute":            func(a *ActionContractV1) { a.Request.RequestTarget = "https://example.test/" },
		"control":             func(a *ActionContractV1) { a.Request.RequestTarget = "/a\r\n" },
		"escape":              func(a *ActionContractV1) { a.Request.RequestTarget = "/%G0" },
		"backslash":           func(a *ActionContractV1) { a.Request.RequestTarget = "/a\\b" },
		"non-URI punctuation": func(a *ActionContractV1) { a.Request.RequestTarget = "/a|b" },
	}
	for name, change := range reject {
		t.Run(name, func(t *testing.T) {
			a := base
			change(&a)
			if _, _, err := a.Freeze(); err == nil {
				t.Fatal("accepted unsupported action")
			}
		})
	}
	for name, mutation := range map[string][]byte{
		"body":       []byte(strings.TrimSuffix(string(raw), "}") + `,"body":"x"}`),
		"case alias": bytes.Replace(raw, []byte(`"method"`), []byte(`"Method"`), 1),
		"null":       bytes.Replace(raw, []byte(`"headers":[]`), []byte(`"headers":null`), 1),
		"missing":    bytes.Replace(raw, []byte(`,"max_requests":1`), nil, 1),
		"wrong type": bytes.Replace(raw, []byte(`"max_requests":1`), []byte(`"max_requests":"1"`), 1),
		"duplicate":  bytes.Replace(raw, []byte(`"method":"GET"`), []byte(`"method":"GET","method":"HEAD"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			forged := sha256.Sum256(append([]byte("reconductor-exact-action/v1\x00"), mutation...))
			if _, err := DecodeContract(mutation, hex.EncodeToString(forged[:])); err == nil {
				t.Fatal("accepted mutated encoding")
			}
		})
	}
}

func TestReviewHashSeparateAndMutationMatrix(t *testing.T) {
	a := testContract()
	_, actionHash, err := a.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	r := testReview()
	raw, reviewHash, err := r.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReview(raw, reviewHash); err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*ReviewContextV1){
		"purpose":     func(r *ReviewContextV1) { r.Purpose = "other purpose" },
		"positive":    func(r *ReviewContextV1) { r.ExpectedPositiveOutcome = "other outcome" },
		"negative":    func(r *ReviewContextV1) { r.ExpectedNegativeOutcome = "other failure" },
		"assumptions": func(r *ReviewContextV1) { r.Assumptions = []string{"different"} },
		"missing":     func(r *ReviewContextV1) { r.MissingEvidence = []string{"different"} },
		"citation": func(r *ReviewContextV1) {
			r.SupportingEvidence = []Citation{{ArtifactID: r.SupportingEvidence[0].ArtifactID, ArtifactSHA256: r.SupportingEvidence[0].ArtifactSHA256, Locator: "line 2"}}
		},
		"source": func(r *ReviewContextV1) { r.ProposalSource.Model = "other" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			next := r
			change(&next)
			_, digest, err := next.Freeze()
			if err != nil || digest == reviewHash {
				t.Fatalf("hash=%q err=%v", digest, err)
			}
			_, same, err := a.Freeze()
			if err != nil || same != actionHash {
				t.Fatal("review changed action hash")
			}
		})
	}
	r.SupportingEvidence = append(r.SupportingEvidence, r.SupportingEvidence[0])
	if _, _, err := r.Freeze(); err == nil {
		t.Fatal("duplicate citation accepted")
	}
	r = testReview()
	r.Purpose = strings.Repeat("p", 2049)
	if _, _, err := r.Freeze(); err == nil {
		t.Fatal("unbounded prose accepted")
	}
}
