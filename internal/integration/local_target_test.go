package integration

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/findings"
)

func TestLocalOpenRedirectVerification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	}))
	defer srv.Close()
	client := srv.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	target := srv.URL + "/?next=" + url.QueryEscape("https://verification.invalid/proof")
	resp, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	v := findings.Verify("open-redirect", findings.VerificationInput{URL: target, StatusCode: resp.StatusCode, Headers: resp.Header, VerificationOrigin: "https://verification.invalid"})
	if v.Verdict != findings.VerdictManual || v.EvidenceVerdict != findings.EvidenceObserved || v.ImpactVerdict != findings.ImpactUnreviewed {
		t.Fatalf("verification=%#v", v)
	}
}
