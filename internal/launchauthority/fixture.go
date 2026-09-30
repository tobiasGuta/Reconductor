package launchauthority

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
)

// ActionFixture is an anonymous, non-networked proof input. It is deliberately
// not a transport contract. A future exact contract must replace this decoder
// before any target executor can use the dispatch gate.
type ActionFixture struct {
	Version string `json:"version"`
	Method  string `json:"method"`
	URL     string `json:"url"`
}

const ActionFixtureV1 = "exact-dispatch-fixture/v1"

func DecodeActionFixture(raw json.RawMessage) (ActionFixture, string, error) {
	var fixture ActionFixture
	if len(raw) > 8192 {
		return fixture, "", fmt.Errorf("action fixture exceeds bound")
	}
	_, _, nodes, depth, err := canonicaljson.ParseStrictBounded(raw, 8192)
	if err != nil {
		return fixture, "", err
	}
	if nodes > 32 || depth > 3 {
		return fixture, "", fmt.Errorf("action fixture structure exceeds bound")
	}
	if err := decodeClosed(raw, &fixture); err != nil {
		return fixture, "", err
	}
	if fixture.Version != ActionFixtureV1 || (fixture.Method != "GET" && fixture.Method != "HEAD") {
		return fixture, "", fmt.Errorf("unsupported action fixture")
	}
	u, err := url.Parse(fixture.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(fixture.URL, "\r\n\t ") {
		return fixture, "", fmt.Errorf("invalid fixture target")
	}
	canonical, _, err := canonical(fixture)
	if err != nil {
		return fixture, "", err
	}
	sum := sha256.Sum256(append([]byte("reconductor-exact-dispatch-fixture/v1\x00"), canonical...))
	return fixture, hex.EncodeToString(sum[:]), nil
}
