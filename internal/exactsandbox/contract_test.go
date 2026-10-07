package exactsandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
	"github.com/tobiasGuta/Reconductor/internal/exactexecution"
)

func capsuleFixture(t testing.TB, target string) Capsule {
	t.Helper()
	a := exactaction.ActionContractV1{ContractVersion: exactaction.ContractVersion, ActionID: "A", Ownership: exactaction.Ownership{ProgramID: "P", TaskID: "T", WorkflowRunID: "W", StepRunID: "S", StepAttempt: 1}, Capability: exactaction.Capability{Name: "http.request", SemanticRevision: "v1"}, Request: exactaction.Request{Method: "GET", Scheme: "https", Hostname: "example.test", EffectivePort: 443, RequestTarget: target, Headers: []string{}}, Identity: exactaction.Identity{Kind: "anonymous"}, Limits: exactaction.Limits{MaxRequests: 1}}
	_, h, err := a.Freeze()
	if err != nil {
		t.Fatal(err)
	}
	return Capsule{wire: executionWire{Version: ExecutionVersion, ProviderAttemptID: "X", ActionSHA256: h, AuthorityEpoch: 2, Action: a}}
}
func mustEncode(t testing.TB, c Capsule) EncodedExecution {
	t.Helper()
	e, err := encodeCapsule(c)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func canonicalWire(t testing.TB, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	_, raw, _, _, err = canonicaljson.ParseStrictBounded(raw, MaxExecutionBytes)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func object(t testing.TB, raw []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCapsuleCanonicalRoundtripAndDigest(t *testing.T) {
	for _, target := range []string{"/ordinary", "/item?id=1&id=2", "/item?b=2&a=1", "/item/%2F?x=%2f", "/item?"} {
		t.Run(target, func(t *testing.T) {
			c := capsuleFixture(t, target)
			encoded := mustEncode(t, c)
			sum := sha256.Sum256(append([]byte("reconductor-exact-sandbox-execution/v1\x00"), encoded.Bytes()...))
			if encoded.Digest() != hex.EncodeToString(sum[:]) || encoded.Digest() == c.ActionSHA256() {
				t.Fatal("digest domain or H separation")
			}
			for i := 0; i < 100; i++ {
				e := mustEncode(t, c)
				if !bytes.Equal(e.Bytes(), encoded.Bytes()) || e.Digest() != encoded.Digest() {
					t.Fatal("nondeterministic capsule")
				}
			}
			decoded, err := DecodeExecution(encoded.Bytes(), encoded.Digest())
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Action().Request.RequestTarget != target || decoded.ProviderAttemptID() != c.ProviderAttemptID() || decoded.AuthorityEpoch() != 2 || decoded.ActionSHA256() != c.ActionSHA256() {
				t.Fatal("execution identity changed")
			}
			a := decoded.Action()
			a.Request.Headers = append(a.Request.Headers, "Authorization: injected")
			a.Request.RequestTarget = "/changed"
			if len(decoded.Action().Request.Headers) != 0 || decoded.Action().Request.RequestTarget != target {
				t.Fatal("mutable action leaked")
			}
			b := encoded.Bytes()
			b[0] = '!'
			if encoded.Bytes()[0] != '{' {
				t.Fatal("encoded backing bytes leaked")
			}
		})
	}
	if _, err := FromExecution(exactexecution.Execution{}); !errors.Is(err, ErrProtocol) {
		t.Fatal("zero Execution accepted")
	}
	if _, err := encodeCapsule(Capsule{}); !errors.Is(err, ErrProtocol) {
		t.Fatal("zero Capsule accepted")
	}
}

func TestRunnerInputConstructionBoundary(t *testing.T) {
	if _, ok := reflect.TypeOf(Capsule{}).MethodByName("Encode"); ok {
		t.Fatal("untrusted decoded capsule can construct Runner input")
	}
	input := reflect.TypeOf(EncodedExecution{})
	for i := 0; i < input.NumField(); i++ {
		if input.Field(i).IsExported() {
			t.Fatal("caller can construct nonzero Runner input")
		}
	}
}

func TestCapsuleValidation(t *testing.T) {
	mutations := map[string]func(*executionWire){
		"version":   func(w *executionWire) { w.Version = "exact-sandbox-execution/v2" },
		"missing X": func(w *executionWire) { w.ProviderAttemptID = "" },
		"large X": func(w *executionWire) {
			w.ProviderAttemptID = domain.ID(strings.Repeat("x", MaxProviderAttemptIDBytes+1))
		},
		"hash uppercase": func(w *executionWire) { w.ActionSHA256 = strings.Repeat("A", 64) },
		"hash malformed": func(w *executionWire) { w.ActionSHA256 = strings.Repeat("z", 64) },
		"hash short":     func(w *executionWire) { w.ActionSHA256 = "a" },
		"hash mismatch":  func(w *executionWire) { w.ActionSHA256 = strings.Repeat("a", 64) },
		"epoch":          func(w *executionWire) { w.AuthorityEpoch = -1 },
		"capability":     func(w *executionWire) { w.Action.Capability.Name = "shell" },
		"revision":       func(w *executionWire) { w.Action.Capability.SemanticRevision = "v2" },
		"identity":       func(w *executionWire) { w.Action.Identity.Kind = "credential" },
		"scheme":         func(w *executionWire) { w.Action.Request.Scheme = "http" },
		"method":         func(w *executionWire) { w.Action.Request.Method = "POST" },
		"headers":        func(w *executionWire) { w.Action.Request.Headers = []string{"Authorization: secret"} },
		"requests":       func(w *executionWire) { w.Action.Limits.MaxRequests = 2 },
		"redirects":      func(w *executionWire) { w.Action.Limits.FollowRedirects = true },
		"retry":          func(w *executionWire) { w.Action.Limits.AutomaticRetries = true },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			c := capsuleFixture(t, "/a")
			mutate(&c.wire)
			if _, err := encodeCapsule(c); !errors.Is(err, ErrProtocol) {
				t.Fatal("invalid capsule encoded")
			}
			raw := canonicalWire(t, c.wire)
			if _, err := DecodeExecution(raw, executionDigest(raw)); !errors.Is(err, ErrProtocol) {
				t.Fatal("invalid capsule decoded")
			}
		})
	}
	c := capsuleFixture(t, "/a")
	c.wire.AuthorityEpoch = 0
	if _, err := encodeCapsule(c); err != nil {
		t.Fatal("valid historical zero epoch denied")
	}
	c.wire.Action.Request.Method = "HEAD"
	_, c.wire.ActionSHA256, _ = c.wire.Action.Freeze()
	if _, err := encodeCapsule(c); err != nil {
		t.Fatal("HEAD denied")
	}
	c.wire.ProviderAttemptID = "\xff"
	if _, err := encodeCapsule(c); err == nil {
		t.Fatal("invalid UTF8 host identity encoded")
	}
}

func TestCapsuleClosedSchemaAttacks(t *testing.T) {
	base := mustEncode(t, capsuleFixture(t, "/a")).Bytes()
	for _, field := range []string{"command", "headers", "retry", "network_mode", "deadline", "review_context", "credential", "path", "proxy"} {
		t.Run(field, func(t *testing.T) {
			v := object(t, base)
			v[field] = "injected"
			raw := canonicalWire(t, v)
			if _, err := DecodeExecution(raw, executionDigest(raw)); !errors.Is(err, ErrProtocol) {
				t.Fatal("unknown field accepted")
			}
		})
	}
	for _, field := range []string{"version", "provider_attempt_id", "action_sha256", "authority_epoch", "action"} {
		t.Run("missing "+field, func(t *testing.T) {
			v := object(t, base)
			delete(v, field)
			raw := canonicalWire(t, v)
			if _, err := DecodeExecution(raw, executionDigest(raw)); err == nil {
				t.Fatal("missing field accepted")
			}
		})
	}
	for _, field := range []string{"provider_attempt_id", "action_sha256", "authority_epoch"} {
		t.Run("duplicate "+field, func(t *testing.T) {
			raw := bytes.Replace(base, []byte(`"`+field+`":`), []byte(`"`+field+`":null,"`+field+`":`), 1)
			if _, err := DecodeExecution(raw, executionDigest(raw)); err == nil {
				t.Fatal("duplicate accepted")
			}
		})
	}
	raw := bytes.Replace(base, []byte(`"request":`), []byte(`"request":{},"request":`), 1)
	if _, err := DecodeExecution(raw, executionDigest(raw)); err == nil {
		t.Fatal("duplicate nested request accepted")
	}
	for name, raw := range map[string][]byte{"trailing": append(bytes.Clone(base), []byte(`{}`)...), "whitespace": append([]byte(" "), base...), "deep": []byte(strings.Repeat("[", 10000) + strings.Repeat("]", 10000)), "nodes": []byte("[" + strings.Repeat("0,", MaxExecutionNodes) + "0]"), "utf8": {0xff}, "null": []byte("null")} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeExecution(raw, executionDigest(raw)); err == nil {
				t.Fatal("hostile representation accepted")
			}
		})
	}
	v := object(t, base)
	v["Authority_Epoch"] = v["authority_epoch"]
	delete(v, "authority_epoch")
	raw = canonicalWire(t, v)
	if _, err := DecodeExecution(raw, executionDigest(raw)); err == nil {
		t.Fatal("case alias accepted")
	}
	for _, digest := range []string{"", strings.Repeat("A", 64), strings.Repeat("a", 64)} {
		if _, err := DecodeExecution(base, digest); err == nil {
			t.Fatal("bad expected digest accepted")
		}
	}
}

func TestResultClosedBinding(t *testing.T) {
	s1 := mustEncode(t, capsuleFixture(t, "/one")).Digest()
	s2 := mustEncode(t, capsuleFixture(t, "/two")).Digest()
	for _, completed := range []bool{false, true} {
		raw, err := EncodeResult(s1, completed)
		if err != nil {
			t.Fatal(err)
		}
		r, err := DecodeResult(raw, s1)
		if err != nil || r.Completed != completed {
			t.Fatal("completion mapping")
		}
		if _, err := DecodeResult(raw, s2); !errors.Is(err, ErrProtocol) {
			t.Fatal("cross-execution result accepted")
		}
	}
	base, _ := EncodeResult(s1, true)
	for _, field := range []string{"retry", "next_action", "stdout", "stderr", "body", "metadata", "failure_code"} {
		v := object(t, base)
		v[field] = "untrusted prose"
		raw := canonicalWire(t, v)
		if _, err := DecodeResult(raw, s1); err == nil {
			t.Fatalf("%s accepted", field)
		}
	}
	for _, field := range []string{"version", "capsule_digest", "completed"} {
		v := object(t, base)
		delete(v, field)
		if _, err := DecodeResult(canonicalWire(t, v), s1); err == nil {
			t.Fatalf("missing %s accepted", field)
		}
		v = object(t, base)
		v[field] = nil
		if _, err := DecodeResult(canonicalWire(t, v), s1); err == nil {
			t.Fatalf("null %s accepted", field)
		}
	}
	for _, field := range []string{"capsule_digest", "completed"} {
		raw := bytes.Replace(base, []byte(`"`+field+`":`), []byte(`"`+field+`":null,"`+field+`":`), 1)
		if _, err := DecodeResult(raw, s1); err == nil {
			t.Fatal("duplicate result field accepted")
		}
	}
	v := object(t, base)
	v["version"] = "exact-sandbox-result/v2"
	if _, err := DecodeResult(canonicalWire(t, v), s1); err == nil {
		t.Fatal("unknown result version accepted")
	}
	v = object(t, base)
	v["completed"] = "true"
	if _, err := DecodeResult(canonicalWire(t, v), s1); err == nil {
		t.Fatal("wrong completion type accepted")
	}
	v = object(t, base)
	v["Completed"] = v["completed"]
	delete(v, "completed")
	if _, err := DecodeResult(canonicalWire(t, v), s1); err == nil {
		t.Fatal("case alias accepted")
	}
	for _, raw := range [][]byte{append(bytes.Clone(base), ' '), append(bytes.Clone(base), []byte(`{}`)...), []byte(strings.Repeat("[", 20) + strings.Repeat("]", 20)), []byte(`{"capsule_digest":"` + s1 + `","completed":true,"version":"exact-sandbox-result/v1","x":0}`)} {
		if _, err := DecodeResult(raw, s1); err == nil {
			t.Fatal("malformed result accepted")
		}
	}
	for _, s := range []string{"", strings.Repeat("A", 64), strings.Repeat("z", 64)} {
		if _, err := EncodeResult(s, true); err == nil {
			t.Fatal("bad result digest encoded")
		}
		if _, err := DecodeResult(base, s); err == nil {
			t.Fatal("bad expected digest decoded")
		}
	}
}

func TestSerializedBounds(t *testing.T) {
	for _, limit := range []int{MaxExecutionBytes, MaxResultBytes} {
		for _, n := range []int{limit - 1, limit, limit + 1} {
			raw := []byte(`"` + strings.Repeat("a", n-2) + `"`)
			_, err := parse(raw, limit, MaxExecutionNodes, MaxExecutionDepth)
			if (err != nil) != (n > limit) {
				t.Fatalf("byte gate at %d/%d: %v", n, limit, err)
			}
			if n > limit && !strings.Contains(err.Error(), "byte bound") {
				t.Fatal("oversize parsed before byte gate")
			}
			if _, err := DecodeExecution(raw, executionDigest(raw)); err == nil {
				t.Fatal("scalar capsule accepted")
			}
			if _, err := DecodeResult(raw, strings.Repeat("a", 64)); err == nil {
				t.Fatal("scalar result accepted")
			}
		}
	}
	for _, n := range []int{MaxExecutionNodes - 1, MaxExecutionNodes, MaxExecutionNodes + 1} {
		raw := []byte("[" + strings.Repeat("0,", n-2) + "0]")
		_, err := parse(raw, MaxExecutionBytes, MaxExecutionNodes, MaxExecutionDepth)
		if (err != nil) != (n > MaxExecutionNodes) {
			t.Fatal("node boundary")
		}
	}
	for _, d := range []int{MaxExecutionDepth - 1, MaxExecutionDepth, MaxExecutionDepth + 1} {
		raw := []byte(strings.Repeat("[", d-1) + "0" + strings.Repeat("]", d-1))
		_, err := parse(raw, MaxExecutionBytes, MaxExecutionNodes, MaxExecutionDepth)
		if (err != nil) != (d > MaxExecutionDepth) {
			t.Fatal("depth boundary")
		}
	}
}

func TestEmbeddedActionByteBound(t *testing.T) {
	for _, limit := range []int{exactaction.MaxContractBytes - 1, exactaction.MaxContractBytes, exactaction.MaxContractBytes + 1} {
		c := capsuleFixture(t, "/a")
		raw, _, err := c.wire.Action.Freeze()
		if err != nil {
			t.Fatal(err)
		}
		c.wire.Action.Ownership.TaskID = domain.ID(strings.Repeat("t", limit-len(raw)+1))
		actionBytes, err := json.Marshal(c.wire.Action)
		if err != nil {
			t.Fatal(err)
		}
		_, canonical, _, _, err := canonicaljson.ParseStrictBounded(actionBytes, MaxExecutionBytes)
		if err != nil || len(canonical) != limit {
			t.Fatal("action size fixture")
		}
		sum := sha256.Sum256(append([]byte("reconductor-exact-action/v1\x00"), canonical...))
		c.wire.ActionSHA256 = hex.EncodeToString(sum[:])
		encoded, err := encodeCapsule(c)
		if (err != nil) != (limit > exactaction.MaxContractBytes) {
			t.Fatalf("embedded action size %d: %v", limit, err)
		}
		if err == nil {
			if _, err := DecodeExecution(encoded.Bytes(), encoded.Digest()); err != nil {
				t.Fatal(err)
			}
		}
		// A valid capsule digest cannot hide an oversized embedded A.
		wire := canonicalWire(t, c.wire)
		_, err = DecodeExecution(wire, executionDigest(wire))
		if (err != nil) != (limit > exactaction.MaxContractBytes) {
			t.Fatal("decoded A byte bound")
		}
	}
}

func TestNestedClosedRepresentation(t *testing.T) {
	base := mustEncode(t, capsuleFixture(t, "/a")).Bytes()
	for _, section := range []string{"request", "ownership", "capability", "identity", "limits"} {
		v := object(t, base)
		a := v["action"].(map[string]any)
		part := a[section].(map[string]any)
		part["command"] = "/bin/sh"
		raw := canonicalWire(t, v)
		if _, err := DecodeExecution(raw, executionDigest(raw)); err == nil {
			t.Fatalf("nested %s unknown field accepted", section)
		}
	}
	v := object(t, base)
	v["action"].(map[string]any)["request"].(map[string]any)["headers"] = nil
	raw := canonicalWire(t, v)
	if _, err := DecodeExecution(raw, executionDigest(raw)); err == nil {
		t.Fatal("null headers accepted")
	}
	v = object(t, base)
	delete(v["action"].(map[string]any)["limits"].(map[string]any), "automatic_retries")
	raw = canonicalWire(t, v)
	if _, err := DecodeExecution(raw, executionDigest(raw)); err == nil {
		t.Fatal("omitted false control accepted")
	}
}

func FuzzDecodeExecution(f *testing.F) {
	e := mustEncode(f, capsuleFixture(f, "/item/%2f?a=1&a=2?"))
	f.Add(e.Bytes(), e.Digest())
	f.Add([]byte(`{}`), "")
	f.Add([]byte(strings.Repeat("[", 500)), strings.Repeat("a", 64))
	f.Fuzz(func(t *testing.T, raw []byte, digest string) {
		c, err := DecodeExecution(raw, digest)
		if err != nil {
			return
		}
		encoded, err := encodeCapsule(c)
		if err != nil || !bytes.Equal(encoded.Bytes(), raw) || encoded.Digest() != digest {
			t.Fatal("accepted capsule did not roundtrip")
		}
	})
}
func FuzzDecodeResult(f *testing.F) {
	s := strings.Repeat("a", 64)
	raw, _ := EncodeResult(s, true)
	f.Add([]byte(raw), s)
	f.Add([]byte(`{}`), s)
	f.Add(bytes.Repeat([]byte("x"), MaxResultBytes+1), s)
	f.Fuzz(func(t *testing.T, raw []byte, digest string) {
		r, err := DecodeResult(raw, digest)
		if err != nil {
			return
		}
		encoded, err := EncodeResult(digest, r.Completed)
		if err != nil || !bytes.Equal(encoded, raw) {
			t.Fatal("accepted result did not roundtrip")
		}
	})
}
