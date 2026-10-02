// Package exactsandbox defines execution material across a future isolation
// boundary. It grants no launch authority and implements no isolation backend.
package exactsandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/tobiasGuta/Reconductor/internal/boundedjson"
	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/exactaction"
	"github.com/tobiasGuta/Reconductor/internal/exactexecution"
)

const (
	ExecutionVersion = "exact-sandbox-execution/v1"
	ResultVersion    = "exact-sandbox-result/v1"
	// All byte/node/depth ceilings are inclusive. Closed-schema and semantic
	// validation apply independently, even to representations below the ceiling.
	// A is capped at 32 KiB. Eight KiB of headroom covers the fixed wrapper
	// and a bounded X without admitting general-purpose execution metadata.
	MaxExecutionBytes = 40 * 1024
	// The three-field result is under 160 bytes; 256 leaves a small fixed margin.
	MaxResultBytes            = 256
	MaxExecutionNodes         = 64
	MaxExecutionDepth         = 8
	MaxResultNodes            = 4
	MaxResultDepth            = 2
	MaxProviderAttemptIDBytes = 128
	executionDigestDomain     = "reconductor-exact-sandbox-execution/v1\x00"
)

var ErrProtocol = errors.New("exact sandbox protocol rejected")

// Private wire types keep target construction out of the public host API.
type executionWire struct {
	Version           string                       `json:"version"`
	ProviderAttemptID domain.ID                    `json:"provider_attempt_id"`
	ActionSHA256      string                       `json:"action_sha256"`
	AuthorityEpoch    int64                        `json:"authority_epoch"`
	Action            exactaction.ActionContractV1 `json:"action"`
}
type resultWire struct {
	Version       string `json:"version"`
	CapsuleDigest string `json:"capsule_digest"`
	Completed     bool   `json:"completed"`
}

// Capsule is execution material, never a permit. DecodeExecution validates
// untrusted IPC material but does not authorize its execution. SHA-256 binding
// proves identity relative to the trusted parent's expected digest, not origin.
type Capsule struct{ wire executionWire }

// FromExecution is the sole public constructor of nonzero Runner input.
// Decoding untrusted bytes cannot produce an EncodedExecution.
func FromExecution(e exactexecution.Execution) (EncodedExecution, error) {
	c := Capsule{wire: executionWire{Version: ExecutionVersion, ProviderAttemptID: e.ProviderAttemptID(), ActionSHA256: e.ActionSHA256(), AuthorityEpoch: e.AuthorityEpoch(), Action: e.Action()}}
	return encodeCapsule(c)
}

func (c Capsule) Version() string              { return c.wire.Version }
func (c Capsule) ProviderAttemptID() domain.ID { return c.wire.ProviderAttemptID }
func (c Capsule) ActionSHA256() string         { return c.wire.ActionSHA256 }
func (c Capsule) AuthorityEpoch() int64        { return c.wire.AuthorityEpoch }
func (c Capsule) Action() exactaction.ActionContractV1 {
	a := c.wire.Action
	a.Request.Headers = append([]string{}, a.Request.Headers...)
	return a
}

func (c Capsule) validate() error {
	w := c.wire
	if w.Version != ExecutionVersion || w.ProviderAttemptID == "" || len(w.ProviderAttemptID) > MaxProviderAttemptIDBytes || !utf8.ValidString(string(w.ProviderAttemptID)) || !validDigest(w.ActionSHA256) || w.AuthorityEpoch < 0 {
		return fmt.Errorf("%w: invalid execution identity or version", ErrProtocol)
	}
	_, hash, err := w.Action.Freeze()
	if err != nil || hash != w.ActionSHA256 {
		return fmt.Errorf("%w: invalid frozen action binding", ErrProtocol)
	}
	return nil
}

// EncodedExecution owns immutable canonical bytes and their domain-separated
// digest. Bytes returns a copy. The zero value is not valid protocol input.
type EncodedExecution struct {
	canonical string
	digest    string
}

func (e EncodedExecution) Bytes() []byte  { return []byte(e.canonical) }
func (e EncodedExecution) Digest() string { return e.digest }

func encodeCapsule(c Capsule) (EncodedExecution, error) {
	if err := c.validate(); err != nil {
		return EncodedExecution{}, err
	}
	raw, err := encode(c.wire, MaxExecutionBytes, MaxExecutionNodes, MaxExecutionDepth)
	if err != nil {
		return EncodedExecution{}, err
	}
	return EncodedExecution{canonical: string(raw), digest: executionDigest(raw)}, nil
}

// DecodeExecution requires the separately conveyed expected digest. Neither
// that digest nor a decoded capsule confers authority or permission to retry.
func DecodeExecution(raw []byte, expectedDigest string) (Capsule, error) {
	var wire executionWire
	if err := decode(raw, MaxExecutionBytes, MaxExecutionNodes, MaxExecutionDepth, &wire); err != nil {
		return Capsule{}, err
	}
	if !validDigest(expectedDigest) || executionDigest(raw) != expectedDigest {
		return Capsule{}, fmt.Errorf("%w: capsule digest mismatch", ErrProtocol)
	}
	c := Capsule{wire: wire}
	if err := c.validate(); err != nil {
		return Capsule{}, err
	}
	return c, nil
}

// EncodedResult is untrusted child output. A future backend must bound IPC reads
// to MaxResultBytes; DecodeResult checks the bound before parsing or copying.
type EncodedResult []byte

// EncodeResult exposes only protocol completion, with no failure prose or retry
// request. It is intended for the fixed future runtime implementing this wire.
func EncodeResult(capsuleDigest string, completed bool) (EncodedResult, error) {
	if !validDigest(capsuleDigest) {
		return nil, fmt.Errorf("%w: invalid result digest", ErrProtocol)
	}
	return encode(resultWire{Version: ResultVersion, CapsuleDigest: capsuleDigest, Completed: completed}, MaxResultBytes, MaxResultNodes, MaxResultDepth)
}

func DecodeResult(raw EncodedResult, expectedDigest string) (exactexecution.Result, error) {
	var wire resultWire
	if err := decode(raw, MaxResultBytes, MaxResultNodes, MaxResultDepth, &wire); err != nil {
		return exactexecution.Result{}, err
	}
	if wire.Version != ResultVersion || !validDigest(expectedDigest) || !validDigest(wire.CapsuleDigest) || wire.CapsuleDigest != expectedDigest {
		return exactexecution.Result{}, fmt.Errorf("%w: invalid result version or binding", ErrProtocol)
	}
	return exactexecution.Result{Completed: wire.Completed}, nil
}

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range s {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}
func executionDigest(raw []byte) string {
	h := sha256.New()
	h.Write([]byte(executionDigestDomain))
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

func parse(raw []byte, maxBytes int, maxNodes, maxDepth uint64) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxBytes {
		return nil, fmt.Errorf("%w: serialized byte bound", ErrProtocol)
	}
	// Reject deep hostile input before the canonical parser's recursive walk.
	stream := boundedjson.New(bytes.NewReader(raw), int(maxDepth))
	if err := stream.Skip(); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON structure", ErrProtocol)
	}
	if err := stream.End(); err != nil {
		return nil, fmt.Errorf("%w: trailing JSON", ErrProtocol)
	}
	_, canonical, nodes, depth, err := canonicaljson.ParseStrictBounded(raw, maxBytes)
	if err != nil || nodes > maxNodes || depth > maxDepth {
		return nil, fmt.Errorf("%w: invalid or unbounded canonical JSON", ErrProtocol)
	}
	return canonical, nil
}
func encode(value any, maxBytes int, maxNodes, maxDepth uint64) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid typed value", ErrProtocol)
	}
	return parse(raw, maxBytes, maxNodes, maxDepth)
}
func decode(raw []byte, maxBytes int, maxNodes, maxDepth uint64, destination any) error {
	canonical, err := parse(raw, maxBytes, maxNodes, maxDepth)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, canonical) {
		return fmt.Errorf("%w: noncanonical JSON", ErrProtocol)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(destination); err != nil {
		return fmt.Errorf("%w: invalid closed schema", ErrProtocol)
	}
	// Require every field, its exact spelling/type, and no null substitutes. This
	// also rejects encoding/json's case-insensitive struct-field aliases.
	reencoded, err := encode(destination, maxBytes, maxNodes, maxDepth)
	if err != nil || !bytes.Equal(raw, reencoded) {
		return fmt.Errorf("%w: closed representation mismatch", ErrProtocol)
	}
	return nil
}
