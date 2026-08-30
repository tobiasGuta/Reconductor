package workflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/domain"
)

const (
	TemplateDescriptorSchemaVersion = 1
	SupportedMaterializerRevision   = "web-recon/v1"
)

var (
	ErrWorkflowTemplateIdentityConflict   = errors.New("workflow template immutable identity conflicts")
	ErrWorkflowTemplateDefinitionConflict = errors.New("workflow template immutable definition conflicts")
	ErrWorkflowRunAlreadyActive           = errors.New("task already has an active workflow run")
	ErrWorkflowRunLineageConflict         = errors.New("task has conflicting active workflow run lineage")
	ErrTaskWorkflowTemplateUnavailable    = errors.New("task workflow template is unavailable")
	ErrWorkflowResumeUnavailable          = errors.New("workflow resume is unavailable")
	ErrWorkflowCheckpointUnavailable      = errors.New("workflow checkpoint is unavailable")
	ErrWorkflowCheckpointConflict         = errors.New("workflow checkpoint conflicts with database state")
	ErrEffectiveStepInputConflict         = errors.New("effective step input conflicts with persisted input")
	ErrStepAttemptOwnershipLost           = errors.New("step attempt ownership was not obtained")
	ErrWorkflowLifecycleConflict          = errors.New("workflow lifecycle conflicts with database state")
)

type StepAttemptOwnershipError struct {
	StepRunID            domain.ID
	RequestedAttempt     int
	AuthoritativeAttempt int
}

func (e *StepAttemptOwnershipError) Error() string {
	return fmt.Sprintf("%s: StepRun %s requested attempt %d; authoritative attempt is %d", ErrStepAttemptOwnershipLost, e.StepRunID, e.RequestedAttempt, e.AuthoritativeAttempt)
}

func (e *StepAttemptOwnershipError) Unwrap() error { return ErrStepAttemptOwnershipLost }

func (e *StepAttemptOwnershipError) Is(target error) bool {
	return target == ErrStepAttemptOwnershipLost || target == ErrEffectiveStepInputConflict
}

type TemplateDescriptor struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Materializer  string `json:"materializer"`
}

type Template struct {
	ID                        domain.ID
	Name                      string
	Version                   string
	Description               string
	Materializer              string
	DefaultPolicyRequirements json.RawMessage
	CreatedAt                 time.Time
}

func (t Template) Descriptor() (json.RawMessage, error) {
	if t.Materializer != SupportedMaterializerRevision {
		return nil, fmt.Errorf("unsupported workflow template materializer revision %q", t.Materializer)
	}
	raw, err := json.Marshal(TemplateDescriptor{SchemaVersion: TemplateDescriptorSchemaVersion, Kind: "built-in", Materializer: t.Materializer})
	if err != nil {
		return nil, err
	}
	canonical, err := canonicaljson.Marshal(json.RawMessage(raw))
	return json.RawMessage(canonical), err
}

func DecodeTemplateDescriptor(raw json.RawMessage) (TemplateDescriptor, error) {
	var descriptor TemplateDescriptor
	if err := decodeStrictJSON(raw, &descriptor); err != nil {
		return TemplateDescriptor{}, fmt.Errorf("invalid workflow template descriptor: %w", err)
	}
	if descriptor.SchemaVersion != TemplateDescriptorSchemaVersion || descriptor.Kind != "built-in" || descriptor.Materializer != SupportedMaterializerRevision {
		return TemplateDescriptor{}, fmt.Errorf("unsupported workflow template descriptor")
	}
	return descriptor, nil
}

func Materialize(definition Definition) (json.RawMessage, string, error) {
	raw, err := json.Marshal(definition)
	if err != nil {
		return nil, "", fmt.Errorf("marshal workflow materialization: %w", err)
	}
	canonical, err := canonicaljson.Marshal(json.RawMessage(raw))
	if err != nil {
		return nil, "", fmt.Errorf("canonicalize workflow materialization: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return json.RawMessage(canonical), hex.EncodeToString(sum[:]), nil
}

func VerifyMaterialization(raw json.RawMessage, digest string) (Definition, error) {
	var definition Definition
	if len(raw) == 0 || digest == "" {
		return definition, fmt.Errorf("%w: materialization is incomplete", ErrWorkflowResumeUnavailable)
	}
	canonical, err := canonicaljson.Marshal(raw)
	if err != nil {
		return definition, fmt.Errorf("%w: %v", ErrWorkflowCheckpointConflict, err)
	}
	sum := sha256.Sum256(canonical)
	if hex.EncodeToString(sum[:]) != digest {
		return definition, fmt.Errorf("%w: materialization digest mismatch", ErrWorkflowCheckpointConflict)
	}
	if err := decodeStrictJSON(canonical, &definition); err != nil {
		return Definition{}, fmt.Errorf("%w: materialized definition is invalid", ErrWorkflowCheckpointConflict)
	}
	if definition.Materializer != SupportedMaterializerRevision {
		return Definition{}, fmt.Errorf("%w: unsupported materializer revision %q", ErrWorkflowCheckpointConflict, definition.Materializer)
	}
	return definition, nil
}

func decodeStrictJSON(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

type RunLineageError struct {
	Cause  error
	TaskID domain.ID
	RunID  domain.ID
	Detail string
}

func (e *RunLineageError) Error() string {
	message := e.Cause.Error()
	if e.TaskID != "" {
		message += " for task " + string(e.TaskID)
	}
	if e.RunID != "" {
		message += "; existing run " + string(e.RunID)
	}
	if e.Detail != "" {
		message += ": " + e.Detail
	}
	return message
}

func (e *RunLineageError) Unwrap() error { return e.Cause }
