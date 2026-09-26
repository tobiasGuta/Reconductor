package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/tobiasGuta/Reconductor/internal/boundedjson"
	"github.com/tobiasGuta/Reconductor/internal/canonicaljson"
	"github.com/tobiasGuta/Reconductor/internal/capability"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/strictjsonschema"
)

type bindingMaterializationLimitError struct{ Limit domain.ResultContractLimitV1 }

func (e *bindingMaterializationLimitError) Error() string {
	return fmt.Sprintf("result_contract_limit: selected binding value exceeded %d %s (observed %d)", e.Limit.Limit, e.Limit.Unit, e.Limit.Observed)
}

func resolveBindingValue(ctx context.Context, engine *Engine, programID, workflowRunID domain.ID, consumerStep, sourceStep string, sourceRun domain.StepRun, selector string) (any, *domain.SemanticBindingReferenceV1, error) {
	legacy, envelope, err := decodeStoredResult(sourceRun.Output)
	if err != nil {
		return nil, nil, err
	}
	if envelope == nil {
		if len(legacy) > domain.InlineSemanticJSONMaxBytes {
			return nil, nil, fmt.Errorf("result_contract_legacy_unavailable")
		}
		value, _, _, _, err := canonicaljson.ParseStrict(legacy)
		if err != nil {
			return nil, nil, fmt.Errorf("legacy semantic output is invalid: %w", err)
		}
		if engine != nil && engine.Registry != nil {
			if implementation, ok := engine.Registry.Get(sourceRun.Capability); ok && len(implementation.Manifest().OutputSchema) > 0 {
				schema, _, _, _, schemaErr := canonicaljson.ParseStrict(implementation.Manifest().OutputSchema)
				if schemaErr != nil || strictjsonschema.Validate(schema, value) != nil {
					return nil, nil, fmt.Errorf("legacy semantic output does not match its registered schema")
				}
			}
		}
		selected, err := applySelector(value, strings.Split(selector, "."), false)
		return selected, nil, err
	}
	if envelope.SemanticOutput.Mode != domain.SemanticModeArtifactJSON {
		semantic := envelope.SemanticOutput.InlineJSON
		if envelope.SemanticOutput.Mode == domain.SemanticModeNone {
			semantic = json.RawMessage(`null`)
		}
		value, _, _, _, err := canonicaljson.ParseStrict(semantic)
		if err != nil {
			return nil, nil, err
		}
		selected, err := applySelector(value, strings.Split(selector, "."), false)
		return selected, nil, err
	}
	artifactReference, ok := semanticArtifactReference(*envelope)
	if !ok {
		return nil, nil, fmt.Errorf("semantic_output_unavailable: semantic artifact reference is absent")
	}
	reference := domain.SemanticBindingReferenceV1{
		SchemaID:                 domain.SemanticBindingReferenceSchemaV1,
		Version:                  domain.SemanticBindingReferenceVersionV1,
		SourceProgramID:          programID,
		SourceWorkflowRunID:      workflowRunID,
		SourceStepRunID:          sourceRun.ID,
		SourceActionRequestID:    envelope.ActionRequestID,
		SourceResultOccurrenceID: envelope.ResultOccurrenceID,
		SourceProviderAttemptID:  envelope.ProviderAttemptID,
		SourceArtifactID:         artifactReference.ArtifactID,
		ArtifactStoreID:          artifactReference.ArtifactStoreID,
		StorageKey:               artifactReference.StorageKey,
		Selector:                 selector,
		ContentSHA256:            artifactReference.ContentSHA256,
		ContentSizeBytes:         artifactReference.ContentSizeBytes,
		OutputSchemaSHA256:       envelope.SemanticOutput.OutputSchemaSHA256,
	}
	if err := reference.Validate(); err != nil {
		return nil, nil, fmt.Errorf("semantic_output_unavailable: %w", err)
	}
	if engine == nil || engine.BindingResolver == nil {
		return nil, &reference, fmt.Errorf("semantic_output_unavailable: authoritative artifact resolver is required")
	}
	reader, err := engine.BindingResolver.ResolveSemanticBinding(ctx, domain.SemanticBindingResolutionV1{ConsumerProgramID: programID, ConsumerWorkflowRunID: workflowRunID, ConsumerStepDefinition: consumerStep, SourceStepDefinition: sourceStep, Reference: reference})
	if err != nil {
		return nil, &reference, err
	}
	selected, selectErr := selectSemanticJSON(reader, strings.Split(selector, "."))
	closeErr := reader.Close()
	if selectErr != nil || closeErr != nil {
		return nil, &reference, errors.Join(selectErr, closeErr)
	}
	return selected, &reference, nil
}

func decodeStoredResult(raw json.RawMessage) (json.RawMessage, *domain.ResultEnvelopeV1, error) {
	if len(raw) == 0 {
		return nil, nil, fmt.Errorf("semantic_output_unavailable: source output is absent")
	}
	value, canonical, _, _, err := canonicaljson.ParseStrict(raw)
	if err != nil {
		return nil, nil, err
	}
	if object, ok := value.(map[string]any); ok {
		if version, ok := object["version"].(string); ok && strings.HasPrefix(version, "result-envelope/") {
			if version != domain.ResultEnvelopeVersionV1 {
				return nil, nil, fmt.Errorf("result_contract_version_unsupported")
			}
			envelope, err := domain.DecodeResultEnvelopeV1(canonical)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid result envelope: %w", err)
			}
			return nil, &envelope, nil
		}
	}
	return canonical, nil, nil
}

func semanticArtifactReference(envelope domain.ResultEnvelopeV1) (domain.ResultArtifactRefV1, bool) {
	for _, reference := range envelope.Artifacts {
		if reference.Role == domain.ArtifactRoleSemanticResult && reference.ArtifactID == envelope.SemanticOutput.ArtifactID {
			return reference, true
		}
	}
	return domain.ResultArtifactRefV1{}, false
}

func applySelector(value any, path []string, mapping bool) (any, error) {
	if len(path) == 0 {
		return value, nil
	}
	part := path[0]
	arraySuffix := strings.HasSuffix(part, "[]")
	name := strings.TrimSuffix(part, "[]")
	if items, ok := value.([]any); ok && !arraySuffix {
		selected := make([]any, 0, len(items))
		for _, item := range items {
			if encoded, ok := item.(string); ok {
				parsed, _, _, _, err := canonicaljson.ParseStrict([]byte(encoded))
				if err == nil {
					item = parsed
				}
			}
			candidate, err := applySelector(item, path, true)
			if err == nil {
				selected = append(selected, candidate)
			}
		}
		return selected, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		if mapping {
			return nil, fmt.Errorf("nonparticipating array element")
		}
		return nil, fmt.Errorf("binding continuation through null or scalar")
	}
	child, ok := object[name]
	if !ok {
		if mapping {
			return nil, fmt.Errorf("nonparticipating array element")
		}
		return nil, fmt.Errorf("binding field %s is missing", name)
	}
	if arraySuffix {
		if _, ok := child.([]any); !ok {
			return nil, fmt.Errorf("binding field %s is not an array", name)
		}
	}
	return applySelector(child, path[1:], false)
}

func selectSemanticJSON(reader io.Reader, path []string) (any, error) {
	stream := boundedjson.New(reader, domain.SemanticJSONMaxDepth)
	raw, found, err := stream.Select(path, domain.InlineSemanticJSONMaxBytes)
	if err != nil {
		var limit *boundedjson.LimitError
		if errors.As(err, &limit) {
			unit := domain.LimitBytes
			if limit.Depth {
				unit = domain.LimitDepth
			}
			return nil, &bindingMaterializationLimitError{Limit: domain.ResultContractLimitV1{Subject: domain.LimitBindingSelectedValue, Unit: unit, Limit: uint64(limit.Limit), Observed: uint64(limit.Observed)}}
		}
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("binding selector was not found")
	}
	if err := stream.End(); err != nil {
		return nil, err
	}
	// Materialization/canonical copies only happen AFTER a serialized byte bound.
	value, canonical, nodes, _, err := canonicaljson.ParseStrictBounded(raw, domain.InlineSemanticJSONMaxBytes)
	if err != nil {
		var bound *canonicaljson.EncodingLimitError
		if errors.As(err, &bound) {
			return nil, &bindingMaterializationLimitError{Limit: domain.ResultContractLimitV1{Subject: domain.LimitBindingSelectedValue, Unit: domain.LimitBytes, Limit: uint64(bound.Limit), Observed: uint64(bound.Limit) + 1}}
		}
		return nil, err
	}
	if len(canonical) > domain.InlineSemanticJSONMaxBytes {
		return nil, &bindingMaterializationLimitError{Limit: domain.ResultContractLimitV1{Subject: domain.LimitBindingSelectedValue, Unit: domain.LimitBytes, Limit: domain.InlineSemanticJSONMaxBytes, Observed: uint64(len(canonical))}}
	}
	if nodes > domain.InlineSemanticJSONMaxNodes {
		return nil, &bindingMaterializationLimitError{Limit: domain.ResultContractLimitV1{Subject: domain.LimitBindingSelectedValue, Unit: domain.LimitItems, Limit: domain.InlineSemanticJSONMaxNodes, Observed: nodes}}
	}
	return value, nil
}

func supportsSemanticBindingReferences(manifest capability.Manifest) bool {
	if !manifest.SupportsSemanticBindingReferences || len(manifest.InputSchema) == 0 {
		return false
	}
	var schema any
	if json.Unmarshal(manifest.InputSchema, &schema) != nil {
		return false
	}
	return hasClosedReferenceBranch(schema)
}

func hasClosedReferenceBranch(value any) bool {
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	if branches, ok := object["oneOf"].([]any); ok {
		for _, branch := range branches {
			candidate, ok := branch.(map[string]any)
			if ok && isExactSemanticBindingReferenceBranch(candidate) {
				return true
			}
		}
	}
	for _, child := range object {
		if hasClosedReferenceBranch(child) {
			return true
		}
		if array, ok := child.([]any); ok {
			for _, item := range array {
				if hasClosedReferenceBranch(item) {
					return true
				}
			}
		}
	}
	return false
}

func isExactSemanticBindingReferenceBranch(candidate map[string]any) bool {
	if candidate["type"] != "object" || candidate["additionalProperties"] != false {
		return false
	}
	properties, ok := candidate["properties"].(map[string]any)
	if !ok {
		return false
	}
	fields := []string{"schema_id", "version", "source_program_id", "source_workflow_run_id", "source_step_run_id", "source_action_request_id", "source_result_occurrence_id", "source_provider_attempt_id", "source_artifact_id", "artifact_store_id", "storage_key", "selector", "content_sha256", "content_size_bytes", "output_schema_sha256"}
	if len(properties) != len(fields) {
		return false
	}
	required, ok := candidate["required"].([]any)
	if !ok || len(required) != len(fields) {
		return false
	}
	requiredSet := make(map[string]bool, len(required))
	for _, raw := range required {
		name, ok := raw.(string)
		if !ok {
			return false
		}
		requiredSet[name] = true
	}
	for _, name := range fields {
		if !requiredSet[name] {
			return false
		}
		if _, ok := properties[name].(map[string]any); !ok {
			return false
		}
	}
	schemaID := properties["schema_id"].(map[string]any)
	version := properties["version"].(map[string]any)
	return schemaID["const"] == domain.SemanticBindingReferenceSchemaV1 && version["const"] == domain.SemanticBindingReferenceVersionV1
}
