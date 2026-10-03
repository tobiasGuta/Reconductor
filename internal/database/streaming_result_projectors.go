package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tobiasGuta/Reconductor/internal/artifact"
	"github.com/tobiasGuta/Reconductor/internal/boundedjson"
	"github.com/tobiasGuta/Reconductor/internal/changes"
	"github.com/tobiasGuta/Reconductor/internal/domain"
	"github.com/tobiasGuta/Reconductor/internal/normalize"
	"github.com/tobiasGuta/Reconductor/internal/provideroutput"
)

type ProjectionContractLimitError struct{ Limit domain.ResultContractLimitV1 }

func (e *ProjectionContractLimitError) Error() string {
	return fmt.Sprintf("result_contract_limit: projection item exceeded %d %s (observed %d)", e.Limit.Limit, e.Limit.Unit, e.Limit.Observed)
}
func (e *ProjectionContractLimitError) ResultContractLimit() domain.ResultContractLimitV1 {
	return e.Limit
}

const projectionItemMaxBytes = domain.ResultEnvelopeMaxBytes

var resultProjectorRegistry = map[string][]string{
	"discover.subdomains/v2":   {"asset-observation/v1", "target-decision-audit/v1"},
	"resolve.dns/v3":           {"asset-observation/v1", "target-decision-audit/v1"},
	"scan.ports/v2":            {"asset-observation/v1", "target-decision-audit/v1"},
	"probe.http/v4":            {"asset-observation/v1", "probe-http-source-lineage/v1", "target-decision-audit/v1"},
	"crawl.web/v2":             {"asset-observation/v1", "target-decision-audit/v1"},
	"discover.archive_urls/v2": {"asset-observation/v1", "target-decision-audit/v1"},
	"scan.nuclei/v2":           {"nuclei-candidate/v1", "target-decision-audit/v1"},
	"targeting.prepare/v2":     {"targeting-prepare-filter-audit/v1"},
	"compare.assets/v2":        {},
	"classify.endpoint/v5":     {"endpoint/v1"},
	"report.changes/v3":        {"report-change/v1"},
}

func runStreamingResultProjectors(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, tool domain.ToolRun, envelope domain.ResultEnvelopeV1, source artifact.ReplayableSource, artifacts []domain.Artifact, acceptedEventID domain.ID) error {
	projectors, ok := resultProjectorRegistry[envelope.CapabilityName+"/v"+envelope.CapabilityVersion]
	if !ok {
		return fmt.Errorf("no closed result projector mapping for %s v%s", envelope.CapabilityName, envelope.CapabilityVersion)
	}
	for _, projector := range projectors {
		var err error
		switch projector {
		case "asset-observation/v1":
			err = streamAssetObservations(ctx, tx, programID, step, tool, source, artifacts, acceptedEventID)
		case "probe-http-source-lineage/v1":
			err = streamProbeHTTPSourceLineage(ctx, tx, programID, step, tool, envelope, source, artifacts, acceptedEventID)
		case "target-decision-audit/v1":
			err = streamTargetDecisionAudit(ctx, tx, programID, step, tool, source, true)
		case "targeting-prepare-filter-audit/v1":
			err = streamTargetDecisionAudit(ctx, tx, programID, step, tool, source, false)
		case "nuclei-candidate/v1":
			err = streamNucleiCandidates(ctx, tx, programID, step, source, artifacts)
		case "endpoint/v1":
			err = streamEndpoints(ctx, tx, programID, step, source)
		case "report-change/v1":
			err = streamReportChanges(ctx, tx, programID, step, source)
		default:
			err = fmt.Errorf("unknown closed result projector %q", projector)
		}
		if err != nil {
			return fmt.Errorf("project %s: %w", projector, err)
		}
	}
	return nil
}

func openProjectionSource(source artifact.ReplayableSource) (io.ReadCloser, error) {
	if source == nil {
		return nil, fmt.Errorf("semantic projection source is absent")
	}
	return source.Open()
}

func forEachTopLevelArray(source artifact.ReplayableSource, field string, visit func(int, json.RawMessage) error) (found bool, count int, returnedErr error) {
	reader, err := openProjectionSource(source)
	if err != nil {
		return false, 0, err
	}
	defer func() { returnedErr = errors.Join(returnedErr, reader.Close()) }()
	stream := boundedjson.New(reader, domain.SemanticJSONMaxDepth)
	if err := stream.Take('{'); err != nil {
		return false, 0, err
	}
	first := true
	for {
		b, err := stream.Peek()
		if err != nil {
			return found, count, err
		}
		if b == '}' {
			if err := stream.Take('}'); err != nil {
				return found, count, err
			}
			break
		}
		if !first {
			if err := stream.Take(','); err != nil {
				return found, count, err
			}
		}
		first = false
		name, complete, err := stream.Key(projectionItemMaxBytes)
		if err != nil {
			return found, count, err
		}
		if err := stream.Take(':'); err != nil {
			return found, count, err
		}
		if !complete || name != field {
			if err := stream.Skip(); err != nil {
				return found, count, projectionStreamError(err)
			}
			continue
		}
		if found {
			return found, count, fmt.Errorf("duplicate projection field")
		}
		found = true
		count, err = stream.Array(projectionItemMaxBytes, visit)
		if err != nil {
			return found, count, projectionStreamError(err)
		}
	}
	return found, count, stream.End()
}

func projectionStreamError(err error) error {
	var limit *boundedjson.LimitError
	if errors.As(err, &limit) {
		unit := domain.LimitBytes
		if limit.Depth {
			unit = domain.LimitDepth
		}
		return &ProjectionContractLimitError{Limit: domain.ResultContractLimitV1{Subject: domain.LimitProjectionItem, Unit: unit, Limit: uint64(limit.Limit), Observed: uint64(limit.Observed)}}
	}
	return err
}

func checkProjectionItem(raw json.RawMessage) error {
	if len(raw) > projectionItemMaxBytes {
		return &ProjectionContractLimitError{Limit: domain.ResultContractLimitV1{Subject: domain.LimitProjectionItem, Unit: domain.LimitBytes, Limit: projectionItemMaxBytes, Observed: uint64(len(raw))}}
	}
	return nil
}

func checkProjectionParameter(value []byte) error {
	if len(value) > projectionItemMaxBytes {
		return &ProjectionContractLimitError{Limit: domain.ResultContractLimitV1{Subject: domain.LimitProjectionItem, Unit: domain.LimitBytes, Limit: projectionItemMaxBytes, Observed: uint64(len(value))}}
	}
	return nil
}

func streamAssetObservations(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, tool domain.ToolRun, source artifact.ReplayableSource, artifacts []domain.Artifact, acceptedEventID domain.ID) error {
	assetType := map[string]string{"discover.subdomains": "subdomain", "resolve.dns": "subdomain", "scan.ports": "network_service", "probe.http": "http_service", "crawl.web": "url", "discover.archive_urls": "url"}[step.Capability]
	if assetType == "" {
		return fmt.Errorf("asset observation projector is not valid for %s", step.Capability)
	}
	visitRecord := func(_ int, raw json.RawMessage) error {
		value := extractValue(string(raw))
		if value == "" {
			return nil
		}
		if err := checkProjectionParameter([]byte(value)); err != nil {
			return err
		}
		assetID := domain.NewID()
		if err := tx.QueryRow(ctx, `INSERT INTO assets(id,program_id,type,canonical_value) VALUES($1,$2,$3,$4) ON CONFLICT(program_id,type,canonical_value) DO UPDATE SET updated_at=now() RETURNING id`, assetID, programID, assetType, value).Scan(&assetID); err != nil {
			return err
		}
		observationID := domain.NewID()
		if err := tx.QueryRow(ctx, `INSERT INTO asset_observations(id,asset_id,workflow_run_id,source_capability,observed_value,metadata,first_seen_at,observed_at,confidence,evidence_artifact_ids) VALUES($1,$2,$3,$4,$5,$6,now(),now(),$7,$8) ON CONFLICT(asset_id,workflow_run_id,source_capability,observed_value) DO UPDATE SET metadata=EXCLUDED.metadata,observed_at=EXCLUDED.observed_at,evidence_artifact_ids=EXCLUDED.evidence_artifact_ids RETURNING id`, observationID, assetID, step.WorkflowRunID, step.Capability, value, raw, 1.0, artifactStrings(artifacts)).Scan(&observationID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO asset_observation_emissions(program_id,asset_observation_id,provider_result_accepted_event_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, programID, observationID, acceptedEventID)
		return err
	}
	found, count, err := forEachTopLevelArray(source, "authorized_records", visitRecord)
	if err != nil {
		return err
	}
	if found && count > 0 {
		return nil
	}
	_, _, err = forEachTopLevelArray(source, "lines", func(_ int, raw json.RawMessage) error {
		var line string
		if err := json.Unmarshal(raw, &line); err != nil {
			return err
		}
		encoded, err := json.Marshal(map[string]string{"value": line})
		if err != nil {
			return err
		}
		return visitRecord(0, encoded)
	})
	return err
}

func streamTargetDecisionAudit(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, tool domain.ToolRun, source artifact.ReplayableSource, includeAccepted bool) error {
	if includeAccepted {
		_, _, err := forEachTopLevelArray(source, "authorized", func(_ int, raw json.RawMessage) error {
			var target string
			if err := json.Unmarshal(raw, &target); err != nil {
				return err
			}
			details, _ := json.Marshal(map[string]string{"target": target})
			if err := checkAuditProjection(details); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,workflow_run_id,step_run_id,tool_run_id,capability,provider,safe_message,details) VALUES($1,'target_accepted','targeting','worker',$2,$3,$4,$5,$6,$7,'target accepted',$8)`, domain.NewID(), programID, step.WorkflowRunID, step.ID, tool.ID, step.Capability, tool.Provider, details)
			return err
		})
		if err != nil {
			return err
		}
	}
	_, _, err := forEachTopLevelArray(source, "filtered", func(_ int, raw json.RawMessage) error {
		if err := checkAuditProjection(raw); err != nil {
			return err
		}
		var item struct {
			Target string `json:"target"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			return err
		}
		eventType := "target_filtered"
		switch item.Reason {
		case "matched_exclusion":
			eventType = "exclusion_matched"
		case "protocol_not_authorized", "port_not_authorized":
			eventType = "protocol_or_port_rejected"
		}
		_, err := tx.Exec(ctx, `INSERT INTO audit_events(id,event_type,component,actor,program_id,workflow_run_id,step_run_id,tool_run_id,capability,provider,safe_message,details) VALUES($1,$2,'targeting','worker',$3,$4,$5,$6,$7,$8,'target filtered',$9)`, domain.NewID(), eventType, programID, step.WorkflowRunID, step.ID, tool.ID, step.Capability, tool.Provider, raw)
		return err
	})
	return err
}

func streamNucleiCandidates(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, source artifact.ReplayableSource, artifacts []domain.Artifact) error {
	_, _, err := forEachTopLevelArray(source, "lines", func(_ int, raw json.RawMessage) error {
		var line string
		if err := json.Unmarshal(raw, &line); err != nil {
			return err
		}
		if err := checkProjectionParameter([]byte(line)); err != nil {
			return err
		}
		var match map[string]any
		if json.Unmarshal([]byte(line), &match) != nil {
			return nil
		}
		templateID := stringField(match, "template-id", "templateID", "template")
		target := stringField(match, "matched-at", "matched", "host", "url")
		if templateID == "" || target == "" {
			return nil
		}
		name, severity := "Nuclei scanner match", "unknown"
		if info, ok := match["info"].(map[string]any); ok {
			name, severity = stringField(info, "name"), stringField(info, "severity")
		}
		assetID := domain.NewID()
		if err := tx.QueryRow(ctx, `INSERT INTO assets(id,program_id,type,canonical_value) VALUES($1,$2,'url',$3) ON CONFLICT(program_id,type,canonical_value) DO UPDATE SET updated_at=now() RETURNING id`, assetID, programID, target).Scan(&assetID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO candidate_findings(id,task_id,workflow_run_id,target_asset_id,source_capability,template_id,claimed_vulnerability,severity,evidence_artifact_ids,detection_confidence,status) SELECT $1,wr.task_id,$2,$3,$4,$5,$6,$7,$8,$9,'new' FROM workflow_runs wr WHERE wr.id=$2 ON CONFLICT(workflow_run_id,target_asset_id,template_id) DO UPDATE SET evidence_artifact_ids=EXCLUDED.evidence_artifact_ids,updated_at=now()`, domain.NewID(), step.WorkflowRunID, assetID, step.Capability, templateID, name, severity, artifactStrings(artifacts), 0.7); err != nil {
			return err
		}
		if item, ok := changes.CandidateFromLine(line, artifactIDs(artifacts), time.Now().UTC()); ok {
			return persistChangeItems(ctx, tx, programID, step.WorkflowRunID, nil, []changes.Item{item})
		}
		return nil
	})
	return err
}

func streamEndpoints(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, source artifact.ReplayableSource) error {
	if step.CompletedAt == nil || step.CompletedAt.IsZero() {
		return fmt.Errorf("classify.endpoint successful StepRun completion time is required")
	}
	found, _, err := forEachTopLevelArray(source, "endpoints", func(index int, raw json.RawMessage) error {
		var serialized normalize.EndpointKey
		if err := json.Unmarshal(raw, &serialized); err != nil {
			return fmt.Errorf("decode endpoint %d: %w", index, err)
		}
		if strings.TrimSpace(serialized.ExactURL) == "" || strings.TrimSpace(serialized.RouteSignature) == "" || strings.TrimSpace(serialized.Method) == "" || strings.TrimSpace(serialized.Digest) == "" || serialized.QueryParameters == nil {
			return fmt.Errorf("endpoint %d is structurally incomplete", index)
		}
		canonical, origin, err := normalize.CanonicalEndpoint(serialized.ExactURL, serialized.Method, serialized.ContentType)
		if err != nil || canonical.ExactURL != serialized.ExactURL || canonical.RouteSignature != serialized.RouteSignature || canonical.Method != serialized.Method || canonical.ContentType != serialized.ContentType || !slices.Equal(canonical.QueryParameters, serialized.QueryParameters) || canonical.Digest != serialized.Digest {
			return fmt.Errorf("endpoint %d does not match canonical identity", index)
		}
		params, _ := json.Marshal(canonical.QueryParameters)
		_, err = tx.Exec(ctx, `INSERT INTO endpoints(id,program_id,exact_url,route_signature,method,content_type,parameter_schema,origin_scheme,origin_host,origin_effective_port,first_seen,last_seen) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$11) ON CONFLICT(program_id,origin_scheme,origin_host,origin_effective_port,route_signature,method,content_type,parameter_schema) WHERE origin_scheme IS NOT NULL AND origin_host IS NOT NULL AND origin_effective_port IS NOT NULL DO UPDATE SET exact_url=LEAST(endpoints.exact_url COLLATE "C",EXCLUDED.exact_url COLLATE "C"),first_seen=LEAST(endpoints.first_seen,EXCLUDED.first_seen),last_seen=GREATEST(endpoints.last_seen,EXCLUDED.last_seen)`, domain.NewID(), programID, canonical.ExactURL, canonical.RouteSignature, canonical.Method, canonical.ContentType, string(params), origin.Scheme, origin.Host, origin.EffectivePort, step.CompletedAt.UTC())
		return err
	})
	if err == nil && !found {
		return fmt.Errorf("classify.endpoint result requires endpoints")
	}
	return err
}

func streamReportChanges(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, source artifact.ReplayableSource) error {
	observedAt := time.Now().UTC()
	if step.CompletedAt != nil && !step.CompletedAt.IsZero() {
		observedAt = step.CompletedAt.UTC()
	}
	for _, field := range []string{"changes", "endpoints", "candidate_matches"} {
		found, _, err := forEachTopLevelArray(source, field, func(_ int, raw json.RawMessage) error {
			item, ok, err := changes.FromReportItem(field, raw, observedAt)
			if err != nil || !ok {
				return err
			}
			return persistChangeItems(ctx, tx, programID, step.WorkflowRunID, nil, []changes.Item{item})
		})
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("report.changes result requires %s", field)
		}
	}
	return nil
}

func streamProbeHTTPSourceLineage(ctx context.Context, tx pgx.Tx, programID domain.ID, step domain.StepRun, tool domain.ToolRun, envelope domain.ResultEnvelopeV1, source artifact.ReplayableSource, artifacts []domain.Artifact, acceptedEventID domain.ID) error {
	normalizedID, err := normalizedResultArtifactID(artifacts)
	if err != nil {
		return err
	}
	found, _, err := forEachTopLevelArray(source, "authorized_source_records", func(_ int, raw json.RawMessage) error {
		var sourceRecord normalize.AuthorizedSourceRecord
		if err := json.Unmarshal(raw, &sourceRecord); err != nil {
			return err
		}
		if sourceRecord.ProviderAttemptID != string(envelope.ProviderAttemptID) || sourceRecord.IdentityNamespace != normalize.HTTPURIResourceNamespace || sourceRecord.DerivationVersion != normalize.HTTPResourceDerivationV1 || sourceRecord.AuthorizedRecordIndex < 0 {
			return fmt.Errorf("probe HTTP source lineage contradicts provider result")
		}
		recordRaw, ok, err := topLevelArrayItem(source, "authorized_records", sourceRecord.AuthorizedRecordIndex)
		if err != nil || !ok {
			return fmt.Errorf("probe HTTP source record index is unavailable")
		}
		var record provideroutput.Record
		decoder := json.NewDecoder(bytes.NewReader(recordRaw))
		decoder.UseNumber()
		if err := decoder.Decode(&record); err != nil {
			return err
		}
		material, err := normalize.CanonicalRecordJSON(record)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(material)
		if hex.EncodeToString(sum[:]) != sourceRecord.RecordDigest {
			return fmt.Errorf("probe HTTP source record digest mismatch")
		}
		semantics := normalize.RequestSemantics{Method: sourceRecord.RequestMethod, ContentType: sourceRecord.RequestContentType}
		locator, err := normalize.SourceLocator(string(programID), normalize.HTTPURIResourceNamespace, string(envelope.ProviderAttemptID), material, semantics)
		if err != nil || locator != sourceRecord.SourceLocator {
			return fmt.Errorf("probe HTTP source locator mismatch")
		}
		resource, err := normalize.ConcreteHTTPResource(record.Target)
		if err != nil {
			return err
		}
		resourceID := domain.NewID()
		if err := tx.QueryRow(ctx, `INSERT INTO canonical_concrete_http_resources(id,program_id,identity_namespace,scheme,host,effective_port,concrete_escaped_path,canonical_query) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(program_id,identity_namespace,scheme,host,effective_port,concrete_escaped_path,canonical_query) DO UPDATE SET id=canonical_concrete_http_resources.id RETURNING id`, resourceID, programID, resource.IdentityNamespace, resource.Scheme, resource.Host, resource.EffectivePort, resource.ConcreteEscapedPath, resource.CanonicalQuery).Scan(&resourceID); err != nil {
			return err
		}
		var observationID domain.ID
		if err := tx.QueryRow(ctx, `SELECT observation.id FROM asset_observations observation JOIN assets asset ON asset.id=observation.asset_id JOIN asset_observation_emissions emission ON emission.asset_observation_id=observation.id WHERE asset.program_id=$1 AND asset.type='http_service' AND asset.canonical_value=$2 AND observation.observed_value=$2 AND observation.workflow_run_id=$3 AND observation.source_capability='probe.http' AND emission.program_id=$1 AND emission.provider_result_accepted_event_id=$4 FOR SHARE OF observation,asset,emission`, programID, record.Target, step.WorkflowRunID, acceptedEventID).Scan(&observationID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO probe_http_source_records(source_locator,program_id,concrete_http_resource_id,asset_observation_id,provider_result_accepted_event_id,provider_attempt_id,normalized_result_artifact_id,authorized_record_index,record_digest,request_method_state,request_method_value,request_content_type_state,request_content_type_value,identity_namespace,derivation_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, sourceRecord.SourceLocator, programID, resourceID, observationID, acceptedEventID, sourceRecord.ProviderAttemptID, normalizedID, sourceRecord.AuthorizedRecordIndex, sourceRecord.RecordDigest, sourceRecord.RequestMethod.State, nullableSourceValue(sourceRecord.RequestMethod), sourceRecord.RequestContentType.State, nullableSourceValue(sourceRecord.RequestContentType), sourceRecord.IdentityNamespace, sourceRecord.DerivationVersion)
		return err
	})
	if err == nil && !found {
		return fmt.Errorf("probe HTTP source lineage collection is absent")
	}
	_ = tool
	return err
}

func topLevelArrayItem(source artifact.ReplayableSource, field string, wanted int) (json.RawMessage, bool, error) {
	var selected json.RawMessage
	found, _, err := forEachTopLevelArray(source, field, func(index int, raw json.RawMessage) error {
		if index == wanted {
			selected = append(json.RawMessage(nil), raw...)
		}
		return nil
	})
	return selected, found && selected != nil, err
}

func artifactIDs(items []domain.Artifact) []domain.ID {
	out := make([]domain.ID, 0, len(items))
	for _, item := range items {
		out = append(out, item.ID)
	}
	return out
}
