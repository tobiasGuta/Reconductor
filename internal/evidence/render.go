package evidence

import (
	"bytes"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

const TerminalContentMaxBytes = 65_536

type RenderReport struct {
	DisplayComplete     bool
	RenderedContentSize int
}

// RenderVerified writes only content already released by Service.Read. The
// content bound is applied after escaping and line-prefix expansion.
func RenderVerified(w io.Writer, verified Verified) (RenderReport, error) {
	rendered, complete := renderContent(verified.Content, TerminalContentMaxBytes)
	status := "shortened"
	if complete {
		status = "complete"
	}

	var output bytes.Buffer
	metadata := verified.Metadata
	writeField := func(name, value string) {
		fmt.Fprintf(&output, "%s: %s\n", name, terminalSafeField(value))
	}
	writeField("artifact_id", string(metadata.ArtifactID))
	writeField("workflow_run_id", string(metadata.WorkflowRunID))
	writeField("step_definition_id", metadata.StepDefinitionID)
	writeField("step_run_id", string(metadata.StepRunID))
	writeField("capability", metadata.CapabilityName)
	writeField("capability_version", metadata.CapabilityVersion)
	writeField("provider", metadata.ProviderName)
	writeField("tool_run_id", string(metadata.ToolRunID))
	writeField("provider_attempt_id", string(metadata.ProviderAttemptID))
	writeField("result_occurrence_id", string(metadata.ResultOccurrenceID))
	writeField("role", string(metadata.Role))
	writeField("artifact_type", metadata.ArtifactType)
	writeField("content_type", metadata.ContentType)
	fmt.Fprintf(&output, "stored_size_bytes: %d\n", metadata.ContentSizeBytes)
	writeField("expected_sha256", metadata.ContentSHA256)
	writeField("publication_state", metadata.PublicationState)
	writeField("redaction_state", metadata.RedactionState)
	writeField("access_status", metadata.AccessStatus)
	writeField("integrity_status", metadata.IntegrityStatus)
	writeField("underlying_evidence_completeness", string(metadata.SemanticCompleteness))
	output.WriteString("artifact_read_status: complete\n")
	writeField("terminal_display_status", status)
	fmt.Fprintf(&output, "rendered_content_bytes: %d\n", len(rendered))
	fmt.Fprintf(&output, "rendered_content_limit_bytes: %d\n", TerminalContentMaxBytes)
	if !complete {
		output.WriteString("display_note: terminal display shortened after full artifact verification\n")
	}
	output.WriteString("content:\n")
	output.Write(rendered)
	output.WriteByte('\n')

	_, err := w.Write(output.Bytes())
	return RenderReport{DisplayComplete: complete, RenderedContentSize: len(rendered)}, err
}

func renderContent(content []byte, limit int) ([]byte, bool) {
	if limit < 2 {
		return nil, len(content) == 0
	}
	result := make([]byte, 0, min(limit, len(content)+2))
	result = append(result, '|', ' ')
	consumed := 0
	for consumed < len(content) {
		token, width := terminalSafeToken(content[consumed:])
		if len(result)+len(token) > limit {
			break
		}
		result = append(result, token...)
		consumed += width
	}
	return result, consumed == len(content)
}

func terminalSafeField(value string) string {
	input := []byte(value)
	result := make([]byte, 0, len(input))
	for len(input) > 0 {
		token, width := terminalSafeToken(input)
		if input[0] == '\n' {
			token = []byte(`\n`)
		}
		result = append(result, token...)
		input = input[width:]
	}
	return string(result)
}

func terminalSafeToken(input []byte) ([]byte, int) {
	b := input[0]
	if b < utf8.RuneSelf {
		switch b {
		case '\n':
			return []byte{'\n', '|', ' '}, 1
		case '\t':
			return []byte(`\t`), 1
		case '\r':
			return []byte(`\r`), 1
		case '\b':
			return []byte(`\b`), 1
		case 0x1b:
			return []byte(`\x1b`), 1
		case 0x7f:
			return []byte(`\x7f`), 1
		default:
			if b < 0x20 {
				return []byte(fmt.Sprintf(`\x%02X`, b)), 1
			}
			return []byte{b}, 1
		}
	}

	r, width := utf8.DecodeRune(input)
	if r == utf8.RuneError && width == 1 {
		return []byte(fmt.Sprintf(`\x%02X`, b)), 1
	}
	if r >= 0x80 && r <= 0x9f {
		return []byte(fmt.Sprintf(`\u%04X`, r)), width
	}
	if unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
		if r <= 0xffff {
			return []byte(fmt.Sprintf(`\u%04X`, r)), width
		}
		return []byte(fmt.Sprintf(`\U%08X`, r)), width
	}
	return input[:width], width
}
