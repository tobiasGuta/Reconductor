package evidence

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

func TestRenderVerifiedAtAndAboveExpandedDisplayBoundary(t *testing.T) {
	for _, test := range []struct {
		name     string
		content  []byte
		complete bool
	}{
		{name: "exact", content: bytes.Repeat([]byte("a"), TerminalContentMaxBytes-2), complete: true},
		{name: "above", content: bytes.Repeat([]byte("a"), TerminalContentMaxBytes-1), complete: false},
		{name: "escape expansion", content: bytes.Repeat([]byte{0x1b}, TerminalContentMaxBytes/4), complete: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			verified := renderFixture(test.content)
			var output bytes.Buffer
			report, err := RenderVerified(&output, verified)
			if err != nil {
				t.Fatal(err)
			}
			if report.DisplayComplete != test.complete || report.RenderedContentSize > TerminalContentMaxBytes {
				t.Fatalf("report=%#v", report)
			}
			status := "terminal_display_status: complete"
			if !test.complete {
				status = "terminal_display_status: shortened"
				if !strings.Contains(output.String(), "shortened after full artifact verification") || strings.Contains(output.String(), "evidence truncated") || strings.Contains(output.String(), "corrupt") {
					t.Fatalf("misleading shortened display: %s", output.String()[:500])
				}
			}
			if !strings.Contains(output.String(), status) || !strings.Contains(output.String(), "artifact_read_status: complete") || !strings.Contains(output.String(), "integrity_status: verified") {
				t.Fatalf("missing status distinctions: %s", output.String()[:500])
			}
		})
	}
}

func TestRenderVerifiedNeutralizesTerminalAndUnicodeControls(t *testing.T) {
	content := append([]byte("plain\x1b[31m red\x1b]0;title\x07\rback\b\x00\x1f\x7f"), 0xc2, 0x85, 0xff)
	content = append(content, []byte(" bidi:\u202Ehidden\u2066 isolate\u200D end\nordinary café")...)
	var output bytes.Buffer
	report, err := RenderVerified(&output, renderFixture(content))
	if err != nil || !report.DisplayComplete {
		t.Fatalf("report=%#v error=%v", report, err)
	}
	text := output.String()
	for _, escaped := range []string{`\x1b[31m`, `\x1b]0;title\x07`, `\r`, `\b`, `\x00`, `\x1F`, `\x7f`, `\u0085`, `\xFF`, `\u202E`, `\u2066`, `\u200D`, "| ordinary café"} {
		if !strings.Contains(text, escaped) {
			t.Fatalf("missing escaped token %q in %q", escaped, text)
		}
	}
	if strings.ContainsRune(text, '\x1b') || strings.ContainsRune(text, '\r') || strings.ContainsRune(text, '\b') || strings.ContainsRune(text, '\u202e') || !utf8.ValidString(text) {
		t.Fatalf("unsafe rendered output: %q", text)
	}
}

func TestRenderVerifiedSanitizesMetadataAndOmitsStorageDetails(t *testing.T) {
	verified := renderFixture([]byte("recorded observation"))
	verified.Metadata.ProviderName = "provider\x1b]0;owned\x07\nforged: true"
	var output bytes.Buffer
	if _, err := RenderVerified(&output, verified); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.ContainsRune(text, '\x1b') || strings.Contains(text, "v1/ab/") || strings.Contains(text, "storage_key") || strings.Contains(text, "filesystem") {
		t.Fatalf("unsafe metadata output: %q", text)
	}
	if !strings.Contains(text, `provider: provider\x1b]0;owned\x07\nforged: true`) {
		t.Fatalf("metadata was not safely escaped: %q", text)
	}
}

func renderFixture(content []byte) Verified {
	return Verified{Metadata: Metadata{
		ArtifactID: "00000000-0000-4000-8000-000000000001", WorkflowRunID: "00000000-0000-4000-8000-000000000002",
		StepRunID: "00000000-0000-4000-8000-000000000003", StepDefinitionID: "probe", ToolRunID: "00000000-0000-4000-8000-000000000004",
		ProviderAttemptID: "00000000-0000-4000-8000-000000000005", ResultOccurrenceID: "00000000-0000-4000-8000-000000000006",
		CapabilityName: "probe.http", CapabilityVersion: "1", ProviderName: "httpx", ArtifactType: "normalized-result",
		Role: domain.ArtifactRoleSemanticResult, ContentType: "application/json", ContentSizeBytes: int64(len(content)),
		ContentSHA256: strings.Repeat("a", 64), PublicationState: "adopted", RedactionState: "redacted", AccessStatus: "permitted",
		IntegrityStatus: "verified", SemanticCompleteness: domain.SemanticComplete,
	}, Content: content}
}
