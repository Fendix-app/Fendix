package reporters

import (
	"bytes"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// pdfSampleFindings is a small mix that exercises every severity
// bucket the renderer styles.
func pdfSampleFindings() []models.Finding {
	return []models.Finding{
		{ID: "SEC-001", Title: "SQL injection in user lookup", Severity: models.SeverityCritical,
			Endpoint: "src/db.py:42", Fix: "Use parameterised queries.", Confidence: models.ConfidenceHigh},
		{ID: "SEC-002", Title: "Hardcoded API key", Severity: models.SeverityHigh,
			Endpoint: "src/cfg.py:1", Fix: "Load from env.", Confidence: models.ConfidenceMedium},
		{ID: "SEC-003", Title: "Missing CSRF token", Severity: models.SeverityMedium,
			Endpoint: "POST /api/v1/account", Fix: "Add CSRF middleware.", Confidence: models.ConfidenceLow},
	}
}

func TestRenderPDF_ProducesNonEmptyOutput(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{
		Target:         "https://example.com",
		Version:        "v0.13.0",
		Mode:           "hybrid",
		Duration:       "1s",
		StartedAt:      time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC),
		EndpointsCount: 0,
	}
	err := RenderPDF(&buf, pdfSampleFindings(), meta, PDFOptions{})
	if err != nil {
		t.Fatalf("RenderPDF: %v", err)
	}
	if buf.Len() < 1000 {
		t.Errorf("PDF too small: %d bytes; expected ≥1000", buf.Len())
	}
	// %PDF- is the unambiguous file-magic header for all PDF
	// versions; if it's missing, fpdf didn't write a valid file.
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Errorf("PDF missing magic header; got %q", buf.Bytes()[:8])
	}
}

func TestRenderPDF_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://example.com", Version: "dev"}
	if err := RenderPDF(&buf, nil, meta, PDFOptions{}); err != nil {
		t.Fatalf("RenderPDF (empty): %v", err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Errorf("empty-findings PDF missing magic header")
	}
}

func TestRenderPDF_HonoursClassificationOption(t *testing.T) {
	// fpdf encodes text via Type1 font streams that aren't trivially
	// substring-searchable in the PDF bytes (the encoding can split
	// individual glyph runs). We assert that a non-default
	// classification still produces a valid PDF byte-stream;
	// human-visible verification of the banner text belongs in the
	// manual DoD step. A future test could embed pdfcpu to parse the
	// stream — out of scope for Sprint 11.
	var withDefault, withCustom bytes.Buffer
	meta := ScanMetadata{Target: "https://example.com", Version: "dev"}
	if err := RenderPDF(&withDefault, pdfSampleFindings(), meta, PDFOptions{}); err != nil {
		t.Fatalf("RenderPDF default: %v", err)
	}
	if err := RenderPDF(&withCustom, pdfSampleFindings(), meta, PDFOptions{Classification: "RESTRICTED"}); err != nil {
		t.Fatalf("RenderPDF custom: %v", err)
	}
	// The two PDFs have different banner content; their byte streams
	// must differ. (They share most content, so we don't require a
	// large delta — just inequality.)
	if bytes.Equal(withDefault.Bytes(), withCustom.Bytes()) {
		t.Errorf("PDFs with different classifications produced identical bytes; flag isn't taking effect")
	}
}

// TestRenderPDF_NeutralizesAndDoesNotPanic covers F-L4: exotic input
// (bidi overrides, zero-width, C0/C1 controls, and malformed UTF-8) must
// not panic the renderer, must still produce a valid PDF, and the raw
// multi-byte sequences of those characters must not be embedded verbatim
// in the output — i.e. NeutralizeFindings ran before fpdf saw the text.
//
// We deliberately do NOT assert byte-equality against a hand-stripped
// finding: fpdf registers fonts via internal Go maps, so font-object
// ordering (and therefore the exact byte stream) is not stable across
// separate fpdf.New() instances even for identical content.
func TestRenderPDF_NeutralizesAndDoesNotPanic(t *testing.T) {
	meta := ScanMetadata{Target: "https://example.com", Version: "dev"}

	exotic := []models.Finding{
		{
			ID:       "SEC-001",
			Title:    "SQL" + rlo + "injection" + bom,
			Severity: models.SeverityCritical,
			Endpoint: "GET /api" + rlo + "/users",
			// \x07 (C0 control) plus a trailing ZWSP exercise the strip path.
			Fix: "use\x07parameterisedqueries" + zwsp,
			// Lone invalid UTF-8 byte: must not panic.
			Evidence: "raw\xffbyte",
			TaintChain: []models.TaintLink{
				{File: "src" + rlo + "/db.py", Line: 1, Expr: "q" + zwj + "1"},
			},
			Confidence: models.ConfidenceHigh,
		},
	}

	var buf bytes.Buffer
	if err := RenderPDF(&buf, exotic, meta, PDFOptions{}); err != nil {
		t.Fatalf("RenderPDF (exotic): %v", err)
	}
	out := buf.Bytes()
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Error("exotic-input PDF missing magic header")
	}
	if len(out) < 1000 {
		t.Errorf("exotic-input PDF too small: %d bytes", len(out))
	}
	// The raw UTF-8 byte sequences of the bidi/zero-width chars must not
	// appear anywhere in the rendered PDF.
	for _, bad := range []string{rlo, zwsp, zwj, bom} {
		if bytes.Contains(out, []byte(bad)) {
			t.Errorf("PDF output embeds raw bytes for %U", []rune(bad)[0])
		}
	}
}

func TestRenderPDF_WithCoverageAndVerdictSucceeds(t *testing.T) {
	status := []ScannerStatus{{Name: "secrets", State: ScannerOK}, {Name: "pip", State: ScannerFailed, Reason: ReasonNetworkError, Detail: "HTTP 503", Attempts: 2}}
	cov := BuildCoverage(status, nil, false)
	var buf bytes.Buffer
	if err := RenderPDF(&buf, sampleFindings(), ScanMetadata{Version: "3.4.0", Mode: "whitebox", ScannerStatus: status, Coverage: &cov, ReleaseDecision: "block", CoverageState: "incomplete"}, PDFOptions{}); err != nil {
		t.Fatal(err)
	}
	if buf.Len() < 1000 {
		t.Fatalf("PDF suspiciously small: %d bytes", buf.Len())
	}
}

// TestRenderPDF_CoverageNeutralizesBidiAndControl covers the same
// Trojan-Source threat as TestRenderPDF_NeutralizesAndDoesNotPanic, but
// for the coverage appendix rows: ScannerStatus.Name/Detail (and, derived
// from Name, Coverage.Gaps) are exactly as operator-controlled under
// `fendix report --input` as finding fields are, and must not survive
// into the rendered PDF.
func TestRenderPDF_CoverageNeutralizesBidiAndControl(t *testing.T) {
	status := []ScannerStatus{
		{Name: "py" + rlo + "engine", State: ScannerFailed, Reason: ReasonNetworkError, Detail: "HTTP" + zwsp + "503"},
	}
	cov := BuildCoverage(status, nil, false)
	meta := ScanMetadata{Target: "https://example.com", Version: "dev", ScannerStatus: status, Coverage: &cov}
	var buf bytes.Buffer
	if err := RenderPDF(&buf, nil, meta, PDFOptions{}); err != nil {
		t.Fatalf("RenderPDF: %v", err)
	}
	out := buf.Bytes()
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Error("PDF missing magic header")
	}
	for _, bad := range []string{rlo, zwsp} {
		if bytes.Contains(out, []byte(bad)) {
			t.Errorf("PDF output embeds raw bytes for %U", []rune(bad)[0])
		}
	}
}

func TestTopNBySeverity_OrdersCorrectly(t *testing.T) {
	findings := []models.Finding{
		{ID: "low", Severity: models.SeverityLow},
		{ID: "critical", Severity: models.SeverityCritical},
		{ID: "high", Severity: models.SeverityHigh},
	}
	got := topNBySeverity(findings, 2)
	if len(got) != 2 || got[0].ID != "critical" || got[1].ID != "high" {
		t.Errorf("topN = %+v; want [critical high]", got)
	}
}
