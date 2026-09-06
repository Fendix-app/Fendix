// Sprint 11 — PDF executive report.
//
// Renders a paginated PDF executive report from a scan's Findings +
// ScanMetadata. The structure: cover page → executive summary →
// findings table (paginated) → remediation plan → metadata appendix.
//
// English-only for v0.13.0. Arabic PDF needs an embedded Noto Arabic
// font (Sprint 11.5); fpdf can't render Arabic glyphs with its
// built-in fonts.
//
// Implementation note: uses github.com/go-pdf/fpdf — pure-Go fork of
// the original jung-kurt/gofpdf that's been GC'd. MIT-licensed, no
// CGo. Bundled as a direct go.mod dep per PLAN.md's allowlist.
package reporters

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-pdf/fpdf"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters/i18n"
)

// PDFOptions configures RenderPDF. Today the only knob is the
// classification banner; future options (custom logo, custom font,
// page-size override) can land here without breaking callers.
type PDFOptions struct {
	// Classification is the banner text rendered on every page
	// (top-right, red). Defaults to "INTERNAL". Empty disables.
	Classification string
}

// RenderPDF writes a print-ready PDF report to the writer.
func RenderPDF(w io.Writer, findings []models.Finding, meta ScanMetadata, opts PDFOptions) error {
	classification := opts.Classification
	if classification == "" {
		classification = "INTERNAL"
	}

	// Strip bidi/zero-width/control characters from untrusted finding
	// fields before rendering. fpdf substitutes glyphs it can't draw
	// (the accepted glyph/font limit) but does nothing about bidi
	// reordering or invisible control chars — neutralize them here so
	// the PDF can't be spoofed the way a Trojan-Source title would.
	findings = NeutralizeFindings(findings)

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 20, 15)
	pdf.SetAutoPageBreak(true, 20)

	// Repeated classification banner. fpdf calls this on every AddPage.
	pdf.SetHeaderFunc(func() {
		if classification == "" {
			return
		}
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(180, 0, 0)
		pdf.SetXY(15, 8)
		pdf.CellFormat(0, 5, classification, "", 0, "R", false, 0, "")
		pdf.SetTextColor(0, 0, 0)
	})

	// Footer: page number + "Fendix vX.Y.Z".
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(120, 120, 120)
		pdf.CellFormat(0, 10,
			fmt.Sprintf("Page %d  ·  Fendix %s", pdf.PageNo(), meta.Version),
			"", 0, "C", false, 0, "")
		pdf.SetTextColor(0, 0, 0)
	})

	renderPDFCover(pdf, meta, findings)
	renderPDFSummary(pdf, findings)
	renderPDFFindingsTable(pdf, findings)
	renderPDFRemediation(pdf, findings)
	renderPDFAppendix(pdf, meta)

	if err := pdf.Output(w); err != nil {
		return fmt.Errorf("write PDF: %w", err)
	}
	return nil
}

func renderPDFCover(pdf *fpdf.Fpdf, meta ScanMetadata, findings []models.Finding) {
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 28)
	pdf.SetY(60)
	pdf.CellFormat(0, 12, "Fendix Security Report", "", 1, "C", false, 0, "")

	pdf.Ln(8)
	pdf.SetFont("Helvetica", "", 14)
	target := meta.Target
	if target == "" {
		target = "(no target specified)"
	}
	pdf.CellFormat(0, 8, target, "", 1, "C", false, 0, "")

	pdf.Ln(4)
	pdf.SetFont("Helvetica", "", 11)
	scanDate := pdfFormatTime(meta.StartedAt)
	pdf.CellFormat(0, 6, "Scan date: "+scanDate, "", 1, "C", false, 0, "")

	pdf.Ln(2)
	mode := meta.Mode
	if mode == "" {
		mode = "n/a"
	}
	pdf.CellFormat(0, 6, "Mode: "+mode+"  ·  Total findings: "+intToString(len(findings)),
		"", 1, "C", false, 0, "")
}

func renderPDFSummary(pdf *fpdf.Fpdf, findings []models.Finding) {
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 18)
	pdf.CellFormat(0, 10, "Executive Summary", "B", 1, "L", false, 0, "")
	pdf.Ln(4)

	counts := CountSeverities(findings)
	rows := [][2]string{
		{"CRITICAL", intToString(counts.Critical)},
		{"HIGH", intToString(counts.High)},
		{"MEDIUM", intToString(counts.Medium)},
		{"LOW", intToString(counts.Low)},
		{"INFO", intToString(counts.Info)},
	}
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetFillColor(240, 240, 240)
	pdf.CellFormat(60, 7, "Severity", "1", 0, "L", true, 0, "")
	pdf.CellFormat(30, 7, "Count", "1", 1, "R", true, 0, "")
	pdf.SetFont("Helvetica", "", 11)
	for _, r := range rows {
		setSeverityBackground(pdf, r[0])
		pdf.CellFormat(60, 7, r[0], "1", 0, "L", true, 0, "")
		pdf.SetFillColor(255, 255, 255)
		pdf.CellFormat(30, 7, r[1], "1", 1, "R", false, 0, "")
	}

	pdf.Ln(8)
	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(0, 8, "Top findings", "B", 1, "L", false, 0, "")
	pdf.Ln(2)

	top := topNBySeverity(findings, 3)
	if len(top) == 0 {
		pdf.SetFont("Helvetica", "I", 11)
		pdf.CellFormat(0, 7, "No findings to report.", "", 1, "L", false, 0, "")
		return
	}
	pdf.SetFont("Helvetica", "", 10)
	for i, f := range top {
		title := truncatePDFLine(f.Title, 80)
		summary := truncatePDFLine(f.Fix, 120)
		pdf.SetFont("Helvetica", "B", 11)
		pdf.CellFormat(0, 6, fmt.Sprintf("%d. [%s] %s", i+1, f.Severity, title), "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		if summary != "" {
			pdf.MultiCell(0, 5, summary, "", "L", false)
		}
		pdf.Ln(2)
	}
}

// renderPDFFindingsTable paginates the findings list in chunks of
// rows-per-page. fpdf's AutoPageBreak handles overflow but we lay
// out columns explicitly to keep the layout predictable.
func renderPDFFindingsTable(pdf *fpdf.Fpdf, findings []models.Finding) {
	if len(findings) == 0 {
		return
	}
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 18)
	pdf.CellFormat(0, 10, "Findings", "B", 1, "L", false, 0, "")
	pdf.Ln(3)

	headers := []struct {
		label string
		width float64
		align string
	}{
		{"ID", 28, "L"},
		{"Severity", 22, "L"},
		{"Title", 70, "L"},
		{"Location", 50, "L"},
		{"Conf.", 16, "L"},
	}
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetFillColor(230, 230, 230)
	for _, h := range headers {
		pdf.CellFormat(h.width, 7, h.label, "1", 0, h.align, true, 0, "")
	}
	pdf.Ln(-1)

	pdf.SetFont("Helvetica", "", 9)
	for _, f := range findings {
		setSeverityBackground(pdf, string(f.Severity))
		pdf.CellFormat(headers[0].width, 6, truncatePDFLine(f.ID, 14), "1", 0, "L", false, 0, "")
		pdf.CellFormat(headers[1].width, 6, string(f.Severity), "1", 0, "L", true, 0, "")
		pdf.SetFillColor(255, 255, 255)
		pdf.CellFormat(headers[2].width, 6, truncatePDFLine(f.Title, 60), "1", 0, "L", false, 0, "")
		pdf.CellFormat(headers[3].width, 6, truncatePDFLine(f.Endpoint, 40), "1", 0, "L", false, 0, "")
		pdf.CellFormat(headers[4].width, 6, string(f.Confidence), "1", 1, "L", false, 0, "")
	}
}

func renderPDFRemediation(pdf *fpdf.Fpdf, findings []models.Finding) {
	highSev := make([]models.Finding, 0)
	for _, f := range findings {
		if f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh {
			highSev = append(highSev, f)
		}
	}
	if len(highSev) == 0 {
		return
	}
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 18)
	pdf.CellFormat(0, 10, "Remediation Plan", "B", 1, "L", false, 0, "")
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "I", 10)
	pdf.MultiCell(0, 5,
		"This section lists CRITICAL and HIGH findings only, in scan order. "+
			"MEDIUM/LOW findings appear in the Findings table above but are omitted "+
			"from the remediation plan to keep this section actionable.",
		"", "L", false)
	pdf.Ln(4)
	for i, f := range highSev {
		pdf.SetFont("Helvetica", "B", 11)
		setSeverityBackground(pdf, string(f.Severity))
		pdf.CellFormat(0, 7, fmt.Sprintf("%d. [%s] %s", i+1, f.Severity, f.Title), "1", 1, "L", true, 0, "")
		pdf.SetFillColor(255, 255, 255)
		pdf.SetFont("Helvetica", "", 10)
		if f.Endpoint != "" {
			pdf.MultiCell(0, 5, "Endpoint: "+f.Endpoint, "", "L", false)
		}
		if f.Fix != "" {
			pdf.MultiCell(0, 5, "Fix: "+f.Fix, "", "L", false)
		}
		pdf.Ln(3)
	}
}

func renderPDFAppendix(pdf *fpdf.Fpdf, meta ScanMetadata) {
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 18)
	pdf.CellFormat(0, 10, "Appendix: Scan Metadata", "B", 1, "L", false, 0, "")
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "", 10)
	rows := [][2]string{
		{"Target", strOrNA(meta.Target)},
		{"Mode", strOrNA(meta.Mode)},
		{"Scan started", pdfFormatTime(meta.StartedAt)},
		{"Duration", strOrNA(meta.Duration)},
		{"Endpoints scanned", intToString(meta.EndpointsCount)},
		{"Fendix version", strOrNA(meta.Version)},
	}
	if meta.ReleaseDecision != "" {
		rows = append(rows, [2]string{"Release decision", i18n.VerdictLabel(i18n.Get("en"), meta.ReleaseDecision, meta.CoverageState)})
	}
	if meta.Coverage != nil {
		cov := "complete"
		if !meta.Coverage.ConfiguredComplete {
			cov = "incomplete: " + strings.Join(meta.Coverage.Gaps, ", ")
		}
		rows = append(rows, [2]string{"Coverage", cov})
		if len(meta.Coverage.RequiredGaps) > 0 {
			rows = append(rows, [2]string{"Required, not delivered", strings.Join(meta.Coverage.RequiredGaps, ", ")})
		}
		for _, s := range meta.ScannerStatus {
			val := s.Class()
			if s.Reason != "" {
				val += " (" + string(s.Reason) + ")"
			}
			if s.Attempts > 1 {
				val += fmt.Sprintf(", %d attempts", s.Attempts)
			}
			if s.Detail != "" {
				val += " — " + s.Detail
			}
			rows = append(rows, [2]string{"  " + s.Name, val})
		}
	} else {
		rows = append(rows, [2]string{"Coverage", "not recorded by this engine version"})
	}
	for _, r := range rows {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(50, 6, r[0], "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.CellFormat(0, 6, r[1], "", 1, "L", false, 0, "")
	}
}

// setSeverityBackground sets the fpdf fill colour to the severity's
// canonical shade for the next cell. Caller is responsible for
// resetting via SetFillColor(255,255,255) after the run.
func setSeverityBackground(pdf *fpdf.Fpdf, sev string) {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		pdf.SetFillColor(255, 200, 200)
	case "HIGH":
		pdf.SetFillColor(255, 230, 200)
	case "MEDIUM":
		pdf.SetFillColor(255, 240, 180)
	case "LOW":
		pdf.SetFillColor(210, 230, 255)
	case "INFO":
		pdf.SetFillColor(225, 225, 225)
	default:
		pdf.SetFillColor(255, 255, 255)
	}
}

// topNBySeverity returns the top N findings ordered by severity rank
// (descending) then by ID. Stable across runs given the same input.
func topNBySeverity(findings []models.Finding, n int) []models.Finding {
	if len(findings) == 0 || n <= 0 {
		return nil
	}
	// Use a copy so we don't reorder the caller's slice.
	cp := make([]models.Finding, len(findings))
	copy(cp, findings)
	// Bubble-style sort; n is small (<= 3) and the findings list is
	// also typically small for the executive summary. Trade-off: no
	// stdlib sort.Slice import, deterministic output.
	for i := 0; i < len(cp); i++ {
		for j := i + 1; j < len(cp); j++ {
			if models.SeverityRank(cp[i].Severity) < models.SeverityRank(cp[j].Severity) {
				cp[i], cp[j] = cp[j], cp[i]
			}
		}
	}
	if len(cp) > n {
		cp = cp[:n]
	}
	return cp
}

// truncatePDFLine clips s to at most max runes (not bytes); appends
// "…" when clipped. Rune-aware so multi-byte UTF-8 characters in
// finding titles / paths are never split mid-byte. fpdf's built-in
// Helvetica still substitutes glyphs it can't render — register a
// Unicode font for true non-Latin-1 support (Sprint 11.5).
func truncatePDFLine(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	return string(runes[:max-1]) + "…"
}

func pdfFormatTime(t interface{}) string {
	if t == nil {
		return "n/a"
	}
	if tt, ok := t.(time.Time); ok {
		return tt.UTC().Format(time.RFC3339)
	}
	if s, ok := t.(string); ok && s != "" {
		return s
	}
	return fmt.Sprintf("%v", t)
}

func strOrNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

func intToString(i int) string {
	return fmt.Sprintf("%d", i)
}
