package reporters

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/reporters/i18n"
)

// TestRenderHTMLOpts_DefaultLangIsEnglish guards against the
// HTMLOptions{} zero value silently producing Arabic — the regression
// would be subtle and locally invisible because English passes through
// all existing string-content checks.
func TestRenderHTMLOpts_DefaultLangIsEnglish(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "hybrid"}
	if err := RenderHTMLOpts(&buf, sampleFindings(), meta, HTMLOptions{}); err != nil {
		t.Fatalf("RenderHTMLOpts: %v", err)
	}
	html := buf.String()
	if !strings.Contains(html, `<html lang="en"`) {
		t.Errorf("missing lang=en attribute: %q", firstLine(html))
	}
	if strings.Contains(html, "dir=\"rtl\"") {
		t.Errorf("default render should not emit dir=rtl")
	}
	if !strings.Contains(html, "Fendix Security Report") {
		t.Errorf("missing English report title")
	}
}

// TestRenderHTMLOpts_ArabicEmitsRTL covers the Sprint-10 RTL branch:
// dir=rtl on <html>, at least one Arabic codepoint in the body, and
// (as a regression guard) the Western-Arabic numerals from the
// per-severity counts are unchanged (we deliberately don't translate
// 0-9 → ٠-٩ per the risk register).
func TestRenderHTMLOpts_ArabicEmitsRTL(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "hybrid"}
	if err := RenderHTMLOpts(&buf, sampleFindings(), meta, HTMLOptions{Lang: "ar"}); err != nil {
		t.Fatalf("RenderHTMLOpts: %v", err)
	}
	html := buf.String()
	if !strings.Contains(html, `<html lang="ar"`) {
		t.Errorf("missing lang=ar attribute: %q", firstLine(html))
	}
	if !strings.Contains(html, `dir="rtl"`) {
		t.Errorf("missing dir=rtl in Arabic render")
	}
	if !strings.Contains(html, "تقرير الأمان من Fendix") {
		t.Errorf("missing translated ReportTitle in Arabic render")
	}
	// Western-Arabic numerals preserved.
	if strings.ContainsAny(html, "٠١٢٣٤٥٦٧٨٩") {
		t.Errorf("Arabic render leaked Eastern Arabic numerals (we use 0-9)")
	}
}

// TestRenderHTMLOpts_UnknownLangFallsBackToEnglish ensures that an
// unrecognised --lang doesn't blow up at render time. The CLI wrapper
// is responsible for warning the user; here we just verify the
// fallback renders.
func TestRenderHTMLOpts_UnknownLangFallsBackToEnglish(t *testing.T) {
	var buf bytes.Buffer
	meta := ScanMetadata{Target: "https://test.com", Version: "dev", Mode: "hybrid"}
	if err := RenderHTMLOpts(&buf, sampleFindings(), meta, HTMLOptions{Lang: "klingon"}); err != nil {
		t.Fatalf("RenderHTMLOpts: %v", err)
	}
	html := buf.String()
	// The <html lang="..."> attribute preserves what the user passed
	// (browsers will treat unknown codes as a hint, not an error).
	if !strings.Contains(html, `<html lang="klingon"`) {
		t.Errorf("expected lang=klingon (preserved as-is); got: %q", firstLine(html))
	}
	// But the content falls back to English.
	if !strings.Contains(html, "Fendix Security Report") {
		t.Errorf("fallback render didn't emit English title")
	}
	if strings.Contains(html, `dir="rtl"`) {
		t.Errorf("unknown lang shouldn't be detected as RTL")
	}
}

// TestI18n_GetReturnsCompleteStringsForEveryLanguage iterates the set
// of supported languages and verifies every field in Strings is
// non-empty. Without this guard, a new field added to the struct
// could ship with the Arabic value empty and silently render as a
// blank cell — worse than English fallback.
func TestI18n_GetReturnsCompleteStringsForEveryLanguage(t *testing.T) {
	for _, lang := range []string{"en", "ar"} {
		lang := lang
		t.Run(lang, func(t *testing.T) {
			s := i18n.Get(lang)
			checkNonEmpty(t, lang, "ReportTitle", s.ReportTitle)
			checkNonEmpty(t, lang, "SeverityCritical", s.SeverityCritical)
			checkNonEmpty(t, lang, "SeverityHigh", s.SeverityHigh)
			checkNonEmpty(t, lang, "SeverityMedium", s.SeverityMedium)
			checkNonEmpty(t, lang, "SeverityLow", s.SeverityLow)
			checkNonEmpty(t, lang, "SeverityInfo", s.SeverityInfo)
			checkNonEmpty(t, lang, "ConfidenceHigh", s.ConfidenceHigh)
			checkNonEmpty(t, lang, "ConfidenceMedium", s.ConfidenceMedium)
			checkNonEmpty(t, lang, "ConfidenceLow", s.ConfidenceLow)
			checkNonEmpty(t, lang, "SectionSummary", s.SectionSummary)
			checkNonEmpty(t, lang, "SortByLabel", s.SortByLabel)
			checkNonEmpty(t, lang, "ExpandAll", s.ExpandAll)
			checkNonEmpty(t, lang, "CollapseAll", s.CollapseAll)
			checkNonEmpty(t, lang, "FieldEvidence", s.FieldEvidence)
			checkNonEmpty(t, lang, "FieldFix", s.FieldFix)
			checkNonEmpty(t, lang, "FieldSource", s.FieldSource)
			checkNonEmpty(t, lang, "FieldCategory", s.FieldCategory)
			checkNonEmpty(t, lang, "FieldReferences", s.FieldReferences)
			checkNonEmpty(t, lang, "FieldLocation", s.FieldLocation)
			checkNonEmpty(t, lang, "ScanStartedLabel", s.ScanStartedLabel)
			checkNonEmpty(t, lang, "DurationLabel", s.DurationLabel)
			checkNonEmpty(t, lang, "ModeLabel", s.ModeLabel)
			checkNonEmpty(t, lang, "EndpointsLabel", s.EndpointsLabel)
			checkNonEmpty(t, lang, "TotalFindingsLabel", s.TotalFindingsLabel)
			checkNonEmpty(t, lang, "NoFindingsMessage", s.NoFindingsMessage)
			checkNonEmpty(t, lang, "GeneratedByFendix", s.GeneratedByFendix)
		})
	}
}

func TestI18n_IsRTL(t *testing.T) {
	for _, c := range []struct {
		lang string
		want bool
	}{
		{"en", false},
		{"en-US", false},
		{"ar", true},
		{"ar-SA", true},
		{"AR", true}, // case-insensitive
		{"he", true},
		{"klingon", false},
		{"", false},
	} {
		if got := i18n.IsRTL(c.lang); got != c.want {
			t.Errorf("IsRTL(%q) = %v; want %v", c.lang, got, c.want)
		}
	}
}

func TestI18n_IsSupported(t *testing.T) {
	for _, c := range []struct {
		lang string
		want bool
	}{
		{"en", true},
		{"ar", true},
		{"ar-SA", true},
		{"fr", false},
		{"", false},
	} {
		if got := i18n.IsSupported(c.lang); got != c.want {
			t.Errorf("IsSupported(%q) = %v; want %v", c.lang, got, c.want)
		}
	}
}

func checkNonEmpty(t *testing.T, lang, name, v string) {
	t.Helper()
	if strings.TrimSpace(v) == "" {
		t.Errorf("lang %q: Strings.%s is empty", lang, name)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}
