package reporters

import (
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestSanitizeFindings_RedactsAuthValues(t *testing.T) {
	auth := &models.AuthContext{
		Value:  "Bearer sk-live-abc123def456",
		Header: "Authorization",
		Type:   models.AuthTypeBearer,
	}

	findings := []models.Finding{
		{
			Title:    "Test finding",
			Evidence: "Request sent with Bearer sk-live-abc123def456 got 200",
			Fix:      "Remove Bearer sk-live-abc123def456 from response",
		},
	}

	sanitized := SanitizeFindings(findings, auth)

	if strings.Contains(sanitized[0].Evidence, "sk-live-abc123def456") {
		t.Errorf("evidence still contains secret: %s", sanitized[0].Evidence)
	}
	if !strings.Contains(sanitized[0].Evidence, "[REDACTED]") {
		t.Error("evidence should contain [REDACTED]")
	}
	if strings.Contains(sanitized[0].Fix, "sk-live-abc123def456") {
		t.Errorf("fix still contains secret: %s", sanitized[0].Fix)
	}
}

func TestSanitizeFindings_RedactsBareToken(t *testing.T) {
	auth := &models.AuthContext{
		Value: "Bearer eyJhbGciOiJIUzI1NiJ9.longpayload.signature",
	}

	findings := []models.Finding{
		{
			Title:    "JWT exposed",
			Evidence: "Token eyJhbGciOiJIUzI1NiJ9.longpayload.signature found in response",
		},
	}

	sanitized := SanitizeFindings(findings, auth)

	if strings.Contains(sanitized[0].Evidence, "eyJhbGciOiJIUzI1NiJ9") {
		t.Errorf("bare token should be redacted: %s", sanitized[0].Evidence)
	}
}

func TestSanitizeFindings_NilAuth(t *testing.T) {
	findings := []models.Finding{
		{Title: "Test", Evidence: "some evidence"},
	}

	sanitized := SanitizeFindings(findings, nil)

	if sanitized[0].Evidence != "some evidence" {
		t.Errorf("nil auth should not modify findings")
	}
}

func TestSanitizeFindings_MultipleAuthContexts(t *testing.T) {
	auth1 := &models.AuthContext{Value: "Bearer token-user1"}
	auth2 := &models.AuthContext{Value: "Bearer token-user2"}

	findings := []models.Finding{
		{
			Evidence: "user1=Bearer token-user1, user2=Bearer token-user2",
		},
	}

	sanitized := SanitizeFindings(findings, auth1, auth2)

	if strings.Contains(sanitized[0].Evidence, "token-user1") {
		t.Error("user1 token should be redacted")
	}
	if strings.Contains(sanitized[0].Evidence, "token-user2") {
		t.Error("user2 token should be redacted")
	}
}

func TestSanitizeFindings_DoesNotMutateOriginal(t *testing.T) {
	auth := &models.AuthContext{Value: "Bearer secret-tok"}

	original := []models.Finding{
		{Evidence: "includes Bearer secret-tok value"},
	}

	_ = SanitizeFindings(original, auth)

	if !strings.Contains(original[0].Evidence, "secret-tok") {
		t.Error("original findings should not be mutated")
	}
}

func TestSanitizeFindings_EmptySecrets(t *testing.T) {
	auth := &models.AuthContext{Value: ""}

	findings := []models.Finding{
		{Evidence: "no secrets here"},
	}

	sanitized := SanitizeFindings(findings, auth)
	if sanitized[0].Evidence != "no secrets here" {
		t.Error("empty auth should not modify findings")
	}
}

func TestSanitizeFindings_RedactsInTitle(t *testing.T) {
	auth := &models.AuthContext{Value: "Bearer my-secret-token"}

	findings := []models.Finding{
		{Title: "Leak found: Bearer my-secret-token"},
	}

	sanitized := SanitizeFindings(findings, auth)

	if strings.Contains(sanitized[0].Title, "my-secret-token") {
		t.Errorf("title should be redacted: %s", sanitized[0].Title)
	}
}

// Invisible Unicode characters are built from rune code points so the
// source file itself stays free of bidi/zero-width chars (a literal BOM
// mid-source is even a hard compile error).
var (
	rlo  = string(rune(0x202e)) // RIGHT-TO-LEFT OVERRIDE (Trojan-Source classic)
	lre  = string(rune(0x202a)) // LEFT-TO-RIGHT EMBEDDING
	pdf  = string(rune(0x202c)) // POP DIRECTIONAL FORMATTING
	lri  = string(rune(0x2066)) // LEFT-TO-RIGHT ISOLATE
	pdi  = string(rune(0x2069)) // POP DIRECTIONAL ISOLATE
	lrm  = string(rune(0x200e)) // LEFT-TO-RIGHT MARK
	rlm  = string(rune(0x200f)) // RIGHT-TO-LEFT MARK
	zwsp = string(rune(0x200b)) // ZERO WIDTH SPACE
	zwnj = string(rune(0x200c)) // ZERO WIDTH NON-JOINER
	zwj  = string(rune(0x200d)) // ZERO WIDTH JOINER
	bom  = string(rune(0xfeff)) // ZERO WIDTH NO-BREAK SPACE / BOM
)

func TestNeutralizeText_StripsBidiAndControl(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		// Trojan-Source RLO override (U+202E) reorders the visible text.
		{"RLO override", "admin" + rlo + "gnp.txt", "admingnp.txt"},
		{"LRE/PDF pair", "a" + lre + "b" + pdf + "c", "abc"},
		{"isolates", "x" + lri + "y" + pdi + "z", "xyz"},
		{"LRM/RLM marks", "a" + lrm + "b" + rlm + "c", "abc"},
		{"zero-width space", "se" + zwsp + "cret", "secret"},
		{"ZWNJ/ZWJ", "a" + zwnj + "b" + zwj + "c", "abc"},
		{"BOM / ZWNBSP", bom + "text", "text"},
		{"C0 controls dropped", "a\x00b\x07c", "abc"},
		{"DEL dropped", "a\x7fb", "ab"},
		{"bare CR dropped", "line1\rline2", "line1line2"},
		{"C1 controls dropped (NEL)", "a\u0085b", "ab"},
		// Legitimate layout characters survive.
		{"newline preserved", "line1\nline2", "line1\nline2"},
		{"tab preserved", "a\tb", "a\tb"},
		// Non-control Unicode (RTL script, emoji) survives untouched.
		{"arabic preserved", "مرحبا", "مرحبا"},
		{"emoji preserved", "shield \U0001f6e1", "shield \U0001f6e1"},
		{"empty", "", ""},
		{"plain ASCII unchanged", "GET /api/users", "GET /api/users"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NeutralizeText(tt.in)
			if got != tt.want {
				t.Errorf("NeutralizeText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNeutralizeText_DropsInvalidUTF8 covers the F-L4 robustness goal:
// raw, malformed UTF-8 bytes (e.g. a lone 0x80..0xFF) must be dropped
// rather than emitted as a U+FFFD replacement char, and must not panic.
func TestNeutralizeText_DropsInvalidUTF8(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lone continuation byte", "a\x80b", "ab"},
		{"lone high byte", "a\xffb", "ab"},
		{"truncated multibyte", "a\xe2\x82c", "ac"},
		{"C1 as proper codepoint", "a\u009fb", "ab"},
		{"valid after invalid", "\xffvalid", "valid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NeutralizeText(tt.in)
			if got != tt.want {
				t.Errorf("NeutralizeText(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if strings.ContainsRune(got, '�') {
				t.Errorf("output should not contain U+FFFD replacement char: %q", got)
			}
		})
	}
}

func TestNeutralizeFindings_StripsAllHumanFacingFields(t *testing.T) {
	findings := []models.Finding{
		{
			Title:             "SQL" + rlo + "injection",
			Evidence:          "payload" + zwsp + "=1",
			Fix:               "use\x07params",
			Endpoint:          "GET /api" + rlo + "/users",
			Category:          "inj" + bom + "ection",
			AffectedEndpoints: []string{"GET /a" + zwj + "b", "POST /c" + rlo + "d"},
			TaintChain: []models.TaintLink{
				{File: "src" + rlo + "/app.py", Line: 10, Expr: "run(" + zwsp + "x)"},
			},
		},
	}

	out := NeutralizeFindings(findings)

	f := out[0]
	if containsAnyNeutralized(f.Title) {
		t.Errorf("Title not neutralized: %q", f.Title)
	}
	if containsAnyNeutralized(f.Evidence) {
		t.Errorf("Evidence not neutralized: %q", f.Evidence)
	}
	if strings.ContainsRune(f.Fix, '\x07') {
		t.Errorf("Fix not neutralized: %q", f.Fix)
	}
	if containsAnyNeutralized(f.Endpoint) {
		t.Errorf("Endpoint not neutralized: %q", f.Endpoint)
	}
	if containsAnyNeutralized(f.Category) {
		t.Errorf("Category not neutralized: %q", f.Category)
	}
	for _, ep := range f.AffectedEndpoints {
		if containsAnyNeutralized(ep) {
			t.Errorf("AffectedEndpoints entry not neutralized: %q", ep)
		}
	}
	if containsAnyNeutralized(f.TaintChain[0].File) {
		t.Errorf("TaintChain File not neutralized: %q", f.TaintChain[0].File)
	}
	if containsAnyNeutralized(f.TaintChain[0].Expr) {
		t.Errorf("TaintChain Expr not neutralized: %q", f.TaintChain[0].Expr)
	}
	// Line is a numeric field carried through unchanged.
	if f.TaintChain[0].Line != 10 {
		t.Errorf("TaintChain Line should be untouched, got %d", f.TaintChain[0].Line)
	}
}

func TestNeutralizeFindings_DoesNotMutateOriginal(t *testing.T) {
	original := []models.Finding{
		{
			Title:             "evil" + rlo + "title",
			AffectedEndpoints: []string{"GET /a" + zwj + "b"},
			TaintChain:        []models.TaintLink{{File: "x" + rlo + "y", Expr: "z" + zwsp}},
		},
	}

	_ = NeutralizeFindings(original)

	if !strings.Contains(original[0].Title, rlo) {
		t.Error("original Title should not be mutated")
	}
	if !strings.Contains(original[0].AffectedEndpoints[0], zwj) {
		t.Error("original AffectedEndpoints should not be mutated")
	}
	if !strings.Contains(original[0].TaintChain[0].File, rlo) {
		t.Error("original TaintChain should not be mutated")
	}
}

// TestNeutralizeCoverageMetadata_StripsAllFields is a direct unit test of
// NeutralizeCoverageMetadata (I2). The PDF integration test
// (TestRenderPDF_CoverageNeutralizesBidiAndControl) only asserts raw bytes
// are absent from a compressed PDF stream, which still passes even if the
// NeutralizeCoverageMetadata call were deleted outright — a compressed
// stream never contains the plaintext bytes either way. This test calls
// the function directly and checks every field its doc comment claims to
// scrub: ScannerStatus.Name/Reason/Detail, Coverage.Gaps/RequiredGaps/
// Limitations/RequiredAnalyzers/Retried, and ReleaseDecision/CoverageState.
func TestNeutralizeCoverageMetadata_StripsAllFields(t *testing.T) {
	status := []ScannerStatus{
		{
			Name:     "py" + rlo + "engine",
			State:    ScannerFailed,
			Reason:   ScannerReason("net" + zwsp + "work_error"),
			Detail:   "lookup\x07failed",
			Attempts: 2,
		},
	}
	cov := Coverage{
		ContractVersion:   1,
		Gaps:              []string{"py" + rlo + "engine"},
		RequiredGaps:      []string{"pip" + zwsp},
		Limitations:       []string{"secrets: partial\x07scan"},
		RequiredAnalyzers: []string{"go" + rlo + "vulncheck"},
		Retried:           []string{"npm" + zwsp},
	}
	meta := ScanMetadata{
		Version:         "3.4.0",
		ScannerStatus:   status,
		Coverage:        &cov,
		ReleaseDecision: "block" + rlo,
		CoverageState:   "incomplete" + zwsp,
	}

	out := NeutralizeCoverageMetadata(meta)

	// --- every documented output field is scrubbed ---
	if containsAnyNeutralized(out.ScannerStatus[0].Name) {
		t.Errorf("ScannerStatus.Name not neutralized: %q", out.ScannerStatus[0].Name)
	}
	if containsAnyNeutralized(string(out.ScannerStatus[0].Reason)) {
		t.Errorf("ScannerStatus.Reason not neutralized: %q", out.ScannerStatus[0].Reason)
	}
	if strings.ContainsRune(out.ScannerStatus[0].Detail, '\x07') {
		t.Errorf("ScannerStatus.Detail not neutralized: %q", out.ScannerStatus[0].Detail)
	}
	if out.ScannerStatus[0].Attempts != 2 {
		t.Errorf("Attempts is numeric and must be untouched, got %d", out.ScannerStatus[0].Attempts)
	}
	if containsAnyNeutralized(out.Coverage.Gaps[0]) {
		t.Errorf("Coverage.Gaps not neutralized: %q", out.Coverage.Gaps[0])
	}
	if containsAnyNeutralized(out.Coverage.RequiredGaps[0]) {
		t.Errorf("Coverage.RequiredGaps not neutralized: %q", out.Coverage.RequiredGaps[0])
	}
	if strings.ContainsRune(out.Coverage.Limitations[0], '\x07') {
		t.Errorf("Coverage.Limitations not neutralized: %q", out.Coverage.Limitations[0])
	}
	if containsAnyNeutralized(out.Coverage.RequiredAnalyzers[0]) {
		t.Errorf("Coverage.RequiredAnalyzers not neutralized: %q", out.Coverage.RequiredAnalyzers[0])
	}
	if containsAnyNeutralized(out.Coverage.Retried[0]) {
		t.Errorf("Coverage.Retried not neutralized: %q", out.Coverage.Retried[0])
	}
	if containsAnyNeutralized(out.ReleaseDecision) {
		t.Errorf("ReleaseDecision not neutralized: %q", out.ReleaseDecision)
	}
	if containsAnyNeutralized(out.CoverageState) {
		t.Errorf("CoverageState not neutralized: %q", out.CoverageState)
	}

	// --- the input is never mutated: the original slice/struct still
	// carries every raw character, and the Coverage pointer differs. ---
	if !containsAnyNeutralized(meta.ScannerStatus[0].Name) {
		t.Error("original ScannerStatus.Name should not be mutated")
	}
	if !strings.Contains(string(meta.ScannerStatus[0].Reason), zwsp) {
		t.Error("original ScannerStatus.Reason should not be mutated")
	}
	if !strings.ContainsRune(meta.ScannerStatus[0].Detail, '\x07') {
		t.Error("original ScannerStatus.Detail should not be mutated")
	}
	if !containsAnyNeutralized(meta.Coverage.Gaps[0]) {
		t.Error("original Coverage.Gaps should not be mutated")
	}
	if !containsAnyNeutralized(meta.Coverage.RequiredGaps[0]) {
		t.Error("original Coverage.RequiredGaps should not be mutated")
	}
	if !strings.ContainsRune(meta.Coverage.Limitations[0], '\x07') {
		t.Error("original Coverage.Limitations should not be mutated")
	}
	if !containsAnyNeutralized(meta.Coverage.RequiredAnalyzers[0]) {
		t.Error("original Coverage.RequiredAnalyzers should not be mutated")
	}
	if !containsAnyNeutralized(meta.Coverage.Retried[0]) {
		t.Error("original Coverage.Retried should not be mutated")
	}
	if !containsAnyNeutralized(meta.ReleaseDecision) {
		t.Error("original ReleaseDecision should not be mutated")
	}
	if !containsAnyNeutralized(meta.CoverageState) {
		t.Error("original CoverageState should not be mutated")
	}
	if meta.Coverage == out.Coverage {
		t.Error("Coverage pointer must not be shared between input and output")
	}
}

// containsAnyNeutralized reports whether s still contains any of the
// bidi/zero-width characters used in these tests — a quick assertion
// that NeutralizeText scrubbed the field.
func containsAnyNeutralized(s string) bool {
	for _, c := range []string{rlo, lre, pdf, lri, pdi, lrm, rlm, zwsp, zwnj, zwj, bom} {
		if strings.Contains(s, c) {
			return true
		}
	}
	return false
}
