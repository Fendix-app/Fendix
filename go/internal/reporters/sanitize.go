package reporters

import (
	"strings"
	"unicode/utf8"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// SanitizeFindings replaces any occurrence of auth credential values
// in finding evidence and fix text with [REDACTED].
// This is a defense-in-depth measure: auth values must never appear in reports.
func SanitizeFindings(findings []models.Finding, authContexts ...*models.AuthContext) []models.Finding {
	var secrets []string
	for _, auth := range authContexts {
		if auth == nil || auth.Value == "" {
			continue
		}
		secrets = append(secrets, auth.Value)

		// Also add the bare token (without "Bearer " prefix) as a secret
		if stripped := strings.TrimPrefix(auth.Value, "Bearer "); stripped != auth.Value {
			secrets = append(secrets, stripped)
		}
		if stripped := strings.TrimPrefix(auth.Value, "Basic "); stripped != auth.Value {
			secrets = append(secrets, stripped)
		}
	}

	if len(secrets) == 0 {
		return findings
	}

	sanitized := make([]models.Finding, len(findings))
	copy(sanitized, findings)

	for i := range sanitized {
		sanitized[i].Evidence = redactSecrets(sanitized[i].Evidence, secrets)
		sanitized[i].Fix = redactSecrets(sanitized[i].Fix, secrets)
		sanitized[i].Title = redactSecrets(sanitized[i].Title, secrets)
	}

	return sanitized
}

func redactSecrets(text string, secrets []string) string {
	for _, secret := range secrets {
		if secret != "" && strings.Contains(text, secret) {
			text = strings.ReplaceAll(text, secret, "[REDACTED]")
		}
	}
	return text
}

// NeutralizeText strips Unicode characters that can be abused to spoof
// the rendered representation of an untrusted finding field — the
// classic "Trojan Source" attack (CVE-2021-42574) plus zero-width and
// raw control-character injection.
//
// It is format-agnostic on purpose: HTML/template auto-escaping and
// fpdf's glyph substitution each protect against a different class of
// attack, but neither neutralizes bidi reordering or invisible control
// chars. Removing them here, BEFORE rendering, means the same defence
// applies to every output format (HTML, PDF, SARIF).
//
// Removed:
//   - Bidi formatting/override controls: U+202A..U+202E (the embedding
//     and override pair) and U+2066..U+2069 (the isolate pair) — these
//     reorder visible text relative to its logical/byte order.
//   - LRM/RLM directional marks: U+200E, U+200F.
//   - Zero-width characters: U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ),
//     U+FEFF (ZWNBSP / BOM) — invisible, used to hide or split tokens.
//   - C0 control chars (U+0000..U+001F) and DEL (U+007F), EXCEPT '\n'
//     and '\t' which formats legitimately use for layout. '\r' is
//     dropped (callers that need CRLF re-add it; a bare CR can mask
//     content in terminals).
//   - C1 control chars (U+0080..U+009F).
//
// Everything else — including legitimate RTL script (Arabic/Hebrew),
// emoji, and CJK — is preserved untouched.
func NeutralizeText(s string) string {
	if s == "" {
		return s
	}
	// Fast path: valid UTF-8 with no characters of interest passes
	// through untouched (the common case for ASCII endpoints/titles).
	if utf8.ValidString(s) && !strings.ContainsFunc(s, isNeutralizeTarget) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	// Decode rune-by-rune so we can also drop invalid UTF-8 bytes.
	// utf8.DecodeRuneInString returns (RuneError, 1) for a malformed
	// byte; emitting a U+FFFD replacement char for attacker-controlled
	// garbage is needless noise, so we skip those bytes entirely.
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			i++ // skip a single invalid byte
			continue
		}
		i += size
		if isNeutralizeTarget(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isNeutralizeTarget reports whether r is a bidi/zero-width/control rune
// that NeutralizeText strips. '\n' and '\t' are explicitly preserved.
func isNeutralizeTarget(r rune) bool {
	switch {
	case r == '\n' || r == '\t':
		return false
	case r < 0x20 || r == 0x7f: // C0 controls + DEL (CR included)
		return true
	case r >= 0x80 && r <= 0x9f: // C1 controls
		return true
	case r >= 0x202a && r <= 0x202e: // bidi embeddings/overrides
		return true
	case r >= 0x2066 && r <= 0x2069: // bidi isolates
		return true
	case r == 0x200e || r == 0x200f: // LRM / RLM
		return true
	case r == 0x200b || r == 0x200c || r == 0x200d: // ZWSP / ZWNJ / ZWJ
		return true
	case r == 0xfeff: // ZWNBSP / BOM
		return true
	default:
		return false
	}
}

// NeutralizeFindings returns a copy of findings with bidi/zero-width/
// control characters stripped from every human-facing text field, so
// renderers (html.go, pdf.go) never emit attacker-controlled invisible
// or reordering characters. The original slice is not mutated.
//
// Fields normalized: Title, Evidence, Fix, Endpoint, Category,
// AffectedEndpoints, and the TaintChain link Expr/File fields. Numeric
// and enum fields (Severity, Confidence, Line, ID) are left alone.
func NeutralizeFindings(findings []models.Finding) []models.Finding {
	out := make([]models.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		out[i].Title = NeutralizeText(out[i].Title)
		out[i].Evidence = NeutralizeText(out[i].Evidence)
		out[i].Fix = NeutralizeText(out[i].Fix)
		out[i].Endpoint = NeutralizeText(out[i].Endpoint)
		out[i].Category = NeutralizeText(out[i].Category)

		if len(out[i].AffectedEndpoints) > 0 {
			eps := make([]string, len(out[i].AffectedEndpoints))
			for j, ep := range out[i].AffectedEndpoints {
				eps[j] = NeutralizeText(ep)
			}
			out[i].AffectedEndpoints = eps
		}

		if len(out[i].TaintChain) > 0 {
			chain := make([]models.TaintLink, len(out[i].TaintChain))
			copy(chain, out[i].TaintChain)
			for j := range chain {
				chain[j].File = NeutralizeText(chain[j].File)
				chain[j].Expr = NeutralizeText(chain[j].Expr)
			}
			out[i].TaintChain = chain
		}
	}
	return out
}

// NeutralizeCoverageMetadata returns a copy of meta with every
// operator-controlled coverage/verdict field neutralized:
// ScannerStatus.Name/Reason/Detail, Coverage.Gaps/RequiredGaps/
// Limitations/RequiredAnalyzers/Retried, and the backend-passthrough
// ReleaseDecision/CoverageState strings. Under `fendix report --input`,
// all of these arrive verbatim from an arbitrary parsed JSON report —
// exactly as untrusted as the finding fields NeutralizeFindings strips.
// All three renderers (html.go, pdf.go, sarif.go) call this before
// rendering or emitting their coverage table / appendix rows / run
// property bag, mirroring the NeutralizeFindings call each already
// makes for findings. DecisionRationale (json.RawMessage) is
// deliberately left untouched: it is opaque, structured data that must
// stay byte-identical.
//
// meta is passed and returned by value: the caller's ScannerStatus slice
// and Coverage value are never mutated, only the local copy's fields are
// reassigned to newly allocated, neutralized copies.
func NeutralizeCoverageMetadata(meta ScanMetadata) ScanMetadata {
	if len(meta.ScannerStatus) > 0 {
		status := make([]ScannerStatus, len(meta.ScannerStatus))
		for i, s := range meta.ScannerStatus {
			status[i] = ScannerStatus{
				Name:     NeutralizeText(s.Name),
				State:    s.State,
				Reason:   ScannerReason(NeutralizeText(string(s.Reason))),
				Detail:   NeutralizeText(s.Detail),
				Attempts: s.Attempts,
			}
		}
		meta.ScannerStatus = status
	}
	if meta.Coverage != nil {
		cov := *meta.Coverage
		cov.Gaps = neutralizeAll(cov.Gaps)
		cov.RequiredGaps = neutralizeAll(cov.RequiredGaps)
		cov.Limitations = neutralizeAll(cov.Limitations)
		cov.RequiredAnalyzers = neutralizeAll(cov.RequiredAnalyzers)
		cov.Retried = neutralizeAll(cov.Retried)
		meta.Coverage = &cov
	}
	meta.ReleaseDecision = NeutralizeText(meta.ReleaseDecision)
	meta.CoverageState = NeutralizeText(meta.CoverageState)
	return meta
}
