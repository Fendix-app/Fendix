package evidence

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// ── Normalized weakness identity for cross-tool correlation ─────────────────
//
// Cross-tool correlation must compare WEAKNESS, not prose: two engines have
// confirmed the same vulnerability only when they name the same CWE at the
// same location. The correlator therefore reads Evidence.Weakness exclusively
// — never free-form References — and this file is the single place that
// weakness identity is derived.
//
// Native fendix rules (Go and Python alike) already emit exact "CWE-NNN"
// tokens as standalone References entries, so derivation is exact-token
// recognition, not text mining. A reference that merely CONTAINS a CWE id
// inside prose or a URL is deliberately not recognized: inventing weakness
// identity from vague text is exactly the guess the correlation design
// forbids (missing weakness must exclude a finding from strong corroboration,
// not be papered over).

// cweTokenRe matches one exact CWE token: "CWE-89" (case-insensitive),
// optionally with an underscore separator, and nothing else in the string.
var cweTokenRe = regexp.MustCompile(`^(?i)cwe[-_](\d{1,5})$`)

// NormalizeCWE canonicalizes a single CWE token to "CWE-<digits>" form
// (uppercased, dash separator, leading zeros stripped). Returns "" when the
// input is not an exact CWE token.
func NormalizeCWE(token string) string {
	m := cweTokenRe.FindStringSubmatch(strings.TrimSpace(token))
	if m == nil {
		return ""
	}
	digits := strings.TrimLeft(m[1], "0")
	if digits == "" {
		return ""
	}
	return "CWE-" + digits
}

// ExtractCWEs returns the sorted, deduped set of normalized CWE ids that
// appear as EXACT tokens in refs. Prose references and URLs contribute
// nothing.
func ExtractCWEs(refs []string) []string {
	seen := map[string]bool{}
	for _, r := range refs {
		if cwe := NormalizeCWE(r); cwe != "" {
			seen[cwe] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// StampWeakness fills Evidence.Weakness in place for NATIVE evidence that
// does not already carry one, from the exact CWE tokens in its References.
// Runs at the normalization boundary BEFORE cross-tool correlation, so the
// correlator receives structured weakness metadata directly.
//
// Imported evidence is NEVER touched: sarifimport already extracted weakness
// from the document's structured metadata (taxa/tags/relationships), and an
// empty Weakness there is a verdict — "no recognizable CWE" — not a gap to
// paper over. Re-deriving it from References would let an import with no
// structured weakness re-enter strong corroboration through its own
// reference strings.
func StampWeakness(evs []Evidence) {
	for i := range evs {
		if evs[i].Source == models.SourceImported {
			continue
		}
		if len(evs[i].Weakness) == 0 {
			evs[i].Weakness = ExtractCWEs(evs[i].References)
		}
	}
}
