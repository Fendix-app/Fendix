package secrets

import (
	"regexp"
	"strings"
)

// ── Deterministic placeholder classification ───────────────────────────────
//
// Four rules over (line, value). Pure functions, no I/O, no randomness, no
// model in the loop (Constitution Rule 8). The output is an EVIDENCE
// ANNOTATION, never a filter: the finding is emitted either way, at the same
// ID, severity, endpoint and evidence, and the confidence scorer turns the
// annotation into one named negative delta.
//
// This is deliberately NOT implemented by extending isReferenceOrPlaceholder
// or placeholderRE. Those DROP matches, which is suppression and violates
// Rule 3 — and placeholderRE's own comment explains why it must stay narrow:
// "EXAMPLE" appears inside real leaked keys too, and over-suppressing on it
// produces false negatives. A confidence penalty with the evidence intact is
// exactly the treatment that comment says suppression could not give.

// placeholderKeyRe matches an assignment key that announces itself as a
// fixture. Two alternatives, because Go's RE2 has no lookarounds and the two
// naming conventions need different boundary rules:
//
//   - `(?i:word)[_\-]` — a snake/kebab prefix in any case: FAKE_API_KEY,
//     Test_Token, mock-key.
//   - `word[A-Z]` — a camelCase prefix, which is only meaningful when the
//     word itself is lower-case: fakeApiKey, dummyPassword.
//
// The second alternative is deliberately case-SENSITIVE. Making it
// case-insensitive would fire on TESTING_KEY and TESTAMENT (`TEST` followed
// by an upper-case letter), which are not fixture names. The anchoring and
// the required boundary together keep `latest_token`, `testament` and
// `testing_key` quiet while catching every intended shape.
var placeholderKeyRe = regexp.MustCompile(
	`^(?:(?i:fake|test|dummy|mock|example|placeholder|sample)[_\-]` +
		`|(?:fake|test|dummy|mock|example|placeholder|sample)[A-Z])`)

// assignmentKeyRe finds the identifier bound to a value. Applied to the part
// of the line BEFORE the value, with the LAST match winning — the binding
// closest to the value is the one that names it.
//
// The optional `["']?\s*\]?` tolerates subscript targets, so
// `app.config['JWT_SECRET_KEY'] = '…'` resolves to JWT_SECRET_KEY rather than
// to `config`.
var assignmentKeyRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_\-]*)\s*["']?\s*\]?\s*[:=]`)

// placeholderValueWords are words that, appearing anywhere inside the VALUE,
// mark it as fixture material. Case-insensitive.
//
// "test" is deliberately ABSENT: it is a common hex/base64 fragment and it
// hides inside `latest`, `attest` and `contest`. It is covered as a key
// prefix by placeholderKeyRe instead, where the word boundary makes it safe.
var placeholderValueWords = []string{
	"fake", "dummy", "mock", "example", "sample", "placeholder",
	"changeme", "notreal", "foobar", "lorem",
}

// placeholderMinLen is the floor below which a value is too short to be a
// real credential. Bounded on purpose: GENERIC_API_KEY already floors at 20
// and AWS_SECRET_KEY at 40, so this only reaches values that
// HARDCODED_PASSWORD (floor 6) and HARDCODED_SECRET_CONFIG (floor 4) were
// widened to catch — 'test', 'admin', 'secret'.
const placeholderMinLen = 8

// placeholderSignals records WHICH rules fired, not just that one did. The
// per-signal breakdown is what makes a failing classification debuggable and
// is what the table test asserts on.
type placeholderSignals struct {
	NamePrefix    bool // the assignment key is FAKE_/TEST_/… prefixed
	ValueWord     bool // a placeholder word appears inside the value
	RepeatedChars bool // a long identical run, or one byte dominating
	LowLength     bool // shorter than any real credential
	// Extended is a signal synthetic.go adds (RC-10b): a published example, a
	// sequential or periodic run, low diversity, a template marker.
	Extended bool
	// Common is a value on the common-sample-credential list ("password123").
	Common bool
}

// isPlaceholder reports whether any signal fired. Disjunctive on purpose: each
// signal is independently strong enough, and requiring corroboration would
// miss the single most common fixture shape (`FAKE_API_KEY = "<32 hex>"`,
// which trips the name prefix and nothing else).
func (s placeholderSignals) isPlaceholder() bool {
	return s.NamePrefix || s.valueBased()
}

// valueBased reports whether a signal read off the VALUE fired. The name prefix
// is deliberately absent: a name records the intent of whoever wrote the line,
// not the nature of the value, so it never counts as evidence that the value is
// synthetic (evidence.Evidence.SyntheticValue).
func (s placeholderSignals) valueBased() bool {
	return s.ValueWord || s.RepeatedChars || s.LowLength || s.Extended || s.Common
}

// classifyPlaceholder decides whether the credential at value (bound at
// valueStart within line) is fixture-shaped.
//
// An empty value — a signature-only match like GCP_SERVICE_ACCOUNT, or a PEM
// header with nothing after it on the line — carries no evidence either way
// and classifies as not-a-placeholder.
func classifyPlaceholder(line string, valueStart int, value string) placeholderSignals {
	return classifyPlaceholderIx(newLineIndex(line), valueStart, value)
}

// classifyPlaceholderIx is classifyPlaceholder with the line's index supplied, so
// the assignment key left of the value is looked up and not recomputed from the
// start of the line for every match.
func classifyPlaceholderIx(ix *lineIndex, valueStart int, value string) placeholderSignals {
	return classifyPlaceholderLit(ix, valueStart, value, -1, -1)
}

// classifyPlaceholderLit is classifyPlaceholderIx for a credential whose value is
// only part of its literal. A provider's token pattern matches the token inside the
// string it sits in, and whether the credential is a sample is a question about the
// WHOLE literal (the whole-value rule, synthetic.go): the extended signals are read
// from line[litStart:litEnd]; litStart < 0 means the value is the literal. The signals v3.7.0 already had (a placeholder word, a repeated
// character, a short value, the name) read the value, exactly as v3.7.0 did.
func classifyPlaceholderLit(ix *lineIndex, valueStart int, value string, litStart, litEnd int) placeholderSignals {
	if value == "" {
		return placeholderSignals{}
	}
	var s placeholderSignals

	if valueStart > 0 && valueStart <= len(ix.line) {
		if key := ix.lastKeyBefore(valueStart); key != "" {
			s.NamePrefix = placeholderKeyRe.MatchString(key)
		}
	}

	lower := strings.ToLower(value)
	for _, w := range placeholderValueWords {
		if strings.Contains(lower, w) {
			s.ValueWord = true
			break
		}
	}

	s.RepeatedChars = hasRepeatedChars(value)
	s.LowLength = len(value) < placeholderMinLen
	if litStart < 0 {
		s.Common = isCommonPlaceholderValue(value)
		s.Extended = extendedSynthetic(value) && !s.Common
		return s
	}
	literal := ix.line[litStart:litEnd]
	s.Common = isCommonPlaceholderValue(value) || isCommonPlaceholderValue(literal)
	s.Extended = ix.extendedSpan(litStart, litEnd) && !s.Common
	return s
}

// lastAssignmentKey returns the identifier from the LAST assignmentKeyRe match
// in prefix, or "" when there is none.
func lastAssignmentKey(prefix string) string {
	ms := assignmentKeyRe.FindAllStringSubmatch(prefix, -1)
	if len(ms) == 0 {
		return ""
	}
	return ms[len(ms)-1][1]
}

// hasRepeatedChars reports whether v has a run of >= 8 identical bytes, or a
// single byte occupying >= 60% of it. Real credentials are drawn from a
// high-entropy alphabet and essentially never do either; hand-written
// fixtures (`ghp_` + 36 A's) routinely do both.
//
// Byte-wise rather than rune-wise on purpose: credential alphabets are ASCII,
// and a multi-byte value that trips this is padding either way.
func hasRepeatedChars(v string) bool {
	if len(v) < 8 {
		return false
	}
	run, best := 1, 1
	for i := 1; i < len(v); i++ {
		if v[i] == v[i-1] {
			run++
			if run > best {
				best = run
			}
		} else {
			run = 1
		}
	}
	if best >= 8 {
		return true
	}
	var counts [256]int
	for i := 0; i < len(v); i++ {
		counts[v[i]]++
	}
	max := 0
	for _, c := range counts {
		if c > max {
			max = c
		}
	}
	return max*100 >= 60*len(v)
}

// providerAnchoredRules are the rules whose REGEX anchors a provider's own
// token signature — an `AKIA…` key id, `gh[opusr]_` + 36 chars, `sk_live_…`,
// `xox[abprs]-…`, `AIza…`, `sk-ant-…`, `sk-…` (OpenAI), `npm_…`, or a PEM
// private-key header.
//
// Membership means the match is anchored on the credential's OWN shape rather
// than on a surrounding assignment. That distinction is what the flag is for:
// the placeholder heuristics include a signal read off the variable NAME, and a
// name records the intent of whoever wrote the line, not the nature of the
// value. `TEST_STRIPE_KEY = "sk_live_…"` is a live key with a misleading
// label; the label must not be allowed to push it below WARN.
//
// The generic rules are deliberately EXCLUDED. GENERIC_API_KEY,
// HARDCODED_PASSWORD, HARDCODED_SECRET_CONFIG, ENV_SECRET, JWT_* and
// DB_CONNECTION_STRING match an assignment SHAPE around an arbitrary value, so
// a fixture is exactly what they most often find — those are the findings the
// fixture de-escalation exists to grade, and vetoing it for them would restore
// the noise this is meant to reduce.
//
// GCP_SERVICE_ACCOUNT is a signature-only match with no value to classify, so
// it is anchored too: nothing about it can be read as fixture-shaped.
var providerAnchoredRules = map[string]bool{
	"AWS_ACCESS_KEY":      true,
	"AWS_SECRET_KEY":      true,
	"PRIVATE_KEY":         true,
	"GITHUB_TOKEN":        true,
	"STRIPE_LIVE_KEY":     true,
	"SLACK_TOKEN":         true,
	"GOOGLE_API_KEY":      true,
	"ANTHROPIC_API_KEY":   true,
	"OPENAI_API_KEY":      true,
	"NPM_TOKEN":           true,
	"GCP_SERVICE_ACCOUNT": true,
}

// isProviderAnchored reports whether a rule id matches a provider's own token
// signature. See providerAnchoredRules.
func isProviderAnchored(ruleID string) bool { return providerAnchoredRules[ruleID] }
