package secrets

import (
	"regexp"
	"strings"
)

// ── Synthetic values (RC-10b) ──────────────────────────────────────────────
//
// classifyPlaceholder (placeholder.go) recognised four shapes of fixture value:
// a placeholder word, a dominant-character run, an implausibly short value, and
// a name prefix. Measured on real documentation it recognised 7 of 56 sample
// values: a sample is usually not a word or a run, it is a sequence
// (`ghp_1A2b3C4d5E6f...`), a repeated pattern, a value the provider published
// (AWS's `AKIAIOSFODNN7EXAMPLE`, Stripe's `4eC39HqLyjWDarjtT1zdp7dc`, jwt.io's
// sample token), a template (`<your-token>`), or one of a short list of sample
// credentials everyone writes (`password123`, `changeit`, `P@ssw0rd`).
//
// These signals are value evidence only, deterministic and pure: no clock, no
// network, no model (Constitution Rule 8). They never read the variable name,
// because a name records intent, not the value. A real credential is drawn from
// a high-entropy alphabet and essentially never trips one; the tests check that
// on thousands of provider-shaped random values.

// publishedExamples are values providers and standards documents publish as
// examples. sampleParts reads one as a whole part (publishedPrefixLen takes the first
// that matches, so the whole jwt.io tokens come before their own segments); only
// looksSampleLike, which never lowers a status, still asks whether a value contains one.
var publishedExamples = []string{
	// The jwt.io sample token, whole (the same three publishedJWT accepts).
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
	"AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBEXAMPLE",
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
	"4eC39HqLyjWDarjtT1zdp7dc",                                                   // Stripe's documentation key body
	"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",                                // the jwt.io sample signature
	"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", // the jwt.io sample payload
}

// commonPlaceholderValues are the sample credentials documentation (and test
// fixtures, and quick-start config) write over and over. A value that IS one of
// them, case-insensitively, is a sample wherever it is written: this applies to
// every file, not only documentation.
//
// It is exact, never a substring: `Xpassword-9f3k2` is not `password`.
var commonPlaceholderValues = map[string]struct{}{
	"password": {}, "passw0rd": {}, "p@ssw0rd": {}, "p@ssword": {}, "pass": {}, "passwd": {}, "pa55word": {},
	"admin": {}, "administrator": {}, "root": {}, "secret": {}, "mysecret": {}, "mypassword": {}, "mypass": {},
	"changeit": {}, "changeme": {}, "default": {}, "test": {}, "testing": {}, "demo": {}, "guest": {},
	"user": {}, "username": {}, "123456": {}, "12345678": {}, "1234": {}, "qwerty": {}, "letmein": {},
	"welcome": {}, "hunter2": {}, "foobar": {}, "s3cr3t": {}, "secretpassword": {},
	"yourpassword": {}, "your_password": {}, "your-password": {}, "password123": {},
}

func isCommonPlaceholderValue(value string) bool {
	_, ok := commonPlaceholderValues[strings.ToLower(strings.TrimSpace(value))]
	return ok
}

// tokenPrefixes are the provider signatures stripped before the shape of the
// random body is judged.
var tokenPrefixes = []string{"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk_live_", "sk_test_",
	"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "npm_", "AKIA", "AIzaSy", "AIza", "sk-ant-", "sk-proj-", "sk-svcacct-", "sk-"}

func stripTokenPrefix(v string) string {
	for _, p := range tokenPrefixes {
		if strings.HasPrefix(v, p) {
			return v[len(p):]
		}
	}
	return v
}

const base36 = "0123456789abcdefghijklmnopqrstuvwxyz"

// sequenceRun is the longest run, over every offset of the stride, in which each
// character follows the previous one in base 36 (case-insensitively): `abcdef`,
// `123456`, `a1b2c3` (stride 2), `1A2b3C` (stride 2). dir is +1 ascending, -1
// descending; a decimal wrap 9→0 / 0→9 continues the run.
func sequenceRun(body string, stride, dir int) int {
	best := 0
	for off := 0; off < stride; off++ {
		run, first := 1, true
		var prev byte
		for i := off; i < len(body); i += stride {
			c := body[i]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if first {
				prev, first = c, false
				continue
			}
			ia, ib := strings.IndexByte(base36, prev), strings.IndexByte(base36, c)
			ok := false
			if ia >= 0 && ib >= 0 {
				d := ((ib-ia)%36 + 36) % 36
				if dir > 0 {
					ok = d == 1
				} else {
					ok = d == 35
				}
			}
			if dir > 0 && prev == '9' && c == '0' {
				ok = true
			}
			if dir < 0 && prev == '0' && c == '9' {
				ok = true
			}
			if ok {
				run++
			} else {
				run = 1
			}
			if run > best {
				best = run
			}
			prev = c
		}
	}
	return best
}

var templateMarkerRE = regexp.MustCompile(`(?i)(your[_-]|replace[_-]?me|<[^>]+>|\$\{[^}]+\}|\*{4,})`)

// ── The whole-value rule (CL5, owner ruling OR-89) ─────────────────────────
//
// A credential value is a SAMPLE (a published example, a sequence, a repeated
// character, a template, a placeholder word, a common sample password) only when the
// WHOLE literal value is such a form, optionally with closed-list junk: a placeholder
// word from the scanner's list, a template marker, or a run of separators between two
// such parts. Every signal below is anchored to the whole value. A signal that matches
// only a substring (a digit run inside a longer value, a sample token inside a longer
// value) makes nothing synthetic, and a value that holds anything else keeps v3.7.0's
// status.
//
// This replaces three rounds of heuristics that tried to say how much text beside a
// sample was still junk (a remainder floor, the sample's "natural tail", a trim of the
// joiners, a cut of the token's identity). Each leaked: a real value of eight or more
// characters that begins with a joiner, a real value glued to a variable-length token,
// real characters that continue the sample's own sequence. A whole-value form cannot
// leak: there is no remainder to judge.

// sampleSeparators are the characters that may separate two sample parts. They are
// never part of a sample on their own: a literal that begins or ends with one, or is
// nothing but them, is not a sample.
const sampleSeparators = " \t-_.:/,;|=+"

func isSampleSeparator(c byte) bool { return strings.IndexByte(sampleSeparators, c) >= 0 }

func isAlnumByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// stepOf is +1 when b follows a in base 36 (a decimal 9 is followed by 0), -1 when it
// precedes it, 0 otherwise; case-insensitively, as sequenceRun reads a body.
func stepOf(a, b byte) int {
	lower := func(c byte) byte {
		if c >= 'A' && c <= 'Z' {
			return c + 'a' - 'A'
		}
		return c
	}
	a, b = lower(a), lower(b)
	ia, ib := strings.IndexByte(base36, a), strings.IndexByte(base36, b)
	if ia < 0 || ib < 0 {
		return 0
	}
	switch d := ((ib-ia)%36 + 36) % 36; {
	case d == 1 || (a == '9' && b == '0'):
		return 1
	case d == 35 || (a == '0' && b == '9'):
		return -1
	}
	return 0
}

// sequencePrefix is the length of the ascending or descending run of consecutive
// characters (base 36, case-insensitive) that begins s, at least 1.
func sequencePrefix(s string) int {
	if len(s) < 2 {
		return len(s)
	}
	d := stepOf(s[0], s[1])
	if d == 0 {
		return 1
	}
	n := 2
	for n < len(s) && stepOf(s[n-1], s[n]) == d {
		n++
	}
	return n
}

// repeatPrefix is the length of the run of one repeated character that begins s.
func repeatPrefix(s string) int {
	n := 0
	for n < len(s) && s[n] == s[0] {
		n++
	}
	return n
}

// stridePrefix is the length of the longest prefix of seg that interleaves consecutive
// runs at stride 2 or 3 (`1A2b3C4d...`: the digits count up and the letters count up),
// every offset a run through the whole prefix, or 0 when no such prefix holds at least six
// steps per offset. A hand-typed sample often joins two such runs (`1A2b...9I0j` then
// `K1l2...`), so a segment may be several of these in a row, each a part of its own.
func stridePrefix(seg string) int {
	best := 0
	for _, stride := range [2]int{2, 3} {
		if len(seg) < 6*stride {
			continue
		}
		var dir [3]int
		n := len(seg)
		for i := stride; i < len(seg); i++ {
			st := stepOf(seg[i-stride], seg[i])
			off := i % stride
			if st == 0 || (dir[off] != 0 && st != dir[off]) {
				n = i
				break
			}
			dir[off] = st
		}
		if n >= 6*stride && n > best {
			best = n
		}
	}
	return best
}

// isPeriodicWhole: the character-class pattern (digit / upper / lower / other) of the
// WHOLE body repeats with a period of 2 to 4, across at least 3 classes, in a body of
// at least 24 characters. A hex or all-uppercase alphabet has 1 or 2 classes and
// repeats by chance, so it never counts.
func isPeriodicWhole(body string) bool {
	if len(body) < 24 {
		return false
	}
	cls := make([]byte, len(body))
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c >= '0' && c <= '9':
			cls[i] = 'd'
		case c >= 'A' && c <= 'Z':
			cls[i] = 'U'
		case c >= 'a' && c <= 'z':
			cls[i] = 'l'
		default:
			cls[i] = 'o'
		}
	}
	for p := 2; p <= 4; p++ {
		whole := true
		for i := p; i < len(cls); i++ {
			if cls[i] != cls[i-p] {
				whole = false
				break
			}
		}
		if whole {
			seen := map[byte]bool{}
			for _, c := range cls {
				seen[c] = true
			}
			if len(seen) >= 3 {
				return true
			}
		}
	}
	return false
}

// isLowDiversity: a body of at least 16 characters drawn from at most 4 distinct ones.
// It reads the whole body, so it is whole-value already.
func isLowDiversity(body string) bool {
	if len(body) < 16 {
		return false
	}
	seen := map[rune]bool{}
	for _, c := range body {
		seen[c] = true
	}
	return len(seen) <= 4
}

// The payload and the signature of the sample token jwt.io publishes.
const (
	jwtIOPayload   = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
	jwtIOSignature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)

// publishedJWT: the value is, whole, the sample token jwt.io publishes: its HS256
// header, one of its two published payloads and its published signature, nothing else.
// (The short payload `eyJzdWIiOiIxMjM0NTY3ODkwIn0` belongs to the shortened sample.)
//
// A JWT that only shares a payload or a signature with the sample is another token and
// keeps v3.7.0's status (OR-89, the whole-value rule). Matching one segment let any text
// in the others ride on the published signature: a real token before it (R7-B1), or in
// the payload segment behind a whitespace-led header that still decodes (F8-B1).
func publishedJWT(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	if _, ok := jwtIOHeaders[parts[0]]; !ok {
		return false
	}
	return (parts[1] == jwtIOPayload || parts[1] == jwtIOShortPayload) && parts[2] == jwtIOSignature
}

// The headers of the published jwt.io sample (with and without `typ`).
var jwtIOHeaders = map[string]struct{}{
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9": {}, // {"alg":"HS256","typ":"JWT"}
	"eyJhbGciOiJIUzI1NiJ9":                 {}, // {"alg":"HS256"}
}

const jwtIOShortPayload = "eyJzdWIiOiIxMjM0NTY3ODkwIn0"

// sampleParts reads v left to right as a sequence of sample parts and reports whether
// ALL of it is one. A part is, at the position it starts:
//
//   - a template marker (`your-`, `<paste-token>`, `${VAR}`, `****`);
//   - a provider prefix (`ghp_`, `xoxb-`, `sk_live_`, `AKIA`...), which is not content
//     on its own;
//   - an example a provider or a standard publishes, whole;
//   - a placeholder word from the scanner's list;
//   - a run of eight or more consecutive characters (ascending or descending), a run of
//     eight or more of one character, or a whole alphanumeric segment that interleaves
//     two or three such runs.
//
// Parts may be adjacent, or separated by a run of separators; a separator run is
// allowed only BETWEEN two parts. Any other character, or any alphanumeric text that is
// none of the above, makes the value not a sample.
func sampleParts(v string) bool {
	return partsFrom(v, 0, false, nil)
}

// runCutWindow bounds how far back a run may be cut so the text after it can start a
// part of its own: the longest part that begins inside a run is a placeholder word or a
// `your-...-here` form, a few dozen bytes. The window keeps the parse linear.
const runCutWindow = 32

// partsFrom reads v[i:] as sample parts; content says a part has already been read.
// A run of consecutive or repeated characters is greedy, but the character after it
// can begin a part of its own (`...uvwx` + `your-key-here`: the `y` continues the
// alphabet), so a shorter run of at least eight is tried too. A cut never admits real
// text: the text after the cut must itself read as sample parts. failed records the
// start positions already known not to read, so the whole parse stays linear.
func partsFrom(v string, i int, content bool, failed map[int]struct{}) bool {
	if content {
		if _, bad := failed[i]; bad {
			return false
		}
	}
	start := i
	fail := func() bool {
		if content && failed != nil {
			failed[start] = struct{}{}
		}
		return false
	}
	// try tries the shorter cuts of a run that begins at i with greedy length n.
	try := func(n, min int) bool {
		if failed == nil {
			failed = map[int]struct{}{}
		}
		if partsFrom(v, i+n, true, failed) {
			return true
		}
		for cut := n - 1; cut >= min && cut >= n-runCutWindow; cut-- {
			if partsFrom(v, i+cut, true, failed) {
				return true
			}
		}
		return false
	}
	for i < len(v) {
		c := v[i]
		rest := v[i:]
		// Eight or more of one character is a repeated run, a sample form on its own
		// whatever the character is (`----------`, `..........`, `0000000000`).
		if n := repeatPrefix(rest); n >= 8 {
			if i+n == len(v) {
				return true
			}
			if try(n, 8) {
				return true
			}
			return fail()
		}
		if isSampleSeparator(c) {
			j := i
			for j < len(v) && isSampleSeparator(v[j]) && repeatPrefix(v[j:]) < 8 {
				j++
			}
			if !content || j == len(v) {
				return fail() // a separator is only ever between two parts
			}
			i = j
			continue
		}
		// a placeholder form or a template marker, anchored here
		if c == 'y' || c == 'Y' || c == 'r' || c == 'R' || c == '<' || c == '$' || c == '*' || c == '{' || c == 'c' || c == 'C' || c == 'p' || c == 'P' {
			window := rest
			if len(window) > 256 {
				window = window[:256]
			}
			if m := placeholderFormRE.FindStringIndex(window); m != nil && m[0] == 0 {
				i += m[1]
				content = true
				continue
			}
			if m := templateMarkerRE.FindStringIndex(window); m != nil && m[0] == 0 {
				i += m[1]
				content = true
				continue
			}
		}
		if e := publishedPrefixLen(rest); e > 0 {
			i += e
			content = true
			continue
		}
		if p := tokenPrefixLen(rest); p > 0 {
			i += p
			continue
		}
		if w := placeholderWordLen(rest); w > 0 {
			i += w
			content = true
			continue
		}
		if !isAlnumByte(c) {
			return fail() // a symbol that is not a separator
		}
		j := i
		for j < len(v) && isAlnumByte(v[j]) {
			j++
		}
		seg := v[i:j]
		if n := sequencePrefix(seg); n >= 8 {
			if i+n == len(v) {
				return true
			}
			if try(n, 8) {
				return true
			}
			return fail()
		}
		if n := stridePrefix(seg); n > 0 {
			if i+n == len(v) {
				return true
			}
			if try(n, 12) {
				return true
			}
		}
		return fail()
	}
	return content
}

// placeholderFormRE is the scanner's own list of unambiguous placeholder forms
// (placeholderRE), anchored at the start of a part instead of the whole value, with
// the `{{ name }}` template marker of Helm and Jinja.
var placeholderFormRE = regexp.MustCompile(`(?i)^(?:your[_-][a-z0-9_-]*here|<[^>]+>|\$\{[^}]+\}|\{\{[^}]*\}\}|changeme|placeholder|redacted|x{6,})`)

func tokenPrefixLen(s string) int {
	for _, p := range tokenPrefixes {
		if strings.HasPrefix(s, p) {
			return len(p)
		}
	}
	return 0
}

func publishedPrefixLen(s string) int {
	for _, e := range publishedExamples {
		if strings.HasPrefix(s, e) {
			return len(e)
		}
	}
	return 0
}

func placeholderWordLen(s string) int {
	for _, w := range placeholderValueWords {
		if len(s) >= len(w) && strings.EqualFold(s[:len(w)], w) {
			return len(w)
		}
	}
	return 0
}

// extendedSynthetic reports whether value is, WHOLE, a form classifyPlaceholder's own
// signals do not read: a published example, a sequence, a repeated or periodic body,
// low diversity, a template, a common sample credential, optionally with closed-list
// junk (see the whole-value rule above). A value that merely contains one of these is
// not synthetic.
func extendedSynthetic(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return false
	}
	if isCommonPlaceholderValue(v) || placeholderRE.MatchString(v) || publishedJWT(v) {
		return true
	}
	body := stripTokenPrefix(v)
	if isLowDiversity(body) || isPeriodicWhole(body) {
		return true
	}
	return sampleParts(v)
}

// providerTokenIDs are the rules whose match IS a token. Their regexes find a token
// anywhere in a longer value; the neighbour rule uses them to tell that a value is a
// provider token, which has a finding of its own.
var providerTokenIDs = []string{"AWS_ACCESS_KEY", "GITHUB_TOKEN", "STRIPE_LIVE_KEY", "SLACK_TOKEN", "GOOGLE_API_KEY",
	"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "NPM_TOKEN", "JWT_TOKEN"}

// providerTokenRuleIDs is providerTokenIDs as a set.
var providerTokenRuleIDs = func() map[string]bool {
	m := map[string]bool{}
	for _, id := range providerTokenIDs {
		m[id] = true
	}
	return m
}()

var providerTokenREs = func() []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, id := range providerTokenIDs {
		for _, p := range patterns {
			if p.id == id {
				out = append(out, p.regex)
			}
		}
	}
	return out
}()

// containsProviderToken reports whether v holds a provider-shaped token.
func containsProviderToken(v string) bool {
	for _, re := range providerTokenREs {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

// looksSampleLike is the guard the offline-provable test applies, and it is deliberately
// NOT whole-value: a value that merely CONTAINS a sample signal (a published example, a
// sequence, a repeated or periodic run, a template) is never called provable. Provable
// is what keeps a documentation credential at BLOCK, so the guard errs toward "not
// provable"; the status of a credential in code never reads it.
func looksSampleLike(value string) bool {
	if hasRepeatedChars(value) || len(value) < placeholderMinLen || containsPlaceholderWord(value) || isCommonPlaceholderValue(value) {
		return true
	}
	for _, k := range publishedExamples {
		if strings.Contains(value, k) {
			return true
		}
	}
	body := stripTokenPrefix(value)
	return containsSequence(body) || containsPeriod(body) || isLowDiversity(body) || templateMarkerRE.MatchString(value)
}

// containsSequence: an ascending or descending run of consecutive characters long enough
// that chance does not explain it (8 steps at stride 1, 6 at stride 2 or 3), anywhere in body.
func containsSequence(body string) bool {
	if len(body) < 8 {
		return false
	}
	for _, sn := range [3][2]int{{1, 8}, {2, 6}, {3, 6}} {
		for _, dir := range [2]int{1, -1} {
			if sequenceRun(body, sn[0], dir) >= sn[1] {
				return true
			}
		}
	}
	return false
}

// containsPeriod: the character-class pattern repeats with a period of 2 to 4 for at
// least 24 characters somewhere in body, across at least 3 classes.
func containsPeriod(body string) bool {
	if len(body) < 24 {
		return false
	}
	cls := make([]byte, len(body))
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c >= '0' && c <= '9':
			cls[i] = 'd'
		case c >= 'A' && c <= 'Z':
			cls[i] = 'U'
		case c >= 'a' && c <= 'z':
			cls[i] = 'l'
		default:
			cls[i] = 'o'
		}
	}
	for p := 2; p <= 4; p++ {
		run, start := 0, 0
		for i := p; i < len(cls); i++ {
			if cls[i] == cls[i-p] {
				run++
				if run == 1 {
					start = i - p
				}
				if run+p >= 24 {
					seen := map[byte]bool{}
					for _, c := range cls[start : i+1] {
						seen[c] = true
					}
					if len(seen) >= 3 {
						return true
					}
				}
			} else {
				run = 0
			}
		}
	}
	return false
}

func containsPlaceholderWord(value string) bool {
	lower := strings.ToLower(value)
	for _, w := range placeholderValueWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}
