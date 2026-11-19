package secrets

// CL4 / F5-C3: the per-window index answers what the per-match prefix scans did,
// byte for byte. The oracles below are those prefix scans.

import (
	"math/rand"
	"strings"
	"testing"
	"time"
)

func oracleLastKey(prefix string) string {
	ms := assignmentKeyRe.FindAllStringSubmatch(prefix, -1)
	if len(ms) == 0 {
		return ""
	}
	return ms[len(ms)-1][1]
}

func oracleEnclosingQuote(prefix string) int {
	open := -1
	var quote byte
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		switch {
		case open >= 0 && c == '\\':
			i++
		case open >= 0 && c == quote:
			open = -1
		case open < 0 && (c == '"' || c == '\''):
			open, quote = i, c
		}
	}
	return open
}

func oracleNeighbor(line string, vStart, vEnd int) bool {
	if !strings.ContainsAny(line, `"'`) {
		return false
	}
	for _, m := range jsonCredentialMemberRE.FindAllStringSubmatchIndex(line, -1) {
		s, e := m[2], m[3]
		if s < vEnd && e > vStart {
			continue
		}
		v := line[s:e]
		if strings.Contains(v, "://") || isReferenceValue(v) || containsProviderToken(v) {
			continue
		}
		if !extendedSynthetic(v) {
			return true
		}
	}
	return false
}

func oracleSecretIdentifier(line string, valueStart int, hasValue bool) string {
	if !hasValue || valueStart <= 0 || valueStart > len(line) {
		return ""
	}
	prefix := line[:valueStart]
	if open := oracleEnclosingQuote(prefix); open >= 0 {
		if outer := oracleLastKey(prefix[:open]); outer != "" {
			return outer
		}
	}
	return oracleLastKey(prefix)
}

// randomLine builds a line out of the fragments the three questions read: keys with
// every separator spelling, quotes of both kinds, escapes, brackets, members whose
// values could or could not be real, tokens, junk.
func randomLine(r *rand.Rand) string {
	frag := []string{
		"password", "passwd", "api_key", "secret_key", "token", "tok", "cfg", "x", "A-b_c", "my.key", "9lives",
		"=", ":", " = ", ": ", "\":", "':", "\" :", "' =", "]", "[", "{", "}", "(", ")", ",", ";", " ", "  ", "\t",
		`"`, `'`, `\"`, `\'`, `\\`, `"`, `"`, "`",
		`"password": "`, `'api_token': '`, `"token_url": "`, `"secret": "`,
		"hqG5KSFdPE0SPgQz!7", "changeme", "https://example.test/x", "arn:aws:secretsmanager:us-east-1:123456789012:secret:a",
		"xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx", "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz", "Tr0ub4d!",
		"0123456789", "abc", "Zk4Hq9xP2mLw",
	}
	n := 1 + r.Intn(40)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(frag[r.Intn(len(frag))])
	}
	return b.String()
}

func TestLineIndexAnswersLikeThePrefixScans(t *testing.T) {
	r := rand.New(rand.NewSource(20261119))
	for n := 0; n < 4000; n++ {
		line := randomLine(r)
		ix := newLineIndex(line)
		for k := 0; k < 12; k++ {
			cut := r.Intn(len(line) + 1)
			if got, want := ix.lastKeyBefore(cut), oracleLastKey(line[:cut]); got != want {
				t.Fatalf("lastKeyBefore(%d) = %q, prefix scan %q\nline: %q", cut, got, want, line)
			}
			if got, want := ix.enclosingQuoteBefore(cut), oracleEnclosingQuote(line[:cut]); got != want {
				t.Fatalf("enclosingQuoteBefore(%d) = %d, prefix scan %d\nline: %q", cut, got, want, line)
			}
			if got, want := secretIdentifierIx(ix, cut, true), oracleSecretIdentifier(line, cut, true); got != want {
				t.Fatalf("secretIdentifier at %d = %q, prefix scan %q\nline: %q", cut, got, want, line)
			}
			start := r.Intn(len(line) + 1)
			end := start + r.Intn(len(line)-start+1)
			if got, want := ix.hasNeighbor(start, end), oracleNeighbor(line, start, end); got != want {
				t.Fatalf("hasNeighbor(%d,%d) = %v, loop %v\nline: %q", start, end, got, want, line)
			}
		}
	}
}

// The classification a match gets does not depend on whether the index or the line
// was handed in.
func TestClassifyPlaceholderIndexedEqualsPlain(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for n := 0; n < 2000; n++ {
		line := randomLine(r)
		ix := newLineIndex(line)
		for k := 0; k < 6; k++ {
			start := r.Intn(len(line) + 1)
			end := start + r.Intn(len(line)-start+1)
			v := line[start:end]
			if a, b := classifyPlaceholderIx(ix, start, v), classifyPlaceholder(line, start, v); a != b {
				t.Fatalf("classification differs at %d %q: %+v vs %+v", start, v, a, b)
			}
		}
	}
}

// A line of thousands of tokens costs time in proportion to its length (F5-C3). The
// per-match prefix scans made it quadratic in the tokens of a window. The bound is
// loose on purpose, and the best of three runs is taken: four times the tokens must
// not cost more than about six times the time (a linear scan costs four).
func TestHugeLineOfTokensIsNearLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing")
	}
	line := func(kb int) string {
		var b strings.Builder
		b.WriteString("const tokens = [")
		for b.Len() < kb*1000 {
			b.WriteString(`"xoxb-` + `1234567890-1234567890-abcdefghijklmnopqrstuvwx", `)
		}
		b.WriteString("];\n")
		return b.String()
	}
	best := func(kb int) time.Duration {
		content := line(kb)
		min := time.Duration(1 << 62)
		for i := 0; i < 3; i++ {
			s := time.Now()
			scanOne(t, "bundle.js", content)
			if d := time.Since(s); d < min {
				min = d
			}
		}
		return min
	}
	small, large := best(100), best(400)
	if large > 6*small+200*time.Millisecond {
		t.Errorf("400 KB took %v and 100 KB took %v: more than linear", large, small)
	}
}

// The window's index is built once, however many matches the window holds: the
// work per match is a lookup, not a scan of the line. This is the deterministic
// form of the timing test above, and it fails when any per-match path builds its
// own index again.
func TestWindowIndexIsBuiltOncePerWindow(t *testing.T) {
	builds := map[string]int{}
	lineIndexBuildHook = func(part string) { builds[part]++ }
	defer func() { lineIndexBuildHook = nil }()
	var b strings.Builder
	b.WriteString(`const tokens = [`)
	for b.Len() < 30000 { // under one window: a single window holds every match
		b.WriteString(`"xoxb-` + `1234567890-1234567890-abcdefghijklmnopqrstuvwx", `)
	}
	b.WriteString("];\n")
	fs := scanOne(t, "bundle.js", b.String())
	if len(fs) < 400 {
		t.Fatalf("expected hundreds of findings, got %d", len(fs))
	}
	for _, part := range []string{"keys", "quotes", "members"} {
		if builds[part] != 1 {
			t.Errorf("%s were built %d times for one window of %d matches, want once", part, builds[part], len(fs))
		}
	}
}
