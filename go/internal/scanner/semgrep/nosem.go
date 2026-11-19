package semgrep

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// A `// nosemgrep` comment must not silence a finding silently (redteam3-
// semgrep-01). The run passes --disable-nosem, so Semgrep reports every match,
// and the engine applies the comment itself: a result whose first line, or
// whose preceding comment-only line, carries a nosemgrep comment that names the
// rule (or no rule) is removed from the findings and reported in Run.Suppressed,
// from which the orchestrator lists each one in the Semgrep ok detail and, in
// full, in the report's metadata.coverage.limitations.
//
// The engine's reading is a subset of Semgrep's, checked against the real
// binary (nosem_test.go): where Semgrep would suppress a result and the engine
// cannot be sure, the result is kept as a finding. Semgrep itself matches
// " nosem" anywhere on the line, a string literal and a word prefix included
// (`"SELECT nosemantic ..." + x`), so a careless or hostile line could hide a
// real finding. The engine reads Semgrep's comment syntax only (redteam4-
// semgrep-01):
//
//   - "nosemgrep" or "nosem" is a whole token inside a COMMENT of the file's
//     language (# for Python; // and /* ... */ for JavaScript, TypeScript, Java
//     and Go), found by reading the line with its string literals skipped, and
//     preceded by a blank; "nosemantic", "nosem-x" and "nosem_x" are not it;
//   - it may be followed by ":" or "=" and a comma-separated list of rule ids;
//   - the comment is on the match's first line, after the match starts (a match
//     on a later line of the match does not count), or the line before the
//     match is only a comment that begins with the token;
//   - a listed id suppresses the rule it equals or ends, at a dot, with
//     ("js-sqli-taint" suppresses "tmp.fendix-semgrep-rules-1.js-sqli-taint");
//     "nosemgrep" with no id suppresses every rule.

var (
	nosemToken = regexp.MustCompile(`(?i)(?:^|\s)nosem(?:grep)?`)
	nosemIDs   = regexp.MustCompile(`^[:=]\s?([^,\s]+(?:,[^,\s]*)*)`)
)

// commentSyntax is how a language writes a comment.
type commentSyntax struct {
	line, block []string // comment openers
	quotes      string   // string delimiters
	triple      bool     // a tripled quote opens a multi-line string
}

var (
	syntaxPython = commentSyntax{line: []string{"#"}, quotes: "'\"", triple: true}
	syntaxC      = commentSyntax{line: []string{"//"}, block: []string{"/*"}, quotes: "'\"`"}
	// syntaxAny is for a file whose language is not known: every opener counts.
	syntaxAny = commentSyntax{line: []string{"#", "//", "--"}, block: []string{"/*", "<!--"}, quotes: "'\"`"}
)

// syntaxOf is the comment syntax of the file at rel.
func syntaxOf(rel string) commentSyntax {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".py", ".pyi":
		return syntaxPython
	case ".js", ".jsx", ".cjs", ".mjs", ".ts", ".tsx", ".mts", ".cts", ".es6", ".java", ".go":
		return syntaxC
	}
	return syntaxAny
}

type commentAt struct {
	at   int
	text string
}

// comments returns the comments of line, each from its opener to its end (the
// end of the line, or the closing marker of a block), with the byte offset
// where it starts. String literals are skipped, so an opener inside one is not
// a comment.
func (cs commentSyntax) comments(line string) (out []commentAt) {
	var quote byte
	triple := false
	for i := 0; i < len(line); {
		c := line[i]
		if quote != 0 {
			switch {
			case c == '\\' && !triple:
				i += 2
			case triple && strings.HasPrefix(line[i:], strings.Repeat(string(quote), 3)):
				quote, triple = 0, false
				i += 3
			case !triple && c == quote:
				quote = 0
				i++
			default:
				i++
			}
			continue
		}
		if strings.IndexByte(cs.quotes, c) >= 0 {
			if cs.triple && strings.HasPrefix(line[i:], strings.Repeat(string(c), 3)) {
				quote, triple = c, true
				i += 3
				continue
			}
			quote = c
			i++
			continue
		}
		opened := false
		for _, op := range cs.line {
			if strings.HasPrefix(line[i:], op) {
				return append(out, commentAt{i, line[i:]})
			}
		}
		for _, op := range cs.block {
			if !strings.HasPrefix(line[i:], op) {
				continue
			}
			closer := "*/"
			if op == "<!--" {
				closer = "-->"
			}
			end := len(line)
			if j := strings.Index(line[i+len(op):], closer); j >= 0 {
				end = i + len(op) + j + len(closer)
			}
			out = append(out, commentAt{i, line[i:end]})
			i = end
			opened = true
			break
		}
		if !opened {
			i++
		}
	}
	return out
}

// commentOnly reports whether line is nothing but a comment and returns its
// text after the opener.
func (cs commentSyntax) commentOnly(line string) (string, bool) {
	t := strings.TrimSpace(line)
	for _, op := range append(append([]string(nil), cs.line...), cs.block...) {
		if strings.HasPrefix(t, op) {
			return strings.TrimPrefix(t, op), true
		}
	}
	// A continuation line of a block comment.
	if len(cs.block) > 0 && strings.HasPrefix(t, "*") {
		return strings.TrimPrefix(t, "*"), true
	}
	return "", false
}

// tokenIn finds the nosemgrep token in text and returns the rule ids it lists
// (nil for none) and whether a token was found. The token must end at a
// non-word character: "nosemantic" and "nosem-x" are not it.
func tokenIn(text string) (ids []string, found bool) {
	for _, loc := range nosemToken.FindAllStringIndex(text, -1) {
		rest := text[loc[1]:]
		if rest != "" {
			c := rest[0]
			if c == '_' || c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
				continue
			}
		}
		return idsOf(rest), true
	}
	return nil, false
}

// idsOf is the rule ids a nosemgrep token lists in rest, the text after it:
// nil for a bare nosemgrep.
func idsOf(rest string) []string {
	m := nosemIDs.FindStringSubmatch(rest)
	if m == nil || m[1] == "" {
		return nil
	}
	var ids []string
	for _, id := range strings.Split(m[1], ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

func ruleNamed(checkID string, ids []string) bool {
	for _, id := range ids {
		if checkID == id || strings.HasSuffix(checkID, "."+id) {
			return true
		}
	}
	return false
}

// nosemSuppresses reports whether a nosemgrep comment on the match's first
// line (after the match starts at column col, 1-based; 0 when unknown) or on
// the comment-only line before it suppresses the rule checkID. cs is the
// comment syntax of the file.
func nosemSuppresses(checkID, first, prev string, cs commentSyntax, col int) bool {
	for _, c := range cs.comments(first) {
		if col > 0 && c.at < col-1 {
			continue
		}
		if ids, ok := tokenIn(c.text); ok && (ids == nil || ruleNamed(checkID, ids)) {
			return true
		}
	}
	if text, ok := cs.commentOnly(prev); ok {
		// The token is the first word of the comment, as in Semgrep.
		probe := " " + strings.TrimLeft(text, " \t*/!#-")
		if m := nosemToken.FindStringIndex(probe); m != nil && m[0] == 0 {
			if ids, ok := tokenIn(probe); ok && (ids == nil || ruleNamed(checkID, ids)) {
				return true
			}
		}
	}
	return false
}

// Suppressed is one result a nosemgrep comment removed from the findings.
type Suppressed struct {
	RuleID string // the bundled rule id, as a finding's RuleID
	Path   string // relative to the scan root, forward slashes
	Line   int
}

// sourceLines caches the lines of the files results point at.
type sourceLines struct {
	root  string
	cache map[string][]string
}

func (s *sourceLines) get(rel string) []string {
	if lines, ok := s.cache[rel]; ok {
		return lines
	}
	var lines []string
	if info, err := os.Stat(filepath.Join(s.root, filepath.FromSlash(rel))); err == nil && info.Mode().IsRegular() && info.Size() <= scope.MaxFileBytes {
		if data, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(rel))); err == nil {
			lines = strings.Split(string(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))), "\n")
		}
	}
	if s.cache == nil {
		s.cache = map[string][]string{}
	}
	s.cache[rel] = lines
	return lines
}

// splitSuppressed separates the results a nosemgrep comment suppresses from the
// rest, in the order Semgrep reported them.
func splitSuppressed(results []semgrepResult, absRoot string) (kept []semgrepResult, suppressed []Suppressed) {
	src := &sourceLines{root: absRoot}
	for _, r := range results {
		rel := relPath(r.Path, absRoot)
		lines := src.get(rel)
		if r.Start.Line < 1 || r.Start.Line > len(lines) {
			kept = append(kept, r)
			continue
		}
		first := lines[r.Start.Line-1]
		prev := ""
		if r.Start.Line >= 2 {
			prev = lines[r.Start.Line-2]
		}
		if nosemSuppresses(r.CheckID, first, prev, syntaxOf(rel), r.Start.Col) {
			suppressed = append(suppressed, Suppressed{RuleID: normalizeCheckID(r.CheckID), Path: rel, Line: r.Start.Line})
			continue
		}
		kept = append(kept, r)
	}
	return kept, suppressed
}
