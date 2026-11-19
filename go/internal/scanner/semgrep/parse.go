package semgrep

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// Decision D1' (round 4), tightened by C4B-27 (round 5): a Semgrep parse problem
// that prevents evaluating an in-scope file is a coverage gap.
//
//   - A whole-file failure (parseFailureTypes) is a ParseFailure: Semgrep ran no
//     rule on the file. ScanRun records it as lost evaluation, the file named.
//   - "PartialParsing" is a PartialParse: Semgrep matched what it could parse
//     and reports the spans it skipped (in the error's type, and again in its
//     `spans`). The run stays ok for the file only when the engine can SHOW that
//     the skipped lines hold no analysable code: every span is reported, lies
//     inside the file, and every line it touches is blank or a whole-line
//     comment (spansHoldNoCode). A skipped line of code, however few the lines
//     or small the share of the file, is lost evaluation like a whole-file
//     failure: a skipped long line can hold the very handler a rule exists to
//     read (round 4 allowed up to 5% of a file by line count, which is how a
//     one-line skip of the vulnerable statement stayed "ok").
//
// Real Semgrep 1.182.1 behaviour (testdata/runs/partial-*.json and the
// real-Semgrep tests): after a syntax error inside a class body, tree-sitter
// skips the REST of the class, so one error can leave most of a file
// unevaluated, and the span says so; a one-token error skips one token, and the
// line it is on is then code.

// Span is a range of lines Semgrep skipped, 1-based and inclusive.
type Span struct {
	StartLine, EndLine int
}

// ParseFailure is a file Semgrep could not parse at all.
type ParseFailure struct {
	Type string // Semgrep's error type, "Syntax error"
	Path string // relative to the scan root, forward slashes
}

// PartialParse is a file Semgrep parsed only in part, with the lines it skipped.
type PartialParse struct {
	Path  string // relative to the scan root, forward slashes
	Spans []Span // every skipped span the run reported for the file, merged
	// Reported is false when an entry for the file carried no usable span, so
	// what was skipped is not known.
	Reported bool
	// Skipped is how many lines the spans cover; Total is the file's lines. Both
	// are set by ScanRun, which reads the file.
	Skipped, Total int
	// Lost is set by ScanRun when the run may not stay ok for the file: its
	// spans are not reported, or cover a line that holds code (spansHoldNoCode).
	Lost bool
}

type spanLoc struct {
	Line int `json:"line"`
}

type rawSpan struct {
	Start spanLoc `json:"start"`
	End   spanLoc `json:"end"`
}

// typeSpans reads the spans of a ["PartialParsing", [ {path, start, end}, ... ]]
// type; ok is false when the type carries no list.
func typeSpans(raw json.RawMessage) (spans []Span, ok bool) {
	var parts []json.RawMessage
	if json.Unmarshal(raw, &parts) != nil || len(parts) < 2 {
		return nil, false
	}
	var list []rawSpan
	if json.Unmarshal(parts[1], &list) != nil {
		return nil, false
	}
	return toSpans(list), true
}

func toSpans(list []rawSpan) []Span {
	var out []Span
	for _, r := range list {
		if r.Start.Line > 0 && r.End.Line >= r.Start.Line {
			out = append(out, Span{r.Start.Line, r.End.Line})
		}
	}
	return out
}

// mergeSpans orders spans and joins overlapping or touching ones.
func mergeSpans(spans []Span) []Span {
	if len(spans) == 0 {
		return nil
	}
	s := append([]Span(nil), spans...)
	sort.Slice(s, func(i, j int) bool { return s[i].StartLine < s[j].StartLine })
	out := []Span{s[0]}
	for _, sp := range s[1:] {
		last := &out[len(out)-1]
		if sp.StartLine <= last.EndLine+1 {
			if sp.EndLine > last.EndLine {
				last.EndLine = sp.EndLine
			}
			continue
		}
		out = append(out, sp)
	}
	return out
}

func skippedLines(spans []Span) int {
	n := 0
	for _, sp := range mergeSpans(spans) {
		n += sp.EndLine - sp.StartLine + 1
	}
	return n
}

// parseFailures decodes the whole-file parse failures of a document's `errors`.
func parseFailures(raw json.RawMessage, absRoot string) []ParseFailure {
	entries, _ := errorEntries(raw)
	var out []ParseFailure
	for _, entry := range entries {
		var e semgrepErrorDetail
		if json.Unmarshal(entry, &e) != nil || !e.perFile() || !IsParseFailureType(e.typeTag()) {
			continue
		}
		pf := ParseFailure{Type: e.typeTag()}
		if p := e.path(); p != "" {
			pf.Path = relPath(p, absRoot)
		}
		out = append(out, pf)
	}
	return out
}

// partialParses decodes the PartialParsing entries of a document's `errors`,
// one PartialParse per file.
func partialParses(raw json.RawMessage, absRoot string) []PartialParse {
	entries, _ := errorEntries(raw)
	var order []string
	byPath := map[string]*PartialParse{}
	for _, entry := range entries {
		var e struct {
			semgrepErrorDetail
			Spans []rawSpan `json:"spans"`
		}
		if json.Unmarshal(entry, &e) != nil || !e.perFile() || e.typeTag() != partialParsingType {
			continue
		}
		path := ""
		if p := e.path(); p != "" {
			path = relPath(p, absRoot)
		}
		pp, ok := byPath[path]
		if !ok {
			pp = &PartialParse{Path: path, Reported: true}
			byPath[path] = pp
			order = append(order, path)
		}
		spans, has := typeSpans(e.Type)
		if !has || len(spans) == 0 {
			spans = toSpans(e.Spans)
		}
		if len(spans) == 0 || path == "" {
			pp.Reported = false
			continue
		}
		pp.Spans = append(pp.Spans, spans...)
	}
	out := make([]PartialParse, 0, len(order))
	for _, path := range order {
		pp := byPath[path]
		pp.Spans = mergeSpans(pp.Spans)
		out = append(out, *pp)
	}
	return out
}

// readSource reads the file at p, which is at most scope.MaxFileBytes, without
// blocking on a FIFO or following a link. nil when it cannot be read.
func readSource(p string) []byte {
	f, err := scope.OpenRegular(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, scope.MaxFileBytes+1))
	if err != nil || len(data) > scope.MaxFileBytes {
		return nil
	}
	return data
}

// splitLines is the lines of data without their terminators: a final line with
// no newline counts, an empty file has none.
func splitLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}

// lineCommentOf is the marker of a whole-line comment in a file of the given
// extension, "" for a language the engine does not know it for.
func lineCommentOf(ext string) string {
	switch strings.ToLower(ext) {
	case ".py", ".pyi":
		return "#"
	case ".js", ".jsx", ".cjs", ".mjs", ".es6", ".ts", ".tsx", ".cts", ".mts", ".java", ".go", ".vue":
		return "//"
	}
	return ""
}

// DE5-07 (RC-1): the judge sees the language's own lines. Semgrep numbers lines
// by "\n" alone, whatever the language does with the file: a bare CR ends a
// Python, JavaScript or Java line (and so does U+2028 or U+2029 in JavaScript),
// and a line that starts with "//" or "#" is not a comment line when it starts
// inside a template literal, an f-string, a JSX text, a text block or a block
// comment. The old judge split on "\n" and looked at each line alone, so it
// called "// ${eval(x) ...}" inside a template, "# {os.system(x)}" inside an
// f-string and "# note\rexec(y)" harmless, and the run stayed ok over code Semgrep
// had skipped.
//
// wse1LineModel splits the file into the language's own lines and says, for each,
// whether the language is in plain code at its first byte: not inside a string,
// a template, a block comment, a JSX text, and not past a point where the
// scanner below can no longer tell. Only such a line can be a whole-line
// comment. The scanner is deliberately conservative: where the language is
// ambiguous (a "/" that may begin a regular expression, a "<" that may begin
// JSX, an unterminated string, an f-string field it cannot close) it stops
// trusting itself for the rest of the file, and every later line reads as code.
// An error of that kind costs a file that should have stayed ok its "ok", never
// a skipped line of code its "inert".

type wse1Lang int

const (
	wse1LangNone wse1Lang = iota
	wse1LangPython
	wse1LangJS // JavaScript and TypeScript, JSX included
	wse1LangJava
	wse1LangGo
	wse1LangVue // a single-file component: the template is text with interpolations
)

func wse1LangOf(ext string) wse1Lang {
	switch strings.ToLower(ext) {
	case ".py", ".pyi":
		return wse1LangPython
	case ".js", ".jsx", ".cjs", ".mjs", ".es6", ".ts", ".tsx", ".cts", ".mts":
		return wse1LangJS
	case ".java":
		return wse1LangJava
	case ".go":
		return wse1LangGo
	case ".vue":
		return wse1LangVue
	}
	return wse1LangNone
}

// terminator is the length of the line terminator at data[i] in the language, 0
// when there is none. A Python or Java line ends at \n, \r or \r\n; a
// JavaScript one also at U+2028 and U+2029; a Go one at \n only (a \r is blank
// space there); a file in a language the engine does not know ends lines at \n.
func (l wse1Lang) terminator(data []byte, i int) int {
	switch data[i] {
	case '\n':
		return 1
	case '\r':
		switch l {
		case wse1LangNone, wse1LangGo:
			return 0
		}
		if i+1 < len(data) && data[i+1] == '\n' {
			return 2
		}
		return 1
	case 0xE2:
		if (l == wse1LangJS || l == wse1LangVue) && i+2 < len(data) && data[i+1] == 0x80 && (data[i+2] == 0xA8 || data[i+2] == 0xA9) {
			return 3
		}
	}
	return 0
}

// wse1LangLine is one line of the language: data[start:end], its terminator
// excluded; lf is the number of the "\n"-delimited line (the numbering Semgrep
// reports) it lies in; plain says the language is in plain code at start.
type wse1LangLine struct {
	start, end int
	lf         int
	plain      bool
}

func wse1SplitLanguageLines(data []byte, lang wse1Lang) []wse1LangLine {
	var out []wse1LangLine
	start, lf := 0, 1
	for i := 0; i < len(data); {
		n := lang.terminator(data, i)
		if n == 0 {
			i++
			continue
		}
		out = append(out, wse1LangLine{start: start, end: i, lf: lf})
		if data[i+n-1] == '\n' {
			lf++
		}
		i += n
		start = i
	}
	if start < len(data) {
		out = append(out, wse1LangLine{start: start, end: len(data), lf: lf})
	}
	return out
}

// wse1Lexer finds, in one pass over a file, the lines that start inside a token
// that spans lines, and the offset from which it no longer trusts itself.
type wse1Lexer struct {
	data        []byte
	lang        wse1Lang
	starts      []int  // the offset each language line starts at
	nonPlain    []bool // per language line: it starts inside a multi-line token
	uncertainAt int    // -1, or the offset from which every line reads as code
	nest        int    // how deep template expressions and f-string fields are nested
}

// wse1MaxNest bounds that nesting: a file that nests deeper is not followed.
const wse1MaxNest = 64

// mark records data[s:e] as one token that may span lines: every line that
// starts strictly inside it is not in plain code.
func (x *wse1Lexer) mark(s, e int) {
	for k := sort.SearchInts(x.starts, s+1); k < len(x.starts) && x.starts[k] < e; k++ {
		x.nonPlain[k] = true
	}
}

func (x *wse1Lexer) uncertain(at int) {
	if x.uncertainAt < 0 || at < x.uncertainAt {
		x.uncertainAt = at
	}
}

// lineEnd is the offset of the terminator that ends the line holding data[i], or
// len(data).
func (x *wse1Lexer) lineEnd(i int) int {
	for i < len(x.data) && x.lang.terminator(x.data, i) == 0 {
		i++
	}
	return i
}

func wse1IdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

func wse1LineModel(data []byte, lang wse1Lang) []wse1LangLine {
	lines := wse1SplitLanguageLines(data, lang)
	x := &wse1Lexer{data: data, lang: lang, starts: make([]int, len(lines)), nonPlain: make([]bool, len(lines)), uncertainAt: -1}
	for i, l := range lines {
		x.starts[i] = l.start
	}
	switch lang {
	case wse1LangPython:
		x.pyCode()
	case wse1LangJS:
		x.jsCode(0, false)
	case wse1LangJava:
		x.javaCode()
	case wse1LangGo:
		x.goCode()
	default:
		x.uncertain(0) // a Vue template, or a language the engine has no lexer for
	}
	for i := range lines {
		lines[i].plain = !x.nonPlain[i] && (x.uncertainAt < 0 || lines[i].start <= x.uncertainAt)
	}
	return lines
}

// ---- JavaScript and TypeScript ---------------------------------------------

// What came before a "/" or a "<" decides whether it begins a regular expression
// or JSX, or is an operator.
type wse1Prev int

const (
	wse1PrevStart     wse1Prev = iota // nothing yet: an expression may start
	wse1PrevOperand                   // an identifier, number, string, template, regex or "]": an operator follows
	wse1PrevPunct                     // an operator or an opening bracket: an expression may start
	wse1PrevCloseBody                 // ")" or "}": a "/" here is ambiguous
	wse1PrevAmbiguous                 // "++" or "--"
)

// wse1RegexKeywords are the words after which "/" begins a regular expression.
var wse1RegexKeywords = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true, "of": true, "new": true,
	"delete": true, "void": true, "throw": true, "case": true, "do": true, "else": true, "yield": true, "await": true,
}

// jsCode lexes JavaScript from i. With inExpr it is the code of a template's
// ${ ... } and returns the offset after the "}" that closes it; otherwise it
// runs to the end of the file.
func (x *wse1Lexer) jsCode(i int, inExpr bool) int {
	d := x.data
	depth := 0
	prev := wse1PrevStart
	if i == 0 && len(d) >= 2 && d[0] == '#' && d[1] == '!' {
		i = x.lineEnd(0) // a hashbang line is a comment
	}
	for i < len(d) {
		c := d[i]
		if n := x.lang.terminator(d, i); n > 0 {
			i += n
			continue
		}
		switch {
		case c == ' ' || c == '\t' || c == '\f' || c == '\v':
			i++
		case c == '/' && i+1 < len(d) && d[i+1] == '/':
			i = x.lineEnd(i)
		case c == '/' && i+1 < len(d) && d[i+1] == '*':
			end := bytes.Index(d[i+2:], []byte("*/"))
			if end < 0 {
				x.mark(i, len(d))
				return len(d)
			}
			x.mark(i, i+2+end+2)
			i += 2 + end + 2
		case c == '\'' || c == '"':
			i = x.jsString(i)
			prev = wse1PrevOperand
		case c == '`':
			i = x.jsTemplate(i)
			prev = wse1PrevOperand
		case c == '/':
			switch prev {
			case wse1PrevStart, wse1PrevPunct:
				i = x.jsRegex(i)
				prev = wse1PrevOperand
			case wse1PrevOperand:
				i++
				if i < len(d) && d[i] == '=' {
					i++
				}
				prev = wse1PrevPunct
			default:
				x.uncertain(i) // a division, or a regular expression after a block or a condition
				i++
				prev = wse1PrevPunct
			}
		case c == '<':
			if i+1 < len(d) && (wse1IdentByte(d[i+1]) || d[i+1] == '>') && prev != wse1PrevOperand {
				x.uncertain(i) // JSX (or a TypeScript type assertion): its text is not code
			}
			i++
			prev = wse1PrevPunct
		case c == '+' || c == '-':
			if i+1 < len(d) && d[i+1] == c {
				i += 2
				prev = wse1PrevAmbiguous
			} else {
				i++
				prev = wse1PrevPunct
			}
		case c == '{':
			depth++
			i++
			prev = wse1PrevPunct
		case c == '}':
			if inExpr && depth == 0 {
				return i + 1
			}
			if depth > 0 {
				depth--
			}
			i++
			prev = wse1PrevCloseBody
		case c == ')':
			i++
			prev = wse1PrevCloseBody
		case c == ']':
			i++
			prev = wse1PrevOperand
		case c >= '0' && c <= '9':
			for i < len(d) && (wse1IdentByte(d[i]) || d[i] == '.' || (d[i] == '+' || d[i] == '-') && (d[i-1] == 'e' || d[i-1] == 'E')) {
				i++
			}
			prev = wse1PrevOperand
		case wse1IdentByte(c) || c == '\\' && i+1 < len(d) && d[i+1] == 'u':
			start := i
			for i < len(d) && (wse1IdentByte(d[i]) || d[i] == '\\' && i+1 < len(d) && d[i+1] == 'u') {
				if d[i] == '\\' {
					i++
				}
				i++
			}
			if wse1RegexKeywords[string(d[start:i])] {
				prev = wse1PrevPunct
			} else {
				prev = wse1PrevOperand
			}
		default:
			i++
			prev = wse1PrevPunct
		}
	}
	if inExpr {
		x.uncertain(len(d)) // a template's ${ never closed
	}
	return len(d)
}

// jsString lexes a '...' or "..." string from i and returns the offset after it.
// A backslash before a line terminator continues the string; any other
// terminator in it is an unterminated string, which the lexer cannot follow.
func (x *wse1Lexer) jsString(i int) int {
	d := x.data
	q := d[i]
	for j := i + 1; j < len(d); {
		switch c := d[j]; {
		case c == '\\':
			j++
			if j < len(d) {
				if n := x.lang.terminator(d, j); n > 0 {
					j += n
				} else {
					j++
				}
			}
		case c == q:
			x.mark(i, j+1)
			return j + 1
		case x.lang.terminator(d, j) > 0:
			x.uncertain(i)
			x.mark(i, j)
			return j
		default:
			j++
		}
	}
	x.uncertain(i)
	x.mark(i, len(d))
	return len(d)
}

// jsTemplate lexes a template literal from i, expressions included.
func (x *wse1Lexer) jsTemplate(i int) int {
	d := x.data
	for j := i + 1; j < len(d); {
		switch {
		case d[j] == '\\':
			j += 2
		case d[j] == '`':
			x.mark(i, j+1)
			return j + 1
		case d[j] == '$' && j+1 < len(d) && d[j+1] == '{':
			if x.nest >= wse1MaxNest {
				x.uncertain(i)
				x.mark(i, len(d))
				return len(d)
			}
			x.nest++
			j = x.jsCode(j+2, true)
			x.nest--
		default:
			j++
		}
	}
	x.uncertain(i)
	x.mark(i, len(d))
	return len(d)
}

// jsRegex lexes a regular expression literal from the "/" at i.
func (x *wse1Lexer) jsRegex(i int) int {
	d := x.data
	inClass := false
	for j := i + 1; j < len(d); {
		switch c := d[j]; {
		case x.lang.terminator(d, j) > 0:
			x.uncertain(i)
			return j
		case c == '\\':
			j += 2
		case c == '[':
			inClass = true
			j++
		case c == ']':
			inClass = false
			j++
		case c == '/' && !inClass:
			j++
			for j < len(d) && wse1IdentByte(d[j]) {
				j++
			}
			return j
		default:
			j++
		}
	}
	x.uncertain(i)
	return len(d)
}

// ---- Java and Go -----------------------------------------------------------

// javaCode lexes Java: comments, strings, text blocks and character literals.
// (JLS 3.3 unicode escapes are not translated: R6-E7, held for the owner.)
func (x *wse1Lexer) javaCode() { x.cFamily(false) }

// goCode lexes Go: comments, strings, raw strings and rune literals.
func (x *wse1Lexer) goCode() { x.cFamily(true) }

func (x *wse1Lexer) cFamily(goLang bool) {
	d := x.data
	for i := 0; i < len(d); {
		c := d[i]
		switch {
		case c == '/' && i+1 < len(d) && d[i+1] == '/':
			i = x.lineEnd(i)
		case c == '/' && i+1 < len(d) && d[i+1] == '*':
			end := bytes.Index(d[i+2:], []byte("*/"))
			if end < 0 {
				x.mark(i, len(d))
				return
			}
			x.mark(i, i+2+end+2)
			i += 2 + end + 2
		case goLang && c == '`':
			end := bytes.IndexByte(d[i+1:], '`')
			if end < 0 {
				x.uncertain(i)
				x.mark(i, len(d))
				return
			}
			x.mark(i, i+1+end+1)
			i += 1 + end + 1
		case !goLang && c == '"' && bytes.HasPrefix(d[i:], []byte(`"""`)):
			i = x.javaTextBlock(i)
		case c == '"' || c == '\'':
			i = x.jsString(i)
		default:
			i++
		}
	}
}

// javaTextBlock lexes a """ text block from i.
func (x *wse1Lexer) javaTextBlock(i int) int {
	d := x.data
	for j := i + 3; j < len(d); {
		switch {
		case d[j] == '\\':
			j += 2
		case bytes.HasPrefix(d[j:], []byte(`"""`)):
			x.mark(i, j+3)
			return j + 3
		default:
			j++
		}
	}
	x.uncertain(i)
	x.mark(i, len(d))
	return len(d)
}

// ---- Python ----------------------------------------------------------------

// pyCode lexes Python: comments, strings of every prefix, f-strings and
// t-strings with their replacement fields.
func (x *wse1Lexer) pyCode() {
	d := x.data
	for i := 0; i < len(d); {
		switch c := d[i]; {
		case c == '#':
			i = x.lineEnd(i)
		case c == '\'' || c == '"':
			i = x.pyString(i)
		default:
			i++
		}
	}
}

// pyStringPrefix is whether the identifier run before the quote at i is a string
// prefix, and whether it makes an f-string or a t-string.
func (x *wse1Lexer) pyStringPrefix(i int) (valid, interpolated bool) {
	d := x.data
	k := i
	for k > 0 && wse1IdentByte(d[k-1]) && i-k <= 2 {
		k--
	}
	if i-k == 0 || i-k > 2 || (k > 0 && wse1IdentByte(d[k-1])) {
		return false, false
	}
	for _, c := range d[k:i] {
		switch c {
		case 'f', 'F', 't', 'T':
			interpolated = true
		case 'r', 'R', 'b', 'B', 'u', 'U':
		default:
			return false, false
		}
	}
	return true, interpolated
}

// pyString lexes the string that starts at the quote at i, prefix included.
func (x *wse1Lexer) pyString(i int) int {
	d := x.data
	q := d[i]
	_, interp := x.pyStringPrefix(i)
	triple := i+2 < len(d) && d[i+1] == q && d[i+2] == q
	j := i + 1
	if triple {
		j = i + 3
	}
	for j < len(d) {
		switch c := d[j]; {
		case c == '\\':
			j++
			if j < len(d) {
				if n := x.lang.terminator(d, j); n > 0 {
					j += n
				} else {
					j++
				}
			}
		case interp && c == '{':
			if j+1 < len(d) && d[j+1] == '{' {
				j += 2
				continue
			}
			if x.nest >= wse1MaxNest {
				j = -1
			} else {
				x.nest++
				j = x.pyField(j + 1)
				x.nest--
			}
			if j < 0 {
				x.uncertain(i)
				x.mark(i, len(d))
				return len(d)
			}
		case c == q && !triple:
			x.mark(i, j+1)
			return j + 1
		case c == q && triple && j+2 < len(d) && d[j+1] == q && d[j+2] == q:
			x.mark(i, j+3)
			return j + 3
		case !triple && x.lang.terminator(d, j) > 0:
			x.uncertain(i) // an unterminated string
			x.mark(i, j)
			return j
		default:
			j++
		}
	}
	x.uncertain(i)
	x.mark(i, len(d))
	return len(d)
}

// pyField lexes the replacement field of an f-string or t-string whose "{" is at
// j-1, and returns the offset after its "}", or -1 when it does not close. A
// quote in the expression begins a nested string (the same quote as the
// enclosing one is allowed since 3.12); after a ":" at bracket depth 0 the field
// holds a format specification, where a quote is a plain character and a "{"
// begins a nested field.
func (x *wse1Lexer) pyField(j int) int {
	d := x.data
	depth := 0
	spec := false
	for j < len(d) {
		switch c := d[j]; {
		case (c == '\'' || c == '"') && !spec:
			j = x.pyString(j)
		case c == '{' && spec:
			if x.nest >= wse1MaxNest {
				return -1
			}
			x.nest++
			j = x.pyField(j + 1)
			x.nest--
			if j < 0 {
				return -1
			}
		case c == '(' || c == '[' || c == '{':
			depth++
			j++
		case c == ')' || c == ']':
			depth--
			j++
		case c == '}':
			if depth <= 0 {
				return j + 1
			}
			depth--
			j++
		case c == ':' && depth == 0 && !spec:
			spec = true
			j++
		case c == '#' && !spec:
			j = x.lineEnd(j)
		case c == '\\':
			j += 2
		default:
			j++
		}
	}
	return -1
}

// ---- the judge -------------------------------------------------------------

// wse1Inert reports whether one line of the language holds no analysable code:
// it is blank, or, with the language in plain code at its start, a whole-line
// comment or (C family) a one-line block comment. A line inside a string, a
// template, an f-string or a block comment is code as far as this proof goes:
// that is the safe side.
func wse1Inert(content []byte, comment string, plain bool) bool {
	t := strings.TrimSpace(string(content))
	switch {
	case t == "":
		return true
	case !plain:
		return false
	case comment != "" && strings.HasPrefix(t, comment):
		return true
	case comment == "//" && strings.HasPrefix(t, "/*") && strings.HasSuffix(t, "*/") && len(t) >= 4 &&
		!strings.Contains(t[2:len(t)-2], "*/") && !strings.Contains(t[2:len(t)-2], "/*"):
		return true
	}
	return false
}

// wse1SpansHoldNoCode reports whether every line the spans touch is inert. The
// spans are numbered by "\n" as Semgrep does; each such line is judged as the
// language's own lines it holds, all of which must be inert. A span outside the
// file is not shown to be inert.
func wse1SpansHoldNoCode(data []byte, spans []Span, ext string) bool {
	if len(spans) == 0 {
		return false
	}
	lines := wse1LineModel(data, wse1LangOf(ext))
	comment := lineCommentOf(ext)
	numLF := 0
	if len(lines) > 0 {
		numLF = lines[len(lines)-1].lf
	}
	first := make([]int, numLF+2) // the first language line of each "\n"-delimited line
	for i := len(lines) - 1; i >= 0; i-- {
		first[lines[i].lf] = i
	}
	for _, sp := range spans {
		if sp.StartLine < 1 || sp.EndLine > numLF {
			return false
		}
		for n := sp.StartLine; n <= sp.EndLine; n++ {
			for k := first[n]; k < len(lines) && lines[k].lf == n; k++ {
				if !wse1Inert(data[lines[k].start:lines[k].end], comment, lines[k].plain) {
					return false
				}
			}
		}
	}
	return true
}

// judge sets Skipped and Total from the file under absRoot and reports whether
// the run may stay ok for it: the spans are reported and the engine can show
// the lines they cover hold no analysable code.
func (p *PartialParse) judge(absRoot string) bool {
	data := readSource(filepath.Join(absRoot, filepath.FromSlash(p.Path)))
	lines := splitLines(data)
	p.Total = len(lines)
	p.Skipped = skippedLines(p.Spans)
	return p.Reported && p.Total > 0 && wse1SpansHoldNoCode(data, p.Spans, path.Ext(p.Path))
}

// Describe is the partial parse as a detail token, "a.py 4-4", "b.js 10-12,40-41":
// the file and the lines Semgrep skipped.
func (p PartialParse) Describe(clean func(string) string) string {
	var ranges []string
	for _, sp := range p.Spans {
		if sp.StartLine == sp.EndLine {
			ranges = append(ranges, fmt.Sprint(sp.StartLine))
		} else {
			ranges = append(ranges, fmt.Sprintf("%d-%d", sp.StartLine, sp.EndLine))
		}
	}
	return clean(p.Path) + " " + strings.Join(ranges, ",")
}
