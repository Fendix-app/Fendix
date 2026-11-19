package scope

// R6-E7a: a unicode escape in identifier position makes a JavaScript or
// TypeScript file lost evaluation (Release Closure Sprint, owner ruling OR-85:
// "mark lost, identifier-position-aware and regex-aware").
//
// The defect. The runtime reads an identifier spelled with escapes as the name
// it spells, so an escaped spelling of eval is a call to eval: an identifier may
// be spelled with \uXXXX or \u{...} escapes, in a name, after a dot, as a
// property key or a label. Semgrep's patterns, textscan's regular expressions
// and the Python engine's JavaScript checks all match identifiers lexically, so
// a file whose dangerous call is spelled that way reads 0 findings with every
// analyzer ok and coverage complete (a false clean). The remedy is an honest
// incomplete: the file is recorded lost evaluation through the existing
// mechanism (Semgrep "not parsed", textscan "unreadable"). No new enum, no
// schema change.
//
// What counts. An escape is in identifier position when it is outside:
//
//   - string literals;
//   - the text of a template literal (code inside ${...} IS code);
//   - regular-expression literals;
//   - comments (a hashbang line included);
//   - the text of a JSX element, and a JSX attribute's string.
//
// The hard part is the regular-expression-versus-division ambiguity. A crude
// scan flags 249 files in 48 of 93 JavaScript repositories of the corpus, almost
// all of them regex literals such as /[^À-῿]/, so the rule would mark
// half of all JavaScript repositories incomplete for no security reason. This is
// a lexer, not a parser: it reads exactly enough to tell code from the zones
// above, and it is validated against the TypeScript scanner (testdata/
// gen_jsescape_vectors.mjs, jsescape_vectors.json), never against its own
// assumptions.
//
// The direction of every doubt is "report". Whatever the previous token cannot
// decide, the lexer reads BOTH ways and the file is lost when either reading
// finds an escape in code:
//
//   - after a `}` that does not certainly close a block of statements (a `{` after
//     `;`, `{`, `}`, the head of an if, for, while, with, switch or catch, `=>`,
//     else, do, try or finally certainly opens one, and a statement starts after
//     it, so `/` opens a regex; any other `{` may be an object literal or a function
//     body, after which `/` may divide);
//   - after of, yield and await (names or keywords);
//   - after `++`, `--` and `!` where a statement may or may not have ended;
//   - `<!--` and `-->` (an HTML-like comment in a script, operators in a module).
//
// Everything else is decided by the token before: after an operator, `(`, `,`, a
// keyword that takes an expression or the head of an if, for, while, with, switch
// or catch, `/` opens a regex and `<` opens JSX; after a name, a number, a string,
// a literal, `)` or `]`, `/` divides. A file the lexer cannot decide within its
// budget is lost too.

import (
	"bytes"
	"path"
	"strings"
	"unicode/utf8"
)

// JSEscape is what JSIdentifierEscape found in a file.
type JSEscape struct {
	// Found is true when some reading of the file has a unicode escape in
	// identifier position.
	Found bool
	// Offset is the byte offset of the first such escape found, or -1.
	Offset int
	// Undecided is true when the lexer gave up within its budget: the caller
	// must treat the file as lost.
	Undecided bool
}

// Lost reports whether the file must be recorded lost evaluation.
func (e JSEscape) Lost() bool { return e.Found || e.Undecided }

// jsFlavour is how a file's extension reads its source.
type jsFlavour struct {
	jsx  bool // `<` where an expression starts opens a JSX element
	tsx  bool // .tsx (TypeScript with JSX); a `<` that may open type parameters is read both ways in every jsx flavour
	html bool // `<!--` and `-->` may be HTML-like comments (a script, not a module)
}

func jsFlavourOf(name string) (jsFlavour, bool) {
	switch strings.ToLower(path.Ext(name)) {
	case ".js", ".cjs", ".es6", ".jsx":
		return jsFlavour{jsx: true, html: true}, true
	case ".mjs":
		return jsFlavour{jsx: true}, true
	case ".tsx":
		return jsFlavour{jsx: true, tsx: true}, true
	case ".ts", ".mts", ".cts":
		return jsFlavour{}, true
	}
	return jsFlavour{}, false
}

// JSSource reports whether JSIdentifierEscape reads a file of this name: the
// JavaScript and TypeScript sources Semgrep selects and the Python engine
// analyses. A Vue single-file component is not one: Semgrep cannot parse it and
// records it lost evaluation already.
func JSSource(name string) bool {
	_, ok := jsFlavourOf(name)
	return ok
}

type jsPrev uint8

const (
	pExpr  jsPrev = iota // an expression may start here: `/` opens a regex, `<` opens JSX
	pValue               // a value was just read: `/` divides
	pBrace               // after a `}`: a block (a statement starts) or an object (a value)
	pWord                // after of, yield, await: a name or a keyword
)

type jsFrameKind uint8

const (
	fParen      jsFrameKind = iota // ( ... )
	fBrace                         // { ... }
	fTemplSubst                    // ${ ... } in a template literal
	fJsxExpr                       // { ... } inside a JSX tag or between its children
	fJsxTag                        // inside < ... >
	fJsxElem                       // the children of an opened JSX element
)

// jsFrame is one entry of the immutable context stack, so that forking a reading
// copies a pointer.
type jsFrame struct {
	kind    jsFrameKind
	ctl     bool // fParen: the head of an if, for, while, with, switch or catch
	closing bool // fJsxTag: </ ... >
	blk     bool // fBrace: certainly a statement block (an object literal and a function body are not certain)
	parent  *jsFrame
	depth   int
	hash    uint64
}

func (f *jsFrame) push(kind jsFrameKind, ctl, closing bool) *jsFrame {
	h := uint64(kind)*2 + 1
	if ctl {
		h += 7
	}
	if closing {
		h += 13
	}
	d := 1
	var ph uint64
	if f != nil {
		d = f.depth + 1
		ph = f.hash
	}
	return &jsFrame{kind: kind, ctl: ctl, closing: closing, parent: f, depth: d, hash: ph*1099511628211 + h}
}

// pushBrace opens a `{`; blk says it is certainly a block of statements.
func (f *jsFrame) pushBrace(blk bool) *jsFrame {
	n := f.push(fBrace, false, false)
	if blk {
		n.blk = true
		n.hash += 101
	}
	return n
}

func (f *jsFrame) kindOrNone() int {
	if f == nil {
		return -1
	}
	return int(f.kind)
}

func (f *jsFrame) hashOrZero() uint64 {
	if f == nil {
		return 0
	}
	return f.hash
}

// jsState is one reading of the file: a position and what the lexer knows there.
type jsState struct {
	pos  int
	prev jsPrev
	dot  bool // the last token was `.` or `?.`: a word after it is a property name
	// ctl is true right after `if`, `while`, `for` or `with` (and `for await`): a `(` now
	// opens the head of a statement.
	ctl      bool
	forTok   bool // the last token was `for`
	lineHead bool // only blanks and comments since the line began: `-->` may start a comment
	// blockNext is true when a `{` here certainly opens a block of statements: at the start
	// of a file, after `;`, `{` or `}`, after the head of an if, for, while, with, switch or catch,
	// after `=>`, else, do, try and finally.
	blockNext bool
	// tagPrev is what the last piece of a JSX tag was, while a tag is being read: a name, an `=`,
	// or anything else. A `<` right after a name opens type arguments (`<Select<string> />`).
	tagPrev uint8
	top     *jsFrame
}

const (
	tpStart uint8 = iota // nothing yet, or an expression container just ended
	tpName               // a tag or attribute name
	tpEq                 // =
	tpOther              // a string, a type-argument list, ...
)

type jsKey struct {
	pos       int
	prev      jsPrev
	dot, ctl  bool
	forTok    bool
	lineHead  bool
	blockNext bool
	tagPrev   uint8
	kind      int
	hash      uint64
}

func (s *jsState) key() jsKey {
	return jsKey{s.pos, s.prev, s.dot, s.ctl, s.forTok, s.lineHead, s.blockNext, s.tagPrev, s.top.kindOrNone(), s.top.hashOrZero()}
}

const (
	jsMaxDepth = 20000
	// jsBudgetPerByte bounds the lexer's work: every token of every reading counts.
	jsBudgetPerByte = 64
	jsBudgetFloor   = 200000
	jsMaxStates     = 20000
)

type jsLexer struct {
	src   []byte
	fl    jsFlavour
	n     int
	found int // offset of the first escape in code, or -1
	steps int
	limit int
	// maxStates and maxDepth are jsMaxStates and jsMaxDepth, lowered only by a test.
	maxStates int
	maxDepth  int
	work      []jsState
	seen      map[jsKey]struct{}
	gaveUp    bool
	// why names the first limit the lexer gave up at (a jsGiveUp constant); "" while it has not.
	why string
}

// The limits a reading gives up at. Giving up is never a clean answer: the file is lost
// (JSEscape.Undecided), whatever the lexer had read so far.
const (
	jsGiveUpDepth    = "depth"          // brackets, tags or templates nested past jsMaxDepth
	jsGiveUpStates   = "states"         // more than jsMaxStates distinct readings
	jsGiveUpSteps    = "steps"          // more tokens read than the budget allows
	jsGiveUpTypeArgs = "type arguments" // a JSX element's type arguments hold a template with a substitution
)

// giveUp stops the search: the file is lost evaluation (Undecided).
func (lx *jsLexer) giveUp(why string) {
	lx.gaveUp = true
	if lx.why == "" {
		lx.why = why
	}
}

// JSIdentifierEscape reports whether src, the source of the JavaScript or
// TypeScript file called name, spells an identifier with a unicode escape (see
// the file comment). A file whose name is not one of those reads as not found.
func JSIdentifierEscape(name string, src []byte) JSEscape {
	e, _ := jsEscapeWhy(name, src)
	return e
}

// jsEscapeWhy is JSIdentifierEscape and, when the lexer gave up, the limit it gave up at.
func jsEscapeWhy(name string, src []byte) (JSEscape, string) {
	fl, ok := jsFlavourOf(name)
	if !ok || !bytes.Contains(src, []byte(`\u`)) {
		return JSEscape{Offset: -1}, ""
	}
	lx := newJSLexer(fl, src)
	e := lx.decide()
	return e, lx.why
}

// newJSLexer is a lexer for src with the limits of this package (a test lowers them to reach one).
func newJSLexer(fl jsFlavour, src []byte) *jsLexer {
	return &jsLexer{
		src: src, fl: fl, n: len(src), found: -1, seen: map[jsKey]struct{}{},
		limit: jsBudgetPerByte*len(src) + jsBudgetFloor, maxStates: jsMaxStates, maxDepth: jsMaxDepth,
	}
}

// decide reads every reading of the file, to the first escape in code, the end of the last
// reading, or a give-up (Undecided).
func (lx *jsLexer) decide() JSEscape {
	start := jsState{prev: pExpr, lineHead: true, blockNext: true}
	lx.work = append(lx.work, start)
	lx.seen[start.key()] = struct{}{}
	for len(lx.work) > 0 && lx.found < 0 && !lx.gaveUp {
		st := lx.work[len(lx.work)-1]
		lx.work = lx.work[:len(lx.work)-1]
		lx.run(st)
	}
	return JSEscape{Found: lx.found >= 0, Offset: lx.found, Undecided: lx.found < 0 && lx.gaveUp}
}

// fork queues another reading, unless it has been read already.
func (lx *jsLexer) fork(st jsState) {
	k := st.key()
	if _, dup := lx.seen[k]; dup {
		return
	}
	if len(lx.seen) >= lx.maxStates {
		lx.giveUp(jsGiveUpStates)
		return
	}
	lx.seen[k] = struct{}{}
	lx.work = append(lx.work, st)
}

func jsIsLT(src []byte, i int) bool {
	switch src[i] {
	case '\n', '\r':
		return true
	case 0xE2:
		return i+2 < len(src) && src[i+1] == 0x80 && (src[i+2] == 0xA8 || src[i+2] == 0xA9)
	}
	return false
}

// jsLTLen is the length of the line terminator at i (CRLF counts as one), 0 if none.
func jsLTLen(src []byte, i int) int {
	switch src[i] {
	case '\n':
		return 1
	case '\r':
		if i+1 < len(src) && src[i+1] == '\n' {
			return 2
		}
		return 1
	case 0xE2:
		if jsIsLT(src, i) {
			return 3
		}
	}
	return 0
}

// jsBlankLen is the length of the whitespace (not a line terminator) at i, 0 if none.
func jsBlankLen(src []byte, i int) int {
	switch src[i] {
	case ' ', '\t', '\v', '\f':
		return 1
	case 0xC2:
		if i+1 < len(src) && src[i+1] == 0xA0 {
			return 2
		}
	case 0xEF:
		if i+2 < len(src) && src[i+1] == 0xBB && src[i+2] == 0xBF {
			return 3
		}
	case 0xE1:
		if i+2 < len(src) && src[i+1] == 0x9A && src[i+2] == 0x80 {
			return 3
		}
	case 0xE2:
		if i+2 < len(src) && src[i+1] == 0x80 && (src[i+2] >= 0x80 && src[i+2] <= 0x8A || src[i+2] == 0xAF) {
			return 3
		}
		if i+2 < len(src) && src[i+1] == 0x81 && src[i+2] == 0x9F {
			return 3
		}
	case 0xE3:
		if i+2 < len(src) && src[i+1] == 0x80 && src[i+2] == 0x80 {
			return 3
		}
	}
	return 0
}

func jsIsHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// jsEscapeLen is the length of the unicode escape that starts at i (a backslash),
// 0 when what is there is not a well-formed \uXXXX or \u{X...}.
func jsEscapeLen(src []byte, i int) int {
	if i+1 >= len(src) || src[i] != '\\' || src[i+1] != 'u' {
		return 0
	}
	j := i + 2
	if j < len(src) && src[j] == '{' {
		k := j + 1
		for k < len(src) && jsIsHex(src[k]) {
			k++
		}
		if k > j+1 && k < len(src) && src[k] == '}' {
			return k + 1 - i
		}
		return 0
	}
	if j+4 <= len(src) && jsIsHex(src[j]) && jsIsHex(src[j+1]) && jsIsHex(src[j+2]) && jsIsHex(src[j+3]) {
		return 6
	}
	return 0
}

func jsIsASCIIIdent(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$'
}

// jsIdentLen is how many bytes of identifier characters (not escapes) start at i.
// Every character from U+0080 up that is not white space or a line terminator is
// one, which can only over-read a name.
func jsIdentLen(src []byte, i int) int {
	c := src[i]
	if c < 0x80 {
		if jsIsASCIIIdent(c) {
			return 1
		}
		return 0
	}
	if jsBlankLen(src, i) > 0 || jsIsLT(src, i) {
		return 0
	}
	_, w := utf8.DecodeRune(src[i:])
	return w
}

// escape records an escape in code at off, which ends the search.
func (lx *jsLexer) escape(off int) {
	if lx.found < 0 {
		lx.found = off
	}
}

// word reads an identifier name starting at i (it may start with an escape) and
// returns its end. An escape in it is an escape in code.
func (lx *jsLexer) word(i int) int {
	for i < lx.n {
		if w := jsIdentLen(lx.src, i); w > 0 {
			i += w
			continue
		}
		if lx.src[i] == '\\' {
			if l := jsEscapeLen(lx.src, i); l > 0 {
				lx.escape(i)
				return i + l
			}
		}
		break
	}
	return i
}

// exprWords are the words after which an expression starts, so `/` opens a regex.
var jsExprWords = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true, "new": true, "delete": true,
	"void": true, "throw": true, "case": true, "do": true, "else": true, "extends": true, "default": true,
}

// ambiguousWords are names that can also be keywords: `of` in a for loop, yield and
// await in a generator or an async function.
var jsAmbiguousWords = map[string]bool{"of": true, "yield": true, "await": true}

// jsTemplateText reads template text from st.pos on, to its closing backtick or
// its next `${`.
func (lx *jsLexer) templateText(st *jsState) {
	src := lx.src
	i := st.pos
	for i < lx.n {
		switch src[i] {
		case '\\':
			i += 2
			continue
		case '`':
			st.pos = i + 1
			st.tok(pValue)
			return
		case '$':
			if i+1 < lx.n && src[i+1] == '{' {
				st.pos = i + 2
				st.top = st.top.push(fTemplSubst, false, false)
				st.tok(pExpr)
				return
			}
		}
		i++
	}
	st.pos = lx.n
}

// regex reads a regular-expression literal that starts at i (a `/`), and returns
// its end, or ok == false when no literal closes on the line.
func (lx *jsLexer) regex(i int) (end int, ok bool) {
	src := lx.src
	j := i + 1
	inClass := false
	for j < lx.n {
		c := src[j]
		switch {
		case c == '\\':
			j++
			if j >= lx.n || jsIsLT(src, j) {
				return 0, false
			}
			j++
			continue
		case jsIsLT(src, j):
			return 0, false
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			return lx.word(j + 1), true
		}
		j++
	}
	return 0, false
}

// run lexes st to the end of the file, the first escape in code, or the first
// doubt (which queues the other readings and goes on with one).
func (lx *jsLexer) run(st jsState) {
	n := lx.n
	for st.pos < n && lx.found < 0 && !lx.gaveUp {
		lx.steps++
		if lx.steps > lx.limit {
			lx.giveUp(jsGiveUpSteps)
			return
		}
		if st.top != nil && st.top.depth > lx.maxDepth {
			lx.giveUp(jsGiveUpDepth)
			return
		}
		switch {
		case st.top != nil && st.top.kind == fJsxElem:
			lx.jsxChildren(&st)
		case st.top != nil && st.top.kind == fJsxTag:
			lx.jsxTag(&st)
		default:
			lx.code(&st)
		}
	}
}

// token ends a significant token: the state after it.
func (st *jsState) tok(prev jsPrev) {
	st.prev = prev
	st.dot, st.ctl, st.forTok, st.lineHead, st.blockNext = false, false, false, false, false
	st.tagPrev = tpStart
}

// skipBlanks skips white space and comments; it returns whether it moved.
func (lx *jsLexer) skipBlank(st *jsState) bool {
	src, i := lx.src, st.pos
	if l := jsBlankLen(src, i); l > 0 {
		st.pos += l
		return true
	}
	if l := jsLTLen(src, i); l > 0 {
		st.pos += l
		st.lineHead = true
		return true
	}
	if src[i] == '/' && i+1 < lx.n {
		switch src[i+1] {
		case '/':
			st.pos = lx.lineEnd(i + 2)
			return true
		case '*':
			end := bytes.Index(src[i+2:], []byte("*/"))
			if end < 0 {
				st.pos = lx.n
				return true
			}
			body := src[i+2 : i+2+end]
			st.pos = i + 2 + end + 2
			for k := 0; k < len(body); k++ {
				if jsIsLT(body, k) {
					st.lineHead = true
					break
				}
			}
			return true
		}
	}
	return false
}

// lineEnd is the offset of the line terminator that ends the line holding i, or the
// end of the file.
func (lx *jsLexer) lineEnd(i int) int {
	for i < lx.n && !jsIsLT(lx.src, i) {
		i++
	}
	return i
}

// code lexes one token of JavaScript or TypeScript.
func (lx *jsLexer) code(st *jsState) {
	src, n := lx.src, lx.n
	i := st.pos
	if i == 0 && n >= 2 && src[0] == '#' && src[1] == '!' {
		st.pos = lx.lineEnd(2)
		return
	}
	if lx.skipBlank(st) {
		return
	}
	c := src[i]
	switch {
	case c == '"' || c == '\'':
		j := i + 1
		for j < n && src[j] != c {
			if src[j] == '\\' {
				if j+1 < n {
					if l := jsLTLen(src, j+1); l > 0 {
						j += 1 + l
					} else {
						j += 2
					}
				} else {
					j++
				}
				continue
			}
			if src[j] == '\n' || src[j] == '\r' {
				break
			}
			j++
		}
		if j < n && src[j] == c {
			j++
		}
		st.pos = j
		st.tok(pValue)
	case c == '`':
		st.pos = i + 1
		st.tok(pValue)
		lx.templateText(st)
	case c >= '0' && c <= '9' || c == '.' && i+1 < n && src[i+1] >= '0' && src[i+1] <= '9':
		j := i + 1
		hex := c == '0' && j < n && (src[j] == 'x' || src[j] == 'X')
		for j < n {
			d := src[j]
			if jsIsASCIIIdent(d) && d != '$' || d == '.' {
				j++
				if !hex && (d == 'e' || d == 'E') && j < n && (src[j] == '+' || src[j] == '-') {
					j++
				}
				continue
			}
			break
		}
		st.pos = j
		st.tok(pValue)
	case jsIdentLen(src, i) > 0 || c == '\\' || (c == '#' && i+1 < n && (jsIdentLen(src, i+1) > 0 || src[i+1] == '\\')):
		start := i
		if c == '#' {
			i++
		}
		if c == '\\' {
			if jsEscapeLen(src, i) == 0 {
				st.pos = i + 1 // a stray backslash: a syntax error, not an identifier
				st.tok(pExpr)
				return
			}
		}
		end := lx.word(i)
		if lx.found >= 0 {
			return
		}
		text := string(src[start:end])
		st.pos = end
		dot := st.dot
		forTok := st.forTok
		switch {
		case c == '#':
			st.tok(pValue)
		case dot:
			st.tok(pValue)
		case jsExprWords[text]:
			st.tok(pExpr)
			st.blockNext = text == "else" || text == "do"
		case jsAmbiguousWords[text]:
			st.tok(pWord)
			if text == "await" && forTok {
				st.ctl = true
			}
		default:
			st.tok(pValue)
			switch text {
			case "if", "while", "with", "switch", "catch":
				st.ctl = true
			case "for":
				st.ctl, st.forTok = true, true
			case "try", "finally":
				st.blockNext = true
			}
		}
	case c == '/':
		lx.slash(st)
	case c == '(':
		st.top = st.top.push(fParen, st.ctl, false)
		st.pos = i + 1
		st.tok(pExpr)
	case c == ')':
		st.pos = i + 1
		if st.top != nil && st.top.kind == fParen {
			ctl := st.top.ctl
			st.top = st.top.parent
			if ctl {
				st.tok(pExpr)
				st.blockNext = true
			} else {
				st.tok(pValue)
			}
		} else {
			st.tok(pValue)
		}
	case c == '{':
		st.top = st.top.pushBrace(st.blockNext)
		st.pos = i + 1
		st.tok(pExpr)
		st.blockNext = true
	case c == '}':
		st.pos = i + 1
		switch {
		case st.top != nil && st.top.kind == fBrace:
			blk := st.top.blk
			st.top = st.top.parent
			if blk {
				st.tok(pExpr) // a block ends: a statement starts, so `/` opens a regex
			} else {
				st.tok(pBrace)
			}
			st.blockNext = true
		case st.top != nil && st.top.kind == fTemplSubst:
			st.top = st.top.parent
			lx.templateText(st)
		case st.top != nil && st.top.kind == fJsxExpr:
			st.top = st.top.parent
			st.tok(pValue)
		default:
			st.tok(pBrace)
			st.blockNext = true
		}
	case c == ']':
		st.pos = i + 1
		st.tok(pValue)
	case c == '!':
		st.pos = i + 1
		switch {
		case i+1 < n && src[i+1] == '=', st.prev == pExpr, st.lineHead:
			// `!=`, `!==`, or a prefix `!` (TypeScript's non-null assertion cannot follow a line break).
			st.tok(pExpr)
		case st.prev == pValue:
			st.tok(pValue) // `x!`: TypeScript's postfix non-null assertion, so `/` divides
		default: // after `}`, of, yield, await: read it both ways
			alt := *st
			alt.tok(pExpr)
			lx.fork(alt)
			st.tok(pValue)
		}
	case c == '[' || c == ',' || c == ';' || c == ':' || c == '@' || c == '~':
		st.pos = i + 1
		st.tok(pExpr)
		st.blockNext = c == ';'
	case c == '.':
		if i+2 < n && src[i+1] == '.' && src[i+2] == '.' {
			st.pos = i + 3
			st.tok(pExpr)
		} else {
			st.pos = i + 1
			st.tok(pExpr)
			st.dot = true
		}
	case c == '?':
		if i+1 < n && src[i+1] == '.' && !(i+2 < n && src[i+2] >= '0' && src[i+2] <= '9') {
			st.pos = i + 2
			st.tok(pExpr)
			st.dot = true
		} else {
			st.pos = i + 1
			st.tok(pExpr)
		}
	case c == '+' || c == '-':
		if i+1 < n && src[i+1] == c {
			// `--` at the head of a line may start an HTML-like close comment.
			if c == '-' && lx.fl.html && st.lineHead && i+2 < n && src[i+2] == '>' {
				alt := *st
				alt.pos = lx.lineEnd(i + 3)
				lx.fork(alt)
			}
			st.pos = i + 2
			switch {
			case st.prev == pValue && !st.lineHead:
				st.tok(pValue) // postfix: a value was just read
			case st.prev == pExpr || st.lineHead:
				st.tok(pExpr) // prefix: an operand is due (a postfix ++ cannot follow a line break)
			default: // after `}`, of, yield, await: an object literal or a function body with a postfix operator, or a statement that starts with a prefix one
				alt := *st
				alt.tok(pExpr)
				lx.fork(alt)
				st.tok(pValue)
			}
			return
		}
		st.pos = i + 1
		st.tok(pExpr)
	case c == '<':
		lx.less(st)
	case c == '=' && i+1 < n && src[i+1] == '>':
		st.pos = i + 2
		st.tok(pExpr)
		st.blockNext = true // an arrow function's body
	default:
		// = > & | ^ * % and anything else: an operator, so an expression follows.
		st.pos = i + 1
		st.tok(pExpr)
	}
}

// slash reads a `/` that is not the start of a comment.
func (lx *jsLexer) slash(st *jsState) {
	i := st.pos
	asRegex := func(s jsState) (jsState, bool) {
		end, ok := lx.regex(i)
		if lx.found >= 0 {
			return s, true
		}
		if !ok {
			return s, false
		}
		s.pos = end
		s.tok(pValue)
		return s, true
	}
	asDivision := func(s jsState) jsState {
		s.pos = i + 1
		if i+1 < lx.n && lx.src[i+1] == '=' {
			s.pos = i + 2
		}
		s.tok(pExpr)
		return s
	}
	switch st.prev {
	case pValue:
		*st = asDivision(*st)
	case pExpr:
		if s, ok := asRegex(*st); ok {
			*st = s
		} else {
			*st = asDivision(*st)
		}
	default: // pBrace, pWord: read it both ways
		div := asDivision(*st)
		if s, ok := asRegex(*st); ok {
			lx.fork(div)
			*st = s
		} else {
			*st = div
		}
	}
}

// less reads a `<`: an operator, a type assertion, a generic's bracket, a JSX
// element, or an HTML-like comment.
func (lx *jsLexer) less(st *jsState) {
	src, n, i := lx.src, lx.n, st.pos
	op := func(s jsState) jsState {
		j := i + 1
		for j < n && (src[j] == '<' || src[j] == '=') && j < i+3 {
			j++
		}
		s.pos = j
		s.tok(pExpr)
		return s
	}
	if lx.fl.html && bytes.HasPrefix(src[i:], []byte("<!--")) {
		alt := *st
		alt.pos = lx.lineEnd(i + 4)
		lx.fork(alt)
		*st = op(*st)
		return
	}
	jsx := func(s jsState) (jsState, bool) {
		if !lx.fl.jsx || i+1 >= n {
			return s, false
		}
		d := src[i+1]
		if !(d == '>' || d == '\\' || jsIdentLen(src, i+1) > 0 && !(d >= '0' && d <= '9')) {
			return s, false
		}
		s.top = s.top.push(fJsxTag, false, false)
		s.pos = i + 1
		s.tok(pExpr)
		return s, true
	}
	switch st.prev {
	case pValue:
		*st = op(*st)
	case pExpr:
		if s, ok := jsx(*st); ok {
			// `<` where an expression starts is an element, unless it opens a type parameter
			// list (`<T,>(x) => ...` in TypeScript, `<T>(x) => ...` in Flow): where the text after it
			// could be one, read it both ways.
			if lx.typeParamStart(i + 1) {
				lx.fork(op(*st))
			}
			*st = s
		} else {
			*st = op(*st)
		}
	default:
		o := op(*st)
		if s, ok := jsx(*st); ok {
			lx.fork(o)
			*st = s
		} else {
			*st = o
		}
	}
}

// skipTrivia is the end of the blanks, line breaks and comments that start at j.
func (lx *jsLexer) skipTrivia(j int) int {
	src, n := lx.src, lx.n
	for j < n {
		if l := jsBlankLen(src, j); l > 0 {
			j += l
		} else if l := jsLTLen(src, j); l > 0 {
			j += l
		} else if src[j] == '/' && j+1 < n && src[j+1] == '/' {
			j = lx.lineEnd(j + 2)
		} else if src[j] == '/' && j+1 < n && src[j+1] == '*' {
			end := bytes.Index(src[j+2:], []byte("*/"))
			if end < 0 {
				return n
			}
			j += 2 + end + 2
		} else {
			break
		}
	}
	return j
}

// nameEnd is the end of the identifier (escapes included) that starts at j, or j.
func (lx *jsLexer) nameEnd(j int) int {
	for j < lx.n {
		if w := jsIdentLen(lx.src, j); w > 0 {
			j += w
		} else if l := jsEscapeLen(lx.src, j); l > 0 {
			j += l
		} else {
			break
		}
	}
	return j
}

// typeParamStart reports whether the text that follows a `<` (at i) could be the start of a type
// parameter list: variance or modifiers (`+`, `-`, `const`, `in`, `out`), a name, and then `,`, `=`,
// `:`, `extends`, or a `>` followed by `(`. `<T,>(x) => x`, `<T extends U>(x) => x`, `<T = V>(x) => x`,
// `<const T,>(x) => x` and Flow's `<T>(x) => x` and `<T: U>(x) => x` are such lists. Wide on purpose:
// it only decides where the lexer reads a `<` both ways.
func (lx *jsLexer) typeParamStart(i int) bool {
	src, n := lx.src, lx.n
	j := lx.skipTrivia(i)
	for k := 0; k < 4 && j < n; k++ {
		if src[j] == '+' || src[j] == '-' {
			j = lx.skipTrivia(j + 1)
		}
		e := lx.nameEnd(j)
		if e == j {
			return false
		}
		switch string(src[j:e]) {
		case "const", "in", "out":
			if nj := lx.skipTrivia(e); nj > e && nj < n && (jsIdentLen(src, nj) > 0 || src[nj] == '\\') {
				j = nj
				continue
			}
		}
		e = lx.skipTrivia(e)
		if e >= n {
			return false
		}
		switch src[e] {
		case ',', '=', ':':
			return true
		case '>':
			p := lx.skipTrivia(e + 1)
			return p < n && src[p] == '('
		}
		return bytes.HasPrefix(src[e:], []byte("extends")) && (e+7 >= n || !jsIsASCIIIdent(src[e+7]))
	}
	// Four modifiers in a row: no type parameter has so many, so this is neither a list nor an
	// element the lexer can name; it reads the `<` both ways, as it reads every doubt.
	return j < n
}

// typeArgs is how a scan for the end of a JSX element's type arguments ended.
type typeArgs uint8

const (
	taClosed      typeArgs = iota // the list ends at the returned offset
	taOpen                        // no `>` closes it before the end of the file: no reading of the file has a list here
	taUnskippable                 // a template with a substitution: valid, but not skipped here
)

// typeArgsEnd is the end of the type argument list that starts at i (a `<`, after the name of a JSX
// element). `<Select<string> />`, `<Select<Array<string>> />` and `<Select<(a: number) => void> />` are
// such lists; a `>` that is the second half of `=>`, a string, a template and a comment are not counted.
//
// The list has no length limit of its own (a union of 40,000 members is valid): what it costs is
// charged to the step budget (R3-SEC-A2: a 64 KiB limit made the lexer read the rest of the file as the
// text of an element). It ends one of three ways. It closes (taClosed). Nothing closes it before the
// end of the file, or a comment in it never ends (taOpen): no valid file has such a list, so the reading
// that holds it is not one, and, like an unterminated comment, it ends the reading with nothing after it
// that could be code; in a file where it is a doubt, the other reading of the `<` is read too. Or a
// template in it holds a substitution (taUnskippable), types of its own with templates and angle
// brackets, which this scan does not read: the lexer gives up, and giving up is lost evaluation.
func (lx *jsLexer) typeArgsEnd(i int) (end int, res typeArgs) {
	src, n := lx.src, lx.n
	depth := 0
	for j := i; j < n; j++ {
		switch c := src[j]; {
		case c == '<':
			depth++
		case c == '>':
			if j > i && src[j-1] == '=' {
				continue
			}
			if depth--; depth == 0 {
				lx.steps += j - i
				return j + 1, taClosed
			}
		case c == '"' || c == '\'':
			// a string ends at its quote or at a line break (U+2028 and U+2029 may be in it, as in code)
			for j++; j < n && src[j] != c && src[j] != '\n' && src[j] != '\r'; j++ {
				if src[j] == '\\' {
					j++
					if j < n {
						if l := jsLTLen(src, j); l > 1 {
							j += l - 1 // a line continuation: CRLF is one terminator
						}
					}
				}
			}
		case c == '`':
			for j++; j < n && src[j] != '`'; j++ {
				if src[j] == '\\' {
					j++
				} else if src[j] == '$' && j+1 < n && src[j+1] == '{' {
					lx.steps += j - i
					return 0, taUnskippable
				}
			}
		case c == '/' && j+1 < n && src[j+1] == '/':
			j = lx.lineEnd(j+2) - 1
		case c == '/' && j+1 < n && src[j+1] == '*':
			e := bytes.Index(src[j+2:], []byte("*/"))
			if e < 0 {
				lx.steps += n - i
				return 0, taOpen
			}
			j += 2 + e + 1
		}
	}
	lx.steps += n - i
	return 0, taOpen
}

// jsxAfterElement is the state when a JSX element has just closed.
func (lx *jsLexer) jsxAfterElement(st *jsState) {
	if st.top != nil && st.top.kind == fJsxElem {
		return // the children of the element it was in
	}
	st.tok(pValue)
}

// jsxChildren reads the children of an open JSX element: text to the next `{` or
// `<`. Nothing in the text is JavaScript.
func (lx *jsLexer) jsxChildren(st *jsState) {
	src, n := lx.src, lx.n
	i := st.pos
	for i < n && src[i] != '{' && src[i] != '<' {
		i++
	}
	st.pos = i
	if i >= n {
		return
	}
	if src[i] == '{' {
		st.top = st.top.push(fJsxExpr, false, false)
		st.pos = i + 1
		st.tok(pExpr)
		return
	}
	if i+1 < n && src[i+1] == '/' {
		st.top = st.top.push(fJsxTag, false, true)
		st.pos = i + 2
		st.tagPrev = tpStart
		return
	}
	if i+1 < n && src[i+1] == '!' {
		st.pos = i + 2 // `<!--` is not an element: the TypeScript scanner reads it as text
		return
	}
	st.top = st.top.push(fJsxTag, false, false)
	st.pos = i + 1
	st.tagPrev = tpStart
}

// jsxTag reads inside a JSX tag, from its name to its `>`.
func (lx *jsLexer) jsxTag(st *jsState) {
	src, n := lx.src, lx.n
	i := st.pos
	c := src[i]
	if l := jsBlankLen(src, i); l > 0 {
		st.pos += l
		return
	}
	if l := jsLTLen(src, i); l > 0 {
		st.pos += l
		return
	}
	switch {
	case c == '>':
		closing := st.top.closing
		st.top = st.top.parent
		st.pos = i + 1
		if closing {
			if st.top != nil && st.top.kind == fJsxElem {
				st.top = st.top.parent
			}
			lx.jsxAfterElement(st)
		} else {
			st.top = st.top.push(fJsxElem, false, false)
		}
	case c == '/' && i+1 < n && src[i+1] == '>':
		st.top = st.top.parent
		st.pos = i + 2
		lx.jsxAfterElement(st)
	case c == '/' && i+1 < n && src[i+1] == '/':
		st.pos = lx.lineEnd(i + 2)
	case c == '/' && i+1 < n && src[i+1] == '*':
		if end := bytes.Index(src[i+2:], []byte("*/")); end >= 0 {
			st.pos = i + 2 + end + 2
		} else {
			st.pos = n
		}
	case c == '{':
		st.top = st.top.push(fJsxExpr, false, false)
		st.pos = i + 1
		st.tok(pExpr)
	case c == '"' || c == '\'':
		j := i + 1
		for j < n && src[j] != c {
			j++
		}
		if j < n {
			j++
		}
		st.pos = j
		st.tagPrev = tpOther
	case c == '<':
		if st.tagPrev == tpName {
			// Right after a tag's name: the type arguments of a generic element, which hold no
			// element and no code (TypeScript, `<Select<string> />`).
			end, res := lx.typeArgsEnd(i)
			switch res {
			case taUnskippable:
				// What follows the list could be code, and this scan cannot say where the list ends:
				// give up (lost evaluation) rather than read on from a guess.
				lx.giveUp(jsGiveUpTypeArgs)
				return
			case taOpen:
				st.pos = lx.n // the list has no end: this reading ends (see typeArgsEnd)
				return
			}
			st.pos = end
			st.tagPrev = tpOther
			return
		}
		st.top = st.top.push(fJsxTag, false, false)
		st.pos = i + 1
		st.tagPrev = tpStart
	case c == '\\':
		if l := jsEscapeLen(src, i); l > 0 {
			lx.escape(i)
			return
		}
		st.pos = i + 1
		st.tagPrev = tpOther
	case c == '=':
		st.pos = i + 1
		st.tagPrev = tpEq
	default:
		if jsIdentLen(src, i) > 0 || c == '.' || c == '-' || c == ':' {
			st.tagPrev = tpName
		} else {
			st.tagPrev = tpOther
		}
		st.pos = i + 1
	}
}
