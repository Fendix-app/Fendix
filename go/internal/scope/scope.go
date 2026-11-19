// Package scope is the one place the Go analyzers (secrets, textscan,
// semgrep) learn which files they may leave unread without that being a
// coverage gap, and how they report the files they did leave unread.
//
// Decision D6. A file an analyzer skips for size (MaxFileBytes) or cannot
// read is, when it is an in-scope source file for that analyzer, lost
// evaluation: the analyzer is recorded failed/execution_error with the files
// named, and the findings from the rest of the tree are kept.
//
// Decision D5-2 (round 5, contract C6). Every supported in-scope file at or
// below the cap is analysed, whatever its content looks like. The only
// declared exclusions are a recognized lockfile (classify.go, lockfile.go) and
// a symbolic link the analyzer does not follow; <root>/.git with a real layout
// is skipped quietly (dirs.go). Every file left unread for a declared reason is
// listed, with the reason, in the analyzer's ok detail ("declared out of scope,
// not scanned: ...") and, complete, in the report's
// metadata.coverage.limitations. Nothing is excluded silently, and a file with
// no evidence is in scope. An in-scope file over the cap or unreadable is never
// an exclusion: it is the lost evaluation recorded by TooLarge and Unreadable.
//
// Contract C1 (detail segments). A detail is segments joined by "; ". Every
// repository-controlled string put in one is sanitised (Sanitize: ';', '…' and
// control characters become '?', each name is cut to 80 bytes), and a segment
// that lists exclusions starts with DeclaredMarker, so a reader can skip it
// whole. Contract C2 (truncation): Compose never cuts a segment; when the
// budget runs out it writes "and N more (see report metadata)".
package scope

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxFileBytes is the per-file size above which the Go analyzers do not read
// a file: secrets and textscan stop there, and Semgrep is passed it as
// --max-target-bytes, so the three agree on which files were too large.
const MaxFileBytes = 1 << 20

// DeclaredMarker starts every detail segment that lists files or directories
// left out of scope. The backend and the frontend never read loss patterns
// inside such a segment (contract C1).
const DeclaredMarker = "declared out of scope, not scanned:"

// NameMax is how many bytes of a path a detail keeps (contract C1).
const NameMax = 80

// exampleNames bounds how many names of one kind a detail keeps by default: a
// detail names the first few and counts the rest.
const exampleNames = 3

// maxKept bounds how many names of one kind a Coverage keeps for the report
// metadata; the count is always exact.
const maxKept = 2000

// Sanitize makes a repository-controlled string safe to put in a detail
// segment (contract C1): ';', '…', control characters, line and paragraph
// separators and bidirectional controls become '?', an invalid UTF-8 byte
// becomes '?', and the result is cut to NameMax bytes at a character boundary.
func Sanitize(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, w := utf8.DecodeRuneInString(s[i:])
		i += w
		switch {
		case r == utf8.RuneError && w <= 1,
			r == ';', r == '…',
			r < 0x20, r >= 0x7f && r <= 0x9f,
			r >= 0x200b && r <= 0x200f,
			r >= 0x2028 && r <= 0x202e,
			r >= 0x2066 && r <= 0x2069,
			r == 0xfeff:
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > NameMax {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// SafeToken is Sanitize for a name in a segment a reader does read for loss
// patterns (one that does not start with DeclaredMarker): it also replaces the
// characters those patterns are built from, so a file name cannot spell one.
func SafeToken(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', ',', ':', '(', ')', '"', '\'', '\t':
			return '?'
		}
		return r
	}, Sanitize(s))
}

// CleanText is Sanitize for free text that is not a name (a Semgrep message):
// the same characters become '?', but it is not cut.
func CleanText(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == ';', r == '…', r < 0x20, r >= 0x7f && r <= 0x9f, r == 0x2028, r == 0x2029:
			return '?'
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
}

// names is a count and the names of one kind, in the order they were added (a
// walk's lexical order). Only the first maxKept are kept.
type names struct {
	n   int
	all []string
	// once, when a kind records a file at most once (addOnce), holds what it has seen.
	once map[string]struct{}
}

func (l *names) add(name string) {
	l.n++
	if len(l.all) < maxKept {
		l.all = append(l.all, name)
	}
}

// addOnce is add that records a name once: the same file reported again is not a second file.
func (l *names) addOnce(name string) {
	if _, dup := l.once[name]; dup {
		return
	}
	if l.once == nil {
		l.once = map[string]struct{}{}
	}
	l.once[name] = struct{}{}
	l.add(name)
}

// first is at most k kept names, cleaned.
func (l names) first(k int) []string {
	if k > len(l.all) {
		k = len(l.all)
	}
	out := make([]string, k)
	for i := range out {
		out[i] = Sanitize(l.all[i])
	}
	return out
}

// exclusion is the files and directories left out for one reason.
type exclusion struct {
	reason Reason
	list   names
}

// Coverage is what one analyzer left unread in one scan. The zero value is a
// scan that read everything. Paths are relative to the scan root, with
// forward slashes.
type Coverage struct {
	// Lost evaluation: in-scope files the analyzer did not evaluate.
	tooLarge   names // over MaxFileBytes
	unreadable names // could not be opened or read (a directory included)
	notText    names // not readable as text: a NUL byte where source was expected
	notScanned names // the tool did not report evaluating it (Semgrep)
	notParsed  names // the tool could not parse it, or skipped most of it (Semgrep)
	// Declared out of scope: listed, never a gap. In the order each reason was
	// first used.
	excluded []exclusion
}

// TooLarge records an in-scope file over MaxFileBytes.
func (c *Coverage) TooLarge(rel string) { c.tooLarge.add(rel) }

// Unreadable records an in-scope file or directory that could not be read.
func (c *Coverage) Unreadable(rel string) { c.unreadable.add(rel) }

// NotText records an in-scope file that is not readable as text.
func (c *Coverage) NotText(rel string) { c.notText.add(rel) }

// NotScanned records an in-scope file the tool did not report evaluating.
func (c *Coverage) NotScanned(rel string) { c.notScanned.add(rel) }

// NotParsed records an in-scope file the tool could not parse, or parsed in
// part and skipped a line of code in (decision D1', C4B-27), or that the engine
// itself cannot show Semgrep read as its program (a foreign source encoding, an
// identifier spelled with a unicode escape). A file reported twice by those sources
// is one file.
func (c *Coverage) NotParsed(rel string) { c.notParsed.addOnce(rel) }

// Exclude records a file or directory left unread as declared out of scope,
// with the evidence that says so. A directory's rel ends in '/'.
func (c *Coverage) Exclude(reason Reason, rel string) {
	for i := range c.excluded {
		if c.excluded[i].reason == reason {
			c.excluded[i].list.add(rel)
			return
		}
	}
	e := exclusion{reason: reason}
	e.list.add(rel)
	c.excluded = append(c.excluded, e)
}

// Symlink records a symbolic link the analyzer did not follow (a directory's
// rel ends in '/').
func (c *Coverage) Symlink(rel string) { c.Exclude(ReasonSymlink, rel) }

// Lost reports whether any in-scope file was left unevaluated.
func (c Coverage) Lost() bool { return c.LostFiles() > 0 }

// LostFiles is how many in-scope files (and directories) were left
// unevaluated.
func (c Coverage) LostFiles() int {
	return c.tooLarge.n + c.unreadable.n + c.notText.n + c.notScanned.n + c.notParsed.n
}

// Declared reports whether anything was left unread as declared out of scope.
func (c Coverage) Declared() bool { return c.DeclaredFiles() > 0 }

// DeclaredFiles is how many files and directories were declared out of scope.
func (c Coverage) DeclaredFiles() int {
	n := 0
	for _, e := range c.excluded {
		n += e.list.n
	}
	return n
}

// DeclaredCount is how many files and directories were declared out of scope
// for one reason.
func (c Coverage) DeclaredCount(reason Reason) int {
	for _, e := range c.excluded {
		if e.reason == reason {
			return e.list.n
		}
	}
	return 0
}

// Reasons are the reasons something was declared out of scope, in the order
// each was first used.
func (c Coverage) Reasons() []Reason {
	out := make([]Reason, len(c.excluded))
	for i, e := range c.excluded {
		out[i] = e.reason
	}
	return out
}

// Seg is one "; "-separated segment of a detail, which can be written naming at
// most k entries per list (k < 0: every kept name). A segment is never cut:
// Compose picks the largest k at which everything fits, and drops whole
// segments when even k = 0 does not.
type Seg func(k int) string

// part is one kind in a segment: "2 over 1048576 bytes (a.js, b.py)".
type part struct {
	label string
	list  names
	// countFirst puts the count before the label ("2 over ...", the lost
	// parts); otherwise the label comes first ("minified 2"), the reasons.
	countFirst bool
}

func (p part) render(k int) string {
	var s string
	if p.countFirst {
		s = strconv.Itoa(p.list.n) + " " + p.label
	} else {
		s = p.label + " " + strconv.Itoa(p.list.n)
	}
	if k < 0 {
		k = len(p.list.all)
	}
	shown := p.list.first(k)
	if len(shown) == 0 {
		return s
	}
	s += " (" + strings.Join(shown, ", ")
	if more := p.list.n - len(shown); more > 0 {
		s += " +" + strconv.Itoa(more) + " more"
	}
	return s + ")"
}

func renderParts(prefix string, parts []part, k int) string {
	var live []string
	for _, p := range parts {
		if p.list.n > 0 {
			live = append(live, p.render(k))
		}
	}
	if len(live) == 0 {
		return ""
	}
	return prefix + strings.Join(live, ", ")
}

func (c Coverage) lostParts() []part {
	return []part{
		{label: "over " + strconv.Itoa(MaxFileBytes) + " bytes", list: c.tooLarge, countFirst: true},
		{label: "unreadable", list: c.unreadable, countFirst: true},
		{label: "not text (NUL bytes)", list: c.notText, countFirst: true},
		{label: "not evaluated by semgrep", list: c.notScanned, countFirst: true},
		{label: "not parsed by semgrep", list: c.notParsed, countFirst: true},
	}
}

func (c Coverage) declaredParts() []part {
	parts := make([]part, len(c.excluded))
	for i, e := range c.excluded {
		parts[i] = part{label: string(e.reason), list: e.list}
	}
	return parts
}

// LostSeg is the loss segment, "lost evaluation: 3 in-scope files not read: 2
// over 1048576 bytes (a.js, b.py), 1 unreadable (c.py)"; empty when nothing was
// lost.
func (c Coverage) LostSeg() Seg {
	return func(k int) string {
		if !c.Lost() {
			return ""
		}
		prefix := "lost evaluation: " + plural(c.LostFiles(), "in-scope file") + " not read: "
		return renderParts(prefix, c.lostParts(), k)
	}
}

// DeclaredSeg is the exclusion segment, "declared out of scope, not scanned:
// lockfile 1 (package-lock.json), minified 2 (a.min.js, b.min.js)"; empty when
// nothing was declared out of scope.
func (c Coverage) DeclaredSeg() Seg {
	return func(k int) string {
		return renderParts(DeclaredMarker+" ", c.declaredParts(), k)
	}
}

// LostDetail is the failed/execution_error detail for the lost files, within
// budget bytes; "" when nothing was lost. When even the counts do not fit, the
// counts are returned anyway: a failed entry's state already says the run is a
// gap, and a segment is never cut.
func (c Coverage) LostDetail(budget int) string {
	seg := c.LostSeg()
	if seg(0) == "" {
		return ""
	}
	if s := Compose(budget, seg); s != "" && !strings.HasPrefix(s, "and ") {
		return s
	}
	return seg(0)
}

// DeclaredDetail is the ok detail listing what was left unread as declared out
// of scope, within budget bytes; "" when nothing was. It never ends in "…" and
// never exceeds the budget it is given: the backend and the frontend read an ok
// Semgrep detail cut by the engine as lost evaluation. When the counts per reason
// do not fit, it says how many in all and points at the report metadata.
func (c Coverage) DeclaredDetail(budget int) string {
	seg := c.DeclaredSeg()
	if seg(0) == "" {
		return ""
	}
	if s := Compose(budget, seg); s != "" && !strings.HasPrefix(s, "and ") {
		return s
	}
	short := DeclaredMarker + " " + strconv.Itoa(c.DeclaredFiles()) + " in all (see report metadata)"
	if len(short) <= budget {
		return short
	}
	return ""
}

// Compose joins segments with "; " within budget bytes, never cutting one.
// Callers pass the loss segments first, then the notes, then the exclusions.
// Every segment is first written as its counts alone (k = 0); if those do not
// all fit, it keeps the leading segments that do and ends with "and N more (see
// report metadata)", N being the segments left out; then the budget that is
// left names entries, the first segments first, so a loss is named before an
// exclusion is.
func Compose(budget int, segs ...Seg) string {
	var live []int
	for i, seg := range segs {
		if seg(0) != "" {
			live = append(live, i)
		}
	}
	levels := make([]int, len(segs))
	render := func(n int) string {
		parts := make([]string, 0, n+1)
		for _, i := range live[:n] {
			parts = append(parts, segs[i](levels[i]))
		}
		if n < len(live) {
			parts = append(parts, "and "+strconv.Itoa(len(live)-n)+" more (see report metadata)")
		}
		return strings.Join(parts, "; ")
	}
	n := len(live)
	for ; n >= 0; n-- {
		if s := render(n); len(s) <= budget {
			break
		}
	}
	if n < 0 || len(live) == 0 {
		return ""
	}
	for _, i := range live[:n] {
		for k := exampleNames; k >= 1; k-- {
			levels[i] = k
			if len(render(n)) <= budget {
				break
			}
			levels[i] = 0
		}
	}
	return render(n)
}

// entryMax is the longest metadata entry: the backend keeps 240 bytes of each.
const entryMax = 240

// chunkNames writes one metadata entry per run of names that fits entryMax,
// each starting with head, so an entry is never cut by a reader.
func chunkNames(head string, list names) []string {
	var out []string
	cur := head
	empty := true
	for _, raw := range list.all {
		n := Sanitize(raw)
		sep := ", "
		if empty {
			sep = ""
		}
		if len(cur)+len(sep)+len(n) > entryMax && !empty {
			out = append(out, cur)
			cur, empty = head, true
			sep = ""
		}
		cur += sep + n
		empty = false
	}
	if !empty {
		out = append(out, cur)
	}
	if omitted := list.n - len(list.all); omitted > 0 {
		out = append(out, head+"and "+strconv.Itoa(omitted)+" more not listed")
	}
	return out
}

// ChunkEntries writes items (already sanitised) as metadata entries, each
// starting with head and at most 240 bytes, so a reader that keeps 240 bytes of
// an entry never cuts one.
func ChunkEntries(head string, items []string) []string {
	var l names
	l.all = items
	l.n = len(items)
	return chunkNames(head, l)
}

// Limitations is the complete listing for the report's metadata.coverage
// .limitations: one or more entries per kind, each starting with the analyzer's
// name, at most 240 bytes, every kept name sanitised (contract C1, C2).
func (c Coverage) Limitations(analyzer string) []string {
	var out []string
	for _, p := range c.lostParts() {
		if p.list.n == 0 {
			continue
		}
		head := analyzer + ": lost evaluation, " + p.label + ": "
		out = append(out, chunkNames(head, p.list)...)
	}
	for _, e := range c.excluded {
		head := analyzer + ": " + DeclaredMarker + " " + string(e.reason) + ": "
		out = append(out, chunkNames(head, e.list)...)
	}
	return out
}

// NotParsedNames is every kept name recorded as not parsed, sanitised.
func (c Coverage) NotParsedNames() []string { return c.notParsed.first(len(c.notParsed.all)) }

// Names is every kept name of one declared reason, sanitised; for tests and
// for callers that build their own listing.
func (c Coverage) Names(reason Reason) []string {
	for _, e := range c.excluded {
		if e.reason == reason {
			return e.list.first(len(e.list.all))
		}
	}
	return nil
}

// plural is "1 file" or "3 files".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}
