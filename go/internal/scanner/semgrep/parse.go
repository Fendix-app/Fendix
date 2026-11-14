package semgrep

import (
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

// inertLine reports whether line holds no analysable code: it is blank, a
// whole-line comment, or a one-line block comment (C-family only). It looks at
// the line alone, never at the lines around it, so a line inside a multi-line
// comment that does not itself start a comment is code as far as this proof
// goes: that is the safe side.
func inertLine(line, comment string) bool {
	t := strings.TrimSpace(line)
	switch {
	case t == "":
		return true
	case comment != "" && strings.HasPrefix(t, comment):
		return true
	case comment == "//" && strings.HasPrefix(t, "/*") && strings.HasSuffix(t, "*/") && len(t) >= 4 &&
		!strings.Contains(t[2:len(t)-2], "*/") && !strings.Contains(t[2:len(t)-2], "/*"):
		return true
	}
	return false
}

// spansHoldNoCode reports whether every line the spans touch is inert (see
// inertLine). A span outside the file, or lines that cannot be read, are not
// shown to be inert.
func spansHoldNoCode(lines []string, spans []Span, ext string) bool {
	comment := lineCommentOf(ext)
	for _, sp := range spans {
		if sp.StartLine < 1 || sp.EndLine > len(lines) {
			return false
		}
		for n := sp.StartLine; n <= sp.EndLine; n++ {
			if !inertLine(lines[n-1], comment) {
				return false
			}
		}
	}
	return len(spans) > 0
}

// judge sets Skipped and Total from the file under absRoot and reports whether
// the run may stay ok for it: the spans are reported and the engine can show
// the lines they cover hold no analysable code.
func (p *PartialParse) judge(absRoot string) bool {
	lines := splitLines(readSource(filepath.Join(absRoot, filepath.FromSlash(p.Path))))
	p.Total = len(lines)
	p.Skipped = skippedLines(p.Spans)
	return p.Reported && p.Total > 0 && spansHoldNoCode(lines, p.Spans, path.Ext(p.Path))
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
