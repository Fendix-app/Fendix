package semgrep

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Decision D1' (round 4): a Semgrep parse problem that prevents evaluating an
// in-scope file is a coverage gap.
//
//   - A whole-file failure (parseFailureTypes) is a ParseFailure: Semgrep ran no
//     rule on the file. ScanRun records it as lost evaluation, the file named.
//   - "PartialParsing" is a PartialParse: Semgrep matched what it could parse
//     and reports the spans it skipped (in the error's type, and again in its
//     `spans`). The analysed scope is then known, and the run stays ok only
//     when the skipped lines are few (partialSkipOK) and every span is
//     reported; the detail says which lines were skipped. A PartialParsing
//     entry with no usable span, or whose spans cover more than a few lines of
//     the file, is lost evaluation like a whole-file failure.
//
// Real Semgrep 1.182.1 behaviour that fixes the bound (testdata/runs/
// partial-*.json and the real-Semgrep tests): after a syntax error inside a
// class body, tree-sitter skips the REST of the class, so one error can leave
// most of a file unevaluated, and the span says so; a one-token error skips
// one token.

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
	// spans are not reported, or cover more than a few lines (partialSkipOK).
	Lost bool
}

// partialSkipMaxLines and partialSkipPercent bound how much of a file a
// partial parse may skip and still read ok: at most the larger of three lines
// and 5% of the file. They are deliberately small. One unsupported token costs
// a line; a skipped class body or function costs the code the rules exist to
// read.
const (
	partialSkipMaxLines = 3
	partialSkipPercent  = 5
)

// partialSkipOK reports whether skipped of total lines is few enough for the
// run to stay ok. The allowance never reaches the whole file: a file of three
// lines or fewer whose every line was skipped (DE4-03: a one-line file that is
// one syntax error) was not analysed at all, and that is lost evaluation, never
// "a few lines".
func partialSkipOK(skipped, total int) bool {
	if total <= 0 {
		return skipped == 0
	}
	allowed := (total*partialSkipPercent + 99) / 100
	if allowed < partialSkipMaxLines {
		allowed = partialSkipMaxLines
	}
	if allowed > total-1 {
		allowed = total - 1
	}
	return skipped <= allowed
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

// countLines is how many lines the file at p has: its newlines, plus one for a
// last line with no newline. 0 when it cannot be read.
func countLines(p string) int {
	data, err := os.ReadFile(p)
	if err != nil || len(data) == 0 {
		return 0
	}
	n := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		n++
	}
	return n
}

// judge sets Skipped and Total from the file under absRoot and reports whether
// the run may stay ok for it: the spans are reported and few.
func (p *PartialParse) judge(absRoot string) bool {
	p.Total = countLines(filepath.Join(absRoot, filepath.FromSlash(p.Path)))
	p.Skipped = skippedLines(p.Spans)
	return p.Reported && p.Total > 0 && partialSkipOK(p.Skipped, p.Total)
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
