package semgrep

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Decision D1' (round 4), tightened by C4B-27: a Semgrep parse problem that
// prevents evaluating an in-scope file is a coverage gap. Whole-file failures
// are always lost; PartialParsing stays ok only when its skipped spans are
// reported and the engine can show the lines they cover hold no analysable code.

func TestPartialParseIsOkOnlyWhenTheSkippedLinesHoldNoCode(t *testing.T) {
	root := t.TempDir()
	handler := "app.get('/u', (req, res) => { db.query(\"SELECT * FROM u WHERE id = '\" + req.query.id + \"'\"); });"
	for _, tc := range []struct {
		name, file, body string
		spans            []Span
		ok               bool
	}{
		{"a skipped comment line", "a.py", "x = 1\n# a note\ny = 2\n", []Span{{2, 2}}, true},
		{"skipped blank and comment lines", "b.js", "a();\n\n// note\n/* one line */\nb();\n", []Span{{2, 4}}, true},
		// C4B-27: one skipped line, a tiny share of the file, that holds the handler.
		{"one skipped line of code in a long file", "c.js", strings.Repeat("// pad\n", 200) + handler + "\n", []Span{{201, 201}}, false},
		{"a skipped long line holding the handler", "d.js", "const a = 1;\n" + handler + "\nconst b = 2;\n", []Span{{2, 2}}, false},
		{"a skipped token on a code line", "e.py", "x = 1\ny = ??? 2\nz = 3\n", []Span{{2, 2}}, false},
		{"code after a comment marker is not a comment line", "f.py", "x = 1\ny = 2  # trailing\n", []Span{{2, 2}}, false},
		{"a line that starts a block comment and runs on", "g.js", "a();\n/* start\n b(); */ c();\n", []Span{{2, 2}}, false},
		{"a comment marker of another language", "h.py", "// not a python comment\nx = 1\n", []Span{{1, 1}}, false},
		{"a span past the end of the file", "i.py", "# a\n", []Span{{1, 5}}, false},
		{"a span before the first line", "j.py", "# a\n", []Span{{0, 1}}, false},
		{"every line skipped, all code", "k.py", "x = 1\n", []Span{{1, 1}}, false},
		{"no span", "l.py", "# a\n", nil, false},
	} {
		if err := os.WriteFile(filepath.Join(root, tc.file), []byte(tc.body), 0o644); err != nil {
			t.Fatal(err)
		}
		p := PartialParse{Path: tc.file, Spans: tc.spans, Reported: len(tc.spans) > 0}
		if got := p.judge(root); got != tc.ok {
			t.Errorf("%s: judge = %v, want %v", tc.name, got, tc.ok)
		}
	}
}

func TestSpansAreMergedAndCounted(t *testing.T) {
	spans := []Span{{10, 12}, {3, 3}, {11, 15}, {16, 16}, {40, 41}}
	merged := mergeSpans(spans)
	want := []Span{{3, 3}, {10, 16}, {40, 41}}
	if fmt.Sprint(merged) != fmt.Sprint(want) {
		t.Errorf("mergeSpans = %v, want %v", merged, want)
	}
	if got := skippedLines(spans); got != 1+7+2 {
		t.Errorf("skippedLines = %d, want 10", got)
	}
	if mergeSpans(nil) != nil {
		t.Error("no spans merge to none")
	}
}

// Real Semgrep 1.182.1 writes the skipped spans in the error's type and again
// in `spans`; either is read, and an entry with neither is not "reported".
func TestPartialParsingSpansAreDecoded(t *testing.T) {
	root := t.TempDir()
	doc := func(entry string) string {
		return `{"results":[],"errors":[` + entry + `],"time":{"fixpoint_timeouts":[]}}`
	}
	typeSpan := `{"code":3,"level":"warn","type":["PartialParsing",[{"path":"ROOT/a.py","start":{"line":2,"col":3,"offset":0},"end":{"line":3,"col":11,"offset":37}}]],"message":"m","path":"ROOT/a.py"}`
	got := parseRun([]byte(strings.ReplaceAll(doc(typeSpan), "ROOT", root)), root).PartialParses
	if len(got) != 1 || got[0].Path != "a.py" || !got[0].Reported || fmt.Sprint(got[0].Spans) != "[{2 3}]" {
		t.Errorf("type spans: %+v", got)
	}
	onlySpans := `{"code":3,"level":"warn","type":["PartialParsing",[]],"message":"m","path":"ROOT/b.js","spans":[{"file":"ROOT/b.js","start":{"line":7,"col":1},"end":{"line":7,"col":9}}]}`
	got = parseRun([]byte(strings.ReplaceAll(doc(onlySpans), "ROOT", root)), root).PartialParses
	if len(got) != 1 || !got[0].Reported || fmt.Sprint(got[0].Spans) != "[{7 7}]" {
		t.Errorf("entry spans: %+v", got)
	}
	for name, entry := range map[string]string{
		"no span anywhere":    `{"code":3,"level":"warn","type":"PartialParsing","message":"m","path":"ROOT/c.py"}`,
		"empty list":          `{"code":3,"level":"warn","type":["PartialParsing",[]],"message":"m","path":"ROOT/c.py"}`,
		"a span with no line": `{"code":3,"level":"warn","type":["PartialParsing",[{"path":"x","start":{},"end":{}}]],"message":"m","path":"ROOT/c.py"}`,
		"an inverted span":    `{"code":3,"level":"warn","type":["PartialParsing",[{"path":"x","start":{"line":9},"end":{"line":2}}]],"message":"m","path":"ROOT/c.py"}`,
	} {
		got := parseRun([]byte(strings.ReplaceAll(doc(entry), "ROOT", root)), root).PartialParses
		if len(got) != 1 || got[0].Reported {
			t.Errorf("%s: %+v; the skipped lines are not known", name, got)
		}
	}
	// Two entries for one file are one partial parse with both spans.
	two := typeSpan + "," + strings.Replace(typeSpan, `"line":2,"col":3`, `"line":9,"col":3`, 1)
	two = strings.Replace(two, `"end":{"line":3,"col":11,"offset":37}}]],"message":"m","path":"ROOT/a.py"},{"code"`, `"end":{"line":3,"col":11,"offset":37}}]],"message":"m","path":"ROOT/a.py"},{"code"`, 1)
	got = parseRun([]byte(strings.ReplaceAll(doc(two), "ROOT", root)), root).PartialParses
	if len(got) != 1 {
		t.Errorf("two entries for one file: %+v", got)
	}
}

// A document through ScanRun: whole-file failures and large or unreported
// partial parses are lost evaluation naming the file; a small reported one is
// not, and its lines are kept for the detail.
func TestScanRunJudgesParseProblems(t *testing.T) {
	lines := func(n int) string { return strings.Repeat("x = 1\n", n) }
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"whole.java": "class A {\n", "small.py": lines(4) + "# a note\n" + lines(35), "codeskip.py": lines(40), "large.py": lines(40), "nospan.py": lines(40), "ok.py": lines(3),
	})
	entry := func(typ, file string, start, end int) string {
		t := `"` + typ + `"`
		if typ == "PartialParsing" {
			t = fmt.Sprintf(`["PartialParsing",[{"path":"ROOT/%s","start":{"line":%d,"col":1},"end":{"line":%d,"col":2}}]]`, file, start, end)
		}
		return fmt.Sprintf(`{"code":3,"level":"warn","type":%s,"message":"m","path":"ROOT/%s"}`, t, file)
	}
	doc := `{"version":"1.182.1","results":[],"errors":[` + strings.Join([]string{
		entry("Syntax error", "whole.java", 0, 0),
		entry("PartialParsing", "small.py", 5, 5),
		entry("PartialParsing", "codeskip.py", 5, 5),
		entry("PartialParsing", "large.py", 3, 30),
		`{"code":3,"level":"warn","type":"PartialParsing","message":"m","path":"ROOT/nospan.py"}`,
	}, ",") + `],"paths":{"scanned":["ROOT/whole.java","ROOT/small.py","ROOT/codeskip.py","ROOT/large.py","ROOT/nospan.py","ROOT/ok.py"]},"time":{"fixpoint_timeouts":[]},"skipped_rules":[]}`
	installFakeSemgrep(t, strings.ReplaceAll(doc, "ROOT", root), "", 0)
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	run, err := ScanRun(t.Context(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := run.Coverage.NotParsedNames(), "codeskip.py large.py nospan.py whole.java"; strings.Join(sortedCopy(got), " ") != want {
		t.Errorf("not parsed = %q, want %q", got, want)
	}
	if len(run.ParseFailures) != 1 || run.ParseFailures[0].Path != "whole.java" {
		t.Errorf("ParseFailures = %+v", run.ParseFailures)
	}
	var kept []string
	for _, p := range run.PartialParses {
		if !p.Lost {
			kept = append(kept, p.Describe(func(s string) string { return s }))
		}
	}
	if strings.Join(kept, ";") != "small.py 5" {
		t.Errorf("kept partial parses = %q; want only small.py 5", kept)
	}
	if got := run.Coverage.LostDetail(1 << 20); !strings.Contains(got, "4 not parsed by semgrep (whole.java, codeskip.py, large.py +1 more)") {
		t.Errorf("lost detail = %q", got)
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// A path in the document that is not under the root cannot be judged: lost.
func TestAPartialParseOfAFileThatCannotBeReadIsLost(t *testing.T) {
	root := t.TempDir()
	p := PartialParse{Path: "gone.py", Spans: []Span{{2, 2}}, Reported: true}
	if p.judge(root) {
		t.Error("a file that cannot be read was judged ok")
	}
	if err := os.WriteFile(filepath.Join(root, "gone.py"), []byte("a\n# b\nc\nd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !p.judge(root) || p.Total != 4 || p.Skipped != 1 {
		t.Errorf("judge = total %d skipped %d", p.Total, p.Skipped)
	}
}
