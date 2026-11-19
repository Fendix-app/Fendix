package scope

// Release Closure Sprint, correction loop CL2-3 (owner ruling OR-88 item 3): every limit,
// budget and give-up of the escape and source-encoding code reads as lost evaluation, never
// as clean and never as a reading that skips code. The JavaScript and TypeScript lexer's own
// limits are in jsescape_giveup_test.go; this file holds the rest of the audit, one test per
// give-up (the table is in the CL2-3 report).

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

func escBS() string { return `\` }

// escapes.go: a file over the cap that reaches EscapeLostFile anyway (the callers measure a
// file before they open it, so this is a file that grew in between) is lost, not clean.
func TestEscapeLostFileOverTheCapIsLostNotClean(t *testing.T) {
	code := escBS() + "u0065xec(1);\n"
	over := code + strings.Repeat("// padding\n", MaxFileBytes/10)
	if len(over) <= MaxFileBytes {
		t.Fatalf("fixture is %d bytes, want over %d", len(over), MaxFileBytes)
	}
	for _, name := range []string{"a.js", "a.ts", "A.JAVA"} {
		if why, lost := EscapeLostFile(name, strings.NewReader(over)); !lost || why == "" {
			t.Errorf("%s: a file over the cap read as clean (%q, %v)", name, why, lost)
		}
	}
	// the clean case over the cap is lost too: nothing about a file that was not read is evidence
	clean := strings.Repeat("// padding\n", MaxFileBytes/10+10)
	if _, lost := EscapeLostFile("a.js", strings.NewReader(clean)); !lost {
		t.Errorf("an over-cap file with no escape read as clean")
	}
}

func TestEscapeLostFileAtTheCapIsReadInFull(t *testing.T) {
	pad := func(n int, s string) string { return s + strings.Repeat(" ", n-len(s)) }
	inCode := pad(MaxFileBytes, escBS()+"u0065xec(1);")
	if why, lost := EscapeLostFile("a.js", strings.NewReader(inCode)); !lost || why != EscapeReasonIdentifier {
		t.Errorf("a file of exactly the cap: %q, %v; want an identifier escape", why, lost)
	}
	inString := pad(MaxFileBytes, `"`+escBS()+`u0041";`)
	if _, lost := EscapeLostFile("a.js", strings.NewReader(inString)); lost {
		t.Errorf("an escape in a string at the cap read as lost")
	}
}

func TestEscapeLostFileReadErrorIsLost(t *testing.T) {
	r := io.MultiReader(strings.NewReader("// a\n"), iotest.ErrReader(errors.New("boom")))
	if why, lost := EscapeLostFile("a.js", r); !lost || why != EscapeReasonUnreadable {
		t.Errorf("a read that fails: %q, %v; want %q, lost", why, lost, EscapeReasonUnreadable)
	}
	if _, lost := EscapeLostFile("a.py", iotest.ErrReader(errors.New("boom"))); lost {
		t.Errorf("a name EscapeCovered does not name is never lost by it")
	}
}

// escapes.go: EscapeLostPath is the entry point for an analyzer that reads the path itself.
// Whatever stops it reading the file (a name swapped for a pipe after the walk, a file that
// vanished or grew, a directory) is lost evaluation, never "no escape".
func TestEscapeLostPathUnreadableIsLost(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.js")
	if err := os.WriteFile(good, []byte(escBS()+"u0065val(1);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(dir, "clean.js")
	if err := os.WriteFile(clean, []byte(`const s = "`+escBS()+`u0041";`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.js")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), 100), 0o644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "pipe.js")
	haveFifo := mkfifo(fifo) == nil
	if why, lost := EscapeLostPath("good.js", good, MaxFileBytes); !lost || why != EscapeReasonIdentifier {
		t.Errorf("a readable file with an escape: %q, %v", why, lost)
	}
	if why, lost := EscapeLostPath("clean.js", clean, MaxFileBytes); lost {
		t.Errorf("a readable file with no escape in code: %q, lost", why)
	}
	cases := map[string]string{"missing": filepath.Join(dir, "nope.js"), "directory": dir, "over the limit": big}
	if haveFifo {
		cases["named pipe"] = fifo
	}
	for name, p := range cases {
		limit := int64(MaxFileBytes)
		if name == "over the limit" {
			limit = 10
		}
		if why, lost := EscapeLostPath("x.js", p, limit); !lost || why != EscapeReasonUnreadable {
			t.Errorf("%s: %q, %v; want %q, lost", name, why, lost, EscapeReasonUnreadable)
		}
	}
	if _, lost := EscapeLostPath("x.py", filepath.Join(dir, "nope.py"), MaxFileBytes); lost {
		t.Errorf("a name EscapeCovered does not name is never lost by it")
	}
}

// javaescape.go has no limit, no budget and no give-up: one linear pass. A structural escape
// at the very end of a file of the cap's size is found.
func TestJavaStructuralEscapeHasNoLimit(t *testing.T) {
	src := append(bytes.Repeat([]byte("// pad\n"), MaxFileBytes/7), []byte("String s = \"\\u000a\";\n")...)
	if got := JavaStructuralEscape(src); !got.Found || got.Offset != len(src)-len("\\u000a\";\n") {
		t.Errorf("an escape after %d bytes: %+v", len(src), got)
	}
	// a truncated escape at the end of the file is no escape (the compiler rejects it)
	if got := JavaStructuralEscape([]byte("// \\u00")); got.Found {
		t.Errorf("a truncated escape read as one: %+v", got)
	}
}

// pysource.go: every way ClassifyPythonStream gives up is PyUndeterminable, which is Lost().
func TestPythonStreamGiveUpsAreLostEvaluation(t *testing.T) {
	// the limit: a first line that never ends decides nothing within it
	long := append([]byte("#"), bytes.Repeat([]byte("x"), 100<<10)...)
	got, head, err := ClassifyPythonStream(bytes.NewReader(long), 20<<10)
	if err != nil || got.Verdict != PyUndeterminable || !got.Lost() || len(head) > 20<<10 {
		t.Errorf("limit: %+v, %d bytes, %v; want undeterminable, lost, within the limit", got, len(head), err)
	}
	// a read error: what was read is classified undeterminable and the error is handed back
	boom := errors.New("boom")
	got, _, err = ClassifyPythonStream(io.MultiReader(strings.NewReader("# a"), iotest.ErrReader(boom)), 1<<20)
	if !errors.Is(err, boom) || got.Verdict != PyUndeterminable || !got.Lost() {
		t.Errorf("read error: %+v, %v; want undeterminable, lost and the error", got, err)
	}
	// a prefix of a file never decides on an unfinished line
	if got := ClassifyPythonSource([]byte("# coding: utf"), false); got.Verdict != PyUndeterminable || !got.Lost() {
		t.Errorf("an unfinished first line read %+v; want undeterminable and lost", got)
	}
	if got := ClassifyPythonSource([]byte("# a\n# coding: utf"), false); got.Verdict != PyUndeterminable || !got.Lost() {
		t.Errorf("an unfinished second line read %+v; want undeterminable and lost", got)
	}
	// the file reader: the limit is the cap plus one byte, and a first line that long is lost
	if got := ClassifyPythonFile(bytes.NewReader(append([]byte("#"), bytes.Repeat([]byte("x"), MaxFileBytes+10)...))); got.Verdict != PyUndeterminable || !got.Lost() {
		t.Errorf("a first line longer than the cap read %+v; want undeterminable and lost", got)
	}
}

// scope.go: only the first maxKept names of a kind are kept for the report, but the count is
// exact and the file is lost: truncating a list never turns a loss into a clean run.
func TestCoverageLossIsExactPastTheNamesItKeeps(t *testing.T) {
	var c Coverage
	total := 0
	for i := 0; i < maxKept+25; i++ {
		name := "f" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + "_" + strings.Repeat("0", i/1000) + itoa(i) + ".js"
		c.TooLarge(name)
		c.Unreadable(name)
		c.NotParsed(name)
		c.NotText(name)
		c.NotScanned(name)
		total += 5
	}
	if !c.Lost() || c.LostFiles() != total {
		t.Errorf("Lost=%v LostFiles=%d, want true and %d", c.Lost(), c.LostFiles(), total)
	}
	// a budget too small for even the counts: the counts are returned anyway, never ""
	for _, budget := range []int{0, 1, 10, 80} {
		d := c.LostDetail(budget)
		if d == "" || !strings.Contains(d, "lost evaluation") || strings.HasPrefix(d, "and ") {
			t.Errorf("budget %d: LostDetail = %q; want the counts", budget, d)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}
