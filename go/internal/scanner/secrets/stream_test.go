package secrets

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"testing/iotest"
)

// R-010 (security3-03, redteam3-secrets-01): the scanner streams every file in
// bounded memory and matches every line, however long, in overlapping windows.

func withWindow(t *testing.T, w, o int) {
	t.Helper()
	ow, oo := lineWindowBytes, lineWindowOverlap
	lineWindowBytes, lineWindowOverlap = w, o
	t.Cleanup(func() { lineWindowBytes, lineWindowOverlap = ow, oo })
}

// splitLinesRef is the line splitter the scanner used before it streamed:
// \r\n, \n and a lone \r end a line; a final empty piece is not a line.
func splitLinesRef(text string) []string {
	if text == "" {
		return nil
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func collectLines(t *testing.T, text string, chunk int) map[int]string {
	t.Helper()
	out := map[int]string{}
	var r = strings.NewReader(text)
	err := streamLines(iotest.OneByteReader(r), func(seg segment) error {
		if chunk == 0 && seg.lineno < 0 {
			return nil
		}
		out[seg.lineno] += seg.text
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Line numbering is exactly the old splitter's, for every line ending, with the
// file delivered one byte at a time (so a \r\n pair is split across reads).
func TestStreamLines_NumbersLinesLikeTheOldSplitter(t *testing.T) {
	for _, text := range []string{
		"a\nb\nc", "a\nb\nc\n", "a\r\nb\r\nc\r\n", "a\rb\rc", "a\n\n\nb", "\n\na", "a\r\n\r\nb\r", "\r\n", "\r", "\n", "", "x",
		"a\r\r\nb", "a\n\rb",
	} {
		want := splitLinesRef(text)
		got := collectLines(t, text, 0)
		var wantNonEmpty int
		for i, l := range want {
			if l == "" {
				if _, ok := got[i+1]; ok {
					t.Errorf("%q: empty line %d was passed to the matcher", text, i+1)
				}
				continue
			}
			wantNonEmpty++
			if got[i+1] != l {
				t.Errorf("%q: line %d = %q, want %q", text, i+1, got[i+1], l)
			}
		}
		if len(got) != wantNonEmpty {
			t.Errorf("%q: got lines %v, want %d non-empty lines of %q", text, got, wantNonEmpty, want)
		}
	}
}

// A line longer than a window is passed in windows whose owned regions tile the
// line exactly once.
func TestStreamLines_OwnedRegionsTileALongLine(t *testing.T) {
	withWindow(t, 100, 30)
	line := strings.Repeat("; ", 265) // 530 bytes, no token bytes to blank
	var owned strings.Builder
	var segs int
	err := streamLines(strings.NewReader("first\n"+line+"\nlast\n"), func(s segment) error {
		if s.lineno != 2 {
			return nil
		}
		segs++
		if (segs == 1) != s.first {
			t.Errorf("segment %d: first = %v", segs, s.first)
		}
		owned.WriteString(s.text[s.ownStart:s.ownEnd])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if owned.String() != line {
		t.Errorf("owned regions do not tile the line: %d bytes, want %d", owned.Len(), len(line))
	}
	if segs < 7 {
		t.Errorf("a 530-byte line in 100-byte windows took %d windows", segs)
	}
}

// Memory is bounded: an endless line is cut at the cap and never held whole.
func TestStreamLines_HoldsOnlyAWindowOfAnEndlessLine(t *testing.T) {
	withWindow(t, 1<<10, 256)
	src := &endless{}
	maxText := 0
	err := streamLines(src, func(s segment) error {
		if len(s.text) > maxText {
			maxText = len(s.text)
		}
		if src.n > 1<<20 {
			return fmt.Errorf("stop")
		}
		return nil
	})
	if err == nil || maxText > 1<<10 {
		t.Fatalf("err %v, largest window %d bytes; want windows of at most 1024", err, maxText)
	}
}

type sample struct {
	id    string
	value string
}

// The credentials that matter, each with a distinct shape, built from pieces
// so this file holds no key-shaped literal.
func samples() []sample {
	return []sample{
		{"SEC-AWS_ACCESS_KEY", "AKIA" + "QZXCVBNMASDFGHJK"},
		{"SEC-GITHUB_TOKEN", "ghp_" + strings.Repeat("aB3dE5", 6)},
		{"SEC-STRIPE_LIVE_KEY", "sk_live_" + strings.Repeat("Qw8rT2", 4)},
		{"SEC-JWT_TOKEN", "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0NTY3OA" + ".abcdefghijklmnop"},
	}
}

// Whatever the window size, a long line yields the same findings as the same
// line matched whole: every credential on it, once, at its line.
func TestScan_LongLineFindingsEqualWholeLineFindings(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	ss := samples()
	for trial := 0; trial < 60; trial++ {
		var b strings.Builder
		var want []string
		for k := 0; k < 1+rng.Intn(4); k++ {
			b.WriteString(strings.Repeat("x", rng.Intn(700)))
			b.WriteString(` "`)
			sm := ss[rng.Intn(len(ss))]
			b.WriteString(sm.value)
			b.WriteString(`"; `)
			want = append(want, sm.id)
		}
		b.WriteString(strings.Repeat("y", rng.Intn(300)))
		line := b.String()
		sort.Strings(want)

		whole := scanLineFindings(t, line, 1<<20, 1<<10)
		for _, w := range []struct{ win, ov int }{{200, 60}, {333, 100}, {1000, 120}} {
			got := scanLineFindings(t, line, w.win, w.ov)
			if strings.Join(got, ",") != strings.Join(whole, ",") {
				t.Fatalf("trial %d, window %d/%d: findings %v, whole-line %v\nline: %q", trial, w.win, w.ov, got, whole, line)
			}
		}
		if len(whole) < len(want) {
			t.Fatalf("trial %d: the whole-line scan found %v, the line holds %v: %q", trial, whole, want, line)
		}
	}
}

func scanLineFindings(t *testing.T, line string, w, o int) []string {
	t.Helper()
	withWindow(t, w, o)
	out, err := scanReader(context.Background(), "f.txt", "f.txt", strings.NewReader("first line\n"+line+"\nlast\n"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range out {
		got = append(got, fmt.Sprintf("%s@%s", e.ev.ID, e.ev.Endpoint))
	}
	sort.Strings(got)
	return got
}

// A credential on a boundary of the window geometry is found exactly once:
// every offset across two window starts, for a window of 100 and an overlap of 30.
func TestScan_CredentialOnAWindowBoundaryIsFoundOnce(t *testing.T) {
	withWindow(t, 100, 30)
	key := "AKIA" + "QZXCVBNMASDFGHJK"
	for off := 0; off < 260; off++ {
		line := strings.Repeat("q", off) + " " + key + " " + strings.Repeat("z", 150)
		out, err := scanReader(context.Background(), "f.txt", "f.txt", strings.NewReader(line+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 || out[0].ev.ID != "SEC-AWS_ACCESS_KEY" {
			t.Fatalf("key at offset %d: %d findings %v, want exactly one", off, len(out), out)
		}
	}
}

// A credential that straddles a window start is redacted as it is when the line
// is matched whole: the window carries the bytes before its owned region, so the
// redaction pass sees the whole credential (the earlier design blanked the
// half-token, which lost a credential glued to it, redteam4-secrets-01). No
// matched part of it reaches the evidence of the finding beside it, and what is
// visible of its unmatched remainder is what the whole-line scan shows.
func TestScan_WindowedEvidenceDoesNotLeakAStraddlingCredential(t *testing.T) {
	// ghp_ + 36 matched characters, then an unmatched remainder.
	line := strings.Repeat("q", 55) + " ghp_" + "aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5aB3dE5" + "TAILOFTHEVALUE" + " " +
		`AKIA` + `QZXCVBNMASDFGHJK` + strings.Repeat("z", 120)
	for _, g := range []struct{ w, o int }{{100, 45}, {120, 50}, {160, 60}} {
		withWindow(t, g.w, g.o)
		out, err := scanReader(context.Background(), "f.txt", "f.txt", strings.NewReader(line+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if len(out) == 0 {
			t.Fatalf("window %d/%d: no findings", g.w, g.o)
		}
		for _, e := range out {
			if strings.Contains(e.ev.Evidence, "aB3dE5") {
				t.Errorf("window %d/%d: evidence of %s leaks part of a credential: %q", g.w, g.o, e.ev.ID, e.ev.Evidence)
			}
		}
	}
}

// A .env line longer than a window is matched in its first window, where the
// ^ anchor holds; the later windows do not match it again.
func TestScan_LongEnvLineIsMatchedOnce(t *testing.T) {
	withWindow(t, 200, 60)
	line := "STRIPE_SECRET_KEY=" + strings.Repeat("v", 900)
	out, err := scanReader(context.Background(), ".env", ".env", strings.NewReader(line+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range out {
		if e.ev.ID == "SEC-ENV_SECRET" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("a long .env line produced %d ENV_SECRET findings, want 1: %v", n, out)
	}
}

// A later window does not start a line: an ENV-shaped run that begins exactly at
// a window start in the middle of a long line is not an assignment at the start
// of a line, and is not reported as one.
func TestScan_LaterWindowDoesNotMatchALineStartPattern(t *testing.T) {
	withWindow(t, 200, 60)
	line := strings.Repeat("#", 140) + "X_API_KEY=" + strings.Repeat("hunter22", 40) // window 2 starts at offset 140
	out, err := scanReader(context.Background(), ".env", ".env", strings.NewReader(line+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range out {
		t.Errorf("a finding on a line that does not start with an assignment: %s %s", e.ev.ID, e.ev.Evidence)
	}
}

func TestUTF16FileIsDecodedNotReadAsNULs(t *testing.T) {
	root := t.TempDir()
	key := "AKIA" + "QZXCVBNMASDFGHJK"
	text := "AWS_ACCESS_KEY_ID=" + key + "\r\n"
	for _, bom := range []struct {
		name  string
		bytes func(string) []byte
	}{
		{"le.env", func(s string) []byte {
			b := []byte{0xFF, 0xFE}
			for _, r := range s {
				b = append(b, byte(r), byte(r>>8))
			}
			return b
		}},
		{"be.env", func(s string) []byte {
			b := []byte{0xFE, 0xFF}
			for _, r := range s {
				b = append(b, byte(r>>8), byte(r))
			}
			return b
		}},
	} {
		writeFile(t, root, bom.name, string(bom.bytes(text)))
	}
	fs, cov, err := ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	aws := 0
	for _, f := range fs {
		if f.ID == "SEC-AWS_ACCESS_KEY" {
			aws++
		}
	}
	if cov.Lost() || aws != 2 {
		t.Errorf("UTF-16LE and UTF-16BE files: findings %v, lost %q", endpointsOf(fs), cov.LostDetail(240))
	}
}
