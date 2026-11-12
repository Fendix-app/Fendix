package scope

import (
	"strings"
	"testing"
)

func TestGeneratedArtifactsAreDeclaredByName(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"package-lock.json", "lockfile"},
		{"web/yarn.lock", "lockfile"},
		{"pnpm-lock.yaml", "lockfile"},
		{"poetry.lock", "lockfile"},
		{"Pipfile.lock", "lockfile"},
		{"Cargo.lock", "lockfile"},
		{"go.sum", "lockfile"},
		{"composer.lock", "lockfile"},
		{"Gemfile.lock", "lockfile"},
		{`sub\package-lock.json`, "lockfile"},
		{"public/app.min.js", "minified"},
		{"public/APP.MIN.JS", "minified"},
		{"styles/site.min.css", "minified"},
		{"public/app.js.map", "source map"},
		{"site.css.map", "source map"},
		// In scope: source, and names that only look like the declared ones.
		{"app.js", ""},
		{"package.json", ""},
		{"locks/package-lock.json.bak", ""},
		{"min.js", ""},
		{"admin.js", ""},
		{"package-lock.json/app.js", ""},
		{"roadmap.md", ""},
		{"Go.sum", ""},
	} {
		if got := Generated(tc.path); got != tc.want {
			t.Errorf("Generated(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestEmptyCoverageSaysNothing(t *testing.T) {
	var c Coverage
	if c.Lost() || c.Declared() || c.LostDetail(240) != "" || c.DeclaredDetail(240) != "" {
		t.Errorf("zero Coverage reports something: %+v", c)
	}
}

func TestLostDetailNamesTheFilesAndCountsTheRest(t *testing.T) {
	var c Coverage
	for _, p := range []string{"a.js", "b.py", "c.go", "d.java"} {
		c.TooLarge(p)
	}
	c.Unreadable("keys/secret.py")
	if !c.Lost() || c.LostFiles() != 5 {
		t.Fatalf("Lost=%v LostFiles=%d; want true, 5", c.Lost(), c.LostFiles())
	}
	got := c.LostDetail(240)
	const want = "lost evaluation: 5 in-scope files not read: 4 over 1048576 bytes (a.js, b.py, c.go +1 more), 1 unreadable (keys/secret.py)"
	if got != want {
		t.Errorf("LostDetail =\n %q\nwant\n %q", got, want)
	}
}

func TestDetailsStayWithinTheirBudget(t *testing.T) {
	var c Coverage
	long := strings.Repeat("deeply/nested/", 12) + "file.js"
	for i := 0; i < 50; i++ {
		c.TooLarge(long)
		c.Generated(long)
		c.Pruned(long)
	}
	for _, budget := range []int{240, 120, 80} {
		if got := c.LostDetail(budget); len(got) > budget || !strings.Contains(got, "50 over 1048576 bytes") {
			t.Errorf("LostDetail(%d) = %q (%d bytes)", budget, got, len(got))
		}
		got := c.DeclaredDetail(budget)
		if len(got) > budget || strings.HasSuffix(got, "…") {
			t.Errorf("DeclaredDetail(%d) = %q (%d bytes)", budget, got, len(got))
		}
		if got != "" && !strings.Contains(got, "generated artifact 50") && !strings.Contains(got, "100 in all (see report metadata)") {
			t.Errorf("DeclaredDetail(%d) = %q lost the count", budget, got)
		}
	}
	// A budget too small for the counts gives no ok detail at all rather than
	// a cut one, and a lost detail that names no file rather than none.
	if got := c.DeclaredDetail(20); got != "" {
		t.Errorf("DeclaredDetail(20) = %q; want \"\"", got)
	}
	// Past the counts per reason the detail still says how many, and where the
	// rest is (contract C2), instead of being cut.
	if got := c.DeclaredDetail(70); got != "declared out of scope, not scanned: 100 in all (see report metadata)" {
		t.Errorf("DeclaredDetail(70) = %q", got)
	}
	if got := c.LostDetail(20); !strings.HasPrefix(got, "lost evaluation: 50 in-scope files not read: 50 over") {
		t.Errorf("LostDetail(20) = %q", got)
	}
}

func TestDeclaredDetailListsEveryKind(t *testing.T) {
	var c Coverage
	c.Exclude(ReasonLockfile, "package-lock.json")
	c.Exclude(ReasonMinified, "public/app.min.js")
	c.TestPath("tests/app.js")
	c.Exclude(ReasonNPMInstall, "node_modules/")
	if c.Lost() {
		t.Fatal("declared exclusions are not lost evaluation")
	}
	// Each reason is named with its count and its first names; the reasons come
	// in the order they were first used, and the segment starts with the marker
	// the backend and the frontend skip.
	const want = "declared out of scope, not scanned: lockfile 1 (package-lock.json), minified 1 (public/app.min.js), test/fixture path 1 (tests/app.js), installed npm packages 1 (node_modules/)"
	if got := c.DeclaredDetail(240); got != want {
		t.Errorf("DeclaredDetail =\n %q\nwant\n %q", got, want)
	}
	if !strings.HasPrefix(c.DeclaredDetail(240), DeclaredMarker) {
		t.Errorf("segment does not start with %q", DeclaredMarker)
	}
}

// The legacy name-only methods still record, under their own reasons.
func TestLegacyNameOnlyMethodsStillRecord(t *testing.T) {
	var c Coverage
	c.Generated("package-lock.json")
	c.Pruned("node_modules")
	const want = "declared out of scope, not scanned: generated artifact 1 (package-lock.json), vendored/build dir 1 (node_modules/)"
	if got := c.DeclaredDetail(240); got != want {
		t.Errorf("DeclaredDetail = %q, want %q", got, want)
	}
}

func TestNamesWithControlCharactersStayOnOneLine(t *testing.T) {
	var c Coverage
	c.Unreadable("evil\nname\x1b.py")
	if got := c.LostDetail(240); strings.ContainsAny(got, "\n\x1b") {
		t.Errorf("detail %q carries control characters", got)
	}
}

// qa3-01: a not-text file alone is lost evaluation. A mutant that dropped
// notText from Lost() survived every test of round 3.
func TestANotTextFileAloneIsLostEvaluation(t *testing.T) {
	var c Coverage
	c.NotText("blob.js")
	if !c.Lost() || c.LostFiles() != 1 {
		t.Fatalf("Lost = %v, LostFiles = %d; want true, 1", c.Lost(), c.LostFiles())
	}
	if got, want := c.LostDetail(240), "lost evaluation: 1 in-scope file not read: 1 not text (NUL bytes) (blob.js)"; got != want {
		t.Errorf("LostDetail = %q, want %q", got, want)
	}
	// And so is each of the other lost kinds, alone.
	for name, mark := range map[string]func(*Coverage){
		"too large": func(c *Coverage) { c.TooLarge("a.js") }, "unreadable": func(c *Coverage) { c.Unreadable("a.js") },
		"not scanned": func(c *Coverage) { c.NotScanned("a.js") }, "not parsed": func(c *Coverage) { c.NotParsed("a.js") },
	} {
		var k Coverage
		mark(&k)
		if !k.Lost() {
			t.Errorf("%s alone is not Lost()", name)
		}
	}
	// Declared exclusions never are.
	var d Coverage
	d.Exclude(ReasonMinified, "a.min.js")
	d.Symlink("link.py")
	if d.Lost() || !d.Declared() {
		t.Errorf("declared exclusions: Lost = %v, Declared = %v", d.Lost(), d.Declared())
	}
}

// Contract C1: a name the repository chose cannot spell a segment separator, an
// ellipsis, a control character, or anything a loss pattern is made of in a
// segment a reader scans.
func TestSanitizeAndSafeToken(t *testing.T) {
	for _, tc := range []struct{ in, sanitize, safe string }{
		{"a.js", "a.js", "a.js"},
		{"x;y.js", "x?y.js", "x?y.js"},
		{"x…y", "x?y", "x?y"},
		{"a\nb\x1b[0m.js", "a?b?[0m.js", "a?b?[0m.js"},
		{"tests/1 rule timeout, matches missing: x.js", "tests/1 rule timeout, matches missing: x.js", "tests/1?rule?timeout??matches?missing??x.js"},
		{"semgrep 1.0: dropped --x (needs 1.0.0)", "semgrep 1.0: dropped --x (needs 1.0.0)", "semgrep?1.0??dropped?--x??needs?1.0.0?"},
		{"bidi‮txt.js", "bidi?txt.js", "bidi?txt.js"},
		{"bad\xffutf8", "bad?utf8", "bad?utf8"},
	} {
		if got := Sanitize(tc.in); got != tc.sanitize {
			t.Errorf("Sanitize(%q) = %q, want %q", tc.in, got, tc.sanitize)
		}
		if got := SafeToken(tc.in); got != tc.safe {
			t.Errorf("SafeToken(%q) = %q, want %q", tc.in, got, tc.safe)
		}
	}
	long := strings.Repeat("é", 100) // 200 bytes
	got := Sanitize(long)
	if len(got) > NameMax || len(got) < NameMax-1 || strings.ContainsRune(got, '�') {
		t.Errorf("Sanitize cut a long name to %d bytes: %q", len(got), got)
	}
}

// Every name a detail or a metadata entry carries is sanitised, whichever way
// it got in.
func TestNamesInEveryRenderingAreSanitised(t *testing.T) {
	var c Coverage
	c.TooLarge("a;b.js")
	c.Exclude(ReasonMinified, "x…y.min.js")
	c.Unreadable("e\nf.py")
	for _, s := range append(c.Limitations("semgrep"), c.LostDetail(240), c.DeclaredDetail(240)) {
		if strings.ContainsAny(s, "\n…") || strings.Contains(s, "a;b") || strings.Contains(s, "x…y") {
			t.Errorf("rendering %q carries an unsanitised name", s)
		}
	}
}

// Contract C2.
func TestComposeNeverCutsASegmentAndSaysWhatItLeftOut(t *testing.T) {
	filler := strings.Repeat("c", 30)
	long := func(label string) Seg {
		return func(k int) string {
			s := label + " counts " + filler
			for i := 0; i < k; i++ {
				s += " name" + strings.Repeat("x", 20)
			}
			return s
		}
	}
	segs := []Seg{long("loss"), long("note"), long("declared")}
	// Plenty of room: names are spent on the first segments first.
	got := Compose(450, segs...)
	if !strings.HasPrefix(got, "loss counts "+filler+" namexxxxxxxxxxxxxxxxxxxx name") || len(got) > 450 {
		t.Errorf("Compose(450) = %q", got)
	}
	// The counts of every segment fit, no names do.
	want := "loss counts " + filler + "; note counts " + filler + "; declared counts " + filler
	if got := Compose(len(want), segs...); got != want {
		t.Errorf("Compose(%d) = %q", len(want), got)
	}
	// Not even the counts fit: whole leading segments and the number left out.
	const left = "; and 2 more (see report metadata)"
	if got := Compose(len("loss counts "+filler+left), segs...); got != "loss counts "+filler+left {
		t.Errorf("Compose(one segment) = %q", got)
	}
	if got := Compose(10, long("loss")); got != "" {
		t.Errorf("Compose(10) = %q; want nothing that does not fit", got)
	}
	for budget := 0; budget < 500; budget += 7 {
		if got := Compose(budget, segs...); len(got) > budget || strings.HasSuffix(got, "…") {
			t.Errorf("Compose(%d) = %q (%d bytes)", budget, got, len(got))
		}
	}
}

// The complete listing: every kept name, in entries of at most 240 bytes that
// each start with the analyzer, and the count of what no entry holds.
func TestLimitationsListEveryNameInBoundedEntries(t *testing.T) {
	var c Coverage
	for i := 0; i < 60; i++ {
		c.Exclude(ReasonMinified, "static/vendor/some/long/path/bundle-"+strings.Repeat("x", i%9)+".min.js")
	}
	c.TooLarge("big.js")
	entries := c.Limitations("semgrep")
	if len(entries) < 4 {
		t.Fatalf("entries = %d; want the 60 names spread over several", len(entries))
	}
	var names int
	for _, e := range entries {
		if len(e) > 240 {
			t.Errorf("entry is %d bytes: %q", len(e), e)
		}
		if !strings.HasPrefix(e, "semgrep: ") {
			t.Errorf("entry %q does not start with the analyzer", e)
		}
		names += strings.Count(e, ".min.js")
	}
	if names != 60 {
		t.Errorf("entries name %d of 60 files", names)
	}
	if entries[0] != "semgrep: lost evaluation, over 1048576 bytes: big.js" {
		t.Errorf("first entry = %q", entries[0])
	}
	// Past the names Coverage keeps, the count of the rest is still said.
	var many Coverage
	for i := 0; i < maxKept+25; i++ {
		many.Exclude(ReasonMinified, "f.min.js")
	}
	last := many.Limitations("secrets")
	if got := last[len(last)-1]; !strings.HasSuffix(got, "and 25 more not listed") {
		t.Errorf("last entry = %q; want the count of names not listed", got)
	}
	if many.DeclaredFiles() != maxKept+25 {
		t.Errorf("DeclaredFiles = %d; the count stays exact", many.DeclaredFiles())
	}
}
