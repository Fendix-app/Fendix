package scope_test

import (
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// A file can be named as not parsed by two sources: the engine's own target check
// (a foreign source encoding, an identifier spelled with a unicode escape, R6-E7a)
// and Semgrep's report that it could not parse it. It is one file: the count and the
// listing say so, never "2 in-scope files" for one.
func TestAFileNotParsedTwiceIsCountedOnce(t *testing.T) {
	var c scope.Coverage
	c.NotParsed("a.js")
	c.NotParsed("a.js")
	c.NotParsed("b.js")
	if got := c.LostFiles(); got != 2 {
		t.Errorf("LostFiles = %d, want 2 (a.js and b.js)", got)
	}
	seg := c.LostSeg()(-1)
	if strings.Count(seg, "a.js") != 1 || !strings.Contains(seg, "2 not parsed by semgrep") {
		t.Errorf("segment %q lists a.js more than once or miscounts", seg)
	}
	for _, e := range c.Limitations("semgrep") {
		if strings.Count(e, "a.js") > 1 {
			t.Errorf("limitation %q names a.js more than once", e)
		}
	}
	// Other kinds keep counting every report: two unreadable entries are two entries.
	var d scope.Coverage
	d.Unreadable("x")
	d.Unreadable("x")
	if d.LostFiles() != 2 {
		t.Errorf("the other kinds changed: LostFiles = %d, want 2", d.LostFiles())
	}
}
