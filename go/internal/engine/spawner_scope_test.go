package engine

import (
	"strings"
	"testing"
)

// DE4-02 (C2): the Python engine's status line carries the complete lists
// behind its detail's counts in an additive `scope` field. The Go side used to
// drop it, so a detail that said "and 40 more (see report metadata)" pointed at
// metadata that never held them.
func TestAPythonStatusLinesScopeReachesTheReportLimitations(t *testing.T) {
	stream := `{"status":{"check":"injection","state":"ok","detail":"declared out of scope, not scanned: 2 paths (see report metadata)","scope":{"lost":[["a.py","parse: python 3.9 too old"]],"declared":[["gen/x.js","generated: DO NOT EDIT"],["evil;name….js","vendored"]],"truncated":true}}}` + "\n" +
		`{"done":true,"total":0,"protocol":2}` + "\n"
	sr := readFindings(strings.NewReader(stream))
	if len(sr.checks) != 1 || sr.checks[0].Scope == nil {
		t.Fatalf("the status line's scope was dropped: %+v", sr.checks)
	}
	var l scannerStatusList
	notes := recordPythonEngine(&l, SpawnResult{Outcome: SpawnOK, Protocol: 2, Checks: sr.checks})
	joined := strings.Join(notes, "\n")
	for _, want := range []string{
		"python-engine/injection: lost evaluation, not fully analysed: a.py (parse: python 3.9 too old)",
		"python-engine/injection: declared out of scope, not scanned: gen/x.js (generated: DO NOT EDIT)",
		"evil?name?.js (vendored)", // C1: ';' and the ellipsis are replaced
		"more were not listed",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("limitations lack %q:\n%s", want, joined)
		}
	}
	for _, n := range notes {
		if len(n) > 240 {
			t.Errorf("a limitation entry is %d bytes, over the 240 a reader keeps: %q", len(n), n)
		}
	}
	// A status line without a scope is read as before.
	if got := recordPythonEngine(&scannerStatusList{}, SpawnResult{Outcome: SpawnOK, Protocol: 2, Checks: []CheckStatus{{Check: "injection", State: "ok"}}}); len(got) != 0 {
		t.Errorf("notes without a scope: %v", got)
	}
}
