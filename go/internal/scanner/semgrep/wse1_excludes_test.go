package semgrep

import (
	"fmt"
	"strings"
	"testing"
)

// Round 6, WS-E1 (R5-14, R6-E5): which unreadable entries are kept out of
// Semgrep's own file listing, and how, at the level of the Targets methods
// (go/internal/scope/semgrep_source_model_test.go drives the same behaviour
// through ScanRun with a fake Semgrep).

func TestWritablePatternForAnUnreadableName(t *testing.T) {
	for _, tc := range []struct {
		rel  string
		want string
		ok   bool
	}{
		{"locked/inner.py", "/locked/inner.py", true},
		{"br[x]/w.py", `/br\[x\]/w.py`, true},
		{" lead.py", "/ lead.py", true},
		{"dir/ lead.py", "/dir/ lead.py", true},
		{"trail ", `/trail\ `, true},
		{"two  ", `/two\ \ `, true},
		{" both ", `/ both\ `, true},
		{"a b/c.py", "/a b/c.py", true},
		{"tab\t.py", "", false},
		{"ctl\x01.py", "", false},
		{"bad\xff.py", "", false},
		{"\tlead.py", "", false},
		{"  ", "", false},
		{"", "", false},
	} {
		got, ok := wse1WritablePattern(tc.rel)
		if got != tc.want || ok != tc.ok {
			t.Errorf("wse1WritablePattern(%q) = %q, %v; want %q, %v", tc.rel, got, ok, tc.want, tc.ok)
		}
	}
}

func wse1PatternsCover(excludes []string, rel string) bool {
	for _, e := range excludes {
		pat := strings.TrimPrefix(e, "/")
		if pat == rel || strings.HasPrefix(rel, strings.TrimSuffix(pat, "/")+"/") {
			return true
		}
	}
	return false
}

// Past the cap a directory stands in for the entries inside it; every entry is
// still covered, and the pattern count stays within the cap.
func TestUnreadableEntriesPastTheCapAreCoveredByTheirDirectory(t *testing.T) {
	for _, n := range []int{512, 513, 10000} {
		var tg Targets
		var rels []string
		for i := 0; i < n; i++ {
			rels = append(rels, fmt.Sprintf("locked/f%05d.py", i))
		}
		for _, rel := range rels {
			tg.excludeUnreadable(rel)
		}
		tg.wse1FinalizeExcludes()
		if len(tg.Excludes) > maxUnreadableExcludes {
			t.Errorf("%d unreadable files give %d patterns, want at most %d", n, len(tg.Excludes), maxUnreadableExcludes)
		}
		for _, rel := range rels {
			if !wse1PatternsCover(tg.Excludes, rel) {
				t.Fatalf("%d unreadable files: %s is not covered by %d patterns", n, rel, len(tg.Excludes))
			}
		}
		if err := tg.ListingErr(); err != nil {
			t.Errorf("%d unreadable files in one directory: %v; the directory can be excluded", n, err)
		}
		if n == 512 && len(tg.Excludes) != 512 {
			t.Errorf("512 entries fit the cap, each by its own pattern: got %d patterns", len(tg.Excludes))
		}
	}
}

// Entries spread over many directories coalesce upward level by level.
func TestUnreadableEntriesSpreadOverManyDirectoriesCoalesceUpward(t *testing.T) {
	var tg Targets
	var rels []string
	for a := 0; a < 40; a++ {
		for b := 0; b < 40; b++ {
			rels = append(rels, fmt.Sprintf("top%02d/mid%02d/f.py", a, b)) // 1,600 entries in 1,600 directories
		}
	}
	for _, rel := range rels {
		tg.excludeUnreadable(rel)
	}
	tg.wse1FinalizeExcludes()
	if len(tg.Excludes) > maxUnreadableExcludes {
		t.Errorf("%d patterns, want at most %d", len(tg.Excludes), maxUnreadableExcludes)
	}
	for _, rel := range rels {
		if !wse1PatternsCover(tg.Excludes, rel) {
			t.Fatalf("%s is not covered", rel)
		}
	}
	if err := tg.ListingErr(); err != nil {
		t.Errorf("40 top-level directories can be excluded one by one: %v", err)
	}
}

// A name that cannot be written is excluded through its nearest directory that
// can; one directly under the root cannot be excluded, and the run says so.
func TestAnUnwritableNameIsExcludedThroughItsNearestWritableDirectory(t *testing.T) {
	var tg Targets
	tg.excludeUnreadable("odd/ctl\x01.py")
	tg.excludeUnreadable("a\x02dir/b\xffbad/x.py")
	tg.excludeUnreadable("ok/inner/y\x03.py")
	tg.wse1FinalizeExcludes()
	for _, want := range []string{"/odd", "/ok/inner"} {
		found := false
		for _, e := range tg.Excludes {
			found = found || e == want
		}
		if !found {
			t.Errorf("excludes %q lack %q", tg.Excludes, want)
		}
	}
	if err := tg.ListingErr(); err == nil || !strings.Contains(err.Error(), "directly under the scan root") {
		t.Errorf("a\\x02dir has no writable ancestor but the root; ListingErr = %v", err)
	}
	if len(tg.wse1Unexcludable) != 1 {
		t.Errorf("unexcludable = %q", tg.wse1Unexcludable)
	}
}

func TestMoreThanTheCapUnreadableEntriesDirectlyUnderTheRootCannotBeExcluded(t *testing.T) {
	var tg Targets
	for i := 0; i < maxUnreadableExcludes; i++ {
		tg.excludeUnreadable(fmt.Sprintf("f%04d.py", i))
	}
	if err := tg.ListingErr(); err != nil {
		t.Errorf("%d entries fit the cap: %v", maxUnreadableExcludes, err)
	}
	tg.excludeUnreadable("one-too-many.py")
	if err := tg.ListingErr(); err == nil {
		t.Errorf("%d entries directly under the root cannot all be excluded, and ListingErr says nothing", maxUnreadableExcludes+1)
	}
}

// An unreadable entry beneath one already excluded adds nothing, and excluding a
// directory drops the entries inside it.
func TestAnExcludedDirectoryCoversWhatIsInsideIt(t *testing.T) {
	var tg Targets
	tg.excludeUnreadable("a/b/one.py")
	tg.excludeUnreadable("a/b/two.py")
	tg.excludeUnreadable("a/b")
	tg.excludeUnreadable("a/b/three.py")
	tg.wse1FinalizeExcludes()
	if got := strings.Join(tg.Excludes, " "); got != "/a/b" {
		t.Errorf("excludes = %q, want just /a/b", got)
	}
}
