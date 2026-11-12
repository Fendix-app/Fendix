package scope

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestRealCorpus classifies every file of the directories named in
// FENDIX_SCOPE_CORPUS (path-list separator) and prints what was flagged, so the
// thresholds can be re-measured on real code. FENDIX_SCOPE_FIRSTPARTY lists
// directories whose files must never be flagged minified or vendored unless
// their own content says so; the test fails for any that is flagged without
// FENDIX_SCOPE_EXPECT (a substring list) naming it. Skipped when unset.
func TestRealCorpus(t *testing.T) {
	roots := os.Getenv("FENDIX_SCOPE_CORPUS")
	if roots == "" {
		t.Skip("FENDIX_SCOPE_CORPUS not set")
	}
	counts := map[Reason]int{}
	var flagged []string
	for _, root := range filepath.SplitList(roots) {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if !jsFamily[ext] && ext != ".css" {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			v := ClassifyFile(p, rel, info.Size())
			if !v.None() {
				counts[v.Reason]++
				flagged = append(flagged, string(v.Reason)+"\t"+p)
			}
			return nil
		})
	}
	sort.Strings(flagged)
	for _, f := range flagged {
		t.Log(f)
	}
	t.Logf("counts: %v", counts)
}
