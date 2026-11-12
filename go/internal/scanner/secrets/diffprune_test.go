package secrets

import (
	"context"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// DE4-07 / redteam3-d6-01: a changed file under a directory pruned on evidence
// was dropped from a --diff scan with nothing recorded, while the full scan of
// the same tree lists the directory.
func TestScanCoverageOfADiffListsAChangedFileUnderAPrunedDirectory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "node_modules/.package-lock.json", `{"lockfileVersion": 3}`)
	writeFile(t, root, "node_modules/lib/i.py", "x = 1\n")
	writeFile(t, root, "a.py", "x = 1\n")
	allow := gitdiff.NewAllowlist(root, []string{"a.py", "node_modules/lib/i.py"})
	_, cov, err := ScanCoverage(context.Background(), root, allow)
	if err != nil {
		t.Fatal(err)
	}
	if got := cov.DeclaredDetail(240); !strings.Contains(got, "node_modules/") {
		t.Errorf("declared detail = %q; want it to list node_modules/", got)
	}
	_, full, _ := ScanCoverage(context.Background(), root, nil)
	if full.DeclaredDetail(240) != cov.DeclaredDetail(240) {
		t.Errorf("diff lists %q, the full scan lists %q", cov.DeclaredDetail(240), full.DeclaredDetail(240))
	}
}
