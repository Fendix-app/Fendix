package secrets

import (
	"context"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// DE4-07 / redteam3-d6-01 (round 4) pinned that a changed file under a directory
// pruned on evidence was LISTED by a --diff scan as the full scan lists it. Round
// 5 (D5-2, C6) prunes nothing on evidence: a changed file under node_modules is
// read by the diff scan, as the full scan reads it, and neither lists anything.
func TestScanCoverageOfADiffReadsAChangedFileUnderAnInstalledPackageTree(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "node_modules/.package-lock.json", `{"lockfileVersion": 3}`)
	writeFile(t, root, "node_modules/lib/i.py", `AWS_ACCESS_KEY_ID = "`+outsideAWS+`"`+"\n")
	writeFile(t, root, "a.py", "x = 1\n")
	allow := gitdiff.NewAllowlist(root, []string{"a.py", "node_modules/lib/i.py"})
	found, cov, err := ScanCoverage(context.Background(), root, allow)
	if err != nil {
		t.Fatal(err)
	}
	if got := endpointsOf(found); len(got) != 1 || !strings.HasSuffix(got[0], "node_modules/lib/i.py:1") {
		t.Errorf("diff findings = %v; want the changed file under node_modules", got)
	}
	if cov.Declared() || cov.Lost() {
		t.Errorf("declared %q / lost %q; want nothing", cov.DeclaredDetail(240), cov.LostDetail(240))
	}
	_, full, _ := ScanCoverage(context.Background(), root, nil)
	if full.DeclaredDetail(240) != cov.DeclaredDetail(240) {
		t.Errorf("diff lists %q, the full scan lists %q", cov.DeclaredDetail(240), full.DeclaredDetail(240))
	}
}
