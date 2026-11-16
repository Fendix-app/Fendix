package textscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// Round 4 pinned that a changed file under a directory pruned on evidence was
// listed. Round 5 (C6) prunes nothing on evidence: the changed file under
// node_modules is scanned, and nothing is declared.
func TestScanCoverageOfADiffReadsAChangedFileUnderAnInstalledPackageTree(t *testing.T) {
	root := t.TempDir()
	for p, c := range map[string]string{
		"node_modules/.package-lock.json": `{"lockfileVersion": 3}`,
		"node_modules/lib/i.go":           "package lib\n\nconst k = \"AKIA" + "ZXCVBNMASDFGHJKL\"\n",
		"a.go":                            "package a\n",
	} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	allow := gitdiff.NewAllowlist(root, []string{"a.go", "node_modules/lib/i.go"})
	got, cov, err := ScanCoverage(context.Background(), root, AllRules(), allow)
	if err != nil {
		t.Fatal(err)
	}
	if e := eps(got); len(e) != 1 || !strings.HasSuffix(e[0], "node_modules/lib/i.go:3") {
		t.Errorf("findings = %v; want the changed file under node_modules", e)
	}
	if cov.Declared() || cov.Lost() {
		t.Errorf("declared %q / lost %q; want nothing", cov.DeclaredDetail(240), cov.LostDetail(240))
	}
}
