package textscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

func TestScanCoverageOfADiffListsAChangedFileUnderAPrunedDirectory(t *testing.T) {
	root := t.TempDir()
	for p, c := range map[string]string{
		"node_modules/.package-lock.json": `{"lockfileVersion": 3}`,
		"node_modules/lib/i.go":           "package lib\n",
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
	_, cov, err := ScanCoverage(root, AllRules(), allow)
	if err != nil {
		t.Fatal(err)
	}
	if got := cov.DeclaredDetail(240); !strings.Contains(got, "node_modules/") {
		t.Errorf("declared detail = %q; want it to list node_modules/", got)
	}
}
