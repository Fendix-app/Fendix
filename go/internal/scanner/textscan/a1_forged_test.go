package textscan

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Round 5 verification, cluster 1: a go.sum the repository wrote is not
// independent provenance (owner amendment A1), so a self-pinned directory is
// scanned like any other.
func TestAForgedGoSumDoesNotHideCodeFromTextscan(t *testing.T) {
	root := t.TempDir()
	const mod, ver = "example.com/lib", "v1.0.0"
	rel := "third_party/" + mod + "@" + ver
	writeFile(t, root, rel+"/web/app.js", innerHTML)
	h := forgedDirHash1(t, filepath.Join(root, filepath.FromSlash(rel)), mod+"@"+ver)
	writeFile(t, root, "go.sum", mod+" "+ver+" "+h+"\n")
	findings, cov, err := ScanCoverage(context.Background(), root, AllRules(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(eps(findings), " "); !strings.Contains(got, rel+"/web/app.js:1") {
		t.Errorf("findings = %q; the self-pinned directory must be scanned", got)
	}
	if cov.Declared() {
		t.Errorf("declared %q", cov.DeclaredDetail(240))
	}
}

// forgedDirHash1 is the go.sum "h1:" hash of a module directory, computed here
// from the files themselves, the way the repository author would write it.
func forgedDirHash1(t *testing.T, dir, prefix string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		lines = append(lines, fmt.Sprintf("%x  %s/%s\n", sha256.Sum256(body), prefix, filepath.ToSlash(rel)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "")))
	return "h1:" + base64.StdEncoding.EncodeToString(sum[:])
}
