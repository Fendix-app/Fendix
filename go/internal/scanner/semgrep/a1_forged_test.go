package semgrep

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// Round 5 verification, cluster 1: a go.sum the repository wrote is not
// independent provenance (owner amendment A1). Semgrep plans every file of a
// self-pinned directory as a target, in a root run and in a diff run, and
// declares nothing out of scope.
func TestAForgedGoSumDoesNotRemoveTargetsFromSemgrep(t *testing.T) {
	root := t.TempDir()
	const mod, ver = "example.com/lib", "v1.0.0"
	rel := "third_party/" + mod + "@" + ver
	writeTree(t, root, map[string]string{
		rel + "/app.py": picklePy,
		"app.py":        picklePy,
	})
	h := forgedDirHash1(t, filepath.Join(root, filepath.FromSlash(rel)), mod+"@"+ver)
	writeTree(t, root, map[string]string{"go.sum": mod + " " + ver + " " + h + "\n"})

	targets := inScopeTargets(root, nil)
	if got := strings.Join(targets.files, " "); !strings.Contains(got, rel+"/app.py") {
		t.Errorf("targets = %q; the self-pinned directory must be scanned", got)
	}
	if targets.Coverage.Declared() || len(targets.Excludes) != 0 {
		t.Errorf("declared %q, excludes %q", targets.Coverage.DeclaredDetail(1<<20), targets.Excludes)
	}

	allow := gitdiff.NewAllowlist(root, []string{rel + "/app.py", "app.py"})
	diff := inScopeTargets(root, allow)
	if got := strings.Join(diff.files, " "); !strings.Contains(got, rel+"/app.py") || diff.Coverage.Declared() {
		t.Errorf("diff targets = %q declared %q", got, diff.Coverage.DeclaredDetail(1<<20))
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
