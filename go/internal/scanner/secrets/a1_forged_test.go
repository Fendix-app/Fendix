package secrets

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

// Round 5 verification, cluster 1 (DE6-01, security5-01, redteam5-01, qa5-03).
// Owner amendment A1: a hash pinned in a file the repository controls is not
// independent provenance. A go.sum written by the same change that adds a
// directory named like a module cache entry must not take that directory out of
// the secrets scan: the scan is offline and cannot check go.sum against the
// checksum database, so nothing is excluded.
func TestAForgedGoSumDoesNotHideACommittedCredential(t *testing.T) {
	root := t.TempDir()
	const mod, ver = "example.com/lib", "v1.0.0"
	rel := "third_party/" + mod + "@" + ver
	writeFile(t, root, rel+"/creds.go", "package lib\nvar k = \""+outsideAWS+"\"\n")
	writeFile(t, root, "app.py", `AWS_ACCESS_KEY_ID = "`+inRepoAWS+`"`+"\n")
	// The repository computes the directory hash itself and writes it into go.sum.
	h := forgedDirHash1(t, filepath.Join(root, filepath.FromSlash(rel)), mod+"@"+ver)
	writeFile(t, root, "go.sum", mod+" "+ver+" "+h+"\n")

	findings, cov, err := ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(endpointsOf(findings), " ")
	if !strings.Contains(got, rel+"/creds.go:2") || !strings.Contains(got, "app.py:1") {
		t.Errorf("findings = %q; the credential under the self-pinned directory must be reported", got)
	}
	if cov.Declared() {
		t.Errorf("a self-pinned directory was declared out of scope: %q", cov.DeclaredDetail(240))
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
