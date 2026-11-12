package textscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// Decision D6 (redteam-semgrep-01, security-01): a file textscan has a rule
// for that it leaves unread, because it is over the size cap, cannot be read,
// or is not text (a NUL byte in its first 512 bytes), is lost evaluation that
// ScanCoverage names; a declared generated artifact and a pruned vendored or
// build directory are declared out of scope and listed.

const innerHTML = "el.innerHTML = location.hash;\n"

func overTheCap(body string) string {
	var b strings.Builder
	b.WriteString(body)
	for b.Len() <= scope.MaxFileBytes {
		b.WriteString("// padding padding padding padding padding padding padding padding\n")
	}
	return b.String()
}

func TestScanCoverageNamesWhatItLeftUnread(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "web/app.js", innerHTML)
	writeFile(t, root, "web/big.js", overTheCap(innerHTML))
	// A real package-lock.json over the cap is a declared lockfile (content
	// evidence, D6'); a file merely NAMED like a library is not.
	writeFile(t, root, "pnpm-lock.yaml", overTheCap("lockfileVersion: '9.0'\n"))
	writeFile(t, root, "web/nul.js", "\x00\x00"+innerHTML)
	writeFile(t, root, "node_modules/.package-lock.json", `{"lockfileVersion": 3}`)
	writeFile(t, root, "node_modules/pkg/index.js", innerHTML)
	writeFile(t, root, ".git/HEAD", "ref: refs/heads/main\n")
	writeFile(t, root, ".git/objects/pack/x", "x")
	writeFile(t, root, ".git/hooks/pre-commit.js", innerHTML)
	writeFile(t, root, "data.bin", overTheCap("x")) // no rule applies

	findings, cov, err := ScanCoverage(root, AllRules(), nil)
	if err != nil {
		t.Fatalf("ScanCoverage: %v", err)
	}
	if got := eps(findings); len(got) != 1 || !strings.HasSuffix(got[0], "web/app.js:1") {
		t.Errorf("findings = %v; want web/app.js:1 kept", got)
	}
	// The detail's wording belongs to the scope package; this test pins which
	// files are named as lost and which as declared.
	lost := cov.LostDetail(240)
	for _, want := range []string{"web/big.js", "web/nul.js"} {
		if !strings.Contains(lost, want) {
			t.Errorf("lost detail = %q; want it to name %s", lost, want)
		}
	}
	for _, not := range []string{"pnpm-lock.yaml", "node_modules", ".git", "data.bin"} {
		if strings.Contains(lost, not) {
			t.Errorf("lost detail = %q; must not name %s", lost, not)
		}
	}
	declared := cov.DeclaredDetail(240)
	for _, want := range []string{"pnpm-lock.yaml", "node_modules/"} {
		if !strings.Contains(declared, want) {
			t.Errorf("declared detail = %q; want it to name %s", declared, want)
		}
	}
	if strings.Contains(declared, ".git") {
		t.Errorf("declared detail = %q; version-control metadata is quiet", declared)
	}
}

func TestScanCoverageNamesAnUnreadableFileAndDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n")
	writeFile(t, root, "locked.go", "package main\n")
	writeFile(t, root, "private/k8s.yaml", "kind: Pod\n")
	writeFile(t, root, "notes.txt", "x")
	for _, p := range []string{"locked.go", "private", "notes.txt"} {
		full := filepath.Join(root, p)
		if err := os.Chmod(full, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(full, 0o755) })
	}
	_, cov, err := ScanCoverage(root, AllRules(), nil)
	if err != nil {
		t.Fatalf("ScanCoverage: %v", err)
	}
	if got := cov.LostDetail(240); got != "lost evaluation: 2 in-scope files not read: 2 unreadable (locked.go, private/)" {
		t.Errorf("lost detail = %q", got)
	}
}

func TestScanCoverageOfADiffNamesTheChangedFilesItLeftUnread(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.go", "package a\n")
	writeFile(t, root, "big.go", overTheCap("package a\n"))
	allow := gitdiff.NewAllowlist(root, []string{"a.go", "big.go"})
	_, cov, err := ScanCoverage(root, AllRules(), allow)
	if err != nil {
		t.Fatalf("ScanCoverage: %v", err)
	}
	if got := cov.LostDetail(240); got != "lost evaluation: 1 in-scope file not read: 1 over 1048576 bytes (big.go)" {
		t.Errorf("lost detail = %q", got)
	}
}

func TestScanCoverageOfACompleteTreeIsEmpty(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "main.go", "package main\n")
	_, cov, err := ScanCoverage(root, AllRules(), nil)
	if err != nil || cov.Lost() || cov.Declared() {
		t.Errorf("ScanCoverage = %v, %q / %q; want nothing", err, cov.LostDetail(240), cov.DeclaredDetail(240))
	}
}
