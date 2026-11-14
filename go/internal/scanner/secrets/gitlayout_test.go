package secrets

import (
	"context"
	"testing"
)

// Contract C6 / review item 5: the only directory the secrets scan leaves unread
// for being version-control metadata is <root>/.git with a real layout (a HEAD
// file and objects/ and refs/ directories). A .git or an objects directory
// anywhere else, or a .git without that layout, is ordinary content.
func TestScan_OnlyARealRootGitDirectoryIsSkipped(t *testing.T) {
	line := `password = "hardcoded_secret_12345"`
	cred := func(root string, files ...string) []string {
		for _, f := range files {
			writeFile(t, root, f, line)
		}
		fs, err := Scan(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		return endpointsOf(fs)
	}
	real := func(root string) {
		writeFile(t, root, ".git/HEAD", "ref: refs/heads/main\n")
		writeFile(t, root, ".git/refs/heads/main", "0\n")
		writeFile(t, root, ".git/objects/ab/cd", "x")
	}
	t.Run("a real root .git is skipped", func(t *testing.T) {
		root := t.TempDir()
		real(root)
		if got := cred(root, ".git/config"); len(got) != 0 {
			t.Errorf("scanned the real .git: %v", got)
		}
	})
	t.Run("a nested .git with a real layout is content", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "sub/.git/HEAD", "ref: x\n")
		writeFile(t, root, "sub/.git/refs/heads/m", "0\n")
		writeFile(t, root, "sub/.git/objects/x", "x")
		if got := cred(root, "sub/.git/config"); len(got) != 1 {
			t.Errorf("a nested .git was skipped: %v", got)
		}
	})
	t.Run("a root .git without refs/ is content", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".git/HEAD", "ref: x\n")
		writeFile(t, root, ".git/objects/x", "x")
		if got := cred(root, ".git/config"); len(got) != 1 {
			t.Errorf("a forged .git was skipped: %v", got)
		}
	})
	t.Run("a root .git without HEAD is content", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, ".git/refs/heads/m", "0\n")
		writeFile(t, root, ".git/objects/x", "x")
		if got := cred(root, ".git/config"); len(got) != 1 {
			t.Errorf("a forged .git was skipped: %v", got)
		}
	})
	t.Run("an objects directory elsewhere is content", func(t *testing.T) {
		root := t.TempDir()
		writeFile(t, root, "x/HEAD", "x\n")
		writeFile(t, root, "x/refs/heads/m", "0\n")
		if got := cred(root, "x/objects/a.py"); len(got) != 1 {
			t.Errorf("an objects directory was skipped: %v", got)
		}
	})
	t.Run("a real .git is quiet", func(t *testing.T) {
		root := t.TempDir()
		real(root)
		writeFile(t, root, "a.py", "x = 1\n")
		_, cov, err := ScanCoverage(context.Background(), root, nil)
		if err != nil || cov.Declared() || cov.Lost() {
			t.Errorf("a real .git must not be listed: %v %q %q", err, cov.DeclaredDetail(200), cov.LostDetail(200))
		}
	})
}
