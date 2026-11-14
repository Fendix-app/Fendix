package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// Decision D6 (redteam-semgrep-01, security-01): a file the secrets scanner
// leaves unread because it is over the size cap or cannot be read is, when it
// is a file the scanner reads (ReadsFile), lost evaluation that ScanCoverage
// names. Round 5 (decision D5-2, contract C6): nothing else is declared out of
// scope except <root>/.git with a real layout; an over-cap lockfile, an
// installed-package tree and a build directory are read or lost like any other
// path, never excluded for how they look.

// Round 4 (R-010): the read cap is the streaming cap, not 1 MiB, so these tests
// lower it to scope.MaxFileBytes with withCap and the files stay small; a file
// of the production size is exercised by TestScan_StreamsAFileFarOverOneMiB.
// A generated artifact is declared on content evidence (scope.ClassifyFile),
// not on its name, so the lockfile fixture is a real package-lock.json.

// overCap is a line holding a synthetic AWS key id, padded past the cap.
func overCap(key string) string {
	var b strings.Builder
	b.WriteString(`AWS_ACCESS_KEY_ID = "` + key + `"` + "\n")
	for b.Len() <= scope.MaxFileBytes {
		b.WriteString("# padding padding padding padding padding padding padding padding\n")
	}
	return b.String()
}

// bigLockfile is a real package-lock.json padded past the cap.
func bigLockfile() string {
	var b strings.Builder
	b.WriteString(`{"name":"x","lockfileVersion":3,"packages":{"":{"name":"x"}`)
	for b.Len() <= scope.MaxFileBytes {
		b.WriteString(`,"node_modules/p":{"version":"1.0.0","integrity":"sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}`)
	}
	b.WriteString("}}\n")
	return b.String()
}

func TestScanCoverageNamesWhatItLeftUnread(t *testing.T) {
	withCap(t, scope.MaxFileBytes)
	root := t.TempDir()
	writeFile(t, root, "app.py", `AWS_ACCESS_KEY_ID = "`+inRepoAWS+`"`+"\n")
	writeFile(t, root, "settings/big.py", overCap(outsideAWS))
	writeFile(t, root, "package-lock.json", bigLockfile())
	// An installed-package tree is read (C6): npm's marker file proves nothing.
	writeFile(t, root, "node_modules/.package-lock.json", `{"lockfileVersion": 3}`)
	writeFile(t, root, "node_modules/pkg/index.js", `const k = "`+outsideAWS+`";`+"\n")
	// A directory called dist is first-party until its content says otherwise.
	writeFile(t, root, "dist/bundle.js", `const k = "`+outsideAWS+`";`+"\n")
	writeFile(t, root, ".git/HEAD", "ref: refs/heads/main\n")
	writeFile(t, root, ".git/refs/heads/main", "0000\n")
	writeFile(t, root, ".git/objects/pack/x", "x")
	writeFile(t, root, ".git/config", `url = https://u:`+outsideAWS+`@h`+"\n")
	writeFile(t, root, "notes.bin", strings.Repeat("x", scope.MaxFileBytes+10)) // a binary type: not read

	findings, cov, err := ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanCoverage: %v", err)
	}
	if got := endpointsOf(findings); len(got) != 3 || !strings.HasSuffix(got[0], "app.py:1") || !strings.HasSuffix(got[1], "dist/bundle.js:1") ||
		!strings.HasSuffix(got[2], "node_modules/pkg/index.js:1") {
		t.Errorf("findings = %v; want app.py:1, dist/bundle.js:1 and node_modules/pkg/index.js:1 (and nothing from .git)", got)
	}
	// An over-cap file is lost evaluation whatever it looks like: a real
	// lockfile included (C6: the cap, not the look of the file, decides).
	if got := cov.LostDetail(240); got != "lost evaluation: 2 in-scope files not read: 2 over 1048576 bytes (package-lock.json, settings/big.py)" {
		t.Errorf("lost detail = %q", got)
	}
	if cov.Declared() {
		t.Errorf("declared detail = %q; nothing is declared out of scope (the real .git is quiet)", cov.DeclaredDetail(240))
	}
}

func TestScanCoverageNamesAnUnreadableFileAndDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	root := t.TempDir()
	locked := writeFile(t, root, "locked.py", `AWS_ACCESS_KEY_ID = "`+outsideAWS+`"`+"\n")
	writeFile(t, root, "private/keys.env", "AWS_SECRET=x\n")
	writeFile(t, root, "real.py", `AWS_ACCESS_KEY_ID = "`+inRepoAWS+`"`+"\n")
	writeFile(t, root, "image.png", "png")
	for _, p := range []string{locked, filepath.Join(root, "private"), filepath.Join(root, "image.png")} {
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		p := p
		t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
	}
	findings, cov, err := ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanCoverage: %v", err)
	}
	if got := endpointsOf(findings); len(got) != 1 || !strings.HasSuffix(got[0], "real.py:1") {
		t.Errorf("findings = %v; want real.py:1", got)
	}
	// image.png is not a file the scanner reads, so its mode costs nothing.
	if got := cov.LostDetail(240); got != "lost evaluation: 2 in-scope files not read: 2 unreadable (locked.py, private/)" {
		t.Errorf("lost detail = %q", got)
	}
}

func TestScanCoverageOfADiffNamesTheChangedFilesItLeftUnread(t *testing.T) {
	withCap(t, scope.MaxFileBytes)
	root := t.TempDir()
	writeFile(t, root, "a.py", "x = 1\n")
	writeFile(t, root, "big.py", overCap(outsideAWS))
	writeFile(t, root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n"+overCap(outsideAWS))
	allow := gitdiff.NewAllowlist(root, []string{"a.py", "big.py", "pnpm-lock.yaml"})
	_, cov, err := ScanCoverage(context.Background(), root, allow)
	if err != nil {
		t.Fatalf("ScanCoverage: %v", err)
	}
	if got := cov.LostDetail(240); got != "lost evaluation: 2 in-scope files not read: 2 over 1048576 bytes (big.py, pnpm-lock.yaml)" {
		t.Errorf("lost detail = %q", got)
	}
	if cov.Declared() {
		t.Errorf("declared detail = %q; an over-cap lockfile is lost evaluation, not declared", cov.DeclaredDetail(240))
	}
}

func TestScanCoverageOfACompleteTreeIsEmpty(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "app.py", "x = 1\n")
	_, cov, err := ScanCoverage(context.Background(), root, nil)
	if err != nil || cov.Lost() || cov.Declared() {
		t.Errorf("ScanCoverage = %v, %q / %q; want nothing", err, cov.LostDetail(240), cov.DeclaredDetail(240))
	}
}

// ScanSightings promises that "no sighting" means a fresh scan would report
// the credential nowhere. With an in-scope file left unread it cannot, so it
// is an error (verify then says unknown, never resolved).
func TestScanSightingsIsAnErrorWhenAFileWasLeftUnread(t *testing.T) {
	withCap(t, scope.MaxFileBytes)
	root := t.TempDir()
	writeFile(t, root, "app.py", "x = 1\n")
	writeFile(t, root, "moved/config.py", overCap(outsideAWS))
	if _, err := ScanSightings(context.Background(), root); err == nil || !strings.Contains(err.Error(), "moved/config.py") {
		t.Errorf("ScanSightings err = %v; want an error naming moved/config.py", err)
	}
	// An over-cap lockfile is lost evaluation too (C6): no look-alike is exempt.
	root = t.TempDir()
	writeFile(t, root, "app.py", "x = 1\n")
	writeFile(t, root, "package-lock.json", bigLockfile())
	if _, err := ScanSightings(context.Background(), root); err == nil || !strings.Contains(err.Error(), "package-lock.json") {
		t.Errorf("ScanSightings err = %v; want an error naming package-lock.json", err)
	}
}
