package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// sre3-06: a symbolic link the scan refuses to follow is listed, as declared out
// of scope, when its target is content that exists outside the scan root, and
// is not listed when nothing was missed (a target inside the root, a dangling
// link). A link is the scan's own boundary, not an unread file of the tree, so
// it is not lost evaluation.
func TestScanCoverage_NamesASymlinkToAFileOutsideTheRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeFile(t, outside, "secret.env", "STRIPE_SECRET="+outsideStripe+"\n")
	symlinkOrSkip(t, filepath.Join(outside, "secret.env"), filepath.Join(root, ".env"))
	writeFile(t, root, "real.py", "x = 1\n")
	symlinkOrSkip(t, "real.py", filepath.Join(root, "inside.py"))                           // inside the root: loses nothing
	symlinkOrSkip(t, filepath.Join(outside, "nope"), filepath.Join(root, "dangling.env"))   // nothing to read
	symlinkOrSkip(t, filepath.Join(outside, "secret.env"), filepath.Join(root, "logo.png")) // a type the scanner never reads

	fs, cov, err := ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("a link out of the root was followed: %v", endpointsOf(fs))
	}
	declared := cov.DeclaredDetail(240)
	if cov.Lost() || !strings.Contains(declared, ".env") {
		t.Fatalf("lost %v, declared detail = %q; want the refused link .env listed as declared", cov.Lost(), declared)
	}
	for _, not := range []string{"inside.py", "dangling.env", "logo.png"} {
		if strings.Contains(declared, not) {
			t.Errorf("declared detail = %q; %s loses nothing", declared, not)
		}
	}
}

func TestScanCoverage_NamesASymlinkedDirectoryOutsideTheRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeFile(t, outside, "k.env", "AWS_ACCESS_KEY_ID="+outsideAWS+"\n")
	symlinkOrSkip(t, outside, filepath.Join(root, "shared"))
	fs, cov, err := ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 || !strings.Contains(cov.DeclaredDetail(240), "shared/") {
		t.Errorf("findings %v, declared %q", endpointsOf(fs), cov.DeclaredDetail(240))
	}
}

func TestScanCoverage_ADiffNamesAChangedSymlinkOutsideTheRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeFile(t, outside, "secret.env", "STRIPE_SECRET="+outsideStripe+"\n")
	symlinkOrSkip(t, filepath.Join(outside, "secret.env"), filepath.Join(root, ".env"))
	writeFile(t, root, "a.py", "x = 1\n")
	allow := gitdiff.NewAllowlist(root, []string{"a.py", ".env"})
	_, cov, err := ScanCoverage(context.Background(), root, allow)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cov.DeclaredDetail(240), ".env") {
		t.Errorf("declared detail = %q", cov.DeclaredDetail(240))
	}
}

// A path is untrusted text: a file name with ';', an ellipsis or a newline must
// not shape the detail (contract C1).
func TestScanCoverage_NamesInTheDetailAreSanitised(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	root := t.TempDir()
	p := writeFile(t, root, "evil; declared out of scope, not scanned: x…\nnew.py", "x = 1\n")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	_, cov, err := ScanCoverage(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := cov.LostDetail(240)
	if strings.ContainsAny(d, ";…\n") {
		t.Errorf("lost detail = %q carries a character a name must not", d)
	}
	if !strings.Contains(d, "evil??declared?out?of?scope??not?scanned??x??new.py") {
		t.Errorf("lost detail = %q; want the sanitised name", d)
	}
}
