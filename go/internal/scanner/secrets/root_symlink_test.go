package secrets

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// redteam-secrets-01. A --code root that is itself a symbolic link is the
// scope the user chose. filepath.WalkDir does not follow its root when the root
// is a link, so the scanner used to walk nothing and the scan recorded secrets
// "ok" over zero files. The root is resolved once and scanned; the links
// INSIDE it are still never followed (R-003), and containment is relative to
// the directory the root resolves to.

var rootLinkAWS = "AKIA" + "ROOTLINKSYNTHET1"

func sortedEndpoints(fs []evidence.Evidence) []string {
	out := endpointsOf(fs)
	sort.Strings(out)
	return out
}

func rootLinkFixture(t *testing.T) (real, link, outside string) {
	t.Helper()
	base := t.TempDir()
	real = filepath.Join(base, "real")
	outside = filepath.Join(base, "outside")
	writeFile(t, real, "app.py", `KEY = "`+rootLinkAWS+`"`+"\n")
	writeFile(t, real, "inroot.env", "AWS_ACCESS_KEY_ID="+rootLinkAWS+"\n")
	writeFile(t, real, "sub/deep.py", `password = "synthetic-deep-pw"`+"\n")
	writeFile(t, outside, "leak.env", "STRIPE_SECRET="+outsideStripe+"\n")
	// A link inside the root that climbs out of the directory the root
	// resolves to: still refused.
	symlinkOrSkip(t, filepath.Join("..", "outside", "leak.env"), filepath.Join(real, "escape.env"))
	link = filepath.Join(base, "current")
	symlinkOrSkip(t, "real", link)
	return real, link, outside
}

func TestScan_RootThatIsASymlinkIsScanned(t *testing.T) {
	real, link, _ := rootLinkFixture(t)
	want, err := Scan(context.Background(), real)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) < 3 {
		t.Fatalf("fixture: the real root produced %v", sortedEndpoints(want))
	}
	got, err := Scan(context.Background(), link)
	if err != nil {
		t.Fatalf("Scan(symlinked root): %v", err)
	}
	if !reflect.DeepEqual(sortedEndpoints(got), sortedEndpoints(want)) {
		t.Fatalf("symlinked root: got %v, want the real root's %v", sortedEndpoints(got), sortedEndpoints(want))
	}
	assertNothingFromOutside(t, got, "escape.env")
}

// A chain of links to the root, and a relative --code, resolve the same way.
func TestScan_RootThatIsAChainOfSymlinksIsScanned(t *testing.T) {
	real, link, _ := rootLinkFixture(t)
	chain := filepath.Join(filepath.Dir(link), "previous")
	symlinkOrSkip(t, "current", chain)
	want, _ := Scan(context.Background(), real)
	t.Chdir(filepath.Dir(link))
	for _, root := range []string{chain, "previous", "current", "./current"} {
		got, err := Scan(context.Background(), root)
		if err != nil {
			t.Fatalf("Scan(%s): %v", root, err)
		}
		if !reflect.DeepEqual(sortedEndpoints(got), sortedEndpoints(want)) {
			t.Errorf("Scan(%s): got %v, want %v", root, sortedEndpoints(got), sortedEndpoints(want))
		}
	}
}

// The diff fast path and the re-test take the same root.
func TestScanWithAllowlist_RootThatIsASymlink(t *testing.T) {
	_, link, _ := rootLinkFixture(t)
	allow := gitdiff.NewAllowlist(link, []string{"app.py", "escape.env"})
	got, err := ScanWithAllowlist(context.Background(), link, allow)
	if err != nil {
		t.Fatal(err)
	}
	if eps := sortedEndpoints(got); len(eps) != 1 || !strings.HasSuffix(eps[0], " @ app.py:1") {
		t.Fatalf("allowlisted scan under a symlinked root: %v, want only app.py:1", eps)
	}
}

func TestRetestFile_RootThatIsASymlink(t *testing.T) {
	_, link, _ := rootLinkFixture(t)
	got, err := RetestFile(context.Background(), link, filepath.Join(link, "app.py"))
	if err != nil {
		t.Fatalf("RetestFile: %v", err)
	}
	if len(got) != 1 || got[0].Endpoint != "app.py:1" {
		t.Fatalf("RetestFile under a symlinked root: %v", sortedEndpoints(got))
	}
	if _, err := RetestFile(context.Background(), link, filepath.Join(link, "escape.env")); err == nil {
		t.Fatal("RetestFile read a link that leaves the resolved root")
	}
}

// A root link that points nowhere is not a scan of nothing.
func TestScan_DanglingRootSymlinkIsNotAnEmptyScan(t *testing.T) {
	link := filepath.Join(t.TempDir(), "gone")
	symlinkOrSkip(t, filepath.Join(t.TempDir(), "missing"), link)
	fs, err := Scan(context.Background(), link)
	if err == nil {
		t.Fatalf("Scan of a dangling root link returned no error and %d findings", len(fs))
	}
}
