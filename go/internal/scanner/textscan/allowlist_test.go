package textscan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// A Go source line that trips a textscan rule (SQLi via string concat),
// used to seed two files so we can prove the allowlist narrows which file's
// findings are reported. Reuses the package-level writeFile helper from
// textscan_test.go.
const vulnGo = "package x\nfunc b(db *sql.DB, id string) { db.Query(\"SELECT * FROM u WHERE id = \" + id) }\n"

func TestScanWithAllowlist_NilMatchesFullScan(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.go", vulnGo)
	writeFile(t, root, "b.go", vulnGo)

	full, err := Scan(root, AllRules())
	if err != nil {
		t.Fatal(err)
	}
	viaNil, err := ScanWithAllowlist(root, AllRules(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != len(viaNil) {
		t.Fatalf("nil allowlist must equal full scan: full=%d nil=%d", len(full), len(viaNil))
	}
	if len(full) == 0 {
		t.Fatal("test seed produced no findings — rule set changed; pick another seed")
	}
}

func TestScanWithAllowlist_ScopesToChangedFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.go", vulnGo)
	writeFile(t, root, "b.go", vulnGo)

	full, _ := Scan(root, AllRules())
	// Allow only a.go — findings should drop to roughly half (exactly the
	// a.go subset). The key invariant: strictly fewer than the full scan,
	// and every reported finding is anchored in a.go.
	allow := gitdiff.NewAllowlist(root, []string{"a.go"})
	scoped, err := ScanWithAllowlist(root, AllRules(), allow)
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) == 0 {
		t.Fatal("scoped scan of the changed file must still find its issue")
	}
	if len(scoped) >= len(full) {
		t.Fatalf("scoped scan must report fewer findings than full: scoped=%d full=%d", len(scoped), len(full))
	}
	for _, f := range scoped {
		if f.Line == nil || filepath.Base(stripLine(*f.Line)) != "a.go" {
			t.Errorf("scoped finding not anchored in a.go: %+v", f.Line)
		}
	}
}

func TestScanWithAllowlist_EmptyFindsNothing(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.go", vulnGo)
	allow := gitdiff.NewAllowlist(root, nil) // non-nil, zero files
	scoped, err := ScanWithAllowlist(root, AllRules(), allow)
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 0 {
		t.Fatalf("empty allowlist must find nothing, got %d", len(scoped))
	}
}

// TestScanWithAllowlist_FastPathPrunesVendor is the B3/S8 parity guard: the
// diff-aware fast path must still skip files under a pruned dir (vendor/),
// exactly as the full walk does — even when such a file is in the allowlist
// (a committed vendor/ change).
func TestScanWithAllowlist_FastPathPrunesVendor(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.go", vulnGo)
	writeFile(t, root, "vendor/v.go", vulnGo) // committed vendor → must be pruned

	allow := gitdiff.NewAllowlist(root, []string{"a.go", filepath.Join("vendor", "v.go")})
	scoped, err := ScanWithAllowlist(root, AllRules(), allow)
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) == 0 {
		t.Fatal("expected findings from a.go")
	}
	for _, f := range scoped {
		if f.Line == nil || filepath.Base(stripLine(*f.Line)) != "a.go" {
			t.Errorf("fast path scanned a pruned/out-of-scope file: %+v", f.Line)
		}
	}
}

// stripLine drops a trailing ":<lineno>" from a "file:line" endpoint string.
func stripLine(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[:i]
		}
	}
	return s
}

// TestScanWithAllowlist_RefusesSymlinkedParent is the v0.25 M1 fix: the
// diff-aware fast path must not read a file reached through a symlinked parent
// directory (walk parity + repo-scope containment).
func TestScanWithAllowlist_RefusesSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, outside, "leak.go", vulnGo)
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	allow := gitdiff.NewAllowlist(root, []string{filepath.Join(root, "link", "leak.go")})
	got, err := ScanWithAllowlist(root, AllRules(), allow)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("fast path read a file outside the repo via a symlinked parent: %d findings", len(got))
	}
}
