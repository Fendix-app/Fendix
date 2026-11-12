package textscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// sre3-06: a link the scan refuses to follow is listed, as declared out of
// scope, when its target is a file or directory outside the root that a rule
// would have read; a link whose target is inside the root, a dangling link, and
// a link to a file no rule applies to are not listed.
func TestScanCoverage_NamesASymlinkToCodeOutsideTheRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeFile(t, outside, "x.go", "package x\n\nconst k = \"AKIA"+"ZXCVBNMASDFGHJKL\"\n")
	writeFile(t, outside, "pkg/y.go", "package y\n")
	if err := os.Symlink(filepath.Join(outside, "x.go"), filepath.Join(root, "linked.go")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	_ = os.Symlink(filepath.Join(outside, "pkg"), filepath.Join(root, "shared"))
	_ = os.Symlink(filepath.Join(outside, "nope.go"), filepath.Join(root, "dangling.go"))
	_ = os.Symlink(filepath.Join(outside, "x.go"), filepath.Join(root, "notes.csv"))
	writeFile(t, root, "main.go", "package main\n")
	_ = os.Symlink("main.go", filepath.Join(root, "inside.go"))

	fs, cov, err := ScanCoverage(root, AllRules(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("a link out of the root was followed: %v", eps(fs))
	}
	declared := cov.DeclaredDetail(240)
	for _, want := range []string{"linked.go", "shared/"} {
		if !strings.Contains(declared, want) {
			t.Errorf("declared detail = %q; want %q", declared, want)
		}
	}
	for _, not := range []string{"dangling.go", "notes.csv", "inside.go"} {
		if strings.Contains(declared, not) {
			t.Errorf("declared detail = %q; %s loses nothing", declared, not)
		}
	}
	if cov.Lost() {
		t.Errorf("a refused link is the scan's boundary, not lost evaluation: %q", cov.LostDetail(240))
	}
}

func TestScanCoverage_ADiffNamesAChangedSymlinkOutsideTheRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeFile(t, outside, "x.go", "package x\n")
	if err := os.Symlink(filepath.Join(outside, "x.go"), filepath.Join(root, "linked.go")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	writeFile(t, root, "a.go", "package a\n")
	_, cov, err := ScanCoverage(root, AllRules(), gitdiff.NewAllowlist(root, []string{"a.go", "linked.go"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cov.DeclaredDetail(240), "linked.go") {
		t.Errorf("declared detail = %q", cov.DeclaredDetail(240))
	}
}
