package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// installArgRecordingSemgrep installs a fake semgrep that writes its argv,
// one argument per line, to argvFile and reports no results.
func installArgRecordingSemgrep(t *testing.T, argvFile string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "semgrep")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + argvFile + "'\nprintf '{\"results\":[],\"errors\":[]}'\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake semgrep: %v", err)
	}
	origLook := LookPath
	LookPath = func(name string) (string, error) {
		if name == "semgrep" {
			return bin, nil
		}
		return origLook(name)
	}
	t.Cleanup(func() { LookPath = origLook })
}

// recordedIncludes returns the --include values of the last fake run; nil if
// semgrep never ran.
func recordedIncludes(t *testing.T, argvFile string) []string {
	t.Helper()
	raw, err := os.ReadFile(argvFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	var out []string
	for _, a := range args {
		// "--include=<rel>": one argument, so a name that starts with '-' is a
		// value and never an option (review item 4).
		if v, ok := strings.CutPrefix(a, "--include="); ok {
			out = append(out, v)
		}
	}
	return out
}

// chdirTempTree creates files under a fresh directory, makes it the working
// directory for the rest of the test, and returns its resolved absolute path.
func chdirTempTree(t *testing.T, files ...string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		p := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x = 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(root)
	return root
}

// The composite Action's default `code: "."` plus diff mode on a pull request
// must give semgrep root-relative --include paths, the same ones an absolute
// --code produces. Through v3.6.1 a relative root produced absolute --include
// values, which semgrep matched against no file: a clean, "ok" run that
// analysed nothing.
func TestScanWithAllowlist_RelativeRootPassesRootRelativeIncludes(t *testing.T) {
	changed := []string{"app/server.py", "deploy/k8s/worker.yaml"}
	abs := chdirTempTree(t, changed...)
	argv := filepath.Join(t.TempDir(), "argv")
	installArgRecordingSemgrep(t, argv)

	want := []string{"app/server.py", "deploy/k8s/worker.yaml"}
	for _, codePath := range []string{".", "./", abs} {
		_ = os.Remove(argv)
		if _, err := ScanWithAllowlist(context.Background(), codePath, gitdiff.NewAllowlist(codePath, changed)); err != nil {
			t.Fatalf("code %q: %v", codePath, err)
		}
		if got := recordedIncludes(t, argv); !reflect.DeepEqual(got, want) {
			t.Errorf("code %q: semgrep --include = %v, want %v", codePath, got, want)
		}
	}
}

// A non-empty allowlist must never reach semgrep as a filter that cannot match
// the scan root. Here the allowlist names a file outside --code, which no
// root-relative --include can express: the scan must fail visibly instead of
// running with an absolute --include and reporting a clean result.
func TestScanWithAllowlist_UnscopableAllowlistFailsInsteadOfScanningNothing(t *testing.T) {
	abs := chdirTempTree(t, "app/server.py")
	elsewhere, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	argv := filepath.Join(t.TempDir(), "argv")
	installArgRecordingSemgrep(t, argv)

	allow := gitdiff.NewAllowlist(elsewhere, []string{"other.py"})
	_, scanErr := ScanWithAllowlist(context.Background(), abs, allow)
	if scanErr == nil {
		t.Errorf("an allowlist outside the scan root was accepted; semgrep ran with --include %v", recordedIncludes(t, argv))
	}
	for _, inc := range recordedIncludes(t, argv) {
		if filepath.IsAbs(inc) || strings.HasPrefix(inc, "../") {
			t.Errorf("semgrep received --include %q, which cannot match a file under the scan root", inc)
		}
	}
}

// Zero changed files still scope semgrep to nothing, for every root spelling.
func TestScanWithAllowlist_EmptyAllowlistWithRelativeRoot(t *testing.T) {
	abs := chdirTempTree(t, "app/server.py")
	argv := filepath.Join(t.TempDir(), "argv")
	installArgRecordingSemgrep(t, argv)
	for _, codePath := range []string{".", "./", abs} {
		got, err := ScanWithAllowlist(context.Background(), codePath, gitdiff.NewAllowlist(codePath, nil))
		if err != nil || got != nil {
			t.Errorf("code %q: empty allowlist returned (%v, %v), want (nil, nil)", codePath, got, err)
		}
		if _, err := os.Stat(argv); err == nil {
			t.Errorf("code %q: semgrep ran for an empty allowlist", codePath)
		}
	}
}
