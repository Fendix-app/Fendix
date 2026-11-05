package semgrep

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSemgrepVersion(t *testing.T) {
	cases := []struct {
		out  string
		want string
	}{
		{"1.182.1\n", "1.182.1"},
		{"1.45.0", "1.45.0"},
		{"A new version is available\n1.110.0\n\n", "1.110.0"},
		{"", "unknown"},
		{`{"results":[],"version":"1.141.0"}`, "unknown"},
		{"semgrep 1.2.3", "unknown"},
		{"1.2", "unknown"},
	}
	for _, c := range cases {
		if got := versionString(parseSemgrepVersion(c.out)); got != c.want {
			t.Errorf("parseSemgrepVersion(%q) = %s, want %s", c.out, got, c.want)
		}
	}
}

func TestSemgrepVersionAtLeast(t *testing.T) {
	v := parseSemgrepVersion("1.110.0")
	for _, c := range []struct {
		major, minor, patch int
		want                bool
	}{
		{1, 111, 0, false}, {1, 110, 0, true}, {1, 109, 9, true}, {2, 0, 0, false}, {0, 999, 0, true},
	} {
		if got := v.atLeast(c.major, c.minor, c.patch); got != c.want {
			t.Errorf("1.110.0 atLeast %d.%d.%d = %v, want %v", c.major, c.minor, c.patch, got, c.want)
		}
	}
	if !(semgrepVersion{}).atLeast(99, 0, 0) {
		t.Error("an unreadable version must be taken to be a current one")
	}
}

// installVersionedSemgrep is a stand-in for a host semgrep of the given
// release. Like a real one it rejects an option it does not know with
// "No such option" and exit 2, and records the arguments of a scan.
func installVersionedSemgrep(t *testing.T, version string, unknown []string, argvFile string) {
	t.Helper()
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	bin := filepath.Join(t.TempDir(), "semgrep")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"--version\" ]; then echo '" + version + "'; exit 0; fi\n" +
		"for a in \"$@\"; do\n" +
		"  case \"$a\" in\n"
	for _, flag := range unknown {
		script += "    " + flag + ") echo \"Error: No such option '" + flag + "'.\" 1>&2; exit 2;;\n"
	}
	script += "  esac\ndone\n" +
		"printf '%s\\n' \"$@\" > '" + argvFile + "'\n" +
		"printf '{\"results\":[],\"errors\":[]}'\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
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

func recordedArgs(t *testing.T, argvFile string) string {
	t.Helper()
	raw, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("the scan never ran: %v", err)
	}
	return "\n" + string(raw)
}

// A host Semgrep older than an option's first release is run without that
// option rather than failing the whole run with "No such option".
func TestScanDropsTheOptionsAnOlderHostSemgrepDoesNotKnow(t *testing.T) {
	argv := filepath.Join(t.TempDir(), "argv")
	installVersionedSemgrep(t, "1.45.0", []string{"--project-root"}, argv)
	if _, err := Scan(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("Scan on Semgrep 1.45.0: %v", err)
	}
	args := recordedArgs(t, argv)
	if strings.Contains(args, "--project-root") {
		t.Errorf("--project-root passed to Semgrep 1.45.0:%s", args)
	}
	for _, kept := range []string{"\n--dataflow-traces\n", "\n--timeout\n30\n", "\n--exclude\nnode_modules\n", "\n--exclude\n*.min.js\n"} {
		if !strings.Contains(args, kept) {
			t.Errorf("Semgrep 1.45.0 takes %q, which was dropped:%s", strings.TrimSpace(kept), args)
		}
	}
}

func TestScanDropsEveryOptionTheVersionPredates(t *testing.T) {
	argv := filepath.Join(t.TempDir(), "argv")
	installVersionedSemgrep(t, "0.10.0", []string{"--project-root", "--dataflow-traces", "--timeout", "--exclude"}, argv)
	if _, err := Scan(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("Scan on Semgrep 0.10.0: %v", err)
	}
	args := recordedArgs(t, argv)
	for _, gone := range []string{"--project-root", "--dataflow-traces", "--timeout", "--exclude"} {
		if strings.Contains(args, gone) {
			t.Errorf("%s passed to Semgrep 0.10.0:%s", gone, args)
		}
	}
	if !strings.Contains(args, "\n--config\n") || !strings.Contains(args, "\n--json\n") {
		t.Errorf("the options every Semgrep has are missing:%s", args)
	}
}

func TestScanPassesEveryOptionToASemgrepThatHasThem(t *testing.T) {
	for _, version := range []string{"1.111.0", "1.182.1"} {
		argv := filepath.Join(t.TempDir(), "argv")
		installVersionedSemgrep(t, version, nil, argv)
		root := t.TempDir()
		if _, err := Scan(context.Background(), root); err != nil {
			t.Fatalf("Scan on Semgrep %s: %v", version, err)
		}
		args := recordedArgs(t, argv)
		for _, want := range []string{"\n--dataflow-traces\n", "\n--timeout\n30\n", "\n--project-root\n" + root + "\n", "\n--exclude\nvendor\n"} {
			if !strings.Contains(args, want) {
				t.Errorf("Semgrep %s was not given %q:%s", version, strings.TrimSpace(want), args)
			}
		}
	}
}

func TestScanPassesEveryOptionWhenTheVersionCannotBeRead(t *testing.T) {
	argv := filepath.Join(t.TempDir(), "argv")
	installVersionedSemgrep(t, "not a version", nil, argv)
	root := t.TempDir()
	if _, err := Scan(context.Background(), root); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if args := recordedArgs(t, argv); !strings.Contains(args, "\n--project-root\n"+root+"\n") {
		t.Errorf("an unreadable version must be run as a current one:%s", args)
	}
}

func TestSemgrepVersionIsReadOncePerBinary(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "count")
	bin := filepath.Join(t.TempDir(), "semgrep")
	script := "#!/bin/sh\necho x >> '" + counter + "'\necho 1.182.1\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	resetVersionCacheForTesting()
	t.Cleanup(resetVersionCacheForTesting)
	for i := 0; i < 3; i++ {
		if v := semgrepVersionOf(context.Background(), bin); versionString(v) != "1.182.1" {
			t.Fatalf("version = %s", versionString(v))
		}
	}
	raw, err := os.ReadFile(counter)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(raw), "x"); n != 1 {
		t.Errorf("semgrep --version ran %d times, want 1", n)
	}
}
