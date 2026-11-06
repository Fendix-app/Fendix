package semgrep

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Semgrep matches a rule's paths.exclude patterns, and its own default ignore
// list, relative to its project root. Inside a git work tree that root is the
// git root, not the directory Fendix was asked to scan, so a target such as
// <gitroot>/fixtures/repo had the "fixtures/" of the JavaScript, Java and Go
// packs applied to every file in it and was scanned for nothing: no error,
// and paths.scanned empty. The scanner passes --project-root <scan target>.
const (
	projectRootJavaSource = `package app;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class App {
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/users")
    public Object users(@RequestParam String name) {
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
`
	projectRootGoSource = `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func users(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
`
)

func TestScanTargetInsideAGitTreeIsNotFilteredByTheGitRoot(t *testing.T) {
	requireSemgrep(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	resetRulesCacheForTesting()

	cases := []struct {
		name   string
		target string // relative to the git root
		files  map[string]string
		want   map[string]bool
	}{
		{"fixtures/repo", "fixtures/repo", map[string]string{
			"app.js":                  spikeApp,
			"__tests__/x.test.js":     spikeApp,
			"src/__fixtures__/dup.js": spikeApp,
		}, map[string]bool{"app.js:9": true}},
		{"mock/repo", "mock/repo", map[string]string{
			"src/main/java/app/App.java":     projectRootJavaSource,
			"src/test/java/app/AppTest.java": projectRootJavaSource,
		}, map[string]bool{"src/main/java/app/App.java:14": true}},
		{"spec/repo", "spec/repo", map[string]string{
			"main.go":      projectRootGoSource,
			"main_test.go": projectRootGoSource,
		}, map[string]bool{"main.go:12": true}},
		{"tests/repo", "tests/repo", map[string]string{
			"main.go":      projectRootGoSource,
			"main_test.go": projectRootGoSource,
		}, map[string]bool{"main.go:12": true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gitRoot := t.TempDir()
			if out, err := exec.Command("git", "-C", gitRoot, "init", "-q").CombinedOutput(); err != nil {
				t.Skipf("git init: %v: %s", err, out)
			}
			target := filepath.Join(gitRoot, filepath.FromSlash(tc.target))
			writeTree(t, target, tc.files)

			got, err := Scan(context.Background(), target)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			assertEndpoints(t, got, tc.want)
		})
	}
}

// The argument is pinned without needing semgrep: the project root is the
// scan target, the same directory the scanner passes as the target.
func TestScanArgsSetTheProjectRootToTheScanTarget(t *testing.T) {
	argv := filepath.Join(t.TempDir(), "argv")
	installArgRecordingSemgrep(t, argv)
	target := t.TempDir()
	if _, err := Scan(context.Background(), target); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	raw, err := os.ReadFile(argv)
	if err != nil {
		t.Fatal(err)
	}
	if want := "\n--project-root\n" + target + "\n"; !strings.Contains("\n"+string(raw), want) {
		t.Errorf("semgrep argv lacks --project-root %s:\n%s", target, raw)
	}
}
