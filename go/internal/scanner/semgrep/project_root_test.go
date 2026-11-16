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
//
// Since decision D6' (rulepaths.go) the bundled packs the engine extracts carry
// no paths.exclude, so a scan evaluates test, mock, spec and fixture paths like
// any other source file: a finding in such a path is reported, and the
// engine's confidence model lowers it afterwards (models.IsTestPath and the
// de-escalation it feeds, in the decision layer, not here), never hidden. The
// first test below therefore expects every file of the target, test paths
// included. With no path filter left in the bundled packs it can no longer show
// that --project-root is passed, so the second test does: it runs a rule that
// still carries paths.exclude, as a project-local rule file does.
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

// TestScanTargetInsideAGitTreeIsNotFilteredByTheGitRoot scans targets whose
// git root has them below a directory of the name a path filter would match
// (fixtures/, mock/, spec/, tests/). Every file of the target is evaluated,
// test paths included (decision D6'), so each one's finding is expected.
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
		}, map[string]bool{"app.js:9": true, "__tests__/x.test.js:9": true, "src/__fixtures__/dup.js:9": true}},
		{"mock/repo", "mock/repo", map[string]string{
			"src/main/java/app/App.java":     projectRootJavaSource,
			"src/test/java/app/AppTest.java": projectRootJavaSource,
		}, map[string]bool{"src/main/java/app/App.java:14": true, "src/test/java/app/AppTest.java:14": true}},
		{"spec/repo", "spec/repo", map[string]string{
			"main.go":      projectRootGoSource,
			"main_test.go": projectRootGoSource,
		}, map[string]bool{"main.go:12": true, "main_test.go:12": true}},
		{"tests/repo", "tests/repo", map[string]string{
			"main.go":      projectRootGoSource,
			"main_test.go": projectRootGoSource,
		}, map[string]bool{"main.go:12": true, "main_test.go:12": true}},
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

// projectRootProbeRule is a taint rule that keeps the path filters the bundled
// packs no longer have (decision D6' strips only the packs the engine
// extracts, not a rule file a project supplies).
const projectRootProbeRule = `rules:
  - id: project-root-probe
    mode: taint
    pattern-sources:
      - pattern: req.query.$X
    pattern-sinks:
      - pattern: $DB.query(...)
    message: probe
    languages: [javascript]
    severity: ERROR
    paths:
      exclude:
        - "**/fixtures/**"
        - "**/tests/**"
        - "**/__tests__/**"
    metadata:
      category: injection
      cwe: CWE-89
      confidence: HIGH
      fendix_severity: HIGH
      fendix_reachability: taint
`

// TestScanTargetInsideAGitTreeAppliesPathFiltersBelowTheScanTarget keeps the
// purpose of the original defect asserted under D6'. A rule that carries
// paths.exclude is matched against paths relative to the scan target, which is
// the project root the scanner passes, not the git root: the rule's finding in
// app.js is reported although the git root has the target under fixtures/ or
// tests/, and its finding in a __tests__ file below the target is still
// filtered by the rule's own path filter. Without --project-root the filter
// is matched from the git root, "fixtures/repo/app.js" matches
// "**/fixtures/**", and the target is scanned for nothing.
func TestScanTargetInsideAGitTreeAppliesPathFiltersBelowTheScanTarget(t *testing.T) {
	requireSemgrep(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	resetRulesCacheForTesting()
	rule := filepath.Join(t.TempDir(), "project-root-probe.yaml")
	if err := os.WriteFile(rule, []byte(projectRootProbeRule), 0o644); err != nil {
		t.Fatal(err)
	}
	withExtraSemgrepConfig(t, rule)

	for _, target := range []string{"fixtures/repo", "tests/repo"} {
		t.Run(target, func(t *testing.T) {
			gitRoot := t.TempDir()
			if out, err := exec.Command("git", "-C", gitRoot, "init", "-q").CombinedOutput(); err != nil {
				t.Skipf("git init: %v: %s", err, out)
			}
			root := filepath.Join(gitRoot, filepath.FromSlash(target))
			writeTree(t, root, map[string]string{
				"app.js":              spikeApp,
				"__tests__/x.test.js": spikeApp,
			})
			got, err := Scan(context.Background(), root)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			var probe []string
			for _, f := range got {
				if strings.HasSuffix(f.RuleID, "project-root-probe") {
					probe = append(probe, f.Endpoint)
				}
			}
			if len(probe) != 1 || probe[0] != "app.js:9" {
				t.Errorf("the rule with path filters reported %q; want only app.js:9: the filter applies below the scan target, not to the git root above it", probe)
			}
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
