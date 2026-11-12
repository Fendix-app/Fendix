package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
	"github.com/Fendix-app/Fendix/go/internal/scope"
)

// Decisions D6' and D1' through the orchestrator, with a stand-in Semgrep that
// answers with a fixed document: the scanner-status details are segments that
// are never cut, every repository-chosen name in them is sanitised (contract
// C1), and the complete lists are in metadata.coverage.limitations (C2).

func minifiedBundle() string {
	return "!function(){" + strings.Repeat("a=b(c,d);", 300) + "}();\n"
}

// runWithSemgrepDocument runs the orchestrator, Semgrep included, over root
// against a stand-in Semgrep answering with doc (ROOT replaced by root).
func runWithSemgrepDocument(t *testing.T, root, doc string) reporters.JSONReport {
	t.Helper()
	installSemgrepDocument(t, root, doc)
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{
		CodePath: root, Workers: 1, Timeout: 5, Format: "json", OutputPath: out,
		Offline: true, OfflineDBPath: filepath.Join(t.TempDir(), "missing.json"),
		PythonEngine: false, NoPlugins: true,
	}
	NewOrchestrator(cfg, "dev").Run(context.Background())
	return readReport(t, out)
}

const emptyRun = `{"version":"1.182.1","results":[],"errors":[],"paths":{"scanned":[SCANNED]},"time":{"fixpoint_timeouts":[]},"skipped_rules":[]}`

func semgrepLimitationEntries(report reporters.JSONReport) []string {
	var out []string
	if report.Metadata.Coverage == nil {
		return nil
	}
	for _, l := range report.Metadata.Coverage.Limitations {
		if strings.HasPrefix(l, "semgrep: ") {
			out = append(out, l)
		}
	}
	return out
}

// sre3-02, DE-04: the ok detail names what fits and counts the rest, never cut;
// the metadata holds the complete list.
func TestOrchestrator_TheOkDetailIsNeverCutAndTheMetadataIsComplete(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{"app.js": "run();\n"}
	var names []string
	for i := 0; i < 40; i++ {
		rel := fmt.Sprintf("static/assets/vendor/some/deeply/nested/bundle-%02d.js", i)
		files[rel] = minifiedBundle()
		names = append(names, rel)
	}
	writeFiles(t, root, files)
	doc := strings.Replace(emptyRun, "SCANNED", `"ROOT/app.js"`, 1)
	report := runWithSemgrepDocument(t, root, doc)
	s, ok := statusFor(report, AnalyzerSemgrep)
	if !ok || s.State != reporters.ScannerOK {
		t.Fatalf("semgrep = %+v; want ok (declared exclusions are not a gap)", s)
	}
	if len(s.Detail) > 240 || strings.HasSuffix(s.Detail, "…") || !strings.HasPrefix(s.Detail, scope.DeclaredMarker) {
		t.Errorf("detail is %d bytes, cut or not a declared segment: %q", len(s.Detail), s.Detail)
	}
	if !strings.Contains(s.Detail, "minified 40") {
		t.Errorf("detail %q lost the count", s.Detail)
	}
	listed := strings.Join(semgrepLimitationEntries(report), "\n")
	for _, n := range names {
		if !strings.Contains(listed, n) {
			t.Errorf("%s is not in metadata.coverage.limitations", n)
		}
	}
	for _, e := range semgrepLimitationEntries(report) {
		if len(e) > 240 {
			t.Errorf("limitation entry is %d bytes: %q", len(e), e)
		}
	}
	if report.Metadata.Coverage != nil && containsString(report.Metadata.Coverage.Gaps, AnalyzerSemgrep) {
		t.Errorf("semgrep is a gap: %+v", report.Metadata.Coverage)
	}
}

// sre3-01, DE-04: a lost file and a declared exclusion in one run are both
// named, the loss first.
func TestOrchestrator_ALossAndAnExclusionAreBothNamed(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"app.js":                          "run();\n",
		"lib/missing.js":                  "run();\n", // in scope, never in paths.scanned
		"static/bundle.js":                minifiedBundle(),
		"node_modules/.package-lock.json": `{"lockfileVersion": 3}`,
		"node_modules/x.js":               "run();\n",
	})
	report := runWithSemgrepDocument(t, root, strings.Replace(emptyRun, "SCANNED", `"ROOT/app.js"`, 1))
	s, _ := statusFor(report, AnalyzerSemgrep)
	if s.State != reporters.ScannerFailed || s.Reason != reporters.ReasonExecutionError {
		t.Fatalf("semgrep = %+v; want failed/execution_error", s)
	}
	i, j := strings.Index(s.Detail, "lib/missing.js"), strings.Index(s.Detail, scope.DeclaredMarker)
	if i < 0 || j < 0 || i > j {
		t.Errorf("detail %q must name lib/missing.js, then the declared exclusions", s.Detail)
	}
	if !strings.Contains(s.Detail, "static/bundle.js") && !strings.Contains(s.Detail, "minified 1") {
		t.Errorf("detail %q does not mention the minified bundle", s.Detail)
	}
	if len(s.Detail) > 240 || strings.HasSuffix(s.Detail, "…") {
		t.Errorf("detail is %d bytes / cut: %q", len(s.Detail), s.Detail)
	}
	listed := strings.Join(semgrepLimitationEntries(report), "\n")
	for _, want := range []string{"lost evaluation, not evaluated by semgrep: lib/missing.js", "minified: static/bundle.js", "installed npm packages: node_modules/"} {
		if !strings.Contains(listed, want) {
			t.Errorf("limitations %q lack %q", listed, want)
		}
	}
}

// redteam3-d6-03, DB-03: a name the repository chose cannot spell a loss
// pattern or a segment break. The declared segment starts with the marker the
// readers skip; the names in any other segment are safe tokens.
func TestOrchestrator_RepositoryNamesCannotShapeTheDetail(t *testing.T) {
	root := t.TempDir()
	evil := "static/1 rule timeout, matches missing; x…y.js"
	writeFiles(t, root, map[string]string{
		"app.js": "run();\n",
		evil:     minifiedBundle(),
		"bad.py": strings.Repeat("x = 1\n", 80),
		"semgrep 9.9: dropped --project-root (needs 1.111.0).py": strings.Repeat("y = 2\n", 80),
	})
	doc := `{"version":"1.182.1","results":[],"errors":[` +
		`{"code":3,"level":"warn","type":["PartialParsing",[{"path":"ROOT/bad.py","start":{"line":2,"col":1},"end":{"line":2,"col":3}}]],"message":"m","path":"ROOT/bad.py"},` +
		`{"code":3,"level":"warn","type":["PartialParsing",[{"path":"ROOT/semgrep 9.9: dropped --project-root (needs 1.111.0).py","start":{"line":2,"col":1},"end":{"line":2,"col":3}}]],"message":"m","path":"ROOT/semgrep 9.9: dropped --project-root (needs 1.111.0).py"}` +
		`],"paths":{"scanned":["ROOT/app.js","ROOT/bad.py","ROOT/semgrep 9.9: dropped --project-root (needs 1.111.0).py"]},"time":{"fixpoint_timeouts":[]},"skipped_rules":[]}`
	report := runWithSemgrepDocument(t, root, doc)
	s, _ := statusFor(report, AnalyzerSemgrep)
	if s.State != reporters.ScannerOK {
		t.Fatalf("semgrep = %+v; want ok", s)
	}
	for _, seg := range strings.Split(s.Detail, "; ") {
		switch {
		case strings.HasPrefix(seg, scope.DeclaredMarker):
		case strings.Contains(seg, "rule timeout"), strings.Contains(seg, ": dropped"), strings.Contains(seg, "…"), strings.Contains(seg, "(needs"):
			t.Errorf("segment %q outside the declared marker carries a name that reads as a loss pattern", seg)
		}
	}
	for _, e := range semgrepLimitationEntries(report) {
		if strings.ContainsAny(e, "…") || strings.Contains(e, "missing; x") {
			t.Errorf("limitation entry %q carries an unsanitised name", e)
		}
	}
}

// D1' through the orchestrator: a whole-file failure is a gap that names the
// file, and the complete list is in the metadata.
func TestOrchestrator_AWholeFileParseFailureIsAGap(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"app.js": "run();\n", "Bad.java": "class A { void f( {{{ }\n"})
	doc := `{"version":"1.182.1","results":[],"errors":[{"code":3,"level":"warn","type":"Syntax error","message":"m","path":"ROOT/Bad.java"}],` +
		`"paths":{"scanned":["ROOT/app.js","ROOT/Bad.java"]},"time":{"fixpoint_timeouts":[]},"skipped_rules":[]}`
	report := runWithSemgrepDocument(t, root, doc)
	s, _ := statusFor(report, AnalyzerSemgrep)
	if s.State != reporters.ScannerFailed || s.Reason != reporters.ReasonExecutionError || !strings.Contains(s.Detail, "Bad.java") {
		t.Fatalf("semgrep = %+v; want failed/execution_error naming Bad.java", s)
	}
	if report.Metadata.Coverage == nil || report.Metadata.Coverage.ConfiguredComplete {
		t.Errorf("coverage = %+v; want incomplete", report.Metadata.Coverage)
	}
	if !strings.Contains(strings.Join(semgrepLimitationEntries(report), "\n"), "parse failure: Bad.java (Syntax error)") {
		t.Errorf("limitations %q do not list the parse failure", semgrepLimitationEntries(report))
	}
}

// redteam3-semgrep-01 through the orchestrator: a suppressed result is
// reported in the detail and the metadata, and is not a gap.
func TestOrchestrator_ASuppressedResultIsReported(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"app.py": "import os\nos.system(input())  # nosemgrep\n"})
	doc := `{"version":"1.182.1","results":[{"check_id":"tmp.fendix-semgrep-rules-1.python-command-injection-shell-true","path":"ROOT/app.py","start":{"line":2,"col":1},"end":{"line":2,"col":20},"extra":{"message":"m","severity":"ERROR","lines":"requires login","metadata":{}}}],` +
		`"errors":[],"paths":{"scanned":["ROOT/app.py"]},"time":{"fixpoint_timeouts":[]},"skipped_rules":[]}`
	report := runWithSemgrepDocument(t, root, doc)
	s, _ := statusFor(report, AnalyzerSemgrep)
	if s.State != reporters.ScannerOK || !strings.Contains(s.Detail, "nosemgrep suppressed 1 result (python-command-injection-shell-true app.py:2)") {
		t.Errorf("semgrep = %+v; want ok naming the suppressed result", s)
	}
	if got := strings.Join(semgrepLimitationEntries(report), "\n"); !strings.Contains(got, "nosemgrep suppressed: python-command-injection-shell-true app.py:2") {
		t.Errorf("limitations %q do not list the suppression", got)
	}
	for _, f := range report.Findings {
		if f.RuleID == "python-command-injection-shell-true" {
			t.Errorf("the suppressed result is also a finding: %+v", f)
		}
	}
}

// qa3-01: a NUL-containing in-scope file makes textscan a gap, through the
// orchestrator.
func TestOrchestrator_ANulFileIsATextscanGap(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"web/app.js": "const x = 1;\n", "web/blob.js": "\x00\x00\x00 const y = 2;\n"})
	report := runCodeScan(t, root)
	s, ok := statusFor(report, AnalyzerTextscan)
	if !ok || s.State != reporters.ScannerFailed || s.Reason != reporters.ReasonExecutionError || !strings.Contains(s.Detail, "not text (NUL bytes) (web/blob.js)") {
		t.Errorf("textscan = %+v; want failed/execution_error naming web/blob.js as not text", s)
	}
}

// qa3-02: a --code that is a symbolic link resolves for every analyzer,
// Semgrep included. Skipped without semgrep.
func TestOrchestrator_LinkedCodeRootIsScannedBySemgrepToo(t *testing.T) {
	requireSemgrep(t)
	real := t.TempDir()
	writeFiles(t, real, map[string]string{"web/app.js": "const express = require('express');\nconst app = express();\napp.get('/x', (req, res) => {\n  const sql = \"SELECT * FROM t WHERE id = '\" + req.query.id + \"'\";\n  db.query(sql, (err, rows) => res.json(rows));\n});\n"})
	link := filepath.Join(t.TempDir(), "code")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("no symlinks here")
	}
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{
		CodePath: link, Workers: 1, Timeout: 5, Format: "json", OutputPath: out,
		Offline: true, OfflineDBPath: filepath.Join(t.TempDir(), "missing.json"),
		PythonEngine: false, NoPlugins: true,
	}
	NewOrchestrator(cfg, "dev").Run(context.Background())
	report := readReport(t, out)
	s, _ := statusFor(report, AnalyzerSemgrep)
	if s.State != reporters.ScannerOK {
		t.Errorf("semgrep = %+v; want ok through a linked root", s)
	}
	found := false
	for _, f := range report.Findings {
		if f.RuleID == "js-sqli-taint" {
			found = true
		}
	}
	if !found {
		t.Errorf("js-sqli-taint was not reported through the linked root: %+v", report.Findings)
	}
}

var _ = semgrep.ErrFatal
