package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
)

// Real-Semgrep regression tests for D1 (R-004, R-007). Each scans a generated
// file in which Semgrep gives up part of its work, with the vulnerable code
// placed AFTER the padding, where the lost work hides it, and requires the
// invariant: either the finding is reported, or the semgrep entry is a gap
// that names the file. Semgrep's taint fixpoint budget is a wall-clock one, so
// on a fast enough machine the finding can survive; on the engine-dev image
// (2-3 CPUs) these shapes lose it. Skipped without semgrep, and failed when
// FENDIX_REQUIRE_SEMGREP is set.

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// expressRouterInline is an Express router of n inline handlers, each reading
// request input into a parameterised query, then an SSRF handler. Returns the
// source and the line of the SSRF sink.
func expressRouterInline(n int) (string, int) {
	var b strings.Builder
	b.WriteString("const express = require('express');\nconst { Pool } = require('pg');\nconst pool = new Pool();\nconst router = express.Router();\n\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "router.get('/users%d/:id', async (req, res) => {\n  const id = req.params.id;\n  const limit = req.query.limit === 'all' ? 1000 : 10;\n", i)
		fmt.Fprintf(&b, "  const r = await pool.query('SELECT * FROM t%d WHERE id = $1 LIMIT $2', [id, limit]);\n  res.json(r.rows);\n});\n\n", i)
	}
	b.WriteString("router.get('/proxy', async (req, res) => {\n  const url = req.query.url;\n")
	line := strings.Count(b.String(), "\n") + 1
	b.WriteString("  const upstream = await fetch(url);\n  res.json({ status: upstream.status });\n});\n\nmodule.exports = router;\n")
	return b.String(), line
}

// ginMainInline is a gin main() of n inline closures, then an SSRF closure.
func ginMainInline(n int) (string, int) {
	var b strings.Builder
	b.WriteString("package main\n\nimport (\n\t\"database/sql\"\n\t\"net/http\"\n\n\t\"github.com/gin-gonic/gin\"\n)\n\nvar db *sql.DB\n\nfunc main() {\n\tr := gin.Default()\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "\tr.GET(\"/u%d\", func(c *gin.Context) {\n\t\tid := c.Query(\"id\")\n\t\tlimit := 10\n\t\tif c.Query(\"all\") == \"1\" {\n\t\t\tlimit = 1000\n\t\t}\n", i)
		fmt.Fprintf(&b, "\t\trows, err := db.Query(\"SELECT name FROM t%d WHERE id = $1 LIMIT $2\", id, limit)\n\t\tif err != nil {\n\t\t\tc.JSON(500, gin.H{})\n\t\t\treturn\n\t\t}\n\t\tdefer rows.Close()\n\t\tc.JSON(200, gin.H{\"ok\": true})\n\t})\n", i)
	}
	b.WriteString("\tr.GET(\"/proxy\", func(c *gin.Context) {\n\t\ttarget := c.Query(\"url\")\n")
	line := strings.Count(b.String(), "\n") + 1
	b.WriteString("\t\tresp, err := http.Get(target)\n\t\tif err != nil {\n\t\t\tc.JSON(502, gin.H{\"error\": \"x\"})\n\t\t\treturn\n\t\t}\n\t\tdefer resp.Body.Close()\n\t\tc.JSON(200, gin.H{\"s\": resp.StatusCode})\n\t})\n\tr.Run(\":8080\")\n}\n")
	return b.String(), line
}

// springRedirects is a Spring controller of n redirect handlers, then an open
// redirect. java-open_redirect-taint grows superlinearly with this file.
func springRedirects(n int) (string, int) {
	var b strings.Builder
	b.WriteString("package app;\n\nimport java.util.List;\nimport java.util.Map;\nimport javax.servlet.http.HttpServletResponse;\nimport org.springframework.jdbc.core.JdbcTemplate;\nimport org.springframework.web.bind.annotation.*;\n\n")
	b.WriteString("@RestController\n@RequestMapping(\"/api\")\npublic class ItemController {\n    private final JdbcTemplate jdbcTemplate;\n    public ItemController(JdbcTemplate jdbcTemplate) { this.jdbcTemplate = jdbcTemplate; }\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "    @GetMapping(\"/go%d\")\n    public void go%d(@RequestParam String next, @RequestParam String sort, HttpServletResponse response) throws Exception {\n", i, i)
		b.WriteString("        String target = next;\n        if (target == null) { target = \"/\"; }\n        String t2 = target.trim();\n")
		fmt.Fprintf(&b, "        List<Map<String, Object>> rows = jdbcTemplate.queryForList(\"SELECT * FROM items ORDER BY id LIMIT ?\", %d);\n", i)
		b.WriteString("        if (rows.isEmpty()) { response.sendRedirect(\"/home\"); return; }\n        response.sendRedirect(t2);\n    }\n")
	}
	b.WriteString("    @GetMapping(\"/last\")\n    public void last(@RequestParam String next, HttpServletResponse response) throws Exception {\n")
	line := strings.Count(b.String(), "\n") + 1
	b.WriteString("        response.sendRedirect(next);\n    }\n}\n")
	return b.String(), line
}

func hasFindingAt(evid []evidence.Evidence, rule, file string, line int) bool {
	// The match can start a line or two from the sink call, depending on how
	// the rule's pattern spans it.
	for _, e := range evid {
		for d := -2; d <= 2; d++ {
			if e.RuleID == rule && e.Endpoint == fmt.Sprintf("%s:%d", file, line+d) {
				return true
			}
		}
	}
	return false
}

// scanAndRecord runs the real Semgrep on root and records it as the
// orchestrator does.
func scanAndRecord(t *testing.T, root string) (reporters.ScannerStatus, []evidence.Evidence, semgrep.Run) {
	t.Helper()
	run, err := semgrep.ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	var status scannerStatusList
	var evid []evidence.Evidence
	recordSemgrepRun(&status, &evid, run)
	if len(status) != 1 {
		t.Fatalf("entries = %+v", status)
	}
	return status[0], evid, run
}

// requireFindingOrGap is the invariant: the vulnerable line is reported, or
// the run is a gap of the given reason whose detail names the file.
func requireFindingOrGap(t *testing.T, got reporters.ScannerStatus, evid []evidence.Evidence, rule, file string, line int, reason reporters.ScannerReason) {
	t.Helper()
	if hasFindingAt(evid, rule, file, line) {
		t.Logf("branch: finding present; %s reported at %s:%d; semgrep entry %+v", rule, file, line, got)
		if got.State == reporters.ScannerOK && strings.Contains(got.Detail, "lost evaluation") {
			t.Errorf("entry %+v is ok but says evaluation was lost", got)
		}
		return
	}
	if got.State != reporters.ScannerFailed || got.Reason != reason {
		t.Fatalf("%s at %s:%d is missing and semgrep is %+v: a scan that lost the finding must not read as complete (want failed/%s)", rule, file, line, got, reason)
	}
	if !strings.Contains(got.Detail, file) {
		t.Errorf("detail %q does not name %s", got.Detail, file)
	}
	t.Logf("branch: gap; %s missing at %s:%d, recorded %s/%s: %s", rule, file, line, got.State, got.Reason, got.Detail)
}

func TestRealSemgrepJSFixpointTimeoutIsAGap(t *testing.T) {
	requireSemgrep(t)
	src, line := expressRouterInline(1000)
	root := writeTree(t, map[string]string{"routes/api.js": src})
	got, evid, _ := scanAndRecord(t, root)
	requireFindingOrGap(t, got, evid, "js-ssrf-taint", "routes/api.js", line, reporters.ReasonTimeout)
}

func TestRealSemgrepGoFixpointTimeoutIsAGap(t *testing.T) {
	requireSemgrep(t)
	src, line := ginMainInline(400)
	root := writeTree(t, map[string]string{"main.go": src, "go.mod": "module example.com/x\n\ngo 1.22\n"})
	got, evid, _ := scanAndRecord(t, root)
	requireFindingOrGap(t, got, evid, "go-ssrf-taint", "main.go", line, reporters.ReasonTimeout)
}

// qa-engine-05: the tests above accept either outcome, so on a fast enough
// host the gap branch may never run. This one cannot pass without it. On the
// 2,700-line controller below java-open_redirect-taint takes about 18 s with no
// timeout (Semgrep 1.182.1, 2 CPUs: measured 18.4 s of a 20.3 s run), so at a
// 1 s per-rule --timeout Semgrep stops it on any host short of one eighteen
// times faster. The run must then be recorded failed/timeout naming the file,
// whatever else it found; a run that reports no Timeout fails the test rather
// than passing it.
func TestRealSemgrepRuleTimeoutIsAlwaysRecordedTimeout(t *testing.T) {
	requireSemgrep(t)
	defer semgrep.SetRuleTimeoutForTesting(1)()
	src, _ := springRedirects(300)
	const file = "src/main/java/app/ItemController.java"
	root := writeTree(t, map[string]string{file: src})
	got, evid, run := scanAndRecord(t, root)
	timedOut := false
	for _, to := range run.Timeouts {
		if to.RuleID == "java-open_redirect-taint" && to.Path == file {
			timedOut = true
		}
	}
	if !timedOut {
		t.Fatalf("Semgrep did not time out java-open_redirect-taint on %s at a 1 s --timeout (timeouts %+v): the input no longer forces the failed/timeout branch, resize it", file, run.Timeouts)
	}
	if got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonTimeout {
		t.Fatalf("semgrep = %+v; a run with a rule timeout must be failed/timeout", got)
	}
	if !strings.Contains(got.Detail, file) || !strings.Contains(got.Detail, "rule timeout") {
		t.Errorf("detail %q does not name the timeout on %s", got.Detail, file)
	}
	if len(evid) != len(run.Findings) {
		t.Errorf("recorded %d findings of the run's %d: the findings a failed run produced are kept", len(evid), len(run.Findings))
	}
	t.Logf("failed/timeout branch taken: %s", got.Detail)
}

// With a 1 s per-rule timeout, three Java taint rules time out on this
// 2,700-line controller, Semgrep's --timeout-threshold of 3 is reached, and no
// other rule runs on the file.
func TestRealSemgrepRuleTimeoutsAndThresholdAreAGap(t *testing.T) {
	requireSemgrep(t)
	defer semgrep.SetRuleTimeoutForTesting(1)()
	src, line := springRedirects(300)
	const file = "src/main/java/app/ItemController.java"
	root := writeTree(t, map[string]string{file: src})
	got, evid, run := scanAndRecord(t, root)
	if len(run.Timeouts) > 0 && got.State == reporters.ScannerOK {
		t.Fatalf("Semgrep timed out %d rule(s) and the run is recorded %+v", len(run.Timeouts), got)
	}
	requireFindingOrGap(t, got, evid, "java-open_redirect-taint", file, line, reporters.ReasonTimeout)
}
