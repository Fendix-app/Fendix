package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// The Python engine's JavaScript pattern checks (rule ids SEC-JS_*) are the
// fallback for a scan that has no Semgrep (D4). When the Semgrep run
// succeeded, its JavaScript pack answers instead and the fallback is dropped,
// so one sink is reported once.

func jsFallbackEvidence() []evidence.Evidence {
	return []evidence.Evidence{
		{ID: "SEC-JS_SQL_TEMPLATE", RuleID: "SEC-JS_SQL_TEMPLATE", Endpoint: "a.ts:3"},
		{ID: "SEC-JS_EVAL", RuleID: "SEC-JS_EVAL", Endpoint: "a.ts:4"},
		{ID: "SEC-PY_SQL_INJECTION", RuleID: "python.ast/PY_SQL_INJECTION", Endpoint: "b.py:9"},
		// A Semgrep rule whose id happens to start the same way is not the
		// Python engine's check and is never in this list, but the filter
		// must key on the exact prefix, not on the case.
		{ID: "SEC-JS_CMDI_TAINT", RuleID: "js-cmdi-taint", Endpoint: "a.ts:5"},
	}
}

func TestDropFallbackJSPatterns(t *testing.T) {
	cases := []struct {
		name   string
		status scannerStatusList
		want   []string
	}{
		{"semgrep ok drops the SEC-JS checks", scannerStatusList{{Name: AnalyzerSemgrep, State: reporters.ScannerOK}},
			[]string{"SEC-PY_SQL_INJECTION", "SEC-JS_CMDI_TAINT"}},
		{"semgrep skipped keeps them (no semgrep installed)", scannerStatusList{{Name: AnalyzerSemgrep, State: reporters.ScannerSkipped, Reason: reporters.ReasonDependencyMissing}},
			[]string{"SEC-JS_SQL_TEMPLATE", "SEC-JS_EVAL", "SEC-PY_SQL_INJECTION", "SEC-JS_CMDI_TAINT"}},
		{"semgrep disabled by --fast keeps them", scannerStatusList{{Name: AnalyzerSemgrep, State: reporters.ScannerSkipped, Reason: reporters.ReasonDisabledByFlag}},
			[]string{"SEC-JS_SQL_TEMPLATE", "SEC-JS_EVAL", "SEC-PY_SQL_INJECTION", "SEC-JS_CMDI_TAINT"}},
		{"semgrep failed keeps them", scannerStatusList{{Name: AnalyzerSemgrep, State: reporters.ScannerFailed, Reason: reporters.ReasonExecutionError}},
			[]string{"SEC-JS_SQL_TEMPLATE", "SEC-JS_EVAL", "SEC-PY_SQL_INJECTION", "SEC-JS_CMDI_TAINT"}},
		{"no semgrep entry keeps them", scannerStatusList{},
			[]string{"SEC-JS_SQL_TEMPLATE", "SEC-JS_EVAL", "SEC-PY_SQL_INJECTION", "SEC-JS_CMDI_TAINT"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The Semgrep finding is not part of the Python engine's output;
			// it is here only to prove the filter spares a non-fallback id.
			in := jsFallbackEvidence()
			got := dropFallbackJSPatterns(in, tc.status)
			var ids []string
			for _, e := range got {
				ids = append(ids, e.ID)
			}
			if len(ids) != len(tc.want) {
				t.Fatalf("kept %v; want %v", ids, tc.want)
			}
			for i := range ids {
				if ids[i] != tc.want[i] {
					t.Fatalf("kept %v; want %v", ids, tc.want)
				}
			}
		})
	}
}

// One JavaScript SQL sink that both the Python engine's pattern check and the
// Semgrep pack recognise is reported once, by Semgrep. Needs Semgrep and the
// Python engine's dependencies (the semgrep-enabled CI job has both).
func TestJSSQLTemplateSinkSeenByBothEnginesReportsOnce(t *testing.T) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep not on PATH")
	}
	src := "import express from \"express\";\n" +
		"import { Pool } from \"pg\";\n" +
		"const pool = new Pool();\n" +
		"const app = express();\n" +
		"app.get(\"/u\", async (req, res) => {\n" +
		"  const name = req.query.name as string;\n" +
		"  const r = await pool.query(`SELECT * FROM users WHERE name = '${name}'`);\n" +
		"  res.json(r.rows);\n" +
		"});\n"
	tree := t.TempDir()
	if err := os.WriteFile(filepath.Join(tree, "app.ts"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if dir, err := filepath.Abs(filepath.Join("..", "..", "..", "python")); err == nil {
		if _, err := os.Stat(filepath.Join(dir, "engine.py")); err == nil {
			t.Setenv("FENDIX_ENGINE", dir)
		}
	}
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{CodePath: tree, Workers: 1, Timeout: 120, Format: "json", OutputPath: out, PythonEngine: true}
	NewOrchestrator(cfg, "dev").Run(context.Background())
	report := readReport(t, out)
	if st, ok := statusFor(report, "python-engine"); !ok || st.State != reporters.ScannerOK {
		t.Skipf("python engine did not run: %+v", st)
	}
	if st, ok := statusFor(report, "semgrep"); !ok || st.State != reporters.ScannerOK {
		t.Skipf("semgrep did not run cleanly: %+v", st)
	}
	var atSink []string
	for _, f := range report.Findings {
		if f.Category == "injection" && f.Endpoint == "app.ts:7" {
			atSink = append(atSink, f.RuleID)
		}
		if f.RuleID == "SEC-JS_SQL_TEMPLATE" {
			t.Errorf("the Python engine's JS check reported beside a successful Semgrep run: %+v", f)
		}
	}
	if len(atSink) != 1 {
		t.Errorf("app.ts:7 reported %d times %v; want once", len(atSink), atSink)
	}
}

// Without Semgrep the fallback answers: the same sink is still reported.
func TestJSSQLTemplateFallbackReportsWithoutSemgrep(t *testing.T) {
	src := "const r = await pool.query(`SELECT * FROM users WHERE name = '${name}'`);\n"
	tree := t.TempDir()
	if err := os.WriteFile(filepath.Join(tree, "app.ts"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if dir, err := filepath.Abs(filepath.Join("..", "..", "..", "python")); err == nil {
		if _, err := os.Stat(filepath.Join(dir, "engine.py")); err == nil {
			t.Setenv("FENDIX_ENGINE", dir)
		}
	}
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{CodePath: tree, Workers: 1, Timeout: 120, Format: "json", OutputPath: out, PythonEngine: true, Fast: true}
	NewOrchestrator(cfg, "dev").Run(context.Background())
	report := readReport(t, out)
	if st, ok := statusFor(report, "python-engine"); !ok || st.State != reporters.ScannerOK {
		t.Skipf("python engine did not run: %+v", st)
	}
	found := false
	for _, f := range report.Findings {
		if f.RuleID == "SEC-JS_SQL_TEMPLATE" {
			found = true
		}
	}
	if !found {
		t.Error("with Semgrep disabled the Python engine's JS SQL check must still report")
	}
}
