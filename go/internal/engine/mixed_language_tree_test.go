package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/semgrep"
)

// mixedTree is one --code tree holding Python, TypeScript and Go. Every file
// has one injection sink that more than one analyzer recognises: the Python
// engine (and Semgrep) on app.py, textscan and Semgrep on server.ts and db.go.
var mixedTree = map[string]string{
	"svc/app.py": `import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def users():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return str(cur.fetchall())
`,
	"web/server.ts": `import express from "express";
import * as child_process from "child_process";

const app = express();

app.get("/ping", (req, res) => {
  const host = req.query.host as string;
  child_process.exec("ping -c 1 " + host, (err, out) => res.send(out));
});
`,
	"api/db.go": `package api

import (
	"database/sql"
	"fmt"
	"net/http"
)

func Users(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
	defer rows.Close()
}
`,
}

// One sink per file: the line each analyzer reports it on.
const (
	pySink = "svc/app.py:12"
	tsSink = "web/server.ts:8"
	goSink = "api/db.go:11"
)

// A bare exec(...) import is not a textscan pattern (JS_CHILD_PROCESS_SHELL
// wants child_process.exec), so on this line only Semgrep reports: its taint
// rule and its -sink twin. With the taint gate closed both are semgrep_shim,
// and the line was reported twice before ruling R-pf83.
func TestSemgrepTaintAndSinkTwinReportOnceFromBareExec(t *testing.T) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep not on PATH")
	}
	tree := t.TempDir()
	src := `import { exec } from "child_process";
import express from "express";

const app = express();

app.get("/ping", (req, res) => {
  const host = req.query.host as string;
  exec("ping -c 1 " + host, (err, out) => res.send(out));
});
`
	if err := os.WriteFile(filepath.Join(tree, "server.ts"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{CodePath: tree, Workers: 1, Timeout: 60, Format: "json", OutputPath: out}
	if code := NewOrchestrator(cfg, "dev").Run(context.Background()); code != 0 {
		t.Fatalf("scan exit = %d, want 0", code)
	}
	fs := injectionBySink(readReport(t, out))["server.ts:8"]
	if len(fs) != 1 {
		ids := make([]string, len(fs))
		for i, f := range fs {
			ids[i] = f.RuleID
		}
		t.Fatalf("server.ts:8 reported %d times %v, want once", len(fs), ids)
	}
	if fs[0].RuleID != "js-cmdi-taint" {
		t.Errorf("kept %q, want the taint member js-cmdi-taint", fs[0].RuleID)
	}
}

// scanMixedTree runs the whole orchestrator over mixedTree and returns the
// report, plus whether the Python engine ran (it needs its dependencies).
func scanMixedTree(t *testing.T) (reporters.JSONReport, bool) {
	t.Helper()
	tree := t.TempDir()
	for rel, body := range mixedTree {
		p := filepath.Join(tree, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if dir, err := filepath.Abs(filepath.Join("..", "..", "..", "python")); err == nil {
		if _, err := os.Stat(filepath.Join(dir, "engine.py")); err == nil {
			t.Setenv("FENDIX_ENGINE", dir)
		}
	}

	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{
		CodePath:     tree,
		Workers:      1,
		Timeout:      60,
		Format:       "json",
		OutputPath:   out,
		PythonEngine: true,
	}
	if code := NewOrchestrator(cfg, "dev").Run(context.Background()); code != 0 {
		t.Fatalf("scan exit = %d, want 0", code)
	}
	report := readReport(t, out)
	st, ok := statusFor(report, "python-engine")
	return report, ok && st.State == reporters.ScannerOK
}

// injectionBySink groups the injection findings by "file:line".
func injectionBySink(report reporters.JSONReport) map[string][]models.Finding {
	by := map[string][]models.Finding{}
	for _, f := range report.Findings {
		if f.Category == "injection" {
			by[f.Endpoint] = append(by[f.Endpoint], f)
		}
	}
	return by
}

func requireOnePerSink(t *testing.T, report reporters.JSONReport, sinks ...string) map[string]models.Finding {
	t.Helper()
	by := injectionBySink(report)
	one := map[string]models.Finding{}
	for sink, fs := range by {
		if len(fs) != 1 {
			titles := make([]string, len(fs))
			for i, f := range fs {
				titles[i] = string(f.SourceTier) + ": " + f.Title
			}
			sort.Strings(titles)
			t.Errorf("sink %s reported %d times, want once: %q", sink, len(fs), titles)
			continue
		}
		one[sink] = fs[0]
	}
	for _, want := range sinks {
		if _, ok := one[want]; !ok && len(by[want]) == 0 {
			t.Errorf("no injection finding at %s; sinks reported: %v", want, mapKeys(by))
		}
	}
	return one
}

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Review Focus 4. One --code tree holding Python, TypeScript and Go runs every
// pack once and reports a sink seen by several analyzers once.
//
// With the shipped config semgrep.ReachabilityLanguages is empty (ruling
// R-pf81): JavaScript, TypeScript and Go Semgrep taint matches are plain
// warnings and none is Reachable. The taint proof that ships is the Python
// engine's own chain, so that is the only proof asserted here.
func TestMixedLanguageTreeReportsEachSinkOnce(t *testing.T) {
	report, pythonRan := scanMixedTree(t)
	one := requireOnePerSink(t, report, pySink, tsSink, goSink)

	for _, sink := range []string{tsSink, goSink} {
		if f, ok := one[sink]; ok && (f.Reachable || f.SourceTier == models.TierSemgrepTaint) {
			t.Errorf("%s: Reachable=%v tier=%s, want no taint proof from a closed gate", sink, f.Reachable, f.SourceTier)
		}
	}
	if !pythonRan {
		t.Log("python engine did not run here; its taint chain is not asserted")
		return
	}
	py, ok := one[pySink]
	if !ok {
		return
	}
	if !py.Reachable || len(py.TaintChain) == 0 {
		t.Errorf("%s: Reachable=%v chain=%d, want the Python engine's taint chain kept through the collapse",
			pySink, py.Reachable, len(py.TaintChain))
	}
}

// The same tree with the Semgrep taint gate opened for JavaScript, TypeScript
// and Go, as the pack tests do. Textscan and the Semgrep taint rule then both
// report the TypeScript and Go sinks, and the collapse must keep one finding
// that still carries the proof.
func TestMixedLanguageTreeKeepsSemgrepTaintProofWhenGateIsOpen(t *testing.T) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep not on PATH")
	}
	orig := semgrep.ReachabilityLanguages
	semgrep.ReachabilityLanguages = map[string]bool{"javascript": true, "typescript": true, "go": true}
	t.Cleanup(func() { semgrep.ReachabilityLanguages = orig })

	report, _ := scanMixedTree(t)
	one := requireOnePerSink(t, report, tsSink, goSink)
	for _, sink := range []string{tsSink, goSink} {
		f, ok := one[sink]
		if !ok {
			continue
		}
		if !f.Reachable || len(f.TaintChain) == 0 {
			t.Errorf("%s (%s): Reachable=%v chain=%d, want the Semgrep taint proof kept", sink, f.SourceTier, f.Reachable, len(f.TaintChain))
		}
	}
}
