package scope_test

// Release Closure Sprint, WS-C2, R6-E7a, end to end through the orchestrator
// (the repro of records/evidence-copy/e7-rerun/js-idescape): an Express handler
// that runs a shell command and a string of code through identifiers spelled with
// unicode escapes read 0 findings from the pattern analyzers with every analyzer
// ok and coverage complete. It must read incomplete, with Semgrep and textscan
// named as the gaps and the file named as lost evaluation; the control that
// spells the same calls plainly keeps its findings and stays complete.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/engine"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

const e7aHandler = `import express from 'express';
import { exec } from 'node:child_process';

const router = express.Router();

router.post('/cmdi', async (req, res) => {
  const host = req.body.host;
  %s('dig ' + host, () => undefined);
  %s(req.body.code);
  res.send('ok');
});

export default router;
`

func e7aRun(t *testing.T, name, body string) d2aReport {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wse1WriteFile(t, filepath.Join(root, name), []byte(body), 0o644)
	wse1InstallFakeSemgrep(t, root, nil, nil)
	out := filepath.Join(t.TempDir(), "report.json")
	cfg := &models.ScanConfig{CodePath: root, PythonEngine: false, Workers: 2, Timeout: 60, Format: "json", OutputPath: out}
	engine.NewOrchestrator(cfg, "dev").Run(context.Background())
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report written: %v", err)
	}
	var rep d2aReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestEscapedIdentifiersInAnExpressHandlerReadIncomplete(t *testing.T) {
	bs := "\\"
	rep := e7aRun(t, "app.js", strings.Replace(strings.Replace(e7aHandler, "%s", bs+"u0065xec", 1), "%s", bs+"u0065val", 1))
	gaps := " " + strings.Join(rep.Metadata.Coverage.Gaps, " ") + " "
	if rep.Metadata.Coverage.ConfiguredComplete || !strings.Contains(gaps, " semgrep ") || !strings.Contains(gaps, " textscan ") {
		t.Errorf("coverage complete=%v gaps=%v; want incomplete with semgrep and textscan named (Node runs the escaped calls)",
			rep.Metadata.Coverage.ConfiguredComplete, rep.Metadata.Coverage.Gaps)
	}
	named := map[string]bool{}
	for _, l := range rep.Metadata.Coverage.Limitations {
		if strings.Contains(l, "lost evaluation") && strings.Contains(l, "app.js") {
			named[strings.SplitN(l, ":", 2)[0]] = true
		}
	}
	if !named["semgrep"] || !named["textscan"] {
		t.Errorf("metadata.coverage.limitations name app.js as lost evaluation for %v, want semgrep and textscan: %v", named, rep.Metadata.Coverage.Limitations)
	}
}

func TestTheSameHandlerSpelledPlainlyKeepsItsFindingsAndStaysComplete(t *testing.T) {
	rep := e7aRun(t, "app.js", strings.Replace(strings.Replace(e7aHandler, "%s", "exec", 1), "%s", "eval", 1))
	if len(rep.Findings) == 0 {
		t.Error("the plain control reported nothing")
	}
	if !rep.Metadata.Coverage.ConfiguredComplete {
		t.Errorf("the plain control reads incomplete: gaps %v", rep.Metadata.Coverage.Gaps)
	}
}

// A regex literal that holds an escape is the commonest reason a crude rule would
// mark a JavaScript repository incomplete; here it must stay complete.
func TestARegexLiteralWithAnEscapeReadsComplete(t *testing.T) {
	rep := e7aRun(t, "util.js", "const strip = (s) => s.replace(/[^\\u00C0-\\u1FFF]/g, '');\nmodule.exports = { strip, ratio: (a, b) => a / b / 2 };\n")
	if !rep.Metadata.Coverage.ConfiguredComplete {
		t.Errorf("a file whose only escapes are in a regex reads incomplete: gaps %v, limitations %v", rep.Metadata.Coverage.Gaps, rep.Metadata.Coverage.Limitations)
	}
}
