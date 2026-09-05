package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
)

// writePythonScript creates a temporary Python script that simulates the engine.
func writePythonScript(t *testing.T, dir, filename, content string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("writing python script: %v", err)
	}
	return path
}

func TestReadFindings_ValidStream(t *testing.T) {
	input := `{"id":"","title":"Hardcoded secret","severity":"HIGH","source":"whitebox","category":"secrets","endpoint":"config.py:14","evidence":"API_KEY = sk-...","fix":"Use env var","references":["CWE-798"],"confidence":"HIGH","line":"config.py:14"}
{"id":"","title":"SQL injection","severity":"CRITICAL","source":"whitebox","category":"injection","endpoint":"db.py:42","evidence":"cursor.execute(f\"...\")","fix":"Use parameterized queries","references":["CWE-89"],"confidence":"HIGH","line":"db.py:42"}
{"done":true,"total":2}
`
	sr := readFindings(strings.NewReader(input))
	if sr.readErr != nil {
		t.Fatalf("unexpected error: %v", sr.readErr)
	}
	if sr.doneTotal != 2 {
		t.Errorf("expected total 2, got %d", sr.doneTotal)
	}
	if len(sr.findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(sr.findings))
	}
	if sr.findings[0].Title != "Hardcoded secret" {
		t.Errorf("unexpected title: %s", sr.findings[0].Title)
	}
	if sr.findings[1].Severity != models.SeverityCritical {
		t.Errorf("unexpected severity: %s", sr.findings[1].Severity)
	}
}

func TestReadFindings_EmptyStream(t *testing.T) {
	input := `{"done":true,"total":0}
`
	sr := readFindings(strings.NewReader(input))
	if sr.doneTotal != 0 {
		t.Errorf("expected total 0, got %d", sr.doneTotal)
	}
	if len(sr.findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(sr.findings))
	}
}

func TestReadFindings_MalformedLine(t *testing.T) {
	input := `not valid json
{"id":"","title":"Valid finding","severity":"HIGH","source":"whitebox","category":"test","endpoint":"a.py:1","evidence":"x","fix":"y","references":[],"confidence":"HIGH","line":null}
{"done":true,"total":1}
`
	sr := readFindings(strings.NewReader(input))
	if sr.doneTotal != 1 {
		t.Errorf("expected total 1, got %d", sr.doneTotal)
	}
	if len(sr.findings) != 1 {
		t.Errorf("expected 1 finding (malformed skipped), got %d", len(sr.findings))
	}
	if sr.malformed != 1 {
		t.Errorf("expected 1 malformed line counted, got %d", sr.malformed)
	}
}

func TestReadFindings_MissingRequiredFields(t *testing.T) {
	input := `{"id":"","title":"","severity":"","source":"","category":"","endpoint":"","evidence":"","fix":"","references":[],"confidence":"","line":null}
{"done":true,"total":0}
`
	sr := readFindings(strings.NewReader(input))
	if len(sr.findings) != 0 {
		t.Errorf("expected 0 findings (empty title/severity skipped), got %d", len(sr.findings))
	}
	if sr.malformed != 1 {
		t.Errorf("expected the empty-fields line to be counted malformed, got %d", sr.malformed)
	}
}

func TestReadFindings_DoneWithError(t *testing.T) {
	input := `{"done":true,"total":0,"error":"invalid ScanRequest JSON: Expecting value"}
`
	sr := readFindings(strings.NewReader(input))
	if sr.doneErr == "" {
		t.Fatal("expected doneErr from done message with error field")
	}
	if !strings.Contains(sr.doneErr, "invalid ScanRequest JSON") {
		t.Errorf("unexpected doneErr message: %v", sr.doneErr)
	}
}

func TestReadFindings_NoTerminator(t *testing.T) {
	input := `{"id":"","title":"Orphan finding","severity":"MEDIUM","source":"whitebox","category":"test","endpoint":"a.py:1","evidence":"x","fix":"y","references":[],"confidence":"MEDIUM","line":null}
`
	sr := readFindings(strings.NewReader(input))
	if len(sr.findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(sr.findings))
	}
	if sr.sawDone {
		t.Error("expected sawDone false: stream ended without a done line")
	}
}

func TestReadFindings_BlankLines(t *testing.T) {
	input := `
{"id":"","title":"Finding","severity":"LOW","source":"whitebox","category":"test","endpoint":"a.py:1","evidence":"x","fix":"y","references":[],"confidence":"LOW","line":null}

{"done":true,"total":1}
`
	sr := readFindings(strings.NewReader(input))
	if sr.doneTotal != 1 {
		t.Errorf("expected total 1, got %d", sr.doneTotal)
	}
	if len(sr.findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(sr.findings))
	}
}

func TestReadFindings_WhiteboxSourceDefault(t *testing.T) {
	input := `{"id":"","title":"No source","severity":"HIGH","source":"","category":"test","endpoint":"a.py","evidence":"x","fix":"y","references":[],"confidence":"HIGH","line":null}
{"done":true,"total":1}
`
	sr := readFindings(strings.NewReader(input))
	if len(sr.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(sr.findings))
	}
	if sr.findings[0].Source != models.SourceWhitebox {
		t.Errorf("expected source whitebox, got %s", sr.findings[0].Source)
	}
}

func TestPythonSpawner_RunWithMockEngine(t *testing.T) {
	dir := t.TempDir()

	// Write a minimal mock engine.py that emits one finding and done
	script := `import json, sys
finding = {
    "id": "",
    "title": "Mock finding",
    "severity": "HIGH",
    "source": "whitebox",
    "category": "secrets",
    "endpoint": "mock.py:1",
    "evidence": "MOCK_KEY = 'abc'",
    "fix": "Remove it",
    "references": ["CWE-798"],
    "confidence": "HIGH",
    "line": "mock.py:1"
}
print(json.dumps(finding), flush=True)
print(json.dumps({"done": True, "total": 1}), flush=True)
`
	writePythonScript(t, dir, "engine.py", script)

	spawner := NewPythonSpawner("python3", dir)
	req := ScanRequest{
		Mode:     "whitebox",
		CodePath: dir,
		Checks:   []string{"secrets"},
	}

	result := spawner.Run(context.Background(), req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.Total != 1 {
		t.Errorf("expected total 1, got %d", result.Total)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].Title != "Mock finding" {
		t.Errorf("unexpected title: %s", result.Findings[0].Title)
	}
}

func TestPythonSpawner_RunEmptyEngine(t *testing.T) {
	dir := t.TempDir()

	script := `import json, sys
request = json.loads(sys.stdin.read())
print(json.dumps({"done": True, "total": 0}), flush=True)
`
	writePythonScript(t, dir, "engine.py", script)

	spawner := NewPythonSpawner("python3", dir)
	req := ScanRequest{
		Mode:   "whitebox",
		Checks: []string{},
	}

	result := spawner.Run(context.Background(), req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.Total != 0 {
		t.Errorf("expected total 0, got %d", result.Total)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestPythonSpawner_ContextCancellation(t *testing.T) {
	dir := t.TempDir()

	// Script that sleeps long enough to be cancelled
	script := `import time, json, sys
sys.stdin.read()
time.sleep(30)
print(json.dumps({"done": True, "total": 0}), flush=True)
`
	writePythonScript(t, dir, "engine.py", script)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	spawner := NewPythonSpawner("python3", dir)
	req := ScanRequest{Mode: "whitebox", Checks: []string{}}

	result := spawner.Run(ctx, req)
	if result.Err == nil {
		t.Fatal("expected error from context cancellation")
	}
}

func TestPythonSpawner_BadPythonBin(t *testing.T) {
	spawner := NewPythonSpawner("/nonexistent/python3", ".")
	req := ScanRequest{Mode: "whitebox", Checks: []string{}}

	result := spawner.Run(context.Background(), req)
	if result.Err == nil {
		t.Fatal("expected error from bad python binary")
	}
}

func TestPythonSpawner_MultipleFindings(t *testing.T) {
	dir := t.TempDir()

	script := `import json, sys
sys.stdin.read()
for i in range(5):
    finding = {
        "id": "",
        "title": f"Finding {i+1}",
        "severity": "MEDIUM",
        "source": "whitebox",
        "category": "test",
        "endpoint": f"file{i}.py:1",
        "evidence": f"issue {i+1}",
        "fix": "Fix it",
        "references": [],
        "confidence": "MEDIUM",
        "line": f"file{i}.py:1"
    }
    print(json.dumps(finding), flush=True)
print(json.dumps({"done": True, "total": 5}), flush=True)
`
	writePythonScript(t, dir, "engine.py", script)

	spawner := NewPythonSpawner("python3", dir)
	req := ScanRequest{Mode: "whitebox", Checks: []string{"secrets"}}

	result := spawner.Run(context.Background(), req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.Total != 5 {
		t.Errorf("expected total 5, got %d", result.Total)
	}
	if len(result.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(result.Findings))
	}
	for i, f := range result.Findings {
		expected := "Finding " + string(rune('1'+i))
		if f.Title != expected {
			// Just check they're all present
			if f.Source != models.SourceWhitebox {
				t.Errorf("finding %d: expected source whitebox, got %s", i, f.Source)
			}
		}
	}
}

func TestPythonSpawner_StderrLogging(t *testing.T) {
	dir := t.TempDir()

	// Script that writes to stderr (diagnostics) and stdout (findings)
	script := `import json, sys
sys.stdin.read()
print("[fendix-engine] starting check: secrets", file=sys.stderr, flush=True)
finding = {
    "id": "",
    "title": "Secret found",
    "severity": "CRITICAL",
    "source": "whitebox",
    "category": "secrets",
    "endpoint": "env.py:3",
    "evidence": "AWS_KEY = AKIA...",
    "fix": "Rotate key",
    "references": ["CWE-798"],
    "confidence": "HIGH",
    "line": "env.py:3"
}
print(json.dumps(finding), flush=True)
print("[fendix-engine] finished check: secrets", file=sys.stderr, flush=True)
print(json.dumps({"done": True, "total": 1}), flush=True)
`
	writePythonScript(t, dir, "engine.py", script)

	spawner := NewPythonSpawner("python3", dir)
	req := ScanRequest{Mode: "whitebox", Checks: []string{"secrets"}, Verbose: true}

	result := spawner.Run(context.Background(), req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestPythonSpawner_EngineCrash(t *testing.T) {
	dir := t.TempDir()

	// Script that crashes with exit code 1
	script := `import sys
sys.stdin.read()
sys.exit(1)
`
	writePythonScript(t, dir, "engine.py", script)

	spawner := NewPythonSpawner("python3", dir)
	req := ScanRequest{Mode: "whitebox", Checks: []string{"secrets"}}

	result := spawner.Run(context.Background(), req)
	if result.Err == nil {
		t.Fatal("expected error from engine crash")
	}
	// Should not have any findings
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings from crashed engine, got %d", len(result.Findings))
	}
}

func TestPythonSpawner_DefaultValues(t *testing.T) {
	spawner := NewPythonSpawner("", "")
	if spawner.pythonBin != "python3" {
		t.Errorf("expected default pythonBin 'python3', got '%s'", spawner.pythonBin)
	}
	if spawner.engineDir != "python" {
		t.Errorf("expected default engineDir 'python', got '%s'", spawner.engineDir)
	}
}

func TestScanRequest_JSONSerialization(t *testing.T) {
	req := ScanRequest{
		Mode:     "whitebox",
		Spec:     "./openapi.yaml",
		CodePath: "./src",
		Checks:   []string{"secrets", "auth", "semgrep"},
		Verbose:  true,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	jsonStr := string(data)
	for _, expected := range []string{`"mode":"whitebox"`, `"spec":"./openapi.yaml"`, `"code_path":"./src"`, `"checks":["secrets","auth","semgrep"]`} {
		if !strings.Contains(jsonStr, expected) {
			t.Errorf("JSON missing expected field: %s\ngot: %s", expected, jsonStr)
		}
	}
}

func TestScanRequest_OmitEmpty(t *testing.T) {
	req := ScanRequest{
		Mode:   "whitebox",
		Checks: []string{"secrets"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	jsonStr := string(data)
	if strings.Contains(jsonStr, `"spec"`) {
		t.Errorf("expected spec to be omitted when empty, got: %s", jsonStr)
	}
	if strings.Contains(jsonStr, `"code_path"`) {
		t.Errorf("expected code_path to be omitted when empty, got: %s", jsonStr)
	}
}

// TestScanRequest_HasNoLanguageField guards a removal.
//
// `language` was dropped from ScanRequest: nothing in production ever set it,
// so the key was never emitted, and the AST analyzer routes by file extension
// anyway — strictly more accurate than one whole-scan hint. Asserting on
// marshalled JSON cannot catch its return (an unset `omitempty` field is
// invisible), so this inspects the struct type directly.
func TestScanRequest_HasNoLanguageField(t *testing.T) {
	rt := reflect.TypeOf(ScanRequest{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if strings.EqualFold(f.Name, "language") || tag == "language" {
			t.Errorf("ScanRequest.%s reintroduces the removed `language` field. If a language\n"+
				"hint is genuinely needed, WIRE it from a flag — do not add another field\n"+
				"nothing populates.", f.Name)
		}
	}
}

// writeFakeEngine writes a minimal engine.py (with the json/sys imports
// prepended) into a fresh temp dir and returns the dir, for spawner-level
// (Run) tests that only need to supply the print(...) body.
func writeFakeEngine(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "engine.py"), []byte("import json, sys\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestReadFindings_StatusLinesAreNotFindings(t *testing.T) {
	in := strings.NewReader(strings.Join([]string{
		`{"status": {"check": "auth", "state": "skipped", "reason": "not_applicable", "detail": "no spec supplied"}}`,
		`{"title": "SQLi", "severity": "HIGH", "category": "injection", "endpoint": "app.py:3"}`,
		`{"status": {"check": "injection", "state": "ok"}}`,
		`{"status": {"check": "deps", "state": "skipped", "reason": "dependency_missing", "detail": "No module named 'packaging'"}}`,
		`{"done": true, "total": 1, "protocol": 2}`,
	}, "\n"))
	sr := readFindings(in)
	if len(sr.findings) != 1 || sr.doneTotal != 1 || !sr.sawDone || sr.malformed != 0 || sr.protocol != 2 {
		t.Fatalf("unexpected stream result: %+v", sr)
	}
	if len(sr.checks) != 3 || sr.checks[0].Check != "auth" || sr.checks[0].Reason != "not_applicable" || sr.checks[1].State != "ok" || sr.checks[2].Detail == "" {
		t.Fatalf("status lines not parsed: %+v", sr.checks)
	}
}

func TestReadFindings_MissingDoneAndMalformedCounted(t *testing.T) {
	sr := readFindings(strings.NewReader(`{"title": "x", "severity": "LOW"}` + "\n" + `this is not json` + "\n"))
	if sr.sawDone || sr.malformed != 1 || len(sr.findings) != 1 {
		t.Fatalf("unexpected: %+v", sr)
	}
}

func TestSpawner_OutcomeClassification(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	finding := `{"title": "SQLi", "severity": "HIGH", "category": "injection", "endpoint": "app.py:3"}`
	for _, tc := range []struct {
		name string
		body string
		want SpawnOutcome
	}{
		{"ok", "print('" + finding + "', flush=True)\nprint(json.dumps({'done': True, 'total': 1}), flush=True)\n", SpawnOK},
		{"truncated: no done", "print('" + finding + "', flush=True)\n", SpawnTruncated},
		{"truncated: total mismatch", "print('" + finding + "', flush=True)\nprint(json.dumps({'done': True, 'total': 5}), flush=True)\n", SpawnTruncated},
		{"malformed line", "print('not json at all', flush=True)\nprint(json.dumps({'done': True, 'total': 0}), flush=True)\n", SpawnMalformed},
		{"exit error wins over done", "print(json.dumps({'done': True, 'total': 0}), flush=True)\nsys.exit(3)\n", SpawnExitError},
		{"done.error", "print(json.dumps({'done': True, 'total': 0, 'error': 'boom'}), flush=True)\n", SpawnExitError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFakeEngine(t, tc.body)
			res := NewPythonSpawner("python3", dir).Run(context.Background(), ScanRequest{Mode: "whitebox", Checks: []string{"injection"}})
			if res.Outcome != tc.want {
				t.Fatalf("outcome = %v (err=%v), want %v", res.Outcome, res.Err, tc.want)
			}
			if tc.want != SpawnOK && res.Err == nil {
				t.Fatal("a non-ok outcome must carry an error")
			}
		})
	}
}

func TestSpawner_ProtocolV2ChildCompleteness(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	st := func(check, state string) string {
		return "print(json.dumps({'status': {'check': '" + check + "', 'state': '" + state + "'}}), flush=True)\n"
	}
	done := "print(json.dumps({'done': True, 'total': 0, 'protocol': 2}), flush=True)\n"
	legacyDone := "print(json.dumps({'done': True, 'total': 0}), flush=True)\n"
	for _, tc := range []struct {
		name       string
		body       string
		want       SpawnOutcome
		wantChecks int
	}{
		{"all three exactly once", st("auth", "ok") + st("injection", "ok") + st("deps", "ok") + done, SpawnOK, 3},
		{"missing one is truncated", st("auth", "ok") + st("deps", "ok") + done, SpawnTruncated, 2},
		{"duplicate is malformed", st("auth", "ok") + st("injection", "ok") + st("injection", "ok") + st("deps", "ok") + done, SpawnMalformed, 4},
		{"unknown child is malformed", st("auth", "ok") + st("injection", "ok") + st("deps", "ok") + st("secrets", "ok") + done, SpawnMalformed, 4},
		{"legacy stream: children ignored, parent ok", st("auth", "ok") + legacyDone, SpawnOK, 0},
		{"legacy stream without any status lines", legacyDone, SpawnOK, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeFakeEngine(t, tc.body)
			res := NewPythonSpawner("python3", dir).Run(context.Background(), ScanRequest{Mode: "whitebox", Checks: []string{"auth", "injection", "deps"}})
			if res.Outcome != tc.want {
				t.Fatalf("outcome = %v (err=%v), want %v", res.Outcome, res.Err, tc.want)
			}
			if len(res.Checks) != tc.wantChecks {
				t.Fatalf("checks kept = %d, want %d: %+v", len(res.Checks), tc.wantChecks, res.Checks)
			}
		})
	}
}

func TestRecordPythonEngine_ChildrenParticipateParentStaysOK(t *testing.T) {
	var l scannerStatusList
	recordPythonEngine(&l, SpawnResult{Outcome: SpawnOK, Protocol: 2, Checks: []CheckStatus{
		{Check: "auth", State: "skipped", Reason: "not_applicable", Detail: "no spec supplied"},
		{Check: "injection", State: "ok"},
		{Check: "deps", State: "skipped", Reason: "dependency_missing", Detail: "No module named 'packaging'"},
	}})
	if got := find(l, AnalyzerPythonEngine); got.State != reporters.ScannerOK {
		t.Fatalf("parent = %+v, want ok", got)
	}
	if got := find(l, AnalyzerPythonDeps); got.Reason != reporters.ReasonDependencyMissing {
		t.Fatalf("deps child = %+v, want dependency_missing", got)
	}
	if n := len(l); n != 4 {
		t.Fatalf("expected parent + 3 children, got %d entries: %+v", n, l)
	}

	l = nil
	recordPythonEngine(&l, SpawnResult{Outcome: SpawnOK, Protocol: 2, Checks: []CheckStatus{{Check: "injection", State: "failed", Reason: "not_applicable"}}})
	if got := find(l, AnalyzerPythonInjection); got.State != reporters.ScannerFailed || got.Reason != reporters.ReasonMalformedOutput {
		t.Fatalf("mismatched pairing must be recorded as failed/malformed_output, got %+v", got)
	}

	l = nil
	recordPythonEngine(&l, SpawnResult{Outcome: SpawnTruncated, Protocol: 2, Err: errors.New("python engine (protocol 2) omitted status for: deps"),
		Checks: []CheckStatus{{Check: "auth", State: "ok"}, {Check: "injection", State: "ok"}}})
	if got := find(l, AnalyzerPythonEngine); got.Reason != reporters.ReasonTruncatedOutput {
		t.Fatalf("missing child → parent %+v, want truncated_output", got)
	}
	if !l.has(AnalyzerPythonAuth) || l.has(AnalyzerPythonDeps) {
		t.Fatal("reported children are kept; the missing one has no entry — the parent failure carries the gap")
	}
}
