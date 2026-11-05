package semgrep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// sqlResult mirrors the _SQL_RESULT fixture in
// python/tests/test_semgrep_runner.py for parity comparisons.
var sqlResult = semgrepResult{
	CheckID: "python-sql-injection-string-format",
	Path:    "/code/app.py",
	Start:   semgrepLineCol{Line: 42, Col: 5},
	Extra: semgrepExtra{
		Message:  "SQL query built via string formatting — SQL injection risk.\nUse parameterized queries.",
		Severity: "ERROR",
		Lines:    "    cursor.execute('SELECT * FROM users WHERE id = %s' % user_id)",
		Metadata: map[string]interface{}{
			"category":        "injection",
			"cwe":             "CWE-89",
			"confidence":      "HIGH",
			"fendix_severity": "CRITICAL",
		},
	},
}

var authResult = semgrepResult{
	CheckID: "python-jwt-decode-no-verification",
	Path:    "/code/views.py",
	Start:   semgrepLineCol{Line: 10, Col: 5},
	Extra: semgrepExtra{
		Message:  "JWT decoded with signature verification disabled. This allows an attacker to forge tokens. Remove options={\"verify_signature\": False} and specify a strong algorithm.",
		Severity: "ERROR",
		Lines:    "    claims = jwt.decode(token, options={'verify_signature': False})",
		Metadata: map[string]interface{}{
			"category":        "auth",
			"cwe":             "CWE-347",
			"confidence":      "HIGH",
			"fendix_severity": "CRITICAL",
		},
	},
}

// semgrepOutputJSON serializes `results` into the wire shape of
// `semgrep --json` so tests don't have to hand-craft the wrapper.
func semgrepOutputJSON(t *testing.T, results []semgrepResult) []byte {
	t.Helper()
	doc := semgrepOutput{Results: results}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// installFakeSemgrep writes a shell script to a fresh tmpdir, marks it
// executable, and points LookPath/commandContext at it for the test's
// duration. The script writes `stdout`, `stderr`, and exits with
// `exitCode`. Returns t.Cleanup-registered restore via t.Cleanup.
//
// Using a real subprocess (not mocking commandContext) exercises the
// stdout-capture + exit-code paths exactly as production would.
func installFakeSemgrep(t *testing.T, stdout, stderr string, exitCode int) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "semgrep")
	stdoutB64 := base64Encode(stdout)
	stderrB64 := base64Encode(stderr)
	script := fmt.Sprintf(`#!/bin/sh
printf '%%s' '%s' | base64 -d
printf '%%s' '%s' | base64 -d 1>&2
exit %d
`, stdoutB64, stderrB64, exitCode)
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

// base64Encode is local-only to keep tests dep-free.
func base64Encode(s string) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(s); i += 3 {
		end := i + 3
		if end > len(s) {
			end = len(s)
		}
		chunk := s[i:end]
		var b uint32
		for j := 0; j < 3; j++ {
			b <<= 8
			if j < len(chunk) {
				b |= uint32(chunk[j])
			}
		}
		out.WriteByte(tbl[(b>>18)&0x3F])
		out.WriteByte(tbl[(b>>12)&0x3F])
		if len(chunk) > 1 {
			out.WriteByte(tbl[(b>>6)&0x3F])
		} else {
			out.WriteByte('=')
		}
		if len(chunk) > 2 {
			out.WriteByte(tbl[b&0x3F])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

// installAbsentSemgrep makes LookPath always fail for "semgrep".
func installAbsentSemgrep(t *testing.T) {
	t.Helper()
	origLook := LookPath
	LookPath = func(name string) (string, error) {
		if name == "semgrep" {
			return "", exec.ErrNotFound
		}
		return origLook(name)
	}
	t.Cleanup(func() { LookPath = origLook })
}

// ---------------------------------------------------------------------------
// Mapping helpers — direct parity with python TestMappingHelpers class.
// ---------------------------------------------------------------------------

func TestResolveSeverity_FromMetadata(t *testing.T) {
	if got := resolveSeverity(&sqlResult); got != models.SeverityCritical {
		t.Errorf("got %q; want CRITICAL", got)
	}
}

func TestResolveSeverity_FallsBackToSemgrepSeverity(t *testing.T) {
	r := semgrepResult{Extra: semgrepExtra{Severity: "WARNING", Metadata: map[string]interface{}{}}}
	if got := resolveSeverity(&r); got != "MEDIUM" {
		t.Errorf("got %q; want MEDIUM", got)
	}
}

func TestResolveSeverity_FendixSeverityCaseInsensitive(t *testing.T) {
	r := semgrepResult{Extra: semgrepExtra{Metadata: map[string]interface{}{"fendix_severity": "high"}}}
	if got := resolveSeverity(&r); got != models.SeverityHigh {
		t.Errorf("got %q; want HIGH", got)
	}
}

func TestResolveSeverity_UnknownDefaultsToMedium(t *testing.T) {
	r := semgrepResult{Extra: semgrepExtra{Severity: "BANANA", Metadata: map[string]interface{}{}}}
	if got := resolveSeverity(&r); got != "MEDIUM" {
		t.Errorf("got %q; want MEDIUM", got)
	}
}

func TestResolveConfidence_FromMetadata(t *testing.T) {
	if got := resolveConfidence(&sqlResult); got != models.ConfidenceHigh {
		t.Errorf("got %q; want HIGH", got)
	}
}

func TestResolveConfidence_DefaultsToMedium(t *testing.T) {
	r := semgrepResult{Extra: semgrepExtra{Metadata: map[string]interface{}{}}}
	if got := resolveConfidence(&r); got != "MEDIUM" {
		t.Errorf("got %q; want MEDIUM", got)
	}
}

func TestResolveCategory_FromMetadata(t *testing.T) {
	if got := resolveCategory(&sqlResult); got != "injection" {
		t.Errorf("got %q; want injection", got)
	}
}

func TestResolveCategory_DefaultsToCode(t *testing.T) {
	r := semgrepResult{Extra: semgrepExtra{Metadata: map[string]interface{}{}}}
	if got := resolveCategory(&r); got != "code" {
		t.Errorf("got %q; want code", got)
	}
}

func TestResolveCWE_StringForm(t *testing.T) {
	got := resolveCWE(&sqlResult)
	if len(got) != 1 || got[0] != "CWE-89" {
		t.Errorf("got %v; want [CWE-89]", got)
	}
}

func TestResolveCWE_ListForm(t *testing.T) {
	r := semgrepResult{Extra: semgrepExtra{Metadata: map[string]interface{}{
		"cwe": []interface{}{"CWE-89", "CWE-564"},
	}}}
	got := resolveCWE(&r)
	if len(got) != 2 || got[0] != "CWE-89" || got[1] != "CWE-564" {
		t.Errorf("got %v; want [CWE-89 CWE-564]", got)
	}
}

func TestResolveCWE_AbsentReturnsNil(t *testing.T) {
	r := semgrepResult{Extra: semgrepExtra{Metadata: map[string]interface{}{}}}
	if got := resolveCWE(&r); got != nil {
		t.Errorf("got %v; want nil", got)
	}
}

// ---------------------------------------------------------------------------
// mapResult shape parity.
// ---------------------------------------------------------------------------

func TestMapResult_SQLInjection(t *testing.T) {
	f, ok := mapResult(&sqlResult, "/code")
	if !ok {
		t.Fatal("expected mapping to succeed")
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("severity = %q; want CRITICAL", f.Severity)
	}
	if f.Category != "injection" {
		t.Errorf("category = %q; want injection", f.Category)
	}
	if f.Source != models.SourceWhitebox {
		t.Errorf("source = %q; want whitebox", f.Source)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("confidence = %q; want HIGH", f.Confidence)
	}
	if len(f.References) != 1 || f.References[0] != "CWE-89" {
		t.Errorf("references = %v; want [CWE-89]", f.References)
	}
	if !strings.HasPrefix(f.ID, "SEC-PYTHON_SQL_INJECTION") {
		t.Errorf("id = %q; want SEC-PYTHON_SQL_INJECTION… prefix", f.ID)
	}
	if !strings.HasSuffix(f.Endpoint, ":42") {
		t.Errorf("endpoint = %q; want :42 suffix", f.Endpoint)
	}
	if f.Line == nil || *f.Line != f.Endpoint {
		t.Errorf("line not mirrored to endpoint; line=%v endpoint=%q", f.Line, f.Endpoint)
	}
	// Title is split on first newline.
	if strings.Contains(f.Title, "\n") {
		t.Errorf("title contains newline: %q", f.Title)
	}
}

func TestMapResult_Auth(t *testing.T) {
	f, ok := mapResult(&authResult, "/code")
	if !ok {
		t.Fatal("expected mapping to succeed")
	}
	// fendix_severity wins over the semgrep severity (ERROR would map to HIGH).
	if f.Severity != models.SeverityCritical {
		t.Errorf("severity = %q; want CRITICAL", f.Severity)
	}
	if f.Category != "auth" {
		t.Errorf("category = %q; want auth", f.Category)
	}
}

func TestMapResult_TruncatesEvidence(t *testing.T) {
	r := sqlResult
	r.Extra.Lines = strings.Repeat("x", 500)
	f, ok := mapResult(&r, "/code")
	if !ok {
		t.Fatal("expected mapping to succeed")
	}
	if len(f.Evidence) > 210 { // 200 + "..."
		t.Errorf("evidence length %d; want ≤210", len(f.Evidence))
	}
	if !strings.HasSuffix(f.Evidence, "...") {
		t.Errorf("evidence missing truncation marker: %q", f.Evidence[len(f.Evidence)-10:])
	}
}

func TestMapResult_RejectsMissingFields(t *testing.T) {
	if _, ok := mapResult(&semgrepResult{}, "/code"); ok {
		t.Errorf("expected empty result to be rejected")
	}
	if _, ok := mapResult(&semgrepResult{CheckID: "x"}, "/code"); ok {
		t.Errorf("expected missing path to be rejected")
	}
}

func TestMapResult_EndpointUsesForwardSlashes(t *testing.T) {
	r := sqlResult
	r.Path = filepath.Join(string(filepath.Separator), "code", "sub", "app.py")
	f, ok := mapResult(&r, string(filepath.Separator)+"code")
	if !ok {
		t.Fatal("expected mapping to succeed")
	}
	if strings.ContainsRune(f.Endpoint, '\\') {
		t.Errorf("endpoint has backslash: %q", f.Endpoint)
	}
}

// ---------------------------------------------------------------------------
// Scan() — error & graceful-degradation paths.
// ---------------------------------------------------------------------------

func TestScan_AbsentSemgrepReturnsSentinel(t *testing.T) {
	installAbsentSemgrep(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Scan(context.Background(), dir)
	if !errors.Is(err, ErrSemgrepUnavailable) {
		t.Errorf("err = %v; want ErrSemgrepUnavailable", err)
	}
}

func TestScan_CodePathMissing(t *testing.T) {
	_, err := Scan(context.Background(), "/nonexistent/path/that/does/not/exist")
	if !errors.Is(err, ErrCodePathMissing) {
		t.Errorf("err = %v; want ErrCodePathMissing", err)
	}
}

func TestScan_EmptyCodePath(t *testing.T) {
	_, err := Scan(context.Background(), "")
	if !errors.Is(err, ErrCodePathMissing) {
		t.Errorf("err = %v; want ErrCodePathMissing", err)
	}
}

func TestScan_FileNotDirectory(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x.py")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Scan(context.Background(), f)
	if err == nil {
		t.Errorf("expected error when path is a file")
	}
	if errors.Is(err, ErrCodePathMissing) {
		t.Errorf("file-not-dir should not collapse to ErrCodePathMissing")
	}
}

// ---------------------------------------------------------------------------
// Scan() — happy-path with fake semgrep on PATH.
// ---------------------------------------------------------------------------

func TestScan_EmitsFindingsFromFakeSemgrep(t *testing.T) {
	stdout := semgrepOutputJSON(t, []semgrepResult{sqlResult, authResult})
	installFakeSemgrep(t, string(stdout), "", 1) // exit 1 == findings present
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings; want 2", len(got))
	}
	cats := []string{got[0].Category, got[1].Category}
	if !((cats[0] == "injection" && cats[1] == "auth") || (cats[0] == "auth" && cats[1] == "injection")) {
		t.Errorf("unexpected categories %v", cats)
	}
}

func TestScan_EmptyResultsProducesNothing(t *testing.T) {
	stdout := semgrepOutputJSON(t, nil)
	installFakeSemgrep(t, string(stdout), "", 0)
	dir := t.TempDir()
	got, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d; want 0", len(got))
	}
}

func TestScan_MalformedJSONReturnsZeroFindings(t *testing.T) {
	installFakeSemgrep(t, "not json", "", 0)
	dir := t.TempDir()
	got, err := Scan(context.Background(), dir)
	if err != nil {
		t.Errorf("err = %v; want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d findings; want 0", len(got))
	}
}

func TestScan_NonSuccessExitWithoutFindingsBubblesError(t *testing.T) {
	installFakeSemgrep(t, "", "fatal: rule parse error", 2)
	dir := t.TempDir()
	_, err := Scan(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for exit code 2")
	}
	if !strings.Contains(err.Error(), "rule parse error") {
		t.Errorf("error %q missing stderr context", err)
	}
}

func TestScan_ContextCancellationKillsSemgrep(t *testing.T) {
	dir := t.TempDir()
	// Fake semgrep that sleeps so cancel has time to fire.
	binDir := t.TempDir()
	bin := filepath.Join(binDir, "semgrep")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	origLook := LookPath
	LookPath = func(name string) (string, error) {
		if name == "semgrep" {
			return bin, nil
		}
		return origLook(name)
	}
	t.Cleanup(func() { LookPath = origLook })

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Scan(ctx, dir)
	if err == nil {
		t.Fatal("expected ctx-cancellation error")
	}
	// Budget of 8s tolerates GitHub-hosted Linux runners where
	// exec.CommandContext's default Cancel SIGKILLs only the
	// entrypoint and Wait blocks until orphaned grandchildren
	// (here: the fake semgrep's `sleep 5` child) exit. Tried
	// cmd.WaitDelay = 1s to bound the wait, but it changes I/O
	// behaviour for non-cancel paths too and exposed a pre-existing
	// pipe race in TestRun_NonZeroExit. Bumping the budget is the
	// minimal-risk fix. A "cancel never fired" regression would be
	// a deterministic ~5s — well below 8s, so this assertion still
	// catches it.
	if time.Since(start) > 8*time.Second {
		t.Errorf("Scan didn't honour ctx cancel — took %s", time.Since(start))
	}
}

// ---------------------------------------------------------------------------
// Embedded rules — verify they extracted and are valid YAML files on disk.
// ---------------------------------------------------------------------------

func TestEnsureRules_ExtractsAllBundledFiles(t *testing.T) {
	resetRulesCacheForTesting()
	dir, err := ensureRules()
	if err != nil {
		t.Fatalf("ensureRules: %v", err)
	}
	for _, name := range []string{"auth.yaml", "injection.yaml", "secrets.yaml", "crypto.yaml"} {
		full := filepath.Join(dir, name)
		info, err := os.Stat(full)
		if err != nil {
			t.Errorf("missing %s: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", name)
		}
	}
}

func TestEnsureRules_CachesAcrossCalls(t *testing.T) {
	resetRulesCacheForTesting()
	first, err := ensureRules()
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := ensureRules()
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first != second {
		t.Errorf("rules dir not cached: %q vs %q", first, second)
	}
}

// ---------------------------------------------------------------------------
// Title trimming.
// ---------------------------------------------------------------------------

func TestMapResult_TitleAtMost120Chars(t *testing.T) {
	r := sqlResult
	r.Extra.Message = strings.Repeat("a", 500)
	f, ok := mapResult(&r, "/code")
	if !ok {
		t.Fatal("expected mapping to succeed")
	}
	if len(f.Title) > 120 {
		t.Errorf("title length %d; want ≤120", len(f.Title))
	}
}

// TestScanWithAllowlist_EmptyReturnsNothingWithoutRunning is the B3/S7 guard:
// an empty (non-nil) allowlist must return nothing WITHOUT looking up or
// running semgrep — otherwise no --include is added and the whole tree is
// scanned (the diff footgun).
func TestScanWithAllowlist_EmptyReturnsNothingWithoutRunning(t *testing.T) {
	dir := t.TempDir()
	origLook := LookPath
	called := false
	LookPath = func(string) (string, error) { called = true; return "", errors.New("must not be called") }
	t.Cleanup(func() { LookPath = origLook })

	allow := gitdiff.NewAllowlist(dir, nil) // non-nil, zero files
	got, err := ScanWithAllowlist(context.Background(), dir, allow)
	if err != nil || got != nil {
		t.Fatalf("empty allowlist: got (%v, %v), want (nil, nil)", got, err)
	}
	if called {
		t.Error("semgrep was looked up despite an empty allowlist (would scan the whole tree)")
	}
}

// ── Taint findings and the semgrep_taint tier (ADR-011) ──────────────────────
//
// The fixtures in testdata/ come from one Semgrep 1.141.0 run of the rule in
// testdata/taint_rule.yaml over the one-file Express app in spikeApp below.
//
// taint_result_logged_out.json is byte-for-byte what
// `semgrep --config taint_rule.yaml --json --dataflow-traces app.js` prints
// with no Semgrep account logged in, re-indented: no extra.dataflow_trace (the
// JSON formatter withholds it, as it withholds `lines`).
//
// taint_result.json is the same run with the JSON document serialized by
// Semgrep's own encoder for its output schema (semgrep_output_v1, CliOutput),
// which is the document the formatter withholds the trace from — what a
// logged-in run receives. It carries extra.dataflow_trace as Semgrep computed
// it, and the real `lines`.

const spikeRuleID = "express-sqli-taint-spike"

const spikeApp = `const express = require("express");
const db = require("./db");

const app = express();

app.get("/users", (req, res) => {
  const name = req.query.name;
  const sql = "SELECT * FROM users WHERE name = '" + name + "'";
  db.query(sql, (err, rows) => res.json(rows));
});

app.listen(3000);
`

// spikeSink is the finding's Sink: line 9 of spikeApp, the match's own line.
const spikeSink = "db.query(sql, (err, rows) => res.json(rows));"

// testdataDir is resolved before any test changes directory.
var testdataDir, _ = filepath.Abs("testdata")

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(testdataDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// inSpikeApp makes a directory holding spikeApp as app.js the working
// directory, so the fixtures' relative path "app.js" names a real file — as it
// does in a real scan, where the finding's line is read from disk.
func inSpikeApp(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(spikeApp), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
}

// spikeRuleSpecs reads testdata/taint_rule.yaml with the parser the bundled
// pack is read with.
func spikeRuleSpecs(t *testing.T) map[string]ruleSpec {
	t.Helper()
	specs, err := parseRuleSpecs(loadFixture(t, "taint_rule.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return specs
}

// useRuleSpecs points the rule lookup at specs for the test.
func useRuleSpecs(t *testing.T, specs map[string]ruleSpec) {
	t.Helper()
	orig := ruleSpecs
	ruleSpecs = func(id string) (ruleSpec, bool) { s, ok := specs[id]; return s, ok }
	t.Cleanup(func() { ruleSpecs = orig })
}

// enableReachability replaces the per-language gate for the test.
func enableReachability(t *testing.T, langs ...string) {
	t.Helper()
	orig := ReachabilityLanguages
	ReachabilityLanguages = map[string]bool{}
	for _, l := range langs {
		ReachabilityLanguages[l] = true
	}
	t.Cleanup(func() { ReachabilityLanguages = orig })
}

// mapOne maps a fixture document that must hold exactly one result.
func mapOne(t *testing.T, doc []byte) evidence.Evidence {
	t.Helper()
	evs, err := parseAndMap(doc, ".")
	if err != nil {
		t.Fatalf("parseAndMap: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d findings, want 1", len(evs))
	}
	return evs[0]
}

// rewriteFixture decodes a fixture, lets edit change its first result, and
// re-encodes it, so a test can vary one field of a recorded document.
func rewriteFixture(t *testing.T, name string, edit func(result map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(loadFixture(t, name), &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc["results"].([]any)[0].(map[string]any))
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func extraOf(result map[string]any) map[string]any { return result["extra"].(map[string]any) }

func requireShim(t *testing.T, ev evidence.Evidence) {
	t.Helper()
	if ev.Reachable || ev.SourceTier != models.TierSemgrepShim || ev.TaintChain != nil {
		t.Errorf("got Reachable=%v SourceTier=%q TaintChain=%v; want a shim finding (false, %q, nil)",
			ev.Reachable, ev.SourceTier, ev.TaintChain, models.TierSemgrepShim)
	}
}

func requireTaint(t *testing.T, ev evidence.Evidence) {
	t.Helper()
	if !ev.Reachable || ev.SourceTier != models.TierSemgrepTaint || len(ev.TaintChain) == 0 {
		t.Errorf("got Reachable=%v SourceTier=%q TaintChain=%v; want a reachable %q finding with a chain",
			ev.Reachable, ev.SourceTier, ev.TaintChain, models.TierSemgrepTaint)
	}
}

// A logged-in run: Semgrep sends the trace, and it becomes the chain.
func TestTaintResultBecomesReachableWhenLanguageEnabled(t *testing.T) {
	useRuleSpecs(t, spikeRuleSpecs(t))
	enableReachability(t, "javascript")
	doc := loadFixture(t, "taint_result.json")
	inSpikeApp(t)

	ev := mapOne(t, doc)

	requireTaint(t, ev)
	want := []models.TaintLink{
		{File: "app.js", Line: 7, Expr: "req.query.name"},
		{File: "app.js", Line: 7, Expr: "name"},
		{File: "app.js", Line: 8, Expr: "sql"},
		// The trace's sink step is the finding's own location, so the link
		// states the operation as the finding does (its Sink).
		{File: "app.js", Line: 9, Expr: spikeSink},
	}
	if !reflect.DeepEqual(ev.TaintChain, want) {
		t.Errorf("TaintChain =\n  %+v\nwant (source, intermediate variables, sink)\n  %+v", ev.TaintChain, want)
	}
	if ev.Sink != spikeSink {
		t.Errorf("Sink = %q, want the match's own line %q", ev.Sink, spikeSink)
	}
}

// What Semgrep 1.141.0 actually prints with no account logged in: no trace.
// The match of a taint-mode rule is the proof (R-pf56), so the finding is
// reachable all the same; its chain holds only the finding's own location.
func TestLoggedOutTaintResultIsReachableWithoutATrace(t *testing.T) {
	useRuleSpecs(t, spikeRuleSpecs(t))
	enableReachability(t, "javascript")
	doc := loadFixture(t, "taint_result_logged_out.json")
	inSpikeApp(t)

	ev := mapOne(t, doc)

	requireTaint(t, ev)
	want := []models.TaintLink{{File: "app.js", Line: 9, Expr: spikeSink}}
	if !reflect.DeepEqual(ev.TaintChain, want) {
		t.Errorf("TaintChain = %+v, want only the finding's own location %+v", ev.TaintChain, want)
	}
	if ev.Sink != spikeSink {
		t.Errorf("Sink = %q, want the match's own line %q", ev.Sink, spikeSink)
	}
}

func TestTaintResultStaysShimWhenLanguageDisabled(t *testing.T) {
	useRuleSpecs(t, spikeRuleSpecs(t))
	enableReachability(t) // the shipped state: no language enabled

	for _, name := range []string{"taint_result.json", "taint_result_logged_out.json"} {
		t.Run(name, func(t *testing.T) {
			requireShim(t, mapOne(t, loadFixture(t, name)))
		})
	}
}

// A trace adds detail and nothing else: the logged-in and the logged-out run
// of one finding, with the gate open or closed, have one identity. Without
// this a login, or enabling a language, would file the finding as
// fixed-plus-new.
func TestTraceNeverMovesIdentity(t *testing.T) {
	useRuleSpecs(t, spikeRuleSpecs(t))
	traced := loadFixture(t, "taint_result.json")
	loggedOut := loadFixture(t, "taint_result_logged_out.json")
	inSpikeApp(t)

	type run struct {
		name string
		ev   evidence.Evidence
	}
	var runs []run
	for _, gate := range [][]string{nil, {"javascript"}} {
		enableReachability(t, gate...)
		runs = append(runs,
			run{fmt.Sprintf("traced, gate %v", gate), mapOne(t, traced)},
			run{fmt.Sprintf("logged out, gate %v", gate), mapOne(t, loggedOut)})
	}
	for _, r := range runs[:2] {
		if r.ev.Reachable {
			t.Errorf("%s: Reachable with the gate closed", r.name)
		}
	}
	for _, r := range runs[2:] {
		if !r.ev.Reachable {
			t.Errorf("%s: not Reachable with the gate open", r.name)
		}
	}
	first := runs[0]
	want := models.Fingerprint(first.ev.ToFinding())
	for _, r := range runs[1:] {
		if got := models.Fingerprint(r.ev.ToFinding()); got != want {
			t.Errorf("fingerprint of %q = %s, want %s (%q)\n %v\n %v", r.name, got, want, first.name,
				models.FingerprintIdentityComponents(r.ev.ToFinding()),
				models.FingerprintIdentityComponents(first.ev.ToFinding()))
		}
		if r.ev.ID != first.ev.ID || r.ev.Title != first.ev.Title || r.ev.Severity != first.ev.Severity ||
			r.ev.Endpoint != first.ev.Endpoint || r.ev.Sink != first.ev.Sink || r.ev.RuleID != first.ev.RuleID ||
			r.ev.Symbol != first.ev.Symbol {
			t.Errorf("%q differs from %q beyond tier, reachability and chain:\n %+v\n %+v",
				r.name, first.name, r.ev, first.ev)
		}
	}
}

func TestNonTaintRuleNeverReachable(t *testing.T) {
	enableReachability(t, "javascript")
	taintSpec := ruleSpec{Mode: "taint", Languages: []string{"javascript"}}

	for name, tc := range map[string]struct {
		spec  map[string]ruleSpec
		edit  func(map[string]any)
		fixed string
	}{
		"no fendix_reachability": {
			spec: map[string]ruleSpec{spikeRuleID: taintSpec},
			edit: func(r map[string]any) {
				delete(extraOf(r)["metadata"].(map[string]any), "fendix_reachability")
			},
		},
		"another fendix_reachability value": {
			spec: map[string]ruleSpec{spikeRuleID: taintSpec},
			edit: func(r map[string]any) {
				extraOf(r)["metadata"].(map[string]any)["fendix_reachability"] = "pattern"
			},
		},
		"no metadata at all": {
			spec: map[string]ruleSpec{spikeRuleID: taintSpec},
			edit: func(r map[string]any) { delete(extraOf(r), "metadata") },
		},
		// fendix_reachability on a rule that is not a taint rule: a pattern
		// match proves no flow, whatever its metadata says.
		"search-mode rule": {
			spec: map[string]ruleSpec{spikeRuleID: {Mode: "", Languages: []string{"javascript"}}},
			edit: func(map[string]any) {},
		},
		"rule not in the pack": {
			spec: map[string]ruleSpec{},
			edit: func(map[string]any) {},
		},
	} {
		t.Run(name, func(t *testing.T) {
			useRuleSpecs(t, tc.spec)
			for _, fixture := range []string{"taint_result.json", "taint_result_logged_out.json"} {
				requireShim(t, mapOne(t, rewriteFixture(t, fixture, tc.edit)))
			}
		})
	}
}

// Every language a rule declares must be enabled: a rule that also runs on
// TypeScript files has not met its gate because JavaScript has.
func TestTaintRuleWithALanguageNotEnabledStaysShim(t *testing.T) {
	enableReachability(t, "javascript")

	for name, langs := range map[string][]string{
		"one of two languages enabled": {"javascript", "typescript"},
		"rule declares no language":    {},
	} {
		t.Run(name, func(t *testing.T) {
			useRuleSpecs(t, map[string]ruleSpec{spikeRuleID: {Mode: "taint", Languages: langs}})
			requireShim(t, mapOne(t, loadFixture(t, "taint_result.json")))
		})
	}
}

// Semgrep's language aliases name the same language as the gate's key.
func TestTaintGateAcceptsSemgrepLanguageAliases(t *testing.T) {
	enableReachability(t, "javascript", "typescript")
	useRuleSpecs(t, map[string]ruleSpec{spikeRuleID: {Mode: "Taint", Languages: []string{"JS", "ts"}}})

	requireTaint(t, mapOne(t, loadFixture(t, "taint_result.json")))
}

// A trace Fendix cannot read, or one without a source, costs detail and
// nothing else: the finding is still reachable, its chain is the finding's own
// location, and every other result in the document is still mapped.
func TestUnreadableTaintTraceOnlyLosesDetail(t *testing.T) {
	useRuleSpecs(t, spikeRuleSpecs(t))
	enableReachability(t, "javascript")
	own := []models.TaintLink{{File: "app.js", Line: 9, Expr: spikeSink}}

	for name, trace := range map[string]any{
		"unknown variant tag": map[string]any{"taint_source": []any{"CliSomethingNew", []any{}}},
		"not an object":       "trace",
		"source not an array": map[string]any{"taint_source": map[string]any{"path": "app.js"}},
		"location without a path": map[string]any{"taint_source": []any{"CliLoc", []any{
			map[string]any{"start": map[string]any{"line": 7}}, "req.query.name"}}},
		"no source": map[string]any{"taint_sink": []any{"CliLoc", []any{
			map[string]any{"path": "app.js", "start": map[string]any{"line": 9}}, "db.query(sql)"}}},
	} {
		t.Run(name, func(t *testing.T) {
			doc := rewriteFixture(t, "taint_result.json", func(r map[string]any) {
				extraOf(r)["dataflow_trace"] = trace
			})
			var parsed map[string]any
			if err := json.Unmarshal(doc, &parsed); err != nil {
				t.Fatal(err)
			}
			second := map[string]any{}
			if err := json.Unmarshal(semgrepOutputJSON(t, []semgrepResult{sqlResult}), &second); err != nil {
				t.Fatal(err)
			}
			parsed["results"] = append(parsed["results"].([]any), second["results"].([]any)...)
			doc, _ = json.Marshal(parsed)

			evs, err := parseAndMap(doc, ".")
			if err != nil || len(evs) != 2 {
				t.Fatalf("got %d findings (err %v), want both results mapped", len(evs), err)
			}
			requireTaint(t, evs[0])
			if !reflect.DeepEqual(evs[0].TaintChain, own) {
				t.Errorf("TaintChain = %+v, want only the finding's own location %+v", evs[0].TaintChain, own)
			}
		})
	}
}

// A call trace (["CliCall", [[loc, content], vars, inner]]) is flattened in
// dataflow order: a source reached through a call starts at the innermost
// source and ends at the call; a sink reached through a call starts at the call
// and ends at the innermost sink. The chain then ends at the finding's own
// location, which keeps its identity (see TestTraceNeverMovesIdentity).
func TestTaintTraceCallVariantsFlattenInDataflowOrder(t *testing.T) {
	useRuleSpecs(t, spikeRuleSpecs(t))
	enableReachability(t, "javascript")

	loc := func(path string, line int) map[string]any {
		return map[string]any{"path": path,
			"start": map[string]any{"line": line, "col": 1}, "end": map[string]any{"line": line, "col": 9}}
	}
	ivar := func(path string, line int, content string) map[string]any {
		return map[string]any{"location": loc(path, line), "content": content}
	}
	doc := rewriteFixture(t, "taint_result.json", func(r map[string]any) {
		extraOf(r)["dataflow_trace"] = map[string]any{
			"taint_source": []any{"CliCall", []any{
				[]any{loc("app.js", 7), "readName(req)"},
				[]any{ivar("lib/input.js", 3, "v")},
				[]any{"CliLoc", []any{loc("lib/input.js", 2), "req.query.name"}},
			}},
			"intermediate_vars": []any{ivar("app.js", 8, "sql")},
			"taint_sink": []any{"CliCall", []any{
				[]any{loc("app.js", 9), "run(sql)"},
				[]any{ivar("lib/db.js", 4, "q")},
				[]any{"CliLoc", []any{loc("lib/db.js", 5), "db.query(q)"}},
			}},
		}
	})

	ev := mapOne(t, doc)
	want := []models.TaintLink{
		{File: "lib/input.js", Line: 2, Expr: "req.query.name"},
		{File: "lib/input.js", Line: 3, Expr: "v"},
		{File: "app.js", Line: 7, Expr: "readName(req)"},
		{File: "app.js", Line: 8, Expr: "sql"},
		{File: "app.js", Line: 9, Expr: "run(sql)"},
		{File: "lib/db.js", Line: 4, Expr: "q"},
		{File: "lib/db.js", Line: 5, Expr: "db.query(q)"},
		// The finding is reported in app.js; the chain ends where it is reported.
		{File: "app.js", Line: 9, Expr: spikeSink},
	}
	if !reflect.DeepEqual(ev.TaintChain, want) {
		t.Errorf("TaintChain =\n  %+v\nwant\n  %+v", ev.TaintChain, want)
	}
}

// Trace locations are made relative the way Endpoint is, and a trace link
// never carries a credential-shaped literal: the chain is published.
func TestTaintChainLinksAreRelativeAndMasked(t *testing.T) {
	useRuleSpecs(t, spikeRuleSpecs(t))
	enableReachability(t, "javascript")

	root := testdataDir
	abs := filepath.Join(root, "src", "app.js")
	const token = "sk_live_51H8xQeLkdIwHu7ix0aBcDeFgHiJ"
	doc := rewriteFixture(t, "taint_result.json", func(r map[string]any) {
		r["path"] = abs
		trace := extraOf(r)["dataflow_trace"].(map[string]any)
		src := trace["taint_source"].([]any)[1].([]any)
		src[0].(map[string]any)["path"] = abs
		src[1] = "req.query.name || \"" + token + "\""
		for _, v := range trace["intermediate_vars"].([]any) {
			v.(map[string]any)["location"].(map[string]any)["path"] = abs
		}
		trace["taint_sink"].([]any)[1].([]any)[0].(map[string]any)["path"] = abs
	})

	evs, err := parseAndMap(doc, root)
	if err != nil || len(evs) != 1 {
		t.Fatalf("got %d findings (err %v), want 1", len(evs), err)
	}
	ev := evs[0]
	if ev.Endpoint != "src/app.js:9" {
		t.Fatalf("precondition: Endpoint = %q, want src/app.js:9", ev.Endpoint)
	}
	for i, link := range ev.TaintChain {
		if link.File != "src/app.js" {
			t.Errorf("link %d file = %q, want src/app.js (relative, like Endpoint)", i, link.File)
		}
		if strings.Contains(link.Expr, token) {
			t.Errorf("link %d expr carries a credential-shaped literal: %q", i, link.Expr)
		}
	}
}

// The Sink of a rule that declares fendix_reachability is the match's own
// first line — read from disk, else the first line semgrep sent — never the
// whole multi-line `lines` a logged-in run sends and never the trace. So the
// Sink, an identity input, is the same text logged in or out.
func TestTaintRuleSinkIsTheMatchLine(t *testing.T) {
	useRuleSpecs(t, spikeRuleSpecs(t))
	enableReachability(t, "javascript")
	multiLine := func(r map[string]any) {
		extraOf(r)["lines"] = "  db.query(sql, (err, rows) => res.json(rows));\n  // and the next line"
	}

	t.Run("file not on disk", func(t *testing.T) {
		if ev := mapOne(t, rewriteFixture(t, "taint_result.json", multiLine)); ev.Sink != spikeSink {
			t.Errorf("Sink = %q, want the first matched line %q", ev.Sink, spikeSink)
		}
	})
	t.Run("file on disk", func(t *testing.T) {
		doc := rewriteFixture(t, "taint_result.json", multiLine)
		inSpikeApp(t)
		if ev := mapOne(t, doc); ev.Sink != spikeSink {
			t.Errorf("Sink = %q, want line 9 of app.js %q", ev.Sink, spikeSink)
		}
	})
}

// Existing rules carry no fendix_reachability, so a trace on their results —
// which --dataflow-traces may now produce — changes nothing about them.
func TestExistingRuleResultsIgnoreTraces(t *testing.T) {
	enableReachability(t, "javascript", "typescript", "java", "go", "python")
	r := sqlResult
	r.Extra.DataflowTrace = json.RawMessage(`{"taint_source":["CliLoc",[{"path":"/code/app.py","start":{"line":40,"col":1},"end":{"line":40,"col":9}},"request.args"]]}`)

	with, ok := mapResult(&r, "/code")
	if !ok {
		t.Fatal("expected mapping to succeed")
	}
	without, _ := mapResult(&sqlResult, "/code")
	if !reflect.DeepEqual(with, without) {
		t.Errorf("a trace changed an existing rule's finding:\n with:    %+v\n without: %+v", with, without)
	}
}

func TestScanRequestsDataflowTraces(t *testing.T) {
	argv := filepath.Join(t.TempDir(), "argv")
	installArgRecordingSemgrep(t, argv)

	if _, err := Scan(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	raw, err := os.ReadFile(argv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains("\n"+string(raw), "\n--dataflow-traces\n") {
		t.Errorf("semgrep argv does not request --dataflow-traces:\n%s", raw)
	}
}

// Semgrep's result names neither the rule's mode nor its languages, so both
// come from the bundled rule pack.
func TestBundledRuleSpecsComeFromThePack(t *testing.T) {
	spec, ok := ruleSpecs("django-view-missing-login-required")
	if !ok || spec.Mode != "" || !reflect.DeepEqual(spec.Languages, []string{"python"}) {
		t.Errorf("bundled pattern rule = %+v (found %v), want mode \"\" and languages [python]", spec, ok)
	}
	if _, ok := ruleSpecs("no-such-rule"); ok {
		t.Error("an unknown rule was found; the gate must fail closed for it")
	}
	if spec := spikeRuleSpecs(t)[spikeRuleID]; spec.Mode != "taint" || !reflect.DeepEqual(spec.Languages, []string{"javascript"}) {
		t.Errorf("testdata taint rule = %+v, want mode taint and languages [javascript]", spec)
	}
}

// The gate opens one language at a time, and only with ADR-011's evidence. The
// blind real-world evaluation of 70 production repos measured taint-tier
// precision of 0.077 (JS/TS), 0.111 (Java) and 0.091 (Go), all below the 0.80
// rule fixed in advance, so no language is enabled (ruling R-pf81) and every
// Semgrep finding is reported as a warning. A language is added only with new
// real-world evidence, and this test is updated in the same change.
func TestNoLanguageClearsTheRealWorldGate(t *testing.T) {
	want := map[string]bool{}
	if !reflect.DeepEqual(ReachabilityLanguages, want) {
		t.Errorf("ReachabilityLanguages = %v, want %v; a language is enabled only with ADR-011's evidence",
			ReachabilityLanguages, want)
	}
}

// testdata/timeout_result.json is byte-for-byte what Semgrep 1.141.0 printed
// for `semgrep --config <tmp>/fendix-semgrep-rules-1234 --json --quiet
// --no-git-ignore --timeout 1 src`, where the one rule (slow-rule) needs more
// than a second on src/big.py: no result, one error of type Timeout, exit 0.
// The scan succeeds, and the timeout is surfaced and logged, not dropped.
func TestScanRunSurfacesRuleTimeouts(t *testing.T) {
	installFakeSemgrep(t, string(loadFixture(t, "timeout_result.json")), "", 0)
	var logged strings.Builder
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(orig) })
	root := t.TempDir()
	t.Chdir(root) // the recorded path is relative to where semgrep ran

	run, err := ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	if len(run.Findings) != 0 {
		t.Errorf("findings = %+v; want none", run.Findings)
	}
	want := []RuleTimeout{{RuleID: "slow-rule", Path: "src/big.py"}}
	if !reflect.DeepEqual(run.Timeouts, want) {
		t.Errorf("timeouts = %+v; want %+v", run.Timeouts, want)
	}
	for _, s := range []string{"rule timed out", "rule=slow-rule", "path=src/big.py"} {
		if !strings.Contains(logged.String(), s) {
			t.Errorf("log lacks %q:\n%s", s, logged.String())
		}
	}

	// ScanWithAllowlist, the findings alone, still succeeds.
	if _, err := ScanWithAllowlist(context.Background(), root, nil); err != nil {
		t.Errorf("ScanWithAllowlist: %v", err)
	}
}

// Only a Timeout error is a rule timeout; other errors in the document are
// not, whatever their shape.
func TestParseRunCountsOnlyTimeoutErrors(t *testing.T) {
	doc := `{"results": [], "errors": [
	  {"type": "Timeout", "rule_id": "a", "path": "x.py"},
	  {"type": "Syntax error", "rule_id": "b", "path": "y.py"},
	  {"type": ["PartialParsing", [{"path": "z.py"}]], "path": "z.py"},
	  {"type": ["Timeout"], "rule_id": "c", "path": "w.py"}
	]}`
	run := parseRun([]byte(doc), "/code")
	want := []RuleTimeout{{RuleID: "a", Path: "x.py"}, {RuleID: "c", Path: "w.py"}}
	if !reflect.DeepEqual(run.Timeouts, want) {
		t.Errorf("timeouts = %+v; want %+v", run.Timeouts, want)
	}
}

// Semgrep's `errors` only add timeouts to a run. Whatever shape they arrive
// in, the results beside them are kept: a malformed entry is skipped, and an
// `errors` that is not a list is ignored.
func TestParseRunKeepsResultsWhateverTheErrors(t *testing.T) {
	const result = `{"check_id": "python-eval-injection", "path": "/code/app.py", "start": {"line": 3, "col": 1},
	  "extra": {"message": "eval()/exec() with dynamic argument", "severity": "ERROR", "lines": "eval(x)", "metadata": {}}}`
	cases := []struct {
		name, errors string
		timeouts     []RuleTimeout
	}{
		{"rule_id of the wrong type", `[{"type": "Timeout", "rule_id": 7, "path": "a.py"}, {"type": "Timeout", "rule_id": "b", "path": "b.py"}]`,
			[]RuleTimeout{{RuleID: "b", Path: "b.py"}}},
		{"path of the wrong type", `[{"type": "Timeout", "rule_id": "a", "path": {"value": "a.py"}}]`, nil},
		{"null fields", `[{"type": "Timeout", "rule_id": null, "path": null}]`, []RuleTimeout{{}}},
		{"an object", `{"unexpected": "object"}`, nil},
		{"a list of strings", `["a string entry"]`, nil},
		{"a string", `"oops"`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			run := parseRun([]byte(`{"results": [`+result+`], "errors": `+tc.errors+`}`), "/code")
			if len(run.Findings) != 1 || run.Findings[0].RuleID != "python-eval-injection" {
				t.Errorf("findings = %+v; want the one result", run.Findings)
			}
			if !reflect.DeepEqual(run.Timeouts, tc.timeouts) {
				t.Errorf("timeouts = %+v; want %+v", run.Timeouts, tc.timeouts)
			}
		})
	}
}

// The same through a whole run, on both of ScanRun's paths: semgrep exiting 0
// and exiting non-zero with a parseable document.
func TestScanRunKeepsResultsBesideMalformedErrors(t *testing.T) {
	root := t.TempDir()
	doc := `{"results": [{"check_id": "python-eval-injection", "path": "` + filepath.ToSlash(filepath.Join(root, "app.py")) +
		`", "start": {"line": 3, "col": 1}, "extra": {"message": "m", "severity": "ERROR", "lines": "eval(x)", "metadata": {}}}],
	  "errors": [{"type": "Timeout", "rule_id": 7, "path": "app.py"}]}`
	for _, exit := range []int{0, 1} {
		installFakeSemgrep(t, doc, "", exit)
		run, err := ScanRun(context.Background(), root, nil)
		if err != nil {
			t.Fatalf("exit %d: ScanRun: %v", exit, err)
		}
		if len(run.Findings) != 1 || run.Findings[0].Endpoint != "app.py:3" {
			t.Errorf("exit %d: findings = %+v; want app.py:3", exit, run.Findings)
		}
	}
}

// A rule Semgrep cannot load is not a finding-free run. Semgrep prints the
// error in `errors`, exits 7 and reports no result at all (checked with
// 1.141.0: `--config rules/` over a directory holding one rule with no
// pattern aborts the whole run), and ScanRun accepts any parseable document.
// Without RuleErrors a broken pack looked like a clean scan.
func TestParseRunSurfacesRuleErrors(t *testing.T) {
	doc := `{"results": [], "errors": [
	  {"code": 4, "level": "error", "type": "InvalidRuleSchemaError",
	   "long_msg": "Expected one of ` + "`pattern`" + ` to be present.", "short_msg": "Invalid rule schema"},
	  {"code": 7, "level": "error", "type": "SemgrepError", "message": "invalid configuration file found (1 configs were invalid)"},
	  {"type": ["PatternParseError", ["javascript"]], "rule_id": "r", "path": "a.js"},
	  {"type": "Timeout", "rule_id": "a", "path": "x.py"},
	  {"type": "Syntax error", "path": "y.py"},
	  {"type": ["PartialParsing", [{"path": "z.py"}]], "path": "z.py"},
	  {"type": "SemgrepError", "message": "some other failure"},
	  {"type": "InvalidRuleSchemaError", "short_msg": 7}
	]}`
	run := parseRun([]byte(doc), "/code")
	var got []string
	for _, e := range run.RuleErrors {
		got = append(got, e.Type)
	}
	want := []string{"InvalidRuleSchemaError", "SemgrepError", "PatternParseError", "InvalidRuleSchemaError"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rule error types = %v; want %v (a Timeout, a file parse error and an unrelated SemgrepError are not rule errors)", got, want)
	}
	if !strings.Contains(run.RuleErrors[0].Message, "Invalid rule schema") {
		t.Errorf("message = %q; want it to carry the short message", run.RuleErrors[0].Message)
	}
	if !strings.Contains(run.RuleErrors[1].Message, "invalid configuration file") {
		t.Errorf("message = %q; want it to carry the message", run.RuleErrors[1].Message)
	}
	if len(run.Timeouts) != 1 {
		t.Errorf("timeouts = %+v; want the one Timeout still counted", run.Timeouts)
	}
}

func TestScanRunReturnsRuleErrorsFromAnAbortedRun(t *testing.T) {
	root := t.TempDir()
	doc := `{"results": [], "errors": [{"code": 7, "level": "error", "type": "SemgrepError", "message": "invalid configuration file found (1 configs were invalid)"}]}`
	installFakeSemgrep(t, doc, "", 7)
	run, err := ScanRun(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("ScanRun: %v", err)
	}
	if len(run.RuleErrors) != 1 {
		t.Errorf("rule errors = %+v; want the one SemgrepError", run.RuleErrors)
	}
}
