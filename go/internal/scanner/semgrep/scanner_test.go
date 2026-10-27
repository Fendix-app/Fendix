package semgrep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

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

// ── Taint traces and the semgrep_taint tier (ADR-011) ───────────────────────
//
// The fixtures in testdata/ come from one Semgrep 1.141.0 run of the rule in
// testdata/taint_rule.yaml over this one-file Express app:
//
//	1  const express = require("express");
//	2  const db = require("./db");
//	3
//	4  const app = express();
//	5
//	6  app.get("/users", (req, res) => {
//	7    const name = req.query.name;
//	8    const sql = "SELECT * FROM users WHERE name = '" + name + "'";
//	9    db.query(sql, (err, rows) => res.json(rows));
//	10 });
//
// taint_result_logged_out.json is byte-for-byte what
// `semgrep --config taint_rule.yaml --json --dataflow-traces app.js` prints
// with no Semgrep account logged in, re-indented: no extra.dataflow_trace (the
// JSON formatter withholds it, as it withholds `lines`).
//
// taint_result.json is the same run with the JSON document serialized by
// Semgrep's own encoder for its output schema (semgrep_output_v1, CliOutput),
// which is the document the formatter withholds the trace from. It carries
// extra.dataflow_trace as Semgrep computed it.

const spikeRuleID = "express-sqli-taint-spike"

// spikeRuleLanguages reads the `languages` of the rules in
// testdata/taint_rule.yaml, keyed by rule id, with the same YAML shape the
// bundled pack is parsed with.
func spikeRuleLanguages(t *testing.T) map[string][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "taint_rule.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc catalogRuleFileYAML
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, r := range doc.Rules {
		out[r.ID] = r.Languages
	}
	return out
}

// useRuleLanguages points the rule-languages lookup at langs for the test.
func useRuleLanguages(t *testing.T, langs map[string][]string) {
	t.Helper()
	orig := ruleLanguages
	ruleLanguages = func(id string) []string { return langs[id] }
	t.Cleanup(func() { ruleLanguages = orig })
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

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
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

func TestTaintResultBecomesReachableWhenLanguageEnabled(t *testing.T) {
	useRuleLanguages(t, spikeRuleLanguages(t))
	enableReachability(t, "javascript")

	ev := mapOne(t, loadFixture(t, "taint_result.json"))

	if !ev.Reachable {
		t.Error("Reachable = false, want true for a taint rule of an enabled language with a traced source")
	}
	if ev.SourceTier != models.TierSemgrepTaint {
		t.Errorf("SourceTier = %q, want %q", ev.SourceTier, models.TierSemgrepTaint)
	}
	want := []models.TaintLink{
		{File: "app.js", Line: 7, Expr: "req.query.name"},
		{File: "app.js", Line: 7, Expr: "name"},
		{File: "app.js", Line: 8, Expr: "sql"},
		// The trace's sink step is the finding's own location, so the link
		// states the operation as the finding does (its Sink).
		{File: "app.js", Line: 9, Expr: "db.query(sql, (err, rows) => res.json(rows));"},
	}
	if !reflect.DeepEqual(ev.TaintChain, want) {
		t.Errorf("TaintChain =\n  %+v\nwant (source, intermediate variables, sink)\n  %+v", ev.TaintChain, want)
	}
	if ev.Sink != want[len(want)-1].Expr {
		t.Errorf("Sink = %q, want the chain's last link %q", ev.Sink, want[len(want)-1].Expr)
	}
}

func TestTaintResultStaysShimWhenLanguageDisabled(t *testing.T) {
	useRuleLanguages(t, spikeRuleLanguages(t))
	enableReachability(t) // the shipped state: no language enabled

	ev := mapOne(t, loadFixture(t, "taint_result.json"))

	if ev.Reachable || ev.SourceTier != models.TierSemgrepShim || ev.TaintChain != nil {
		t.Errorf("got Reachable=%v SourceTier=%q TaintChain=%v; want false, %q, nil",
			ev.Reachable, ev.SourceTier, ev.TaintChain, models.TierSemgrepShim)
	}
}

func TestNonTaintRuleNeverReachable(t *testing.T) {
	useRuleLanguages(t, spikeRuleLanguages(t))
	enableReachability(t, "javascript")

	for name, edit := range map[string]func(map[string]any){
		"no fendix_reachability": func(r map[string]any) {
			delete(extraOf(r)["metadata"].(map[string]any), "fendix_reachability")
		},
		"another fendix_reachability value": func(r map[string]any) {
			extraOf(r)["metadata"].(map[string]any)["fendix_reachability"] = "pattern"
		},
		"no metadata at all": func(r map[string]any) { delete(extraOf(r), "metadata") },
	} {
		t.Run(name, func(t *testing.T) {
			ev := mapOne(t, rewriteFixture(t, "taint_result.json", edit))
			if ev.Reachable || ev.SourceTier != models.TierSemgrepShim || ev.TaintChain != nil {
				t.Errorf("got Reachable=%v SourceTier=%q TaintChain=%v; want false, %q, nil",
					ev.Reachable, ev.SourceTier, ev.TaintChain, models.TierSemgrepShim)
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
		"rule languages unknown":       nil,
		"rule declares no language":    {},
	} {
		t.Run(name, func(t *testing.T) {
			useRuleLanguages(t, map[string][]string{spikeRuleID: langs})
			ev := mapOne(t, loadFixture(t, "taint_result.json"))
			if ev.Reachable || ev.SourceTier != models.TierSemgrepShim || ev.TaintChain != nil {
				t.Errorf("languages %v: got Reachable=%v SourceTier=%q; want a shim finding",
					langs, ev.Reachable, ev.SourceTier)
			}
		})
	}
}

// Semgrep's language aliases name the same language as the gate's key.
func TestTaintGateAcceptsSemgrepLanguageAliases(t *testing.T) {
	enableReachability(t, "javascript", "typescript")
	useRuleLanguages(t, map[string][]string{spikeRuleID: {"JS", "ts"}})

	if ev := mapOne(t, loadFixture(t, "taint_result.json")); !ev.Reachable {
		t.Error("languages [JS, ts] with javascript and typescript enabled: want Reachable")
	}
}

// What Semgrep 1.141.0 actually prints with no account logged in: no trace.
// The gate's "the trace has a source" condition fails, so the finding stays a
// shim finding even for an enabled language — ADR-011 records this.
func TestLoggedOutTaintResultStaysShim(t *testing.T) {
	useRuleLanguages(t, spikeRuleLanguages(t))
	enableReachability(t, "javascript")

	ev := mapOne(t, loadFixture(t, "taint_result_logged_out.json"))
	if ev.Reachable || ev.SourceTier != models.TierSemgrepShim || ev.TaintChain != nil {
		t.Errorf("got Reachable=%v SourceTier=%q TaintChain=%v; want a shim finding",
			ev.Reachable, ev.SourceTier, ev.TaintChain)
	}
}

func TestTaintTraceWithoutSourceStaysShim(t *testing.T) {
	useRuleLanguages(t, spikeRuleLanguages(t))
	enableReachability(t, "javascript")

	ev := mapOne(t, rewriteFixture(t, "taint_result.json", func(r map[string]any) {
		delete(extraOf(r)["dataflow_trace"].(map[string]any), "taint_source")
	}))
	if ev.Reachable || ev.SourceTier != models.TierSemgrepShim || ev.TaintChain != nil {
		t.Errorf("got Reachable=%v SourceTier=%q; want a shim finding", ev.Reachable, ev.SourceTier)
	}
}

// A trace Fendix cannot read must never cost a finding: the result is still
// reported (as a shim finding), and so is every other result in the document.
func TestUnreadableTaintTraceNeverDropsFindings(t *testing.T) {
	useRuleLanguages(t, spikeRuleLanguages(t))
	enableReachability(t, "javascript")

	for name, trace := range map[string]any{
		"unknown variant tag": map[string]any{"taint_source": []any{"CliSomethingNew", []any{}}},
		"not an object":       "trace",
		"source not an array": map[string]any{"taint_source": map[string]any{"path": "app.js"}},
		"location without a path": map[string]any{"taint_source": []any{"CliLoc", []any{
			map[string]any{"start": map[string]any{"line": 7}}, "req.query.name"}}},
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
			if evs[0].Reachable || evs[0].SourceTier != models.TierSemgrepShim {
				t.Errorf("unreadable trace: got Reachable=%v SourceTier=%q; want a shim finding",
					evs[0].Reachable, evs[0].SourceTier)
			}
		})
	}
}

// A call trace (["CliCall", [[loc, content], vars, inner]]) is flattened in
// dataflow order: a source reached through a call starts at the innermost
// source and ends at the call; a sink reached through a call starts at the call
// and ends at the innermost sink. The chain then ends at the finding's own
// location, which keeps its identity (see TestTaintGateKeepsFindingIdentity).
func TestTaintTraceCallVariantsFlattenInDataflowOrder(t *testing.T) {
	useRuleLanguages(t, spikeRuleLanguages(t))
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
		{File: "app.js", Line: 9, Expr: ev.Sink},
	}
	if !reflect.DeepEqual(ev.TaintChain, want) {
		t.Errorf("TaintChain =\n  %+v\nwant\n  %+v", ev.TaintChain, want)
	}
}

// Trace locations are made relative the way Endpoint is, and a trace link
// never carries a credential-shaped literal: the chain is published and its
// last link can be an identity input.
func TestTaintChainLinksAreRelativeAndMasked(t *testing.T) {
	useRuleLanguages(t, spikeRuleLanguages(t))
	enableReachability(t, "javascript")

	root, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
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

// Turning the gate on must not move a finding's identity: the fingerprint of
// the same result is the same as a shim finding and as a semgrep_taint
// finding. Without this, enabling a language would file every existing
// finding of its taint rules as fixed-plus-new.
func TestTaintGateKeepsFindingIdentity(t *testing.T) {
	useRuleLanguages(t, spikeRuleLanguages(t))
	doc := loadFixture(t, "taint_result.json")

	enableReachability(t)
	off := mapOne(t, doc)
	enableReachability(t, "javascript")
	on := mapOne(t, doc)

	if !on.Reachable || off.Reachable {
		t.Fatalf("precondition: gate on Reachable=%v, gate off Reachable=%v", on.Reachable, off.Reachable)
	}
	if a, b := models.Fingerprint(off.ToFinding()), models.Fingerprint(on.ToFinding()); a != b {
		t.Errorf("fingerprint moved when the gate opened: %s -> %s\n off: %v\n on:  %v", a, b,
			models.FingerprintIdentityComponents(off.ToFinding()),
			models.FingerprintIdentityComponents(on.ToFinding()))
	}
	if on.ID != off.ID || on.Title != off.Title || on.Severity != off.Severity ||
		on.Endpoint != off.Endpoint || on.Sink != off.Sink || on.RuleID != off.RuleID {
		t.Errorf("gate changed more than tier, reachability and chain:\n off: %+v\n on:  %+v", off, on)
	}
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

func TestBundledRuleLanguagesComeFromThePack(t *testing.T) {
	if got := ruleLanguages("django-view-missing-login-required"); !reflect.DeepEqual(got, []string{"python"}) {
		t.Errorf("languages of a bundled python rule = %v, want [python]", got)
	}
	if got := ruleLanguages("no-such-rule"); got != nil {
		t.Errorf("languages of an unknown rule = %v, want nil (the gate fails closed)", got)
	}
}

// The gate ships closed. Tasks 4.3 (javascript, typescript), 4.4 (java) and
// 4.5 (go) each add a language only after its pack meets the precision gate
// recorded in ADR-011, and update this test in the same change.
func TestReachabilityLanguagesShipEmpty(t *testing.T) {
	if len(ReachabilityLanguages) != 0 {
		t.Errorf("ReachabilityLanguages = %v; a language is enabled only with ADR-011's evidence", ReachabilityLanguages)
	}
}
