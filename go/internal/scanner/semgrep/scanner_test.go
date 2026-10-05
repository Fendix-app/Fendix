package semgrep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	CheckID: "flask-missing-login-required",
	Path:    "/code/views.py",
	Start:   semgrepLineCol{Line: 10, Col: 1},
	Extra: semgrepExtra{
		Message:  "Flask route 'admin_view' is missing @login_required decorator.",
		Severity: "ERROR",
		Lines:    "@app.route('/admin')\ndef admin_view():",
		Metadata: map[string]interface{}{
			"category":        "auth",
			"cwe":             "CWE-306",
			"confidence":      "MEDIUM",
			"fendix_severity": "HIGH",
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
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity = %q; want HIGH", f.Severity)
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
