package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// writeFile writes content to tmpDir/relPath, creating parent dirs as
// needed. Test helper — t.Fatal on any I/O error.
func writeFile(t *testing.T, tmpDir, relPath, content string) string {
	t.Helper()
	full := filepath.Join(tmpDir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", relPath, err)
	}
	return full
}

// idsFound returns the set of finding IDs in fs.
func idsFound(fs []evidence.Evidence) map[string]struct{} {
	out := make(map[string]struct{}, len(fs))
	for _, f := range fs {
		out[f.ID] = struct{}{}
	}
	return out
}

// ---------------------------------------------------------------------------
// Per-pattern positive detection. One file per group keeps assertions clean.
// ---------------------------------------------------------------------------

func TestScan_DetectsAllProviderTokens(t *testing.T) {
	dir := t.TempDir()
	// Use the same shapes as python/tests/fixtures/secrets_target/provider_tokens.py
	writeFile(t, dir, "tokens.py", strings.Join([]string{
		`GITHUB_TOKEN = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`,
		`GITHUB_GHS = "ghs_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"`,
		`STRIPE_LIVE = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`,
		`SLACK_BOT = "xoxb-1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx"`,
		`SLACK_USER = "xoxp-9999999999-8888888888-AAAAAAAAAAAAAAAAAAAAAAAA"`,
		`GOOGLE_KEY = "AIzaSyD-ExampleFakeKeyForTestingPurpose"`,
		`ANTHROPIC_KEY = "sk-ant-api03-ExampleFakeAnthropicKeyForTesting123456"`,
		`OPENAI_LEGACY = "sk-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrSt"`,
		`OPENAI_PROJ = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMn"`,
		`NPM_TOKEN = "npm_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`,
	}, "\n"))

	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := idsFound(fs)
	wantAll := []string{
		"SEC-GITHUB_TOKEN", "SEC-STRIPE_LIVE_KEY", "SEC-SLACK_TOKEN",
		"SEC-GOOGLE_API_KEY", "SEC-ANTHROPIC_API_KEY", "SEC-OPENAI_API_KEY",
		"SEC-NPM_TOKEN",
	}
	for _, id := range wantAll {
		if _, ok := got[id]; !ok {
			t.Errorf("missing %s; got ids=%v", id, got)
		}
	}
}

func TestScan_DetectsGenericPatterns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.py", strings.Join([]string{
		`AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`,
		`AWS_SECRET_ACCESS_KEY = "aws_secret_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
		`api_key = "abc123-super-secret-api-key-value-here"`,
		`password = "mysupersecretpassword123"`,
		`JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`,
		`DB_URL = "postgresql://admin:secretpassword@db.example.com:5432/mydb"`,
	}, "\n"))

	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := idsFound(fs)
	for _, id := range []string{
		"SEC-AWS_ACCESS_KEY", "SEC-AWS_SECRET_KEY", "SEC-GENERIC_API_KEY",
		"SEC-HARDCODED_PASSWORD", "SEC-JWT_TOKEN", "SEC-DB_CONNECTION_STRING",
	} {
		if _, ok := got[id]; !ok {
			t.Errorf("missing %s; got ids=%v", id, got)
		}
	}
}

// TestScan_HardcodedSecretConfig exercises HARDCODED_SECRET_CONFIG —
// the subscript/attribute-style and compound-suffix variants that the
// bare HARDCODED_PASSWORD regex misses, surfaced by the May 2026
// real-world vs bandit benchmark on we45/Vulnerable-Flask-App.
func TestScan_HardcodedSecretConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "app.py", strings.Join([]string{
		// subscript style with compound suffix — most common in Flask config
		`app.config['SECRET_KEY_HMAC'] = 'secret'`,
		`app.config["JWT_SECRET_KEY"] = "rotate-me"`,
		// attribute style
		`app.secret_key = 'F12Zr47jyXR_XatHjmMLwfKT'`,
		// bare assignment with ≥4-char value (would be too short for GENERIC_API_KEY's 20-char floor)
		`SESSION_SECRET = "sess-x"`,
	}, "\n"))

	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// Expect at least one HARDCODED_SECRET_CONFIG match per line.
	// We don't care that orchestrator-side dedup later collapses them
	// — at the scanner layer they should all surface so AffectedEndpoints
	// can list every flagged line.
	want := []int{1, 2, 3, 4}
	got := map[int]bool{}
	for _, f := range fs {
		if f.ID != "SEC-HARDCODED_SECRET_CONFIG" {
			continue
		}
		// Endpoint format: "app.py:N"
		var line int
		_, err := fmt.Sscanf(f.Endpoint, "app.py:%d", &line)
		if err != nil {
			t.Errorf("parse endpoint %q: %v", f.Endpoint, err)
			continue
		}
		got[line] = true
	}
	for _, ln := range want {
		if !got[ln] {
			t.Errorf("missing HARDCODED_SECRET_CONFIG on app.py:%d; got %v", ln, got)
		}
	}
}

// TestScan_HardcodedSecretConfig_NoFalsePositives confirms the regex
// doesn't fire on plausible non-credential code shapes.
func TestScan_HardcodedSecretConfig_NoFalsePositives(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "ok.py", strings.Join([]string{
		// keyword appears in a docstring or comment
		`# Set up the secret_key field on the user model`,
		// keyword appears as a return value, not a definition
		`return "secret_key not found"`,
		// function declaration with secret-like name
		`def validate_secret_key(key, salt):`,
		// dict literal — keyword inside the dict but no assignment line
		`schema = {"secret_key": str, "other": int}`,
		// keyword in import
		`from mylib import secret_key`,
	}, "\n"))

	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range fs {
		if f.ID == "SEC-HARDCODED_SECRET_CONFIG" {
			t.Errorf("unexpected FP: %s @ %s :: %s", f.ID, f.Endpoint, f.Evidence)
		}
	}
}

// TestScan_AWSSecretShortPrefix exercises the short-prefix variants of
// the AWS secret-key pattern, surfaced as a real-world miss by the Track 4
// heavy-eval: customer code often writes `aws_secret = "..."` without the
// trailing `_access_key` / `_key`. Regex relaxed in lockstep.
func TestScan_AWSSecretShortPrefix(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"canonical-long", `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`},
		{"medium-_key", `aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`},
		{"short-aws-secret", `aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`},
		{"upper-AWS-Secret", `AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "app.py", c.line+"\n")
			fs, err := Scan(context.Background(), dir)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if _, ok := idsFound(fs)["SEC-AWS_SECRET_KEY"]; !ok {
				t.Errorf("expected SEC-AWS_SECRET_KEY for %q; got %v", c.line, idsFound(fs))
			}
		})
	}
}

func TestScan_PrivateKeyDetected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "cert.js", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n")
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, ok := idsFound(fs)["SEC-PRIVATE_KEY"]; !ok {
		t.Errorf("expected SEC-PRIVATE_KEY; got %v", idsFound(fs))
	}
}

func TestScan_GCPServiceAccountDetected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "sa.json", `{"type": "service_account", "project_id": "x"}`)
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, ok := idsFound(fs)["SEC-GCP_SERVICE_ACCOUNT"]; !ok {
		t.Errorf("expected SEC-GCP_SERVICE_ACCOUNT; got %v", idsFound(fs))
	}
}

// ---------------------------------------------------------------------------
// .env handling (TASK-085 regression).
// ---------------------------------------------------------------------------

func TestScan_EnvUnquotedSecretDetected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".env", strings.Join([]string{
		`DB_PASSWORD=production-password-123`,
		`SECRET_KEY=this-should-not-be-in-git`,
		`# This comment line should not match`,
		`NORMAL_VAR=harmless_string`,
	}, "\n"))

	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var envHits []evidence.Evidence
	for _, f := range fs {
		if f.ID == "SEC-ENV_SECRET" && strings.Contains(f.Endpoint, ".env") {
			envHits = append(envHits, f)
		}
	}
	if len(envHits) < 2 {
		t.Errorf("expected ≥2 SEC-ENV_SECRET on .env, got %d (all: %v)", len(envHits), fs)
	}
}

func TestScan_EnvVariantNames(t *testing.T) {
	cases := []string{".env", ".env.local", ".env.production", "app.env"}
	for _, name := range cases {
		name := name
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, name, "API_TOKEN=tok_unquoted_value_in_env_file_here\n")
			fs, err := Scan(context.Background(), dir)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			found := false
			for _, f := range fs {
				if f.ID == "SEC-ENV_SECRET" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: expected SEC-ENV_SECRET; got %v", name, idsFound(fs))
			}
		})
	}
}

func TestScan_EnvPatternNotAppliedOutsideEnvFiles(t *testing.T) {
	dir := t.TempDir()
	// Same content as .env, but in a .py file → ENV_SECRET must not fire.
	writeFile(t, dir, "config.py", "DB_PASSWORD=production-password-123\n")
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, ok := idsFound(fs)["SEC-ENV_SECRET"]; ok {
		t.Errorf("SEC-ENV_SECRET fired outside .env file: %v", fs)
	}
}

// ---------------------------------------------------------------------------
// Boundary validation — replaces Python (?<!...)/(?!...) lookarounds.
// ---------------------------------------------------------------------------

func TestScan_GithubTokenRejectsAlnumNeighbour(t *testing.T) {
	dir := t.TempDir()
	// Adjacent alnum char on the right → Python's (?![A-Za-z0-9]) would
	// reject this; Go must reject too via boundaryOK.
	writeFile(t, dir, "code.py", `token = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAX"`)
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, ok := idsFound(fs)["SEC-GITHUB_TOKEN"]; ok {
		t.Errorf("SEC-GITHUB_TOKEN fired despite trailing alnum (longer token)")
	}
}

func TestScan_AWSKeyRejectsAlnumNeighbour(t *testing.T) {
	dir := t.TempDir()
	// 17 uppercase chars after AKIA would match without the right boundary;
	// Python's (?![A-Z0-9]) blocks this.
	writeFile(t, dir, "code.py", `k = "AKIAIOSFODNN7EXAMPLEX"`)
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, ok := idsFound(fs)["SEC-AWS_ACCESS_KEY"]; ok {
		t.Errorf("SEC-AWS_ACCESS_KEY fired despite trailing alnum")
	}
}

func TestScan_OpenAIDoesNotMatchAnthropicKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "code.py", `ANT = "sk-ant-api03-ExampleFakeAnthropicKeyForTesting123456"`)
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// OpenAI regex body `sk-(?:proj-|svcacct-)?[A-Za-z0-9]{32,}` forbids
	// `-` so it can never consume the Anthropic `-ant-` prefix.
	var anthEPs, openEPs []string
	for _, f := range fs {
		switch f.ID {
		case "SEC-ANTHROPIC_API_KEY":
			anthEPs = append(anthEPs, f.Endpoint)
		case "SEC-OPENAI_API_KEY":
			openEPs = append(openEPs, f.Endpoint)
		}
	}
	if len(anthEPs) == 0 {
		t.Fatal("expected anthropic key to match its own pattern")
	}
	for _, aep := range anthEPs {
		for _, oep := range openEPs {
			if aep == oep {
				t.Errorf("OpenAI pattern incorrectly matched at anthropic endpoint %s", aep)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Finding structure parity with Python.
// ---------------------------------------------------------------------------

func TestScan_FindingShape(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.py", `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`)
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := fs[0]
	if f.Source != models.SourceWhitebox {
		t.Errorf("source = %q; want whitebox", f.Source)
	}
	if f.Category != "secrets" {
		t.Errorf("category = %q; want secrets", f.Category)
	}
	if f.Confidence != models.ConfidenceHigh {
		t.Errorf("confidence = %q; want HIGH", f.Confidence)
	}
	if !strings.HasPrefix(f.ID, "SEC-") {
		t.Errorf("id = %q; want SEC- prefix", f.ID)
	}
	if !strings.Contains(f.Endpoint, ":") {
		t.Errorf("endpoint missing :line — %q", f.Endpoint)
	}
	if f.Line == nil || *f.Line != f.Endpoint {
		t.Errorf("line pointer not set or mismatched endpoint; line=%v endpoint=%q", f.Line, f.Endpoint)
	}
	if len(f.References) == 0 || !strings.HasPrefix(f.References[0], "CWE-") {
		t.Errorf("references missing CWE: %v", f.References)
	}
	if len(f.Evidence) > 150 {
		t.Errorf("evidence too long (%d chars): %q", len(f.Evidence), f.Evidence)
	}
}

// TestScan_EvidenceRedactsRawSecret asserts that NO 6-char window of the
// credential survives into evidence, not merely that the whole value is
// absent. The weaker form this replaced passed while evidence carried
// `ghp_AAAAAAAAAAAAAA...` — the first 20 RAW characters — because the whole
// key was absent and the leaked prefix ended in "...".
func TestScan_EvidenceRedactsRawSecret(t *testing.T) {
	dir := t.TempDir()
	const rawKey = "ghp_Zq7Wm3Xk9Rb2Nv5Tc8Hd1Jf4Ls6Py0Ag3BnK"
	writeFile(t, dir, "tok.py", `GITHUB = "`+rawKey+`"`)
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range fs {
		if f.ID == "SEC-GITHUB_TOKEN" {
			assertNoLeak(t, "SEC-GITHUB_TOKEN evidence", f.Evidence, rawKey, 6)
			if !strings.Contains(f.Evidence, "[REDACTED len=40 sha256:") {
				t.Errorf("evidence missing redaction marker: %q", f.Evidence)
			}
			// Retained signal: the variable name still tells a triager which
			// assignment to look at.
			if !strings.Contains(f.Evidence, "GITHUB") {
				t.Errorf("evidence lost the assignment context: %q", f.Evidence)
			}
			return
		}
	}
	t.Fatal("SEC-GITHUB_TOKEN not emitted")
}

// ---------------------------------------------------------------------------
// Walker behaviour: skip dirs, size cap, minified-JS, unsupported exts.
// ---------------------------------------------------------------------------

func TestScan_SkipsGitDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".git/config", `password = "hardcoded_secret_12345"`)
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("found %d findings inside .git: %v", len(fs), fs)
	}
}

func TestScan_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "node_modules/pkg/index.js", `const key = "AKIAIOSFODNN7EXAMPLE";`)
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("found %d findings inside node_modules: %v", len(fs), fs)
	}
}

func TestScan_SkipsLargeFile(t *testing.T) {
	dir := t.TempDir()
	full := writeFile(t, dir, "big.py", "x = 1\n")
	// Append until we cross 1MB plus a buried secret on the final line.
	f, err := os.OpenFile(full, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	junk := strings.Repeat("y = 1\n", 200_000) // ~1.2 MB
	if _, err := f.WriteString(junk); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := f.WriteString(`AWS_KEY = "AKIAIOSFODNN7EXAMPLE"` + "\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("oversized file not skipped: %v", fs)
	}
}

func TestScan_SkipsMinifiedJSLine(t *testing.T) {
	dir := t.TempDir()
	// One 600-char line with the secret embedded — Python skips, Go must too.
	line := strings.Repeat("a", 580) + ` "AKIAIOSFODNN7EXAMPLE";`
	writeFile(t, dir, "bundle.min.js", line)
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("minified line not skipped: %v", fs)
	}
}

func TestScan_SkipsUnsupportedExtension(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "doc.md", `password = "hardcoded_secret_12345"`)
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("unsupported ext scanned: %v", fs)
	}
}

func TestScan_CleanFileProducesNothing(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "clean.py", strings.Join([]string{
		`import os`,
		`API_KEY = os.environ["API_KEY"]`,
		`DB_URL = os.environ["DATABASE_URL"]`,
		`SECRET = os.getenv("SECRET_KEY", "")`,
	}, "\n"))
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("expected 0 findings on clean file, got %d: %v", len(fs), fs)
	}
}

// ---------------------------------------------------------------------------
// Error / edge-case handling.
// ---------------------------------------------------------------------------

func TestScan_NonexistentPath(t *testing.T) {
	_, err := Scan(context.Background(), "/nonexistent/path/that/does/not/exist")
	if !errors.Is(err, ErrCodePathMissing) {
		t.Errorf("err = %v; want ErrCodePathMissing", err)
	}
}

func TestScan_EmptyPath(t *testing.T) {
	_, err := Scan(context.Background(), "")
	if !errors.Is(err, ErrCodePathMissing) {
		t.Errorf("err = %v; want ErrCodePathMissing", err)
	}
}

func TestScan_FileNotDirectory(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, dir, "x.py", "")
	_, err := Scan(context.Background(), f)
	if err == nil {
		t.Errorf("expected error when path is a file, got nil")
	}
}

func TestScan_ContextCanceledStopsWalk(t *testing.T) {
	dir := t.TempDir()
	// Spray files so the walk would visit several entries.
	for i := 0; i < 50; i++ {
		writeFile(t, dir, filepath.Join("sub", "f"+string(rune('a'+i%26))+".py"),
			`x = "AKIAIOSFODNN7EXAMPLE"`)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Scan(ctx, dir)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled", err)
	}
}

// ---------------------------------------------------------------------------
// Deterministic endpoint formatting (no \\ on macOS/Linux, no os.sep leak).
// ---------------------------------------------------------------------------

func TestScan_EndpointUsesForwardSlashes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, filepath.Join("sub", "deep", "code.py"),
		`AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`)
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range fs {
		if strings.ContainsRune(f.Endpoint, '\\') {
			t.Errorf("endpoint contains backslash: %q", f.Endpoint)
		}
	}
}

// ---------------------------------------------------------------------------
// Helper unit tests.
// ---------------------------------------------------------------------------

// TestRedactionMarkerIsDeterministicAndNonReversible replaces the deleted
// TestTruncateSecret, which asserted the exact prefix leak this fix removes
// (truncateSecret(40×"A") == 20×"A"+"...").
func TestRedactionMarkerIsDeterministicAndNonReversible(t *testing.T) {
	const value = "ghp_Zq7Wm3Xk9Rb2Nv5Tc8Hd1Jf4Ls6Py0Ag3BnK"
	shape := regexp.MustCompile(`^\[REDACTED len=\d+ sha256:[0-9a-f]{8}\.\.\.\]$`)

	got := redactionMarker(value)
	if got != redactionMarker(value) {
		t.Errorf("redactionMarker is not deterministic: %q vs %q", got, redactionMarker(value))
	}
	if !shape.MatchString(got) {
		t.Errorf("marker %q does not match %s", got, shape)
	}
	if want := fmt.Sprintf("len=%d", len(value)); !strings.Contains(got, want) {
		t.Errorf("marker %q does not carry %q", got, want)
	}
	if d := redactionMarker(value + "x"); d == got {
		t.Errorf("distinct values produced the same marker: %q", got)
	}
	for _, sub := range substrings(value, 6) {
		if strings.Contains(got, sub) {
			t.Errorf("marker %q leaks %q from the value", got, sub)
		}
	}
}

// substrings returns every substring of s of exactly length n. Used by the
// leak assertions: "the raw value is absent" is far too weak a check, because
// half a token is still a leak.
func substrings(s string, n int) []string {
	if len(s) < n {
		return nil
	}
	out := make([]string, 0, len(s)-n+1)
	for i := 0; i+n <= len(s); i++ {
		out = append(out, s[i:i+n])
	}
	return out
}

// assertNoLeak fails when any n-char window of secret appears in text.
func assertNoLeak(t *testing.T, what, text, secret string, n int) {
	t.Helper()
	for _, sub := range substrings(secret, n) {
		if strings.Contains(text, sub) {
			t.Errorf("%s leaks %d-char fragment %q of the secret: %q", what, n, sub, text)
			return
		}
	}
}

// TestEvidenceRedactsEverySecretOnTheLine is the multi-credential case: the
// evidence window is a slice of the SOURCE LINE, so redacting only the
// emitting pattern's own match ships the neighbour in the clear.
func TestEvidenceRedactsEverySecretOnTheLine(t *testing.T) {
	dir := t.TempDir()
	const (
		gh  = "ghp_Zq7Wm3Xk9Rb2Nv5Tc8Hd1Jf4Ls6Py0Ag3BnK"
		aws = "AKIA5TQ3PJ7WVNE2HB4D"
	)
	writeFile(t, dir, "both.py", `CREDS = {"gh": "`+gh+`", "aws": "`+aws+`"}`)

	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	ids := idsFound(fs)
	for _, want := range []string{"SEC-GITHUB_TOKEN", "SEC-AWS_ACCESS_KEY"} {
		if _, ok := ids[want]; !ok {
			t.Fatalf("expected %s; got %v", want, ids)
		}
	}
	for _, f := range fs {
		assertNoLeak(t, f.ID+" evidence", f.Evidence, gh, 6)
		assertNoLeak(t, f.ID+" evidence", f.Evidence, aws, 6)
	}
}

// TestPrivateKeyBodyOnTheSameLineIsRedacted reproduces the shape of a Google
// service-account JSON file, where the whole PEM sits on ONE line and the
// pattern matches only the armour header — so the key body lands inside the
// evidence window unless the rest of the line is treated as key material.
func TestPrivateKeyBodyOnTheSameLineIsRedacted(t *testing.T) {
	const body = "MIIBOgIBAAJBAK7X9v2QhT8mN3Wc"
	dir := t.TempDir()
	writeFile(t, dir, "sa.json", `{"private_key": "-----BEGIN RSA PRIVATE KEY-----`+body+`"}`)

	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var pem *evidence.Evidence
	for i := range fs {
		if fs[i].ID == "SEC-PRIVATE_KEY" {
			pem = &fs[i]
		}
	}
	if pem == nil {
		t.Fatalf("expected SEC-PRIVATE_KEY; got %v", idsFound(fs))
	}
	// Retained signal: the armour header says WHAT was found and is not
	// itself a secret.
	if !strings.Contains(pem.Evidence, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("evidence lost the PEM header (retained signal): %q", pem.Evidence)
	}
	assertNoLeak(t, "SEC-PRIVATE_KEY evidence", pem.Evidence, body, 6)
}

// TestPrivateKeyHeaderAloneKeepsEvidenceUnmarked is the complementary case:
// the ordinary multi-line PEM file, where the rest-of-line span is empty and
// evidence must stay exactly as it was before redaction existed.
func TestPrivateKeyHeaderAloneKeepsEvidenceUnmarked(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "cert.js", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n")
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range fs {
		if f.ID != "SEC-PRIVATE_KEY" {
			continue
		}
		if f.Evidence != "-----BEGIN RSA PRIVATE KEY-----" {
			t.Errorf("evidence = %q; want the bare header with no marker", f.Evidence)
		}
		return
	}
	t.Fatalf("expected SEC-PRIVATE_KEY; got %v", idsFound(fs))
}

// TestDBConnectionStringRedactsOnlyThePassword pins the deliberate scoping of
// DB_CONNECTION_STRING's capture group: scheme/user/host stay readable for
// triage, the password does not.
func TestDBConnectionStringRedactsOnlyThePassword(t *testing.T) {
	const pw = "Pr0d9Db8Pw7Qz6Ln"
	dir := t.TempDir()
	writeFile(t, dir, "cfg.py", `DB = "postgresql://svc:`+pw+`@db.internal:5432/app"`)

	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range fs {
		if f.ID != "SEC-DB_CONNECTION_STRING" {
			continue
		}
		assertNoLeak(t, "SEC-DB_CONNECTION_STRING evidence", f.Evidence, pw, 6)
		for _, keep := range []string{"postgresql://", "svc", "db.internal"} {
			if !strings.Contains(f.Evidence, keep) {
				t.Errorf("evidence lost retained signal %q: %q", keep, f.Evidence)
			}
		}
		return
	}
	t.Fatalf("expected SEC-DB_CONNECTION_STRING; got %v", idsFound(fs))
}

func TestIsEnvFile(t *testing.T) {
	cases := map[string]bool{
		".env":            true,
		".env.local":      true,
		".env.production": true,
		"app.env":         true,
		"env":             false,
		"server.env.bak":  false,
		"config.py":       false,
		".envfilelike":    false, // doesn't begin with .env.
	}
	for name, want := range cases {
		if got := isEnvFile(name); got != want {
			t.Errorf("isEnvFile(%q) = %v; want %v", name, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Multi-file walk: verify endpoints are sorted by file path post-scan
// (callers typically dedupe/sort, but a stable in-file order eases debug).
// ---------------------------------------------------------------------------

func TestScan_MultiFileEmitsPerEndpoint(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.py", `KEY = "AKIAIOSFODNN7EXAMPLE"`)
	writeFile(t, dir, "b.py", `KEY = "AKIAIOSFODNN7EXAMPLE"`)
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var awsHits []string
	for _, f := range fs {
		if f.ID == "SEC-AWS_ACCESS_KEY" {
			awsHits = append(awsHits, f.Endpoint)
		}
	}
	if len(awsHits) != 2 {
		t.Fatalf("expected 2 SEC-AWS_ACCESS_KEY (one per file), got %d: %v", len(awsHits), awsHits)
	}
	sort.Strings(awsHits)
	if !strings.HasPrefix(awsHits[0], "a.py:") || !strings.HasPrefix(awsHits[1], "b.py:") {
		t.Errorf("expected endpoints a.py:N and b.py:N, got %v", awsHits)
	}
}

// ---------------------------------------------------------------------------
// B1/B2: references-not-credentials (ARN / Secrets-Manager lookup key) and
// unambiguous placeholders are filtered out via isReferenceOrPlaceholder.
// ---------------------------------------------------------------------------

func TestScan_SuppressesSecretsManagerReferences(t *testing.T) {
	dir := t.TempDir()
	// These are the lookup-key / ARN cases that previously had to be
	// hand-suppressed per file:line in .fendix-ignore (B1). The literal in
	// source is the *address* of the secret, not its value.
	writeFile(t, dir, "config.py", strings.Join([]string{
		`secret_name = "rds!db-403f5acc-6752-4edd-a4a9-339a8395f134"`,
		`secret_arn = "arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/db-AbCdEf"`,
		`gcp_secret = "projects/my-proj/secrets/db-password/versions/latest"`,
	}, "\n")+"\n")

	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings (all are secret references, not values), got %d: %+v", len(fs), fs)
	}
}

func TestScan_SuppressesUnambiguousPlaceholders(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.py", strings.Join([]string{
		`api_key = "YOUR_API_KEY_HERE"`,
		`password = "changeme"`,
		`token = "<your-token>"`,
		`secret_key = "${VAULT_SECRET}"`,
	}, "\n")+"\n")

	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("expected 0 findings (all unambiguous placeholders), got %d: %+v", len(fs), fs)
	}
}

func TestScan_DoesNotOverSuppressRealSecrets(t *testing.T) {
	dir := t.TempDir()
	// Guard against B2 over-reach: AWS's documented example keys and values
	// that merely CONTAIN "example" must still be detected — "EXAMPLE" shows
	// up inside real leaked keys, so suppressing on the substring would be a
	// false negative.
	writeFile(t, dir, "config.py", `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`+"\n")

	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, ok := idsFound(fs)["SEC-AWS_ACCESS_KEY"]; !ok {
		t.Fatalf("AWS example key must still be detected (not over-suppressed); got %+v", fs)
	}
}

// TestScanWithAllowlist_FastPathParity is the B3/S8 safety net: the diff-aware
// fast path (scan only allowlisted files) must produce the SAME findings as the
// full walk for those files — and must still prune skipDirs (a committed
// vendor/ file the walk never reaches stays unscanned).
func TestScanWithAllowlist_FastPathParity(t *testing.T) {
	dir := t.TempDir()
	secret := `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`
	changed := writeFile(t, dir, "app.py", secret)
	writeFile(t, dir, "vendor/dep.py", secret) // committed vendor → must be skipped
	writeFile(t, dir, "untouched.py", secret)  // not in allowlist → must be ignored

	allow := gitdiff.NewAllowlist(dir, []string{changed, filepath.Join(dir, "vendor/dep.py")})
	fast, err := ScanWithAllowlist(context.Background(), dir, allow)
	if err != nil {
		t.Fatalf("fast path: %v", err)
	}

	// Every finding must be from app.py — vendor pruned, untouched out of scope.
	for _, f := range fast {
		if !strings.Contains(f.Endpoint, "app.py") {
			t.Errorf("fast path scanned an out-of-scope/pruned file: %s", f.Endpoint)
		}
	}
	if len(fast) == 0 {
		t.Fatal("fast path found nothing; expected the app.py secret")
	}

	// Parity: a full walk filtered to app.py yields the same finding IDs.
	full, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("full scan: %v", err)
	}
	fullApp := map[string]struct{}{}
	for _, f := range full {
		if strings.Contains(f.Endpoint, "app.py") {
			fullApp[f.ID] = struct{}{}
		}
	}
	for id := range idsFound(fast) {
		if _, ok := fullApp[id]; !ok {
			t.Errorf("fast path produced %s that the walk did not", id)
		}
	}
	if len(fullApp) != len(idsFound(fast)) {
		t.Errorf("finding-ID count diverged: fast=%d walk(app.py)=%d", len(idsFound(fast)), len(fullApp))
	}
}

// TestScanWithAllowlist_RefusesSymlinkedParent is the v0.25 M2 fix: the
// diff-aware fast path must not read a file reached through a symlinked parent
// directory — the full walk never descends one, and it could escape the repo.
func TestScanWithAllowlist_RefusesSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, outside, "creds.env", `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"`)
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	// Allowlist a file *through* the symlinked dir (a forged/abnormal entry).
	allow := gitdiff.NewAllowlist(root, []string{filepath.Join(root, "link", "creds.env")})
	got, err := ScanWithAllowlist(context.Background(), root, allow)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("fast path read a file outside the repo via a symlinked parent: %d findings", len(got))
	}
}

// A JWT split across lines by implicit string concatenation was invisible to
// the three-segment pattern, because this scanner is line-based and no single
// line holds all three segments. The accuracy corpus contains exactly this
// shape and scored it as DETECTED only because a duplicate emission from
// another pattern fell inside the scorer's tolerance window — the miss was
// masked, not absent.
func TestScanDetectsMultiLineJWT(t *testing.T) {
	dir := t.TempDir()
	src := "JWT_TOKEN = (\n" +
		"    \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\"\n" +
		"    \"eyJzdWIiOiIxMjM0NTY3ODkwIn0.\"\n" +
		"    \"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\"\n" +
		")\n"
	if err := os.WriteFile(filepath.Join(dir, "cfg.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	var jwt int
	for _, f := range found {
		if strings.Contains(f.Title, "JWT") {
			jwt++
		}
	}
	if jwt == 0 {
		t.Error("multi-line (implicitly concatenated) JWT not detected")
	}
}

// The header-anchored pattern must not fire on ordinary base64 or on env-var
// reads — `eyJhbGciOi` is the base64 of `{\"alg\":\"`, which is what keeps it
// specific.
func TestScanMultiLineJWTPatternDoesNotOverfire(t *testing.T) {
	dir := t.TempDir()
	src := "import os\n" +
		"SAFE = os.environ.get(\"API_KEY\")\n" +
		"BLOB = \"eyJvdGhlciI6ICJqc29uIn0=\"\n" + // base64 JSON, not a JOSE header
		"TEXT = \"eyes on the prize\"\n"
	if err := os.WriteFile(filepath.Join(dir, "safe.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range found {
		if strings.Contains(f.Title, "JWT") {
			t.Errorf("JWT pattern over-fired on %q: %s", f.Endpoint, f.Evidence)
		}
	}
}

// TestScan_PlaceholderIsAnnotationNotSuppression is the Rule 3 gate on the
// placeholder classifier. A fixture-shaped credential must still be REPORTED —
// same ID, same severity, same endpoint, non-empty evidence — and merely
// carry the annotation the confidence scorer reads. It fails loudly if anyone
// "optimises" the classifier into isReferenceOrPlaceholder, which drops
// matches.
func TestScan_PlaceholderIsAnnotationNotSuppression(t *testing.T) {
	const value = "08bf2e526a1f4c8db3b91e7d0f2a5c6e"
	cases := []struct {
		name            string
		line            string
		wantPlaceholder bool
	}{
		{"fixture-named key", `FAKE_API_KEY = "` + value + `"`, true},
		{"same value, plain key", `API_KEY = "` + value + `"`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "cfg.py", c.line+"\n")
			fs, err := Scan(context.Background(), dir)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			for _, f := range fs {
				if f.ID != "SEC-GENERIC_API_KEY" {
					continue
				}
				if f.Severity != models.SeverityHigh {
					t.Errorf("severity = %q; want HIGH — placeholder must not change it", f.Severity)
				}
				if f.Evidence == "" {
					t.Error("evidence is empty — placeholder must not strip it")
				}
				if !strings.HasSuffix(f.Endpoint, "cfg.py:1") {
					t.Errorf("endpoint = %q; want cfg.py:1", f.Endpoint)
				}
				if f.Placeholder != c.wantPlaceholder {
					t.Errorf("Placeholder = %v; want %v (line %q)", f.Placeholder, c.wantPlaceholder, c.line)
				}
				return
			}
			t.Fatalf("SEC-GENERIC_API_KEY was SUPPRESSED, not de-escalated; got %v", idsFound(fs))
		})
	}
}

// --- provider anchoring ---------------------------------------------------
//
// ProviderAnchored records whether a match was anchored on the credential's OWN
// signature or merely on a surrounding assignment shape. It carries no score of
// its own; it bounds how far decision.fixtureCorroborated may de-escalate a
// finding, so getting it wrong either suppresses a live key or restores the
// noise the de-escalation exists to remove.

func findingFor(t *testing.T, evs []evidence.Evidence, id string) evidence.Evidence {
	t.Helper()
	for _, e := range evs {
		if strings.Contains(e.Title, id) || strings.Contains(e.RuleID, id) {
			return e
		}
	}
	var titles []string
	for _, e := range evs {
		titles = append(titles, e.Title)
	}
	t.Fatalf("no finding matching %q; got %v", id, titles)
	return evidence.Evidence{}
}

// A live provider key under a misleading TEST_ name must stay anchored, so the
// name alone can never push it below WARN.
func TestScan_ProviderKeyUnderTestNameStaysAnchored(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, tmp, "tests/test_billing.py",
		"TEST_STRIPE_KEY = \"sk_live_abcdefghijklmnopqrstuvwxyz\"\n")

	found, err := Scan(context.Background(), tmp)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	f := findingFor(t, found, "Stripe")
	if !f.ProviderAnchored {
		t.Error("a sk_live_ match must be provider-anchored regardless of the variable name")
	}
	// The fixture heuristics still fire on the TEST_ prefix — that is the whole
	// point of the veto: both are true, and anchoring wins.
	if !f.Placeholder {
		t.Error("expected the TEST_ name prefix to still register as fixture-shaped")
	}
}

// A generic assignment-shaped match is NOT anchored: nothing about the value
// carries a provider's signature, which is precisely the case the fixture
// de-escalation is for.
func TestScan_GenericFixtureKeyIsNotProviderAnchored(t *testing.T) {
	tmp := t.TempDir()
	writeFile(t, tmp, "tests/test_client.py",
		"FAKE_API_KEY = \"abcdef0123456789abcdef0123456789\"\n")

	found, err := Scan(context.Background(), tmp)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	f := findingFor(t, found, "API key")
	if f.ProviderAnchored {
		t.Error("a generic assignment-shaped match must not claim a provider signature")
	}
	if !f.Placeholder {
		t.Error("FAKE_ prefix must register as fixture-shaped")
	}
}

// Every provider rule anchors; every generic rule does not. Locked as a table
// so a new rule cannot silently land on the wrong side.
func TestProviderAnchoredPartitionsTheRuleSet(t *testing.T) {
	anchored := []string{
		"AWS_ACCESS_KEY", "AWS_SECRET_KEY", "PRIVATE_KEY", "GITHUB_TOKEN",
		"STRIPE_LIVE_KEY", "SLACK_TOKEN", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY",
		"OPENAI_API_KEY", "NPM_TOKEN", "GCP_SERVICE_ACCOUNT",
	}
	generic := []string{
		"GENERIC_API_KEY", "HARDCODED_PASSWORD", "HARDCODED_SECRET_CONFIG",
		"JWT_TOKEN", "JWT_TOKEN_HEADER", "DB_CONNECTION_STRING", "ENV_SECRET",
	}
	for _, id := range anchored {
		if !isProviderAnchored(id) {
			t.Errorf("%s matches a provider's own token signature and must be anchored", id)
		}
	}
	for _, id := range generic {
		if isProviderAnchored(id) {
			t.Errorf("%s matches an assignment shape, not a provider signature; anchoring it "+
				"would block the fixture de-escalation for the rules that need it most", id)
		}
	}
	// The two lists must together account for BOTH registries — the general
	// `patterns` set and the .env-only `envPatterns` set — or a new rule could
	// be added and silently default to un-anchored, which is the failure mode
	// that would quietly let a new provider token be de-escalated by its name.
	total := len(patterns) + len(envPatterns)
	if got := len(anchored) + len(generic); got != total {
		t.Errorf("rule partition covers %d rules but the registries hold %d — a new pattern "+
			"needs an explicit side", got, total)
	}
}
