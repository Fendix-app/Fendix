package verifycmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
)

// A secrets finding in a file the re-test scanner does not read must never be
// "resolved": the secrets scanner skips .mjs/.cjs/.mts/.cts, so it can never
// re-emit the finding, and its silence says nothing about the file.
func TestVerify_SecretsFindingInUnreadExtensionIsNotResolved(t *testing.T) {
	// Split so this test file holds no key-shaped literal.
	key := "AKIA" + "ZXCVBNMASDFGHJKL"
	body := "const awsKey = \"" + key + "\";\n"

	// The .js case is the control: the same content is re-emitted and kept.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.js"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	found, err := secrets.Scan(context.Background(), dir)
	if err != nil || len(found) == 0 {
		t.Fatalf("control: secrets.Scan found %d findings, err=%v", len(found), err)
	}
	title := found[0].Title

	run := func(t *testing.T, name string) *Result {
		t.Helper()
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		baseline := writeBaseline(t, d, []models.Finding{{
			ID: "SEC-KEY-1", Title: title, Source: models.SourceWhitebox,
			Category: "secrets", Endpoint: name + ":1", RuleID: "JS_HARDCODED_AWS_KEY",
		}})
		res, err := Run(context.Background(), "SEC-KEY-1", Options{BaselinePath: baseline, CodePath: d})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res
	}

	t.Run(".js is re-tested as before", func(t *testing.T) {
		res := run(t, "server.js")
		if res.Status != StatusStillPresent {
			t.Fatalf("status = %s, want %s: %s", res.Status, StatusStillPresent, res.Reason)
		}
	})
	for _, ext := range []string{".mjs", ".cjs", ".mts", ".cts"} {
		t.Run(ext+" is unknown, never resolved", func(t *testing.T) {
			res := run(t, "server"+ext)
			if res.Status != StatusUnknown {
				t.Fatalf("status = %s, want %s: %s", res.Status, StatusUnknown, res.Reason)
			}
			if !strings.Contains(res.Reason, ext) || !strings.Contains(res.Reason, "secrets scanner") {
				t.Errorf("reason should name the extension and the scanner: %s", res.Reason)
			}
		})
	}
}

// A Semgrep-tier finding is kept by its own branch even when its category is
// "secrets": another scanner never re-tests it.
func TestVerify_SemgrepFindingWithSecretsCategoryIsKept(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.mjs"), []byte("// source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline := writeBaseline(t, dir, []models.Finding{{
		ID: "SEC-SG-1", Source: models.SourceWhitebox, SourceTier: models.TierSemgrepShim,
		Category: "secrets", Endpoint: "server.mjs:1", RuleID: "js-hardcoded-secret-sink",
	}})
	res, err := Run(context.Background(), "SEC-SG-1", Options{BaselinePath: baseline, CodePath: dir})
	if err != nil {
		t.Fatal(err)
	}
	assertKeptSemgrepFinding(t, res, "js-hardcoded-secret-sink")
}

// The secrets scanner also skips a file by path (a pruned directory such as
// node_modules) and by size (over 1 MiB). A re-test that cannot read the file
// must not call the finding resolved, and must name the skip.
func TestVerify_SecretsFindingTheScannerSkipsByPathOrSizeIsNotResolved(t *testing.T) {
	key := "AKIA" + "ZXCVBNMASDFGHJKL"
	line := "const awsKey = \"" + key + "\";\n"

	control := t.TempDir()
	if err := os.WriteFile(filepath.Join(control, "server.js"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	found, err := secrets.Scan(context.Background(), control)
	if err != nil || len(found) == 0 {
		t.Fatalf("control: secrets.Scan found %d findings, err=%v", len(found), err)
	}
	title := found[0].Title

	// maxFileBytes is 1 MiB; pad a valid file to one byte over it, key first.
	const limit = 1 << 20
	over := line + strings.Repeat("x", limit+1-len(line))
	exact := line + strings.Repeat("x", limit-len(line))

	cases := []struct {
		name    string
		rel     string
		content string
		status  Status
		reason  string
	}{
		{"normal path control", "src/server.js", line, StatusStillPresent, ""},
		{"file of exactly the size limit is still read", "src/big.js", exact, StatusStillPresent, ""},
		{"under node_modules", "node_modules/pkg/server.js", line, StatusUnknown, "node_modules"},
		{"under vendor", "vendor/pkg/server.js", line, StatusUnknown, "vendor"},
		{"under build", "build/server.js", line, StatusUnknown, "build"},
		{"just over the size limit", "src/big.js", over, StatusUnknown, "larger than"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			abs := filepath.Join(dir, filepath.FromSlash(tc.rel))
			if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(abs, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			baseline := writeBaseline(t, dir, []models.Finding{{
				ID: "SEC-KEY-2", Title: title, Source: models.SourceWhitebox,
				Category: "secrets", Endpoint: tc.rel + ":1", RuleID: "JS_HARDCODED_AWS_KEY",
			}})
			res, err := Run(context.Background(), "SEC-KEY-2", Options{BaselinePath: baseline, CodePath: dir})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.Status != tc.status {
				t.Fatalf("status = %s, want %s: %s", res.Status, tc.status, res.Reason)
			}
			if tc.reason != "" && (!strings.Contains(res.Reason, tc.reason) || !strings.Contains(res.Reason, "secrets scanner")) {
				t.Errorf("reason should name the skip %q and the scanner: %s", tc.reason, res.Reason)
			}
		})
	}
}
