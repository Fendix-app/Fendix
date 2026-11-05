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
