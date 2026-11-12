package verifycmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
)

// R-010 (security3-01). The secrets scanner reads every text file, so a finding
// in a file whose extension it once skipped (.mjs/.cjs/.mts/.cts, and a
// Dockerfile or an extension-less file) is re-tested like any other: still
// present while it is committed, resolved once it is gone. Round 3 pinned these
// as "unknown, never resolved" because the scanner could not read them; the
// scanner now can, and unknown for a readable file would hide a real verdict.
func TestVerify_SecretsFindingInAFormerlyUnreadFileIsReTested(t *testing.T) {
	// Split so this test file holds no key-shaped literal.
	key := "AKIA" + "ZXCVBNMASDFGHJKL"
	body := "const awsKey = \"" + key + "\";\n"

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.js"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	found, err := secrets.Scan(context.Background(), dir)
	if err != nil || len(found) == 0 {
		t.Fatalf("control: secrets.Scan found %d findings, err=%v", len(found), err)
	}

	run := func(t *testing.T, name, content string) *Result {
		t.Helper()
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		// The baseline is what a real scan of the original file produced.
		fs, err := secrets.Scan(context.Background(), d)
		if err != nil || len(fs) == 0 {
			t.Fatalf("%s: secrets.Scan found %d findings, err=%v", name, len(fs), err)
		}
		baseline := writeBaseline(t, d, evidence.ToFindings(fs))
		if err := os.WriteFile(filepath.Join(d, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := Run(context.Background(), evidence.ToFindings(fs)[0].ID, Options{BaselinePath: baseline, CodePath: d})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return res
	}

	for _, name := range []string{"server.js", "server.mjs", "server.cjs", "server.mts", "server.cts", "Dockerfile", "credentials", "app.properties"} {
		t.Run(name+" unchanged is still present", func(t *testing.T) {
			if res := run(t, name, body); res.Status != StatusStillPresent {
				t.Fatalf("status = %s, want %s: %s", res.Status, StatusStillPresent, res.Reason)
			}
		})
		t.Run(name+" with the key removed is resolved", func(t *testing.T) {
			res := run(t, name, "const awsKey = process.env.AWS_KEY;\n")
			if res.Status != StatusResolved {
				t.Fatalf("status = %s, want %s: %s", res.Status, StatusResolved, res.Reason)
			}
			if !strings.Contains(res.Reason, "searched") || !strings.Contains(res.Reason, "text files") {
				t.Errorf("the reason must say what was searched: %s", res.Reason)
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

// The secrets scanner prunes a directory only on evidence that it holds
// installed or built output (D6'), and reads a file of any size up to its
// streaming cap. A finding under an installed-package tree is re-tested as
// unknown with the skip named; a finding under a folder that is only called
// node_modules, vendor or build, and one in a file over 1 MiB, is re-tested
// like any other. (Round 3 pinned those last three as unknown: that was the
// scanner skipping first-party code by name and a 1 MiB file by size.)
func TestVerify_SecretsFindingUnderEvidencedDependencyTreeIsNotResolved(t *testing.T) {
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

	const limit = 1 << 20
	over := line + strings.Repeat("x", limit+1-len(line))

	cases := []struct {
		name    string
		rel     string
		extra   map[string]string
		content string
		status  Status
		reason  string
	}{
		{"normal path control", "src/server.js", nil, line, StatusStillPresent, ""},
		{"a file just over 1 MiB is read", "src/big.js", nil, over, StatusStillPresent, ""},
		{"a folder only named node_modules is read", "node_modules/pkg/server.js", nil, line, StatusStillPresent, ""},
		{"a folder only named vendor is read", "vendor/pkg/server.js", nil, line, StatusStillPresent, ""},
		{"a folder only named build is read", "build/server.js", nil, line, StatusStillPresent, ""},
		{"an installed npm tree is pruned", "node_modules/pkg/server.js",
			map[string]string{"node_modules/.package-lock.json": `{"lockfileVersion": 3}`}, line, StatusUnknown, "node_modules"},
		{"a Go vendor tree is pruned", "vendor/pkg/server.js",
			map[string]string{"vendor/modules.txt": "# example.com/pkg v1.0.0\n"}, line, StatusUnknown, "vendor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			put := func(rel, content string) {
				abs := filepath.Join(dir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			put(tc.rel, tc.content)
			for rel, c := range tc.extra {
				put(rel, c)
			}
			baseline := writeBaseline(t, dir, []models.Finding{{
				ID: "SEC-KEY-2", Title: title, Source: models.SourceWhitebox,
				Category: "secrets", Endpoint: tc.rel + ":1", RuleID: found[0].RuleID,
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
