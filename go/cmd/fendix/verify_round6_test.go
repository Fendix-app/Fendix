package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/cli"
	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
)

// Round 6, WS-E2: C4B-21 (stale `verify --help`) and D4 = Option A at the CLI.

func verifyHelpText(t *testing.T) string {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(new(bytes.Buffer))
	root.SetArgs([]string{"verify", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("verify --help: %v", err)
	}
	return out.String()
}

// C4B-21: the help may list as supported only what verify can establish. URL,
// dependency and correlated findings never get a confident verdict (the
// backstop in verifyOne turns any resolved outside the secrets scanner into
// unknown), and under Option A no secrets finding resolves from absence, so no
// verdict exits 0 by "the finding no longer fires".
func TestVerifyHelp_C4B21_ClaimsOnlyWhatVerifyEstablishes(t *testing.T) {
	help := verifyHelpText(t)
	supported := help
	if i := strings.Index(help, "Not yet supported"); i >= 0 {
		supported = help[:i]
	}
	for _, stale := range []string{
		"URL-anchored DAST findings",
		"Dependency CVE findings",
	} {
		if strings.Contains(supported, stale) {
			t.Errorf("verify --help lists %q as a supported shape; verify never gives it more than unknown", stale)
		}
	}
	for _, stale := range []string{
		"the finding no longer fires",
		"0   resolved",
	} {
		if strings.Contains(help, stale) {
			t.Errorf("verify --help still promises %q; under D4 Option A verify never answers resolved from absence", stale)
		}
	}
	// The Short line (mirrored in docs/cli-contract.json) and the CI example
	// promise resolved too.
	if short := newVerifyCmd().Short; strings.Contains(short, "resolved") {
		t.Errorf("verify Short still promises resolved: %q", short)
	}
	if strings.Contains(help, `0) echo "resolved"`) {
		t.Error(`verify --help's CI example still has a "0) resolved" branch; under Option A verify never exits 0 for a secrets finding`)
	}
	for _, want := range []string{"still-present", "unknown"} {
		if !strings.Contains(help, want) {
			t.Errorf("verify --help does not name the %q verdict", want)
		}
	}
}

// The help text is a contract (RC-4): a golden, reviewed once and compared on
// every run. Regenerate with UPDATE_GOLDEN=1 only after reviewing the text.
func TestVerifyHelp_C4B21_Golden(t *testing.T) {
	got := verifyHelpText(t)
	golden := filepath.Join("testdata", "verify_help.golden")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("no reviewed verify --help golden (%v); write the corrected help text, review it, then run UPDATE_GOLDEN=1 go test ./cmd/fendix -run TestVerifyHelp_C4B21_Golden", err)
	}
	if string(want) != got {
		t.Fatalf("verify --help changed; review the contract and regenerate the golden:\n--- golden\n%s\n--- got\n%s", want, got)
	}
}

// D4 Option A at the process boundary: a secrets finding whose credential was
// found nowhere is unknown, which exits 2. Exit 0 ("resolved") would let a CI
// gate close the finding on absence.
func TestVerifyCLI_R6_SecretsFindingNeverExitsZero(t *testing.T) {
	const pw = "Zq8vK2" + "mP9xR4tL7w"
	code := t.TempDir()
	if err := os.MkdirAll(filepath.Join(code, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(code, "app", "settings.py")
	if err := os.WriteFile(src, []byte(`DB_PASSWORD = "`+pw+`"`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ev, err := secrets.Scan(context.Background(), code)
	if err != nil {
		t.Fatal(err)
	}
	var f *models.Finding
	for _, x := range evidence.ToFindings(ev) {
		if x.RuleID == "secrets/HARDCODED_PASSWORD" {
			x.ID = "SEC-001"
			f = &x
			break
		}
	}
	if f == nil {
		t.Fatal("fixture error: no secrets/HARDCODED_PASSWORD finding")
	}
	blob, err := json.Marshal(reporters.JSONReport{Metadata: reporters.ScanMetadata{Version: "test", Mode: "whitebox"}, Total: 1, Findings: []models.Finding{*f}})
	if err != nil {
		t.Fatal(err)
	}
	baseline := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(baseline, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	// The credential is removed and nothing replaces it.
	if err := os.WriteFile(src, []byte(`DB_PASSWORD = os.environ["DB_PASSWORD"]`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	root := newRootCmd()
	root.SetOut(new(bytes.Buffer))
	root.SetErr(new(bytes.Buffer))
	root.SetArgs([]string{"verify", "SEC-001", "--baseline", baseline, "--code", code, "--json"})
	runErr := root.Execute()
	var ee *cli.ExitError
	switch {
	case runErr == nil:
		t.Fatal("verify exited 0 (resolved) for a secrets finding on absence; D4 Option A requires exit 2 (unknown)")
	case !errors.As(runErr, &ee):
		t.Fatalf("verify failed outright: %v", runErr)
	case ee.Code != 2:
		t.Fatalf("verify exit %d, want 2 (unknown)", ee.Code)
	}
}
