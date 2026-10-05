// Package secrets_test holds the end-to-end redaction canary. It lives in the
// external test package on purpose: it needs internal/reporters, and putting
// it here makes the dependency direction explicit (reporters does not import
// secrets, so there is no cycle) rather than smuggling a renderer into the
// package under test.
package secrets_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
)

// TestNoSecretSubstringReachesAnyReport is THE canary for capture-time
// redaction.
//
// Redaction is only worth anything if it holds all the way to the artifacts a
// human (or a Jira ticket, or a GitHub PR comment) actually reads. So this
// drives the real scanner over a real fixture file, projects the evidence the
// way the orchestrator does, renders JSON + SARIF + HTML, and asserts that no
// SIX-character window of any credential appears in any of them. Six, not the
// whole value: half a leaked token is still a leak, and the assertion that
// caught nothing for a year was "the full key is absent".
//
// Every canary value is alphanumeric-and-dash only, so HTML entity escaping
// cannot mask a leak by rewriting the bytes we search for.
func TestNoSecretSubstringReachesAnyReport(t *testing.T) {
	// canaries maps a credential to the portion that must never appear. For
	// the DB URL and the PEM the canary is scoped to the credential half:
	// `postgresql://` and `-----BEGIN RSA PRIVATE KEY-----` are RETAINED
	// signal, and a whole-string canary would fail on exactly the text the
	// design deliberately keeps.
	canaries := []string{
		"ghp_Zq7Wm3Xk9Rb2Nv5Tc8Hd1Jf4Ls6Py0Ag3BnK",
		"AKIA5TQ3PJ7WVNE2HB4D",
		"sk-ant-api03-9Qv2Lm7Tx4Rb8Nc1Kd6Fh3Jz5Wp0Ys2Ug7",
		"Pr0d9Db8Pw7Qz6Ln",             // the password inside the DB URL
		"MIIBOgIBAAJBAK7X9v2QhT8mN3Wc", // the PEM body, not the armour header
	}

	dir := t.TempDir()
	fixture := strings.Join([]string{
		`GITHUB_TOKEN = "ghp_Zq7Wm3Xk9Rb2Nv5Tc8Hd1Jf4Ls6Py0Ag3BnK"`,
		`AWS_ACCESS_KEY_ID = "AKIA5TQ3PJ7WVNE2HB4D"`,
		`ANTHROPIC = "sk-ant-api03-9Qv2Lm7Tx4Rb8Nc1Kd6Fh3Jz5Wp0Ys2Ug7"`,
		`DB = "postgresql://svc:Pr0d9Db8Pw7Qz6Ln@db.internal:5432/app"`,
		`PEM = "-----BEGIN RSA PRIVATE KEY-----MIIBOgIBAAJBAK7X9v2QhT8mN3Wc"`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "leaky.py"), []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}

	evs, err := secrets.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// The canary must never pass vacuously by detecting nothing: if the
	// scanner stopped firing, every "absent from the report" assertion below
	// would trivially hold.
	got := map[string]bool{}
	for _, e := range evs {
		got[e.ID] = true
	}
	for _, want := range []string{
		"SEC-GITHUB_TOKEN",
		"SEC-AWS_ACCESS_KEY",
		"SEC-ANTHROPIC_API_KEY",
		"SEC-DB_CONNECTION_STRING",
		"SEC-PRIVATE_KEY",
	} {
		if !got[want] {
			t.Fatalf("fixture stopped producing %s (canary would pass vacuously); got %v", want, keys(got))
		}
	}

	findings := evidence.ToFindings(evs)
	meta := reporters.ScanMetadata{Target: "canary", Mode: "whitebox", Version: "test"}

	renders := map[string]func(*bytes.Buffer) error{
		"json":  func(b *bytes.Buffer) error { return reporters.RenderJSON(b, findings, meta) },
		"sarif": func(b *bytes.Buffer) error { return reporters.RenderSARIF(b, findings, meta) },
		"html":  func(b *bytes.Buffer) error { return reporters.RenderHTML(b, findings, meta) },
	}
	for name, render := range renders {
		var buf bytes.Buffer
		if err := render(&buf); err != nil {
			t.Fatalf("render %s: %v", name, err)
		}
		out := buf.String()
		for _, secret := range canaries {
			for i := 0; i+6 <= len(secret); i++ {
				if frag := secret[i : i+6]; strings.Contains(out, frag) {
					t.Errorf("%s report leaks %q (a 6-char window of %q)", name, frag, secret)
					break
				}
			}
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
