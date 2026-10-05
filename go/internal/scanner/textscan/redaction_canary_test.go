// Package textscan_test holds textscan's redaction canary. External test
// package on purpose, mirroring secrets/redaction_canary_test.go: it needs
// internal/reporters, and keeping the dependency direction explicit beats
// smuggling a renderer into the package under test.
package textscan_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner/textscan"
)

// awsKeyFixture is a syntactically valid but non-functional AKIA literal. It
// must match GO_HARDCODED_AWS_KEY / JS_HARDCODED_AWS_KEY's `AKIA[A-Z0-9]{16}`.
const awsKeyFixture = "AKIA3RQ7ZL2XVBN9CDTK"

// TestNoAWSKeySubstringReachesAnyReport is the canary for textscan's half of
// capture-time redaction.
//
// secrets/redaction_canary_test.go covers the secrets scanner. It did NOT
// cover this package, and that gap was real rather than theoretical: textscan
// carries its own secrets-category rules, and until Rule.RedactMatch existed
// they emitted the raw source line as evidence. A live AWS key in a .go or .js
// file therefore reached Finding.Evidence verbatim and travelled from there
// into SARIF, HTML, Jira tickets and GitHub PR comments — while the secrets
// scanner was redacting the identical value three packages away.
//
// Asserts on a SIX-character window rather than the whole key, for the same
// reason the secrets canary does: half a leaked credential is still a leak,
// and "the full key is absent" is the assertion that lets a truncated prefix
// through.
func TestNoAWSKeySubstringReachesAnyReport(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("main.go", "package main\n\nconst awsKey = \""+awsKeyFixture+"\"\n")
	write("app.js", "const k = \""+awsKeyFixture+"\";\n")

	found, err := textscan.Scan(dir, textscan.AllRules())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var aws []evidence.Evidence
	for _, e := range found {
		if strings.Contains(e.Title, "AWS access-key") {
			aws = append(aws, e)
		}
	}
	if len(aws) != 2 {
		t.Fatalf("expected the Go and JS AWS rules to fire, got %d findings", len(aws))
	}

	// The finding must still be REPORTED — redaction de-escalates the evidence
	// text, it never suppresses the detection (Rule 3).
	for _, e := range aws {
		if !strings.Contains(e.Evidence, "[REDACTED") {
			t.Errorf("%s: evidence carries no redaction marker: %q", e.ID, e.Evidence)
		}
	}

	// Both occurrences are the same credential, so both markers must carry the
	// same digest — that is the whole point of embedding one.
	if len(aws) == 2 && markerOf(aws[0].Evidence) != markerOf(aws[1].Evidence) {
		t.Errorf("same credential rendered two different markers:\n  %q\n  %q",
			aws[0].Evidence, aws[1].Evidence)
	}

	findings := evidence.ToFindings(found)
	meta := reporters.ScanMetadata{Target: dir, Mode: "whitebox", Version: "test"}

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
		for i := 0; i+6 <= len(awsKeyFixture); i++ {
			if window := awsKeyFixture[i : i+6]; strings.Contains(out, window) {
				t.Fatalf("%s report leaks a %d-char window of the credential: %q",
					name, len(window), window)
			}
		}
	}
}

// markerOf returns the first [REDACTED …] marker in s, or "" when absent.
func markerOf(s string) string {
	start := strings.Index(s, "[REDACTED")
	if start < 0 {
		return ""
	}
	end := strings.Index(s[start:], "]")
	if end < 0 {
		return ""
	}
	return s[start : start+end+1]
}

// TestWeakHashRuleKeepsItsEvidence guards the other side of the per-rule
// choice. GO_WEAK_HASH_PASSWORD is also a secrets-category rule, but its
// Pattern matches an md5/sha1 CALL rather than a credential. Keying redaction
// off Category would blank the only useful part of its evidence, so
// RedactMatch is deliberately per-rule — this test fails if someone
// "simplifies" it back to a category check.
func TestWeakHashRuleKeepsItsEvidence(t *testing.T) {
	dir := t.TempDir()
	// The rule's Pattern requires a password-shaped identifier next to the
	// hash call, so the parameter must actually be named `password` — an
	// earlier `pw` here made this test skip, and a skipping guard guards
	// nothing.
	body := "package main\n\nimport \"crypto/md5\"\n\nfunc h(password string) []byte {\n\tsum := md5.Sum([]byte(password))\n\treturn sum[:]\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "hash.go"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	found, err := textscan.Scan(dir, textscan.AllRules())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, e := range found {
		if e.ID != "GO_WEAK_HASH_PASSWORD" {
			continue
		}
		if strings.Contains(e.Evidence, "[REDACTED") {
			t.Fatalf("weak-hash evidence was redacted, losing the signal: %q", e.Evidence)
		}
		if !strings.Contains(e.Evidence, "md5") {
			t.Fatalf("weak-hash evidence lost the call it exists to show: %q", e.Evidence)
		}
		return
	}
	t.Fatal("GO_WEAK_HASH_PASSWORD did not fire — the fixture no longer matches " +
		"its pattern, so this guard is asserting nothing. Fix the fixture, do " +
		"not soften this to a Skip.")
}
