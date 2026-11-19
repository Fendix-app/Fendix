package verifycmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
	"github.com/Fendix-app/Fendix/go/internal/scanner/textscan"
)

// R-010 / decision D5. verify re-tests a `secrets`-category finding with the
// secrets scanner only when the secrets scanner produced it. A finding another
// analyzer produced (textscan's AWS-key and weak-password-hash rules, the
// Python engine's weak-crypto check) can never be re-emitted by that scanner,
// so its silence proves nothing: the verdict is unknown, which exits 2, never
// resolved (exit 0).

// Synthetic credentials, split so this file holds no key-shaped literal.
var (
	pyKey  = "AKIA" + "QWERTYUIOPZXCVBN"
	jsKey  = "AKIA" + "Z7QK3LMN4PQR5STU"
	goKey  = "AKIA" + "MNBVCXZLKJHGFDSA"
	newKey = "AKIA" + "ROTATEDSYNTHETC9"
)

func producerFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "app/settings.py", `AWS_ACCESS_KEY_ID = "`+pyKey+`"`+"\n")
	writeFile(t, root, "web/cfg.js", `const key = "`+jsKey+`";`+"\nmodule.exports = { key };\n")
	writeFile(t, root, "svc/hash.go", "package svc\n\nimport \"crypto/md5\"\n\nfunc Hash(password string) [16]byte {\n\treturn md5.Sum([]byte(password))\n}\n")
	writeFile(t, root, "svc/keys.go", "package svc\n\nconst accessKey = \""+goKey+"\"\n")
	writeFile(t, root, "py/auth.py", "import hashlib\n\ndef h(password):\n    return hashlib.md5(password.encode()).hexdigest()\n")
	return root
}

// findingsOf runs the two native analyzers that emit `secrets`-category
// findings over root and projects them exactly as the engine's accumulator
// does, so the baseline is one the real pipeline produces (BQA-03), not a
// hand-assembled mix of one analyzer's rule id and another's title.
func findingsOf(t *testing.T, root string) []models.Finding {
	t.Helper()
	ts, err := textscan.Scan(root, textscan.AllRules())
	if err != nil {
		t.Fatalf("textscan: %v", err)
	}
	ss, err := secrets.Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("secrets: %v", err)
	}
	var out []models.Finding
	for i, f := range evidence.ToFindings(append(ts, ss...)) {
		if f.Category != "secrets" {
			continue
		}
		f.ID = fmt.Sprintf("SEC-%03d", i+1)
		out = append(out, f)
	}
	// The Python engine's weak-crypto check carries category secrets too; its
	// shape is the one the engine reports (python.ast/ rule, tree-sitter tier).
	out = append(out, models.Finding{
		ID: "SEC-900", RuleID: "python.ast/PY_WEAK_CRYPTO_PASSWORD", SourceTier: models.TierTreeSitter,
		Title:  "Weak hash (MD5/SHA1) used for password — credential exposure risk",
		Source: models.SourceWhitebox, Category: "secrets", Severity: models.SeverityHigh,
		Endpoint: "py/auth.py:4",
	})
	return out
}

func verifyAll(t *testing.T, root string, fs []models.Finding) map[string]*Result {
	t.Helper()
	baseline := writeBaseline(t, t.TempDir(), fs)
	out := map[string]*Result{}
	for _, f := range fs {
		r, err := Run(context.Background(), f.ID, Options{BaselinePath: baseline, CodePath: root})
		if err != nil {
			t.Fatalf("%s: %v", f.ID, err)
		}
		out[f.ID] = r
	}
	return out
}

func TestVerify_NoSecretsCategoryFindingOfARealScanResolvesOnUnchangedCode(t *testing.T) {
	root := producerFixture(t)
	fs := findingsOf(t, root)
	rules := map[string]bool{}
	for _, f := range fs {
		rules[f.RuleID] = true
	}
	for _, want := range []string{"GO_WEAK_HASH_PASSWORD", "GO_HARDCODED_AWS_KEY", "JS_HARDCODED_AWS_KEY", "secrets/AWS_ACCESS_KEY"} {
		if !rules[want] {
			t.Fatalf("fixture did not produce %s; got %v", want, rules)
		}
	}
	for _, f := range fs {
		r := verifyAll(t, root, []models.Finding{f})[f.ID]
		if r.Status == StatusResolved {
			t.Errorf("%s (%s, tier %q) on UNCHANGED code verified as resolved: %s", f.ID, f.RuleID, f.SourceTier, r.Reason)
			continue
		}
		if strings.HasPrefix(f.RuleID, "secrets/") {
			if r.Status != StatusStillPresent {
				t.Errorf("%s (%s) from the secrets scanner on unchanged code: %s, want still-present: %s", f.ID, f.RuleID, r.Status, r.Reason)
			}
			continue
		}
		if r.Status != StatusUnknown {
			t.Errorf("%s (%s) from another analyzer: %s, want unknown: %s", f.ID, f.RuleID, r.Status, r.Reason)
		}
		if !strings.Contains(r.Reason, f.RuleID) {
			t.Errorf("%s: the reason should name the producing rule %s: %s", f.ID, f.RuleID, r.Reason)
		}
	}
}

// The same holds after the code changes: a finding from another analyzer is
// unknown whether or not its line is still there, because verify cannot tell.
func TestVerify_OtherAnalyzerSecretsFindingIsUnknownEvenWhenRemoved(t *testing.T) {
	root := producerFixture(t)
	fs := findingsOf(t, root)
	writeFile(t, root, "web/cfg.js", "module.exports = {};\n")
	writeFile(t, root, "svc/hash.go", "package svc\n")
	writeFile(t, root, "svc/keys.go", "package svc\n")
	writeFile(t, root, "py/auth.py", "x = 1\n")
	for id, r := range verifyAll(t, root, fs) {
		if r.Original != nil && !strings.HasPrefix(r.Original.RuleID, "secrets/") && r.Status != StatusUnknown {
			t.Errorf("%s (%s): %s, want unknown: %s", id, r.Original.RuleID, r.Status, r.Reason)
		}
	}
}

// secretsScannerFinding scans root and returns the secrets scanner's
// AWS_ACCESS_KEY finding at rel, as the baseline would hold it.
func secretsScannerFinding(t *testing.T, root, rel string) models.Finding {
	t.Helper()
	ss, err := secrets.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range evidence.ToFindings(ss) {
		if f.RuleID == "secrets/AWS_ACCESS_KEY" && strings.HasPrefix(f.Endpoint, rel+":") {
			f.ID = "SEC-001"
			return f
		}
	}
	t.Fatalf("no secrets/AWS_ACCESS_KEY finding at %s", rel)
	return models.Finding{}
}

// Removed, unchanged and modified secrets, for a finding the secrets scanner
// produced. The documented semantics: verify asks whether the secrets scanner
// still reports the SAME RULE in the SAME FILE, or the SAME CREDENTIAL (its
// redaction marker) anywhere under --code. Line moves, in-place rotation to
// another literal and a move to another file keep it present; replacing the
// literal with a lookup the scanner does not report is unknown (Round 6, D4
// Option A: it resolved before; resolved is never derived from absence).
func TestVerify_SecretsScannerFindingRemovedUnchangedAndModified(t *testing.T) {
	const rel = "app/settings.py"
	cases := []struct {
		name    string
		mutate  func(t *testing.T, root string)
		want    Status
		snippet string
	}{
		{"unchanged", func(*testing.T, string) {}, StatusStillPresent, ""},
		{"removed from the file", func(t *testing.T, root string) {
			writeFile(t, root, rel, "import os\n")
		}, StatusUnknown, "Not detected is not the same as fixed"},
		{"replaced by an environment lookup", func(t *testing.T, root string) {
			writeFile(t, root, rel, "import os\nAWS_ACCESS_KEY_ID = os.environ[\"AWS_ACCESS_KEY_ID\"]\n")
		}, StatusUnknown, "Not detected is not the same as fixed"},
		{"rotated in place to another literal", func(t *testing.T, root string) {
			writeFile(t, root, rel, `AWS_ACCESS_KEY_ID = "`+newKey+`"`+"\n")
		}, StatusStillPresent, ""},
		{"moved to another line of the same file", func(t *testing.T, root string) {
			writeFile(t, root, rel, "import os\n\n\nAWS_ACCESS_KEY_ID = \""+pyKey+"\"\n")
		}, StatusStillPresent, ""},
		{"moved to a same-named file in another directory", func(t *testing.T, root string) {
			writeFile(t, root, rel, "import os\n")
			writeFile(t, root, "app/sub/settings.py", `AWS_ACCESS_KEY_ID = "`+pyKey+`"`+"\n")
			// redteam-verify-01: the same credential is still committed, so
			// the finding is not resolved; the reason names where it went.
		}, StatusStillPresent, "app/sub/settings.py:1"},
		{"file deleted", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, rel)); err != nil {
				t.Fatal(err)
			}
		}, StatusUnknown, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := producerFixture(t)
			f := secretsScannerFinding(t, root, rel)
			tc.mutate(t, root)
			r := verifyAll(t, root, []models.Finding{f})[f.ID]
			if r.Status != tc.want {
				t.Fatalf("status %s, want %s: %s", r.Status, tc.want, r.Reason)
			}
			if tc.snippet != "" && !strings.Contains(r.Reason, tc.snippet) {
				t.Errorf("reason should say %q: %s", tc.snippet, r.Reason)
			}
		})
	}
}

// A re-test that could not read everything the original scan read never
// proves resolution.
func TestVerify_IncompleteSecretsRetestIsNeverResolved(t *testing.T) {
	// Round 3 had a case here for "the line holding the secret is now a skipped
	// minified line". The scanner no longer skips any line (R-010), so that
	// state is a plain still-present: asserted below, not an incomplete re-test.
	t.Run("the line holding the secret is now a long line: still present", func(t *testing.T) {
		root := producerFixture(t)
		writeFile(t, root, "web/app.js", `const key = "`+newKey+`";`+"\n")
		f := secretsScannerFinding(t, root, "web/app.js")
		writeFile(t, root, "web/app.js", `const key = "`+newKey+`";`+strings.Repeat(" ", 600)+"x();\n")
		r := verifyAll(t, root, []models.Finding{f})[f.ID]
		if r.Status != StatusStillPresent {
			t.Fatalf("status %s, want still-present: %s", r.Status, r.Reason)
		}
	})
	t.Run("the endpoint is a symlink the scanner does not read", func(t *testing.T) {
		root := producerFixture(t)
		if err := os.Symlink("settings.py", filepath.Join(root, "app", "link.py")); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		f := secretsScannerFinding(t, root, "app/settings.py")
		f.Endpoint = "app/link.py:1"
		line := "app/link.py:1"
		f.Line = &line
		f.Occurrences = nil
		writeFile(t, root, "app/settings.py", "import os\n")
		r := verifyAll(t, root, []models.Finding{f})[f.ID]
		if r.Status != StatusUnknown {
			t.Fatalf("status %s, want unknown: %s", r.Status, r.Reason)
		}
	})
	t.Run("the file is unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses file permissions")
		}
		root := producerFixture(t)
		f := secretsScannerFinding(t, root, "app/settings.py")
		p := filepath.Join(root, "app", "settings.py")
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
		r := verifyAll(t, root, []models.Finding{f})[f.ID]
		if r.Status != StatusUnknown {
			t.Fatalf("status %s, want unknown: %s", r.Status, r.Reason)
		}
	})
}

// A finding whose producer cannot be established is not re-tested by the
// secrets scanner: a baseline from before rule ids, a group whose tier says
// another analyzer is a member, an imported result.
func TestVerify_SecretsFindingWithoutProvableProducerIsUnknown(t *testing.T) {
	cases := []struct {
		name   string
		modify func(f *models.Finding)
	}{
		{"no rule id (pre-v0.22 baseline)", func(f *models.Finding) { f.RuleID = "" }},
		{"secrets rule id but a native_go tier (merged with textscan)", func(f *models.Finding) { f.SourceTier = models.TierNativeGo }},
		{"secrets rule id but a tree-sitter tier", func(f *models.Finding) { f.SourceTier = models.TierTreeSitter }},
		{"imported from another tool's SARIF", func(f *models.Finding) { f.Source = models.SourceImported }},
		{"an unknown secrets/ rule id", func(f *models.Finding) { f.RuleID = "secrets/NOT_A_RULE" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := producerFixture(t)
			f := secretsScannerFinding(t, root, "app/settings.py")
			tc.modify(&f)
			// The secret is gone: the old code called this resolved.
			writeFile(t, root, "app/settings.py", "import os\n")
			r := verifyAll(t, root, []models.Finding{f})[f.ID]
			if r.Status != StatusUnknown {
				t.Fatalf("status %s, want unknown: %s", r.Status, r.Reason)
			}
		})
	}
}

// A grouped secrets-scanner finding stays present while any occurrence's file
// still carries the rule. Round 6 (D4 Option A): once every occurrence is gone the
// fold is unknown, never resolved.
func TestVerify_GroupedSecretsScannerFindingNeedsEveryOccurrence(t *testing.T) {
	root := producerFixture(t)
	// A real scan groups EVERY secrets/AWS_ACCESS_KEY finding into one
	// (engine dedupKey: severity|category|title), so the tree holds no AWS
	// key outside the two occurrences: otherwise the root-wide search
	// (redteam-verify-01) rightly finds a key the group does not account for.
	writeFile(t, root, "web/cfg.js", "module.exports = {};\n")
	writeFile(t, root, "svc/keys.go", "package svc\n")
	writeFile(t, root, "app/other.py", `AWS_ACCESS_KEY_ID = "`+pyKey+`"`+"\n")
	f := secretsScannerFinding(t, root, "app/settings.py")
	f.AffectedEndpoints = []string{"app/other.py:1", "app/settings.py:1"}
	f.Occurrences = nil
	writeFile(t, root, "app/settings.py", "import os\n")
	r := verifyAll(t, root, []models.Finding{f})[f.ID]
	if r.Status != StatusStillPresent {
		t.Fatalf("one occurrence remains: status %s, want still-present: %s", r.Status, r.Reason)
	}
	writeFile(t, root, "app/other.py", "import os\n")
	r = verifyAll(t, root, []models.Finding{f})[f.ID]
	if r.Status != StatusUnknown {
		t.Fatalf("both occurrences removed: status %s, want unknown (D4 Option A: the fold never resolves): %s", r.Status, r.Reason)
	}
}
