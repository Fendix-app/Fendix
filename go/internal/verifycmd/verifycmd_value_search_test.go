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

// R-010, round 4. verify searches the whole tree for the credential's VALUE, in
// every text file and in the forms a literal is rewritten into, before it says
// resolved. These tests pin the false-resolved cases the round 3 reviewers
// reproduced: security3-01 (a key moved into a Dockerfile), DE-01 (an
// assignment-shaped rule whose literal changed representation), redteam3-verify-01
// (a key on a long .ts line), and credentials moved into extension-less and
// other text files.

const (
	vsKey = "AKIA" + "QMOVEDSYNTHETIC9"
	vsPW  = "Zq8vK2" + "mP9xR4tL7w"
)

// baselineOf scans a tree holding one finding of ruleID and returns it.
func baselineOf(t *testing.T, ruleID, file, content string) (models.Finding, string) {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, file, content)
	ss, err := secrets.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range evidence.ToFindings(ss) {
		if f.RuleID == ruleID {
			f.ID = "SEC-001"
			return f, root
		}
	}
	t.Fatalf("no %s finding in %s", ruleID, file)
	return models.Finding{}, ""
}

func verifyIn(t *testing.T, f models.Finding, root string) *Result {
	t.Helper()
	return verifyAll(t, root, []models.Finding{f})[f.ID]
}

func rewrite(t *testing.T, root string, files map[string]string, remove ...string) {
	t.Helper()
	for _, r := range remove {
		if err := os.Remove(filepath.Join(root, r)); err != nil {
			t.Fatal(err)
		}
	}
	for rel, c := range files {
		writeFile(t, root, rel, c)
	}
}

// The credential moved to a file of another kind: the verdict is still-present
// and names where, whatever the file is called.
func TestVerify_CredentialMovedToAnyTextFileIsStillPresent(t *testing.T) {
	long := strings.Repeat("x", 600)
	for name, mv := range map[string]struct{ rel, content string }{
		"Dockerfile (security3-01)":          {"Dockerfile", "FROM alpine\nENV AWS_ACCESS_KEY_ID=" + vsKey + "\n"},
		"Dockerfile.prod":                    {"deploy/Dockerfile.prod", "ENV K=" + vsKey + "\n"},
		"extension-less credentials":         {"creds/credentials", "[default]\naws_access_key_id = " + vsKey + "\n"},
		"hidden extension-less file":         {".secrets", vsKey + "\n"},
		".env.production":                    {".env.production", "AWS_ACCESS_KEY_ID=" + vsKey + "\n"},
		".properties":                        {"src/app.properties", "aws.key=" + vsKey + "\n"},
		".txt":                               {"notes.txt", "key " + vsKey + "\n"},
		".md":                                {"docs/README.md", "Use `" + vsKey + "`\n"},
		".conf":                              {"etc/app.conf", "key=" + vsKey + "\n"},
		".ini":                               {"etc/app.ini", "key=" + vsKey + "\n"},
		".yml":                               {"ci/pipeline.yml", "env:\n  KEY: " + vsKey + "\n"},
		".toml":                              {"cfg.toml", "key = \"" + vsKey + "\"\n"},
		"Makefile":                           {"Makefile", "KEY=" + vsKey + "\n"},
		"long .ts line (redteam3-verify-01)": {"web/cfg.ts", `const a = "` + long + `"; const k = "` + vsKey + `";` + "\n"},
		"long .js line":                      {"web/cfg.js", `const a = "` + long + `"; const k = "` + vsKey + `";` + "\n"},
		"folder only named vendor":           {"vendor/lib/x.txt", "k=" + vsKey + "\n"},
		"folder only named build":            {"build/out.txt", "k=" + vsKey + "\n"},
		"folder only named node_modules":     {"node_modules/p/i.js", "k='" + vsKey + "'\n"},
		"over 1 MiB data json":               {"data/big.json", `{"k":"` + vsKey + `","pad":"` + strings.Repeat("y", 1_300_000) + `"}` + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			f, root := baselineOf(t, "secrets/AWS_ACCESS_KEY", "app/cfg.py", `AWS_ACCESS_KEY_ID = "`+vsKey+`"`+"\n")
			rewrite(t, root, map[string]string{"app/cfg.py": `AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]` + "\n", mv.rel: mv.content})
			r := verifyIn(t, f, root)
			if r.Status != StatusStillPresent {
				t.Fatalf("status %s, want still-present (the key is committed in %s): %s", r.Status, mv.rel, r.Reason)
			}
			if !strings.Contains(r.Reason, strings.SplitN(mv.rel, "/", 2)[0]) {
				t.Errorf("the reason should name %s: %s", mv.rel, r.Reason)
			}
		})
	}
}

// DE-01: the literal is still in the file, but in a shape the rule does not
// match. Round 3 said resolved.
func TestVerify_LiteralInAnotherShapeIsStillPresent(t *testing.T) {
	a, b := vsPW[:7], vsPW[7:]
	for name, code := range map[string]string{
		"environment lookup with a default (DE-01)": `DB_PASSWORD = os.environ.get("DB_PASSWORD", "` + vsPW + `")`,
		"call argument":                   "configure(pw='" + vsPW + "')",
		"dictionary key":                  `cfg = {"db": {"pw": "` + vsPW + `"}}`,
		"moved to a variable":             "x = \"" + vsPW + "\"\nDB_PASSWORD = x",
		"f-string":                        `DB_PASSWORD = f"{prefix}` + vsPW + `"`,
		"JSON":                            `{"db_pw": "` + vsPW + `"}`,
		"template literal":                "const p = `" + vsPW + "`;",
		"heredoc":                         "cat <<EOF\npw=" + vsPW + "\nEOF",
		"bytes literal":                   `DB_PASSWORD = b"` + vsPW + `"`,
		"concatenated with +":             `DB_PASSWORD = "` + vsPW[:3] + `" + "` + vsPW[3:6] + `" + "` + vsPW[6:] + `"`,
		"implicit concatenation":          "DB_PASSWORD = (\n    \"" + a[:3] + "\"\n    \"" + a[3:] + "\"\n    \"" + b + "\"\n)",
		"java concatenation across lines": "String DB_PASSWORD = \"" + vsPW[:3] + "\" +\n    \"" + vsPW[3:] + "\";",
		"backslash continuation":          "DB_PASSWORD = \"" + vsPW[:3] + "\" \\\n    \"" + vsPW[3:] + "\"",
		"quoted differently":              "DB_PASSWORD = '" + vsPW + "'  # rotate",
	} {
		t.Run(name, func(t *testing.T) {
			f, root := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
			rewrite(t, root, map[string]string{"app/settings.py": code + "\nOTHER = 1\n"})
			r := verifyIn(t, f, root)
			if r.Status != StatusStillPresent {
				t.Fatalf("status %s, want still-present (the password is still in settings.py): %s", r.Status, r.Reason)
			}
		})
	}
}

// The value found nowhere is unknown (Round 6, D4 Option A; it was resolved), and
// the reason says what was searched.
func TestVerify_ResolvedSaysWhatWasSearched(t *testing.T) {
	f, root := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
	writeFile(t, root, "Dockerfile", "FROM alpine\n")
	writeFile(t, root, "logo.png", "png")
	rewrite(t, root, map[string]string{"app/settings.py": `DB_PASSWORD = os.environ["DB_PASSWORD"]` + "\n"})
	r := verifyIn(t, f, root)
	if r.Status != StatusUnknown {
		t.Fatalf("status %s, want unknown (D4 Option A: never resolved): %s", r.Status, r.Reason)
	}
	for _, want := range []string{"searched 2 text files", "under --code", "string literals", "backslash escapes", "1 binary files"} {
		if !strings.Contains(r.Reason, want) {
			t.Errorf("the reason should say %q: %s", want, r.Reason)
		}
	}
}

// Anything verify could not search is unknown, never resolved.
func TestVerify_UnsearchableTreeIsUnknown(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	f, root := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
	locked := filepath.Join(root, "ops", "vault.txt")
	writeFile(t, root, "ops/vault.txt", vsPW)
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })
	rewrite(t, root, map[string]string{"app/settings.py": `DB_PASSWORD = os.environ["DB_PASSWORD"]` + "\n"})
	r := verifyIn(t, f, root)
	if r.Status != StatusUnknown || !strings.Contains(r.Reason, "vault.txt") {
		t.Fatalf("status %s, want unknown naming ops/vault.txt: %s", r.Status, r.Reason)
	}
}

// A grouped finding's other occurrences carry no marker (verifyUnits clears
// their evidence): for an assignment-shaped rule they are never resolved on the
// strength of the files read, because the literal may have moved to a shape the
// rule does not match.
func TestVerify_GroupedOccurrenceWithoutAMarkerIsNeverResolved(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "a.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
	writeFile(t, root, "b.py", `DB_PASSWORD = "`+vsPW+`x"`+"\n")
	ss, err := secrets.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	var f models.Finding
	for _, x := range evidence.ToFindings(ss) {
		if x.RuleID == "secrets/HARDCODED_PASSWORD" && strings.HasPrefix(x.Endpoint, "a.py:") {
			f = x
		}
	}
	f.ID = "SEC-001"
	f.Occurrences = []models.Occurrence{{Endpoint: "a.py:1"}, {Endpoint: "b.py:1"}}
	rewrite(t, root, map[string]string{"a.py": "x = 1\n", "b.py": "y = 2\n"})
	r := verifyIn(t, f, root)
	if r.Status != StatusUnknown {
		t.Fatalf("status %s, want unknown (the second occurrence has no marker): %s", r.Status, r.Reason)
	}
}

// Names in a reason are untrusted text (contract C1).
func TestVerify_ReasonNamesAreSanitised(t *testing.T) {
	f, root := baselineOf(t, "secrets/AWS_ACCESS_KEY", "app/cfg.py", `AWS_ACCESS_KEY_ID = "`+vsKey+`"`+"\n")
	rewrite(t, root, map[string]string{"app/cfg.py": "x = 1\n", "evil; resolved: ok….txt": "k=" + vsKey + "\n"})
	r := verifyIn(t, f, root)
	if r.Status != StatusStillPresent {
		t.Fatalf("status %s: %s", r.Status, r.Reason)
	}
	if strings.Contains(r.Reason, "evil;") || strings.Contains(r.Reason, "…") {
		t.Errorf("the reason carries a name unsanitised: %s", r.Reason)
	}
}
