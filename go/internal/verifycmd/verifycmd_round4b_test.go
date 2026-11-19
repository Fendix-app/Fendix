package verifycmd

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
)

// Round 4b: redteam4-verify-01 and -02, DE4-05.

// redteam4-verify-01: verify must be at least as permissive as the scanner. For
// every way of gluing a key to the bytes before it, if the scanner itself
// reports the key anywhere on the tree, verify must not call it resolved.
func TestVerify_NeverResolvesACredentialTheScannerStillReports(t *testing.T) {
	f, base := baselineOf(t, "secrets/AWS_ACCESS_KEY", "app/cfg.py", `AWS_ACCESS_KEY_ID = "`+vsKey+`"`+"\n")
	_ = base
	reported := 0
	for _, glue := range []string{"x", "token=x", "abc", "9", "_", "-", "Zz9", ":", "=", "/", "", "key_"} {
		for _, file := range []string{"other.txt", "other.yaml", "Dockerfile", "creds/credentials", "w.md"} {
			root := t.TempDir()
			writeFile(t, root, "app/cfg.py", `AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]`+"\n")
			writeFile(t, root, file, "k "+glue+vsKey+" end\n")
			sightings, err := secrets.ScanSightings(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if len(sightings) == 0 {
				continue
			}
			reported++
			r := verifyIn(t, f, root)
			if r.Status == StatusResolved {
				t.Errorf("glue %q in %s: the scanner reports the key at %s but verify says resolved: %s", glue, file, sightings[0].Endpoint, r.Reason)
			}
		}
	}
	if reported == 0 {
		t.Fatal("the scanner reported nothing in any variant: the differential is vacuous")
	}
}

func gz(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.String()
}

func zipOf(t *testing.T, name, content string) string {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	e, _ := w.Create(name)
	e.Write([]byte(content))
	w.Close()
	return b.String()
}

// redteam4-verify-02: a credential moved into an escape, an array join, base64,
// a binary or compressed file, or a directory a scan prunes on evidence is
// still present.
func TestVerify_CredentialMovedIntoAnotherRepresentationOrPlaceIsStillPresent(t *testing.T) {
	a, b := vsPW[:6], vsPW[6:]
	hexEsc := ""
	for i := 0; i < len(vsPW); i++ {
		hexEsc += fmt.Sprintf(`\x%02x`, vsPW[i])
	}
	utf16le := func(s string) string {
		var out []byte
		for _, r := range s {
			out = append(out, byte(r), byte(r>>8))
		}
		return string(out)
	}
	for name, mv := range map[string]map[string]string{
		"hex escapes":             {"app/settings.py": `DB_PASSWORD = "` + hexEsc + `"`},
		"array join":              {"app/settings.py": `DB_PASSWORD = ["` + a + `","` + b + `"].join("")`},
		"concat method":           {"app/settings.py": `DB_PASSWORD = "` + a + `".concat("` + b + `")`},
		"base64 in yaml":          {"k8s/s.yaml": "data:\n  pw: " + base64.StdEncoding.EncodeToString([]byte(vsPW)) + "\n"},
		"binary file":             {"bin/app.bin": "\x7fELF\x00\x00" + vsPW + "\x00"},
		"png":                     {"img/logo.png": "\x89PNG\r\n\x1a\n\x00\x00tEXt" + vsPW},
		"gzip":                    {"pkg/s.gz": gz(t, "pw="+vsPW)},
		"gzip named txt":          {"pkg/s.txt": gz(t, "pw="+vsPW)},
		"jar":                     {"lib/app.jar": zipOf(t, "app.properties", "pw="+vsPW)},
		"node_modules (evidence)": {"node_modules/.package-lock.json": `{"lockfileVersion": 3}`, "node_modules/acme/index.js": "module.exports='" + vsPW + "'"},
		"virtualenv":              {"env/pyvenv.cfg": "home = /usr/bin\n", "env/keys.py": "K='" + vsPW + "'"},
		"UTF-16 without a BOM":    {"win/s.txt": utf16le("DB_PASSWORD = \"" + vsPW + "\"\r\n")},
		"glued to a letter":       {"o.txt": "token=x" + vsPW + "\n"},
	} {
		t.Run(name, func(t *testing.T) {
			f, root := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
			mv["app/settings.py"] = orDefault(mv["app/settings.py"], `DB_PASSWORD = os.environ["DB_PASSWORD"]`)
			rewrite(t, root, mv)
			r := verifyIn(t, f, root)
			if r.Status != StatusStillPresent {
				t.Fatalf("status %s, want still-present: %s", r.Status, r.Reason)
			}
		})
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// An archive verify cannot open is unknown, never resolved; a clean tree with
// opened archives and an image is unknown too (Round 6, D4 Option A: it was
// resolved) and says what was searched and not.
func TestVerify_AnArchiveItCannotOpenIsUnknownAndACleanTreeIsResolved(t *testing.T) {
	f, root := baselineOf(t, "secrets/HARDCODED_PASSWORD", "app/settings.py", `DB_PASSWORD = "`+vsPW+`"`+"\n")
	rewrite(t, root, map[string]string{
		"app/settings.py": `DB_PASSWORD = os.environ["DB_PASSWORD"]` + "\n",
		"pkg/s.xz":        "\xfd7zXZ\x00\x00\x04" + strings.Repeat("\x00", 40),
	})
	if r := verifyIn(t, f, root); r.Status != StatusUnknown || !strings.Contains(r.Reason, "s.xz") {
		t.Fatalf("status %s, want unknown naming s.xz: %s", r.Status, r.Reason)
	}
	rewrite(t, root, map[string]string{
		"pkg/ok.gz":    gz(t, "nothing here\n"),
		"pkg/ok.jar":   zipOf(t, "a.txt", "nothing"),
		"img/logo.png": "\x89PNG\r\n\x1a\n\x00\x00nothing",
	}, "pkg/s.xz")
	r := verifyIn(t, f, root)
	if r.Status != StatusUnknown {
		t.Fatalf("status %s, want unknown (D4 Option A: never resolved): %s", r.Status, r.Reason)
	}
	for _, want := range []string{"raw bytes", "archives", "including directories a scan prunes", "version-control history", "not covered"} {
		if !strings.Contains(r.Reason, want) {
			t.Errorf("the reason must say %q: %s", want, r.Reason)
		}
	}
}

// With no marker to search for, the rule is the only witness; it does not read
// binary files or pruned directories. Round 6 (D4 Option A): a clean tree is
// unknown (it was resolved), and a binary file leaves it unknown for its own
// reason, which the reason names.
func TestVerify_ARuleOnlyResolvedNeedsNothingLeftUnread(t *testing.T) {
	f, root := baselineOf(t, "secrets/AWS_ACCESS_KEY", "app/cfg.py", `AWS_ACCESS_KEY_ID = "`+vsKey+`"`+"\n")
	f.Evidence = "AWS_ACCESS_KEY_ID = \"AKIA...\"" // an older baseline: no redaction marker
	rewrite(t, root, map[string]string{"app/cfg.py": `AWS_ACCESS_KEY_ID = os.environ["X"]` + "\n"})
	if r := verifyIn(t, f, root); r.Status != StatusUnknown || strings.Contains(r.Reason, "binary") {
		t.Fatalf("clean tree: status %s, want unknown for the rule-only absence (D4 Option A): %s", r.Status, r.Reason)
	}
	rewrite(t, root, map[string]string{"img/logo.png": "\x89PNG\r\n\x1a\n"})
	if r := verifyIn(t, f, root); r.Status != StatusUnknown || !strings.Contains(r.Reason, "binary") {
		t.Fatalf("with a binary file: status %s, want unknown: %s", r.Status, r.Reason)
	}
}
