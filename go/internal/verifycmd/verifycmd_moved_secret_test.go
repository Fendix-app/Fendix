package verifycmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
)

// redteam-verify-01. A committed credential that was moved to another file is
// still committed: verify must never call its finding resolved (exit 0). Before
// resolving, verify searches the whole --code root with the secrets scanner for
// the credential the baseline evidence identifies by its redaction marker
// ([REDACTED len=N sha256:...]); a sighting anywhere is still-present and the
// reason names where. A baseline that carries no marker cannot identify the
// credential, so it is never resolved on the strength of one file.

// otherKey is a second synthetic AWS key id, a different credential from pyKey.
var otherKey = "AKIA" + "UNRELATEDSYNTH42"

func TestVerify_SecretMovedToAnotherFileIsStillPresent(t *testing.T) {
	const rel = "app/settings.py"
	cases := []struct {
		name   string
		mutate func(t *testing.T, root string)
		where  string
	}{
		{"the redteam reproduction: literal moved to a sibling file", func(t *testing.T, root string) {
			writeFile(t, root, rel, "import os\nAWS_ACCESS_KEY_ID = os.environ[\"AWS_ACCESS_KEY_ID\"]\n")
			writeFile(t, root, "app/config.py", `AWS_KEY = "`+pyKey+`"`+"\n")
		}, "app/config.py:1"},
		{"moved to a same-named file in another directory", func(t *testing.T, root string) {
			writeFile(t, root, rel, "import os\n")
			writeFile(t, root, "app/sub/settings.py", `AWS_ACCESS_KEY_ID = "`+pyKey+`"`+"\n")
		}, "app/sub/settings.py:1"},
		{"moved into an .env file, where another rule reports it too", func(t *testing.T, root string) {
			writeFile(t, root, rel, "import os\n")
			writeFile(t, root, "deploy/.env", "AWS_ACCESS_KEY_ID="+pyKey+"\n")
		}, "deploy/.env:1"},
		{"moved into a line where an overlapping rule widens the redacted span", func(t *testing.T, root string) {
			// GENERIC_API_KEY captures the whole quoted value, so the line's
			// marker covers more than the key id. The key id is still the
			// same credential.
			writeFile(t, root, rel, "import os\n")
			writeFile(t, root, "lib/client.py", `api_key = "`+pyKey+`-suffix"`+"\n")
		}, "lib/client.py:1"},
		{"moved to a deeper file in another language", func(t *testing.T, root string) {
			writeFile(t, root, rel, "import os\n")
			writeFile(t, root, "svc/internal/aws/creds.go", "package aws\n\nvar id = \""+pyKey+"\"\n")
		}, "svc/internal/aws/creds.go:3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := producerFixture(t)
			f := secretsScannerFinding(t, root, rel)
			if len(secrets.Markers(f.Evidence)) == 0 {
				t.Fatalf("baseline evidence carries no redaction marker: %q", f.Evidence)
			}
			tc.mutate(t, root)
			r := verifyAll(t, root, []models.Finding{f})[f.ID]
			if r.Status != StatusStillPresent {
				t.Fatalf("status %s, want still-present (the credential is still committed at %s): %s", r.Status, tc.where, r.Reason)
			}
			if !strings.Contains(r.Reason, tc.where) {
				t.Errorf("the reason should name the new location %s: %s", tc.where, r.Reason)
			}
		})
	}
}

// Moving the literal elsewhere is a still-present verdict even when the
// original file now carries a long line: the credential was found.
func TestVerify_MovedSecretIsFoundEvenWhenTheOriginalFileHasALongLine(t *testing.T) {
	root := producerFixture(t)
	// newKey is in no other fixture file, so web/keys.ts is its only sighting.
	writeFile(t, root, "web/app.js", `const key = "`+newKey+`";`+"\n")
	f := secretsScannerFinding(t, root, "web/app.js")
	writeFile(t, root, "web/app.js", "const key = process.env.KEY;"+strings.Repeat(" ", 600)+"x();\n")
	writeFile(t, root, "web/keys.ts", `export const k = "`+newKey+`";`+"\n")
	r := verifyAll(t, root, []models.Finding{f})[f.ID]
	if r.Status != StatusStillPresent || !strings.Contains(r.Reason, "web/keys.ts:1") {
		t.Fatalf("status %s, want still-present naming web/keys.ts:1: %s", r.Status, r.Reason)
	}
}

// The search is for THIS credential, not for the rule: another, unrelated key
// of the same kind elsewhere is a different finding and does not keep this one
// open, and a rotated literal in another file is not this credential either.
func TestVerify_RemovedSecretIsResolvedWhenOnlyOtherCredentialsOfItsKindRemain(t *testing.T) {
	root := producerFixture(t)
	f := secretsScannerFinding(t, root, "app/settings.py")
	writeFile(t, root, "app/settings.py", "import os\n")
	writeFile(t, root, "app/other.py", `AWS_KEY = "`+otherKey+`"`+"\n")
	r := verifyAll(t, root, []models.Finding{f})[f.ID]
	if r.Status != StatusResolved {
		t.Fatalf("status %s, want resolved: %s", r.Status, r.Reason)
	}
	if !strings.Contains(r.Reason, "nowhere") {
		t.Errorf("the reason should say the credential was searched for across --code: %s", r.Reason)
	}
}

var markerRE = regexp.MustCompile(`\[REDACTED [^\]]*\]`)

// stripMarkers turns f's evidence into what a baseline without a value hash
// carries: a non-primary occurrence (verifyUnits clears its evidence), a
// signature-only rule, or a baseline written before markers had a digest.
func stripMarkers(f *models.Finding, with string) {
	f.Evidence = markerRE.ReplaceAllString(f.Evidence, with)
}

func TestVerify_SecretWithoutValueHashIsNeverResolvedOnOneFile(t *testing.T) {
	for _, stand := range []string{"", "[REDACTED]", "[REDACTED len=20]", "AKIAQWER..."} {
		t.Run("evidence "+strings.TrimSpace(stand+" "), func(t *testing.T) {
			t.Run("a credential of the same kind is still committed elsewhere", func(t *testing.T) {
				root := producerFixture(t)
				f := secretsScannerFinding(t, root, "app/settings.py")
				stripMarkers(&f, stand)
				writeFile(t, root, "app/settings.py", "import os\n")
				writeFile(t, root, "app/other.py", `AWS_KEY = "`+otherKey+`"`+"\n")
				r := verifyAll(t, root, []models.Finding{f})[f.ID]
				if r.Status != StatusUnknown {
					t.Fatalf("status %s, want unknown (verify cannot tell whether app/other.py holds the moved credential): %s", r.Status, r.Reason)
				}
				if !strings.Contains(r.Reason, "app/other.py:1") {
					t.Errorf("the reason should name app/other.py:1: %s", r.Reason)
				}
			})
			t.Run("a provider-shaped rule that fires nowhere under --code", func(t *testing.T) {
				// AWS_ACCESS_KEY matches the key id's own shape wherever it
				// appears, so its absence from every file the scanner reads
				// is evidence the credential is gone.
				root := producerFixture(t)
				f := secretsScannerFinding(t, root, "app/settings.py")
				stripMarkers(&f, stand)
				writeFile(t, root, "app/settings.py", "import os\n")
				// The fixture's other AWS keys go too: any AWS key left
				// anywhere keeps this unknown (the subtest above).
				writeFile(t, root, "web/cfg.js", "module.exports = {};\n")
				writeFile(t, root, "svc/keys.go", "package svc\n")
				r := verifyAll(t, root, []models.Finding{f})[f.ID]
				if r.Status != StatusResolved {
					t.Fatalf("status %s, want resolved: %s", r.Status, r.Reason)
				}
			})
		})
	}
}

// A rule that matches an assignment SHAPE (a password, a generic API key)
// stops matching when the literal moves into another shape, so with no value
// hash its absence everywhere proves nothing about the credential.
func TestVerify_AssignmentShapedSecretWithoutValueHashIsUnknown(t *testing.T) {
	root := t.TempDir()
	pw := "hunter" + "2-synthetic-pw"
	writeFile(t, root, "app/db.py", `password = "`+pw+`"`+"\n")
	ss, err := secrets.Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	var f models.Finding
	for _, x := range evidence.ToFindings(ss) {
		if x.RuleID == "secrets/HARDCODED_PASSWORD" {
			f = x
		}
	}
	if f.RuleID == "" {
		t.Fatal("fixture produced no HARDCODED_PASSWORD finding")
	}
	f.ID = "SEC-001"
	stripMarkers(&f, "")
	// Moved into a shape the password rule does not match.
	writeFile(t, root, "app/db.py", "import os\n")
	writeFile(t, root, "app/conn.py", `DSN_PART = "`+pw+`"`+"\n")
	r := verifyAll(t, root, []models.Finding{f})[f.ID]
	if r.Status != StatusUnknown {
		t.Fatalf("status %s, want unknown: %s", r.Status, r.Reason)
	}

	// With its marker the credential itself is searched for, so the same move
	// is still-present: the literal is on line 1 of app/conn.py whatever rule
	// matches it. (Round 3 expected resolved here, which is DE-01: the password
	// was still committed and verify said it was not.)
	f2 := f
	f2.Evidence = `password = "` + secrets.RedactValue(pw) + `"`
	r = verifyAll(t, root, []models.Finding{f2})[f2.ID]
	if r.Status != StatusStillPresent || !strings.Contains(r.Reason, "app/conn.py:1") {
		t.Fatalf("with a marker: status %s, want still-present naming app/conn.py:1: %s", r.Status, r.Reason)
	}
	// Once the literal is gone from the whole tree the same finding resolves,
	// and the reason says what was searched.
	writeFile(t, root, "app/conn.py", `DSN_PART = os.environ["DSN_PART"]`+"\n")
	r = verifyAll(t, root, []models.Finding{f2})[f2.ID]
	if r.Status != StatusResolved || !strings.Contains(r.Reason, "searched") {
		t.Fatalf("literal removed: status %s, want resolved with what was searched: %s", r.Status, r.Reason)
	}
}

// The root search never claims resolution it could not establish: when the
// rest of the tree cannot be searched, a re-test that would have resolved is
// unknown.
func TestVerify_SecretIsNotResolvedWhenTheRootCannotBeSearched(t *testing.T) {
	root := producerFixture(t)
	f := secretsScannerFinding(t, root, "app/settings.py")
	writeFile(t, root, "app/settings.py", "import os\n")
	opts := Options{CodePath: root}
	opts.sightings = &sightingCache{loaded: true, err: errors.New("walk aborted")}
	opts.searches = &searchCache{byKey: map[string]searchEntry{
		strings.Join(secrets.Markers(f.Evidence), "\x00"): {err: errors.New("walk aborted")},
	}}
	out := &Result{}
	verifySecret(context.Background(), &f, opts, filepath.Join(root, "app/settings.py"), "app/settings.py", out)
	if out.Status != StatusUnknown {
		t.Fatalf("status %s, want unknown when --code could not be searched: %s", out.Status, out.Reason)
	}
}

// A --code root that is itself a symbolic link is the user's chosen scope:
// verify resolves it like a scan does, so a moved credential is still found.
func TestVerify_MovedSecretIsFoundUnderASymlinkedRoot(t *testing.T) {
	real := producerFixture(t)
	link := filepath.Join(t.TempDir(), "current")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	f := secretsScannerFinding(t, real, "app/settings.py")
	writeFile(t, real, "app/settings.py", "import os\n")
	writeFile(t, real, "app/config.py", `AWS_KEY = "`+pyKey+`"`+"\n")
	r := verifyAll(t, link, []models.Finding{f})[f.ID]
	if r.Status != StatusStillPresent || !strings.Contains(r.Reason, "app/config.py:1") {
		t.Fatalf("status %s, want still-present naming app/config.py:1: %s", r.Status, r.Reason)
	}
}
