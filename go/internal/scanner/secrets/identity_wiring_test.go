package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/evidence"
)

// The v2 fingerprint keys a committed credential on the non-sensitive
// identifier it is bound to — never on the credential or a digest of it. That
// identifier is what lets two secrets in one file stay distinct while either
// one survives being moved down the file, so the scanner has to capture it at
// the point of match.
func TestScanCapturesTheNonSensitiveIdentifier(t *testing.T) {
	src := "" +
		"import os\n" +
		"AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMIK7MDENGbPxRfiCYz9QhTkLpVxNr\"\n" +
		"STRIPE_SECRET_KEY = \"sk_live_51H8xQeLkdIwHu7ix0aBcDeFgHiJkLmNoPqRs\"\n"

	found := scanContent(t, "config/settings.py", src)
	if len(found) < 2 {
		t.Fatalf("expected both credentials to be found, got %d: %+v", len(found), found)
	}

	seen := map[string]bool{}
	for _, ev := range found {
		if ev.Secret == nil {
			t.Fatalf("Secret is nil for %q — the v2 fingerprint has no safe identity to key on", ev.Title)
		}
		if ev.Secret.Identifier == "" {
			t.Errorf("Identifier is empty for %q", ev.Title)
		}
		if ev.Secret.File != "config/settings.py" {
			t.Errorf("File = %q, want config/settings.py", ev.Secret.File)
		}
		seen[ev.Secret.Identifier] = true
	}
	for _, want := range []string{"AWS_SECRET_ACCESS_KEY", "STRIPE_SECRET_KEY"} {
		if !seen[want] {
			t.Errorf("identifier %q was not captured; got %v", want, seen)
		}
	}
}

// The identifier is an identity input, so it must never carry credential
// material of its own.
func TestCapturedIdentifierHoldsNoCredentialMaterial(t *testing.T) {
	const credential = "wJalrXUtnFEMIK7MDENGbPxRfiCYz9QhTkLpVxNr"
	src := "AWS_SECRET_ACCESS_KEY = \"" + credential + "\"\n"

	for _, ev := range scanContent(t, "settings.py", src) {
		if ev.Secret == nil {
			continue
		}
		if strings.Contains(ev.Secret.Identifier, credential) ||
			strings.Contains(ev.Secret.Identifier, credential[:8]) {
			t.Errorf("credential material leaked into the identity: %q", ev.Secret.Identifier)
		}
	}
}

// scanContent writes src at rel inside a fresh tree and returns the secrets
// findings, so a test can state the SOURCE it cares about rather than a
// fixture path.
func scanContent(t *testing.T, rel, src string) []evidence.Evidence {
	t.Helper()
	root := t.TempDir()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := Scan(t.Context(), root)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return found
}

// The identifier must be the name the credential is BOUND to, not a fragment
// found inside the credential's own text.
//
// A connection string contains its own "key:value" shapes — postgres://user:pw
// — and the nearest-key search reads `user` out of the URL. That is stable only
// until someone rotates the database username, at which point the finding gets
// a new identity for a change that is not a new vulnerability. The binding on
// the left of the assignment is the stable name.
func TestIdentifierIsTheBindingNameNotAFragmentOfTheValue(t *testing.T) {
	src := `DATABASE_URL = "postgres://appuser:s3cr3tpassw0rd@db.internal:5432/app"` + "\n"

	found := scanContent(t, "settings.py", src)
	if len(found) == 0 {
		t.Fatal("connection string was not detected")
	}
	for _, ev := range found {
		if ev.Secret == nil {
			continue
		}
		if ev.Secret.Identifier != "DATABASE_URL" {
			t.Errorf("identifier = %q, want DATABASE_URL — a name read out of the URL "+
				"changes whenever the credential is rotated", ev.Secret.Identifier)
		}
	}
}

// Rotating the credential must not change identity: same binding, same secret.
func TestRotatingACredentialKeepsTheIdentity(t *testing.T) {
	before := scanContent(t, "settings.py",
		`DATABASE_URL = "postgres://appuser:oldpassword1@db.internal:5432/app"`+"\n")
	after := scanContent(t, "settings.py",
		`DATABASE_URL = "postgres://rotated:newpassword2@db.internal:5432/app"`+"\n")

	if len(before) == 0 || len(after) == 0 {
		t.Fatal("connection string was not detected on one side")
	}
	if before[0].Secret == nil || after[0].Secret == nil {
		t.Fatal("no secret identity captured")
	}
	if before[0].Secret.Identifier != after[0].Secret.Identifier {
		t.Errorf("rotating the credential changed its identity: %q -> %q",
			before[0].Secret.Identifier, after[0].Secret.Identifier)
	}
}
