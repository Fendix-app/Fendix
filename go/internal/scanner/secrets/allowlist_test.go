package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/gitdiff"
)

// A line that trips a secrets pattern (AWS access key id), used to seed two
// files so we can prove the allowlist scopes which file is scanned.
const awsKeyLine = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"

func seed(t *testing.T, root, rel string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(awsKeyLine), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanWithAllowlist_NilEqualsFullScan(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "a.py")
	seed(t, root, "b.py")

	full, err := Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	viaNil, err := ScanWithAllowlist(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) != len(viaNil) || len(full) == 0 {
		t.Fatalf("nil allowlist must equal full scan and be non-empty: full=%d nil=%d", len(full), len(viaNil))
	}
}

func TestScanWithAllowlist_ScopesToChangedFile(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "a.py")
	seed(t, root, "b.py")

	full, _ := Scan(context.Background(), root)
	allow := gitdiff.NewAllowlist(root, []string{"a.py"})
	scoped, err := ScanWithAllowlist(context.Background(), root, allow)
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) == 0 {
		t.Fatal("scoped scan of the changed file must still find the secret")
	}
	if len(scoped) >= len(full) {
		t.Fatalf("scoped scan must report fewer findings: scoped=%d full=%d", len(scoped), len(full))
	}
}

func TestScanWithAllowlist_EmptyFindsNothing(t *testing.T) {
	root := t.TempDir()
	seed(t, root, "a.py")
	allow := gitdiff.NewAllowlist(root, nil)
	scoped, err := ScanWithAllowlist(context.Background(), root, allow)
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 0 {
		t.Fatalf("empty allowlist must find nothing, got %d", len(scoped))
	}
}
