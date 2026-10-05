package npm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/offline"
)

const offlineLockfile = `{
  "name": "myapp",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "myapp", "version": "1.0.0"},
    "node_modules/lodash": {"version": "4.17.20"},
    "node_modules/express": {"version": "4.17.1"}
  }
}`

// TestScanOffline_MatchesSnapshot verifies the air-gapped npm path finds
// a vulnerable resolved version from the snapshot with zero network.
func TestScanOffline_MatchesSnapshot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(offlineLockfile), 0644); err != nil {
		t.Fatal(err)
	}
	snap := offline.FromOSVExport([]offline.Advisory{{
		ID:      "GHSA-lodash-pp",
		Aliases: []string{"CVE-2026-2222"},
		Package: offline.PackageRef{Ecosystem: "npm", Name: "lodash"},
		Ranges:  []offline.Range{{Introduced: "0.0.0", Fixed: "4.17.21"}},
		Summary: "Lodash prototype pollution",
	}}, nil)

	findings, err := ScanOffline(dir, snap)
	if err != nil {
		t.Fatalf("ScanOffline: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings; want 1 (lodash only)", len(findings))
	}
	// FIX-05: the snapshot advisory carries CVE-2026-2222 as an alias, and
	// the canonical-id rule prefers the CVE over the GHSA it was filed
	// under. The offline path shares the online finding constructor, so it
	// renames in lockstep.
	if findings[0].ID != "SEC-DEPS-CVE_2026_2222" {
		t.Errorf("ID = %q; want SEC-DEPS-CVE_2026_2222", findings[0].ID)
	}
	if want := "Upgrade to lodash@4.17.21 or later."; findings[0].Fix != want {
		t.Errorf("Fix = %q; want %q", findings[0].Fix, want)
	}
}

// TestScanOffline_NoLockfileSentinel ensures the offline path returns the
// same sentinel errors the orchestrator switches on.
func TestScanOffline_NoLockfileSentinel(t *testing.T) {
	snap := offline.FromOSVExport(nil, nil)
	_, err := ScanOffline(t.TempDir(), snap)
	if !errors.Is(err, ErrNoLockfile) {
		t.Errorf("err = %v; want ErrNoLockfile", err)
	}
}

// TestScanOffline_LockfileMissingSentinel ensures the package.json-present
// gap still surfaces in offline mode.
func TestScanOffline_LockfileMissingSentinel(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x"}`), 0644); err != nil {
		t.Fatal(err)
	}
	snap := offline.FromOSVExport(nil, nil)
	_, err := ScanOffline(dir, snap)
	if !errors.Is(err, ErrLockfileMissingButPackageJsonPresent) {
		t.Errorf("err = %v; want ErrLockfileMissingButPackageJsonPresent", err)
	}
}

func TestScanOffline_NilSnapshotErrors(t *testing.T) {
	if _, err := ScanOffline(t.TempDir(), nil); err == nil {
		t.Fatal("expected error for nil snapshot, got nil")
	}
}
