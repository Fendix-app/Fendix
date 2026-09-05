package pip

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/offline"
)

// TestScanOffline_MatchesSnapshot verifies the air-gapped path finds a
// vulnerable pinned dep from the snapshot with zero network access.
func TestScanOffline_MatchesSnapshot(t *testing.T) {
	dir := t.TempDir()
	req := "flask==2.2.0\nrequests==2.99.0\n# comment\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(req), 0644); err != nil {
		t.Fatal(err)
	}

	snap := offline.FromOSVExport([]offline.Advisory{
		{
			ID:      "GHSA-flask-ssrf",
			Aliases: []string{"CVE-2026-1111"},
			Package: offline.PackageRef{Ecosystem: "PyPI", Name: "flask"},
			Ranges:  []offline.Range{{Introduced: "0.0.0", Fixed: "2.3.0"}},
			Summary: "Flask SSRF",
		},
		{
			ID:      "GHSA-other",
			Package: offline.PackageRef{Ecosystem: "PyPI", Name: "django"},
			Ranges:  []offline.Range{{Introduced: "0.0.0", Fixed: "5.0.0"}},
		},
	}, []string{"osv.dev"})

	findings, err := ScanOffline(dir, DefaultRecurseDepth, snap)
	if err != nil {
		t.Fatalf("ScanOffline: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings; want 1 (flask only)", len(findings))
	}
	f := findings[0]
	// FIX-05: the snapshot advisory carries CVE-2026-1111 as an alias, and
	// the canonical-id rule prefers a CVE over the GHSA it was filed
	// under. The offline path deliberately shares the online path's
	// finding constructor, so it renames in lockstep.
	if f.ID != "SEC-DEPS-CVE_2026_1111" {
		t.Errorf("ID = %q; want SEC-DEPS-CVE_2026_1111", f.ID)
	}
	// The id it was filed under is preserved as a reference (Rule 3).
	foundGHSA := false
	for _, r := range f.References {
		if r == "GHSA-flask-ssrf" {
			foundGHSA = true
		}
	}
	if !foundGHSA {
		t.Errorf("References %v dropped the snapshot's own advisory id", f.References)
	}
	if f.Category != "deps" {
		t.Errorf("Category = %q; want deps", f.Category)
	}
	// Fix line should name the snapshot's fixed version.
	if want := "Upgrade to flask==2.3.0 or later."; f.Fix != want {
		t.Errorf("Fix = %q; want %q", f.Fix, want)
	}
	// Alias from the snapshot must surface as a reference (parity with online path).
	foundAlias := false
	for _, r := range f.References {
		if r == "CVE-2026-1111" {
			foundAlias = true
		}
	}
	if !foundAlias {
		t.Errorf("References %v missing CVE alias", f.References)
	}
}

// TestScanOffline_PatchedVersionNoFinding verifies a pinned version at or
// above the fixed endpoint produces no finding.
func TestScanOffline_PatchedVersionNoFinding(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.3.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	snap := offline.FromOSVExport([]offline.Advisory{{
		ID:      "GHSA-flask-ssrf",
		Package: offline.PackageRef{Ecosystem: "PyPI", Name: "flask"},
		Ranges:  []offline.Range{{Introduced: "0.0.0", Fixed: "2.3.0"}},
	}}, nil)
	findings, err := ScanOffline(dir, DefaultRecurseDepth, snap)
	if err != nil {
		t.Fatalf("ScanOffline: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("patched flask 2.3.0 should yield no findings; got %d", len(findings))
	}
}

// TestScanOffline_NilSnapshotErrors guards the contract that a nil
// snapshot is an explicit error, never a silent empty result.
func TestScanOffline_NilSnapshotErrors(t *testing.T) {
	if _, err := ScanOffline(t.TempDir(), 0, nil); err == nil {
		t.Fatal("expected error for nil snapshot, got nil")
	}
}

// TestScanOffline_NoManifestsIsErrNoManifests mirrors the online "checked
// everywhere, nothing to scan" contract: ErrNoManifests, not a silent
// empty-slice ok, so the orchestrator can record pip skipped/not_applicable.
func TestScanOffline_NoManifestsIsErrNoManifests(t *testing.T) {
	snap := offline.FromOSVExport(nil, nil)
	findings, err := ScanOffline(t.TempDir(), DefaultRecurseDepth, snap)
	if !errors.Is(err, ErrNoManifests) {
		t.Fatalf("ScanOffline: got err %v, want ErrNoManifests", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings; want 0", len(findings))
	}
}
