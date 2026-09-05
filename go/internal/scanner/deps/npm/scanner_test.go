package npm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/neterr"
)

func TestScan_NoLockfile_ReturnsErrNoLockfile(t *testing.T) {
	dir := t.TempDir()
	_, err := Scan(context.Background(), dir)
	if !errors.Is(err, ErrNoLockfile) {
		t.Fatalf("expected ErrNoLockfile, got %v", err)
	}
}

// TestScan_PackageJsonNoLock_ReturnsAdvisoryError covers the case
// surfaced by the Track 4 heavy-eval: directory has package.json but
// no package-lock.json (vulnerable OSS app didn't ship a lock file).
// We want a different sentinel so the orchestrator can emit an INFO
// advisory finding rather than silently skip.
func TestScan_PackageJsonNoLock_ReturnsAdvisoryError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"x","version":"1.0.0"}`), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	_, err := Scan(context.Background(), dir)
	if !errors.Is(err, ErrLockfileMissingButPackageJsonPresent) {
		t.Fatalf("expected ErrLockfileMissingButPackageJsonPresent, got %v", err)
	}
}

func TestParseLockfile_V2HappyPath(t *testing.T) {
	lockfile := []byte(`{
  "name": "myapp",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {"name": "myapp", "version": "1.0.0"},
    "node_modules/express": {"version": "4.17.1"},
    "node_modules/qs": {"version": "6.7.0", "dev": true},
    "node_modules/@scope/pkg": {"version": "2.0.0"}
  }
}`)
	pkgs, err := parseLockfile(lockfile)
	if err != nil {
		t.Fatalf("parseLockfile: %v", err)
	}
	// Sorted by name. Root entry ("") excluded.
	want := []resolvedPackage{
		{name: "@scope/pkg", version: "2.0.0"},
		{name: "express", version: "4.17.1"},
		{name: "qs", version: "6.7.0", dev: true},
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d pkgs, want %d: %v", len(pkgs), len(want), pkgs)
	}
	for i, p := range pkgs {
		if p.name != want[i].name || p.version != want[i].version || p.dev != want[i].dev {
			t.Errorf("[%d] got %+v, want %+v", i, p, want[i])
		}
	}
}

func TestParseLockfile_NestedDuplicate_Deduped(t *testing.T) {
	// node_modules/express/node_modules/lodash at the same version as
	// node_modules/lodash must produce only one resolvedPackage.
	lockfile := []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {"version": "4.17.20"},
    "node_modules/express": {"version": "4.17.1"},
    "node_modules/express/node_modules/lodash": {"version": "4.17.20"}
  }
}`)
	pkgs, err := parseLockfile(lockfile)
	if err != nil {
		t.Fatalf("parseLockfile: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("want 2 dedup'd pkgs, got %d: %v", len(pkgs), pkgs)
	}
}

func TestParseLockfile_NestedDifferentVersion_Kept(t *testing.T) {
	// Two different versions of the same package both ship — must both
	// be scanned (one might be vulnerable, the other not).
	lockfile := []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {"version": "4.17.20"},
    "node_modules/express/node_modules/lodash": {"version": "4.17.15"}
  }
}`)
	pkgs, err := parseLockfile(lockfile)
	if err != nil {
		t.Fatalf("parseLockfile: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("want 2 different-version pkgs, got %d: %v", len(pkgs), pkgs)
	}
}

func TestParseLockfile_V1Rejected(t *testing.T) {
	// Legacy v1 lockfile has `dependencies` tree, no flat `packages`.
	// Parser should return an explicit error so the orchestrator
	// can slog.Warn + skip; callers don't get a confusing empty
	// findings list silently.
	lockfile := []byte(`{
  "name": "old", "version": "1.0", "lockfileVersion": 1,
  "dependencies": {"lodash": {"version": "4.17.20"}}
}`)
	_, err := parseLockfile(lockfile)
	if err == nil {
		t.Fatal("expected error on v1 lockfile, got nil")
	}
	if !strings.Contains(err.Error(), "lockfileVersion") {
		t.Errorf("error should mention lockfileVersion, got: %v", err)
	}
}

func TestParseLockfile_MalformedJSON(t *testing.T) {
	_, err := parseLockfile([]byte("not json at all"))
	if err == nil {
		t.Fatal("expected error on garbage input")
	}
}

func TestNameFromPath(t *testing.T) {
	cases := []struct {
		path, explicit, want string
	}{
		{"node_modules/express", "", "express"},
		{"node_modules/@scope/pkg", "", "@scope/pkg"},
		{"node_modules/express/node_modules/qs", "", "qs"},
		{"node_modules/express/node_modules/@scope/pkg", "", "@scope/pkg"},
		{"node_modules/a/node_modules/b/node_modules/c", "", "c"},
		// Edge: bare scoped without nested path.
		{"node_modules/@scope/pkg/node_modules/dep", "", "dep"},
		// Edge: link: deps don't use node_modules paths — trust explicit.
		{"packages/local-pkg", "local-pkg", "local-pkg"},
	}
	for _, c := range cases {
		got := nameFromPath(c.path, c.explicit)
		if got != c.want {
			t.Errorf("nameFromPath(%q, %q): got %q, want %q", c.path, c.explicit, got, c.want)
		}
	}
}

func TestFirstFixVersion(t *testing.T) {
	v := osvVuln{
		Affected: []osvAffected{{
			Ranges: []osvRange{{
				Events: []osvEvent{
					{Introduced: "0"},
					{Fixed: "4.17.21"},
				},
			}},
		}},
	}
	if got := firstFixVersion(v); got != "4.17.21" {
		t.Errorf("got %q want 4.17.21", got)
	}

	if got := firstFixVersion(osvVuln{}); got != "" {
		t.Errorf("got %q want empty", got)
	}
}

func TestBuildFinding_MatchesPythonShape(t *testing.T) {
	v := osvVuln{
		ID:      "GHSA-jf85-cpcp-j695",
		Summary: "Prototype Pollution in lodash",
		Details: "Versions of lodash prior to 4.17.21 are vulnerable to Prototype Pollution.",
		Aliases: []string{"CVE-2020-8203"},
		Affected: []osvAffected{{
			Ranges: []osvRange{{Events: []osvEvent{{Fixed: "4.17.21"}}}},
		}},
	}
	f := buildFinding(resolvedPackage{name: "lodash", version: "4.17.20"}, v, "package-lock.json")

	// FIX-05: identified by the CANONICAL id of the alias set. The CVE is
	// the identifier every downstream tracker agrees on, and OSV carries
	// it here only as an alias of the GHSA record.
	if f.ID != "SEC-DEPS-CVE_2020_8203" {
		t.Errorf("ID: got %q want SEC-DEPS-CVE_2020_8203", f.ID)
	}
	if f.RuleID != "CVE-2020-8203" {
		t.Errorf("RuleID: got %q want CVE-2020-8203", f.RuleID)
	}
	if !strings.Contains(f.Title, "lodash@4.17.20") || !strings.Contains(f.Title, "CVE-2020-8203") {
		t.Errorf("Title shape wrong: %s", f.Title)
	}
	if !strings.Contains(f.Fix, "lodash@4.17.21") {
		t.Errorf("Fix wrong: %s", f.Fix)
	}
	if f.Severity != "HIGH" || f.Confidence != "HIGH" {
		t.Errorf("severity/confidence drift: %s / %s", f.Severity, f.Confidence)
	}
	if f.Category != "deps" || f.Source != "whitebox" {
		t.Errorf("category/source drift: %s / %s", f.Category, f.Source)
	}
	// Same as pip: canonical first, then every other merged id sorted.
	// Nothing is dropped, so an ignore rule pinned to the GHSA id still
	// has something to match after the rename (Rule 3).
	if len(f.References) != 2 || f.References[0] != "CVE-2020-8203" || f.References[1] != "GHSA-jf85-cpcp-j695" {
		t.Errorf("refs wrong: %v", f.References)
	}
}

func TestBuildFinding_ScopedPackage(t *testing.T) {
	v := osvVuln{ID: "GHSA-xyz", Summary: "vuln"}
	f := buildFinding(resolvedPackage{name: "@types/node", version: "18.0.0"}, v, "package-lock.json")
	if !strings.Contains(f.Title, "@types/node@18.0.0") {
		t.Errorf("scoped package in title wrong: %s", f.Title)
	}
}

func TestBuildFinding_NoFixVersion(t *testing.T) {
	v := osvVuln{ID: "GHSA-X", Summary: "no fix"}
	f := buildFinding(resolvedPackage{name: "pkg", version: "1.0"}, v, "package-lock.json")
	if !strings.Contains(f.Fix, "no fix listed") {
		t.Errorf("expected 'no fix listed', got: %s", f.Fix)
	}
}

func TestCache_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	pkg, version := "lodash", "4.17.20"

	if _, ok := readCache(dir, pkg, version); ok {
		t.Fatal("expected cache miss on empty dir")
	}

	want := []osvVuln{{ID: "GHSA-jf85-cpcp-j695", Summary: "test"}}
	writeCache(dir, pkg, version, want)

	got, ok := readCache(dir, pkg, version)
	if !ok {
		t.Fatal("expected cache hit after write")
	}
	if len(got) != 1 || got[0].ID != "GHSA-jf85-cpcp-j695" {
		t.Errorf("cache roundtrip mismatch: %v", got)
	}
}

func TestCache_ScopedPackageFilesystemSafe(t *testing.T) {
	// @scope/name contains a slash — must be normalised before hitting
	// the filesystem.
	dir := t.TempDir()
	writeCache(dir, "@types/node", "18.0.0", []osvVuln{{ID: "X"}})
	got, ok := readCache(dir, "@types/node", "18.0.0")
	if !ok {
		t.Fatal("expected cache hit for scoped package")
	}
	if got[0].ID != "X" {
		t.Errorf("scoped cache value wrong: %v", got)
	}
	// No nested directory should have been created.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			t.Errorf("scoped slash created a directory: %s", e.Name())
		}
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	dir := t.TempDir()
	writeCache(dir, "lodash", "4.17.20", []osvVuln{{ID: "X"}})
	p := cachePath(dir, "lodash", "4.17.20")
	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if _, ok := readCache(dir, "lodash", "4.17.20"); ok {
		t.Fatal("expected cache miss on expired entry")
	}
}

func TestCache_EmptyDirNoOp(t *testing.T) {
	if _, ok := readCache("", "x", "y"); ok {
		t.Error("readCache on empty dir should miss, not hit")
	}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("writeCache on empty dir panicked: %v", r)
		}
	}()
	writeCache("", "x", "y", []osvVuln{{ID: "Z"}})
}

func TestScan_HappyPath_AgainstFakeOSV(t *testing.T) {
	// Stand up a fake OSV.dev that returns one vuln for lodash@4.17.20,
	// zero for everything else. Verifies Scan walks package-lock.json,
	// dispatches per-package queries, maps responses to Findings.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" {
			http.NotFound(w, r)
			return
		}
		var req osvQueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if req.Package.Ecosystem != "npm" {
			http.Error(w, "wrong ecosystem", 400)
			return
		}
		if req.Package.Name == "lodash" && req.Version == "4.17.20" {
			_ = json.NewEncoder(w).Encode(osvQueryResponse{
				Vulns: []osvVuln{{
					ID:      "GHSA-jf85-cpcp-j695",
					Summary: "Prototype Pollution in lodash",
					Affected: []osvAffected{{
						Ranges: []osvRange{{Events: []osvEvent{{Fixed: "4.17.21"}}}},
					}},
				}},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(osvQueryResponse{})
	}))
	defer srv.Close()

	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	lockfile := `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "test", "version": "1.0.0"},
    "node_modules/lodash": {"version": "4.17.20"},
    "node_modules/express": {"version": "4.17.1"}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.ID != "SEC-DEPS-GHSA_jf85_cpcp_j695" {
		t.Errorf("ID drift: %s", f.ID)
	}
	if !strings.Contains(f.Title, "lodash@4.17.20") {
		t.Errorf("Title: %s", f.Title)
	}
}

// TestScan_PerPackageErrorDoesNotKillScan asserts that a per-package
// lookup failure still emits findings for the packages that DID resolve
// (Rule 3), while surfacing a typed *neterr.LookupError naming the one
// package that didn't — Task 7 replaces the old "swallow and return nil"
// posture with an honest partial-failure report.
func TestScan_PerPackageErrorDoesNotKillScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req osvQueryRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Package.Name == "broken" {
			http.Error(w, "boom", 500)
			return
		}
		if req.Package.Name == "lodash" {
			_ = json.NewEncoder(w).Encode(osvQueryResponse{Vulns: []osvVuln{{ID: "X-Y-Z"}}})
			return
		}
		_, _ = w.Write([]byte(`{"vulns":[]}`))
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	lockfile := `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/broken": {"version": "1.0.0"},
    "node_modules/lodash": {"version": "4.17.20"}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), dir)
	var le *neterr.LookupError
	if !errors.As(err, &le) {
		t.Fatalf("expected *neterr.LookupError for the broken package, got %v", err)
	}
	if le.Failed != 1 || le.Total != 2 {
		t.Fatalf("lookup error = %+v, want Failed=1 Total=2", le)
	}
	if len(findings) != 1 || findings[0].ID != "SEC-DEPS-X_Y_Z" {
		t.Fatalf("want 1 finding for lodash, got %v", findings)
	}
}

func TestScan_EmptyPackagesMap(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"),
		[]byte(`{"lockfileVersion": 3, "packages": {"": {"name": "x", "version": "1.0"}}}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("want 0 findings, got %d", len(findings))
	}
}

func TestScan_V1LockfileSurfacesError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"),
		[]byte(`{"lockfileVersion": 1, "dependencies": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Scan(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error on v1 lockfile")
	}
	if !strings.Contains(err.Error(), "parse lockfile") {
		t.Errorf("expected parse-lockfile error, got: %v", err)
	}
}
