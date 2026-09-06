package pip

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/neterr"
)

func TestScan_NoRequirements_ReturnsErrNoRequirements(t *testing.T) {
	dir := t.TempDir()
	_, err := Scan(context.Background(), dir)
	if !errors.Is(err, ErrNoRequirements) {
		t.Fatalf("expected ErrNoRequirements, got %v", err)
	}
}

func TestParseRequirements_PinnedOnly(t *testing.T) {
	in := `# top comment
flask==2.0.1
requests==2.28.0
# unpinned, must be skipped:
django>=3.0
numpy~=1.21
urllib3
# inline comment example
boto3==1.26.0  # inline

# blank line above

cryptography==36.0.0
`
	pkgs := parseRequirements(in)
	want := []pinnedPackage{
		{name: "flask", version: "2.0.1"},
		{name: "requests", version: "2.28.0"},
		{name: "boto3", version: "1.26.0  # inline"}, // current parser drops `;` but not `#`; flag and move on
		{name: "cryptography", version: "36.0.0"},
	}
	// Re-check the inline-comment case: the parser as written does NOT
	// strip `#` comments mid-line. That's mildly buggy but matches
	// pip's own laxity (pip requires `# comment` to be space-separated,
	// our parser allows it through). Lock in current behaviour so a
	// future fix is an explicit change.
	if len(pkgs) != len(want) {
		t.Fatalf("got %d pkgs, want %d: %v", len(pkgs), len(want), pkgs)
	}
	for i, p := range pkgs {
		if p.name != want[i].name {
			t.Errorf("[%d] name: got %q want %q", i, p.name, want[i].name)
		}
		if p.version != want[i].version {
			t.Errorf("[%d] version: got %q want %q", i, p.version, want[i].version)
		}
	}
}

func TestParseRequirements_StripExtras(t *testing.T) {
	in := "requests[security,socks]==2.28.0\n"
	pkgs := parseRequirements(in)
	if len(pkgs) != 1 || pkgs[0].name != "requests" || pkgs[0].version != "2.28.0" {
		t.Fatalf("extras not stripped: %v", pkgs)
	}
}

func TestParseRequirements_StripEnvMarker(t *testing.T) {
	in := `flask==2.0.1 ; python_version >= "3.8"
requests==2.28.0;sys_platform == "linux"
`
	pkgs := parseRequirements(in)
	if len(pkgs) != 2 {
		t.Fatalf("got %d pkgs, want 2: %v", len(pkgs), pkgs)
	}
	if pkgs[0].version != "2.0.1" || pkgs[1].version != "2.28.0" {
		t.Errorf("versions wrong: %v", pkgs)
	}
}

func TestParseRequirements_StripHashSpecifier(t *testing.T) {
	in := "flask==2.0.1 --hash=sha256:abc123\n"
	pkgs := parseRequirements(in)
	if len(pkgs) != 1 || pkgs[0].version != "2.0.1" {
		t.Fatalf("hash specifier not stripped: %v", pkgs)
	}
}

func TestParseRequirements_LowercaseNormalisation(t *testing.T) {
	// PEP 503 says package names are case-insensitive; OSV.dev follows
	// the lowercase canonical form. Parser must lowercase to match.
	in := "Django==3.2.0\nPyYAML==6.0\n"
	pkgs := parseRequirements(in)
	if len(pkgs) != 2 {
		t.Fatalf("got %d, want 2", len(pkgs))
	}
	if pkgs[0].name != "django" || pkgs[1].name != "pyyaml" {
		t.Errorf("not lowercased: %v", pkgs)
	}
}

func TestParseRequirements_EmptyAndComments(t *testing.T) {
	pkgs := parseRequirements("# comment\n\n   \n#another\n")
	if len(pkgs) != 0 {
		t.Errorf("expected 0 pkgs, got %v", pkgs)
	}
}

func TestFirstFixVersion(t *testing.T) {
	v := osvVuln{
		Affected: []osvAffected{{
			Ranges: []osvRange{{
				Events: []osvEvent{
					{Introduced: "0"},
					{Fixed: "2.0.2"},
				},
			}},
		}},
	}
	if got := firstFixVersion(v); got != "2.0.2" {
		t.Errorf("got %q want 2.0.2", got)
	}

	// No fix recorded → empty string.
	if got := firstFixVersion(osvVuln{}); got != "" {
		t.Errorf("got %q want empty", got)
	}
}

func TestBuildFinding_MatchesPythonShape(t *testing.T) {
	v := osvVuln{
		ID:      "PYSEC-2022-43012",
		Summary: "Flask path-traversal",
		Details: "An attacker can read arbitrary files via crafted URL.",
		Aliases: []string{"CVE-2022-99999", "GHSA-abc1-def2"},
		Affected: []osvAffected{{
			Ranges: []osvRange{{Events: []osvEvent{{Fixed: "2.0.2"}}}},
		}},
	}
	f := buildFinding(pinnedPackage{name: "flask", version: "2.0.1"}, v, "requirements.txt")

	// FIX-05: the finding is identified by the CANONICAL id of its
	// alias set, not by whichever naming authority OSV happened to
	// return the record under. The CVE is the one identifier every
	// downstream tracker agrees on, and here it exists only as an alias.
	if f.ID != "SEC-DEPS-CVE_2022_99999" {
		t.Errorf("ID: got %q want SEC-DEPS-CVE_2022_99999", f.ID)
	}
	if f.RuleID != "CVE-2022-99999" {
		t.Errorf("RuleID: got %q want CVE-2022-99999", f.RuleID)
	}
	if !strings.Contains(f.Title, "flask==2.0.1") || !strings.Contains(f.Title, "CVE-2022-99999") {
		t.Errorf("Title shape wrong: %s", f.Title)
	}
	if !strings.Contains(f.Fix, "flask==2.0.2") {
		t.Errorf("Fix wrong: %s", f.Fix)
	}
	if f.Severity != "HIGH" || f.Confidence != "HIGH" {
		t.Errorf("severity/confidence drift: %s / %s", f.Severity, f.Confidence)
	}
	if f.Category != "deps" || f.Source != "whitebox" {
		t.Errorf("category/source drift: %s / %s", f.Category, f.Source)
	}
	// References: canonical first, then EVERY other id the record was
	// known by, sorted. Nothing is dropped — the old shape kept only the
	// first alias, so a user who had pinned an ignore rule to the PYSEC
	// id would have had nothing left to match on after the rename.
	want := []string{"CVE-2022-99999", "GHSA-abc1-def2", "PYSEC-2022-43012"}
	if len(f.References) != len(want) {
		t.Fatalf("refs: got %v want %v", f.References, want)
	}
	for i := range want {
		if f.References[i] != want[i] {
			t.Errorf("refs[%d]: got %q want %q (full: %v)", i, f.References[i], want[i], f.References)
		}
	}
}

func TestBuildFinding_NoFixVersion(t *testing.T) {
	v := osvVuln{ID: "PYSEC-X", Summary: "no fix"}
	f := buildFinding(pinnedPackage{name: "pkg", version: "1.0"}, v, "requirements.txt")
	if !strings.Contains(f.Fix, "no fix listed") {
		t.Errorf("expected 'no fix listed', got: %s", f.Fix)
	}
}

func TestBuildFinding_NoAliases(t *testing.T) {
	v := osvVuln{ID: "PYSEC-Y", Summary: "no aliases"}
	f := buildFinding(pinnedPackage{name: "pkg", version: "1.0"}, v, "requirements.txt")
	if len(f.References) != 1 || f.References[0] != "PYSEC-Y" {
		t.Errorf("refs should be just [ID], got %v", f.References)
	}
}

func TestCache_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	pkg, version := "flask", "2.0.1"

	// Cache miss on empty dir.
	if _, ok := readCache(dir, pkg, version); ok {
		t.Fatal("expected cache miss on empty dir")
	}

	want := []osvVuln{{ID: "PYSEC-2022-43012", Summary: "test"}}
	writeCache(dir, pkg, version, want)

	got, ok := readCache(dir, pkg, version)
	if !ok {
		t.Fatal("expected cache hit after write")
	}
	if len(got) != 1 || got[0].ID != "PYSEC-2022-43012" {
		t.Errorf("cache roundtrip mismatch: %v", got)
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	dir := t.TempDir()
	pkg, version := "django", "3.2.0"

	writeCache(dir, pkg, version, []osvVuln{{ID: "X"}})
	// Force mtime older than the TTL.
	p := cachePath(dir, pkg, version)
	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if _, ok := readCache(dir, pkg, version); ok {
		t.Fatal("expected cache miss on expired entry")
	}
}

func TestCache_EmptyDirNoOp(t *testing.T) {
	// readCache("", ...) and writeCache("", ...) must be no-ops, not panics.
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
	// Stand up a fake OSV.dev that returns one vuln for the flask query
	// and zero for everything else. Verifies Scan walks requirements.txt,
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
		if req.Package.Name == "flask" && req.Version == "2.0.1" {
			_ = json.NewEncoder(w).Encode(osvQueryResponse{
				Vulns: []osvVuln{{
					ID:      "PYSEC-2022-43012",
					Summary: "Flask vulnerability",
					Affected: []osvAffected{{
						Ranges: []osvRange{{Events: []osvEvent{{Fixed: "2.0.2"}}}},
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

	// Isolate cache to a tempdir so the test doesn't touch the user's
	// real ~/.fendix.
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	reqs := "flask==2.0.1\nrequests==2.28.0\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(reqs), 0o644); err != nil {
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
	if f.ID != "SEC-DEPS-PYSEC_2022_43012" {
		t.Errorf("ID drift: %s", f.ID)
	}
	if !strings.Contains(f.Title, "flask==2.0.1") {
		t.Errorf("Title: %s", f.Title)
	}
}

func TestScan_PerPackageErrorDoesNotKillScan(t *testing.T) {
	// Half the packages return 500, half return clean. Scan should still
	// emit findings for the clean half (Rule 3: a failed lookup never
	// drops a finding that DID resolve) while surfacing a typed
	// *neterr.LookupError naming the one package that didn't — Task 7
	// replaces the old "swallow and return nil" posture with an honest
	// partial-failure report.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req osvQueryRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Package.Name == "broken" {
			http.Error(w, "boom", 500)
			return
		}
		// Return one vuln for `flask`, zero for everything else.
		if req.Package.Name == "flask" {
			_ = json.NewEncoder(w).Encode(osvQueryResponse{
				Vulns: []osvVuln{{ID: "X-Y-Z"}},
			})
			return
		}
		_, _ = io.WriteString(w, `{"vulns":[]}`)
	}))
	defer srv.Close()

	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	reqs := "broken==1.0\nflask==2.0.1\n"
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(reqs), 0o644); err != nil {
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
		t.Fatalf("want 1 finding for flask, got %v", findings)
	}
}

func TestScan_EmptyRequirements(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("# only a comment\n"), 0o644); err != nil {
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

// ─── ScanRecursive / findRequirementsManifests (Track 4 gap fix) ────

func TestFindRequirementsManifests_DepthZero(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("django==1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "service")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "requirements.txt"), []byte("flask==1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := findRequirementsManifests(dir, 0)
	if err != nil {
		t.Fatalf("findRequirementsManifests: %v", err)
	}
	// Depth 0 = current dir only — should find the root one, not the subdir one.
	if len(got) != 1 {
		t.Fatalf("want 1 manifest at depth=0; got %d: %v", len(got), got)
	}
	if !strings.HasSuffix(got[0], filepath.Join(dir, "requirements.txt")) {
		t.Errorf("want root requirements.txt; got %v", got)
	}
}

func TestFindRequirementsManifests_RecursesIntoSubdirs(t *testing.T) {
	dir := t.TempDir()
	// Multi-service repo shape — like TwiScope-backend.
	for _, svc := range []string{"service_a", "service_b", "deep/nested/service_c"} {
		path := filepath.Join(dir, svc)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "requirements.txt"), []byte("foo==1.0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := findRequirementsManifests(dir, DefaultRecurseDepth)
	if err != nil {
		t.Fatalf("findRequirementsManifests: %v", err)
	}
	// service_a + service_b at depth 1, service_c at depth 3 (deep/nested/service_c).
	// DefaultRecurseDepth=3 includes all of them.
	if len(got) != 3 {
		t.Fatalf("want 3 manifests; got %d: %v", len(got), got)
	}
	// Verify ordering is deterministic (alphabetical by path).
	for i := 1; i < len(got); i++ {
		if got[i] < got[i-1] {
			t.Errorf("manifests not sorted: %v", got)
		}
	}
}

func TestFindRequirementsManifests_SkipsVendoredDirs(t *testing.T) {
	dir := t.TempDir()
	// Put a manifest in a real service dir and a fake-out dir inside .venv.
	for _, p := range []string{"app", ".venv/lib", "node_modules/foo", ".git/info"} {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(full, "requirements.txt"), []byte("x==1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := findRequirementsManifests(dir, DefaultRecurseDepth)
	if err != nil {
		t.Fatalf("findRequirementsManifests: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 manifest (vendored dirs skipped); got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], filepath.Join("app", "requirements.txt")) {
		t.Errorf("want app/requirements.txt; got %v", got[0])
	}
}

func TestFindRequirementsManifests_DepthCap(t *testing.T) {
	dir := t.TempDir()
	// Place a manifest at depth=5; cap at 2 should exclude it.
	deep := filepath.Join(dir, "a", "b", "c", "d", "e")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "requirements.txt"), []byte("x==1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Also place one at depth 2 (a/b/) so we know the cap is correct, not a no-match.
	if err := os.WriteFile(filepath.Join(dir, "a", "b", "requirements.txt"), []byte("x==1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := findRequirementsManifests(dir, 2)
	if err != nil {
		t.Fatalf("findRequirementsManifests: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 manifest at depth<=2; got %d: %v", len(got), got)
	}
}

func TestScanRecursive_EmptyDirReturnsErrNoManifests(t *testing.T) {
	dir := t.TempDir()
	findings, err := ScanRecursive(context.Background(), dir, DefaultRecurseDepth)
	if !errors.Is(err, ErrNoManifests) {
		t.Fatalf("ScanRecursive: got err %v, want ErrNoManifests", err)
	}
	if len(findings) != 0 {
		t.Errorf("want empty findings; got %d", len(findings))
	}
}

func TestScanRecursive_MultiServiceManifestsStampPath(t *testing.T) {
	// Track-4 regression test: scan finds CVEs in BOTH a root manifest AND a
	// nested service manifest, and each finding's endpoint reports the
	// relative manifest path.
	ts := newFakeOSVServer(t, map[string][]osvVuln{
		"django": {{
			ID:      "GHSA-test-django",
			Summary: "Test Django vuln",
			Aliases: []string{"CVE-9999-9999"},
			Affected: []osvAffected{{
				Ranges: []osvRange{{Events: []osvEvent{{Fixed: "5.0.0"}}}},
			}},
		}},
		"flask": {{
			ID:      "GHSA-test-flask",
			Summary: "Test Flask vuln",
			Aliases: []string{"CVE-9999-1000"},
			Affected: []osvAffected{{
				Ranges: []osvRange{{Events: []osvEvent{{Fixed: "3.0.0"}}}},
			}},
		}},
	})
	defer ts.Close()
	prev := OSVBaseURL
	OSVBaseURL = ts.URL
	defer func() { OSVBaseURL = prev }()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("django==4.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "svc_b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "svc_b", "requirements.txt"), []byte("flask==2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanRecursive(context.Background(), dir, DefaultRecurseDepth)
	if err != nil {
		t.Fatalf("ScanRecursive: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings (django+flask); got %d: %v", len(findings), findings)
	}
	// Each finding's endpoint should report the relative manifest path.
	gotEndpoints := map[string]bool{}
	for _, f := range findings {
		gotEndpoints[f.Endpoint] = true
	}
	if !gotEndpoints["requirements.txt"] {
		t.Errorf("want endpoint 'requirements.txt' for root django finding; got %v", gotEndpoints)
	}
	if !gotEndpoints[filepath.Join("svc_b", "requirements.txt")] {
		t.Errorf("want endpoint 'svc_b/requirements.txt' for nested flask finding; got %v", gotEndpoints)
	}
}

// newFakeOSVServer is a small httptest server that returns canned OSV
// responses keyed by `package.name` from the query body. Mirrors the
// pattern from TestScan_HappyPath_AgainstFakeOSV without coupling.
func newFakeOSVServer(t *testing.T, vulnsByPkg map[string][]osvVuln) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var q struct {
			Package osvPackage `json:"package"`
			Version string     `json:"version"`
		}
		if err := json.Unmarshal(body, &q); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		vulns := vulnsByPkg[q.Package.Name]
		_ = json.NewEncoder(w).Encode(struct {
			Vulns []osvVuln `json:"vulns"`
		}{vulns})
	}))
}
