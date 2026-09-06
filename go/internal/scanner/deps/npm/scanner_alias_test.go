package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

// captureStderr captures os.Stderr writes during fn(). Mirrors the pip
// package's helper — the two deps scanners are deliberately independent
// packages, so the helper is duplicated rather than shared.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	w.Close()
	os.Stderr = orig
	return <-done
}

// lodashOSVRecords is the npm shape of the FIX-05 bug: OSV returns the
// GHSA record and the CVE-named record for one prototype-pollution bug as
// two separate vulns[] entries, so one lockfile pin was reported twice.
func lodashOSVRecords() []osvVuln {
	eco := func(fixed string) []osvAffected {
		return []osvAffected{{Ranges: []osvRange{{
			Type:   "ECOSYSTEM",
			Events: []osvEvent{{Introduced: "0"}, {Fixed: fixed}},
		}}}}
	}
	return []osvVuln{
		{ID: "GHSA-jf85-cpcp-j695", Summary: "Prototype pollution in lodash",
			Aliases: []string{"CVE-2020-8203"}, Affected: eco("4.17.21")},
		{ID: "CVE-2020-8203", Summary: "Prototype pollution in lodash",
			Aliases: []string{"GHSA-jf85-cpcp-j695"}, Affected: eco("4.17.21")},
	}
}

func TestAliasComponents_NpmMergesGhsaAndCve(t *testing.T) {
	got := buildFindings(resolvedPackage{name: "lodash", version: "4.17.20"},
		lodashOSVRecords(), "package-lock.json")
	if len(got) != 1 {
		t.Fatalf("got %d findings; want 1 — two records, one vulnerability", len(got))
	}
	if got[0].ID != "SEC-DEPS-CVE_2020_8203" {
		t.Errorf("ID = %q; want the canonical CVE", got[0].ID)
	}
	want := []string{"CVE-2020-8203", "GHSA-jf85-cpcp-j695"}
	if !reflect.DeepEqual(got[0].References, want) {
		t.Errorf("References = %v; want %v (canonical first, remainder sorted)", got[0].References, want)
	}
	if !strings.Contains(got[0].Fix, "lodash@4.17.21") {
		t.Errorf("Fix = %q; want lodash@4.17.21", got[0].Fix)
	}
}

// TestCanonicalID_ScopedPackageUnaffected: the canonical-id rule ranges
// over advisory ids, never over package names, so a scoped package name
// (which contains both '@' and '/') cannot perturb it.
func TestCanonicalID_ScopedPackageUnaffected(t *testing.T) {
	v := osvVuln{ID: "GHSA-scoped-xyz", Aliases: []string{"CVE-2026-4242"}}
	f := buildFinding(resolvedPackage{name: "@scope/pkg", version: "1.0.0"}, v, "package-lock.json")
	if f.ID != "SEC-DEPS-CVE_2026_4242" {
		t.Errorf("ID = %q; want SEC-DEPS-CVE_2026_4242", f.ID)
	}
	if !strings.Contains(f.Title, "@scope/pkg@1.0.0") {
		t.Errorf("scoped package name mangled in the title: %s", f.Title)
	}
}

func TestAliasComponents_DisjointRangesRefuseToMerge(t *testing.T) {
	a := osvVuln{ID: "GHSA-aaaa", Aliases: []string{"CVE-2026-0001"},
		Affected: []osvAffected{{Ranges: []osvRange{{Type: "ECOSYSTEM",
			Events: []osvEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}}}}
	b := osvVuln{ID: "CVE-2026-0001",
		Affected: []osvAffected{{Ranges: []osvRange{{Type: "ECOSYSTEM",
			Events: []osvEvent{{Introduced: "3.0.0"}, {Fixed: "4.0.0"}}}}}}}

	var got [][]osvVuln
	stderr := captureStderr(t, func() { got = aliasComponents([]osvVuln{a, b}) })
	if len(got) != 2 {
		t.Fatalf("got %d components; want 2 — a bad alias edge must not merge disjoint advisories", len(got))
	}
	if !strings.Contains(stderr, "refusing to merge alias-linked advisories") {
		t.Errorf("expected the refusal on stderr; got %q", stderr)
	}
}

func TestAliasComponents_DeterministicAcrossShuffles(t *testing.T) {
	records := append(lodashOSVRecords(), osvVuln{
		ID: "GHSA-unrelated", Aliases: []string{"CVE-2026-9999"},
		Affected: []osvAffected{{Ranges: []osvRange{{Type: "ECOSYSTEM",
			Events: []osvEvent{{Introduced: "0"}, {Fixed: "5.0.0"}}}}}},
	})
	pkg := resolvedPackage{name: "lodash", version: "4.17.20"}
	want := buildFindings(pkg, records, "package-lock.json")
	if len(want) != 2 {
		t.Fatalf("fixture should yield 2 components, got %d", len(want))
	}

	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 50; i++ {
		shuffled := append([]osvVuln(nil), records...)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		if got := buildFindings(pkg, shuffled, "package-lock.json"); !reflect.DeepEqual(got, want) {
			t.Fatalf("permutation %d produced different findings\n got=%+v\nwant=%+v", i, got, want)
		}
	}
}

// TestBatchPathHydratesAliasesAndFix covers the DEFAULT route: without
// hydration, /v1/querybatch's bare-id records leave FIX-05 and FIX-06 dead
// on the only path most scans take.
func TestBatchPathHydratesAliasesAndFix(t *testing.T) {
	var batchHits, queryHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			batchHits.Add(1)
			var req batchRequestEnv
			_ = json.NewDecoder(r.Body).Decode(&req)
			out := batchResponseEnv{Results: make([]batchResultEntry, len(req.Queries))}
			for i, q := range req.Queries {
				if q.Package.Name != "lodash" {
					continue
				}
				refs := make([]batchVulnRef, 0, 2)
				for _, v := range lodashOSVRecords() {
					refs = append(refs, batchVulnRef{ID: v.ID})
				}
				out.Results[i] = batchResultEntry{Vulns: refs}
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/v1/query":
			queryHits.Add(1)
			var q osvQueryRequest
			_ = json.NewDecoder(r.Body).Decode(&q)
			if q.Package.Name == "lodash" {
				_ = json.NewEncoder(w).Encode(osvQueryResponse{Vulns: lodashOSVRecords()})
				return
			}
			_ = json.NewEncoder(w).Encode(osvQueryResponse{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	writeLockfile(t, codeDir, []resolvedPackage{
		{name: "lodash", version: "4.17.20"},
		{name: "clean-pkg", version: "1.0.0"},
	})

	findings, err := Scan(context.Background(), codeDir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings; want 1 — the batch path must merge like the serial one", len(findings))
	}
	if batchHits.Load() != 1 {
		t.Errorf("batch hits = %d; want 1", batchHits.Load())
	}
	// One hydration for the one VULNERABLE package; clean-pkg costs nothing.
	if queryHits.Load() != 1 {
		t.Errorf("query hits = %d; want exactly 1 — hydration is per vulnerable PACKAGE", queryHits.Load())
	}
	if findings[0].ID != "SEC-DEPS-CVE_2020_8203" {
		t.Errorf("finding %q did not get its aliases: the batch record has no CVE", findings[0].ID)
	}
	if strings.Contains(findings[0].Fix, "no fix listed") {
		t.Errorf("finding still prints the no-fix sentinel after hydration: %q", findings[0].Fix)
	}
}

// TestCache_LegacyBareArrayIsAMiss: a pre-FIX-05 binary wrote a bare
// []osvVuln array whose alias/affected content depended on which path
// filled it. Serving one now would mean an upgraded user sees no change
// for a day and then a partial one.
func TestCache_LegacyBareArrayIsAMiss(t *testing.T) {
	dir := t.TempDir()
	legacy := `[{"id":"GHSA-jf85-cpcp-j695","summary":"legacy shape"}]`
	if err := os.WriteFile(cachePath(dir, "lodash", "4.17.20"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := readCache(dir, "lodash", "4.17.20"); ok {
		t.Errorf("legacy v1 cache file was served as a hit: %+v", got)
	}
}

func TestCache_EnvelopeRoundTripPreservesAliasesAndRanges(t *testing.T) {
	dir := t.TempDir()
	want := lodashOSVRecords()
	writeCache(dir, "lodash", "4.17.20", want)

	got, ok := readCache(dir, "lodash", "4.17.20")
	if !ok {
		t.Fatal("expected a cache hit after write")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cache round trip lost data:\n got=%+v\nwant=%+v", got, want)
	}
	if len(buildFindings(resolvedPackage{name: "lodash", version: "4.17.20"}, got, "package-lock.json")) != 1 {
		t.Error("a cached record set no longer merges into 1 finding")
	}
}
