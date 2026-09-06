package pip

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
)

// ─── Verified ground truth (DECISIONS.md D10, live OSV.dev) ─────────────
//
// cryptography==48.0.1 returns SIX vulns[] entries — three GHSA records
// and three PYSEC records — which are THREE real vulnerabilities. The CVE
// ids appear ONLY as aliases and never as a record's top-level `id`, which
// is exactly why the canonical picker has to range over aliases.

func cryptographyOSVRecords() []osvVuln {
	eco := func(fixed string) []osvAffected {
		return []osvAffected{{Ranges: []osvRange{{
			Type:   "ECOSYSTEM",
			Events: []osvEvent{{Introduced: "0"}, {Fixed: fixed}},
		}}}}
	}
	return []osvVuln{
		{ID: "GHSA-g6cj-pr64-35w5", Summary: "Bleichenbacher timing oracle",
			Aliases: []string{"CVE-2026-69247", "PYSEC-2026-3552"}, Affected: eco("50.0.0")},
		{ID: "GHSA-jwv3-5hgf-82ww", Summary: "NULL deref parsing a PKCS#7 blob",
			Aliases: []string{"CVE-2026-69248", "PYSEC-2026-3553"}, Affected: eco("49.0.0")},
		{ID: "GHSA-m2h6-j472-rp4c", Summary: "Buffer overflow in the X.509 parser",
			Aliases: []string{"CVE-2026-69249", "PYSEC-2026-3554"}, Affected: eco("49.0.0")},
		{ID: "PYSEC-2026-3552", Summary: "Bleichenbacher timing oracle",
			Aliases: []string{"CVE-2026-69247", "GHSA-g6cj-pr64-35w5"}, Affected: eco("50.0.0")},
		{ID: "PYSEC-2026-3553", Summary: "NULL deref parsing a PKCS#7 blob",
			Aliases: []string{"CVE-2026-69248", "GHSA-jwv3-5hgf-82ww"}, Affected: eco("49.0.0")},
		{ID: "PYSEC-2026-3554", Summary: "Buffer overflow in the X.509 parser",
			Aliases: []string{"CVE-2026-69249", "GHSA-m2h6-j472-rp4c"}, Affected: eco("49.0.0")},
	}
}

// djangoOSVRecords is the single django==5.2.16 record: one advisory,
// two patched branches, a BIT-* alias riding along with the CVE.
func djangoOSVRecords() []osvVuln {
	return []osvVuln{{
		ID:      "PYSEC-2026-3717",
		Summary: "Django DoS in the template engine",
		Aliases: []string{"BIT-django-2026-15830", "CVE-2026-15830"},
		Affected: []osvAffected{{Ranges: []osvRange{{
			Type: "ECOSYSTEM",
			Events: []osvEvent{
				{Introduced: "0"}, {Fixed: "5.2.17"},
				{Introduced: "6.0"}, {Fixed: "6.0.8"},
			},
		}}}},
	}}
}

// TestAliasComponents_CryptographySixRecordsToThree is the FIX-05
// headline: six OSV records, three vulnerabilities, three findings.
func TestAliasComponents_CryptographySixRecordsToThree(t *testing.T) {
	got := buildFindings(pinnedPackage{name: "cryptography", version: "48.0.1"},
		cryptographyOSVRecords(), "requirements.txt")

	if len(got) != 3 {
		ids := make([]string, len(got))
		for i, f := range got {
			ids[i] = f.ID
		}
		t.Fatalf("got %d findings %v; want 3 — six records are three vulnerabilities", len(got), ids)
	}
	wantIDs := []string{"SEC-DEPS-CVE_2026_69247", "SEC-DEPS-CVE_2026_69248", "SEC-DEPS-CVE_2026_69249"}
	wantFix := []string{"50.0.0", "49.0.0", "49.0.0"}
	for i, f := range got {
		if f.ID != wantIDs[i] {
			t.Errorf("[%d] ID = %q; want %q", i, f.ID, wantIDs[i])
		}
		if !strings.Contains(f.Fix, "cryptography=="+wantFix[i]) {
			t.Errorf("[%d] Fix = %q; want cryptography==%s", i, f.Fix, wantFix[i])
		}
		// Every record that merged in is still findable (Rule 3).
		if len(f.References) != 3 {
			t.Errorf("[%d] References = %v; want the CVE plus both merged record ids", i, f.References)
		}
	}
}

// TestCanonicalID_PrefersCVEFoundOnlyInAliases guards the exact trap the
// verified data sets: no record's top-level `id` is a CVE, so a picker
// that inspected v.ID alone would never select one and the whole tier
// table would be dead code.
func TestCanonicalID_PrefersCVEFoundOnlyInAliases(t *testing.T) {
	for _, v := range cryptographyOSVRecords() {
		if strings.HasPrefix(v.ID, "CVE-") {
			t.Fatalf("fixture drift: %q is a top-level CVE, which defeats the point of this test", v.ID)
		}
	}
	ids := componentIDs(cryptographyOSVRecords()[:1])
	if got := canonicalID(ids); got != "CVE-2026-69247" {
		t.Errorf("canonicalID(%v) = %q; want CVE-2026-69247", ids, got)
	}
}

// TestCanonicalID_BITPrefixIsOther pins the django case. BIT-* is a real
// OSV alias prefix, and any looser prefix test would promote it past the
// PYSEC id that should win when no CVE is present.
func TestCanonicalID_BITPrefixIsOther(t *testing.T) {
	if got := canonicalID([]string{"BIT-django-2026-15830", "PYSEC-2026-3717"}); got != "PYSEC-2026-3717" {
		t.Errorf("canonicalID = %q; want PYSEC-2026-3717 — BIT-* belongs in the 'other' tier", got)
	}
	// With the CVE present the CVE still wins, BIT-* notwithstanding.
	if got := canonicalID([]string{"BIT-django-2026-15830", "PYSEC-2026-3717", "CVE-2026-15830"}); got != "CVE-2026-15830" {
		t.Errorf("canonicalID = %q; want CVE-2026-15830", got)
	}
}

func TestCanonicalID_TieBreakIsLexicographic(t *testing.T) {
	ids := []string{"GHSA-zzzz-zzzz-zzzz", "GHSA-aaaa-aaaa-aaaa", "GHSA-mmmm-mmmm-mmmm"}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 100; i++ {
		shuffled := append([]string(nil), ids...)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		if got := canonicalID(shuffled); got != "GHSA-aaaa-aaaa-aaaa" {
			t.Fatalf("canonicalID(%v) = %q; want the lexicographically smallest in-tier id", shuffled, got)
		}
	}
}

func TestBuildFindings_ReferencesCanonicalFirstThenSorted(t *testing.T) {
	got := buildFindings(pinnedPackage{name: "django", version: "5.2.16"},
		djangoOSVRecords(), "requirements.txt")
	if len(got) != 1 {
		t.Fatalf("got %d findings; want 1", len(got))
	}
	want := []string{"CVE-2026-15830", "BIT-django-2026-15830", "PYSEC-2026-3717"}
	if !reflect.DeepEqual(got[0].References, want) {
		t.Errorf("References = %v; want %v (canonical first, remainder sorted)", got[0].References, want)
	}
	// This is a SCANNER-package contract only: engine.Deduplicate re-sorts
	// References unconditionally, so no report-level test may assert it.
	if got[0].References[0] != got[0].RuleID {
		t.Errorf("References[0] (%q) and RuleID (%q) disagree on the canonical id",
			got[0].References[0], got[0].RuleID)
	}
}

// TestAliasComponents_DisjointRangesRefuseToMerge covers the bad-alias
// guard. Alias data is contributed by many authorities and is not
// verified; two records whose affected windows cannot both describe one
// bug are kept apart and the refusal is logged.
//
// Honest note: on every live path both records were returned BECAUSE OSV
// matched them against the same installed version, so their ranges
// necessarily overlap. This is reachable only for a multi-ecosystem
// advisory whose per-ecosystem `affected` entries diverge.
func TestAliasComponents_DisjointRangesRefuseToMerge(t *testing.T) {
	a := osvVuln{ID: "GHSA-aaaa", Aliases: []string{"CVE-2026-0001"},
		Affected: []osvAffected{{Ranges: []osvRange{{Type: "ECOSYSTEM",
			Events: []osvEvent{{Introduced: "1.0.0"}, {Fixed: "2.0.0"}}}}}}}
	b := osvVuln{ID: "PYSEC-2026-0001", Aliases: []string{"CVE-2026-0001"},
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
	// Both survive as findings, un-suppressed (Rule 3).
	findings := buildFindings(pinnedPackage{name: "pkg", version: "1.5.0"}, []osvVuln{a, b}, "requirements.txt")
	if len(findings) != 2 {
		t.Errorf("got %d findings; want 2", len(findings))
	}
}

// TestAliasComponents_UnknownRangesStillMerge pins the direction of the
// guard: merge-unless-PROVEN-disjoint. An advisory with only a GIT range
// carries no comparable version window, which is not evidence that the
// two are different bugs.
func TestAliasComponents_UnknownRangesStillMerge(t *testing.T) {
	a := osvVuln{ID: "GHSA-aaaa", Aliases: []string{"CVE-2026-0002"},
		Affected: []osvAffected{{Ranges: []osvRange{{Type: "GIT",
			Events: []osvEvent{{Fixed: "8f1d2c3b4a59607e6c1f0dd0d2a1b9e77c3d4a51"}}}}}}}
	b := osvVuln{ID: "PYSEC-2026-0002", Aliases: []string{"CVE-2026-0002"},
		Affected: []osvAffected{{Ranges: []osvRange{{Type: "ECOSYSTEM",
			Events: []osvEvent{{Introduced: "0"}, {Fixed: "2.0.0"}}}}}}}

	if got := aliasComponents([]osvVuln{a, b}); len(got) != 1 {
		t.Fatalf("got %d components; want 1 — an unrankable range is not proof of disjointness", len(got))
	}
}

// TestAliasComponents_DeterministicAcrossShuffles is the Rule 8 gate: the
// partition, the member order and the rendered findings must all be a pure
// function of the input SET, never of OSV's response ordering.
func TestAliasComponents_DeterministicAcrossShuffles(t *testing.T) {
	records := cryptographyOSVRecords()
	pkg := pinnedPackage{name: "cryptography", version: "48.0.1"}
	want := buildFindings(pkg, records, "requirements.txt")

	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 50; i++ {
		shuffled := append([]osvVuln(nil), records...)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		got := buildFindings(pkg, shuffled, "requirements.txt")
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("permutation %d produced different findings\n got=%+v\nwant=%+v", i, got, want)
		}
	}
}

// TestScan_AcceptanceCryptographyPlusDjango is the end-to-end acceptance
// case: cryptography (3 vulnerabilities across 6 records) + django (1) is
// exactly FOUR dependency findings, each naming its canonical CVE, each
// with the correct minimal upgrade target, and no commit SHA anywhere.
func TestScan_AcceptanceCryptographyPlusDjango(t *testing.T) {
	ts := newFakeOSVServer(t, map[string][]osvVuln{
		"cryptography": cryptographyOSVRecords(),
		"django":       djangoOSVRecords(),
	})
	defer ts.Close()
	prev := OSVBaseURL
	OSVBaseURL = ts.URL
	defer func() { OSVBaseURL = prev }()
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"),
		[]byte("cryptography==48.0.1\ndjango==5.2.16\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 4 {
		ids := make([]string, len(findings))
		for i, f := range findings {
			ids[i] = f.ID
		}
		t.Fatalf("got %d findings %v; want exactly 4 (cryptography 3 + django 1)", len(findings), ids)
	}

	wantFix := map[string]string{
		"SEC-DEPS-CVE_2026_15830": "django==5.2.17", // NOT 6.0.8 — minimal in-branch
		"SEC-DEPS-CVE_2026_69247": "cryptography==50.0.0",
		"SEC-DEPS-CVE_2026_69248": "cryptography==49.0.0",
		"SEC-DEPS-CVE_2026_69249": "cryptography==49.0.0",
	}
	for _, f := range findings {
		want, ok := wantFix[f.ID]
		if !ok {
			t.Errorf("unexpected finding id %q", f.ID)
			continue
		}
		if !strings.Contains(f.Fix, want) {
			t.Errorf("%s: Fix = %q; want it to name %s", f.ID, f.Fix, want)
		}
		if strings.Contains(f.Fix, "6.0.8") {
			t.Errorf("%s recommended a major-version jump: %q", f.ID, f.Fix)
		}
		// No commit SHA may reach any fix text (FIX-06).
		for _, word := range strings.Fields(f.Fix) {
			trimmed := strings.Trim(word, ".,")
			if len(trimmed) == 40 && !strings.ContainsAny(trimmed, ".=@") {
				t.Errorf("%s: %q looks like a commit SHA in the fix text", f.ID, trimmed)
			}
		}
		if len(f.References) < 2 {
			t.Errorf("%s: References = %v; the merged ids must be preserved", f.ID, f.References)
		}
	}
}

// ─── batch-path hydration ───────────────────────────────────────────────

// TestBatchPathHydratesAliasesAndFix covers the DEFAULT route. Left alone,
// /v1/querybatch's bare-id records would have made FIX-05 and FIX-06 dead
// code on the only path most scans take.
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
				if q.Package.Name != "cryptography" {
					continue
				}
				// The batch endpoint knows only the ids — all SIX of them.
				refs := make([]batchVulnRef, 0, 6)
				for _, v := range cryptographyOSVRecords() {
					refs = append(refs, batchVulnRef{ID: v.ID})
				}
				out.Results[i] = batchResultEntry{Vulns: refs}
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/v1/query":
			queryHits.Add(1)
			var q osvQueryRequest
			_ = json.NewDecoder(r.Body).Decode(&q)
			if q.Package.Name == "cryptography" {
				_ = json.NewEncoder(w).Encode(osvQueryResponse{Vulns: cryptographyOSVRecords()})
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
	writeReqs(t, codeDir, "requirements.txt", "cryptography==48.0.1", "clean-pkg==1.0.0")

	findings, err := scanViaOSV(context.Background(), codeDir, DefaultRecurseDepth)
	if err != nil {
		t.Fatalf("scanViaOSV: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("got %d findings; want 3 — the batch path must merge like the serial one", len(findings))
	}
	if batchHits.Load() != 1 {
		t.Errorf("batch hits = %d; want 1", batchHits.Load())
	}
	// ONE hydration for the one VULNERABLE package — not six (one per
	// vuln) and not two (one per package).
	if queryHits.Load() != 1 {
		t.Errorf("query hits = %d; want exactly 1 — hydration is per vulnerable PACKAGE", queryHits.Load())
	}
	for _, f := range findings {
		if !strings.HasPrefix(f.ID, "SEC-DEPS-CVE_") {
			t.Errorf("finding %q did not get its aliases: the batch record has no CVE", f.ID)
		}
		if strings.Contains(f.Fix, "no fix listed") {
			t.Errorf("finding %q still prints the no-fix sentinel after hydration: %q", f.ID, f.Fix)
		}
	}
}

// TestBatchPathHydrationFailureKeepsDegradedFinding is Rule 3 on the
// hydration path: a /v1/query outage after a successful batch must not
// silently drop a vulnerability. It degrades — bare id, no fix — and says
// so on stderr.
func TestBatchPathHydrationFailureKeepsDegradedFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var req batchRequestEnv
			_ = json.NewDecoder(r.Body).Decode(&req)
			out := batchResponseEnv{Results: make([]batchResultEntry, len(req.Queries))}
			for i, q := range req.Queries {
				if q.Package.Name == "flask" {
					out.Results[i] = batchResultEntry{Vulns: []batchVulnRef{{ID: "PYSEC-2022-43012"}}}
				}
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/v1/query":
			http.Error(w, "hydration outage", http.StatusInternalServerError)
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
	writeReqs(t, codeDir, "requirements.txt", "flask==2.0.1")

	var findings []evidence.Evidence
	stderr := captureStderr(t, func() {
		fs, err := scanViaOSV(context.Background(), codeDir, DefaultRecurseDepth)
		if err != nil {
			t.Errorf("scanViaOSV: %v", err)
		}
		findings = fs
	})
	if got := len(findings); got != 1 {
		t.Fatalf("got %d findings; want 1 — a hydration failure must never drop a vulnerability", got)
	}
	// It degrades to the bare batch record rather than vanishing.
	if findings[0].ID != "SEC-DEPS-PYSEC_2022_43012" {
		t.Errorf("degraded finding id = %q; want the bare batch id", findings[0].ID)
	}
	if !strings.Contains(findings[0].Fix, "no fix listed") {
		t.Errorf("degraded finding should print the honest no-fix sentinel; got %q", findings[0].Fix)
	}
	if !strings.Contains(stderr, "hydration for flask==2.0.1 failed") {
		t.Errorf("expected the hydration failure on stderr; got %q", stderr)
	}

	// And it must NOT have poisoned the cache: a degraded record cached
	// under the current schema would be served to EVERY path for 24h.
	cache, err := cacheDir()
	if err != nil {
		t.Fatalf("cacheDir: %v", err)
	}
	if _, ok := readCache(cache, "flask", "2.0.1"); ok {
		t.Error("a degraded batch record was cached; the next scan would serve it for 24h")
	}
}

// ─── cache shape versioning ─────────────────────────────────────────────

// TestCache_LegacyBareArrayIsAMiss: a pre-FIX-05 binary wrote a bare
// []osvVuln array whose alias/affected content depended on which path
// filled it. Serving one now would mean an upgraded user sees no change
// for a day and then a partial one.
func TestCache_LegacyBareArrayIsAMiss(t *testing.T) {
	dir := t.TempDir()
	legacy := `[{"id":"PYSEC-2022-43012","summary":"legacy shape"}]`
	if err := os.WriteFile(cachePath(dir, "flask", "2.0.1"), []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := readCache(dir, "flask", "2.0.1"); ok {
		t.Errorf("legacy v1 cache file was served as a hit: %+v", got)
	}
}

func TestCache_EnvelopeRoundTripPreservesAliasesAndRanges(t *testing.T) {
	dir := t.TempDir()
	want := cryptographyOSVRecords()
	writeCache(dir, "cryptography", "48.0.1", want)

	got, ok := readCache(dir, "cryptography", "48.0.1")
	if !ok {
		t.Fatal("expected a cache hit after write")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cache round trip lost data:\n got=%+v\nwant=%+v", got, want)
	}
	// The whole point: aliases and ranges survive, so a cache-hit scan
	// merges and ranks exactly like a fresh one.
	if len(buildFindings(pinnedPackage{name: "cryptography", version: "48.0.1"}, got, "requirements.txt")) != 3 {
		t.Error("a cached record set no longer merges into 3 findings")
	}
	if fmt.Sprint(got[0].Affected) == "[]" {
		t.Error("affected ranges were dropped by the cache round trip")
	}
}
