package pip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// batchQuery / batchResponse mirror the OSV.dev /v1/querybatch shape so
// the test server can decode requests and emit the documented response.
// (queryOSVBatch declares its own shadow types internally; these are
// the test-side duplicates so the server doesn't reach into unexported
// implementation types.)
type batchQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type batchRequestEnv struct {
	Queries []batchQuery `json:"queries"`
}

type batchVulnRef struct {
	ID string `json:"id"`
}

type batchResultEntry struct {
	Vulns []batchVulnRef `json:"vulns"`
}

type batchResponseEnv struct {
	Results []batchResultEntry `json:"results"`
}

// vulnsByKey maps "<pkg>@<version>" to the OSV-id list the server should
// echo back. Empty list means "no vulns" — a valid OSV.dev response.
type vulnsByKey map[string][]string

// newFakeOSVBatchServer answers /v1/querybatch from vulnsByKey. Optional
// /v1/query handler covers the serial-fallback path. failBatch controls
// whether the batch endpoint returns 500.
func newFakeOSVBatchServer(t *testing.T, vulns vulnsByKey, failBatch bool, batchHits *atomic.Int32, queryHits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			if batchHits != nil {
				batchHits.Add(1)
			}
			if failBatch {
				http.Error(w, "induced batch failure", http.StatusInternalServerError)
				return
			}
			body, _ := io.ReadAll(r.Body)
			var req batchRequestEnv
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			out := batchResponseEnv{Results: make([]batchResultEntry, len(req.Queries))}
			for i, q := range req.Queries {
				ids := vulns[q.Package.Name+"@"+q.Version]
				refs := make([]batchVulnRef, len(ids))
				for j, id := range ids {
					refs[j] = batchVulnRef{ID: id}
				}
				out.Results[i] = batchResultEntry{Vulns: refs}
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/v1/query":
			if queryHits != nil {
				queryHits.Add(1)
			}
			body, _ := io.ReadAll(r.Body)
			var q struct {
				Package osvPackage `json:"package"`
				Version string     `json:"version"`
			}
			_ = json.Unmarshal(body, &q)
			ids := vulns[q.Package.Name+"@"+q.Version]
			vs := make([]osvVuln, len(ids))
			for i, id := range ids {
				// /v1/query is the RICH endpoint: it is what the batch
				// path hydrates against, so the canned records carry the
				// summary and the fixed range /v1/querybatch omits.
				// Deliberately NO aliases here — several tests in this
				// file pin the finding ID, and an alias would rename it.
				vs[i] = osvVuln{
					ID:      id,
					Summary: "hydrated summary for " + id,
					Affected: []osvAffected{{
						Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: "99.0.0"}}}},
					}},
				}
			}
			_ = json.NewEncoder(w).Encode(osvQueryResponse{Vulns: vs})
		default:
			http.NotFound(w, r)
		}
	}))
}

// writeReqs writes a requirements.txt at dir/path with the given lines.
func writeReqs(t *testing.T, dir, path string, lines ...string) {
	t.Helper()
	full := filepath.Join(dir, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestScanViaOSV_BatchUsedWhenManyPackages asserts the batch path is used
// for cache-miss packages — one /v1/querybatch covering the whole chunk —
// and that each VULNERABLE package is then hydrated through /v1/query.
//
// The hydration half is FIX-05/FIX-06 wiring, not an optimisation regret:
// /v1/querybatch returns bare ids, so before it every batch-path finding
// had an empty description AND printed "no fix listed in OSV" even when
// OSV listed one. The request count stays proportional to VULNERABLE
// packages, not to total packages — clean-pkg costs nothing.
func TestScanViaOSV_BatchUsedWhenManyPackages(t *testing.T) {
	var batchHits, queryHits atomic.Int32
	srv := newFakeOSVBatchServer(t,
		vulnsByKey{
			"flask@2.0.1":     {"PYSEC-2022-43012"},
			"requests@2.20.0": {"PYSEC-2018-91"},
		},
		false, &batchHits, &queryHits)
	defer srv.Close()

	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	writeReqs(t, codeDir, "requirements.txt",
		"flask==2.0.1",
		"requests==2.20.0",
		"clean-pkg==1.0.0",
	)

	findings, err := scanViaOSV(context.Background(), codeDir, DefaultRecurseDepth)
	if err != nil {
		t.Fatalf("scanViaOSV: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d: %#v", len(findings), findings)
	}
	if batchHits.Load() != 1 {
		t.Errorf("expected exactly 1 /v1/querybatch hit, got %d", batchHits.Load())
	}
	// One hydration per VULNERABLE package (flask, requests) — NOT one per
	// vuln and NOT one per package. clean-pkg came back empty and is never
	// re-queried.
	if queryHits.Load() != 2 {
		t.Errorf("expected 1 /v1/query hydration per vulnerable package (2), got %d", queryHits.Load())
	}
	for _, f := range findings {
		if !strings.Contains(f.Evidence, "hydrated summary for") {
			t.Errorf("batch finding has no hydrated description: %q", f.Evidence)
		}
		if !strings.Contains(f.Fix, "99.0.0") {
			t.Errorf("batch finding lost its fix version: %q", f.Fix)
		}
	}
}

// TestScanViaOSV_CacheHitsSkipBatch asserts that fully-cached packages
// do NOT trigger any HTTP call. Pre-warm cache with writeCache, then
// scan with a httptest server that fails on ANY hit.
func TestScanViaOSV_CacheHitsSkipBatch(t *testing.T) {
	var batchHits, queryHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			batchHits.Add(1)
		} else if r.URL.Path == "/v1/query" {
			queryHits.Add(1)
		}
		http.Error(w, "no HTTP should hit on a fully-cached scan", http.StatusInternalServerError)
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()

	// Use a real-on-disk cache dir under HOME to exercise the actual
	// readCache path.
	t.Setenv("HOME", t.TempDir())
	cache, err := cacheDir()
	if err != nil {
		t.Fatalf("cacheDir: %v", err)
	}
	writeCache(cache, "flask", "2.0.1", []osvVuln{{ID: "PYSEC-2022-43012"}})
	writeCache(cache, "requests", "2.20.0", []osvVuln{{ID: "PYSEC-2018-91"}})

	codeDir := t.TempDir()
	writeReqs(t, codeDir, "requirements.txt", "flask==2.0.1", "requests==2.20.0")

	findings, err := scanViaOSV(context.Background(), codeDir, DefaultRecurseDepth)
	if err != nil {
		t.Fatalf("scanViaOSV: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings from cache, got %d", len(findings))
	}
	if batchHits.Load() != 0 || queryHits.Load() != 0 {
		t.Errorf("expected zero HTTP hits on fully-cached scan, got batch=%d query=%d", batchHits.Load(), queryHits.Load())
	}
}

// TestScanViaOSV_BatchFailureFallsBackToSerial asserts that a 500
// from /v1/querybatch triggers the per-package serial fallback.
func TestScanViaOSV_BatchFailureFallsBackToSerial(t *testing.T) {
	var batchHits, queryHits atomic.Int32
	srv := newFakeOSVBatchServer(t,
		vulnsByKey{
			"flask@2.0.1": {"PYSEC-2022-43012"},
		},
		true, &batchHits, &queryHits) // failBatch=true → batch returns 500
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	writeReqs(t, codeDir, "requirements.txt", "flask==2.0.1", "requests==2.28.0")

	findings, err := scanViaOSV(context.Background(), codeDir, DefaultRecurseDepth)
	if err != nil {
		t.Fatalf("scanViaOSV: %v", err)
	}
	if batchHits.Load() == 0 {
		t.Error("expected batch hit (followed by failure + fallback), got 0")
	}
	if queryHits.Load() == 0 {
		t.Error("expected serial fallback to /v1/query, got 0 hits")
	}
	// Serial fallback should still produce the flask finding.
	if len(findings) != 1 || findings[0].ID != "SEC-DEPS-PYSEC_2022_43012" {
		t.Fatalf("expected fallback to surface the flask finding, got %#v", findings)
	}
}

// TestScanViaOSV_BatchSizeRespected asserts that >100 packages are
// chunked into multiple batches of <=100 each.
func TestScanViaOSV_BatchSizeRespected(t *testing.T) {
	const totalPkgs = 250 // expect ceil(250/100) = 3 batches
	var batchHits atomic.Int32
	var maxBatchSize atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			http.NotFound(w, r)
			return
		}
		batchHits.Add(1)
		body, _ := io.ReadAll(r.Body)
		var req batchRequestEnv
		_ = json.Unmarshal(body, &req)
		size := int32(len(req.Queries))
		for {
			cur := maxBatchSize.Load()
			if size <= cur || maxBatchSize.CompareAndSwap(cur, size) {
				break
			}
		}
		out := batchResponseEnv{Results: make([]batchResultEntry, len(req.Queries))}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	lines := make([]string, totalPkgs)
	for i := 0; i < totalPkgs; i++ {
		lines[i] = fmt.Sprintf("pkg-%03d==1.0.0", i)
	}
	writeReqs(t, codeDir, "requirements.txt", lines...)

	if _, err := scanViaOSV(context.Background(), codeDir, DefaultRecurseDepth); err != nil {
		t.Fatalf("scanViaOSV: %v", err)
	}
	wantBatches := int32((totalPkgs + osvBatchMaxSize - 1) / osvBatchMaxSize)
	if batchHits.Load() != wantBatches {
		t.Errorf("want %d batches for %d pkgs, got %d", wantBatches, totalPkgs, batchHits.Load())
	}
	if maxBatchSize.Load() > osvBatchMaxSize {
		t.Errorf("a single batch exceeded osvBatchMaxSize=%d (max seen: %d)", osvBatchMaxSize, maxBatchSize.Load())
	}
}

// TestScanViaOSV_ConcurrencyCapRespected asserts that at most
// osvMaxConcurrentBatches batches are in flight simultaneously.
func TestScanViaOSV_ConcurrencyCapRespected(t *testing.T) {
	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	var mu sync.Mutex
	const holdMS = 80

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			http.NotFound(w, r)
			return
		}
		cur := inFlight.Add(1)
		mu.Lock()
		if cur > maxInFlight.Load() {
			maxInFlight.Store(cur)
		}
		mu.Unlock()
		// Hold the connection so concurrent requests have a chance to
		// land while this one is still in-flight.
		time.Sleep(time.Duration(holdMS) * time.Millisecond)
		inFlight.Add(-1)

		body, _ := io.ReadAll(r.Body)
		var req batchRequestEnv
		_ = json.Unmarshal(body, &req)
		out := batchResponseEnv{Results: make([]batchResultEntry, len(req.Queries))}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	// Force enough chunks to exceed the concurrency cap (cap=4 → use ≥6
	// chunks worth of pkgs so at least 2 chunks must wait).
	const totalPkgs = osvBatchMaxSize * (osvMaxConcurrentBatches + 2)
	codeDir := t.TempDir()
	lines := make([]string, totalPkgs)
	for i := 0; i < totalPkgs; i++ {
		lines[i] = fmt.Sprintf("pkg-%04d==1.0.0", i)
	}
	writeReqs(t, codeDir, "requirements.txt", lines...)

	if _, err := scanViaOSV(context.Background(), codeDir, DefaultRecurseDepth); err != nil {
		t.Fatalf("scanViaOSV: %v", err)
	}
	if got := maxInFlight.Load(); got > osvMaxConcurrentBatches {
		t.Errorf("max concurrent batches = %d, want <= %d", got, osvMaxConcurrentBatches)
	}
}

// TestQueryOSVBatch_LengthMismatchErrors asserts that a misbehaving
// OSV.dev (returns fewer results than queries) produces a clean error,
// not a panic.
func TestQueryOSVBatch_LengthMismatchErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return zero results regardless of how many queries.
		_ = json.NewEncoder(w).Encode(batchResponseEnv{Results: nil})
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()

	client := &http.Client{Timeout: httpTimeout}
	_, err := queryOSVBatch(context.Background(), client, []pinnedPackage{
		{name: "flask", version: "2.0.1"},
		{name: "requests", version: "2.28.0"},
	})
	if err == nil {
		t.Fatal("expected error on length mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "length mismatch") {
		t.Errorf("error should mention length mismatch: %v", err)
	}
}

// TestQueryOSVBatch_ExceedingMaxSizeErrors asserts the boundary: callers
// must chunk before invoking; queryOSVBatch refuses to send oversize.
func TestQueryOSVBatch_ExceedingMaxSizeErrors(t *testing.T) {
	pkgs := make([]pinnedPackage, osvBatchMaxSize+1)
	for i := range pkgs {
		pkgs[i] = pinnedPackage{name: fmt.Sprintf("p%d", i), version: "1.0.0"}
	}
	client := &http.Client{Timeout: httpTimeout}
	_, err := queryOSVBatch(context.Background(), client, pkgs)
	if err == nil {
		t.Fatal("expected error on oversize batch, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds OSV.dev limit") {
		t.Errorf("error should mention the OSV.dev limit: %v", err)
	}
}
