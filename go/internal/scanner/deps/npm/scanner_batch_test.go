package npm

import (
	"context"
	"encoding/json"
	"errors"
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

	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/neterr"
)

// batchQuery / batchResponse mirror the OSV.dev /v1/querybatch shape so
// the test server can decode requests and emit the documented response.
// queryOSVBatch declares its own shadow types internally; these are the
// test-side duplicates.
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
				// /v1/query is the RICH endpoint the batch path hydrates
				// against, so the canned records carry the summary and
				// fixed range /v1/querybatch omits. Deliberately NO
				// aliases — several tests here pin the finding ID, and an
				// alias would rename it under FIX-05.
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

// writeLockfile writes a minimal v3 package-lock.json at dir/path with
// the given (name, version) pairs as `packages` entries. Each entry is
// keyed by "node_modules/<name>" — the conventional shape parseLockfile
// expects.
func writeLockfile(t *testing.T, dir string, pkgs []resolvedPackage) {
	t.Helper()
	type pkgEntry struct {
		Version string `json:"version"`
	}
	type lock struct {
		LockfileVersion int                 `json:"lockfileVersion"`
		Packages        map[string]pkgEntry `json:"packages"`
	}
	lf := lock{
		LockfileVersion: 3,
		Packages:        map[string]pkgEntry{"": {Version: "1.0.0"}},
	}
	for _, p := range pkgs {
		lf.Packages["node_modules/"+p.name] = pkgEntry{Version: p.version}
	}
	body, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(dir, "package-lock.json")
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestScan_BatchUsedWhenManyPackages asserts the batch path is used for
// cache-miss packages — one /v1/querybatch for the whole chunk — and that
// each VULNERABLE package is then hydrated through /v1/query.
//
// The hydration half is FIX-05/FIX-06 wiring: /v1/querybatch returns bare
// ids, so before it every batch-path finding had an empty description AND
// printed "no fix listed in OSV" even when OSV listed one. The request
// count stays proportional to VULNERABLE packages, not total packages.
func TestScan_BatchUsedWhenManyPackages(t *testing.T) {
	var batchHits, queryHits atomic.Int32
	srv := newFakeOSVBatchServer(t,
		vulnsByKey{
			"lodash@4.17.15": {"GHSA-p6mc-m468-83gw"},
			"minimist@1.2.0": {"GHSA-vh95-rmgr-6w4m"},
		},
		false, &batchHits, &queryHits)
	defer srv.Close()

	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	writeLockfile(t, codeDir, []resolvedPackage{
		{name: "lodash", version: "4.17.15"},
		{name: "minimist", version: "1.2.0"},
		{name: "clean-pkg", version: "1.0.0"},
	})

	findings, err := Scan(context.Background(), codeDir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d: %#v", len(findings), findings)
	}
	if batchHits.Load() != 1 {
		t.Errorf("expected exactly 1 /v1/querybatch hit, got %d", batchHits.Load())
	}
	// One hydration per VULNERABLE package (lodash, minimist) — not one
	// per vuln, and not one per package: clean-pkg is never re-queried.
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

// TestScan_CacheHitsSkipBatch asserts that fully-cached packages do NOT
// trigger any HTTP call. Pre-warm cache with writeCache, then scan with
// a httptest server that fails on ANY hit.
func TestScan_CacheHitsSkipBatch(t *testing.T) {
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

	t.Setenv("HOME", t.TempDir())
	cache, err := cacheDir()
	if err != nil {
		t.Fatalf("cacheDir: %v", err)
	}
	writeCache(cache, "lodash", "4.17.15", []osvVuln{{ID: "GHSA-p6mc-m468-83gw"}})
	writeCache(cache, "minimist", "1.2.0", []osvVuln{{ID: "GHSA-vh95-rmgr-6w4m"}})

	codeDir := t.TempDir()
	writeLockfile(t, codeDir, []resolvedPackage{
		{name: "lodash", version: "4.17.15"},
		{name: "minimist", version: "1.2.0"},
	})

	findings, err := Scan(context.Background(), codeDir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings from cache, got %d", len(findings))
	}
	if batchHits.Load() != 0 || queryHits.Load() != 0 {
		t.Errorf("expected zero HTTP hits on fully-cached scan, got batch=%d query=%d", batchHits.Load(), queryHits.Load())
	}
}

// TestScan_BatchFailureFallsBackToSerial asserts that a 500 from
// /v1/querybatch triggers the per-package serial fallback.
func TestScan_BatchFailureFallsBackToSerial(t *testing.T) {
	var batchHits, queryHits atomic.Int32
	srv := newFakeOSVBatchServer(t,
		vulnsByKey{
			"lodash@4.17.15": {"GHSA-p6mc-m468-83gw"},
		},
		true, &batchHits, &queryHits) // failBatch=true → batch returns 500
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	writeLockfile(t, codeDir, []resolvedPackage{
		{name: "lodash", version: "4.17.15"},
		{name: "express", version: "4.17.1"},
	})

	findings, err := Scan(context.Background(), codeDir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if batchHits.Load() == 0 {
		t.Error("expected batch hit (followed by failure + fallback), got 0")
	}
	if queryHits.Load() == 0 {
		t.Error("expected serial fallback to /v1/query, got 0 hits")
	}
	if len(findings) != 1 || findings[0].ID != "SEC-DEPS-GHSA_p6mc_m468_83gw" {
		t.Fatalf("expected fallback to surface the lodash finding, got %#v", findings)
	}
}

// TestScan_BatchSizeRespected asserts that >100 packages are chunked
// into multiple batches of <=100 each.
func TestScan_BatchSizeRespected(t *testing.T) {
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
	pkgs := make([]resolvedPackage, totalPkgs)
	for i := 0; i < totalPkgs; i++ {
		pkgs[i] = resolvedPackage{name: fmt.Sprintf("pkg-%03d", i), version: "1.0.0"}
	}
	writeLockfile(t, codeDir, pkgs)

	if _, err := Scan(context.Background(), codeDir); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	wantBatches := int32((totalPkgs + osvBatchMaxSize - 1) / osvBatchMaxSize)
	if batchHits.Load() != wantBatches {
		t.Errorf("want %d batches for %d pkgs, got %d", wantBatches, totalPkgs, batchHits.Load())
	}
	if maxBatchSize.Load() > osvBatchMaxSize {
		t.Errorf("a single batch exceeded osvBatchMaxSize=%d (max seen: %d)", osvBatchMaxSize, maxBatchSize.Load())
	}
}

// TestScan_ConcurrencyCapRespected asserts that at most
// osvMaxConcurrentBatches batches are in flight simultaneously.
func TestScan_ConcurrencyCapRespected(t *testing.T) {
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

	// Force enough chunks to exceed the concurrency cap.
	const totalPkgs = osvBatchMaxSize * (osvMaxConcurrentBatches + 2)
	codeDir := t.TempDir()
	pkgs := make([]resolvedPackage, totalPkgs)
	for i := 0; i < totalPkgs; i++ {
		pkgs[i] = resolvedPackage{name: fmt.Sprintf("pkg-%04d", i), version: "1.0.0"}
	}
	writeLockfile(t, codeDir, pkgs)

	if _, err := Scan(context.Background(), codeDir); err != nil {
		t.Fatalf("Scan: %v", err)
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
	_, err := queryOSVBatch(context.Background(), client, []resolvedPackage{
		{name: "lodash", version: "4.17.15"},
		{name: "express", version: "4.17.1"},
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
	pkgs := make([]resolvedPackage, osvBatchMaxSize+1)
	for i := range pkgs {
		pkgs[i] = resolvedPackage{name: fmt.Sprintf("p%d", i), version: "1.0.0"}
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

// TestScan_TotalFailureIsLookupError mirrors the pip scanner's contract:
// when OSV.dev returns 503 on both /v1/querybatch and the per-package
// /v1/query fallback, Scan returns a *neterr.LookupError naming every
// failed lookup instead of a silent "ok" with an empty finding set.
func TestScan_TotalFailureIsLookupError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	writeLockfile(t, codeDir, []resolvedPackage{{name: "lodash", version: "4.17.15"}})

	findings, err := Scan(context.Background(), codeDir)
	var le *neterr.LookupError
	if !errors.As(err, &le) {
		t.Fatalf("expected *neterr.LookupError, got %v", err)
	}
	if le.Failed != 1 || le.Total != 1 || neterr.Classify(err) != neterr.KindNetwork {
		t.Fatalf("lookup error = %+v (kind %v)", le, neterr.Classify(err))
	}
	if len(findings) != 0 {
		t.Fatalf("no lookup succeeded, expected no findings, got %d", len(findings))
	}
}

// TestScan_BatchFailsSerialSucceedsIsNotAnError mirrors the pip
// scanner's contract: a batch-endpoint outage that the serial fallback
// fully recovers from is not reported as a failure — the accumulator
// only counts a package once every fallback for it is exhausted.
func TestScan_BatchFailsSerialSucceedsIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v1/querybatch") {
			http.Error(w, "nope", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulns": []}`))
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	writeLockfile(t, codeDir, []resolvedPackage{{name: "lodash", version: "4.17.15"}})

	if _, err := Scan(context.Background(), codeDir); err != nil {
		t.Fatalf("serial fallback covered every package, expected nil error, got %v", err)
	}
}
