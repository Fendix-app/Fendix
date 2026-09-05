package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/neterr"
)

// Sprint 02.5's performance gate: post-sprint Scan against a 150+
// resolved-dep fixture must be ≥4× faster than the pre-sprint
// per-package serial path. We can't load-test against api.osv.dev in
// CI, so the httptest server below sleeps deterministically to simulate
// the real RTT we observe in production:
//
//   - /v1/query (per-package): ~50 ms each (typical small-payload RTT)
//   - /v1/querybatch (up to 100 pkgs): ~100 ms each (larger payload,
//     same single round trip)
//
// Numbers are mock-fast vs. real OSV.dev (which adds ~150-500ms per
// request) but the *ratio* between batch and serial wall-clock under
// these caps is what the gate measures. Mirrors pip's bench in shape
// so the two numbers compare directly.

const (
	benchNpmDeps      = 150
	benchSerialRTTms  = 50
	benchBatchRTTms   = 100
	benchOSVPath      = "/v1/query"
	benchOSVBatchPath = "/v1/querybatch"
)

// newBenchOSVServer simulates an OSV.dev with realistic-ish per-request
// latency. Returns zero vulns for every package — bench measures the
// transport overhead, not the response-decode cost.
func newBenchOSVServer(b *testing.B) *httptest.Server {
	b.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case benchOSVBatchPath:
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Queries []struct {
					Package osvPackage `json:"package"`
					Version string     `json:"version"`
				} `json:"queries"`
			}
			_ = json.Unmarshal(body, &req)
			time.Sleep(benchBatchRTTms * time.Millisecond)
			out := struct {
				Results []struct {
					Vulns []struct {
						ID string `json:"id"`
					} `json:"vulns"`
				} `json:"results"`
			}{Results: make([]struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			}, len(req.Queries))}
			_ = json.NewEncoder(w).Encode(out)
		case benchOSVPath:
			time.Sleep(benchSerialRTTms * time.Millisecond)
			_ = json.NewEncoder(w).Encode(osvQueryResponse{})
		default:
			http.NotFound(w, r)
		}
	}))
}

// writeBenchLockfile writes a 150-package package-lock.json under dir.
// Each package has a unique name so no cache hits dampen the test
// (bench resets HOME to a temp dir, so the OSV cache starts empty
// anyway).
func writeBenchLockfile(b *testing.B, dir string, n int) {
	b.Helper()
	type pkgEntry struct {
		Version string `json:"version"`
	}
	type lock struct {
		LockfileVersion int                 `json:"lockfileVersion"`
		Packages        map[string]pkgEntry `json:"packages"`
	}
	lf := lock{
		LockfileVersion: 3,
		Packages:        make(map[string]pkgEntry, n+1),
	}
	lf.Packages[""] = pkgEntry{Version: "1.0.0"}
	for i := 0; i < n; i++ {
		lf.Packages[fmt.Sprintf("node_modules/benchpkg-%04d", i)] = pkgEntry{Version: "1.0.0"}
	}
	body, err := json.Marshal(lf)
	if err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), body, 0o644); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkNpmDepCVE_Batch measures the post-Sprint-02.5 Scan path
// (batch + concurrency cap). Compare to BenchmarkNpmDepCVE_Serial below.
func BenchmarkNpmDepCVE_Batch(b *testing.B) {
	srv := newBenchOSVServer(b)
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		b.Setenv("HOME", b.TempDir())
		dir := b.TempDir()
		writeBenchLockfile(b, dir, benchNpmDeps)
		b.StartTimer()

		_, err := Scan(context.Background(), dir)
		if err != nil {
			b.Fatalf("Scan: %v", err)
		}
	}
}

// BenchmarkNpmDepCVE_Serial measures the pre-Sprint-02.5 baseline by
// driving the legacy per-package /v1/query path directly via
// runSerialFallback. Same fixture, same fake server, same cache-cold
// setup so the only variable is the transport pattern.
func BenchmarkNpmDepCVE_Serial(b *testing.B) {
	srv := newBenchOSVServer(b)
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		b.Setenv("HOME", b.TempDir())
		dir := b.TempDir()
		writeBenchLockfile(b, dir, benchNpmDeps)
		cache, _ := cacheDir()
		// Construct the chunk the serial path would receive if the
		// batch path were disabled. This isolates the per-package RTT
		// pattern so the bench measures only transport shape.
		chunk := make([]pkgWithManifest, benchNpmDeps)
		for j := 0; j < benchNpmDeps; j++ {
			chunk[j] = pkgWithManifest{
				pkg:      resolvedPackage{name: fmt.Sprintf("benchpkg-%04d", j), version: "1.0.0"},
				manifest: "package-lock.json",
			}
		}
		client := &http.Client{Timeout: httpTimeout}
		b.StartTimer()

		var lf neterr.Failures
		_ = runSerialFallback(context.Background(), client, cache, chunk, &lf)
	}
}
