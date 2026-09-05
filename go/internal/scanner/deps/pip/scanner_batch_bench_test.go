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
	"testing"
	"time"
)

// Sprint 02's performance gate: post-sprint scanViaOSV against a 150+
// pinned-dep fixture must be ≥4x faster than the pre-sprint per-package
// serial path. We can't load-test against api.osv.dev in CI, so the
// httptest server below sleeps deterministically to simulate the real
// RTT we observe in production:
//
//   - /v1/query (per-package): ~50 ms each (typical small-payload RTT)
//   - /v1/querybatch (up to 100 pkgs): ~100 ms each (larger payload,
//     same single round trip)
//
// Numbers are mock-fast vs. real OSV.dev (which adds ~150-500ms per
// request) but the *ratio* between batch and serial wall-clock under
// these caps is what the gate measures.

const (
	benchPipDeps      = 150
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

// writeBenchFixture writes a 150-line requirements.txt under a temp dir
// and returns the dir path. Each line is a unique pinned package so no
// cache hits dampen the test (the bench resets HOME to a temp dir, so
// the OSV cache starts empty in any case).
func writeBenchFixture(b *testing.B, dir string, n int) {
	b.Helper()
	lines := make([]string, n)
	for i := 0; i < n; i++ {
		lines[i] = fmt.Sprintf("benchpkg-%04d==1.0.0", i)
	}
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		b.Fatal(err)
	}
}

// BenchmarkPipDepCVE_Batch measures the post-Sprint-02 scanViaOSV path
// (batch + concurrency cap). Compare to BenchmarkPipDepCVE_Serial below.
func BenchmarkPipDepCVE_Batch(b *testing.B) {
	srv := newBenchOSVServer(b)
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Fresh HOME each iteration so cache writes from one iteration
		// don't make subsequent iterations cheat by hitting cache.
		b.Setenv("HOME", b.TempDir())
		dir := b.TempDir()
		writeBenchFixture(b, dir, benchPipDeps)
		b.StartTimer()

		_, err := scanViaOSV(context.Background(), dir, DefaultRecurseDepth)
		if err != nil {
			b.Fatalf("scanViaOSV: %v", err)
		}
	}
}

// BenchmarkPipDepCVE_Serial measures the pre-Sprint-02 baseline by
// driving the legacy per-package /v1/query path directly. Same fixture,
// same fake server, same cache-cold setup so the only variable is the
// transport pattern.
func BenchmarkPipDepCVE_Serial(b *testing.B) {
	srv := newBenchOSVServer(b)
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		b.Setenv("HOME", b.TempDir())
		dir := b.TempDir()
		writeBenchFixture(b, dir, benchPipDeps)
		b.StartTimer()

		// Drive the serial path directly via Scan() (which is the
		// pre-Sprint-02 per-package /v1/query loop, untouched by Sprint 02).
		_, err := Scan(context.Background(), dir)
		if err != nil {
			b.Fatalf("Scan: %v", err)
		}
	}
}
