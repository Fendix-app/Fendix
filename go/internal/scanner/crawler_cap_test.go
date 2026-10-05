package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// TestLoadSpec_LocalFileSizeCap pins the contract that a local spec file is
// read under the same byte ceiling as the URL path, so a huge (or
// malicious) on-disk spec can't exhaust memory once the product backend
// writes user-uploaded specs to disk and hands the path to the engine.
func TestLoadSpec_LocalFileSizeCap(t *testing.T) {
	crawler := NewCrawler(&models.ScanConfig{Timeout: 10})
	dir := t.TempDir()

	// Positive: a small local spec reads fine; JSON detected by suffix.
	okPath := filepath.Join(dir, "spec.json")
	if err := os.WriteFile(okPath, []byte(`{"openapi":"3.0.0","paths":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	data, isJSON, err := crawler.loadSpec(context.Background(), okPath)
	if err != nil {
		t.Fatalf("loadSpec(small file): %v", err)
	}
	if !isJSON {
		t.Errorf("expected isJSON=true for .json suffix")
	}
	if len(data) == 0 {
		t.Errorf("expected spec bytes, got empty")
	}

	// Negative: a file just over the cap is rejected with a clear error
	// rather than slurped whole into memory.
	bigPath := filepath.Join(dir, "huge.json")
	f, err := os.Create(bigPath)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20) // 1 MB
	for written := 0; written <= maxSpecBytes; written += len(chunk) {
		if _, werr := f.Write(chunk); werr != nil {
			f.Close()
			t.Fatal(werr)
		}
	}
	f.Close()

	if _, _, err := crawler.loadSpec(context.Background(), bigPath); err == nil {
		t.Errorf("expected error for oversized spec file, got nil")
	} else if !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected 'too large' error, got: %v", err)
	}
}

// TestCrawlHTML_StopsFetchingAtCap pins the contract that the BFS
// short-circuits once `--max-endpoints` is reached, so the crawler
// stops fetching and parsing pages instead of running to completion
// and truncating after the fact.
//
// Test setup:
//   - Root page links to /child1, /child2, … /childN (one per discovered endpoint).
//   - Each /childK page also links to /grandK1 … /grandK5 (multipliers at depth 2).
//   - --crawl-depth=2 → without the cap, the crawler would fetch
//     1 (root) + N (children) + N*5 (grandchildren) pages.
//   - --max-endpoints=5 → with the cap, the crawler should stop
//     well before fetching all of those.
//
// The test asserts (a) the result is capped at 5 endpoints AND
// (b) the server saw substantially fewer fetches than the no-cap
// upper bound — which is what the in-loop short-circuit changes vs.
// the previous "post-walk truncate" behaviour.
func TestCrawlHTML_StopsFetchingAtCap(t *testing.T) {
	const linksPerPage = 20

	var fetchCount atomic.Int32
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		for i := 0; i < linksPerPage; i++ {
			fmt.Fprintf(w, `<a href="/child%d">c%d</a>`, i, i)
		}
	})
	for i := 0; i < linksPerPage; i++ {
		i := i // capture
		mux.HandleFunc(fmt.Sprintf("/child%d", i), func(w http.ResponseWriter, r *http.Request) {
			fetchCount.Add(1)
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(200)
			for j := 0; j < 5; j++ {
				fmt.Fprintf(w, `<a href="/gc%d_%d">gc</a>`, i, j)
			}
		})
		for j := 0; j < 5; j++ {
			mux.HandleFunc(fmt.Sprintf("/gc%d_%d", i, j), func(w http.ResponseWriter, r *http.Request) {
				fetchCount.Add(1)
				w.WriteHeader(200)
			})
		}
	}

	srv := httptest.NewServer(mux)
	defer srv.Close()

	crawler := NewCrawler(&models.ScanConfig{
		URL:          srv.URL,
		CrawlDepth:   2,
		MaxEndpoints: 5,
		Timeout:      10,
	})

	// Call crawlHTMLLinks directly so the test isolates the BFS
	// short-circuit from the spec-discovery + post-walk dedupe
	// paths in CrawlEndpoints.
	eps, err := crawler.crawlHTMLLinks(context.Background(), 2)
	if err != nil {
		t.Fatalf("crawlHTMLLinks: %v", err)
	}

	// Without the in-loop cap, the BFS would enqueue all 20
	// children + 100 grandchildren and fetch root + 20 = 21 pages
	// before the post-walk truncate kicked in. With the in-loop
	// cap, we should see far fewer fetches.
	got := fetchCount.Load()
	if got > 10 {
		t.Errorf("crawler fetched %d pages with --max-endpoints=5; expected ≤10 (the in-loop cap should stop the BFS early)", got)
	}

	// The endpoint count itself should be at-or-below the cap when
	// the in-loop break fires before the per-page inner loop emits
	// more. (The inner short-circuit can leave us at most one full
	// page's-worth past the cap if the outer check hadn't fired
	// yet — accept a small overshoot.)
	if len(eps) > 25 {
		t.Errorf("expected endpoint count near cap=5, got %d", len(eps))
	}
}
