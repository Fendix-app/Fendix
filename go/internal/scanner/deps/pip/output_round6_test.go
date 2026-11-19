package pip

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Round 6, WS-E2: OR-50 low-priority bounded output (R-34 output path, OR-28).
// Scan writes one stderr line per package whose OSV lookup failed
// (scanner.go:179). Package names come from the scanned repository, and the
// hosted worker keeps the engine's whole stderr in memory: the output must be
// bounded in bytes, whatever the number or length of the names. The failures
// stay counted (neterr.Failures), so nothing is lost by not printing each one.
func TestScan_OR13_PerPackageFailureOutputIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	var req strings.Builder
	for i := 0; i < 1_000; i++ {
		fmt.Fprintf(&req, "pkg-%04d-%s==1.0.0\n", i, strings.Repeat("x", 180))
	}
	dir := t.TempDir()
	writeReqs(t, dir, "requirements.txt", req.String())

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stderr
	os.Stderr = w
	var out strings.Builder
	counted := make(chan int64)
	go func() { n, _ := io.Copy(&out, r); counted <- n }()
	_, _ = Scan(context.Background(), dir)
	os.Stderr = prev
	_ = w.Close()
	n := <-counted

	const budget = 64 << 10
	if n > budget {
		t.Errorf("1,000 failed package lookups wrote %d KiB to stderr; per-item output must be bounded in bytes (budget %d KiB)", n>>10, budget>>10)
	}
	// OR-60: the lookups not reported one by one are counted, exactly, so
	// deleting the output cannot pass.
	written := strings.Count(out.String(), "[fendix] pip: query ")
	if written < 1_000 {
		m := regexp.MustCompile(`(\d+) further [a-z -]*not (?:written|logged)`).FindStringSubmatch(out.String())
		if m == nil || m[1] != fmt.Sprint(1_000-written) {
			t.Errorf("%d of 1,000 lookup failures written and no exact 'N further ... not written' line (got %q)", written, m)
		}
	}
}
