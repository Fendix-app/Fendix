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

// Round 6, WS-E2 (OR-13): the default (batch) path of the pip scanner bounds its
// per-package stderr lines in bytes too, and counts the lines it does not write.
func TestScanRecursive_WSE2_BatchFallbackOutputIsBoundedAndCounted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	var req strings.Builder
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&req, "pkg-%04d-%s==1.0.0\n", i, strings.Repeat("y", 200))
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
	_, _ = ScanRecursive(context.Background(), dir, 0)
	os.Stderr = prev
	_ = w.Close()
	n := <-counted

	if n > 64<<10 {
		t.Errorf("600 failed lookups wrote %d KiB to stderr, want a bounded number of bytes", n>>10)
	}
	// Every package that failed is either narrated or counted: the exact sum.
	narrated := strings.Count(out.String(), "[fendix] pip: query ")
	m := regexp.MustCompile(`(\d+) further lines not written`).FindStringSubmatch(out.String())
	dropped := 0
	if m != nil {
		fmt.Sscan(m[1], &dropped)
	}
	// One more line per chunk: the querybatch failure that sends the chunk to the
	// per-package path. It shares the budget, so it is narrated or counted too.
	chunks := (600 + osvBatchMaxSize - 1) / osvBatchMaxSize
	narratedOther := strings.Count(out.String(), "querybatch failed")
	if narrated+dropped+narratedOther != 600+chunks {
		t.Errorf("narrated %d query lines + %d querybatch lines + %d counted as dropped != %d items; the output must account for every line it did not write (%q)",
			narrated, narratedOther, dropped, 600+chunks, out.String()[max(0, len(out.String())-200):])
	}
}
