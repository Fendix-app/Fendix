package pip

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/neterr"
)

// TestScanViaOSV_TotalFailureIsLookupError asserts that when OSV.dev
// returns 503 on BOTH /v1/querybatch AND the per-package /v1/query
// fallback, scanViaOSV returns a *neterr.LookupError naming every failed
// lookup rather than a bare "ok" with a quietly-empty finding set. This
// replaces the old tolerant TestScanViaOSV_BothBatchAndSerialFail, which
// accepted either a nil error or an untyped one — Task 7 makes total
// lookup failure an explicit, typed contract instead of two-outcomes-
// both-honest.
func TestScanViaOSV_TotalFailureIsLookupError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	saved := OSVBaseURL
	OSVBaseURL = srv.URL
	defer func() { OSVBaseURL = saved }()
	t.Setenv("HOME", t.TempDir())

	codeDir := t.TempDir()
	writeReqs(t, codeDir, "requirements.txt", "flask==2.0.1\nrequests==2.25.0\n")

	findings, err := scanViaOSV(context.Background(), codeDir, DefaultRecurseDepth)
	var le *neterr.LookupError
	if !errors.As(err, &le) {
		t.Fatalf("expected *neterr.LookupError, got %v", err)
	}
	if le.Failed != 2 || le.Total != 2 || neterr.Classify(err) != neterr.KindNetwork {
		t.Fatalf("lookup error = %+v (kind %v)", le, neterr.Classify(err))
	}
	if len(findings) != 0 {
		t.Fatalf("no lookup succeeded, expected no findings, got %d", len(findings))
	}
}

// TestScanViaOSV_BatchFailsSerialSucceedsIsNotAnError asserts that a
// batch-endpoint outage which the serial fallback fully recovers from is
// NOT reported as a failure: the lookup accumulator only counts a
// package once every fallback for it has been exhausted, and here the
// serial /v1/query path answers for the one package in the chunk.
func TestScanViaOSV_BatchFailsSerialSucceedsIsNotAnError(t *testing.T) {
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
	writeReqs(t, codeDir, "requirements.txt", "flask==2.0.1\n")
	if _, err := scanViaOSV(context.Background(), codeDir, DefaultRecurseDepth); err != nil {
		t.Fatalf("serial fallback covered every package, expected nil error, got %v", err)
	}
}
