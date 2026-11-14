package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/cli"
)

// Round 5, C4B-06: the real CLI, with the argv the Action builds
// (--require-analyzers active-probes), against an httptest target. 0 probes
// evaluated of N never exits 0 and never reads complete; one evaluated probe
// delivers.

func runActive(t *testing.T, handler http.HandlerFunc, extra ...string) (code int, active statusEntry, complete bool, gated int) {
	t.Helper()
	srv := httptest.NewServer(handler)
	defer srv.Close()
	out := filepath.Join(t.TempDir(), "report.json")
	root := newRootCmd()
	args := []string{"scan", "--url", srv.URL, "--allow-private-targets", "--enable-active", "--format", "json", "--output", out,
		"--crawl-depth", "1", "--timeout", "4", "--no-plugins", "--python-engine=false"}
	root.SetArgs(append(args, extra...))
	root.SetOut(new(strings.Builder))
	root.SetErr(new(strings.Builder))
	if err := root.Execute(); err != nil {
		var exitErr *cli.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("scan failed without an exit code: %v", err)
		}
		code = exitErr.Code
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the scan wrote no report: %v", err)
	}
	var rep struct {
		Metadata struct {
			ScannerStatus []statusEntry `json:"scanner_status"`
			Coverage      struct {
				ConfiguredComplete bool `json:"configured_complete"`
				ActiveProbes       struct {
					Gated struct {
						Total int `json:"total"`
					} `json:"gated"`
				} `json:"active_probes"`
			} `json:"coverage"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	for _, e := range rep.Metadata.ScannerStatus {
		if e.Name == "active-probes" {
			active = e
		}
	}
	return code, active, rep.Metadata.Coverage.ConfiguredComplete, rep.Metadata.Coverage.ActiveProbes.Gated.Total
}

func page(w http.ResponseWriter, r *http.Request, links string) bool {
	if r.URL.Path == "/" && r.URL.RawQuery == "" {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>%s</body></html>`, links)
		return true
	}
	return false
}

func TestCLI_ActiveProbesRequirementFailsWhenNothingWasEvaluated(t *testing.T) {
	// Two of the four statuses: each scan costs ~20 s (the engine-level test
	// covers all four).
	for _, status := range []int{403, 404} {
		code, active, complete, gated := runActive(t, func(w http.ResponseWriter, r *http.Request) {
			if page(w, r, `<a href="/item?id=1">item</a>`) {
				return
			}
			w.WriteHeader(status)
		}, "--require-analyzers", "active-probes")
		if code != 2 {
			t.Errorf("%d: exit %d, want 2: 0 probes evaluated never satisfies --require-analyzers active-probes", status, code)
		}
		if active.State != "failed" || active.Reason != "no_endpoints" {
			t.Errorf("%d: active-probes %+v, want failed/no_endpoints", status, active)
		}
		if complete {
			t.Errorf("%d: configured_complete is true with 0 probes evaluated", status)
		}
		if gated == 0 {
			t.Errorf("%d: no gated probes counted", status)
		}
	}
}

func TestCLI_ActiveProbesRequirementIsMetByOneEvaluatedProbe(t *testing.T) {
	code, active, complete, _ := runActive(t, func(w http.ResponseWriter, r *http.Request) {
		if page(w, r, `<a href="/ok?id=1">ok</a> <a href="/item?id=1">item</a>`) {
			return
		}
		if r.URL.Path == "/item" && r.URL.RawQuery != "id=1" {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "fine")
	}, "--require-analyzers", "active-probes")
	if code != 0 || active.State != "ok" || !complete {
		t.Fatalf("exit %d, active-probes %+v, complete %v: some probes evaluated, the rest gated beside them", code, active, complete)
	}
	if !strings.Contains(active.Detail, "gated probes (target answered 401/403/404/410 so not evaluated): 403 ") {
		t.Fatalf("the gated probes must be stated beside the verdict, got %q", active.Detail)
	}
}
