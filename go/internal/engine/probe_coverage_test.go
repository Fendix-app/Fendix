package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
)

// End-to-end: what an active scan reports about its probes when the target
// misbehaves. The page "/" links to /item?id=1 (the probed endpoint); how /item
// behaves is the scenario. The invariant under test: a target that does not
// answer is inconclusive, never an evaluation, never a scanner gap by itself,
// and never leaves the report claiming every probe was evaluated.

func scanScenario(t *testing.T, item func(w http.ResponseWriter, r *http.Request)) (reporters.JSONReport, int) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/item?id=1">item</a></body></html>`)
	})
	var itemHits atomic.Int32
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		// The crawler's own GET is answered normally so discovery finds the
		// endpoint; only requests that carry a probe payload misbehave.
		if itemHits.Add(1) == 1 && r.URL.RawQuery == "id=1" {
			w.WriteHeader(200)
			return
		}
		item(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	out := filepath.Join(t.TempDir(), "r.json")
	cfg := &models.ScanConfig{URL: srv.URL, AllowPrivate: true, Workers: 4, Timeout: 4, CrawlDepth: 1, Format: "json", OutputPath: out, EnableActive: true}
	code := NewOrchestrator(cfg, "dev").Run(context.Background())
	return readReport(t, out), code
}

func probesOf(t *testing.T, r reporters.JSONReport) (*models.ActiveProbeCoverage, reporters.ScannerStatus) {
	t.Helper()
	if r.Metadata.Coverage == nil || r.Metadata.Coverage.ActiveProbes == nil {
		t.Fatalf("metadata.coverage.active_probes missing: %+v", r.Metadata.Coverage)
	}
	s, ok := statusFor(r, AnalyzerActiveProbes)
	if !ok {
		t.Fatal("no active-probes status entry")
	}
	return r.Metadata.Coverage.ActiveProbes, s
}

// itemOnly asserts that every probe that was not evaluated hit /item (the
// scenario's endpoint) and that the account adds up: the page "/" answers
// normally, so its probes are legitimately evaluated.
func itemOnly(t *testing.T, ap *models.ActiveProbeCoverage) {
	t.Helper()
	if ap.Attempted == 0 || ap.Evaluated+ap.Inconclusive+ap.UnknownOrigin+ap.ScannerFailed != ap.Attempted {
		t.Fatalf("the account does not add up: %+v", ap)
	}
	for _, e := range ap.NotEvaluatedChecks {
		if !strings.HasPrefix(e.Endpoint, "GET /item") {
			t.Fatalf("an answered endpoint was reported as not evaluated: %+v", e)
		}
	}
}

func TestProbeCoverage_TargetNeverAnswersIsInconclusiveNotCompleteAndSafe(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	rep, _ := scanScenario(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	ap, st := probesOf(t, rep)
	itemOnly(t, ap)
	if ap.Inconclusive == 0 || ap.Reasons["target"]["timeout"] != ap.Inconclusive || ap.UnknownOrigin+ap.ScannerFailed != 0 {
		t.Fatalf("a target that never answers: %+v", ap)
	}
	// Target-controlled non-answers alone never fail the entry (no refund path)...
	if st.State != reporters.ScannerOK {
		t.Fatalf("state = %s/%s %q, want ok: target non-responses alone are not a scanner gap", st.State, st.Reason, st.Detail)
	}
	// ...but the entry states what was and was not evaluated, first.
	if !strings.HasPrefix(st.Detail, "probe evaluation: ") || !strings.Contains(st.Detail, "inconclusive probes (target did not answer): timeout") {
		t.Fatalf("detail = %q", st.Detail)
	}
	if len(ap.NotEvaluatedChecks) == 0 || ap.NotEvaluatedChecks[0].Origin != "target" || !strings.HasPrefix(ap.NotEvaluatedChecks[0].Endpoint, "GET /item") {
		t.Fatalf("not_evaluated_checks = %+v", ap.NotEvaluatedChecks)
	}
	// Findings are always kept; none were fabricated from non-answers.
	for _, f := range rep.Findings {
		if strings.HasPrefix(f.RuleID, "injection/") || strings.HasPrefix(f.RuleID, "xss/") {
			t.Fatalf("a probe that never got an answer produced a finding: %+v", f)
		}
	}
}

func TestProbeCoverage_ResetConnectionsAreTargetSide(t *testing.T) {
	rep, _ := scanScenario(t, func(w http.ResponseWriter, r *http.Request) {
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		c.Close()
	})
	ap, st := probesOf(t, rep)
	itemOnly(t, ap)
	if ap.Inconclusive == 0 || ap.Reasons["target"]["connection_reset"] != ap.Inconclusive || ap.UnknownOrigin != 0 || ap.ScannerFailed != 0 {
		t.Fatalf("resets: %+v", ap)
	}
	if st.State != reporters.ScannerOK {
		t.Fatalf("state %s/%s %q", st.State, st.Reason, st.Detail)
	}
}

func TestProbeCoverage_GatedStatusesAreEvaluatedAndStayVisible(t *testing.T) {
	for _, code := range []int{401, 403, 404, 410} {
		rep, _ := scanScenario(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) })
		ap, st := probesOf(t, rep)
		if ap.Attempted == 0 || ap.Evaluated != ap.Attempted || ap.Inconclusive+ap.UnknownOrigin+ap.ScannerFailed != 0 || len(ap.NotEvaluatedChecks) != 0 {
			t.Fatalf("%d: %+v", code, ap)
		}
		if st.State != reporters.ScannerOK {
			t.Fatalf("%d: state %s %q", code, st.State, st.Detail)
		}
	}
}

func TestProbeCoverage_RateLimitAfterRetriesIsInconclusive(t *testing.T) {
	var hits atomic.Int32
	rep, _ := scanScenario(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(429)
	})
	ap, st := probesOf(t, rep)
	itemOnly(t, ap)
	if ap.Inconclusive == 0 || ap.Reasons["target"]["rate_limited"] != ap.Inconclusive {
		t.Fatalf("429: %+v", ap)
	}
	if hits.Load() <= int32(ap.Inconclusive) {
		t.Fatalf("hits=%d inconclusive=%d: 429 must have been retried", hits.Load(), ap.Inconclusive)
	}
	if st.State != reporters.ScannerOK || !strings.Contains(st.Detail, "rate_limited") {
		t.Fatalf("state %s detail %q", st.State, st.Detail)
	}
	if rep.Metadata.Coverage.ConfiguredComplete != true {
		t.Fatalf("target non-answers keep scan-wide completeness: %+v", rep.Metadata.Coverage)
	}
}

func TestProbeCoverage_PartialResultsKeepEvaluatedAndInconclusiveApart(t *testing.T) {
	var n atomic.Int32
	rep, _ := scanScenario(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1)%2 == 0 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	ap, _ := probesOf(t, rep)
	if ap.Evaluated == 0 || ap.Evaluated+ap.Inconclusive != ap.Attempted {
		t.Fatalf("partial: %+v", ap)
	}
}

// A target that serves discovery and then refuses every connection: the
// refusals come within the health window of answered requests, so they are the
// target's behaviour (inconclusive), not an unknown-origin gap.
func TestProbeCoverage_TargetGoingDarkAfterAnsweringIsInconclusive(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/item?id=1">item</a></body></html>`)
	})
	srv := httptest.NewServer(mux)
	out := filepath.Join(t.TempDir(), "r.json")
	cfg := &models.ScanConfig{URL: srv.URL, AllowPrivate: true, Workers: 1, Timeout: 3, CrawlDepth: 1, Format: "json", OutputPath: out, EnableActive: true}
	// Stop listening shortly after the crawler is done.
	time.AfterFunc(600*time.Millisecond, func() { srv.CloseClientConnections(); srv.Listener.Close() })
	NewOrchestrator(cfg, "dev").Run(context.Background())
	rep := readReport(t, out)
	if rep.Metadata.Coverage == nil || rep.Metadata.Coverage.ActiveProbes == nil {
		t.Skip("no probes were sent before the target went dark")
	}
	ap := rep.Metadata.Coverage.ActiveProbes
	if ap.Attempted == 0 {
		t.Skip("no probes were sent before the target went dark")
	}
	if ap.Reasons["unknown"]["connection_refused"] != 0 {
		t.Fatalf("refusals within the window of answered requests are target-side, got %+v", ap)
	}
}

// The live report's metadata.coverage.active_probes conforms to the published
// docs/schema.json: required keys, no undeclared keys, the closed reason
// vocabularies, the origin enum, the list cap. (The repository has no JSON
// Schema library, so the subset this definition uses is checked here.)
func TestProbeCoverage_ReportMatchesPublishedSchema(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../docs/schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Definitions map[string]map[string]any `json:"definitions"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	rep, _ := scanScenario(t, func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1)%3 == 0 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	probesOf(t, rep)
	data, _ := json.Marshal(rep.Metadata.Coverage.ActiveProbes)
	var live map[string]any
	if err := json.Unmarshal(data, &live); err != nil {
		t.Fatal(err)
	}
	var check func(path string, def map[string]any, v any)
	resolve := func(def map[string]any) map[string]any {
		if ref, ok := def["$ref"].(string); ok {
			return schema.Definitions[strings.TrimPrefix(ref, "#/definitions/")]
		}
		return def
	}
	check = func(path string, def map[string]any, v any) {
		def = resolve(def)
		switch def["type"] {
		case "object":
			obj, ok := v.(map[string]any)
			if !ok {
				t.Fatalf("%s: not an object", path)
			}
			props, _ := def["properties"].(map[string]any)
			if req, ok := def["required"].([]any); ok {
				for _, k := range req {
					if _, ok := obj[k.(string)]; !ok {
						t.Errorf("%s: required key %q missing", path, k)
					}
				}
			}
			for k, child := range obj {
				cd, declared := props[k].(map[string]any)
				if !declared {
					if def["additionalProperties"] == false {
						t.Errorf("%s: key %q is not declared in the schema", path, k)
					}
					continue
				}
				check(path+"."+k, cd, child)
			}
		case "array":
			arr, ok := v.([]any)
			if !ok {
				t.Fatalf("%s: not an array", path)
			}
			if m, ok := def["maxItems"].(float64); ok && float64(len(arr)) > m {
				t.Errorf("%s: %d items over maxItems %v", path, len(arr), m)
			}
			if items, ok := def["items"].(map[string]any); ok {
				for i, e := range arr {
					check(fmt.Sprintf("%s[%d]", path, i), items, e)
				}
			}
		case "integer":
			f, ok := v.(float64)
			if !ok || f != float64(int(f)) {
				t.Errorf("%s: %v is not an integer", path, v)
			} else if m, ok := def["minimum"].(float64); ok && f < m {
				t.Errorf("%s: %v under minimum %v", path, f, m)
			}
		case "boolean":
			if _, ok := v.(bool); !ok {
				t.Errorf("%s: not a boolean", path)
			}
		case "string":
			s, ok := v.(string)
			if !ok {
				t.Errorf("%s: not a string", path)
			}
			if en, ok := def["enum"].([]any); ok {
				found := false
				for _, e := range en {
					found = found || e == s
				}
				if !found {
					t.Errorf("%s: %q not in enum %v", path, s, en)
				}
			}
		}
	}
	check("active_probes", schema.Definitions["ActiveProbeCoverage"], live)
	// And the Coverage definition declares the property.
	props := schema.Definitions["Coverage"]["properties"].(map[string]any)
	if _, ok := props["active_probes"]; !ok {
		t.Fatal("Coverage does not declare active_probes")
	}
}
