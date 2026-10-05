package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// RC-8 — the rate-limit check probed a hardcoded GET while labelling the
// finding with the OpenAPI operation's method. Fendix therefore reported
// "No rate limiting observed" against "POST /login" having never sent a POST,
// which is a claim about a test that did not happen.
//
// The fix is constrained by the safety model: rateLimitCheck is TierPassive
// ("always on"), and the check sends a BURST of 20. Probing the real verb
// unconditionally would make a passive check issue 20 writes against a
// production target. So the verb is either probed honestly or reported as not
// tested — never substituted.

// methodRecorder captures every verb a probe actually sent.
type methodRecorder struct {
	mu      sync.Mutex
	methods []string
	srv     *httptest.Server
}

func newMethodRecorder(t *testing.T) *methodRecorder {
	t.Helper()
	r := &methodRecorder{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.methods = append(r.methods, req.Method)
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *methodRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.methods...)
}

func (r *methodRecorder) endpoint(method, path string) Endpoint {
	return Endpoint{Method: method, Path: path, FullURL: r.srv.URL + path}
}

func runRateLimit(t *testing.T, r *methodRecorder, ep Endpoint, active bool) []evidenceLike {
	t.Helper()
	cfg := &models.ScanConfig{URL: r.srv.URL, EnableActive: active}
	out := rateLimitCheck{}.Run(t.Context(), NewCheckContext(cfg), ep)
	res := make([]evidenceLike, 0, len(out))
	for _, e := range out {
		res = append(res, evidenceLike{Title: e.Title, Endpoint: e.Endpoint, Evidence: e.Evidence})
	}
	return res
}

type evidenceLike struct{ Title, Endpoint, Evidence string }

// A safe method is probed with the method it claims to have probed.
func TestRateLimitProbesTheOperationsMethodWhenItIsSafe(t *testing.T) {
	r := newMethodRecorder(t)
	runRateLimit(t, r, r.endpoint("GET", "/api/items"), false)

	for _, m := range r.seen() {
		if m != "GET" {
			t.Errorf("probed %s on a GET operation", m)
		}
	}
	if len(r.seen()) == 0 {
		t.Fatal("no probes were sent at all")
	}
}

func TestRateLimitProbesHeadAndOptionsAsThemselves(t *testing.T) {
	for _, method := range []string{"HEAD", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			r := newMethodRecorder(t)
			runRateLimit(t, r, r.endpoint(method, "/api/items"), false)
			seen := r.seen()
			if len(seen) == 0 {
				t.Fatalf("%s operation was never probed", method)
			}
			for _, m := range seen {
				if m != method {
					t.Errorf("probed %s on a %s operation", m, method)
				}
			}
		})
	}
}

// The headline defect: a POST operation must never be probed with GET.
func TestRateLimitNeverSubstitutesGetForAWriteMethod(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			r := newMethodRecorder(t)
			runRateLimit(t, r, r.endpoint(method, "/api/resource"), false)

			for _, m := range r.seen() {
				if m == "GET" {
					t.Errorf("sent GET while the finding would be labelled %s %s — "+
						"the report would claim a test that never happened", method, "/api/resource")
				}
			}
		})
	}
}

// Passive tier must not burst writes at a production target.
func TestRateLimitSendsNoWritesWithoutActiveScanning(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			r := newMethodRecorder(t)
			runRateLimit(t, r, r.endpoint(method, "/api/resource"), false)
			if got := r.seen(); len(got) > 0 {
				t.Errorf("a passive check sent %d %s request(s) to the target: %v", len(got), method, got)
			}
		})
	}
}

// An operation that could not be probed is reported as NOT TESTED, never as
// tested-and-clean and never silently dropped.
func TestUntestedOperationIsReportedAsUntested(t *testing.T) {
	r := newMethodRecorder(t)
	found := runRateLimit(t, r, r.endpoint("POST", "/login"), false)

	if len(found) != 1 {
		t.Fatalf("expected exactly one not-tested record, got %d: %+v", len(found), found)
	}
	f := found[0]
	if !strings.Contains(strings.ToLower(f.Title), "not tested") {
		t.Errorf("title does not say the operation was untested: %q", f.Title)
	}
	if strings.Contains(f.Title, "No rate limiting observed") {
		t.Errorf("an untested operation is reported as if it had been tested: %q", f.Title)
	}
	if !strings.Contains(f.Endpoint, "POST") {
		t.Errorf("the record does not name the operation it could not test: %q", f.Endpoint)
	}
}

// Under active scanning the operator has opted in, so POST/PUT/PATCH are
// probed with their real verb.
func TestActiveScanningProbesWriteMethodsHonestly(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH"} {
		t.Run(method, func(t *testing.T) {
			r := newMethodRecorder(t)
			runRateLimit(t, r, r.endpoint(method, "/api/resource"), true)

			seen := r.seen()
			if len(seen) == 0 {
				t.Fatalf("%s operation was never probed even under --active", method)
			}
			for _, m := range seen {
				if m != method {
					t.Errorf("probed %s on a %s operation under --active", m, method)
				}
			}
		})
	}
}

// DELETE is never burst-probed, opt-in or not. Twenty deletions is data loss,
// not scanning — and the active tier's licence is to send attack payloads, not
// to destroy the target's data.
func TestDeleteIsNeverBurstProbedEvenUnderActiveScanning(t *testing.T) {
	r := newMethodRecorder(t)
	found := runRateLimit(t, r, r.endpoint("DELETE", "/api/items/1"), true)

	if got := r.seen(); len(got) > 0 {
		t.Errorf("sent %d DELETE request(s) to the target: %v", len(got), got)
	}
	if len(found) != 1 || !strings.Contains(strings.ToLower(found[0].Title), "not tested") {
		t.Errorf("DELETE should be recorded as not tested, got %+v", found)
	}
}

// The scientific caveat must survive: a bounded burst cannot prove absence.
func TestFindingNeverClaimsRateLimitingIsAbsent(t *testing.T) {
	r := newMethodRecorder(t)
	found := runRateLimit(t, r, r.endpoint("GET", "/api/items"), false)
	if len(found) != 1 {
		t.Fatalf("expected one finding, got %d", len(found))
	}
	f := found[0]
	if strings.Contains(f.Title, "No rate limiting exists") {
		t.Errorf("title claims absence, which a bounded burst cannot establish: %q", f.Title)
	}
	if !strings.Contains(f.Evidence, "cannot prove the absence") {
		t.Errorf("evidence dropped the scope caveat: %q", f.Evidence)
	}
}
