package models

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestIsTestPathMatchesPythonMarkers locks the marker set against the Python
// analyzer's `_is_test_path` (python/analyzers/ast_analyzer.py). Deriving test
// context in Go from the endpoint only works because the two agree; if the
// Python side grows a marker, this table is where the drift shows up.
func TestIsTestPathMatchesPythonMarkers(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     bool
	}{
		// --- the five Python markers -----------------------------------
		{"tests dir", "tests/test_login.py:10", true},
		{"test dir singular", "test/helpers.py:3", true},
		{"testing dir", "app/testing/factory.py:8", true},
		{"conftest", "app/conftest.py:1", true},
		{"test_ prefix file", "app/test_views.py:42", true},
		{"_test suffix file", "app/views_test.py:42", true},
		{"fixtures dir", "app/fixtures/users.py:5", true},
		{"fixture dir singular", "app/fixture/users.py:5", true},

		// --- production paths -------------------------------------------
		{"plain module", "app/views.py:10", false},
		{"nested module", "src/api/handlers/login.py:22", false},
		{"substring not a segment", "app/latest/mod.py:1", false},
		{"contest is not conftest", "app/contest.py:1", false},

		// --- shapes that are not source paths at all ---------------------
		{"empty", "", false},
		{"url endpoint", "GET /api/users", false},
		{"absolute url", "https://api.example.com/tests", false},

		// --- LIVE ROUTES THAT MERELY LOOK LIKE TEST PATHS ------------------
		// Regression gate. The marker regex matches a `tests?`/`testing`/
		// `fixtures` segment anywhere, so without the URL guard every one of
		// these deployed routes classified as test code and had its DAST
		// findings de-escalated to INFO. A route is attack surface no matter
		// what it is named; only a source FILE can be test code.
		{"route named test", "GET /api/test", false},
		{"route named tests", "GET /tests", false},
		{"route under testing", "GET /api/testing/run", false},
		{"route with .json suffix", "POST /v1/test.json", false},
		{"route under fixtures", "GET /fixtures/team-roster", false},
		{"bare path route", "/test/echo", false},
		{"lowercase method", "get /tests", false},
		{"absolute url with test segment", "https://api.example.com/api/testing/run", false},

		// --- normalisation ------------------------------------------------
		{"windows separators", `app\tests\test_login.py:10`, true},
		{"no line suffix", "tests/test_login.py", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTestPath(tc.endpoint); got != tc.want {
				t.Errorf("IsTestPath(%q) = %v, want %v", tc.endpoint, got, tc.want)
			}
		})
	}
}

// TestIsTestPathIsDeterministic guards the reproducibility contract: the
// classifier feeds the confidence/decision layer, so it must be a pure
// function with no filesystem or environment dependence.
func TestIsTestPathIsDeterministic(t *testing.T) {
	const ep = "app/tests/test_views.py:42"
	first := IsTestPath(ep)
	for i := 0; i < 100; i++ {
		if got := IsTestPath(ep); got != first {
			t.Fatalf("IsTestPath is not deterministic: iteration %d returned %v, want %v", i, got, first)
		}
	}
}

// testPathVectorsFile is shared with the Python twin: python/tests/
// test_rc10_test_paths.py checks `_is_test_path` against the same vectors, and
// checks that this package's regex source equals the Python one. A convention
// added to one side without the other fails one of the two.
const testPathVectorsFile = "../../../python/tests/fixtures/test_path_vectors.json"

type testPathVector struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Want bool   `json:"want"`
}

func loadTestPathVectors(t *testing.T) []testPathVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(testPathVectorsFile))
	if err != nil {
		t.Fatalf("read the shared vectors: %v", err)
	}
	var doc struct {
		Vectors []testPathVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode the shared vectors: %v", err)
	}
	if len(doc.Vectors) < 80 {
		t.Fatalf("the shared vector file holds %d vectors, want at least 80", len(doc.Vectors))
	}
	return doc.Vectors
}

// TestIsTestPathSharedVectors is the RC-10 (a) lockstep gate: the conventions
// of the JS, TS, Go, Java and Ruby ecosystems, and the near misses that are
// production code, as one table both languages answer the same way.
func TestIsTestPathSharedVectors(t *testing.T) {
	for _, v := range loadTestPathVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			if got := IsTestPath(v.Path); got != v.Want {
				t.Errorf("IsTestPath(%q) = %v, want %v", v.Path, got, v.Want)
			}
			// The endpoint of a finding carries a line suffix.
			if got := IsTestPath(v.Path + ":42"); got != v.Want {
				t.Errorf("IsTestPath(%q) = %v, want %v", v.Path+":42", got, v.Want)
			}
		})
	}
}

// TestIsTestPathUrlGuardHoldsForEveryConvention keeps the guard the extended set
// must not weaken: a live route is attack surface whatever its path looks like,
// so a source-path convention never classifies a URL-shaped endpoint as test code.
func TestIsTestPathUrlGuardHoldsForEveryConvention(t *testing.T) {
	for _, v := range loadTestPathVectors(t) {
		if !v.Want {
			continue
		}
		for _, ep := range []string{
			"GET /" + v.Path,
			"POST /api/" + v.Path,
			"/" + v.Path,
			"https://api.example.com/" + v.Path,
		} {
			if IsTestPath(ep) {
				t.Errorf("IsTestPath(%q) = true: a live route is never test code (from vector %q)", ep, v.Name)
			}
		}
	}
}
