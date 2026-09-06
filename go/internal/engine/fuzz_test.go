package engine

import (
	"strings"
	"testing"
)

// FuzzReadFindings tests that readFindings never panics on any input.
// Run with: go test -fuzz=FuzzReadFindings ./internal/engine/ -fuzztime=30s
func FuzzReadFindings(f *testing.F) {
	// Seed corpus with valid, edge-case, and malformed inputs
	f.Add(`{"title":"Test","severity":"HIGH","source":"whitebox","category":"secrets","endpoint":"f.py:1","evidence":"x","fix":"y","references":["CWE-1"],"confidence":"HIGH"}
{"done":true,"total":1}
`)
	f.Add(`{"done":true,"total":0}
`)
	f.Add("")
	f.Add("\n\n\n")
	f.Add(`not json at all`)
	f.Add(`{"title":"","severity":""}
{"done":true,"total":0}
`)
	f.Add(`{"title":"X","severity":"INVALID_LEVEL","source":"unknown","category":"","endpoint":"","evidence":"","fix":"","references":null,"confidence":""}
{"done":true,"total":1}
`)
	// Extremely large line
	f.Add(strings.Repeat("a", 2*1024*1024))
	// Null bytes
	f.Add("{\x00\"title\":\"null\"}\n")
	// Unicode
	f.Add(`{"title":"Ünîcödé tëst 🔥","severity":"HIGH","source":"whitebox","category":"test","endpoint":"f.py:1","evidence":"é","fix":"ñ","references":[],"confidence":"HIGH"}
{"done":true,"total":1}
`)
	// Nested JSON
	f.Add(`{"title":{"nested":"object"},"severity":"HIGH"}
`)
	// Truncated JSON
	f.Add(`{"title":"trunc`)
	// Multiple done messages
	f.Add(`{"done":true,"total":0}
{"done":true,"total":0}
`)
	// Mixed valid and invalid
	f.Add(`garbage
{"title":"Valid","severity":"HIGH","source":"whitebox","category":"c","endpoint":"e","evidence":"ev","fix":"f","references":[],"confidence":"HIGH"}
more garbage
{"done":true,"total":1}
`)

	f.Fuzz(func(t *testing.T, data string) {
		// readFindings must never panic
		sr := readFindings(strings.NewReader(data))
		// We don't assert specific results — only that it doesn't crash
		_ = sr
	})
}

// FuzzNormalizeEndpoint tests that normalizeEndpoint never panics.
func FuzzNormalizeEndpoint(f *testing.F) {
	f.Add("https://api.example.com/api/v1/users?page=1")
	f.Add("GET /api/v1/users")
	f.Add("src/routes/users.py:42")
	f.Add("")
	f.Add("/")
	f.Add("://")
	f.Add("http://[::1]:8080/path")
	f.Add(strings.Repeat("/a", 1000))
	f.Add("file:///etc/passwd")
	f.Add("\x00\x01\x02")

	f.Fuzz(func(t *testing.T, endpoint string) {
		result := normalizeEndpoint(endpoint)
		_ = result
	})
}
