package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/logagg"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// configLeakPaths is the deny-list of paths whose 200-response means
// a config file was served by the live target. These are paths the
// crawler's wordlist (CommonPaths + .env-style brute-force) routinely
// discovers, and a non-404 response on any of them is a CRITICAL
// finding regardless of body content — the existence of a 200 is the
// vulnerability, not what the body contains.
//
// Keyed by basename + a few directory-prefix patterns (for .git/* and
// .aws/* which exist as directories with multiple sensitive files).
// Match strategy in matchesConfigLeakPath:
//   - exact basename match (case-sensitive, since servers are typically
//     case-sensitive on POSIX)
//   - prefix match for the directory-style entries (".git/", ".aws/")
//
// TASK-133 / Phase 17d. Closes the inversion FP-CORPUS.md D2: today
// these paths produce noisy "missing CSP" / "no rate limiting" LOW
// findings; with this check they produce one CRITICAL "exposed config
// file" finding instead, and the existing dedup pass collapses the
// noisier per-path findings naturally because their (title, category,
// severity) tuple is shared across the affected paths.
var configLeakBasenames = map[string]string{
	// Environment / app config
	".env":             "Environment configuration file exposed",
	".env.local":       "Environment configuration file exposed",
	".env.production":  "Environment configuration file exposed",
	".env.development": "Environment configuration file exposed",
	".env.staging":     "Environment configuration file exposed",
	".env.backup":      "Environment configuration backup exposed",
	".envrc":           "direnv configuration file exposed",
	// Web-server config
	".htaccess":  "Apache .htaccess file exposed",
	".htpasswd":  "Apache .htpasswd credentials file exposed",
	"web.config": "IIS web.config file exposed",
	// Package-manager credentials
	".npmrc":        "npm authentication tokens exposed",
	".pypirc":       "PyPI authentication tokens exposed",
	".netrc":        "netrc credentials file exposed",
	"composer.lock": "PHP Composer lockfile exposed (lower risk; informational)",
	// CI / config-as-code that should be in source control, never on the live server
	".dockerenv":                  "Docker environment file exposed",
	"docker-compose.override.yml": "Docker Compose override file exposed",
	// Editor / IDE / OS leftovers
	".DS_Store": "macOS .DS_Store file exposed (directory listing leak)",
}

// configLeakPrefixes matches when the discovered path starts with the
// prefix — for directory-style leaks (the whole .git or .aws tree
// served by mis-aliased nginx locations).
var configLeakPrefixes = map[string]string{
	".git/":    "Git repository internals exposed",
	".aws/":    "AWS credentials directory exposed",
	".ssh/":    "SSH key directory exposed",
	".idea/":   "JetBrains IDE configuration exposed",
	".vscode/": "VSCode workspace configuration exposed",
}

// configLeakFix is the canonical remediation message — the response
// path doesn't matter; the fix is always the same.
const configLeakFix = "Remove this file from the public web root, OR configure the server (nginx/Apache/etc) to deny requests for hidden / config files. Rotate any credentials this file may have exposed."

// configLeakCheck implements the Check interface for the config-file
// leak detector. Structural adapter — Run holds the unchanged body of
// the historical CheckConfigLeak free function.
type configLeakCheck struct{}

func (configLeakCheck) Name() string                        { return "configleak" }
func (configLeakCheck) Category() string                    { return "data_exposure" }
func (configLeakCheck) Tier() Tier                          { return TierPassive }
func (configLeakCheck) Enabled(cfg *models.ScanConfig) bool { return true }

// CheckConfigLeak hits the endpoint and emits a CRITICAL "exposed
// config file" finding when (a) the endpoint's path matches a known
// config-file leak pattern AND (b) the response is 200-series (the
// server is actually serving the file).
//
// Cheap to run — single HEAD-style GET, no probes, no body parse
// beyond a length check. Designed to slot into the worker pool as the
// first check so noisier downstream checks (headers / cors /
// ratelimit) can be deduped naturally by the existing pipeline when
// they fire on the same path.
func CheckConfigLeak(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []ev.Evidence {
	return configLeakCheck{}.Run(ctx, NewCheckContext(cfg), endpoint)
}

// Run holds the unchanged config-leak detection body. Outbound requests
// go through the shared SSRF-guarded follow-redirect client (cc.Client);
// the per-job deadline comes from ctx (runCheck).
func (configLeakCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []ev.Evidence {
	cfg := cc.Cfg
	if endpoint.FullURL == "" {
		return nil
	}
	leakPath, title, ok := matchesConfigLeakPath(endpoint.Path)
	if !ok {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.FullURL, nil)
	if err != nil {
		logagg.Warn("configleak", "configleak request build failed", "endpoint", endpoint.FullURL, "err", err)
		return nil
	}
	if cfg != nil && cfg.Auth != nil {
		cfg.Auth.ApplyToRequest(req)
	}

	client := cc.Client

	resp, err := client.Do(req)
	if err != nil {
		logagg.Warn("configleak", "configleak request failed", "endpoint", endpoint.FullURL, "err", err)
		return nil
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// Only 2xx is a leak. 3xx / 4xx / 5xx all mean the server isn't
	// serving the file (redirect to login, blocked, etc.).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	// Read a bounded prefix of the body: the first sniffLen bytes feed an
	// HTML/SPA-fallback check; the rest is drained only for the size
	// descriptor. The bytes are NEVER stored (persisting a leaked
	// secret-file body would itself be a leak; the 200 + path is the proof).
	const (
		bodyLenCap = 1 << 20 // 1 MiB ceiling for the size probe
		sniffLen   = 512     // http.DetectContentType inspects ≤512 bytes
	)
	head := make([]byte, sniffLen)
	hn, _ := io.ReadFull(resp.Body, head)
	head = head[:hn]
	rest, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, bodyLenCap))
	n := int64(hn) + rest

	// SPA / catch-all guard. Single-page-app and framework servers
	// (Express, Next, Vite, CRA, …) return their index.html with HTTP 200
	// for EVERY unknown path, so a status-only check fires a phantom
	// CRITICAL on every such app (found via the v0.20 Juice Shop baseline:
	// 5 identical text/html index.html responses on /.env, /.git/HEAD, …).
	// A genuinely exposed .env / .git/HEAD / .htpasswd is served as
	// text/plain or octet-stream, never as an HTML document — so an HTML
	// body means "framework fallback", not "config file served".
	if looksLikeHTML(resp.Header.Get("Content-Type"), head) {
		return nil
	}
	// Same guard, second shape: a JSON API catch-all. See looksLikeJSONCatchAll.
	if looksLikeJSONCatchAll(resp.Header.Get("Content-Type"), head) {
		return nil
	}

	line := endpoint.Path
	return []ev.Evidence{{
		Title:      title,
		Severity:   models.SeverityCritical,
		Source:     models.SourceBlackbox,
		Category:   "data_exposure",
		Endpoint:   endpoint.Path,
		Evidence:   fmt.Sprintf("HTTP %d on %s (config file served; body %d bytes, not captured)", resp.StatusCode, leakPath, n),
		Fix:        configLeakFix,
		References: []string{"CWE-538"}, // Insertion of Sensitive Information into Externally-Accessible File
		Confidence: models.ConfidenceHigh,
		Line:       &line,
		// The claim IS the wire read: a 2xx on this path, a non-HTML non-JSON
		// content type, and a body size — all taken from the response with no
		// inference step between the bytes and the assertion. That is exactly
		// what DirectObservation denotes, and the check deliberately stops
		// there: persisting the body of a leaked secret file would itself be a
		// leak, so "the 200 + path is the proof" is a design decision, not
		// missing evidence.
		//
		// Without this the finding carries no corroborating signal of any class
		// and, after the tautological blackbox signal was removed, silently
		// stopped being able to gate a build.
		DirectObservation: true,
	}}
}

// matchesConfigLeakPath inspects endpointPath for any known leak
// pattern. Returns (canonical-leak-path, finding-title, true) when
// matched.
//
// Lookup order: basename exact match → prefix match. Lookup is
// case-sensitive (matches typical POSIX server behaviour); leading
// slashes, query strings, and HTTP-method prefixes are normalised
// away before matching.
func matchesConfigLeakPath(endpointPath string) (string, string, bool) {
	cleaned := normalizeForConfigLeak(endpointPath)
	if cleaned == "" {
		return "", "", false
	}

	base := path.Base(cleaned)
	if title, ok := configLeakBasenames[base]; ok {
		return cleaned, title, true
	}

	// Prefix match — strip leading "/" for comparison.
	trimmed := strings.TrimPrefix(cleaned, "/")
	for prefix, title := range configLeakPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return cleaned, title, true
		}
	}
	return "", "", false
}

// normalizeForConfigLeak strips method prefix, query string,
// fragment, and any trailing slashes from an Endpoint.Path before we
// inspect it. Doesn't validate; just normalises.
func normalizeForConfigLeak(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// "GET /foo" → "/foo"
	for _, method := range []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "} {
		if strings.HasPrefix(p, method) {
			p = strings.TrimSpace(strings.TrimPrefix(p, method))
			break
		}
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return p
}

// looksLikeHTML reports whether a 200 response is an HTML document — i.e.
// a single-page-app / framework catch-all fallback rather than a served
// config file. It trusts an explicit text/html Content-Type, and falls
// back to sniffing the body prefix (for servers that omit the header) via
// the same detector the net/http stdlib uses.
func looksLikeHTML(contentType string, head []byte) bool {
	if strings.Contains(strings.ToLower(contentType), "text/html") {
		return true
	}
	if len(head) == 0 {
		return false
	}
	return strings.Contains(http.DetectContentType(head), "text/html")
}

// looksLikeJSONCatchAll reports whether the response is a JSON document, which
// for these paths means a framework fallback rather than a served config file.
//
// The HTML guard above was written against SPA servers, and it misses the shape
// that is far more common among the targets Fendix actually scans: a JSON API
// whose router answers 200 with a generic body for every unknown path. Found
// end-to-end — a fixture returning application/json for every path produced five
// phantom CRITICALs (.env, .git/HEAD, .htaccess, .htpasswd, .DS_Store), the same
// soft-404 class the HTML guard exists to stop.
//
// None of the paths this check probes is ever legitimately a JSON document: a
// real .env is key=value text, .git/HEAD is a ref line, .htpasswd is
// colon-separated, .DS_Store is binary. A JSON body is therefore positive
// evidence of a catch-all, not weak evidence of a leak.
//
// Content-Type is authoritative when present; DetectContentType does not sniff
// JSON, so a bare `{`/`[` prefix is the fallback for a server that sends no
// type at all.
func looksLikeJSONCatchAll(contentType string, head []byte) bool {
	if ct := strings.ToLower(contentType); strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "+json") {
		return true
	}
	if contentType != "" {
		return false
	}
	trimmed := strings.TrimLeft(string(head), " \t\r\n")
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}
