package scanner

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/budget"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/netguard"
	"gopkg.in/yaml.v3"
)

// CommonPaths is a hardcoded list of frequently found API paths to brute-force.
// Curated for high signal — admin surfaces, source-control leakage, common
// dev tooling. Override with --wordlist for custom lists. ~100 entries.
var CommonPaths = []string{
	// REST API roots
	"/api", "/api/v1", "/api/v2", "/api/v3",
	"/api/health", "/api/status", "/api/ping",
	"/api/v1/users", "/api/v1/user", "/api/v1/me",
	"/api/v1/accounts", "/api/v1/auth", "/api/v1/login",
	"/api/v1/logout", "/api/v1/register", "/api/v1/signup",
	"/api/v1/token", "/api/v1/refresh",
	"/api/v1/admin", "/api/v1/config", "/api/v1/settings",
	"/api/v1/products", "/api/v1/orders", "/api/v1/items",
	"/api/v1/search", "/api/v1/upload", "/api/v1/files",
	"/api/v1/auth/login", "/api/v2/auth/login",
	"/api/v1/users/me", "/api/me",
	"/api/internal", "/api/private", "/api/admin",
	// Health & readiness
	"/health", "/healthz", "/ready", "/readyz",
	"/status", "/ping", "/info", "/version",
	// API spec / docs
	"/swagger.json", "/swagger/", "/swagger-ui/", "/swagger-ui.html",
	"/openapi.json", "/openapi.yaml", "/openapi",
	"/api-docs", "/docs", "/redoc", "/graphql",
	"/metrics", "/actuator", "/actuator/health",
	"/.well-known/openapi.yaml", "/.well-known/openapi.json",
	"/.well-known/security.txt",
	// Bare versions / common public roots
	"/v1", "/v2", "/v3",
	"/users", "/admin", "/auth", "/login",
	"/logout", "/signin", "/signout", "/register", "/signup",
	// Admin/dashboard surfaces
	"/admin/login", "/admin/api", "/admin/dashboard", "/admin/users",
	"/console", "/dashboard", "/manage", "/management",
	// PHP-era admin tooling (still common on hosted apps)
	"/wp-admin", "/wp-login.php", "/wp-json/wp/v2/users",
	"/phpmyadmin", "/adminer", "/myadmin",
	// DevOps tooling exposure
	"/grafana", "/prometheus", "/kibana", "/jenkins",
	"/server-status", "/server-info",
	// Debug/profiling endpoints (Go pprof, Flask debug, etc.)
	"/debug", "/debug/vars", "/debug/pprof", "/debug/pprof/heap",
	// Source-control + config leakage (high-value misconfigurations)
	"/.git/config", "/.git/HEAD", "/.git/index",
	"/.svn/entries", "/.svn/wc.db",
	"/.env", "/.env.local", "/.env.production",
	"/.htaccess", "/.htpasswd", "/.DS_Store",
	// Common static / private surfaces
	"/internal", "/private", "/static", "/assets", "/public",
	"/test", "/tests", "/tmp", "/temp",
	// Crawler hints
	"/robots.txt", "/sitemap.xml",
}

// apiPathRe matches patterns like "/api/something" or "'/api/v1/users'" in JS source.
var apiPathRe = regexp.MustCompile(`["'` + "`" + `](/(?:api|v\d+)/[a-zA-Z0-9/_\-{}]+)["'` + "`" + `]`)

// scriptSrcRe matches <script src="..."> tags.
var scriptSrcRe = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)

// Crawler discovers API endpoints using multiple strategies.
type Crawler struct {
	client *http.Client
	cfg    *models.ScanConfig
	seen   map[string]bool
	// disallows is the deny list parsed from robots.txt during fromRobots,
	// used by the other discovery sources (brute-force, HTML crawl) to
	// avoid even a single fetch against disallowed paths when
	// cfg.RespectRobots is true. Empty by default.
	disallows []string
	// Discovered is the number of unique endpoints found BEFORE the
	// --max-endpoints cap truncated the returned slice. Equal to len(result)
	// when no cap fired. Read by the orchestrator after CrawlEndpoints to
	// surface coverage (endpoints_discovered / endpoints_truncated in the
	// report) instead of leaving the truncation a silent slog.Warn.
	Discovered int
	// SpecErr is the error fromSpec returned, when --spec was given and the
	// document could not be parsed. Discovery continues with the other
	// strategies (unchanged), but the orchestrator reads this to record the
	// `spec` analyzer as failed/input_error instead of leaving a silent WARN.
	SpecErr error
}

// NewCrawler creates a Crawler with an HTTP client configured from scan config.
//
// The transport raises MaxIdleConnsPerHost from Go's default of 2 to a value
// large enough to keep the brute-force phase reusing one keep-alive connection
// per host. With the default, ~115 sequential requests against the same host
// would churn TCP setup/teardown, and on macOS that reliably exhausts
// ephemeral ports when multiple httptest servers run in parallel — the e2e
// suite was flaky at exactly that boundary before this fix.
//
// The SSRF egress guard (internal/netguard) is composed UNDERNEATH the budget
// counter via budget.WrapTransportGuarded, preserving the keep-alive transport
// fields. CheckRedirect caps redirect hops and re-applies the IP policy per
// hop. This matters for the crawler specifically because robots.txt /
// sitemap.xml are fetched at the very start of discovery — before any
// same-host filter runs — so an attacker-controlled --url could otherwise
// 30x-redirect those early fetches into the metadata IP or the host's own
// network. AllowPrivate (operator flag + auto-allow for private --url targets)
// makes the guard a passthrough.
func NewCrawler(cfg *models.ScanConfig) *Crawler {
	ap := allowPrivate(cfg)
	return &Crawler{
		client: &http.Client{
			Timeout: time.Duration(cfg.Timeout) * time.Second,
			Transport: budget.WrapTransportGuarded(&http.Transport{
				MaxIdleConns:        32,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
			}, ap),
			CheckRedirect: netguard.Config{AllowPrivate: ap}.CheckRedirect(),
		},
		cfg:  cfg,
		seen: make(map[string]bool),
	}
}

// CrawlEndpoints discovers endpoints using all available strategies in priority order:
//  1. OpenAPI spec parsing (--spec)
//  2. robots.txt parsing (--url) — Disallow/Allow + Sitemap directives
//  3. sitemap.xml parsing (--url) — <loc> entries + sitemapindex recursion
//  4. JavaScript source analysis (--url)
//  5. HTML link parsing with recursive depth (--url, --crawl-depth)
//  6. Common-path brute-force, optionally from --wordlist (--url)
//
// Result is deduplicated, sorted, and capped at --max-endpoints.
func (c *Crawler) CrawlEndpoints(ctx context.Context) ([]Endpoint, error) {
	var endpoints []Endpoint
	var disallows []string // populated by fromRobots when --respect-robots is set

	if c.cfg.SpecPath != "" {
		specEndpoints, err := c.fromSpec(ctx)
		if err != nil {
			c.SpecErr = err
			slog.Warn("spec parsing failed, continuing with other strategies", "error", err)
		} else {
			endpoints = append(endpoints, specEndpoints...)
		}
	}

	if c.cfg.URL != "" {
		// robots.txt — by default we capture Disallow paths as endpoint hints
		// (high-value targets); with --respect-robots we filter them out and
		// also use them as a deny list for the other discovery sources below.
		robotsResult, err := c.fromRobots(ctx)
		if err != nil {
			slog.Debug("robots.txt discovery failed", "error", err)
		} else {
			endpoints = append(endpoints, robotsResult.endpoints...)
			disallows = robotsResult.disallows
		}

		// sitemap.xml — pull URLs declared in robots.txt first, fall back to
		// the canonical /sitemap.xml location. Both forms are common.
		sitemapURLs := robotsResult.sitemapURLs
		if len(sitemapURLs) == 0 {
			sitemapURLs = []string{strings.TrimRight(c.cfg.URL, "/") + "/sitemap.xml"}
		}
		smEndpoints, err := c.fromSitemap(ctx, sitemapURLs)
		if err != nil {
			slog.Debug("sitemap.xml discovery failed", "error", err)
		} else {
			endpoints = append(endpoints, smEndpoints...)
		}

		jsEndpoints, err := c.fromJS(ctx)
		if err != nil {
			slog.Debug("JS discovery failed", "error", err)
		} else {
			endpoints = append(endpoints, jsEndpoints...)
		}

		// Recursive HTML link crawl. Default depth 1 follows links from the
		// home page; --crawl-depth 0 disables. Same-host only; visited set
		// prevents loops; total cap enforced after dedupe via --max-endpoints.
		if c.cfg.CrawlDepth > 0 {
			htmlEndpoints, err := c.crawlHTMLLinks(ctx, c.cfg.CrawlDepth)
			if err != nil {
				slog.Debug("HTML link crawl failed", "error", err)
			} else {
				endpoints = append(endpoints, htmlEndpoints...)
			}
		}

		bruteEndpoints, err := c.fromBruteForce(ctx)
		if err != nil {
			slog.Debug("brute-force discovery failed", "error", err)
		} else {
			endpoints = append(endpoints, bruteEndpoints...)
		}
	}

	deduped := c.deduplicate(endpoints)

	// --respect-robots filter (TASK-095). Apply AFTER dedupe so we don't
	// waste matching work on duplicates from multiple discovery sources.
	// Filter against ALL discovery sources, not just robots.txt itself —
	// the polite-crawler convention is "don't fetch anything the operator
	// disallowed", regardless of how that path was discovered.
	if c.cfg.RespectRobots && len(disallows) > 0 {
		filtered := deduped[:0]
		blocked := 0
		for _, ep := range deduped {
			if pathDisallowedByRobots(ep.Path, disallows) {
				blocked++
				continue
			}
			filtered = append(filtered, ep)
		}
		if blocked > 0 {
			slog.Info("respect-robots filter applied",
				"blocked", blocked,
				"remaining", len(filtered),
				"disallow_rules", len(disallows),
			)
		}
		deduped = filtered
	}

	sort.Slice(deduped, func(i, j int) bool {
		if deduped[i].Path != deduped[j].Path {
			return deduped[i].Path < deduped[j].Path
		}
		return deduped[i].Method < deduped[j].Method
	})

	// Record the pre-truncation discovery count so the orchestrator can
	// surface coverage (endpoints_discovered / endpoints_truncated) in the
	// report — a CI gate otherwise can't tell a capped scan from a complete
	// one.
	c.Discovered = len(deduped)
	if cap := c.cfg.MaxEndpoints; cap > 0 && len(deduped) > cap {
		slog.Warn("endpoint discovery hit --max-endpoints cap; truncating",
			"discovered", len(deduped), "cap", cap)
		deduped = deduped[:cap]
	}

	slog.Info("endpoint discovery complete", "total", len(deduped))
	return deduped, nil
}

// specAllowsAnon reports whether an OpenAPI `security` value permits anonymous
// access. Mirrors python/analyzers/spec_parser.py:_allows_anon so the two
// analyzers cannot drift.
//
// In OpenAPI 3.x BOTH `security: []` and a list containing the empty object
// `security: [{}]` make auth optional. The second form is the trap: len([{}])
// is 1, so "a non-empty list means a requirement" reads an explicit opt-out as
// a requirement. Checked explicitly for that reason.
//
// An absent or malformed value returns false — it is not a claim of anonymity,
// and the caller resolves it to Unknown rather than Public.
func specAllowsAnon(security interface{}) bool {
	list, ok := security.([]interface{})
	if !ok {
		return false
	}
	if len(list) == 0 {
		return true // `security: []`
	}
	for _, req := range list {
		if m, ok := req.(map[string]interface{}); ok && len(m) == 0 {
			return true // `security: [{}]`
		}
	}
	return false
}

// authExpectationFor resolves the declared authentication expectation for one
// operation. opSecurity is the operation's own `security` value (nil = inherits
// the global one); globalSecurity is the spec's top-level value.
//
// Returns Unknown when NEITHER level declares anything. Spec silence is not a
// declaration of public access — see models.AuthExpectation on why that
// distinction is load-bearing rather than pedantic.
func authExpectationFor(opSecurity, globalSecurity interface{}) models.AuthExpectation {
	resolve := func(v interface{}) (models.AuthExpectation, bool) {
		if v == nil {
			return models.AuthExpectationUnknown, false
		}
		if specAllowsAnon(v) {
			return models.AuthExpectationPublic, true
		}
		if list, ok := v.([]interface{}); ok && len(list) > 0 {
			return models.AuthExpectationRequired, true
		}
		// Present but malformed (not a list): no usable declaration.
		return models.AuthExpectationUnknown, true
	}

	if exp, declared := resolve(opSecurity); declared {
		return exp
	}
	exp, _ := resolve(globalSecurity)
	return exp
}

// fromSpec parses an OpenAPI 2.0/3.x spec and extracts all path+method combinations.
// Accepts both local file paths and HTTP/HTTPS URLs. URL form is needed because
// many real services publish their spec at /openapi.json or /swagger.json — users
// would otherwise have to curl-then-pass, and v0.1 silently fell back to brute-force
// when given a URL (TASK-082).
func (c *Crawler) fromSpec(ctx context.Context) ([]Endpoint, error) {
	data, isJSON, err := c.loadSpec(ctx, c.cfg.SpecPath)
	if err != nil {
		return nil, err
	}

	var spec map[string]interface{}
	if isJSON {
		if err := json.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("parsing JSON spec: %w", err)
		}
	} else {
		if err := yaml.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("parsing YAML spec: %w", err)
		}
	}

	paths, ok := spec["paths"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("spec has no 'paths' field or invalid format")
	}

	baseURL := c.specBaseURL(spec)
	// The spec's top-level security requirement, inherited by every operation
	// that does not declare its own. Read once — it is the same for all paths.
	globalSecurity := spec["security"]
	var endpoints []Endpoint

	httpMethods := map[string]bool{
		"get": true, "post": true, "put": true, "patch": true,
		"delete": true, "head": true, "options": true,
	}

	for path, methods := range paths {
		methodMap, ok := methods.(map[string]interface{})
		if !ok {
			continue
		}

		// OpenAPI/Swagger lets path-level `parameters` apply to every operation
		// under that path; operation-level `parameters` add to (and may override
		// by name) the path-level set. Capture path-level once outside the
		// per-method loop.
		pathLevelParams := extractParamsList(methodMap["parameters"])

		// Path-level header params apply to every operation under the path,
		// same as query/path. Body params can only be declared per-operation
		// in OAS 3 (`requestBody` is operation-level), but Swagger 2 allows
		// `in: body` at path level so we extract from both layers.
		pathLevelHeaders := extractHeaderParamsList(methodMap["parameters"])
		pathLevelBodyParams := extractBodyParamNames(methodMap)

		for method, op := range methodMap {
			method = strings.ToLower(method)
			if !httpMethods[method] {
				continue
			}
			opMap, _ := op.(map[string]interface{})
			opParams := extractParamsList(opMap["parameters"])
			opHeaders := extractHeaderParamsList(opMap["parameters"])
			opBodyParams := extractBodyParamNames(opMap)

			// Substitute path placeholders into the URL only — keep `Path` as
			// the template form so reports still show "GET /users/{id}".
			// http.NewRequest URL-encodes `{` and `}` to `%7B`/`%7D`, which
			// every server returns 404 for, so without substitution every
			// black-box check on a templated endpoint silently observes nothing.
			schemas := extractPathParamSchemas(methodMap["parameters"], opMap["parameters"])
			fullURL := baseURL + substitutePathPlaceholders(path, schemas)

			ep := Endpoint{
				Method:     strings.ToUpper(method),
				Path:       path,
				FullURL:    fullURL,
				Params:     mergeParams(extractPathParams(path), pathLevelParams, opParams),
				Headers:    mergeParams(pathLevelHeaders, opHeaders),
				BodyParams: mergeParams(pathLevelBodyParams, opBodyParams),
				// RC-2: the spec is the only source that knows whether this
				// operation is SUPPOSED to be authenticated. Capturing it here
				// is what lets the auth check tell a public endpoint from a
				// bypassed one; opMap may be nil for a malformed operation,
				// which indexes to nil and resolves to Unknown.
				AuthExpectation: authExpectationFor(opMap["security"], globalSecurity),
			}
			endpoints = append(endpoints, ep)
		}
	}

	slog.Info("endpoints from spec", "count", len(endpoints), "spec", c.cfg.SpecPath)
	return endpoints, nil
}

// maxSpecBytes caps how many bytes we read from a spec — whether fetched
// from a URL or read from a local file — before parsing, so a malicious or
// runaway spec can't exhaust memory. GitHub's spec is ~12 MB, so 50 MB
// leaves ample headroom for legitimate specs while bounding the blast
// radius. (yaml.v3 already guards billion-laughs alias expansion; this caps
// the orthogonal "just a huge document" case.)
const maxSpecBytes = 50 << 20 // 50 MB

// loadSpec reads a spec from either a local file path or an HTTP/HTTPS URL.
// Returns the raw bytes and whether the format is JSON (vs YAML).
//
// Format detection is layered: explicit .json/.yaml suffix first, then
// HTTP Content-Type header, finally first non-whitespace byte ('{' or '[' = JSON).
// We don't fall back to "always YAML" even though yaml.Unmarshal accepts JSON,
// because the existing tests assert the JSON path produces JSON-typed errors.
func (c *Crawler) loadSpec(ctx context.Context, src string) (data []byte, isJSON bool, err error) {
	lower := strings.ToLower(src)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return c.fetchSpec(ctx, src)
	}
	// Local file: cap the read with the same ceiling as the URL path so a
	// huge (or malicious) on-disk spec can't exhaust memory. The URL branch
	// was capped (TASK-082); the local branch was not — a gap that matters
	// now that the product backend writes user-uploaded specs to disk and
	// hands the path here. Callers accepting untrusted uploads should still
	// enforce a tighter cap of their own before reaching this point.
	f, err := os.Open(src)
	if err != nil {
		return nil, false, fmt.Errorf("reading spec file %s: %w", src, err)
	}
	defer f.Close()
	data, err = io.ReadAll(io.LimitReader(f, maxSpecBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("reading spec file %s: %w", src, err)
	}
	if int64(len(data)) > maxSpecBytes {
		return nil, false, fmt.Errorf("spec file too large (>%d bytes): %s", maxSpecBytes, src)
	}
	return data, strings.HasSuffix(lower, ".json"), nil
}

// fetchSpec downloads a spec from an HTTP/HTTPS URL using the crawler's HTTP
// client (so --timeout applies). 4xx/5xx responses are surfaced as errors.
func (c *Crawler) fetchSpec(ctx context.Context, src string) (data []byte, isJSON bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, false, fmt.Errorf("building spec request: %w", err)
	}
	// Hint preference but don't restrict — many specs are served as text/plain or octet-stream.
	req.Header.Set("Accept", "application/json, application/yaml, text/yaml, */*")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("fetching spec from %s: %w", src, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return nil, false, fmt.Errorf("fetching spec from %s: HTTP %d", src, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSpecBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("reading spec body: %w", err)
	}
	if int64(len(body)) > maxSpecBytes {
		return nil, false, fmt.Errorf("spec too large (>%d bytes) from %s", maxSpecBytes, src)
	}

	// Format detection: URL suffix > Content-Type > first non-whitespace byte.
	lowerSrc := strings.ToLower(src)
	switch {
	case strings.HasSuffix(lowerSrc, ".json"):
		isJSON = true
	case strings.HasSuffix(lowerSrc, ".yaml") || strings.HasSuffix(lowerSrc, ".yml"):
		isJSON = false
	default:
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		switch {
		case strings.Contains(ct, "json"):
			isJSON = true
		case strings.Contains(ct, "yaml") || strings.Contains(ct, "yml"):
			isJSON = false
		default:
			isJSON = looksLikeJSON(body)
		}
	}

	return body, isJSON, nil
}

// looksLikeJSON returns true if the first non-whitespace byte is '{' or '['.
// This is the canonical JSON-vs-YAML sniff used by parsers when no other
// signal is available (suffix, Content-Type).
func looksLikeJSON(b []byte) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// specBaseURL extracts the base URL from an OpenAPI spec.
// Supports both OpenAPI 3.x (servers[0].url) and Swagger 2.0 (host + basePath).
func (c *Crawler) specBaseURL(spec map[string]interface{}) string {
	// Prefer explicit --url flag
	if c.cfg.URL != "" {
		return strings.TrimRight(c.cfg.URL, "/")
	}

	// OpenAPI 3.x: servers[0].url
	if servers, ok := spec["servers"].([]interface{}); ok && len(servers) > 0 {
		if srv, ok := servers[0].(map[string]interface{}); ok {
			if u, ok := srv["url"].(string); ok {
				return strings.TrimRight(u, "/")
			}
		}
	}

	// Swagger 2.0: host + basePath
	host, _ := spec["host"].(string)
	basePath, _ := spec["basePath"].(string)
	scheme := "https"
	if schemes, ok := spec["schemes"].([]interface{}); ok && len(schemes) > 0 {
		if s, ok := schemes[0].(string); ok {
			scheme = s
		}
	}
	if host != "" {
		return fmt.Sprintf("%s://%s%s", scheme, host, strings.TrimRight(basePath, "/"))
	}

	return "http://localhost"
}

// fromJS fetches the base URL page, extracts <script> sources,
// downloads each JS file, and extracts API path patterns.
func (c *Crawler) fromJS(ctx context.Context) ([]Endpoint, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.cfg.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", c.cfg.URL, err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching base URL %s: %w", c.cfg.URL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var endpoints []Endpoint
	baseURL := strings.TrimRight(c.cfg.URL, "/")

	// Extract paths directly from HTML/JSON response. JS-discovered paths can
	// contain `{id}`-style placeholders (the apiPathRe regex includes braces),
	// so apply name-heuristic substitution to FullURL — no schema is available
	// from raw JS source, but `/users/{id}` → `/users/1` still beats the
	// broken `/users/%7Bid%7D` request.
	for _, match := range apiPathRe.FindAllSubmatch(body, -1) {
		path := string(match[1])
		endpoints = append(endpoints, Endpoint{
			Method:  "GET",
			Path:    path,
			FullURL: baseURL + substitutePathPlaceholders(path, nil),
			Params:  extractPathParams(path),
		})
	}

	// Find and fetch script sources
	scriptMatches := scriptSrcRe.FindAllSubmatch(body, -1)
	for _, match := range scriptMatches {
		scriptURL := resolveURL(c.cfg.URL, string(match[1]))
		jsPaths, err := c.extractPathsFromJS(ctx, scriptURL)
		if err != nil {
			slog.Debug("failed to fetch JS", "url", scriptURL, "error", err)
			continue
		}
		for _, path := range jsPaths {
			endpoints = append(endpoints, Endpoint{
				Method:  "GET",
				Path:    path,
				FullURL: baseURL + substitutePathPlaceholders(path, nil),
				Params:  extractPathParams(path),
			})
		}
	}

	slog.Info("endpoints from JS discovery", "count", len(endpoints))
	return endpoints, nil
}

// extractPathsFromJS downloads a JS file and extracts API path patterns.
func (c *Crawler) extractPathsFromJS(ctx context.Context, jsURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating JS request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JS %s: %w", jsURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading JS body: %w", err)
	}

	var paths []string
	for _, match := range apiPathRe.FindAllSubmatch(body, -1) {
		paths = append(paths, string(match[1]))
	}
	return paths, nil
}

// fromBruteForce tries common API paths against the target and returns those that respond.
// The path list is c.cfg.WordlistPath when set, otherwise CommonPaths.
func (c *Crawler) fromBruteForce(ctx context.Context) ([]Endpoint, error) {
	baseURL := strings.TrimRight(c.cfg.URL, "/")
	var endpoints []Endpoint

	paths, err := c.loadWordlist()
	if err != nil {
		return nil, err
	}

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return endpoints, ctx.Err()
		default:
		}

		// --respect-robots pre-filter: skip paths covered by a Disallow
		// rule before sending even a discovery probe. Without this the
		// brute-force loop would still GET /admin to check existence,
		// breaking the "polite scanner never touches disallowed URLs"
		// contract that the flag implies.
		if c.cfg.RespectRobots && pathDisallowedByRobots(path, c.disallows) {
			continue
		}

		fullURL := baseURL + path
		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}
		c.cfg.Auth.ApplyToRequest(req)

		resp, err := c.client.Do(req)
		if err != nil {
			continue
		}
		// Drain the body before close so net/http can return the connection
		// to the keep-alive pool. Without this, Go marks the connection
		// "unfit for reuse" and tears down the TCP socket — which is fine for
		// one or two probes but rapidly exhausts ephemeral source ports when
		// hammering 117 paths against the same host.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode < 404 {
			endpoints = append(endpoints, Endpoint{
				Method:  "GET",
				Path:    path,
				FullURL: fullURL,
			})
		}

		if c.cfg.DelayMs > 0 {
			time.Sleep(time.Duration(c.cfg.DelayMs) * time.Millisecond)
		}
	}

	slog.Info("endpoints from brute-force", "count", len(endpoints), "wordlist_size", len(paths))
	return endpoints, nil
}

// loadWordlist returns the brute-force path list. Reads c.cfg.WordlistPath
// if set (one path per line, `#` comments + blank lines skipped, leading
// `/` added if missing), otherwise returns CommonPaths.
func (c *Crawler) loadWordlist() ([]string, error) {
	if c.cfg.WordlistPath == "" {
		return CommonPaths, nil
	}
	data, err := os.ReadFile(c.cfg.WordlistPath)
	if err != nil {
		return nil, fmt.Errorf("reading wordlist %s: %w", c.cfg.WordlistPath, err)
	}
	var paths []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			line = "/" + line
		}
		paths = append(paths, line)
	}
	return paths, nil
}

// robotsDiscovery is the result of parsing a robots.txt file: discovered
// endpoint paths plus any Sitemap: URLs declared in the file, plus the
// Disallow path list. Default: Disallow paths are treated as a discovery
// hint (queued as endpoints) — those paths are exactly the URLs operators
// don't want exposed, so they're high-value targets for a security tool.
// With cfg.RespectRobots set: Disallow paths are filtered OUT of the
// crawl entirely (polite-crawler convention for third-party scans), and
// the Disallow list is propagated up so the caller can also filter
// endpoints discovered via other strategies (sitemap, HTML crawl,
// brute-force) that happen to fall under a disallowed prefix.
type robotsDiscovery struct {
	endpoints   []Endpoint
	sitemapURLs []string
	disallows   []string // populated only when cfg.RespectRobots is true
}

// fromRobots fetches /robots.txt and extracts endpoint paths, Sitemap URLs,
// and Disallow patterns. Missing or 4xx robots.txt is not an error — many
// sites simply don't publish one.
func (c *Crawler) fromRobots(ctx context.Context) (robotsDiscovery, error) {
	baseURL := strings.TrimRight(c.cfg.URL, "/")
	body, err := c.fetchBody(ctx, baseURL+"/robots.txt", 1<<20) // 1 MB cap
	if err != nil {
		return robotsDiscovery{}, err
	}
	disallows, allows, sitemaps := parseRobots(body)
	res := robotsDiscovery{sitemapURLs: sitemaps}

	// Always queue Allow paths as discovery hints — they're publicly
	// declared as scannable.
	hints := allows
	if !c.cfg.RespectRobots {
		// Default behaviour: Disallow paths ARE the most interesting targets
		// (admin panels, internal APIs that operators flag as off-limits to
		// crawlers but leave un-secured), so queue them too.
		hints = append(hints, disallows...)
	} else {
		// Polite mode: forward the Disallow list so CrawlEndpoints can
		// filter every other discovery source against it. Also stash on
		// the Crawler so brute-force / HTML crawl can pre-filter their
		// candidate paths before sending a single request — that way the
		// scan never even probes a disallowed URL during discovery.
		res.disallows = disallows
		c.disallows = disallows
	}

	for _, p := range hints {
		res.endpoints = append(res.endpoints, Endpoint{
			Method: "GET",
			Path:   p,
			// Most robots.txt entries are concrete paths, but a few sites
			// list templated patterns (e.g. `Disallow: /users/{id}/admin`).
			// Apply name-heuristic substitution defensively.
			FullURL: baseURL + substitutePathPlaceholders(p, nil),
			Params:  extractPathParams(p),
		})
	}
	slog.Info("endpoints from robots.txt",
		"count", len(res.endpoints),
		"sitemaps", len(sitemaps),
		"disallows_filtered", len(res.disallows),
	)
	return res, nil
}

// parseRobots parses a robots.txt body. Returns Disallow paths, Allow paths,
// and Sitemap URLs separately so callers can decide how to treat each
// (--respect-robots filters Disallows, default mode queues them as hints).
// All paths are de-duplicated within their own list and have a leading `/`.
// User-agent grouping is intentionally ignored — discovery is path-level
// regardless of which agent the rule targets.
func parseRobots(body []byte) (disallows, allows, sitemapURLs []string) {
	disSeen, allowSeen, smSeen := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:i]))
		val := strings.TrimSpace(line[i+1:])
		if val == "" {
			continue
		}
		switch key {
		case "disallow":
			// Strip wildcard suffix (`/admin/*` → `/admin/`) and trailing `$`
			// — those are pattern-match anchors, not literal characters.
			cleaned := strings.TrimSuffix(val, "$")
			cleaned = strings.TrimSuffix(cleaned, "*")
			if !strings.HasPrefix(cleaned, "/") || disSeen[cleaned] {
				continue
			}
			disSeen[cleaned] = true
			disallows = append(disallows, cleaned)
		case "allow":
			cleaned := strings.TrimSuffix(val, "$")
			cleaned = strings.TrimSuffix(cleaned, "*")
			if !strings.HasPrefix(cleaned, "/") || allowSeen[cleaned] {
				continue
			}
			allowSeen[cleaned] = true
			allows = append(allows, cleaned)
		case "sitemap":
			if smSeen[val] {
				continue
			}
			smSeen[val] = true
			sitemapURLs = append(sitemapURLs, val)
		}
	}
	return disallows, allows, sitemapURLs
}

// pathDisallowedByRobots reports whether `path` falls under any Disallow
// rule, using prefix match (the standard robots.txt convention). An empty
// rules list means "nothing is disallowed".
func pathDisallowedByRobots(path string, rules []string) bool {
	for _, r := range rules {
		if r == "" {
			continue
		}
		// `/` as a Disallow rule means "everything"; any non-root path matches.
		if r == "/" {
			return true
		}
		if strings.HasPrefix(path, r) {
			return true
		}
	}
	return false
}

// sitemapURLEntry / sitemapIndexEntry / sitemapDoc capture the two sitemap
// XML formats: <urlset><url><loc>... for normal sitemaps and
// <sitemapindex><sitemap><loc>... for sitemap-of-sitemaps. We parse a single
// document tolerantly via a struct that admits both children.
type sitemapEntry struct {
	Loc string `xml:"loc"`
}

type sitemapDoc struct {
	URLs     []sitemapEntry `xml:"url"`
	Sitemaps []sitemapEntry `xml:"sitemap"`
}

// fromSitemap fetches one or more sitemap.xml URLs and returns the discovered
// page endpoints. Sitemap-index files are followed one level deep (typical
// real-world structure: index → child sitemaps → URL list).
func (c *Crawler) fromSitemap(ctx context.Context, urls []string) ([]Endpoint, error) {
	const maxSitemapBytes = 10 << 20 // 10 MB; large sitemaps are real
	const maxIndexFollow = 16        // cap on child sitemaps to prevent runaway

	visited := map[string]bool{}
	var queue []string
	queue = append(queue, urls...)
	var pages []string

	for len(queue) > 0 && len(visited) < maxIndexFollow {
		u := queue[0]
		queue = queue[1:]
		if u == "" || visited[u] {
			continue
		}
		visited[u] = true

		body, err := c.fetchBody(ctx, u, maxSitemapBytes)
		if err != nil {
			slog.Debug("sitemap fetch failed", "url", u, "error", err)
			continue
		}
		urlList, childSitemaps := parseSitemap(body)
		pages = append(pages, urlList...)
		queue = append(queue, childSitemaps...)
	}

	base, err := url.Parse(c.cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing --url for sitemap host filter: %w", err)
	}
	baseHost := strings.ToLower(base.Host)

	var endpoints []Endpoint
	pathSeen := map[string]bool{}
	for _, raw := range pages {
		parsed, err := url.Parse(raw)
		if err != nil {
			continue
		}
		// Sitemap entries usually carry a host; if absent, treat as same-host.
		if parsed.Host != "" && strings.ToLower(parsed.Host) != baseHost {
			continue
		}
		path := parsed.Path
		if path == "" {
			path = "/"
		}
		if pathSeen[path] {
			continue
		}
		pathSeen[path] = true
		endpoints = append(endpoints, Endpoint{
			Method:  "GET",
			Path:    path,
			FullURL: strings.TrimRight(c.cfg.URL, "/") + substitutePathPlaceholders(path, nil),
			Params:  extractPathParams(path),
		})
	}
	slog.Info("endpoints from sitemap", "count", len(endpoints), "documents", len(visited))
	return endpoints, nil
}

// parseSitemap returns (page URLs, child sitemap URLs) from a sitemap XML
// document. Tolerant of malformed XML — returns empty lists rather than
// erroring, since a broken sitemap shouldn't kill the whole scan.
func parseSitemap(body []byte) (pages, childSitemaps []string) {
	var doc sitemapDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		return nil, nil
	}
	for _, e := range doc.URLs {
		if e.Loc != "" {
			pages = append(pages, strings.TrimSpace(e.Loc))
		}
	}
	for _, e := range doc.Sitemaps {
		if e.Loc != "" {
			childSitemaps = append(childSitemaps, strings.TrimSpace(e.Loc))
		}
	}
	return pages, childSitemaps
}

// anchorHrefRe matches <a ... href="..."> and form actionRe matches
// <form ... action="...">. Lower/upper-case tag names handled with
// case-insensitive flag; quotes are required (bare-href HTML5 unquoted
// attributes are rare on real sites and not worth the parser complexity).
var (
	anchorHrefRe = regexp.MustCompile(`(?i)<a\b[^>]*?\shref=["']([^"'#]+)["']`)
	formActionRe = regexp.MustCompile(`(?i)<form\b[^>]*?\saction=["']([^"'#]+)["']`)
)

// crawlHTMLLinks performs a BFS crawl from --url, extracting <a href> and
// <form action> targets and following same-host links up to the given depth.
// depth=1 means "extract links from the home page only"; depth=2 also
// follows those links and harvests their links; etc. A visited set prevents
// loops, and --max-endpoints caps the result globally (applied after dedupe).
func (c *Crawler) crawlHTMLLinks(ctx context.Context, depth int) ([]Endpoint, error) {
	if depth <= 0 || c.cfg.URL == "" {
		return nil, nil
	}
	base, err := url.Parse(c.cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parsing --url: %w", err)
	}
	baseHost := strings.ToLower(base.Host)

	type queued struct {
		url   string
		depth int
	}
	visited := map[string]bool{c.cfg.URL: true}
	queue := []queued{{c.cfg.URL, 0}}
	var endpoints []Endpoint

	const maxBytes = 5 * 1024 * 1024 // 5 MB per page

	// cap is applied two places: here (early-exit the BFS the moment we
	// reach the budget, so we stop fetching pages and parsing HTML) and
	// again post-walk in CrawlEndpoints as the canonical truncate. The
	// post-walk truncate stays as belt-and-suspenders against future
	// callers, but for `--crawl-depth ≥ 2` against large sites the
	// in-loop check saves real CPU + bandwidth.
	cap := c.cfg.MaxEndpoints
	for len(queue) > 0 {
		select {
		case <-ctx.Done():
			return endpoints, ctx.Err()
		default:
		}
		if cap > 0 && len(endpoints) >= cap {
			slog.Debug("html-crawl reached --max-endpoints; stopping BFS",
				"endpoints", len(endpoints), "cap", cap,
				"queue_remaining", len(queue))
			break
		}

		cur := queue[0]
		queue = queue[1:]

		body, err := c.fetchBody(ctx, cur.url, maxBytes)
		if err != nil {
			slog.Debug("html-crawl fetch failed", "url", cur.url, "error", err)
			continue
		}

		for _, raw := range extractHTMLLinks(body) {
			// Inner short-circuit: don't keep processing links from
			// the current page once we're at cap.
			if cap > 0 && len(endpoints) >= cap {
				break
			}
			// Drop non-http(s) schemes early: `mailto:`, `tel:`, `javascript:`,
			// `data:` URLs are common in real HTML but not scannable as endpoints.
			if hasUnscannableScheme(raw) {
				continue
			}
			absolute := resolveURL(cur.url, raw)
			parsed, err := url.Parse(absolute)
			if err != nil {
				continue
			}
			parsed.Fragment = ""
			// After resolution, scheme should be http/https; reject anything else
			// (defensive — resolveURL can preserve unexpected schemes).
			if parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
				continue
			}
			// Same-host only — the scanner shouldn't probe arbitrary external
			// links it happens to find on the page. Cross-host CDN URLs etc.
			// are noise here.
			if parsed.Host != "" && strings.ToLower(parsed.Host) != baseHost {
				continue
			}
			cleaned := parsed.String()
			if visited[cleaned] {
				continue
			}
			visited[cleaned] = true

			path := parsed.Path
			if path == "" {
				path = "/"
			}
			// Substitute path placeholders for sendable URL while keeping the
			// template form on the Path field for human-readable reports.
			fullURL := cleaned
			if strings.Contains(path, "{") {
				parsed.Path = substitutePathPlaceholders(path, nil)
				fullURL = parsed.String()
			}
			endpoints = append(endpoints, Endpoint{
				Method:  "GET",
				Path:    path,
				FullURL: fullURL,
				Params:  extractPathParams(path),
			})

			if cur.depth+1 < depth {
				queue = append(queue, queued{cleaned, cur.depth + 1})
			}
		}

		if c.cfg.DelayMs > 0 {
			time.Sleep(time.Duration(c.cfg.DelayMs) * time.Millisecond)
		}
	}

	slog.Info("endpoints from HTML crawl", "count", len(endpoints), "depth", depth)
	return endpoints, nil
}

// unscannableSchemes are URL schemes whose values are not HTTP endpoints.
// Common in real HTML (mailto contact links, tel: links, javascript: handlers,
// data: URIs); following them produces "unsupported protocol scheme" errors
// downstream and noisy findings on phantom endpoints.
var unscannableSchemes = []string{"mailto:", "tel:", "javascript:", "data:", "ftp:", "file:", "sms:"}

// hasUnscannableScheme reports whether the raw href starts with a non-HTTP
// scheme we can't probe. Comparison is case-insensitive — `MAILTO:` happens
// in real HTML.
func hasUnscannableScheme(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	for _, prefix := range unscannableSchemes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// extractHTMLLinks returns raw href/action values from anchor and form tags.
// Fragment-only links (`#section`) are dropped at regex level so we don't
// re-fetch the same page with no path change.
func extractHTMLLinks(body []byte) []string {
	var raw []string
	for _, m := range anchorHrefRe.FindAllSubmatch(body, -1) {
		raw = append(raw, string(m[1]))
	}
	for _, m := range formActionRe.FindAllSubmatch(body, -1) {
		raw = append(raw, string(m[1]))
	}
	return raw
}

// fetchBody performs an authenticated GET against target with a body cap.
// Used by robots.txt, sitemap.xml, and the HTML crawl.
func (c *Crawler) fetchBody(ctx context.Context, target string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", target, err)
	}
	c.cfg.Auth.ApplyToRequest(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", target, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("fetching %s: HTTP %d", target, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s body: %w", target, err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response from %s exceeds %d-byte cap", target, maxBytes)
	}
	return body, nil
}

// deduplicate removes duplicate endpoints by Method+Path key.
func (c *Crawler) deduplicate(endpoints []Endpoint) []Endpoint {
	var result []Endpoint
	for _, ep := range endpoints {
		key := ep.Method + " " + ep.Path
		if !c.seen[key] {
			c.seen[key] = true
			result = append(result, ep)
		}
	}
	return result
}

// extractPathParams returns parameter names from a path template like /users/{id}.
func extractPathParams(path string) []string {
	re := regexp.MustCompile(`\{([^}]+)\}`)
	matches := re.FindAllStringSubmatch(path, -1)
	var params []string
	for _, m := range matches {
		params = append(params, m[1])
	}
	return params
}

// pathPlaceholderRe matches `{name}` placeholders in OpenAPI path templates.
// Stops at `/` so chained placeholders like `/users/{id}/posts/{post_id}`
// resolve placeholder-by-placeholder instead of as one greedy span.
var pathPlaceholderRe = regexp.MustCompile(`\{([^/}]+)\}`)

// pathParamSchema is the resolved schema info for one path parameter, used to
// pick a concrete sample value when substituting `{name}` placeholders into
// the URL we'll actually send. Only the fields we consult are kept.
type pathParamSchema struct {
	Type    string        // OpenAPI type: integer, number, string, boolean
	Format  string        // e.g. uuid, date, date-time
	Example interface{}   // schema.example or parameter-level example
	Enum    []interface{} // first enum value used as fallback when example absent
}

// extractPathParamSchemas walks one or more OAS `parameters` lists and returns
// a map name → schema info for entries with `in: path`. Path-level + op-level
// lists can be passed in order; later entries overwrite earlier on duplicate
// names (op-level overrides path-level, which matches OpenAPI semantics).
//
// Both OpenAPI 3 (schema nested under `parameters[*].schema`) and Swagger 2
// (type/format/enum/example directly on the parameter) are accepted. $ref
// entries are skipped — deref is out of scope, same convention as
// extractParamsList / extractBodyParamNames.
func extractPathParamSchemas(lists ...interface{}) map[string]pathParamSchema {
	out := make(map[string]pathParamSchema)
	for _, raw := range lists {
		list, ok := raw.([]interface{})
		if !ok {
			continue
		}
		for _, item := range list {
			entry, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if _, hasRef := entry["$ref"]; hasRef {
				continue
			}
			name, _ := entry["name"].(string)
			in, _ := entry["in"].(string)
			if name == "" || strings.ToLower(in) != "path" {
				continue
			}
			ps := pathParamSchema{}
			// OAS 3: schema is nested under parameters[*].schema
			if schema, ok := entry["schema"].(map[string]interface{}); ok {
				ps.Type, _ = schema["type"].(string)
				ps.Format, _ = schema["format"].(string)
				ps.Example = schema["example"]
				if e, ok := schema["enum"].([]interface{}); ok {
					ps.Enum = e
				}
			} else {
				// Swagger 2: type/format/enum/example sit directly on the parameter
				ps.Type, _ = entry["type"].(string)
				ps.Format, _ = entry["format"].(string)
				ps.Example = entry["example"]
				if e, ok := entry["enum"].([]interface{}); ok {
					ps.Enum = e
				}
			}
			// Parameter-level example overrides schema-level when both present
			// (OAS 3 lets authors set examples at either layer).
			if px, ok := entry["example"]; ok && px != nil {
				ps.Example = px
			}
			out[name] = ps
		}
	}
	return out
}

// substitutePathPlaceholders replaces every `{name}` placeholder in a path
// template with a concrete sample value. Returns the path unchanged if it
// has no placeholders (fast path — most discovered paths are concrete).
//
// The motivation is that http.NewRequest URL-encodes `{` and `}` to `%7B`
// and `%7D`, so an un-substituted `/users/{id}` becomes `/users/%7Bid%7D` on
// the wire — every server returns 404 for that, and every black-box check
// fires zero findings on that endpoint. Substitution makes the request hit
// real handler code so checks (auth, headers, exposure, injection) actually
// observe response behaviour.
//
// Sample-value selection order:
//  1. schema.example (or parameter-level example, OAS 3 allows either)
//  2. schema.enum[0]
//  3. type-driven default (integer/number → "1", boolean → "true",
//     string with format=uuid → all-zero UUID, etc.)
//  4. parameter-name heuristic (`*id` → "1", `*name` → "sample", ...)
//  5. plain "1"
//
// The result is run through url.PathEscape so values containing reserved
// characters (e.g. an example like "abc/def") don't break the path.
func substitutePathPlaceholders(template string, schemas map[string]pathParamSchema) string {
	if !strings.Contains(template, "{") {
		return template
	}
	return pathPlaceholderRe.ReplaceAllStringFunc(template, func(match string) string {
		name := strings.TrimSuffix(strings.TrimPrefix(match, "{"), "}")
		return url.PathEscape(samplePathValue(name, schemas[name]))
	})
}

// samplePathValue picks a concrete sample for one path parameter.
// See substitutePathPlaceholders for the order of resolution.
func samplePathValue(name string, ps pathParamSchema) string {
	if ps.Example != nil {
		return fmt.Sprintf("%v", ps.Example)
	}
	if len(ps.Enum) > 0 && ps.Enum[0] != nil {
		return fmt.Sprintf("%v", ps.Enum[0])
	}
	switch strings.ToLower(ps.Type) {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	case "string":
		switch strings.ToLower(ps.Format) {
		case "uuid":
			return "00000000-0000-0000-0000-000000000000"
		case "date":
			return "2024-01-01"
		case "date-time":
			return "2024-01-01T00:00:00Z"
		case "email":
			return "user@example.com"
		}
		return sampleByName(name)
	}
	return sampleByName(name)
}

// sampleByName picks a sample value based on substring hints in the parameter
// name, used when the spec gives no schema info AND for non-spec discovery
// sources (JS regex, sitemap, HTML crawl) where placeholder paths slip in.
//
// The heuristic is conservative: prefer numeric "1" for anything that looks
// like an identifier (the common case for REST APIs), only fall back to a
// string sample for clearly-non-numeric names. Word-boundary checks matter:
// `HasSuffix("valid", "id")` is true even though "valid" is not an ID-typed
// name, so we require either an exact match, a snake_case boundary, or a
// camelCase boundary to count something as identifier-shaped.
func sampleByName(name string) string {
	lname := strings.ToLower(name)
	switch {
	case strings.Contains(lname, "uuid") || strings.Contains(lname, "guid"):
		return "00000000-0000-0000-0000-000000000000"
	case lname == "id" ||
		strings.HasSuffix(name, "Id") || // camelCase: userId, postId
		strings.HasSuffix(name, "ID") || // SCREAMING-ish: UserID
		strings.HasSuffix(lname, "_id"): // snake_case: user_id
		return "1"
	case lname == "index" || lname == "page" || lname == "limit" ||
		lname == "offset" || lname == "count":
		return "1"
	default:
		return "sample"
	}
}

// extractParamsList reads an OpenAPI/Swagger `parameters` array (raw decoded
// YAML/JSON) and returns the names of params with `in: query` or `in: path`.
// Header and body params have their own extractors (extractHeaderParamsList,
// extractBodyParamNames). Returns nil if the input isn't a list.
//
// Accepts the value type produced by yaml.v3 (map[string]interface{} entries)
// and the type produced by encoding/json (also map[string]interface{}). Both
// land in the same shape after Unmarshal into map[string]interface{}.
func extractParamsList(raw interface{}) []string {
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	var names []string
	for _, item := range list {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		// $ref entries left unresolved; deref is out of scope for v0.3.
		if _, hasRef := entry["$ref"]; hasRef {
			continue
		}
		name, _ := entry["name"].(string)
		in, _ := entry["in"].(string)
		if name == "" {
			continue
		}
		switch strings.ToLower(in) {
		case "query", "path":
			names = append(names, name)
		}
	}
	return names
}

// skippableHeaderNames are headers we never probe with injection payloads.
// Authorization-class headers are the auth scanner's responsibility, and
// scribbling junk into them risks breaking the test session for downstream
// endpoints. Compared lower-case.
var skippableHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"apikey":              true,
	"api-key":             true,
}

// extractHeaderParamsList returns the names of `in: header` params, with
// standard auth headers filtered out (see skippableHeaderNames). Same input
// shape as extractParamsList. Custom headers like X-Trace-Id, X-User-Role,
// etc. are preserved — those are exactly the fields where header-value
// injection bugs hide.
func extractHeaderParamsList(raw interface{}) []string {
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	var names []string
	for _, item := range list {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if _, hasRef := entry["$ref"]; hasRef {
			continue
		}
		name, _ := entry["name"].(string)
		in, _ := entry["in"].(string)
		if name == "" || strings.ToLower(in) != "header" {
			continue
		}
		if skippableHeaderNames[strings.ToLower(name)] {
			continue
		}
		names = append(names, name)
	}
	return names
}

// extractBodyParamNames returns the JSON body field names declared on an
// operation (or path-level entry). Handles both:
//
//   - OpenAPI 3: operation.requestBody.content["application/json"].schema.properties
//   - Swagger 2: parameters[*] where in=body, schema.properties
//
// Nested objects are walked one level deep (top-level properties only) since
// active probing of nested fields would multiply the probe budget without
// matching how most JSON-body SQLi bugs surface in practice. $ref schemas
// are skipped — deref is out of scope, same as extractParamsList.
func extractBodyParamNames(opMap map[string]interface{}) []string {
	if opMap == nil {
		return nil
	}
	var names []string

	// OpenAPI 3: requestBody.content."application/json".schema.properties
	if rb, ok := opMap["requestBody"].(map[string]interface{}); ok {
		if content, ok := rb["content"].(map[string]interface{}); ok {
			// Pick the JSON content type if present; spec authors commonly
			// duplicate the schema across content types so the first JSON-y
			// match is enough.
			for ct, body := range content {
				ctLower := strings.ToLower(ct)
				if !strings.Contains(ctLower, "json") {
					continue
				}
				bodyMap, ok := body.(map[string]interface{})
				if !ok {
					continue
				}
				schema, _ := bodyMap["schema"].(map[string]interface{})
				names = append(names, schemaPropertyNames(schema)...)
				break
			}
		}
	}

	// Swagger 2: parameters[*] where in=body, schema.properties
	if params, ok := opMap["parameters"].([]interface{}); ok {
		for _, p := range params {
			entry, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			in, _ := entry["in"].(string)
			if strings.ToLower(in) != "body" {
				continue
			}
			schema, _ := entry["schema"].(map[string]interface{})
			names = append(names, schemaPropertyNames(schema)...)
		}
	}

	return names
}

// schemaPropertyNames returns the top-level property names from a JSON-Schema
// `properties` object. Returns nil for $ref-only schemas or non-object types.
func schemaPropertyNames(schema map[string]interface{}) []string {
	if schema == nil {
		return nil
	}
	if _, hasRef := schema["$ref"]; hasRef {
		return nil
	}
	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		return nil
	}
	// Sort for deterministic ordering (map iteration is random in Go).
	names := make([]string, 0, len(props))
	for name := range props {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// mergeParams combines multiple param-name lists, preserving first-seen order
// and deduplicating case-sensitively. Used to layer URL-template params,
// path-level spec params, and operation-level spec params into one list.
func mergeParams(lists ...[]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, l := range lists {
		for _, name := range l {
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// resolveURL resolves a potentially relative URL against a base URL.
func resolveURL(base, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}

	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}

	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}

	return baseURL.ResolveReference(refURL).String()
}
