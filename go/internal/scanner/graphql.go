package scanner

// Active GraphQL introspection-exposure check (CWE-200).
//
// A GraphQL endpoint with introspection enabled hands an attacker the full
// schema — every type, field, argument and (if exposed) mutation — which is the
// reconnaissance starting point for the rest of an API attack. This check
// confirms introspection is reachable by POSTing the standard minimal
// introspection query and requiring a VALID GraphQL response shape back.
//
// ============================================================================
// DISCOVERY-GAP MITIGATION (why this is an ORIGIN sweep, not per-endpoint):
//
//   The passive crawler almost never finds a POST-only /graphql: there is no
//   link to follow, and a GET to /graphql is typically a 400/405 or a GraphiQL
//   HTML shell. So relying on crawled endpoints would miss the most common case.
//   Instead this check probes a BOUNDED set of well-known GraphQL paths at the
//   TARGET ORIGIN, exactly ONCE PER SCAN per origin (guarded by graphqlSwept).
//   Doing the sweep per-endpoint would POST an introspection query to every
//   crawled endpoint of the origin — needless traffic and noise — so the sweep
//   is origin-scoped and runs only the first time an origin is seen.
//
//   PLUS: if the CURRENT endpoint's own path contains "graphql" (case-
//   insensitive), it is probed directly even if it is not in the known-path set
//   — this recovers a non-standard but crawler-discovered GraphQL path.
//
// ============================================================================
// FALSE-POSITIVE CONTROL (LOAD-BEARING — this IS the check):
//
//   A positive requires the FULL valid GraphQL introspection SHAPE, NEVER a
//   bare 200. Specifically:
//     (1) the Content-Type must contain "application/json" or
//         "application/graphql-response+json", AND
//     (2) the parsed body must have data.__schema as a JSON object that itself
//         carries a queryType.
//   A static 200 (HTML welcome page, {"ok":true}, a generic API root) does NOT
//   satisfy the shape and yields NO finding. The same shape requirement applies
//   to the GET-execution sub-finding (a valid data.__typename / data.__schema is
//   required, not a bare 200).
//
//   Severity: introspection enabled → HIGH (CWE-200). If data.__schema
//   .mutationType is a non-null named type (mutations exposed) the severity
//   stays HIGH but the evidence notes the exposed mutation surface.
//
//   GET-execution sub-finding (MEDIUM): after a positive introspection, the same
//   query is replayed via GET (?query=...). If GET ALSO returns a valid data
//   shape, the endpoint executes state-changing-capable queries from a GET — a
//   CSRF surface (a GET can be triggered cross-site via <img>/<script>).
//
// ============================================================================
// KNOWN LIMITS (honest, documented false negatives — deliberate scope):
//
//   - NO OUT-OF-BAND / BLIND detection. fendix ships no collaborator server, so
//     a GraphQL surface that only manifests via a server-side side effect with
//     no in-band introspection response is undetectable here.
//   - DISCOVERY is bounded to the 7 known paths + any crawled path containing
//     "graphql". A GraphQL endpoint mounted at a non-standard, unlinked, POST-
//     only path the crawler never saw (e.g. /internal/q7) is MISSED.
//   - NO "PRODUCTION" SIGNAL. fendix has no --env flag, so this cannot say
//     "introspection is on in production specifically" vs a staging host; it
//     reports the exposure of whatever origin it is pointed at.
//   - NO WAF / DEPTH-LIMIT / disable-introspection EVASION is attempted. A server
//     that blocks the canonical __schema introspection but leaks the schema via a
//     field-suggestion or alias trick will read as "introspection disabled" here.
//   - The GET-execution finding is MEDIUM (a CSRF surface, not proven CSRF): we
//     do not demonstrate a cross-site request actually mutating state.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/logagg"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// graphqlIntrospectionQuery is the standard minimal introspection query. It
// asks only for the query/mutation type names — enough to confirm introspection
// is enabled and to learn whether mutations are exposed, without pulling the
// whole (potentially huge) schema.
const graphqlIntrospectionQuery = `query{__schema{queryType{name} mutationType{name}}}`

// graphqlIntrospectionBody is the JSON request body for the introspection POST.
const graphqlIntrospectionBody = `{"query":"query{__schema{queryType{name} mutationType{name}}}"}`

// graphqlBodyLimit caps how much of each response body we read into memory.
const graphqlBodyLimit = 1 << 20 // 1 MiB

// graphqlKnownPaths is the BOUNDED well-known GraphQL path set probed at the
// target origin once per scan. Kept small and ordered most-common-first.
var graphqlKnownPaths = []string{
	"/graphql",
	"/api/graphql",
	"/v1/graphql",
	"/graphql/v1",
	"/query",
	"/api/v1/graphql",
	"/gql",
}

// graphqlSwept tracks origins already swept this scan, so the bounded known-path
// sweep runs ONCE PER ORIGIN. It is guarded by graphqlSweptMu because the worker
// pool runs checks across goroutines (concurrency-safe) and is cleared by
// resetGraphQLSweep (test-safe; called from ResetGlobalAuditLog).
var (
	graphqlSweptMu sync.Mutex
	graphqlSwept   = map[string]bool{}
)

// resetGraphQLSweep clears the per-scan origin-sweep guard. Called from
// ResetGlobalAuditLog so each scan/test starts with a clean sweep set and no
// "already swept" state leaks across runs.
func resetGraphQLSweep() {
	graphqlSweptMu.Lock()
	defer graphqlSweptMu.Unlock()
	graphqlSwept = map[string]bool{}
}

// markOriginSwept atomically records that origin has been swept and returns true
// iff THIS call was the first to claim it (so only the first caller runs the
// known-path sweep). Concurrency-safe under graphqlSweptMu.
func markOriginSwept(origin string) bool {
	graphqlSweptMu.Lock()
	defer graphqlSweptMu.Unlock()
	if graphqlSwept[origin] {
		return false
	}
	graphqlSwept[origin] = true
	return true
}

// graphQLCheck is the active GraphQL introspection-exposure (CWE-200) check.
// It sweeps a bounded known-path set at the target origin once per scan, plus
// the current endpoint if its path contains "graphql", and reports introspection
// exposure (HIGH) and a GET-execution CSRF surface (MEDIUM) — both gated on the
// full GraphQL response shape (LOAD-BEARING FP control), never a bare 200.
type graphQLCheck struct{}

func (graphQLCheck) Name() string     { return "graphql" }
func (graphQLCheck) Category() string { return "graphql" }
func (graphQLCheck) Tier() Tier       { return TierActive }
func (graphQLCheck) Enabled(cfg *models.ScanConfig) bool {
	return cfg != nil && cfg.EnableActive
}

// Run derives the origin from ep.FullURL, builds the candidate set (known paths
// once-per-origin + the current endpoint if its path contains "graphql"), and
// probes each candidate. Active-probe discipline mirrors hostHeaderCheck /
// SSRFCheck: a ctx.Done()/budget check before every probe, a ProbeRecord per
// probe, and auth applied via cfg.Auth.ApplyToRequest.
func (graphQLCheck) Run(ctx context.Context, cc *CheckContext, ep Endpoint) []ev.Evidence {
	if cc == nil || cc.Cfg == nil || !cc.Cfg.EnableActive {
		return nil
	}

	origin := graphqlOrigin(ep.FullURL)
	if origin == "" {
		return nil
	}

	// Build the candidate URL set. The known-path sweep runs ONLY the first time
	// this origin is seen in the scan (concurrency-safe origin guard); doing it
	// per-endpoint would POST introspection to every crawled endpoint.
	var candidates []string
	if markOriginSwept(origin) {
		for _, p := range graphqlKnownPaths {
			candidates = append(candidates, origin+p)
		}
	}
	// Discovery-gap recovery: if the current endpoint's own path looks like a
	// GraphQL path, probe it directly (covers non-standard crawled paths the
	// known-path set does not include). Avoid duplicating a known-path URL.
	if strings.Contains(strings.ToLower(ep.Path), "graphql") {
		if !containsString(candidates, ep.FullURL) {
			candidates = append(candidates, ep.FullURL)
		}
	}

	maxProbes := effectiveMaxProbes(cc.Cfg)

	var findings []ev.Evidence
	for _, candidate := range candidates {
		// Active discipline: soft-stop on cancellation, then budget cap — both
		// checked before sending the probe (mirrors hostHeaderCheck).
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		if cc.Audit.Count(candidate) >= maxProbes {
			logagg.Warn("graphql", "max probes reached for endpoint", "endpoint", candidate, "max", maxProbes)
			continue
		}

		intro, ok := graphqlIntrospectionProbe(ctx, cc, candidate)
		if !ok {
			continue
		}
		findings = append(findings, graphqlIntrospectionFinding(candidate, intro))

		// Sub-finding: after a positive introspection, test GET-execution (CSRF
		// surface). Honors the same budget/cancellation discipline + shape FP
		// control inside the probe.
		if graphqlGETExecutionProbe(ctx, cc, candidate) {
			findings = append(findings, graphqlGETExecutionFinding(candidate))
		}

		// One introspection finding per origin is the goal; the first positive
		// candidate is the GraphQL endpoint, so stop sweeping this origin.
		break
	}

	return findings
}

// graphqlIntrospectionResult captures the parsed-shape facts a positive
// introspection probe yields, used to build the finding.
type graphqlIntrospectionResult struct {
	queryType    string
	mutationType string // "" when mutationType is null/absent
	hasMutations bool
	contentType  string
}

// graphqlIntrospectionProbe POSTs the standard introspection query to url and
// returns (result, true) ONLY when the response has a GraphQL JSON Content-Type
// AND a parsed data.__schema object carrying a queryType. Records a ProbeRecord.
// LOAD-BEARING: a bare 200 / HTML / non-__schema JSON returns ok=false.
func graphqlIntrospectionProbe(ctx context.Context, cc *CheckContext, url string) (graphqlIntrospectionResult, bool) {
	if cc.Audit.Count(url) >= effectiveMaxProbes(cc.Cfg) {
		return graphqlIntrospectionResult{}, false
	}
	select {
	case <-ctx.Done():
		return graphqlIntrospectionResult{}, false
	default:
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(graphqlIntrospectionBody))
	if err != nil {
		logagg.Warn("graphql", "failed to create introspection request", "url", url, "error", err)
		return graphqlIntrospectionResult{}, false
	}
	req.Header.Set("Content-Type", "application/json")
	cc.Cfg.Auth.ApplyToRequest(req)

	resp, err := cc.Client.Do(req)
	elapsed := time.Since(start)
	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  url,
		ProbeType: ProbeGraphQL,
		Payload:   graphqlIntrospectionQuery,
		Method:    http.MethodPost,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}
	if err != nil {
		logagg.Warn("graphql", "introspection probe failed", "url", url, "error", err)
		record.Status = 0
		cc.Audit.Record(record)
		return graphqlIntrospectionResult{}, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, graphqlBodyLimit))
	resp.Body.Close()
	contentType := resp.Header.Get("Content-Type")
	record.Status = resp.StatusCode

	res, ok := graphqlParseIntrospection(contentType, body)
	if !ok {
		cc.Audit.Record(record)
		return graphqlIntrospectionResult{}, false
	}
	record.Finding = true
	cc.Audit.Record(record)
	return res, true
}

// graphqlParseIntrospection applies the LOAD-BEARING FP control: it returns ok
// only when contentType is a GraphQL JSON type AND the body parses to a
// data.__schema object carrying a queryType. mutationType (non-null named type)
// is surfaced for severity escalation in evidence.
func graphqlParseIntrospection(contentType string, body []byte) (graphqlIntrospectionResult, bool) {
	if !graphqlIsJSONContentType(contentType) {
		return graphqlIntrospectionResult{}, false
	}

	var parsed struct {
		Data *struct {
			Schema *struct {
				QueryType *struct {
					Name string `json:"name"`
				} `json:"queryType"`
				MutationType *struct {
					Name string `json:"name"`
				} `json:"mutationType"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return graphqlIntrospectionResult{}, false
	}
	// Require data.__schema as an object carrying a queryType — never a bare 200.
	if parsed.Data == nil || parsed.Data.Schema == nil || parsed.Data.Schema.QueryType == nil {
		return graphqlIntrospectionResult{}, false
	}

	res := graphqlIntrospectionResult{
		queryType:   parsed.Data.Schema.QueryType.Name,
		contentType: contentType,
	}
	if mt := parsed.Data.Schema.MutationType; mt != nil && mt.Name != "" {
		res.mutationType = mt.Name
		res.hasMutations = true
	}
	return res, true
}

// graphqlGETExecutionProbe replays the introspection query via GET (?query=...)
// and returns true ONLY when the response is GraphQL JSON carrying a valid data
// shape (data.__typename or data.__schema). LOAD-BEARING: a bare 200 is NOT a
// positive. Records a ProbeRecord.
func graphqlGETExecutionProbe(ctx context.Context, cc *CheckContext, baseURL string) bool {
	if cc.Audit.Count(baseURL) >= effectiveMaxProbes(cc.Cfg) {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	default:
	}

	getURL := graphqlGETURL(baseURL, graphqlIntrospectionQuery)
	if getURL == "" {
		return false
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		logagg.Warn("graphql", "failed to create GET-execution request", "url", baseURL, "error", err)
		return false
	}
	cc.Cfg.Auth.ApplyToRequest(req)

	resp, err := cc.Client.Do(req)
	elapsed := time.Since(start)
	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  baseURL,
		ProbeType: ProbeGraphQL,
		Payload:   "GET ?query=" + graphqlIntrospectionQuery,
		Method:    http.MethodGet,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}
	if err != nil {
		logagg.Warn("graphql", "GET-execution probe failed", "url", baseURL, "error", err)
		record.Status = 0
		cc.Audit.Record(record)
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, graphqlBodyLimit))
	resp.Body.Close()
	contentType := resp.Header.Get("Content-Type")
	record.Status = resp.StatusCode

	ok := graphqlGETExecuted(contentType, body)
	record.Finding = ok
	cc.Audit.Record(record)
	return ok
}

// graphqlGETExecuted applies the GET-execution FP control: GraphQL JSON
// Content-Type AND a parsed data object that is a non-empty GraphQL response
// (carries __typename or __schema). A bare 200 / non-data JSON is NOT a positive.
func graphqlGETExecuted(contentType string, body []byte) bool {
	if !graphqlIsJSONContentType(contentType) {
		return false
	}
	var parsed struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	if parsed.Data == nil {
		return false
	}
	// Require a recognizable GraphQL data shape, not just any non-null data.
	_, hasTypename := parsed.Data["__typename"]
	_, hasSchema := parsed.Data["__schema"]
	return hasTypename || hasSchema
}

// graphqlIsJSONContentType reports whether ct is a GraphQL-bearing JSON content
// type: application/json or application/graphql-response+json (case-insensitive,
// substring so charset suffixes are tolerated).
func graphqlIsJSONContentType(ct string) bool {
	lc := strings.ToLower(ct)
	return strings.Contains(lc, "application/json") ||
		strings.Contains(lc, "application/graphql-response+json")
}

// graphqlOrigin returns scheme://host[:port] for a full URL, or "" if it cannot
// be parsed or lacks a scheme/host.
func graphqlOrigin(fullURL string) string {
	u, err := url.Parse(fullURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// graphqlGETURL appends ?query=<query> to baseURL, preserving any existing path
// while replacing the query string. Returns "" if baseURL is unparseable.
func graphqlGETURL(baseURL, query string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	q := url.Values{}
	q.Set("query", query)
	u.RawQuery = q.Encode()
	return u.String()
}

// containsString reports whether s is in xs.
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// graphqlIntrospectionFinding builds the HIGH introspection-enabled finding.
// Evidence notes the exposed mutation surface when mutations are present, but
// severity stays HIGH either way.
func graphqlIntrospectionFinding(url string, res graphqlIntrospectionResult) ev.Evidence {
	evidence := fmt.Sprintf(
		"GraphQL introspection enabled at %s: POSTing the standard introspection query returned a valid GraphQL response (Content-Type %q) with data.__schema.queryType=%q. An attacker can enumerate the full schema (types, fields, arguments) — the reconnaissance starting point for the API.",
		url, res.contentType, res.queryType,
	)
	if res.hasMutations {
		evidence += fmt.Sprintf(" Mutations are also exposed (data.__schema.mutationType=%q), revealing every state-changing operation available.", res.mutationType)
	}
	return ev.Evidence{
		RuleID:   "graphql/introspection-enabled",
		Title:    "GraphQL introspection enabled",
		Severity: models.SeverityHigh,
		Source:   models.SourceBlackbox,
		Category: "graphql",
		Endpoint: fmt.Sprintf("POST %s", url),
		Evidence: evidence,
		Fix: "Disable GraphQL introspection in production (e.g. introspection: false / NoIntrospection validation rule). " +
			"Introspection should only be enabled in development. Combine with field-level authorization and query depth/complexity limits.",
		References: []string{"CWE-200", "OWASP-A05"},
		Confidence: models.ConfidenceHigh,
		// The differential: we POSTed the standard introspection query, and the
		// server answered with a parsed schema. A server with introspection
		// disabled returns an error for the SAME payload, so the pair is the
		// evidence — not the fact that a GraphQL endpoint exists.
		Payload: graphqlIntrospectionQuery,
		Response: ProbeExcerpt(fmt.Sprintf(
			"Content-Type: %s; data.__schema.queryType=%q mutationType=%q",
			res.contentType, res.queryType, res.mutationType)),
	}
}

// graphqlGETExecutionFinding builds the MEDIUM GET-execution (CSRF surface)
// sub-finding.
func graphqlGETExecutionFinding(url string) ev.Evidence {
	return ev.Evidence{
		RuleID:   "graphql/get-execution",
		Title:    "GraphQL query execution via GET (CSRF surface)",
		Severity: models.SeverityMedium,
		Source:   models.SourceBlackbox,
		Category: "graphql",
		Endpoint: fmt.Sprintf("GET %s", url),
		Evidence: fmt.Sprintf(
			"GraphQL endpoint %s executes queries supplied via the GET query string (?query=...) and returned a valid GraphQL data response. GET requests can be triggered cross-site (e.g. via <img>/<script>/<link> tags), so any state-changing-capable query reachable over GET is a CSRF surface.",
			url,
		),
		Fix:        "Reject GraphQL queries sent over GET (allow GET only for safe, explicitly whitelisted persisted queries), require POST with a CSRF token / SameSite cookies, and validate the Content-Type to block simple-request CSRF.",
		References: []string{"CWE-200", "OWASP-A05"},
		Confidence: models.ConfidenceMedium,
	}
}
