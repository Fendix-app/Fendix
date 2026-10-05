package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/logagg"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// MaxProbesPerEndpoint is the default cap on active probes per endpoint when
// ScanConfig.MaxProbesPerEndpoint is unset (zero). The cap is overridable via
// the --max-probes-per-endpoint CLI flag (TASK-086).
const MaxProbesPerEndpoint = 20

// effectiveMaxProbes returns the per-endpoint probe budget for a scan.
// Treats 0 as "use the default" so that ScanConfig zero-values stay safe.
func effectiveMaxProbes(cfg *models.ScanConfig) int {
	if cfg == nil || cfg.MaxProbesPerEndpoint <= 0 {
		return MaxProbesPerEndpoint
	}
	return cfg.MaxProbesPerEndpoint
}

// ProbeLocation identifies where in the HTTP request a probe payload is placed.
// Different vulnerabilities surface in different locations: query params get
// reflected into URLs and SQL, body params reach the same handlers but bypass
// query-string-only WAFs, and custom headers (X-Trace-Id, X-User-Role, etc.)
// often flow into logs and SQL queries.
type ProbeLocation string

const (
	LocQuery  ProbeLocation = "query"
	LocHeader ProbeLocation = "header"
	LocBody   ProbeLocation = "body"
)

// ActiveDisclaimer is printed to stderr when --enable-active is used.
const ActiveDisclaimer = `
WARNING: Active scanning enabled (--enable-active).
Active probes send potentially dangerous payloads to the target.
Only use this against systems you own or have explicit authorization to test.
You are solely responsible for ensuring you have permission.
`

// ProbeType identifies the kind of active probe.
type ProbeType string

const (
	ProbeSQLi     ProbeType = "sqli"
	ProbeCMDi     ProbeType = "cmdi"
	ProbeCRLF     ProbeType = "crlf"
	ProbeRedirect ProbeType = "redirect"
	ProbeXSS      ProbeType = "xss"
	ProbeSSRF     ProbeType = "ssrf"

	ProbeHostHeader   ProbeType = "host_header"
	ProbeGraphQL      ProbeType = "graphql"
	ProbeMethodTamper ProbeType = "method_tamper"
)

// ProbeRecord captures a single probe sent during active scanning.
type ProbeRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Endpoint  string    `json:"endpoint"`
	ProbeType ProbeType `json:"probe_type"`
	Payload   string    `json:"payload"`
	Parameter string    `json:"parameter"`
	Method    string    `json:"method"`
	Status    int       `json:"status_code"`
	Duration  string    `json:"duration"`
	Finding   bool      `json:"finding_generated"`
}

// ProbeAuditLog records every active probe for accountability and debugging.
type ProbeAuditLog struct {
	mu      sync.Mutex
	records []ProbeRecord
	writer  io.Writer
}

// NewProbeAuditLog creates a new audit log that writes to stderr.
func NewProbeAuditLog() *ProbeAuditLog {
	return &ProbeAuditLog{
		writer: os.Stderr,
	}
}

// NewProbeAuditLogWithWriter creates an audit log with a custom writer (for testing).
func NewProbeAuditLogWithWriter(w io.Writer) *ProbeAuditLog {
	return &ProbeAuditLog{
		writer: w,
	}
}

// Record adds a probe record to the audit log and writes it to the log writer.
func (a *ProbeAuditLog) Record(r ProbeRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, r)
	fmt.Fprintf(a.writer, "[PROBE] %s %s type=%s param=%q payload=%q status=%d duration=%s finding=%v\n",
		r.Timestamp.Format(time.RFC3339), r.Endpoint, r.ProbeType, r.Parameter, r.Payload, r.Status, r.Duration, r.Finding)
}

// Records returns a copy of all recorded probe entries.
func (a *ProbeAuditLog) Records() []ProbeRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]ProbeRecord, len(a.records))
	copy(out, a.records)
	return out
}

// Count returns the number of probes recorded for a given endpoint.
func (a *ProbeAuditLog) Count(endpoint string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, r := range a.records {
		if r.Endpoint == endpoint {
			n++
		}
	}
	return n
}

// PrintDisclaimer writes the active scanning disclaimer to stderr.
func PrintDisclaimer() {
	fmt.Fprint(os.Stderr, ActiveDisclaimer)
}

// measureBaseline sends 3 requests and returns the median response time.
func measureBaseline(ctx context.Context, client *http.Client, cfg *models.ScanConfig, method, url string) (time.Duration, error) {
	var durations []time.Duration
	for i := 0; i < 3; i++ {
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return 0, fmt.Errorf("creating baseline request: %w", err)
		}
		// F-I (C1 baseline-auth): the baseline must traverse the SAME auth
		// state as the probes, or the timing delta compares two different code
		// paths (a fast 401 stub vs the authenticated handler).
		if cfg != nil {
			cfg.Auth.ApplyToRequest(req)
		}
		start := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(start)
		if err != nil {
			return 0, fmt.Errorf("baseline request %d failed: %w", i+1, err)
		}
		resp.Body.Close()
		durations = append(durations, elapsed)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	return durations[1], nil // median
}

// sqliPayloads returns time-based blind SQL injection payloads.
// Five DB types are covered (TASK-086 expanded MySQL/Postgres/MSSQL → +SQLite +Oracle):
//
//   - MySQL: SLEEP(n)
//   - Postgres: pg_sleep(n)
//   - MSSQL: WAITFOR DELAY
//   - SQLite: randomblob() — no native sleep, but a CASE-gated large blob
//     allocation reliably blocks for several seconds on default builds
//   - Oracle: DBMS_PIPE.RECEIVE_MESSAGE waits on a named pipe that never
//     receives, returning after the timeout
//
// Threshold check is `baseline + 4s`, so any payload that pushes the request
// past 5s detects as positive.
func sqliPayloads() []struct {
	DB      string
	Payload string
	Delay   time.Duration
} {
	return []struct {
		DB      string
		Payload string
		Delay   time.Duration
	}{
		{DB: "MySQL", Payload: "' AND SLEEP(5)--", Delay: 5 * time.Second},
		{DB: "Postgres", Payload: "' AND pg_sleep(5)--", Delay: 5 * time.Second},
		{DB: "MSSQL", Payload: "'; WAITFOR DELAY '00:00:05'--", Delay: 5 * time.Second},
		{DB: "SQLite", Payload: "' AND CASE WHEN 1=1 THEN randomblob(99999999) ELSE 0 END--", Delay: 5 * time.Second},
		{DB: "Oracle", Payload: "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", Delay: 5 * time.Second},
	}
}

// sqliErrorPayload is sent once per (param, location) for error-based SQLi.
// A bare single-quote is the most universally-effective: virtually every SQL
// engine returns a syntax error if user input is concatenated into a query
// without escaping. The follow-up regex match identifies WHICH engine.
const sqliErrorPayload = "fendix'\""

// sqliErrorPatterns matches DB error signatures in response bodies. Drawn from
// real-world payloads in sqlmap and OWASP testing guides — kept conservative to
// avoid false positives on generic "syntax error" strings in unrelated text.
var sqliErrorPatterns = []struct {
	DB string
	Re *regexp.Regexp
}{
	{DB: "MySQL", Re: regexp.MustCompile(`(?i)you have an error in your sql syntax|warning.*mysql_|mysql_fetch|valid mysql result|mysqli?_query\(\)|com\.mysql\.jdbc`)},
	{DB: "Postgres", Re: regexp.MustCompile(`(?i)pg_query\(\)|pg_exec\(\)|syntax error at or near|postgresql\.util\.PSQLException|invalid input syntax for|unterminated quoted string at or near`)},
	{DB: "MSSQL", Re: regexp.MustCompile(`(?i)unclosed quotation mark after the character string|microsoft.*odbc.*sql server|incorrect syntax near|sqlserver\.jdbc|com\.microsoft\.sqlserver`)},
	{DB: "Oracle", Re: regexp.MustCompile(`(?i)\bORA-\d{5}\b|quoted string not properly terminated|oracle\.jdbc|oracledatabase`)},
	{DB: "SQLite", Re: regexp.MustCompile(`(?i)sqlite3?::|sqlite_error|unrecognized token|near \".*\": syntax error|sqlite3\.OperationalError`)},
}

// sqliBooleanPayloads is a (true-condition, false-condition) pair for boolean-
// based blind SQLi. If response length or status differs significantly between
// the two, that suggests the payload was concatenated into a SQL WHERE clause.
var sqliBooleanPayloads = struct {
	True  string
	False string
}{
	True:  "' OR '1'='1",
	False: "' AND '1'='2",
}

// sqliBooleanLengthThreshold is the minimum percent difference in response
// body length between the true and false probes that we consider significant.
// 5% is the spec's default — small enough to catch reflected boolean flips,
// large enough to ignore byte-level noise (timestamps, request IDs, etc.).
const sqliBooleanLengthThreshold = 0.05

// sqliBooleanControl is the neutral control value sent before the true/false
// pair (fix 2.2). Sending it twice measures the endpoint's natural per-request
// length jitter: if two identical control responses already differ by more than
// the threshold, the target is too dynamic to draw a boolean-blind conclusion
// and the probe bails. When the endpoint is stable, the control also gives us a
// baseline shape so we can require the true/false flip to be injection-driven
// (one side tracks the control, the other diverges) rather than mere noise.
const sqliBooleanControl = "fendix"

// cmdiPayload is the safe COMPUTED-canary command injection probe (fix 2.4).
// The payload embeds a shell arithmetic expansion `$((13*99))`. A vulnerable
// target that passes the input to a shell EVALUATES the arithmetic and emits
// "fendix1287end" (13*99 = 1287). A non-vulnerable endpoint that merely reflects
// the input echoes the SOURCE text "13*99" — which never contains the computed
// marker "1287end" — so simple reflection no longer trips a false positive.
//
// The wrapping delimiters (fendix…end) keep the marker from colliding with
// unrelated "1287" runs that might appear in a large response body.
const cmdiPayload = "; echo fendix$((13*99))end"

// cmdiComputedCanary is the shell-evaluated result of cmdiPayload. Its presence
// in the response body is unambiguous evidence the payload reached a shell:
// 13*99 = 1287, so an executing shell prints "fendix1287end" while a literal
// reflection of the payload prints "fendix$((13*99))end" (no match).
const cmdiComputedCanary = "fendix1287end"

// crlfPayload injects a Set-Cookie header via CRLF (URL-encoded spaces for valid HTTP).
const crlfPayload = "%0d%0aSet-Cookie:%20fendix=injected"

// methodAcceptsBody returns true for HTTP methods that conventionally carry
// a request body. Body probing is only meaningful for these — sending a body
// on GET/DELETE typically gets ignored or rejected.
func methodAcceptsBody(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	}
	return false
}

// probeTarget identifies one (parameter, location) pair to test. The injection
// orchestrator emits one of these per param-location combination, then each
// probe function decides whether to send an HTTP request for it.
type probeTarget struct {
	Name     string
	Location ProbeLocation
}

// targetsForEndpoint returns the (param, location) pairs to probe. Order is
// query → header → body so that simpler request shapes execute first; if the
// max-probes budget kicks in, we'd rather have probed query params for every
// endpoint than headers for one and nothing for the rest.
//
// Falls back to a single ("id", query) target when an endpoint has no declared
// params anywhere — preserves the v0.2 behavior of "always try `id` so we
// catch undocumented surface" without turning every empty body into a 0-probe
// no-op.
func targetsForEndpoint(ep Endpoint) []probeTarget {
	var targets []probeTarget
	for _, p := range ep.Params {
		targets = append(targets, probeTarget{Name: p, Location: LocQuery})
	}
	for _, h := range ep.Headers {
		targets = append(targets, probeTarget{Name: h, Location: LocHeader})
	}
	if methodAcceptsBody(ep.Method) {
		for _, b := range ep.BodyParams {
			targets = append(targets, probeTarget{Name: b, Location: LocBody})
		}
	}
	if len(targets) == 0 {
		targets = []probeTarget{{Name: "id", Location: LocQuery}}
	}
	return targets
}

// buildProbeRequest constructs an HTTP request that places `payload` in the
// requested location. For body probes, the JSON body is built from the
// endpoint's BodyParams: the target field carries the payload, sibling fields
// get a non-empty placeholder so the server's input validation doesn't reject
// the request before it reaches the vulnerable code.
func buildProbeRequest(ctx context.Context, ep Endpoint, param, payload string, loc ProbeLocation) (*http.Request, error) {
	switch loc {
	case LocQuery:
		probeURL := buildProbeURL(ep.FullURL, param, payload)
		return http.NewRequestWithContext(ctx, ep.Method, probeURL, nil)

	case LocHeader:
		req, err := http.NewRequestWithContext(ctx, ep.Method, ep.FullURL, nil)
		if err != nil {
			return nil, err
		}
		// Header values can't legitimately contain CR/LF; for non-CRLF probes
		// we strip them to keep the http client from rejecting the request as
		// malformed. CRLF probes use buildCRLFRequest directly.
		safe := strings.NewReplacer("\r", "", "\n", "").Replace(payload)
		req.Header.Set(param, safe)
		return req, nil

	case LocBody:
		body := buildJSONBody(ep.BodyParams, param, payload)
		req, err := http.NewRequestWithContext(ctx, ep.Method, ep.FullURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil

	default:
		return nil, fmt.Errorf("unknown probe location %q", loc)
	}
}

// buildJSONBody serializes a JSON object where `target` carries `payload` and
// every other field in `fields` gets the placeholder string "fendix". Falls
// back to a one-key object when fields is empty.
func buildJSONBody(fields []string, target, payload string) []byte {
	body := make(map[string]string, len(fields)+1)
	for _, f := range fields {
		body[f] = "fendix"
	}
	body[target] = payload
	if len(body) == 0 {
		body[target] = payload
	}
	out, _ := json.Marshal(body)
	return out
}

// injectionCheck implements the Check interface for the active injection
// scanner. Structural adapter — Run delegates to the unchanged
// CheckInjectionWithAudit, threading the scan-wide audit log through the
// CheckContext (cc.Audit aliases currentAuditLog(), so behaviour is
// identical to the historical CheckInjection free function).
type injectionCheck struct{}

func (injectionCheck) Name() string     { return "injection" }
func (injectionCheck) Category() string { return "injection" }
func (injectionCheck) Tier() Tier       { return TierActive }
func (injectionCheck) Enabled(cfg *models.ScanConfig) bool {
	return cfg != nil && cfg.EnableActive
}

// CheckInjection runs active injection probes on an endpoint.
// This function MUST only be called when cfg.EnableActive is true.
// It runs SQLi (time/error/boolean), CMDi, and CRLF probes across each
// declared query/header/body parameter.
func CheckInjection(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []ev.Evidence {
	return injectionCheck{}.Run(ctx, NewCheckContext(cfg), endpoint)
}

// Run delegates to the unchanged CheckInjectionWithAudit. The audit log
// comes from the CheckContext (cc.Audit == currentAuditLog()), so probe
// records still accumulate in the one package-level log the orchestrator
// reads post-scan via scanner.GlobalAuditRecords (e.g. --debug-bundle).
func (injectionCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []ev.Evidence {
	if !cc.Cfg.EnableActive {
		return nil
	}
	return CheckInjectionWithAudit(ctx, cc.Cfg, endpoint, cc.Audit)
}

// CheckInjectionWithAudit runs active injection probes with a provided audit log.
// Iterates over (param, location) pairs returned by targetsForEndpoint —
// query params, header params, and (for POST/PUT/PATCH) body fields — and
// runs all configured probe types against each. The per-endpoint probe
// budget (cfg.MaxProbesPerEndpoint, default 20) caps total probe count.
func CheckInjectionWithAudit(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint, auditLog *ProbeAuditLog) []ev.Evidence {
	if !cfg.EnableActive {
		return nil
	}

	client := guardedClient(cfg)
	var findings []ev.Evidence
	maxProbes := effectiveMaxProbes(cfg)

	for _, t := range targetsForEndpoint(endpoint) {
		// F-L5: stop iterating targets when the scan context is cancelled
		// (soft-stop / --max-requests cap / --max-duration). Mirrors the
		// select-on-ctx.Done() guard in ratelimit.go so a soft-stop stops
		// probing the remaining targets instead of running every payload.
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if auditLog.Count(endpoint.FullURL) >= maxProbes {
			logagg.Warn("injection", "max probes reached for endpoint", "endpoint", endpoint.FullURL, "max", maxProbes)
			break
		}

		findings = append(findings, probeSQLi(ctx, client, cfg, endpoint, t.Name, t.Location, auditLog)...)
		findings = append(findings, probeSQLiErrorBased(ctx, client, cfg, endpoint, t.Name, t.Location, auditLog)...)
		findings = append(findings, probeSQLiBoolean(ctx, client, cfg, endpoint, t.Name, t.Location, auditLog)...)
		findings = append(findings, probeCMDi(ctx, client, cfg, endpoint, t.Name, t.Location, auditLog)...)

		// CRLF only makes sense for query params — header/body values that
		// contain CR/LF are stripped or rejected before reaching response
		// header construction in any reasonable framework.
		if t.Location == LocQuery {
			findings = append(findings, probeCRLF(ctx, client, cfg, endpoint, t.Name, auditLog)...)
		}
	}

	return findings
}

// probeSQLi sends time-based blind SQLi payloads and checks for delayed responses.
// Supports query, header, and body locations (TASK-086) — same detection logic
// regardless of where the payload is placed.
func probeSQLi(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, param string, loc ProbeLocation, auditLog *ProbeAuditLog) []ev.Evidence {
	var findings []ev.Evidence
	maxProbes := effectiveMaxProbes(cfg)

	baseline, err := measureBaseline(ctx, client, cfg, endpoint.Method, endpoint.FullURL)
	if err != nil {
		logagg.Warn("injection", "failed to measure baseline for sqli", "endpoint", endpoint.FullURL, "error", err)
		return nil
	}

	for _, p := range sqliPayloads() {
		// F-L5: per-payload soft-stop check — abandon remaining SQLi payloads
		// the moment the scan context is cancelled.
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if auditLog.Count(endpoint.FullURL) >= maxProbes {
			break
		}

		start := time.Now()
		req, err := buildProbeRequest(ctx, endpoint, param, p.Payload, loc)
		if err != nil {
			logagg.Warn("injection", "failed to create sqli probe request", "error", err)
			continue
		}
		cfg.Auth.ApplyToRequest(req)

		resp, err := client.Do(req)
		elapsed := time.Since(start)

		record := ProbeRecord{
			Timestamp: start,
			Endpoint:  endpoint.FullURL,
			ProbeType: ProbeSQLi,
			Payload:   p.Payload,
			Parameter: param,
			Method:    endpoint.Method,
			Duration:  elapsed.Round(time.Millisecond).String(),
		}

		if err != nil {
			logagg.Warn("injection", "sqli probe request failed", "endpoint", endpoint.FullURL, "db", p.DB, "error", err)
			record.Status = 0
			record.Finding = false
			auditLog.Record(record)
			continue
		}
		resp.Body.Close()

		record.Status = resp.StatusCode

		threshold := baseline + 4*time.Second
		if elapsed > threshold {
			record.Finding = true
			auditLog.Record(record)

			confidence := models.ConfidenceMedium
			// Run a second probe to confirm timing isn't a one-off blip —
			// but only if recording it won't push this endpoint past the
			// per-endpoint probe budget. The primary record above already
			// consumed a slot, so the confirmation (which records a 2nd
			// slot) is what historically overshot maxProbes by +1 (F-I4).
			// When the budget is exhausted we keep the MEDIUM-confidence
			// finding and skip confirmation rather than overshooting the
			// cap the operator set to bound load on the target.
			if auditLog.Count(endpoint.FullURL) < maxProbes {
				// Run a second probe to confirm timing isn't a one-off blip.
				start2 := time.Now()
				req2, err := buildProbeRequest(ctx, endpoint, param, p.Payload, loc)
				if err == nil {
					cfg.Auth.ApplyToRequest(req2)
					resp2, err := client.Do(req2)
					elapsed2 := time.Since(start2)
					if err == nil {
						resp2.Body.Close()
						if elapsed2 > threshold {
							confidence = models.ConfidenceHigh
						}
						auditLog.Record(ProbeRecord{
							Timestamp: start2,
							Endpoint:  endpoint.FullURL,
							ProbeType: ProbeSQLi,
							Payload:   p.Payload + " (confirmation)",
							Parameter: param,
							Method:    endpoint.Method,
							Status:    resp2.StatusCode,
							Duration:  elapsed2.Round(time.Millisecond).String(),
							Finding:   elapsed2 > threshold,
						})
					}
				}
			}

			findings = append(findings, ev.Evidence{
				RuleID:   "injection/sqli-time-based",
				Title:    fmt.Sprintf("Potential SQL Injection (%s, time-based)", p.DB),
				Severity: models.SeverityHigh,
				Source:   models.SourceBlackbox,
				Category: "injection",
				Endpoint: fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path),
				Evidence: fmt.Sprintf("Time-based blind SQLi: baseline=%s, probe=%s (threshold=%s), %s, payload=%q",
					baseline.Round(time.Millisecond), elapsed.Round(time.Millisecond), threshold.Round(time.Millisecond), paramLabel(param, loc), p.Payload),
				Fix:        "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
				References: []string{"CWE-89", "OWASP-A03"},
				Confidence: confidence,
				// For a TIMING check the confirming observation is the delay,
				// not the body — the body proves nothing here and is not even
				// read. Recording the measured differential is the truthful
				// response observation; recording an unread body would be
				// fabrication.
				Payload:  p.Payload,
				Response: ProbeTimingExcerpt(elapsed, threshold),
			})
			// Once one DB type confirms, skip the rest for this (param, loc) —
			// the underlying vuln is the same; multiple findings would just be
			// noise.
			break
		}

		record.Finding = false
		auditLog.Record(record)
	}

	return findings
}

// paramLabel formats a (param, location) pair for log messages and finding
// evidence — disambiguates "param=id" between query/header/body so the user
// can immediately tell which surface a finding came from.
func paramLabel(param string, loc ProbeLocation) string {
	return fmt.Sprintf("%s=%q (in=%s)", "param", param, loc)
}

// probeSQLiErrorBased sends a single bare-quote payload and scans the response
// body for known database error signatures. Confirmed errors are HIGH-severity
// HIGH-confidence — the response body literally contains "you have an error in
// your SQL syntax", which is unambiguous evidence the input reached an
// unparameterized query.
func probeSQLiErrorBased(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, param string, loc ProbeLocation, auditLog *ProbeAuditLog) []ev.Evidence {
	// Fix 2.5: soft-stop uniformity — bail before sending any request if the
	// scan context is already cancelled (--max-requests / --max-duration / Ctrl-C).
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	if auditLog.Count(endpoint.FullURL) >= effectiveMaxProbes(cfg) {
		return nil
	}

	start := time.Now()
	req, err := buildProbeRequest(ctx, endpoint, param, sqliErrorPayload, loc)
	if err != nil {
		logagg.Warn("injection", "failed to create error-based sqli probe request", "error", err)
		return nil
	}
	cfg.Auth.ApplyToRequest(req)

	resp, err := client.Do(req)
	elapsed := time.Since(start)

	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  endpoint.FullURL,
		ProbeType: ProbeSQLi,
		Payload:   sqliErrorPayload,
		Parameter: param,
		Method:    endpoint.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}

	if err != nil {
		logagg.Warn("injection", "error-based sqli probe failed", "endpoint", endpoint.FullURL, "error", err)
		record.Status = 0
		auditLog.Record(record)
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	record.Status = resp.StatusCode

	bodyStr := string(body)
	for _, p := range sqliErrorPatterns {
		if !p.Re.MatchString(bodyStr) {
			continue
		}
		record.Finding = true
		auditLog.Record(record)

		match := p.Re.FindString(bodyStr)
		// Cap evidence size; the matched string is the high-signal part,
		// arbitrary trailing body would just be noise.
		if len(match) > 160 {
			match = match[:160] + "..."
		}
		return []ev.Evidence{{
			RuleID:   "injection/sqli-error-based",
			Title:    fmt.Sprintf("SQL Injection (%s, error-based)", p.DB),
			Severity: models.SeverityHigh,
			Source:   models.SourceBlackbox,
			Category: "injection",
			Endpoint: fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path),
			Evidence: fmt.Sprintf("DB error signature in response: %q. %s, payload=%q",
				match, paramLabel(param, loc), sqliErrorPayload),
			Fix:        "Use parameterized queries / prepared statements. Sanitize input before SQL.",
			References: []string{"CWE-89", "OWASP-A03"},
			Confidence: models.ConfidenceHigh,
			// The probe differential: what we sent, and the DB error signature
			// that came back. confidence.payloadValidated needs BOTH, and the
			// decision layer counts the pair as independent corroboration.
			Payload:  sqliErrorPayload,
			Response: ProbeExcerpt(match),
		}}
	}

	record.Finding = false
	auditLog.Record(record)
	return nil
}

// probeSQLiBoolean sends a (true, false) payload pair and detects whether the
// server's response shape changes — status flip or response-body length delta
// > sqliBooleanLengthThreshold (5%). Either signal indicates the payload was
// concatenated into the WHERE clause and the engine evaluated the condition.
func probeSQLiBoolean(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, param string, loc ProbeLocation, auditLog *ProbeAuditLog) []ev.Evidence {
	// Fix 2.5: soft-stop uniformity — bail before sending any request if the
	// scan context is already cancelled.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	maxProbes := effectiveMaxProbes(cfg)
	// Fix 2.2: we now send up to FOUR probes — two neutral controls (to measure
	// per-request noise) plus the true/false pair. Skip if any of them would
	// bust the per-endpoint budget.
	if auditLog.Count(endpoint.FullURL)+4 > maxProbes {
		return nil
	}

	// Noise floor: send the SAME neutral control twice. If two identical
	// requests already differ by more than the threshold, the endpoint is too
	// dynamic (random tokens / timestamps in the body) for a boolean-blind
	// length comparison to mean anything — bail rather than emit a false
	// positive on per-request jitter.
	_, control1Len, ok := sendBoolProbe(ctx, client, cfg, endpoint, param, sqliBooleanControl, loc, auditLog)
	if !ok {
		return nil
	}
	_, control2Len, ok := sendBoolProbe(ctx, client, cfg, endpoint, param, sqliBooleanControl, loc, auditLog)
	if !ok {
		return nil
	}
	controlJitter := lengthDelta(control1Len, control2Len)
	if controlJitter > sqliBooleanLengthThreshold {
		// Dynamic content — too noisy to conclude anything.
		return nil
	}
	controlLen := control1Len

	trueStatus, trueLen, ok := sendBoolProbe(ctx, client, cfg, endpoint, param, sqliBooleanPayloads.True, loc, auditLog)
	if !ok {
		return nil
	}
	falseStatus, falseLen, ok := sendBoolProbe(ctx, client, cfg, endpoint, param, sqliBooleanPayloads.False, loc, auditLog)
	if !ok {
		return nil
	}

	statusFlip := trueStatus != falseStatus
	lenDelta := lengthDelta(trueLen, falseLen)
	lengthFlip := lenDelta > sqliBooleanLengthThreshold

	// Fix 2.2: a length flip only counts as injection-driven when it clearly
	// exceeds the endpoint's natural noise AND one side of the pair tracks the
	// neutral control while the other diverges. A boolean SQLi flips exactly one
	// branch (the false condition prunes the result set); random per-request
	// noise instead makes BOTH true and false differ from the control by similar
	// amounts. Requiring (control≈true XOR control≈false) rejects that case.
	if lengthFlip {
		trueTracksControl := lengthDelta(controlLen, trueLen) <= sqliBooleanLengthThreshold
		falseTracksControl := lengthDelta(controlLen, falseLen) <= sqliBooleanLengthThreshold
		exceedsNoise := lenDelta > controlJitter
		if !exceedsNoise || !(trueTracksControl || falseTracksControl) {
			lengthFlip = false
		}
	}

	if !statusFlip && !lengthFlip {
		return nil
	}

	return []ev.Evidence{{
		RuleID:   "injection/sqli-boolean-based",
		Title:    "SQL Injection (boolean-based)",
		Severity: models.SeverityHigh,
		Source:   models.SourceBlackbox,
		Category: "injection",
		Endpoint: fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path),
		Evidence: fmt.Sprintf("Response differs between true (%q → status=%d len=%d) and false (%q → status=%d len=%d) payloads. delta=%.1f%%, %s",
			sqliBooleanPayloads.True, trueStatus, trueLen,
			sqliBooleanPayloads.False, falseStatus, falseLen,
			lenDelta*100, paramLabel(param, loc)),
		Fix:        "Use parameterized queries / prepared statements. Sanitize input before SQL.",
		References: []string{"CWE-89", "OWASP-A03"},
		Confidence: models.ConfidenceMedium,
	}}
}

// lengthDelta returns the symmetric, order-independent relative difference
// between two response-body lengths: |a-b| / max(a,b). Normalizing against the
// larger side (fix 2.3) makes lengthDelta(a,b) == lengthDelta(b,a) — the old
// calc divided by the first argument only, so swapping true/false lengths
// produced a different delta and could cross the threshold in one direction but
// not the other. Returns 0 when both are zero.
func lengthDelta(a, b int) float64 {
	denom := math.Max(math.Max(float64(a), float64(b)), 1)
	return math.Abs(float64(a-b)) / denom
}

// sendBoolProbe sends one boolean probe and records the audit entry. Returns
// (status, response-body-length, ok) — ok=false means the request failed and
// the caller should abandon the boolean test.
func sendBoolProbe(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, param, payload string, loc ProbeLocation, auditLog *ProbeAuditLog) (status int, bodyLen int, ok bool) {
	start := time.Now()
	req, err := buildProbeRequest(ctx, endpoint, param, payload, loc)
	if err != nil {
		logagg.Warn("injection", "failed to create boolean sqli probe request", "error", err)
		return 0, 0, false
	}
	cfg.Auth.ApplyToRequest(req)

	resp, err := client.Do(req)
	elapsed := time.Since(start)

	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  endpoint.FullURL,
		ProbeType: ProbeSQLi,
		Payload:   payload,
		Parameter: param,
		Method:    endpoint.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}

	if err != nil {
		logagg.Warn("injection", "boolean sqli probe failed", "endpoint", endpoint.FullURL, "error", err)
		auditLog.Record(record)
		return 0, 0, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	record.Status = resp.StatusCode
	auditLog.Record(record)
	return resp.StatusCode, len(body), true
}

// probeCMDi sends a safe COMPUTED-canary payload and checks the response for
// the shell-EVALUATED result, not the literal payload text (fix 2.4).
// Location-aware: works on query, header, and body params. The marker
// "fendix1287end" only appears if a shell evaluated the embedded `$((13*99))`
// arithmetic — a server that merely reflects the input echoes "13*99" and is
// not flagged.
func probeCMDi(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, param string, loc ProbeLocation, auditLog *ProbeAuditLog) []ev.Evidence {
	// Fix 2.5: soft-stop uniformity — bail before sending any request if the
	// scan context is already cancelled.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	if auditLog.Count(endpoint.FullURL) >= effectiveMaxProbes(cfg) {
		return nil
	}

	start := time.Now()
	req, err := buildProbeRequest(ctx, endpoint, param, cmdiPayload, loc)
	if err != nil {
		logagg.Warn("injection", "failed to create cmdi probe request", "error", err)
		return nil
	}
	cfg.Auth.ApplyToRequest(req)

	resp, err := client.Do(req)
	elapsed := time.Since(start)

	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  endpoint.FullURL,
		ProbeType: ProbeCMDi,
		Payload:   cmdiPayload,
		Parameter: param,
		Method:    endpoint.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}

	if err != nil {
		logagg.Warn("injection", "cmdi probe request failed", "endpoint", endpoint.FullURL, "error", err)
		record.Status = 0
		record.Finding = false
		auditLog.Record(record)
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	resp.Body.Close()

	record.Status = resp.StatusCode

	if strings.Contains(string(body), cmdiComputedCanary) {
		record.Finding = true
		auditLog.Record(record)

		evidence := fmt.Sprintf("Command injection confirmed: computed canary %q (shell-evaluated 13*99) in response body, %s", cmdiComputedCanary, paramLabel(param, loc))
		if len(body) > 200 {
			body = body[:200]
		}
		evidence += fmt.Sprintf(", response snippet: %s", string(body))

		return []ev.Evidence{{
			RuleID:     "injection/command-injection",
			Title:      "Command Injection confirmed",
			Severity:   models.SeverityCritical,
			Source:     models.SourceBlackbox,
			Category:   "injection",
			Endpoint:   fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path),
			Evidence:   evidence,
			Fix:        "Never pass user input to shell commands. Use safe APIs that avoid shell interpretation.",
			References: []string{"CWE-78", "OWASP-A03"},
			Confidence: models.ConfidenceHigh,
			// `body` was truncated to 200 bytes just above for the evidence
			// text; ProbeExcerpt re-bounds and sanitizes it for the scorer.
			Payload:  cmdiPayload,
			Response: ProbeExcerpt(string(body)),
		}}
	}

	record.Finding = false
	auditLog.Record(record)
	return nil
}

// probeCRLF injects CRLF characters into a query parameter and checks whether
// the resulting Set-Cookie header is reflected in the response. Query-only —
// header values can't smuggle CR/LF past the http client, and body values
// don't reach response-header construction in any reasonable framework.
func probeCRLF(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, param string, auditLog *ProbeAuditLog) []ev.Evidence {
	// Fix 2.5: soft-stop uniformity — bail before sending any request if the
	// scan context is already cancelled.
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	if auditLog.Count(endpoint.FullURL) >= effectiveMaxProbes(cfg) {
		return nil
	}

	// Inject CRLF payload into the query parameter value (raw, not double-encoded)
	sep := "?"
	if strings.Contains(endpoint.FullURL, "?") {
		sep = "&"
	}
	probeURL := fmt.Sprintf("%s%s%s=%s", endpoint.FullURL, sep, url.QueryEscape(param), crlfPayload)

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, probeURL, nil)
	if err != nil {
		logagg.Warn("injection", "failed to create crlf probe request", "error", err)
		return nil
	}
	cfg.Auth.ApplyToRequest(req)

	resp, err := client.Do(req)
	elapsed := time.Since(start)

	record := ProbeRecord{
		Timestamp: start,
		Endpoint:  endpoint.FullURL,
		ProbeType: ProbeCRLF,
		Payload:   crlfPayload,
		Parameter: param,
		Method:    endpoint.Method,
		Duration:  elapsed.Round(time.Millisecond).String(),
	}

	if err != nil {
		logagg.Warn("injection", "crlf probe request failed", "endpoint", endpoint.FullURL, "error", err)
		record.Status = 0
		record.Finding = false
		auditLog.Record(record)
		return nil
	}
	resp.Body.Close()

	record.Status = resp.StatusCode

	// Check if the injected Set-Cookie header was reflected
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "fendix" && cookie.Value == "injected" {
			record.Finding = true
			auditLog.Record(record)

			return []ev.Evidence{{
				RuleID:     "injection/header-crlf",
				Title:      "Header Injection / CRLF",
				Severity:   models.SeverityHigh,
				Source:     models.SourceBlackbox,
				Category:   "injection",
				Endpoint:   fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path),
				Evidence:   fmt.Sprintf("CRLF injection confirmed: injected Set-Cookie header reflected in response, param=%q", param),
				Fix:        "Sanitize all user input used in HTTP headers. Strip CR/LF characters.",
				References: []string{"CWE-113", "OWASP-A03"},
				Confidence: models.ConfidenceHigh,
				// The confirming observation is the reflected header itself,
				// not the body (which is closed unread).
				Payload:  crlfPayload,
				Response: ProbeExcerpt("Set-Cookie: " + cookie.Name + "=" + cookie.Value),
			}}
		}
	}

	record.Finding = false
	auditLog.Record(record)
	return nil
}

// buildProbeURL appends a query parameter with the probe payload (URL-encoded).
func buildProbeURL(baseURL, param, payload string) string {
	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%s%s=%s", baseURL, sep, url.QueryEscape(param), url.QueryEscape(payload))
}

// medianDuration returns the median of a slice of durations.
func medianDuration(durations []time.Duration) time.Duration {
	n := len(durations)
	if n == 0 {
		return 0
	}
	sorted := make([]time.Duration, n)
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if n%2 == 0 {
		return time.Duration(math.Round(float64(sorted[n/2-1]+sorted[n/2]) / 2))
	}
	return sorted[n/2]
}
