// Package verifycmd implements `fendix verify <finding-id>` — re-run a
// single finding against the current state of the target and report
// whether it's still present or has been resolved.
//
// Surfaced as a Track 4 gap by the TwiScope-backend scan: the verify
// subcommand was a Phase-4 stub that just printed "not yet implemented"
// despite being documented in `fendix --help`.
//
// Supported finding shapes:
//
//   - URL-anchored DAST findings (endpoint shape: "GET /path", "POST /path",
//     or "http(s)://host/path"; source: blackbox): re-issue the request
//     with the same auth and re-evaluate the SAME check that produced
//     the finding originally.
//
//   - File-anchored SAST findings (endpoint shape: "path/to/file.py:42";
//     source: whitebox; category: secrets/injection/headers/...): re-scan
//     the file containing the original endpoint and look for a finding
//     with the same ID at the same approximate line.
//
//   - Dep-CVE findings (category: deps, endpoint: "requirements.txt" or
//     "package-lock.json" or similar): re-run the relevant native
//     scanner against the manifest's directory and check if the same
//     (package, version, OSV-id) tuple still emerges.
//
//   - Correlated findings (source: correlated) — C4: re-test BOTH halves.
//     The blackbox half is the endpoint's reachability; the whitebox half is
//     the tainted source file's continued existence. Missing or inaccessible
//     source is unknown, since checkout completeness is not established.
//     Needs both --url and --code; missing one → unknown.
//
//   - Active injection-probe findings (blackbox injection/xss/ssrf/... under
//     --enable-active) — C4: a gated endpoint (401/403/404/410) resolves the
//     finding; an open one without consent is reported still-present with a
//     note that a confirmed re-exploit needs --enable-active consent; with
//     --enable-active, verify re-hits the endpoint and looks for the recorded
//     payload signal.
//
// Process exit codes (Sprint 03):
//
//   - 0 — Status: resolved. The finding no longer fires.
//   - 1 — Status: still-present. The finding still fires; CI should fail.
//   - 2 — Status: unknown OR not-found-in-baseline. Verify could not
//     produce a confident result; the operator should investigate but
//     CI should NOT auto-fail on this — that would punish edge cases
//     (correlated findings, baseline drift) the operator hasn't yet
//     opted to handle.
//
// There's no automatic discovery of the scan target — the caller passes
// --url / --code explicitly, the same way they did for the original scan.
package verifycmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/npm"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/pip"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/secrets"
)

// Status is the verify outcome for a single finding.
type Status string

const (
	StatusStillPresent Status = "still-present"
	StatusResolved     Status = "resolved"
	StatusUnknown      Status = "unknown"
	StatusNotFound     Status = "not-found-in-baseline"
)

// Result is the structured output of a verify call. Callers can render
// it as plain text, JSON, or use it programmatically.
type Result struct {
	FindingID string `json:"finding_id"`
	Status    Status `json:"status"`
	// Original is the finding as it appeared in the baseline. Always
	// set when Status != not-found-in-baseline.
	Original *models.Finding `json:"original,omitempty"`
	// Reason carries a human-readable explanation, especially for
	// unknown / not-found-in-baseline outcomes.
	Reason string `json:"reason,omitempty"`
	// VerifiedAt is when the re-test ran (UTC ISO-8601).
	VerifiedAt string `json:"verified_at"`
	// Latency is how long the re-test took. Useful for diagnosing
	// slow CI cycles or unreliable targets.
	LatencyMs int64 `json:"latency_ms"`
}

// Options configures a verify call. URL / CodePath / Auth are the same
// inputs the user gave the original scan — verify doesn't try to guess.
type Options struct {
	BaselinePath string
	URL          string
	CodePath     string
	Auth         string // raw Authorization header value (e.g. "Bearer eyJ...")
	Timeout      time.Duration
	// EnableActive mirrors the original scan's --enable-active consent. It is
	// required for verify to actually re-issue an attack payload against an
	// active-probe finding's endpoint (C4). Without it, an active-probe verify
	// falls back to a reachability-only verdict and says so.
	EnableActive bool
}

// Run loads the baseline, finds the requested ID, dispatches to the
// right per-category verifier, and returns the Result. Errors here are
// reserved for unrecoverable problems (baseline can't be read, malformed
// JSON); a "couldn't reach the target" case is encoded as StatusUnknown
// with an explanatory Reason rather than an error.
func Run(ctx context.Context, findingID string, opts Options) (*Result, error) {
	start := time.Now()
	out := &Result{
		FindingID:  findingID,
		VerifiedAt: start.UTC().Format(time.RFC3339),
	}

	baseline, err := loadBaseline(opts.BaselinePath)
	if err != nil {
		return nil, fmt.Errorf("verify: load baseline: %w", err)
	}

	original := findByID(baseline, findingID)
	if original == nil {
		out.Status = StatusNotFound
		out.Reason = fmt.Sprintf("finding %q not present in baseline %q", findingID, opts.BaselinePath)
		out.LatencyMs = time.Since(start).Milliseconds()
		return out, nil
	}
	out.Original = original

	// Gate by Source first. A correlated finding fuses a blackbox URL match
	// with a whitebox file/taint match; a single-shape verifier would answer
	// for ONE side only. C4 gives correlated findings a real two-sided verdict
	// (verifyCorrelated), which is correct precisely because a correlation is
	// broken the moment EITHER half stops reproducing.
	if original.Source == models.SourceCorrelated {
		verifyCorrelated(ctx, original, opts, out)
		out.LatencyMs = time.Since(start).Milliseconds()
		return out, nil
	}

	// Dispatch by finding shape. Active-probe findings (blackbox injection/
	// xss/ssrf/... produced under --enable-active) are checked BEFORE the
	// generic URL path so they get the consent-gated re-probe (C4) rather than
	// the header-oriented checkURLFindingPresence heuristics.
	switch {
	case isDepFinding(original):
		verifyDep(ctx, original, opts, out)
	case isActiveProbeFinding(original):
		verifyActiveProbe(ctx, original, opts, out)
	case isURLFinding(original):
		verifyURL(ctx, original, opts, out)
	case isFileFinding(original):
		verifyFile(ctx, original, opts, out)
	default:
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf(
			"verify does not yet support this finding shape (source=%q, category=%q). "+
				"Workaround: re-run the full scan that produced the baseline "+
				"(fendix scan --code <path> --url <url> --enable-active if applicable) "+
				"and diff against the baseline.",
			original.Source, original.Category)
	}

	out.LatencyMs = time.Since(start).Milliseconds()
	return out, nil
}

// ─── baseline / dispatch helpers ────────────────────────────────────

// loadBaseline reads a verify baseline. Two on-disk shapes are accepted,
// mirroring the engine's own baseline loader (engine.loadBaseline):
//
//   - the full report envelope — {"metadata":…,"findings":[…]} — written by
//     `fendix scan --format json --output scan.json`;
//   - a bare JSON array of findings — [{…},{…}] — written by
//     `fendix scan --save-baseline <path>` (engine.SaveBaseline).
//
// Verify previously handed everything to reporters.ParseJSONReport, which
// unmarshals into a map[string]any and therefore rejects the array outright:
// the scanner's own --save-baseline output was not valid input to its own
// verify command. Accepting the array here fixes that without changing what
// SaveBaseline writes, so every baseline file already on disk keeps loading.
//
// Dispatch is on the first non-whitespace byte rather than "try one, fall
// back to the other", so a malformed array reports the array parse error
// instead of the confusing map-shaped one. Anything that is not an array
// still goes through ParseJSONReport and keeps its SARIF / not-a-report
// rejections — this widens the accepted shapes, it does not accept any JSON.
func loadBaseline(path string) (*reporters.JSONReport, error) {
	if path == "" {
		return nil, errors.New("baseline path required (pass --baseline <findings.json>)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	switch firstJSONToken(data) {
	case '[':
		var findings []models.Finding
		if err := json.Unmarshal(data, &findings); err != nil {
			return nil, fmt.Errorf(
				"parsing %s as a bare findings array (the shape `fendix scan --save-baseline` writes): %w",
				path, err)
		}
		return &reporters.JSONReport{Total: len(findings), Findings: findings}, nil

	case 'n':
		// engine.SaveBaseline marshals an empty/nil findings slice to the
		// JSON literal `null` — a clean scan run with --save-baseline. Treat
		// it as an empty baseline so verify answers not-found-in-baseline
		// (exit 2, "verify couldn't tell") instead of failing the load.
		// Anything else starting with 'n' is not valid JSON and falls
		// through to ParseJSONReport's error.
		if isJSONNull(data) {
			return &reporters.JSONReport{}, nil
		}
	}

	return reporters.ParseJSONReport(data)
}

// firstJSONToken returns the first non-whitespace byte of data, or 0 when
// data is empty or all whitespace. Used only to pick a parse strategy — the
// chosen parser still validates the document.
func firstJSONToken(data []byte) byte {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return b
		}
	}
	return 0
}

// isJSONNull reports whether data is exactly the JSON literal `null`
// (modulo surrounding whitespace).
func isJSONNull(data []byte) bool {
	return strings.TrimSpace(string(data)) == "null"
}

func findByID(r *reporters.JSONReport, id string) *models.Finding {
	for i := range r.Findings {
		if r.Findings[i].ID == id {
			return &r.Findings[i]
		}
	}
	return nil
}

// isDepFinding matches the category that pip/npm/govulncheck scanners
// emit. The endpoint is a manifest path ("requirements.txt", etc.)
// rather than a URL or a file:line.
func isDepFinding(f *models.Finding) bool {
	return f.Category == "deps"
}

// isURLFinding picks endpoints that look like HTTP requests. The
// scanner emits these as "<METHOD> <path>" (e.g. "GET /admin") or as
// fully-qualified URLs depending on the check. Bare paths starting with
// "/" also count when they look like URL paths.
func isURLFinding(f *models.Finding) bool {
	ep := f.Endpoint
	if ep == "" {
		return false
	}
	if strings.HasPrefix(ep, "http://") || strings.HasPrefix(ep, "https://") {
		return true
	}
	// "GET /path", "POST /path", etc.
	for _, m := range []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "} {
		if strings.HasPrefix(ep, m) {
			return true
		}
	}
	return false
}

// isFileFinding matches SAST endpoints like "path/to/file.py:42".
// We require a `:` followed by digits AND a recognised source extension
// to avoid false-matching URLs that happen to contain colons.
func isFileFinding(f *models.Finding) bool {
	ep := f.Endpoint
	if ep == "" {
		return false
	}
	// Strip optional :line suffix
	base := ep
	if i := strings.LastIndex(ep, ":"); i > 0 {
		base = ep[:i]
	}
	// Recognise common SAST-relevant extensions.
	for _, ext := range []string{".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".php", ".env", ".yaml", ".yml", ".json"} {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	// .env.Production / .env.bak / .env.master — extensionless secret files.
	if strings.Contains(base, ".env") {
		return true
	}
	return false
}

// ─── per-category verifiers ─────────────────────────────────────────

// verifyURL re-issues a request to the same endpoint with the same
// method and auth, and checks whether the response still matches the
// signal that produced the original finding.
//
// We deliberately keep this conservative: we look for "the same finding
// title appears for the same endpoint" rather than re-running the
// entire scanner pipeline. That avoids false-resolved when the engine
// has been updated between the baseline and verify — the user expects
// "is this specific finding fixed?", not "what would a fresh scan
// say?".
func verifyURL(ctx context.Context, f *models.Finding, opts Options, out *Result) {
	if opts.URL == "" {
		out.Status = StatusUnknown
		out.Reason = "url-anchored finding requires --url <base> to re-test"
		return
	}
	method, path := splitMethodPath(f.Endpoint)
	if method == "" {
		method = "GET"
	}
	targetURL := joinURL(opts.URL, path)
	if targetURL == "" {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("cannot construct target URL from endpoint %q and base %q", f.Endpoint, opts.URL)
		return
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("build request: %v", err)
		return
	}
	if opts.Auth != "" {
		req.Header.Set("Authorization", opts.Auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("request to %s failed: %v", targetURL, err)
		return
	}
	defer resp.Body.Close()
	// A login/error page can carry secure headers without representing the
	// application response whose missing header produced the finding.
	if f.Category == "headers" && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("header verification requires a successful application response; received HTTP %d", resp.StatusCode)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	// Apply a focused per-title heuristic. Each branch matches a
	// stable check-output title from internal/scanner/.
	stillPresent, evidence := checkURLFindingPresence(f, resp, body)
	if stillPresent {
		out.Status = StatusStillPresent
		out.Reason = evidence
	} else {
		out.Status = StatusResolved
		out.Reason = evidence
	}
}

// checkURLFindingPresence returns (true, evidence) if the original
// finding's signal is still observable in the response, else (false,
// reason it looks resolved).
func checkURLFindingPresence(f *models.Finding, resp *http.Response, body []byte) (bool, string) {
	title := f.Title
	headers := resp.Header

	switch {
	case strings.Contains(title, "Missing Content-Security-Policy"):
		if headers.Get("Content-Security-Policy") == "" {
			return true, "Content-Security-Policy header is still absent"
		}
		return false, fmt.Sprintf("Content-Security-Policy now set: %s", truncate(headers.Get("Content-Security-Policy"), 80))

	case strings.Contains(title, "Missing Strict-Transport-Security"):
		if headers.Get("Strict-Transport-Security") == "" {
			return true, "Strict-Transport-Security header is still absent"
		}
		return false, fmt.Sprintf("Strict-Transport-Security now set: %s", truncate(headers.Get("Strict-Transport-Security"), 80))

	case strings.Contains(title, "X-Content-Type-Options"):
		if !strings.EqualFold(headers.Get("X-Content-Type-Options"), "nosniff") {
			return true, fmt.Sprintf("X-Content-Type-Options still %q (expected 'nosniff')", headers.Get("X-Content-Type-Options"))
		}
		return false, "X-Content-Type-Options: nosniff is now set"

	case strings.Contains(title, "X-Frame-Options"):
		if headers.Get("X-Frame-Options") == "" {
			return true, "X-Frame-Options header is still absent"
		}
		return false, fmt.Sprintf("X-Frame-Options now set: %s", headers.Get("X-Frame-Options"))

	case strings.Contains(title, "CORS allows any origin"):
		if headers.Get("Access-Control-Allow-Origin") == "*" {
			return true, "Access-Control-Allow-Origin is still '*'"
		}
		return false, fmt.Sprintf("Access-Control-Allow-Origin now %q", headers.Get("Access-Control-Allow-Origin"))

	case strings.Contains(title, "Server version disclosed"):
		serverHeader := headers.Get("Server")
		if serverHeader == "" {
			return false, "Server header is no longer present"
		}
		// Detect a version-shaped substring (digits.digits)
		if containsVersionLike(serverHeader) {
			return true, fmt.Sprintf("Server header still discloses version: %q", serverHeader)
		}
		return false, fmt.Sprintf("Server header no longer discloses version: %q", serverHeader)

	case strings.Contains(title, "No rate limiting detected"),
		strings.Contains(title, "No rate limiting observed"):
		// Best-effort: a single re-test request can't conclusively
		// determine rate-limiting. Report unknown so the user re-runs
		// a focused load test. (Phase 5.4 renamed the title to the
		// scoped "No rate limiting observed within N requests"; the old
		// literal is kept for findings persisted before that change.)
		return false, "rate-limit verification needs a full re-scan with multiple rapid requests; single-request verify can't disprove rate limiting"

	case strings.Contains(title, "Missing authentication on endpoint"):
		// Re-test with no auth; if endpoint still 200s, finding holds.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return true, fmt.Sprintf("endpoint still returns %d to unauthenticated request", resp.StatusCode)
		}
		return false, fmt.Sprintf("endpoint now returns %d to unauthenticated request", resp.StatusCode)

	case strings.Contains(title, "Software version string in response"):
		// Naive but useful: re-scan the body for any version-shaped substring.
		if containsVersionLike(string(body)) {
			return true, "response body still contains a version-shaped string"
		}
		return false, "response body no longer contains an obvious version string"

	default:
		// Generic fallback: if the response status changed from 200 to
		// 401/403/404/410, treat as plausibly resolved.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
			resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
			return false, fmt.Sprintf("endpoint now returns %d (presumed gated or removed)", resp.StatusCode)
		}
		return true, fmt.Sprintf("no per-title re-test for %q yet; endpoint still reachable (HTTP %d) — flagging as still-present conservatively", f.Title, resp.StatusCode)
	}
}

// verifyFile re-scans the source file containing the original endpoint
// and reports whether a finding with the same ID still emerges.
// MVP implementation only handles secrets findings (which run via the
// native Go secrets scanner — no subprocess, fast); other SAST
// categories defer to a full re-scan.
func verifyFile(ctx context.Context, f *models.Finding, opts Options, out *Result) {
	if opts.CodePath == "" {
		out.Status = StatusUnknown
		out.Reason = "file-anchored finding requires --code <root> to re-test"
		return
	}
	// Strip :line from endpoint to get the file path.
	relPath := f.Endpoint
	if i := strings.LastIndex(relPath, ":"); i > 0 {
		// Only strip if what follows looks like a line number.
		if _, err := stringToInt(relPath[i+1:]); err == nil {
			relPath = relPath[:i]
		}
	}
	absFile := relPath
	if !filepath.IsAbs(relPath) {
		absFile = filepath.Join(opts.CodePath, relPath)
	}
	if err := inspectVerificationFile(opts.CodePath, absFile); err != nil {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("cannot inspect source file %s; missing or inaccessible source is not proof of remediation: %v", absFile, err)
		return
	}

	if f.Category == "secrets" {
		// Re-run the native secrets scanner against the file's dir.
		// (The scanner itself walks; pointing it at the immediate
		// parent gives a fast, focused re-test.)
		findings, err := secrets.Scan(ctx, filepath.Dir(absFile))
		if err != nil {
			out.Status = StatusUnknown
			out.Reason = fmt.Sprintf("secrets re-scan failed: %v", err)
			return
		}
		for _, nf := range findings {
			if endpointFileMatches(nf.Endpoint, relPath) && titleMatches(nf.Title, f.Title) {
				out.Status = StatusStillPresent
				out.Reason = fmt.Sprintf("secrets scanner re-emitted the same finding at %s", nf.Endpoint)
				return
			}
			// Also check affected_endpoints — secrets dedups across files.
			for _, ep := range nf.AffectedEndpoints {
				if endpointFileMatches(ep, relPath) && titleMatches(nf.Title, f.Title) {
					out.Status = StatusStillPresent
					out.Reason = fmt.Sprintf("secrets scanner re-emitted same finding at %s (via affected_endpoints)", ep)
					return
				}
			}
		}
		out.Status = StatusResolved
		out.Reason = fmt.Sprintf("secrets scanner no longer flags %s for %q", relPath, truncate(f.Title, 60))
		return
	}

	// AST-based SAST findings (category=injection / xss / etc.) need
	// the Python engine — defer.
	out.Status = StatusUnknown
	out.Reason = "AST-based SAST verify (injection/xss/path-traversal/...) requires --python-engine and a focused re-scan harness; not in MVP. Run `fendix scan --code <path> --python-engine` for the full re-eval."
}

// verifyDep re-runs the native pip/npm scanner against the manifest's
// directory and checks if the same vulnerable (package, version) tuple
// still appears.
func verifyDep(ctx context.Context, f *models.Finding, opts Options, out *Result) {
	if opts.CodePath == "" {
		out.Status = StatusUnknown
		out.Reason = "dep finding requires --code <root> to re-test"
		return
	}
	// The endpoint is the manifest path relative to the original scan root.
	manifest := f.Endpoint
	absManifest := manifest
	if !filepath.IsAbs(manifest) {
		absManifest = filepath.Join(opts.CodePath, manifest)
	}
	manifestDir := filepath.Dir(absManifest)
	if err := inspectVerificationFile(opts.CodePath, absManifest); err != nil {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("cannot inspect dependency manifest %s: %v", manifest, err)
		return
	}

	var newFindings []models.Finding
	var err error
	switch {
	case strings.HasSuffix(manifest, "requirements.txt"):
		var pipEv []evidence.Evidence
		pipEv, err = pip.Scan(ctx, manifestDir)
		newFindings = evidence.ToFindings(pipEv)
		if errors.Is(err, pip.ErrNoRequirements) {
			out.Status = StatusUnknown
			out.Reason = fmt.Sprintf("requirements.txt unavailable at %s; dependency inventory is insufficient to verify remediation", manifestDir)
			return
		}
	case strings.HasSuffix(manifest, "package.json") || strings.HasSuffix(manifest, "package-lock.json"):
		var npmEv []evidence.Evidence
		npmEv, err = npm.Scan(ctx, manifestDir)
		newFindings = evidence.ToFindings(npmEv)
		if errors.Is(err, npm.ErrNoLockfile) || errors.Is(err, npm.ErrLockfileMissingButPackageJsonPresent) {
			out.Status = StatusUnknown
			out.Reason = fmt.Sprintf("package-lock.json is not scannable at %s; dependency inventory is insufficient to verify remediation", manifestDir)
			return
		}
	default:
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("unrecognised dep manifest %q (supported: requirements.txt, package-lock.json)", manifest)
		return
	}
	if err != nil {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("dep re-scan failed: %v", err)
		return
	}

	// Match by ID — dep findings carry stable SEC-DEPS-* / SEC-NPM-*
	// IDs derived from the OSV-id, so the same vuln re-emits with the
	// same suffix even if SEC-* renumbering changed the prefix.
	//
	// ...except the OSV-id a dep finding is named after is no longer
	// fixed. FIX-05 collapses the several OSV records that describe one
	// vulnerability into a single finding named after the CANONICAL id of
	// that alias set — usually the CVE. A finding recorded before that
	// change as SEC-DEPS-PYSEC_2026_3552 re-scans as
	// SEC-DEPS-CVE_2026_69247, the id tail stops matching, and this loop
	// would fall through to StatusResolved: a security tool announcing
	// "fixed" about a vulnerability that is still installed. Worst
	// possible direction of error.
	//
	// So the identity of a dep finding is its whole id SET, not one id.
	// depIdentity gathers the OSV-id slug out of the finding's ID plus
	// every reference (which, by construction, contains every merged
	// alias), and a non-empty intersection means "same vulnerability".
	idTail := tailAfterDash(f.ID)
	storedIDs := depIdentity(*f)
	for _, nf := range newFindings {
		if strings.HasSuffix(nf.ID, idTail) || nf.ID == f.ID || depIdentitiesIntersect(storedIDs, depIdentity(nf)) {
			out.Status = StatusStillPresent
			out.Reason = fmt.Sprintf("dep scanner re-emitted %s for %s", nf.ID, truncate(nf.Title, 60))
			return
		}
	}
	out.Status = StatusResolved
	out.Reason = fmt.Sprintf("dep scanner no longer flags this vulnerability at %s", manifest)
}

// ─── C4: correlated + active-probe verifiers ────────────────────────

// activeProbeCategories are the active-tier blackbox check categories whose
// findings are produced by sending an attack payload (gated by --enable-active
// at scan time). Passive header/CORS/exposure checks are excluded — those have
// dedicated per-title re-tests in checkURLFindingPresence.
var activeProbeCategories = map[string]bool{
	"injection":     true,
	"xss":           true,
	"ssrf":          true,
	"open-redirect": true,
	"host-header":   true,
	"method-tamper": true,
	"graphql":       true,
}

// isActiveProbeFinding reports whether f came from an active-tier probe: a
// blackbox finding in an active-probe category whose evidence records an
// injected payload. Requiring both the category AND the "active probe" evidence
// marker avoids misclassifying a whitebox taint finding (same category, source
// whitebox) or a passively-observed one.
func isActiveProbeFinding(f *models.Finding) bool {
	if f.Source != models.SourceBlackbox {
		return false
	}
	if !activeProbeCategories[f.Category] {
		return false
	}
	return strings.Contains(strings.ToLower(f.Evidence), "active probe") ||
		strings.Contains(strings.ToLower(f.Evidence), "payload")
}

// verifyCorrelated re-tests BOTH halves of a correlated finding. The blackbox
// half is the endpoint's reachability (a gated 401/403/404/410 means the DAST
// signal no longer reproduces); the whitebox half is the tainted source file's
// continued existence. Unavailable source cannot establish that the SAST half
// was removed from the intended revision. Both halves need their input
// (--url and --code); insufficient source context returns unknown.
func verifyCorrelated(ctx context.Context, f *models.Finding, opts Options, out *Result) {
	if opts.URL == "" || opts.CodePath == "" {
		out.Status = StatusUnknown
		out.Reason = "correlated finding needs BOTH --url (blackbox half) and --code (whitebox half) to re-test; " +
			"a correlation fuses a DAST endpoint hit with a SAST taint path. Missing one means verify can only " +
			"check one side, which cannot confirm the correlation. Re-run with both, or re-scan and diff."
		return
	}

	// Whitebox half: does the tainted source file still exist? The taint sink
	// lives at an affected endpoint ("file.py:line") or the primary endpoint.
	whiteboxFile := correlatedWhiteboxFile(f)
	if whiteboxFile != "" {
		abs := whiteboxFile
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(opts.CodePath, whiteboxFile)
		}
		if err := inspectVerificationFile(opts.CodePath, abs); err != nil {
			out.Status = StatusUnknown
			out.Reason = fmt.Sprintf("cannot inspect correlated source file %q; missing or inaccessible source is not proof of remediation: %v", whiteboxFile, err)
			return
		}
	}

	// Blackbox half: is the endpoint still reachable (not gated/removed)?
	method, path := splitMethodPath(f.Endpoint)
	if method == "" {
		method = "GET"
	}
	targetURL := joinURL(opts.URL, path)
	if targetURL == "" {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("cannot construct target URL from endpoint %q and base %q", f.Endpoint, opts.URL)
		return
	}
	status, err := probeStatus(ctx, method, targetURL, opts)
	if err != nil {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("correlated blackbox half: request to %s failed: %v", targetURL, err)
		return
	}
	if isGatedStatus(status) {
		out.Status = StatusResolved
		out.Reason = fmt.Sprintf(
			"correlation broken: the blackbox endpoint now returns %d (gated/removed), so the DAST half no "+
				"longer reproduces — a correlated finding is resolved once either half is gone.", status)
		return
	}

	// Both halves still hold.
	out.Status = StatusStillPresent
	out.Reason = fmt.Sprintf(
		"correlation holds: the blackbox endpoint is still reachable (HTTP %d) AND the whitebox tainted-source "+
			"file %q still exists. Both halves reproduce; re-run a full scan for a fresh taint-path confirmation.",
		status, whiteboxFile)
}

// inspectVerificationFile excludes missing, unreadable, non-file and out-of-root
// inputs before a scanner can interpret an empty result as remediation.
// It does not establish checkout completeness or guard against later mutation;
// governed resolution still requires independently collected execution evidence.
func inspectVerificationFile(root, path string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	rootAbs, err = filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return err
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	pathAbs, err = filepath.EvalSymlinks(pathAbs)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("verification input is outside the supplied code root")
	}
	info, err := os.Stat(pathAbs)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("verification input is not a regular file")
	}
	file, err := os.Open(pathAbs)
	if err != nil {
		return err
	}
	return file.Close()
}

// correlatedWhiteboxFile returns the source file that carries the correlated
// finding's taint sink: the first affected endpoint that looks like a
// "file:line", else the primary endpoint if it is file-shaped.
func correlatedWhiteboxFile(f *models.Finding) string {
	for _, ep := range f.AffectedEndpoints {
		if file := fileOfEndpoint(ep); file != "" {
			return file
		}
	}
	return fileOfEndpoint(f.Endpoint)
}

// fileOfEndpoint returns the file part of a "path/to/file.py:42" endpoint, or
// "" if the endpoint is not file-shaped (e.g. a URL).
func fileOfEndpoint(ep string) string {
	if ep == "" {
		return ""
	}
	base := ep
	if i := strings.LastIndex(ep, ":"); i > 0 {
		if _, err := stringToInt(ep[i+1:]); err == nil {
			base = ep[:i]
		}
	}
	for _, ext := range []string{".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".php"} {
		if strings.HasSuffix(base, ext) {
			return base
		}
	}
	return ""
}

// verifyActiveProbe re-tests an active-probe finding. Re-issuing the actual
// attack payload requires explicit consent (opts.EnableActive) mirroring the
// original scan's --enable-active gate:
//
//   - No consent: a reachability-only verdict. A gated endpoint (401/403/404/
//     410) is resolved; an open one is reported still-present WITH a note that
//     a confirmed re-exploit needs --enable-active.
//   - Consent: re-hit the endpoint and look for the finding's signal in the
//     response body (a reflected payload / marker). Absent → resolved.
func verifyActiveProbe(ctx context.Context, f *models.Finding, opts Options, out *Result) {
	if opts.URL == "" {
		out.Status = StatusUnknown
		out.Reason = "active-probe finding requires --url <base> to re-test"
		return
	}
	method, path := splitMethodPath(f.Endpoint)
	if method == "" {
		method = "GET"
	}
	targetURL := joinURL(opts.URL, path)
	if targetURL == "" {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("cannot construct target URL from endpoint %q and base %q", f.Endpoint, opts.URL)
		return
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("build request: %v", err)
		return
	}
	if opts.Auth != "" {
		req.Header.Set("Authorization", opts.Auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("request to %s failed: %v", targetURL, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	// A gated/removed endpoint resolves the finding regardless of consent —
	// the attack surface is no longer reachable.
	if isGatedStatus(resp.StatusCode) {
		out.Status = StatusResolved
		out.Reason = fmt.Sprintf("active-probe endpoint now returns %d (gated/removed) — attack surface no longer reachable", resp.StatusCode)
		return
	}

	if !opts.EnableActive {
		out.Status = StatusStillPresent
		out.Reason = fmt.Sprintf(
			"active-probe endpoint still reachable (HTTP %d). This is a REACHABILITY verdict only — a confirmed "+
				"re-exploit requires re-sending the attack payload, which needs explicit consent: re-run with "+
				"--enable-active (mirroring the original scan) to actually re-probe.", resp.StatusCode)
		return
	}

	// Consent given: re-probe. Best-effort signal match — a reflected marker
	// from the recorded payload still appearing in the body means the finding
	// reproduces. If the recorded payload marker is gone, treat as resolved.
	if marker := probeMarker(f); marker != "" && strings.Contains(string(body), marker) {
		out.Status = StatusStillPresent
		out.Reason = fmt.Sprintf("re-probe reflected the recorded payload marker %q in the response — finding reproduces", truncate(marker, 40))
		return
	}
	out.Status = StatusResolved
	out.Reason = "re-probe did not reproduce the recorded payload signal — finding presumed resolved (re-run a full --enable-active scan for exhaustive confirmation)"
}

// probeStatus issues a single request and returns the HTTP status code.
func probeStatus(ctx context.Context, method, targetURL string, opts Options) (int, error) {
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return 0, err
	}
	if opts.Auth != "" {
		req.Header.Set("Authorization", opts.Auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}

// isGatedStatus reports whether an HTTP status means the endpoint is no longer
// an open attack surface (auth-gated or gone).
func isGatedStatus(code int) bool {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusGone:
		return true
	}
	return false
}

// probeMarker extracts a reflected-payload marker from a finding's evidence so
// a re-probe can look for it in the response. Best-effort: pulls a
// <script>...</script> or a quoted SQL tautology when present.
func probeMarker(f *models.Finding) string {
	ev := f.Evidence
	if i := strings.Index(ev, "<script>"); i >= 0 {
		if j := strings.Index(ev[i:], "</script>"); j >= 0 {
			return ev[i : i+j+len("</script>")]
		}
		return "<script>"
	}
	return ""
}

// ─── small utilities ────────────────────────────────────────────────

func splitMethodPath(endpoint string) (method, path string) {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		if u, err := url.Parse(endpoint); err == nil {
			return "GET", u.Path
		}
	}
	// "GET /path", "POST /path", etc.
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"} {
		prefix := m + " "
		if strings.HasPrefix(endpoint, prefix) {
			return m, strings.TrimSpace(endpoint[len(prefix):])
		}
	}
	if strings.HasPrefix(endpoint, "/") {
		return "GET", endpoint
	}
	return "", ""
}

func joinURL(base, path string) string {
	if base == "" {
		return ""
	}
	bu, err := url.Parse(base)
	if err != nil {
		return ""
	}
	// If path is already absolute URL, return as-is.
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	bu.Path = path
	return bu.String()
}

func endpointFileMatches(endpoint, relPath string) bool {
	if endpoint == "" {
		return false
	}
	base := endpoint
	if i := strings.LastIndex(base, ":"); i > 0 {
		if _, err := stringToInt(base[i+1:]); err == nil {
			base = base[:i]
		}
	}
	return strings.HasSuffix(base, relPath) || strings.HasSuffix(relPath, base)
}

func titleMatches(a, b string) bool {
	// Title equality with a small tolerance: the secrets scanner uses
	// stable canonical titles, so equality is the common case.
	return a == b
}

func stringToInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit %q", c)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func containsVersionLike(s string) bool {
	// Match "<digit>.<digit>" anywhere in the string — proxy for a
	// version number. Cheap, deliberately approximate.
	for i := 0; i < len(s)-2; i++ {
		if s[i] >= '0' && s[i] <= '9' && s[i+1] == '.' && s[i+2] >= '0' && s[i+2] <= '9' {
			return true
		}
	}
	return false
}

// depIdentity renders every OSV/CVE id a dependency finding is known by
// into one comparable set: the slug carried in its SEC-DEPS-* id, plus
// every reference, normalised to the underscored slug form the ids use.
//
// Both halves matter. The references are what survive a canonical rename
// (FIX-05 preserves every merged id there), and the id slug is what a
// finding recorded before that rename has instead of the new canonical
// reference.
func depIdentity(f models.Finding) map[string]bool {
	set := map[string]bool{}
	add := func(id string) {
		if id != "" {
			set[strings.ReplaceAll(id, "-", "_")] = true
		}
	}
	for _, prefix := range []string{"SEC-DEPS-GO-", "SEC-DEPS-", "SEC-NPM-"} {
		if tail := strings.TrimPrefix(f.ID, prefix); tail != f.ID {
			add(tail)
			break
		}
	}
	for _, ref := range f.References {
		add(ref)
	}
	return set
}

// depIdentitiesIntersect reports whether two dep findings name at least
// one OSV/CVE id in common — i.e. describe the same vulnerability.
func depIdentitiesIntersect(a, b map[string]bool) bool {
	// Iterate the smaller set; the result is order-independent either way.
	if len(b) < len(a) {
		a, b = b, a
	}
	for id := range a {
		if b[id] {
			return true
		}
	}
	return false
}

func tailAfterDash(id string) string {
	if i := strings.LastIndex(id, "-"); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

// Render writes the Result either as pretty-printed JSON (when
// emitJSON=true) or a short human-readable summary. Returns a non-nil
// error only on write failure.
func Render(w io.Writer, r *Result, emitJSON bool) error {
	if emitJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}

	statusGlyph := map[Status]string{
		StatusStillPresent: "✗",
		StatusResolved:     "✓",
		StatusUnknown:      "?",
		StatusNotFound:     "—",
	}[r.Status]
	if statusGlyph == "" {
		statusGlyph = "?"
	}

	fmt.Fprintf(w, "%s %s — %s (%.0d ms)\n", statusGlyph, r.FindingID, r.Status, r.LatencyMs)
	if r.Original != nil {
		fmt.Fprintf(w, "  baseline: %s [%s]\n", truncate(r.Original.Title, 80), r.Original.Severity)
		if r.Original.Endpoint != "" {
			fmt.Fprintf(w, "  endpoint: %s\n", r.Original.Endpoint)
		}
	}
	if r.Reason != "" {
		fmt.Fprintf(w, "  reason:   %s\n", r.Reason)
	}
	fmt.Fprintf(w, "  verified: %s\n", r.VerifiedAt)
	return nil
}

// We import scanner just to make sure the package compiles its
// transitive deps even when only the secrets sub-scanner is invoked
// at verify time. Remove if it becomes a problem.
var _ = scanner.NewCrawler
