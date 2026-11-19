// Package verifycmd implements `fendix verify <finding-id>` — re-run a
// single finding against the current state of the target and report
// whether it is still present or could not be confirmed.
//
// Surfaced as a Track 4 gap by the TwiScope-backend scan: the verify
// subcommand was a Phase-4 stub that just printed "not yet implemented"
// despite being documented in `fendix --help`.
//
// Decision D4, Option A (Round 6): verify never answers "resolved". Not finding
// a credential in an enumerated list of representations cannot prove it is gone,
// because the list of ways to write a value down is open (encodings, archives,
// media containers, a file name, history, a value built at run time). The
// answer is still-present when the problem is seen, and unknown otherwise, for
// every finding, occurrence and group. StatusResolved stays in the output
// vocabulary so a consumer that knows it keeps parsing, but nothing here
// produces it: verifyOne turns any such verdict into unknown, and the fold over
// a group's occurrences cannot reach it.
//
// What verify re-tests:
//
//   - File-anchored findings the native secrets scanner produced (rule_id
//     "secrets/<PATTERN>", no source tier): the file is re-read by that scanner
//     and the finding is still present while the same rule fires anywhere in the
//     same file, or while the credential's VALUE (identified by the redaction
//     marker in the baseline evidence) is found in any text file under --code, as
//     written or with string concatenation, line continuations and backslash
//     escapes undone (see verifySecret). When neither is seen the answer is
//     unknown, with what was searched stated: a credential found nowhere is not a
//     credential that is gone. Every other file-anchored finding — Semgrep,
//     textscan, the Python engine, including their `secrets`-category findings —
//     is unknown: verify cannot re-run that analyzer on one file.
//
//   - URL-anchored DAST findings (endpoint shape: "GET /path", "POST /path", or
//     "http(s)://host/path"; source: blackbox): the request is re-issued with the
//     same auth and the SAME check that produced the finding re-evaluates it. A
//     response that still shows the problem is still-present; anything else is
//     unknown, because what one response shows now says nothing about a fix.
//
//   - Dep-CVE findings (category: deps, endpoint: "requirements.txt" or
//     "package-lock.json" or similar): the relevant native scanner is re-run
//     against the manifest's directory. The same (package, version, OSV-id)
//     tuple emerging is still-present; otherwise unknown.
//
//   - Correlated findings (source: correlated): the blackbox half's endpoint is
//     requested and the whitebox half's source file must still exist. Both
//     halves holding is still-present. A gated or removed route (401, 403, 404,
//     410) is never a fix, whatever the category (C4B-11, contract C8): a status
//     says the route changed, not that the code half was fixed. Missing or
//     inaccessible source is unknown. Needs both --url and --code; missing one is
//     unknown.
//
//   - Active injection-probe findings (blackbox injection/xss/ssrf/... under
//     --enable-active) never resolve. A gated endpoint (401/403/404/410) is
//     unknown; with --enable-active, verify re-hits the endpoint and a
//     reflected payload marker is still-present.
//
// Process exit codes (Sprint 03; mapped in cmd/fendix's verify command):
//
//   - 1 — Status: still-present. The finding still fires; CI should fail.
//   - 2 — Status: unknown OR not-found-in-baseline (and any status the
//     command does not recognise, and any command error). Verify could not
//     confirm the finding is gone; the operator should investigate but CI
//     should NOT auto-fail on this — that would punish edge cases
//     (correlated findings, baseline drift) the operator hasn't yet
//     opted to handle. It is never the success code.
//   - 0 — Status: resolved. Reserved: verify does not produce it (D4 Option A).
//     A gate that treats exit 0 as "resolved" never closes an unknown, and
//     under Option A it never sees a zero for a secrets finding.
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

	"github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
	"github.com/Fendix-app/Fendix/go/internal/reporters"
	"github.com/Fendix-app/Fendix/go/internal/scanner"
	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/npm"
	"github.com/Fendix-app/Fendix/go/internal/scanner/deps/pip"
	"github.com/Fendix-app/Fendix/go/internal/scanner/secrets"
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
	// Occurrences holds one verdict per occurrence when the finding is a
	// group of several; Status is their fold (see verifyEach).
	Occurrences []OccurrenceResult `json:"occurrences,omitempty"`
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

	// sightings caches one secrets-scanner pass over CodePath, and searches
	// the credential search of each distinct set of markers, for every
	// occurrence of the finding being verified (verifySecret). Run sets them.
	sightings *sightingCache
	searches  *searchCache
}

// sightingCache holds the secrets scanner's findings over the whole --code
// root, computed at most once per Run.
type sightingCache struct {
	loaded bool
	list   []secrets.Sighting
	scope  secrets.SightingsScope
	err    error
}

func (c *sightingCache) get(ctx context.Context, root string) ([]secrets.Sighting, secrets.SightingsScope, error) {
	if c == nil {
		return secrets.ScanSightingsDetail(ctx, root)
	}
	if !c.loaded {
		c.list, c.scope, c.err = secrets.ScanSightingsDetail(ctx, root)
		c.loaded = true
	}
	return c.list, c.scope, c.err
}

// searchCache holds the result of each credential search, so the occurrences of
// one finding (and a repeated marker) read the tree once.
type searchCache struct {
	byKey map[string]searchEntry
}

type searchEntry struct {
	res *secrets.SearchResult
	err error
}

func (c *searchCache) get(ctx context.Context, root string, markers []string) (*secrets.SearchResult, error) {
	if c == nil {
		return secrets.SearchValues(ctx, root, markers)
	}
	key := strings.Join(markers, "\x00")
	if e, ok := c.byKey[key]; ok {
		return e.res, e.err
	}
	res, err := secrets.SearchValues(ctx, root, markers)
	if c.byKey == nil {
		c.byKey = map[string]searchEntry{}
	}
	c.byKey[key] = searchEntry{res, err}
	return res, err
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
	if opts.sightings == nil {
		opts.sightings = &sightingCache{}
	}
	if opts.searches == nil {
		opts.searches = &searchCache{}
	}

	// A grouped finding presents several security occurrences. Re-testing
	// only its primary location and reporting the result for the whole
	// group would let one occurrence speak for the others: a still-present
	// occurrence must keep the group present. So each occurrence is re-tested on
	// its own and folded (verifyEach). Neither an occurrence nor the fold is ever
	// resolved (D4 Option A).
	if units := verifyUnits(original); len(units) > 1 {
		verifyEach(ctx, units, opts, out)
	} else {
		verifyOne(ctx, original, opts, out)
	}

	out.LatencyMs = time.Since(start).Milliseconds()
	return out, nil
}

// verifyOne dispatches one finding (or one occurrence of a grouped finding)
// to its verifier, writing Status and Reason into out.
func verifyOne(ctx context.Context, original *models.Finding, opts Options, out *Result) {
	dispatchOne(ctx, original, opts, out)
	// D4 Option A (Round 6): verify never answers resolved. Not finding a
	// credential in a list of forms cannot prove it is gone, and no verifier
	// establishes absence any other way (contract C8, D5-3: only a secrets
	// finding could resolve, and that was the verdict this removes). This is the
	// backstop for every verifier, present and future: a verdict of resolved
	// becomes unknown, so neither an occurrence nor the fold over a group can
	// carry it out of this function.
	if out.Status == StatusResolved {
		why := absenceNote
		if w := notSecretsScannerFinding(original); w != "" {
			why = fmt.Sprintf("%s; %s", w, absenceNote)
		}
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("verify never answers resolved (%s): %s", why, truncate(out.Reason, 160))
	}
}

// observationNote ends a reason that rests on what a response or an inventory
// shows now, which is evidence about that response and nothing about the fix.
const observationNote = "this is what one re-test observed, not proof that the vulnerability is fixed: verify never answers resolved, so a finding it cannot see is unconfirmed. " +
	"Re-run `fendix scan` against the target and compare with the baseline"

func dispatchOne(ctx context.Context, original *models.Finding, opts Options, out *Result) {
	// Gate by Source first. A correlated finding fuses a blackbox URL match
	// with a whitebox file/taint match; a single-shape verifier would answer
	// for ONE side only. C4 gives correlated findings a real two-sided verdict
	// (verifyCorrelated), which is correct precisely because a correlation is
	// broken the moment EITHER half stops reproducing.
	if original.Source == models.SourceCorrelated {
		verifyCorrelated(ctx, original, opts, out)
		return
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

}

// OccurrenceResult is the verdict for one occurrence of a grouped finding.
type OccurrenceResult struct {
	Endpoint    string `json:"endpoint"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Status      Status `json:"status"`
	Reason      string `json:"reason,omitempty"`
}

// verifyUnits splits a grouped finding into one finding per occurrence (its
// listed occurrences, or for a report that predates them, its distinct
// affected endpoints). A finding with one location is returned as itself.
func verifyUnits(f *models.Finding) []*models.Finding {
	type loc struct{ endpoint, fingerprint string }
	var locs []loc
	seen := map[loc]bool{}
	for _, o := range f.Occurrences {
		l := loc{o.Endpoint, o.Fingerprint}
		if o.Endpoint != "" && !seen[l] {
			seen[l] = true
			locs = append(locs, l)
		}
	}
	// A correlated finding's affected endpoints are the two halves of ONE
	// correlated occurrence (the live URL and the source file), not several
	// occurrences; verifyCorrelated needs them together.
	if len(locs) == 0 && f.Source != models.SourceCorrelated {
		for _, ep := range f.AffectedEndpoints {
			l := loc{endpoint: ep}
			if ep != "" && !seen[l] {
				seen[l] = true
				locs = append(locs, l)
			}
		}
	}
	if len(locs) <= 1 {
		return []*models.Finding{f}
	}
	units := make([]*models.Finding, 0, len(locs))
	for _, l := range locs {
		u := *f
		u.Endpoint = l.endpoint
		u.AffectedEndpoints = nil
		u.Occurrences = nil
		if l.fingerprint != "" {
			u.Fingerprint = l.fingerprint
			u.Occurrences = []models.Occurrence{{Endpoint: l.endpoint, Fingerprint: l.fingerprint}}
		}
		if l.endpoint != f.Endpoint {
			// The evidence, line and proof were captured at the primary
			// location; another occurrence is located by its own endpoint.
			u.Evidence = ""
			u.TaintChain = nil
			u.Route = nil
			u.Line = nil
			if !strings.Contains(l.endpoint, " ") && !strings.HasPrefix(l.endpoint, "/") && !strings.Contains(l.endpoint, "://") {
				ep := l.endpoint
				u.Line = &ep
			}
		}
		units = append(units, &u)
	}
	return units
}

// verifyEach re-tests every occurrence and folds the verdicts: any
// still-present occurrence keeps the finding present; anything else is
// unknown. A group never folds to resolved: no occurrence can be resolved
// (D4 Option A), and a fold of resolved verdicts would claim a whole group gone
// from what was not seen.
func verifyEach(ctx context.Context, units []*models.Finding, opts Options, out *Result) {
	var present, unknown []string
	for _, u := range units {
		r := &Result{}
		verifyOne(ctx, u, opts, r)
		out.Occurrences = append(out.Occurrences, OccurrenceResult{
			Endpoint: u.Endpoint, Fingerprint: u.Fingerprint, Status: r.Status, Reason: r.Reason,
		})
		switch r.Status {
		case StatusStillPresent:
			present = append(present, u.Endpoint)
		case StatusResolved:
		default:
			unknown = append(unknown, u.Endpoint)
		}
	}
	switch {
	case len(present) > 0:
		out.Status = StatusStillPresent
		out.Reason = fmt.Sprintf("%d of %d occurrences still present: %s", len(present), len(units), strings.Join(present, ", "))
	case len(unknown) > 0:
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("%d of %d occurrences could not be re-tested (%s); the finding is not resolved until every occurrence is",
			len(unknown), len(units), strings.Join(unknown, ", "))
	default:
		// Every occurrence answered resolved. No verifier produces that any more
		// (D4 Option A: resolved is never derived from absence), so a fold that
		// reaches here is a defect elsewhere, and it fails closed.
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("all %d occurrences read resolved, which verify never answers (%s)", len(units), absenceNote)
	}
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

	// A versioned baseline (format v2, what `fendix scan --save-baseline`
	// writes now) is an object with `baseline_version` and no report
	// metadata, so it is recognised before ParseJSONReport, which would
	// reject it for lacking metadata.version / metadata.mode.
	if reporters.IsBaselineDocument(data) {
		doc, err := reporters.ParseBaselineDocument(data)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		return &reporters.JSONReport{Total: len(doc.Findings), Findings: doc.Findings}, nil
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
	for _, ext := range []string{".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".go", ".rb", ".java", ".php", ".env", ".yaml", ".yml", ".json"} {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	// .env.Production / .env.bak / .env.master — extensionless secret files.
	if strings.Contains(base, ".env") {
		return true
	}
	// A finding of the secrets scanner, which reads every text file (R-010): a
	// Dockerfile, a credentials file or a .properties file has no extension on
	// the list above but is a file the scanner anchors a finding to.
	if strings.HasPrefix(f.RuleID, "secrets/") && base != ep {
		return true
	}
	return false
}

// isSemgrepRuleFinding reports whether f came from a bundled Semgrep rule: its
// tier says so (semgrep_shim, or semgrep_taint once a language gate opens), or
// its rule id is a -taint / -sink rule of the JS/TS, Java or Go packs, which
// covers a baseline whose tier was not recorded.
func isSemgrepRuleFinding(f *models.Finding) bool {
	if f.SourceTier.IsSemgrep() {
		return true
	}
	id := f.RuleID
	packed := strings.HasPrefix(id, "js-") || strings.HasPrefix(id, "java-") || strings.HasPrefix(id, "go-")
	return packed && (strings.HasSuffix(id, "-taint") || strings.HasSuffix(id, "-sink"))
}

func semgrepRuleLabel(f *models.Finding) string {
	if f.RuleID != "" {
		return f.RuleID
	}
	return f.ID
}

func semgrepTierLabel(f *models.Finding) string {
	if f.SourceTier != "" {
		return "tier " + string(f.SourceTier)
	}
	return "tier not recorded"
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
	// A CORS finding exists because the server answered a request that carried
	// an attacker Origin (the scanner sends one). The re-test sends the same
	// header: a server that answers the wildcard only to a cross-origin request
	// is still vulnerable, and one request without an Origin cannot show it.
	if strings.Contains(strings.ToUpper(f.Title), "CORS") {
		req.Header.Set("Origin", corsProbeOrigin)
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
	switch state, evidence := checkURLFindingPresence(f, resp, body); state {
	case urlPresent:
		out.Status = StatusStillPresent
		out.Reason = evidence
	case urlAbsent:
		// What one response shows is an observation, not a remediation
		// (contract C8, D5-3): a header that is set now can come from another
		// route, a CDN or a different build, and only a credential the secrets
		// scanner found in source can be searched for in the whole tree. So the
		// answer is unknown, with what was observed.
		out.Status = StatusUnknown
		out.Reason = evidence + "; " + observationNote
	default:
		out.Status = StatusUnknown
		out.Reason = evidence
	}
}

// corsProbeOrigin is the attacker origin the CORS check (scanner/cors.go,
// evilOrigin) probes with.
const corsProbeOrigin = "https://evil.example.com"

// urlPresence is what one re-issued request shows about a URL-anchored finding.
type urlPresence int

const (
	// urlPresent: the finding's signal is still observable in the response.
	urlPresent urlPresence = iota
	// urlAbsent: the response carries the evidence that the signal is gone (a
	// header that is now set, a version string that is no longer disclosed).
	urlAbsent
	// urlInconclusive: the request shows nothing about the finding. An HTTP
	// status alone never resolves anything (contract C8): a 401, 403, 404 or 410
	// says the route changed, not that the vulnerability was fixed; and one
	// request cannot show that a rate limit exists or not.
	urlInconclusive
)

// checkURLFindingPresence classifies the response: the original finding's
// signal is still observable (urlPresent), the response shows it gone
// (urlAbsent, with what was observed) or the request cannot tell
// (urlInconclusive).
func checkURLFindingPresence(f *models.Finding, resp *http.Response, body []byte) (urlPresence, string) {
	title := f.Title
	headers := resp.Header

	switch {
	case strings.Contains(title, "Missing Content-Security-Policy"):
		if headers.Get("Content-Security-Policy") == "" {
			return urlPresent, "Content-Security-Policy header is still absent"
		}
		return urlAbsent, fmt.Sprintf("Content-Security-Policy now set: %s", truncate(headers.Get("Content-Security-Policy"), 80))

	case strings.Contains(title, "Missing Strict-Transport-Security"):
		if headers.Get("Strict-Transport-Security") == "" {
			return urlPresent, "Strict-Transport-Security header is still absent"
		}
		return urlAbsent, fmt.Sprintf("Strict-Transport-Security now set: %s", truncate(headers.Get("Strict-Transport-Security"), 80))

	case strings.Contains(title, "X-Content-Type-Options"):
		if !strings.EqualFold(headers.Get("X-Content-Type-Options"), "nosniff") {
			return urlPresent, fmt.Sprintf("X-Content-Type-Options still %q (expected 'nosniff')", headers.Get("X-Content-Type-Options"))
		}
		return urlAbsent, "X-Content-Type-Options: nosniff is now set"

	case strings.Contains(title, "X-Frame-Options"):
		if headers.Get("X-Frame-Options") == "" {
			return urlPresent, "X-Frame-Options header is still absent"
		}
		return urlAbsent, fmt.Sprintf("X-Frame-Options now set: %s", headers.Get("X-Frame-Options"))

	case strings.Contains(title, "CORS allows any origin"):
		if headers.Get("Access-Control-Allow-Origin") == "*" {
			return urlPresent, "Access-Control-Allow-Origin is still '*'"
		}
		return urlAbsent, fmt.Sprintf("Access-Control-Allow-Origin now %q", headers.Get("Access-Control-Allow-Origin"))

	case strings.Contains(title, "Server version disclosed"):
		serverHeader := headers.Get("Server")
		if serverHeader == "" {
			return urlAbsent, "Server header is no longer present"
		}
		// Detect a version-shaped substring (digits.digits)
		if containsVersionLike(serverHeader) {
			return urlPresent, fmt.Sprintf("Server header still discloses version: %q", serverHeader)
		}
		return urlAbsent, fmt.Sprintf("Server header no longer discloses version: %q", serverHeader)

	case strings.Contains(title, "No rate limiting detected"),
		strings.Contains(title, "No rate limiting observed"):
		// Best-effort: a single re-test request can't conclusively
		// determine rate-limiting. Report unknown so the user re-runs
		// a focused load test. (Phase 5.4 renamed the title to the
		// scoped "No rate limiting observed within N requests"; the old
		// literal is kept for findings persisted before that change.)
		return urlInconclusive, "rate-limit verification needs a full re-scan with multiple rapid requests; a single request cannot show that a rate limit exists, so this finding is kept as unconfirmed"

	case strings.Contains(title, "Missing authentication on endpoint"):
		// Re-test with no auth; if endpoint still 200s, finding holds.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return urlPresent, fmt.Sprintf("endpoint still returns %d to unauthenticated request", resp.StatusCode)
		}
		return urlInconclusive, fmt.Sprintf(
			"endpoint now returns %d to the unauthenticated request; a changed HTTP status alone is not proof of remediation "+
				"(an auth wall, a WAF, a moved route or a rate limiter answer the same), so this finding is kept as unconfirmed", resp.StatusCode)

	case strings.Contains(title, "Software version string in response"):
		// Naive but useful: re-scan the body for any version-shaped substring.
		if containsVersionLike(string(body)) {
			return urlPresent, "response body still contains a version-shaped string"
		}
		return urlAbsent, "response body no longer contains an obvious version string"

	default:
		// Generic fallback. A status that gates or removes the route is not
		// evidence about the finding (contract C8): it used to read as
		// "presumed gated or removed" and resolve.
		if isGatedStatus(resp.StatusCode) {
			return urlInconclusive, fmt.Sprintf("endpoint now returns %d; a changed HTTP status alone is not proof of remediation, and there is no per-title re-test for %q, so this finding is kept as unconfirmed", resp.StatusCode, f.Title)
		}
		return urlPresent, fmt.Sprintf("no per-title re-test for %q yet; endpoint still reachable (HTTP %d) — flagging as still-present conservatively", f.Title, resp.StatusCode)
	}
}

// verifyFile re-tests a file-anchored finding. Only the native secrets
// scanner's own findings get a verdict (verifySecret: no subprocess, fast);
// every other file-anchored finding is unknown and defers to a full re-scan.
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

	// A Semgrep rule's finding (the JS/TS, Java and Go packs, taint and sink
	// rules alike) is kept, with its own reason, rather than falling through
	// to the generic deferral below. It comes first: another scanner (the
	// secrets re-test below) never re-tests a Semgrep-tier finding.
	if isSemgrepRuleFinding(f) {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf(
			"%s is a Semgrep rule (%s); verify cannot re-run Semgrep against a single file, so this "+
				"finding is kept as unconfirmed rather than resolved. Re-run `fendix scan --code <path>` "+
				"and diff against the baseline for a verdict.",
			semgrepRuleLabel(f), semgrepTierLabel(f))
		return
	}

	if f.Category == "secrets" {
		verifySecret(ctx, f, opts, absFile, relPath, out)
		return
	}

	// AST-based SAST findings (category=injection / xss / etc.) need
	// the Python engine — defer.
	out.Status = StatusUnknown
	out.Reason = "AST-based SAST verify (injection/xss/path-traversal/...) requires --python-engine and a focused re-scan harness; not in MVP. Run `fendix scan --code <path> --python-engine` for the full re-eval."
}

// verifySecret re-tests a `secrets`-category finding (R-010, decision D5).
//
// Only the secrets scanner's own findings are re-tested, and only by that
// scanner. Other analyzers also file findings under category "secrets" —
// textscan's GO_HARDCODED_AWS_KEY, JS_HARDCODED_AWS_KEY and
// GO_WEAK_HASH_PASSWORD, the Python engine's PY_WEAK_CRYPTO_PASSWORD — with
// rules and titles the secrets scanner never emits. Re-testing one of those
// with the secrets scanner always came back empty, and verify called a live
// CRITICAL key "resolved" (exit 0) on unchanged code. Their verdict is now
// unknown (exit 2), because verify cannot re-run their analyzer on one file.
//
// For a secrets-scanner finding the re-test reads exactly the finding's file
// through secrets.RetestFile, which refuses to answer for a file it cannot
// read completely (a skipped path or binary type, a symlink, an unreadable or
// over-cap file). Before the answer can be anything but still-present, the whole
// --code root is searched for the credential ITSELF, identified by the redaction marker the
// baseline evidence carries ([REDACTED len=N sha256:...], the byte length and
// the first 4 bytes of the SHA-256 of the value): a rule stops matching as soon
// as the literal changes shape, the value does not (secrets.SearchValues).
// The search reads every file, whatever its name or extension, and finds the
// value as written, with adjacent string literals and line continuations
// joined, backslash escapes (\x \u \N{}) and %XX undone, HTML character
// references undone, as a list of character codes, as hex (with separators) and
// as base64 (two layers), written backwards, and inside compressed streams.
// The verdict is:
//
//   - still-present: the scanner reports the same rule (rule_id) in the same
//     file, at any line, or a value with the marker's length and digest is
//     found anywhere under --code in any of those forms; the reason names where.
//     A secret moved within the file, rotated in place to another literal of the
//     same kind, moved to another file of any kind, or written another way
//     (an environment lookup's default, a call argument, a concatenation) is
//     still present.
//   - never resolved (D4 Option A). The scanner read the whole file and reports
//     that rule there no more, AND the search read and decoded everything under
//     --code and found the value nowhere: the answer is unknown, and the reason
//     says what was searched and what was not (the root's own git history;
//     values built at run time) and closes with "not detected is not the same as
//     fixed". The list of forms the search decodes is not the list of ways to
//     write a value down, so absence from it proves nothing; likewise, when the
//     baseline evidence carries no marker (a non-primary occurrence of a group, a
//     signature-only rule, an older baseline) and a rule that matches the
//     credential's own token shape (secrets.IsProviderAnchoredRule) fires
//     nowhere under --code, the value was never searched for at all.
//   - unknown: everything else, including an incomplete re-test, content under
//     --code that could not be read or decoded (over the read cap, unreadable,
//     an opaque binary, an archive in a format that cannot be opened, a git
//     object store other than <root>/.git/objects), and a credential too long
//     to search for.
//
// One rule reported twice in a file keeps both findings present until both
// are gone: the re-test cannot tell which literal a finding was, so it errs
// towards still-present. A credential split over variables, case-changed,
// shifted, encrypted or otherwise built at run time is not found: that is stated
// in the reason, not hidden, and the reason of an unfound credential ends by
// saying that not detected is not fixed (contract C8).
// Content that could not be read or decoded (an opaque binary file, an archive
// in a format that cannot be opened, a \N{} name outside the ASCII table, a git
// object store other than <root>/.git/objects) makes the answer unknown, and the
// reason lists it.
func verifySecret(ctx context.Context, f *models.Finding, opts Options, absFile, relPath string, out *Result) {
	if why := notSecretsScannerFinding(f); why != "" {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf(
			"%s; verify re-tests a secrets finding only with the analyzer that produced it, and "+
				"cannot re-run that one against a single file, so this finding is kept as unconfirmed "+
				"rather than resolved. Re-run `fendix scan --code <path>` and diff against the baseline "+
				"for a verdict.",
			why)
		return
	}
	rootAbs, err := filepath.Abs(opts.CodePath)
	if err == nil {
		var fileAbs string
		if fileAbs, err = filepath.Abs(absFile); err == nil {
			var rel string
			if rel, err = filepath.Rel(rootAbs, fileAbs); err == nil {
				relPath = filepath.ToSlash(rel)
			}
		}
	}
	if err != nil {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf("cannot place %s inside --code %s: %v", secrets.SafeName(relPath), opts.CodePath, err)
		return
	}
	safeRel := secrets.SafeName(relPath)
	findings, retestErr := secrets.RetestFile(ctx, opts.CodePath, absFile)
	for _, nf := range findings {
		if nf.RuleID == f.RuleID && fileOfLineEndpoint(nf.Endpoint) == relPath {
			out.Status = StatusStillPresent
			out.Reason = fmt.Sprintf("secrets scanner still reports %s at %s", f.RuleID, safeEndpoint(nf.Endpoint))
			return
		}
	}

	// Not reported by the rule in its own file any more. Is the credential
	// itself anywhere under --code, in any text file, in any form?
	markers := secrets.Markers(f.Evidence)
	var search *secrets.SearchResult
	var searchErr error
	if len(markers) > 0 {
		search, searchErr = opts.searches.get(ctx, opts.CodePath, markers)
		if searchErr == nil && len(search.Hits) > 0 {
			out.Status = StatusStillPresent
			out.Reason = fmt.Sprintf(
				"the same credential (%s) is still committed: found at %s. "+
					"It is no longer reported by %s in %s, but moving or reshaping a secret does not remove it from the repository.",
				strings.Join(markers, ", "), listHits(search.Hits), f.RuleID, safeRel)
			return
		}
	}
	if retestErr != nil {
		// Not re-emitted, but the re-test did not read the whole file.
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf(
			"the secrets scanner could not re-test %s completely (%v), so verify will not call this "+
				"finding resolved. Re-run `fendix scan --code <path>` and diff against the baseline "+
				"for a verdict.",
			safeRel, retestErr)
		return
	}
	if len(markers) > 0 {
		switch {
		case searchErr != nil:
			out.Status = StatusUnknown
			out.Reason = fmt.Sprintf(
				"%s no longer reports %s in %s, but the rest of --code could not be searched for the "+
					"same credential (%v), so verify will not call this finding resolved.",
				"the secrets scanner", f.RuleID, safeRel, searchErr)
		case !search.Complete():
			out.Status = StatusUnknown
			out.Reason = fmt.Sprintf(
				"the secrets scanner no longer reports %s in %s, but the search for the same credential "+
					"could not read all of --code (%s), so verify will not call this finding resolved. "+
					"Searched: %d text files.",
				f.RuleID, safeRel, search.Coverage.LostDetail(240), search.Files)
		default:
			// The value search found nothing. The scanner itself is the other
			// witness: whatever it reports anywhere under --code for this
			// credential (its own value marker) is still present, however the
			// value search's candidates were chosen (redteam4-verify-01). Verify
			// must never call resolved a credential the scanner still reports.
			sightings, _, serr := opts.sightings.get(ctx, opts.CodePath)
			if serr != nil {
				out.Status = StatusUnknown
				out.Reason = fmt.Sprintf(
					"the credential (%s) was found nowhere by the value search, but the secrets scanner could not "+
						"be applied to the rest of --code to confirm it (%v), so verify will not call this finding resolved.",
					strings.Join(markers, ", "), serr)
				return
			}
			if hit := sightingWithMarker(sightings, markers); hit != nil {
				out.Status = StatusStillPresent
				out.Reason = fmt.Sprintf(
					"the secrets scanner still reports the same credential (%s) at %s (%s). It is no longer "+
						"reported by %s in %s, but moving or reshaping a secret does not remove it from the repository.",
					strings.Join(markers, ", "), safeEndpoint(hit.Endpoint), hit.RuleID, f.RuleID, safeRel)
				return
			}
			out.Status = StatusUnknown
			out.Reason = fmt.Sprintf(
				"secrets scanner re-read all of %s and no longer reports %s there, and the credential (%s) "+
					"was found nowhere: %s. "+absenceNote,
				safeRel, f.RuleID, strings.Join(markers, ", "), search.Scope())
		}
		return
	}

	// The baseline evidence does not identify the credential, so it cannot be
	// searched for. Only a rule that matches the credential's own token shape,
	// and fires nowhere under --code, shows it is gone.
	if !secrets.IsProviderAnchoredRule(f.RuleID) {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf(
			"the secrets scanner no longer reports %s in %s, but the baseline evidence carries no "+
				"redaction marker ([REDACTED len=N sha256:...]) identifying the credential, and %s matches "+
				"an assignment shape rather than the credential's own format, so verify cannot rule out "+
				"that the literal moved to a place the rule does not match. Re-run `fendix scan --code <path>` "+
				"and diff against the baseline for a verdict.",
			f.RuleID, safeRel, f.RuleID)
		return
	}
	sightings, sc, searchErr := opts.sightings.get(ctx, opts.CodePath)
	if searchErr != nil {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf(
			"the secrets scanner no longer reports %s in %s, but could not search the rest of --code for "+
				"the same credential (%v), so verify will not call this finding resolved.",
			f.RuleID, safeRel, searchErr)
		return
	}
	scopeText := sc.Text
	var same []secrets.Sighting
	for _, s := range sightings {
		if s.RuleID == f.RuleID {
			same = append(same, s)
		}
	}
	if len(same) > 0 {
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf(
			"the secrets scanner no longer reports %s in %s, but still reports it at %s, and the baseline "+
				"evidence carries no redaction marker identifying this credential, so verify cannot tell "+
				"whether that is this secret moved. Re-run `fendix scan --code <path>` and diff against "+
				"the baseline for a verdict.",
			f.RuleID, safeRel, listSightings(same))
		return
	}
	if !sc.Complete() {
		// With no value to search for, the rule is the only witness, and it did
		// not read binary files, archives or the directories a scan prunes: the
		// credential could be in any of them, in a form no rule matches.
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf(
			"the secrets scanner no longer reports %s in %s, and the baseline evidence carries no redaction "+
				"marker identifying the credential, so only the rule could show it gone; %s, so the credential "+
				"could be in what was not read. Re-run `fendix scan --code <path>` and diff against the baseline "+
				"for a verdict.",
			f.RuleID, safeRel, scopeText)
		return
	}
	out.Status = StatusUnknown
	out.Reason = fmt.Sprintf(
		"secrets scanner re-read all of %s and no longer reports %s there, and %s, which matches the "+
			"credential's own format, fires nowhere under --code (%s; the baseline evidence carries no "+
			"redaction marker to search for the credential itself). "+absenceNote,
		safeRel, f.RuleID, f.RuleID, scopeText)
}

// absenceNote closes the reason of a secrets finding whose credential was seen
// nowhere. That is as far as verify goes: D4 Option A, verify never answers
// resolved from absence. The ways to write a value down are open (encodings,
// archives, containers, a file name, history, a value built at run time), so
// not finding it in a list of forms cannot show it is gone.
const absenceNote = "Not detected is not the same as fixed: the ways a committed credential can be written down are open, " +
	"and verify cannot see the repository's history, an encrypted copy or a value built at run time, " +
	"so it answers unknown, never resolved. Rotate or revoke the credential, then re-run `fendix scan --code <path>` and diff against the baseline"

// sightingWithMarker returns a sighting whose redaction markers include one of
// the baseline's, or nil.
func sightingWithMarker(ss []secrets.Sighting, markers []string) *secrets.Sighting {
	want := map[string]bool{}
	for _, m := range markers {
		want[m] = true
	}
	for i := range ss {
		for _, m := range ss[i].Markers {
			if want[m] {
				return &ss[i]
			}
		}
	}
	return nil
}

// listHits renders up to five hits as "path:line (form)".
func listHits(hs []secrets.Hit) string {
	const max = 5
	parts := make([]string, 0, max+1)
	for i, h := range hs {
		if i == max {
			parts = append(parts, fmt.Sprintf("and %d more", len(hs)-max))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", h.Endpoint, h.Form))
	}
	return strings.Join(parts, ", ")
}

// listSightings renders up to five sightings as "path:line (rule)".
func listSightings(ss []secrets.Sighting) string {
	const max = 5
	parts := make([]string, 0, max+1)
	for i, s := range ss {
		if i == max {
			parts = append(parts, fmt.Sprintf("and %d more", len(ss)-max))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", safeEndpoint(s.Endpoint), s.RuleID))
	}
	return strings.Join(parts, ", ")
}

// notSecretsScannerFinding returns why f cannot be shown to come from the
// secrets scanner, or "" when it does. The scanner stamps rule_id
// "secrets/<PATTERN>", leaves source_tier empty and reports whitebox; a
// non-empty tier on such a finding means a member from another analyzer was
// merged into it (dedup keeps the most trusted tier).
func notSecretsScannerFinding(f *models.Finding) string {
	switch {
	case f.RuleID == "":
		return "the finding records no rule_id, so the analyzer that produced it is unknown"
	case !secrets.IsRuleID(f.RuleID):
		return fmt.Sprintf("%s (%s) was not produced by the secrets scanner", f.RuleID, semgrepTierLabel(f))
	case f.SourceTier != "":
		return fmt.Sprintf("%s carries %s, so another analyzer contributed to it", f.RuleID, semgrepTierLabel(f))
	case f.Source != models.SourceWhitebox:
		return fmt.Sprintf("%s has source %q, not the secrets scanner's whitebox", f.RuleID, f.Source)
	}
	return ""
}

// safeEndpoint makes a "path:line" endpoint safe to put in a reason: the path is
// sanitised and cut (secrets.SafeName), the line number kept.
func safeEndpoint(ep string) string {
	file := fileOfLineEndpoint(ep)
	return secrets.SafeName(file) + ep[len(file):]
}

// fileOfLineEndpoint strips a trailing ":<line>" from a "path:line" endpoint.
func fileOfLineEndpoint(ep string) string {
	if i := strings.LastIndex(ep, ":"); i > 0 {
		if _, err := stringToInt(ep[i+1:]); err == nil {
			return ep[:i]
		}
	}
	return ep
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
	// The dependency scanner's inventory not listing the vulnerability is an
	// observation of one manifest, not proof the vulnerable package is gone
	// from what runs (another manifest, a lockfile out of step, a transitive or
	// vendored copy). Nothing resolves (D4 Option A; C8, D5-3).
	out.Status = StatusUnknown
	out.Reason = fmt.Sprintf("dep scanner no longer flags this vulnerability at %s; %s", manifest, observationNote)
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
	// The categories the checks actually stamp (Check.Category()): the hyphenated
	// spellings above are kept for baselines written by older tooling.
	"redirect":      true,
	"host_header":   true,
	"method_tamper": true,
}

// isActiveProbeFinding reports whether f came from an active-tier probe: a
// blackbox finding in an active-probe category. The category alone decides: an
// earlier version also required the evidence to mention a payload, which let an
// active finding whose evidence reads "Open redirect confirmed: ..." fall into
// the generic per-title fallback, where a 404 reads as "presumed gated or
// removed" and the finding as resolved. Source must still be blackbox, so a
// whitebox taint finding in the same category is not misclassified.
func isActiveProbeFinding(f *models.Finding) bool {
	return f.Source == models.SourceBlackbox && activeProbeCategories[f.Category]
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
		// A gated or removed route is not proof that either half was fixed, for
		// any category (contract C8, C4B-11): the same status comes from an
		// auth wall, a WAF, a moved route or a rate limiter, and the whitebox
		// half (a committed credential, a taint path) is untouched by it. Until
		// a verification contract validated for the correlated shape exists, a
		// correlated finding is never resolved.
		out.Status = StatusUnknown
		out.Reason = fmt.Sprintf(
			"the blackbox endpoint now returns HTTP %d; a changed HTTP status alone is not proof of remediation "+
				"(it says the route changed, not that the code half was fixed), and verify never resolves a correlated finding "+
				"on a status", status)
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

// verifyActiveProbe re-tests an active-probe finding. It NEVER returns
// resolved, and returns still-present only when the recorded payload signal
// reproduces. Everything else is unknown, with a reason naming what was
// observed (decision 2026-11-12, amendment 1; contract C5.6).
//
// Why no resolved: an active-probe finding is closed on evidence that the
// probe was evaluated and the vulnerability is absent. A gated or removed
// endpoint (401/403/404/410) says the route changed, not that it was fixed (an
// auth wall, a WAF, a moved route or a rate limiter all produce the same
// status); a response without the reflected marker says one request did not
// reflect it. A probe-specific verification contract that has been
// independently validated may one day establish a result; none exists, so a
// result is unknown. This is the same rule as secrets-only resolution (D5).
//
//   - No consent (opts.EnableActive unset): a reachability observation only.
//     Re-sending the attack payload needs the same consent as the original
//     scan's --enable-active gate.
//   - Consent: re-hit the endpoint and look for the finding's signal (a
//     reflected payload marker). Present -> still-present, the one observation
//     that is evidence about the vulnerability itself.
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
		out.Reason = fmt.Sprintf("request to %s failed (the probe was not evaluated; a failed request proves nothing about the finding): %v", targetURL, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	const noContract = "no validated probe-specific verification contract exists"

	// Consent given: re-probe and look for the recorded signal first, so a
	// reproduced finding is reported whatever the status.
	if opts.EnableActive {
		if marker := probeMarker(f); marker != "" && strings.Contains(string(body), marker) {
			out.Status = StatusStillPresent
			out.Reason = fmt.Sprintf("re-probe reflected the recorded payload marker %q in the response (HTTP %d); the finding reproduces", truncate(marker, 40), resp.StatusCode)
			return
		}
	}

	out.Status = StatusUnknown
	switch {
	case isGatedStatus(resp.StatusCode):
		out.Reason = fmt.Sprintf("active-probe endpoint now returns HTTP %d; a reachability change is not proof of remediation (%s)", resp.StatusCode, noContract)
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusBadGateway ||
		resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout:
		out.Reason = fmt.Sprintf("active-probe endpoint returned HTTP %d, a rate limit or temporary failure; the probe was not evaluated and proves nothing about the finding", resp.StatusCode)
	case !opts.EnableActive:
		out.Reason = fmt.Sprintf(
			"active-probe endpoint is reachable (HTTP %d). This is a reachability observation only, not a re-test: re-sending the "+
				"attack payload needs explicit consent, so re-run with --enable-active (mirroring the original scan). Even then %s, "+
				"so a response without the signal is reported unknown, never resolved.", resp.StatusCode, noContract)
	default:
		out.Reason = fmt.Sprintf("re-probe (HTTP %d) did not reproduce the recorded payload signal; one response without it is not proof of remediation (%s). Re-run a full --enable-active scan for the evaluated result",
			resp.StatusCode, noContract)
	}
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
