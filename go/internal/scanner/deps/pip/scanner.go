// Package pip queries the OSV.dev /v1/query API to find vulnerabilities in
// Python dependencies declared in requirements.txt manifests. It provides
// behavioural parity with pip-audit (same advisory sources, same finding
// shape) but does NOT shell out to pip-audit by default.
//
// Users who require an actual pip-audit invocation (for reproducibility
// in environments that audit subprocess calls, or to pick up pip-audit-
// specific patches ahead of OSV.dev's index) can pass --use-pip-audit
// to fendix scan. When set, the scanner runs `pip-audit --format json -r
// <manifest>` for every manifest discovered by findRequirementsManifests
// and converts the output to []models.Finding using the same shape as
// the native OSV.dev path. If pip-audit is not on PATH, a warning is
// logged to stderr and the OSV.dev path is used as fallback — never
// fails-closed silently.
//
// Limitations (unchanged from existing implementation):
//   - Only pinned `==` versions are checked. Range specifiers
//     (`>=`, `~=`, `>`) are skipped with a stderr warning.
//   - No transitive resolution. Direct deps only.
//
// Cache (OSV.dev path only):
//
//	~/.fendix/cache/osv-pypi/<package>@<version>.json with a 24h TTL.
package pip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/Abdel-RahmanSaied/Fendix/internal/evidence"
	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/offline"
	"github.com/Abdel-RahmanSaied/Fendix/internal/scanner/deps/applicability"
)

// ErrNoRequirements is returned by Scan when codePath has no
// requirements.txt at its root. Callers use this to skip silently.
var ErrNoRequirements = errors.New("pip: no requirements.txt at path root")

// ErrNoManifests is returned by the recursive scan when no Python
// manifest (requirements.txt, Pipfile.lock, poetry.lock, pyproject.toml)
// was found anywhere under codePath. Placeholder here — Task 3 wires it
// into the recursive walk; for now recordDepScanResult's errors.Is check
// against it simply never matches.
var ErrNoManifests = errors.New("pip: no Python manifest under code path")

// DefaultRecurseDepth bounds how many directory levels ScanRecursive
// walks looking for nested requirements.txt manifests. 3 is enough to
// catch multi-service repos (service/requirements.txt or
// services/foo/requirements.txt) without descending into vendored deps
// (node_modules/, .venv/, site-packages/) — those are explicitly
// excluded by name regardless of depth.
const DefaultRecurseDepth = 3

// recurseSkipDirs are directory basenames ScanRecursive never enters.
// They're either vendored deps (whose own requirements.txt files belong
// to upstream packages, not this project) or scratch dirs not worth
// audit. Match-by-basename so a project that itself names a dir "tests"
// is unaffected — we only skip exact-name matches at any depth.
var recurseSkipDirs = map[string]bool{
	".git":          true,
	".venv":         true,
	"venv":          true,
	"node_modules":  true,
	"site-packages": true,
	"__pycache__":   true,
	".tox":          true,
	".mypy_cache":   true,
	".pytest_cache": true,
	"build":         true,
	"dist":          true,
}

// osvAPIBase is the OSV.dev REST endpoint. Var-not-const so tests can
// point it at an httptest server.
var osvAPIBase = "https://api.osv.dev"

// SetOSVAPIBaseForTest replaces the OSV.dev endpoint with a test URL
// and returns a restore function. Exported (with `ForTest` suffix
// to make the intent visible at call sites) so cross-package tests
// (e.g. the orchestrator continue-on-error path in
// internal/engine) can drive failure injection without an
// in-package test seam.
//
// Production code MUST NOT call this; calling it permanently rebases
// every OSV.dev query at the new URL for the current process.
func SetOSVAPIBaseForTest(url string) (restore func()) {
	prev := osvAPIBase
	osvAPIBase = url
	return func() { osvAPIBase = prev }
}

// cacheTTL is how long an OSV response is considered fresh. 24h matches
// pip-audit's default cache lifetime.
//
// Staleness window, stated plainly because it is a real limitation of
// every finding this scanner emits: an advisory PUBLISHED in the last 24h
// is not seen until the entry for that exact (package, version) expires,
// and an advisory WITHDRAWN in the last 24h keeps being reported. There is
// no cache-bust flag — delete ~/.fendix/cache/osv-pypi/ to force a
// refresh. Entries are shape-versioned as well as time-bounded; see
// cacheSchema.
const cacheTTL = 24 * time.Hour

// httpTimeout bounds a single OSV.dev request. The /v1/query endpoint
// is fast (<1s typical) — 15s is enough headroom for a slow link
// without holding a scan hostage.
const httpTimeout = 15 * time.Second

// osvBatchMaxSize is OSV.dev's documented max batch size for
// /v1/querybatch (https://google.github.io/osv.dev/post-v1-querybatch/).
const osvBatchMaxSize = 100

// osvMaxConcurrentBatches caps how many /v1/querybatch requests are in
// flight simultaneously. Conservative for OSV.dev's undocumented
// ~10 req/s per-IP rate limit — at 4 concurrent batches of up to 100
// packages each, a 200-dep monorepo finishes in 2 batches with
// effectively zero rate-limit risk. Benchmark before bumping.
const osvMaxConcurrentBatches = 4

// Scan reads requirements.txt at codePath and returns one Finding per
// (package, version, OSV-id) tuple. ErrNoRequirements signals "not a
// Python project" — callers should errors.Is-check it and skip.
//
// Network errors against api.osv.dev bubble up as wrapped errors —
// the orchestrator logs + continues; the Python deps.py path provides
// fallback coverage until Phase 17b removes it.
func Scan(ctx context.Context, codePath string) ([]evidence.Evidence, error) {
	abs, err := filepath.Abs(codePath)
	if err != nil {
		return nil, fmt.Errorf("pip: resolve path: %w", err)
	}
	reqFile := filepath.Join(abs, "requirements.txt")
	if _, err := os.Stat(reqFile); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoRequirements
		}
		return nil, fmt.Errorf("pip: stat requirements.txt: %w", err)
	}

	content, err := os.ReadFile(reqFile)
	if err != nil {
		return nil, fmt.Errorf("pip: read requirements.txt: %w", err)
	}
	pkgs := parseRequirements(string(content))
	if len(pkgs) == 0 {
		return nil, nil
	}

	client := &http.Client{Timeout: httpTimeout}
	cache, _ := cacheDir() // empty string disables caching — Scan still works

	findings := make([]evidence.Evidence, 0)
	for _, p := range pkgs {
		vulns, err := queryOSV(ctx, client, cache, p.name, p.version)
		if err != nil {
			// Per-package failure shouldn't sink the whole scan. Log
			// to stderr and move on — pip-audit has the same posture.
			fmt.Fprintf(os.Stderr, "[fendix] pip: query %s==%s failed: %v\n", p.name, p.version, err)
			continue
		}
		findings = append(findings, buildFindings(p, vulns, "requirements.txt")...)
	}
	findings = applicability.Resolve(abs, findings)
	sortFindingsByID(findings)
	return findings, nil
}

// Options controls runtime behaviour of ScanRecursiveWithOptions. The
// zero value uses the native OSV.dev client (current default).
type Options struct {
	// UsePipAudit, when true, shells out to `pip-audit --format json`
	// for every discovered manifest instead of querying OSV.dev directly.
	// If pip-audit is not on PATH, a warning is emitted and the OSV.dev
	// path is used as fallback (never fails-closed silently).
	UsePipAudit bool
}

// ScanRecursive walks `codePath` up to `maxDepth` levels deep looking
// for every `requirements.txt` and scans them all. The returned findings
// carry a relative-path manifest stamp ("service/requirements.txt") so
// users can tell which manifest each CVE came from in multi-service
// monorepos.
//
// Surfaced as a UX gap by the Track 4 heavy-eval on TwiScope-backend:
// the root scan returned zero dep-CVEs because `requirements.txt` lived
// at `Twiscope_Main_App/requirements.txt`, not the scan root. Re-running
// against the subdir surfaced 7 cryptography CVEs that had been
// silently invisible.
//
// `maxDepth=0` means "current directory only" (equivalent to Scan).
// `maxDepth=1` means "current directory + immediate children", etc.
//
// Returns the empty slice (not ErrNoRequirements) when the walk finds
// no manifests at any depth — that's a "checked everywhere, nothing to
// scan" state distinct from a single-level miss. Caller can decide
// whether to log or skip.
//
// Dedups by absolute path so a symlink loop can't double-count, and
// scans manifests in alphabetical path order for stable output.
//
// Preserved as a thin wrapper around ScanRecursiveWithOptions for
// backward compat. Callers that want the new flag use the With-Options
// variant.
func ScanRecursive(ctx context.Context, codePath string, maxDepth int) ([]evidence.Evidence, error) {
	return ScanRecursiveWithOptions(ctx, codePath, maxDepth, Options{})
}

// ScanRecursiveWithOptions is the explicit-options variant of
// ScanRecursive. When opts.UsePipAudit is true and pip-audit is on PATH,
// the scanner shells out to it; otherwise it falls back to the native
// OSV.dev /v1/query client. The fallback emits a stderr warning so the
// caller knows their flag was honoured at "best effort" only.
func ScanRecursiveWithOptions(ctx context.Context, codePath string, maxDepth int, opts Options) ([]evidence.Evidence, error) {
	if opts.UsePipAudit {
		if path, err := exec.LookPath("pip-audit"); err == nil {
			return scanViaSubprocess(ctx, codePath, maxDepth, path)
		}
		fmt.Fprintln(os.Stderr, "[fendix] pip: --use-pip-audit set but pip-audit not found on PATH; falling back to OSV.dev client")
		// intentional fallthrough to OSV.dev path
	}
	return scanViaOSV(ctx, codePath, maxDepth)
}

// ScanOffline scans every requirements.txt under codePath (recursing up
// to maxDepth) against the in-memory offline snapshot instead of
// osv.dev. It makes ZERO network calls — the air-gapped dep-CVE path
// (F-M4/F-H4). Findings carry the identical shape to the online path
// (same SEC-DEPS-<id> IDs, Title/Fix/References) so dedup, correlation,
// and the reporters cannot tell the two apart.
//
// Returns the empty slice (not ErrNoRequirements) when the walk finds
// no manifests, matching scanViaOSV's "checked everywhere, nothing to
// scan" contract.
func ScanOffline(codePath string, maxDepth int, snap *offline.Snapshot) ([]evidence.Evidence, error) {
	if snap == nil {
		return nil, errors.New("pip: offline snapshot is nil")
	}
	if maxDepth < 0 {
		maxDepth = 0
	}
	abs, err := filepath.Abs(codePath)
	if err != nil {
		return nil, fmt.Errorf("pip: resolve path: %w", err)
	}
	manifests, err := findRequirementsManifests(abs, maxDepth)
	if err != nil {
		return nil, fmt.Errorf("pip: walk for requirements.txt: %w", err)
	}
	if len(manifests) == 0 {
		return []evidence.Evidence{}, nil
	}

	var findings []evidence.Evidence
	for _, m := range manifests {
		content, err := os.ReadFile(m)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[fendix] pip: read %s failed: %v\n", m, err)
			continue
		}
		pkgs := parseManifest(m, string(content))
		if len(pkgs) == 0 {
			continue
		}
		rel, _ := filepath.Rel(abs, m)
		if rel == "" {
			rel = filepath.Base(m)
		}
		for _, p := range pkgs {
			advisories := snap.LookupVulnerable("PyPI", p.name, p.version)
			if len(advisories) == 0 {
				continue
			}
			// Collect the whole per-package advisory set BEFORE building, so
			// alias-connected snapshot advisories merge exactly the way the
			// online path's do. Emitting inside this loop would give the
			// air-gapped path a different finding COUNT from the online one
			// for identical data.
			vulns := make([]osvVuln, 0, len(advisories))
			for _, a := range advisories {
				vulns = append(vulns, advisoryToOSV(a))
			}
			findings = append(findings, buildFindings(p, vulns, rel)...)
		}
	}
	findings = applicability.Resolve(abs, findings)
	sortFindingsByID(findings)
	return findings, nil
}

// advisoryToOSV adapts an offline snapshot Advisory to the osvVuln shape
// buildFinding consumes, so the offline path reuses the exact online
// finding constructor (one source of truth for the finding shape).
func advisoryToOSV(a offline.Advisory) osvVuln {
	v := osvVuln{
		ID:      a.ID,
		Summary: a.Summary,
		Aliases: a.Aliases,
	}
	if fix := a.FirstFixedVersion(); fix != "" {
		// Stamp the type explicitly rather than leaning on usableRange's
		// empty-means-ECOSYSTEM allowance: a snapshot fix IS an ecosystem
		// version, and saying so keeps the GIT filter from ever having to
		// guess about a synthesised range.
		v.Affected = []osvAffected{{Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: fix}}}}}}
	}
	return v
}

// scanViaOSV scans every requirements.txt manifest under codePath
// (recursing up to maxDepth levels), batching OSV.dev queries across
// packages. Cache hits are processed first; cache misses are chunked
// into osvBatchMaxSize-sized batches with up to osvMaxConcurrentBatches
// in flight at once.
//
// If /v1/querybatch returns a non-2xx, the affected chunk falls back to
// the per-package /v1/query path with a logged warning. Per-batch
// failures don't sink the whole scan.
//
// /v1/querybatch answers with bare vuln IDs — no aliases, summary or
// affected ranges. Since FIX-05, runBatchOrFallback hydrates any package
// the batch reported as vulnerable through the per-package /v1/query, so
// the batch path is a throughput optimisation over the package SET rather
// than a downgrade of the records themselves.
func scanViaOSV(ctx context.Context, codePath string, maxDepth int) ([]evidence.Evidence, error) {
	if maxDepth < 0 {
		maxDepth = 0
	}
	abs, err := filepath.Abs(codePath)
	if err != nil {
		return nil, fmt.Errorf("pip: resolve path: %w", err)
	}
	manifests, err := findRequirementsManifests(abs, maxDepth)
	if err != nil {
		return nil, fmt.Errorf("pip: walk for requirements.txt: %w", err)
	}
	if len(manifests) == 0 {
		return []evidence.Evidence{}, nil
	}

	// Phase 1: collect all (package, manifest-rel-path) pairs across
	// every discovered manifest. The same package can appear in multiple
	// manifests in a multi-service repo; we keep the manifest stamp on
	// each pair so each finding's Endpoint correctly attributes ownership.
	var allPairs []pkgWithManifest
	for _, m := range manifests {
		content, err := os.ReadFile(m)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[fendix] pip: read %s failed: %v\n", m, err)
			continue
		}
		pkgs := parseManifest(m, string(content))
		if len(pkgs) == 0 {
			continue
		}
		rel, _ := filepath.Rel(abs, m)
		if rel == "" {
			rel = filepath.Base(m)
		}
		for _, p := range pkgs {
			allPairs = append(allPairs, pkgWithManifest{pkg: p, manifest: rel})
		}
	}
	if len(allPairs) == 0 {
		return []evidence.Evidence{}, nil
	}

	client := &http.Client{Timeout: httpTimeout}
	cache, _ := cacheDir()

	// Phase 2: cache lookup. Anything fresh in cache produces findings
	// now; misses go into the batch queue. Note we look up per-pair (not
	// per-package), so the same package present in two manifests gets
	// the cache hit applied to both manifests' findings.
	var findings []evidence.Evidence
	var misses []pkgWithManifest
	for _, p := range allPairs {
		if vulns, ok := readCache(cache, p.pkg.name, p.pkg.version); ok {
			findings = append(findings, buildFindings(p.pkg, vulns, p.manifest)...)
			continue
		}
		misses = append(misses, p)
	}

	// Phase 3: batch the misses. Chunk into osvBatchMaxSize-sized
	// groups, run up to osvMaxConcurrentBatches concurrently. The
	// semaphore + waitgroup pattern keeps backpressure on OSV.dev's
	// rate limiter while still parallelising across chunks.
	if len(misses) > 0 {
		sem := semaphore.NewWeighted(osvMaxConcurrentBatches)
		var batchMu sync.Mutex
		batchFindings := make([]evidence.Evidence, 0)
		var wg sync.WaitGroup
		for start := 0; start < len(misses); start += osvBatchMaxSize {
			end := start + osvBatchMaxSize
			if end > len(misses) {
				end = len(misses)
			}
			chunk := misses[start:end]
			if err := sem.Acquire(ctx, 1); err != nil {
				// Context cancellation surfaces here; bail with whatever
				// we've already gathered (cache hits + completed batches).
				wg.Wait()
				batchMu.Lock()
				findings = append(findings, batchFindings...)
				batchMu.Unlock()
				sortFindingsByID(findings)
				return findings, fmt.Errorf("pip: acquire batch slot: %w", err)
			}
			wg.Add(1)
			go func(chunk []pkgWithManifest) {
				defer wg.Done()
				defer sem.Release(1)
				chunkFindings := runBatchOrFallback(ctx, client, cache, chunk)
				batchMu.Lock()
				batchFindings = append(batchFindings, chunkFindings...)
				batchMu.Unlock()
			}(chunk)
		}
		wg.Wait()
		findings = append(findings, batchFindings...)
	}

	// Deliberately NOT applied on the sem.Acquire cancellation path above:
	// that branch is unwinding a cancelled scan and must not start a tree
	// walk.
	findings = applicability.Resolve(abs, findings)
	sortFindingsByID(findings)
	return findings, nil
}

// runBatchOrFallback tries /v1/querybatch for a single chunk; on any
// batch-level failure (non-2xx, length mismatch, transport error) it
// falls back to the per-package /v1/query path so individual findings
// still surface. Cache writes happen on both paths.
func runBatchOrFallback(ctx context.Context, client *http.Client, cache string, chunk []pkgWithManifest) []evidence.Evidence {
	pkgs := make([]pinnedPackage, len(chunk))
	for i, p := range chunk {
		pkgs[i] = p.pkg
	}
	results, err := queryOSVBatch(ctx, client, pkgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fendix] pip: querybatch failed (%v); falling back to per-package /v1/query for %d packages\n", err, len(chunk))
		return runSerialFallback(ctx, client, cache, chunk)
	}
	var findings []evidence.Evidence
	for _, p := range chunk {
		key := p.pkg.name + "@" + p.pkg.version
		vulns := results[key]
		if len(vulns) == 0 {
			// Cache the batch result even when empty — that's a valid
			// "no known vulns" answer worth caching for 24h.
			writeCache(cache, p.pkg.name, p.pkg.version, vulns)
			findings = append(findings, buildFindings(p.pkg, vulns, p.manifest)...)
			continue
		}
		// /v1/querybatch answers with bare {id}s — no Summary, no Details,
		// no Aliases and no Affected. That is the DEFAULT path, so leaving
		// it alone would ship FIX-05 (which merges on aliases) and FIX-06
		// (which reads ranges) as dead code on the route that actually
		// runs, and would keep printing "no fix listed in OSV" for
		// advisories that list one.
		//
		// Hydrate per PACKAGE, not per vuln: one /v1/query gets every
		// record for this (package, version) fully populated. cryptography
		// costs ONE extra request, not six. A 200-dep repo with 5
		// vulnerable packages goes from 2 requests to 7, against 200 for
		// full-serial. This runs inside the per-chunk goroutine, under the
		// osvMaxConcurrentBatches semaphore, so worst-case in-flight serial
		// requests stays at 4 — do not parallelise it within a chunk.
		full, err := queryOSV(ctx, client, cache, p.pkg.name, p.pkg.version)
		if err != nil {
			// Rule 3: never drop the finding. Emit the degraded batch
			// record, and deliberately do NOT cache it — a poisoned entry
			// would serve alias-less, fix-less records to every path
			// (including the serial one) for the full 24h TTL.
			fmt.Fprintf(os.Stderr,
				"[fendix] pip: alias/fix hydration for %s==%s failed (%v); emitting the degraded batch record\n",
				p.pkg.name, p.pkg.version, err)
		} else {
			vulns = full
		}
		findings = append(findings, buildFindings(p.pkg, vulns, p.manifest)...)
	}
	return findings
}

// runSerialFallback walks the chunk one package at a time using the
// classic /v1/query endpoint. Used when /v1/querybatch fails so any
// transient batch-only outage doesn't hide CVE coverage.
func runSerialFallback(ctx context.Context, client *http.Client, cache string, chunk []pkgWithManifest) []evidence.Evidence {
	var findings []evidence.Evidence
	for _, p := range chunk {
		vulns, err := queryOSV(ctx, client, cache, p.pkg.name, p.pkg.version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[fendix] pip: query %s==%s failed: %v\n", p.pkg.name, p.pkg.version, err)
			continue
		}
		findings = append(findings, buildFindings(p.pkg, vulns, p.manifest)...)
	}
	return findings
}

// queryOSVBatch sends one /v1/querybatch request with up to
// osvBatchMaxSize packages. Returns map[<pkg>@<version>]vulns so
// callers can correlate responses back to their request packages.
//
// The response shape carries vuln IDs ONLY — no aliases, no summary, no
// affected ranges. That is a property of the endpoint, not a decision
// made here, and it is why runBatchOrFallback re-fetches every package
// this reports as vulnerable through /v1/query before building findings:
// alias merging (FIX-05) and fix-version ranking (FIX-06) both need the
// full record, and a bare id also renders as an empty description.
//
// Hydration is per PACKAGE rather than per vuln, so the cost is one extra
// request per VULNERABLE package — 1 for cryptography's six records, not
// 6 — and clean packages cost nothing beyond their share of the batch.
func queryOSVBatch(ctx context.Context, client *http.Client, pkgs []pinnedPackage) (map[string][]osvVuln, error) {
	if len(pkgs) == 0 {
		return map[string][]osvVuln{}, nil
	}
	if len(pkgs) > osvBatchMaxSize {
		return nil, fmt.Errorf("batch size %d exceeds OSV.dev limit of %d — caller must chunk", len(pkgs), osvBatchMaxSize)
	}
	type batchQuery struct {
		Package osvPackage `json:"package"`
		Version string     `json:"version"`
	}
	type batchRequest struct {
		Queries []batchQuery `json:"queries"`
	}
	type batchResultEntry struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}
	type batchResponse struct {
		Results []batchResultEntry `json:"results"`
	}

	reqBody := batchRequest{Queries: make([]batchQuery, len(pkgs))}
	for i, p := range pkgs {
		reqBody.Queries[i] = batchQuery{
			Package: osvPackage{Ecosystem: "PyPI", Name: p.name},
			Version: p.version,
		}
	}
	body, err := json.Marshal(&reqBody)
	if err != nil {
		return nil, fmt.Errorf("encode batch request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvAPIBase+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build batch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post batch to %s: %w", osvAPIBase, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("osv batch returned %d: %s", resp.StatusCode, snippet)
	}
	var parsed batchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode batch response: %w", err)
	}
	if len(parsed.Results) != len(pkgs) {
		return nil, fmt.Errorf("osv batch response length mismatch: %d results for %d packages", len(parsed.Results), len(pkgs))
	}

	out := make(map[string][]osvVuln, len(pkgs))
	for i, entry := range parsed.Results {
		if len(entry.Vulns) == 0 {
			continue
		}
		vulns := make([]osvVuln, 0, len(entry.Vulns))
		for _, v := range entry.Vulns {
			// Bare id only — everything else the finding needs comes from
			// runBatchOrFallback's per-package hydration.
			vulns = append(vulns, osvVuln{ID: v.ID})
		}
		out[pkgs[i].name+"@"+pkgs[i].version] = vulns
	}
	return out, nil
}

// scanViaSubprocess runs `pip-audit --format json -r <manifest>` for every
// requirements.txt manifest discovered under codePath up to maxDepth levels.
// Stamps the relative manifest path on each finding's Endpoint so users can
// tell which service owns each CVE (parity with scanViaOSV).
//
// pip-audit's JSON output shape (--format json):
//
//	{
//	  "dependencies": [
//	    {"name": "...", "version": "...", "vulns": [{"id": "...", "fix_versions": [...], "description": "..."}, ...]},
//	    ...
//	  ]
//	}
//
// We map pip-audit's vuln IDs (which are OSV IDs) into the SEC-DEPS-<id>
// shape used by scanViaOSV's buildFinding. Title/severity/fix shape is
// identical to the OSV.dev path so downstream dedup, correlator, and
// reporters cannot tell the two paths apart.
//
// pip-audit's JSON shape has changed twice in 2024. This implementation
// targets pip-audit >= 2.7.0 schema. Older versions: parsing returns an
// error with a clear "upgrade pip-audit" hint.
//
// The scan-budget context is inherited verbatim — pip-audit invocations
// honour the same wall-clock cap the orchestrator passes to the package.
func scanViaSubprocess(ctx context.Context, codePath string, maxDepth int, pipAuditPath string) ([]evidence.Evidence, error) {
	if maxDepth < 0 {
		maxDepth = 0
	}
	abs, err := filepath.Abs(codePath)
	if err != nil {
		return nil, fmt.Errorf("pip: resolve path: %w", err)
	}
	manifests, err := findRequirementsManifests(abs, maxDepth)
	if err != nil {
		return nil, fmt.Errorf("pip: walk for requirements.txt: %w", err)
	}
	if len(manifests) == 0 {
		return []evidence.Evidence{}, nil
	}
	var all []evidence.Evidence
	for _, m := range manifests {
		rel, _ := filepath.Rel(abs, m)
		if rel == "" {
			rel = "requirements.txt"
		}
		cmd := exec.CommandContext(ctx, pipAuditPath, "--format", "json", "-r", m)
		out, err := cmd.Output()
		if err != nil {
			// pip-audit exits 1 when findings exist. Distinguish:
			// exit-1 + JSON output = expected; other exits = failure
			// (log + continue, don't sink the whole scan).
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 && len(out) > 0 {
				// findings exist; proceed to parse
			} else {
				fmt.Fprintf(os.Stderr, "[fendix] pip: pip-audit failed on %s: %v\n", m, err)
				continue
			}
		}
		findings, perr := parsePipAuditJSON(out, rel)
		if perr != nil {
			return nil, fmt.Errorf("pip: parse pip-audit output for %s: %w (run with --verbose for stderr)", rel, perr)
		}
		all = append(all, findings...)
	}
	all = applicability.Resolve(abs, all)
	sortFindingsByID(all)
	return all, nil
}

// parsePipAuditJSON maps pip-audit's --format json output to []models.Finding.
// Targets pip-audit >= 2.7.0 schema. Returns a clear error on older schemas
// or any malformed JSON.
func parsePipAuditJSON(jsonBytes []byte, manifestRelPath string) ([]evidence.Evidence, error) {
	var report struct {
		Dependencies []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Vulns   []struct {
				ID          string   `json:"id"`
				FixVersions []string `json:"fix_versions"`
				Description string   `json:"description"`
				Aliases     []string `json:"aliases"`
			} `json:"vulns"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(jsonBytes, &report); err != nil {
		return nil, fmt.Errorf("decode pip-audit JSON (expected schema from pip-audit >= 2.7.0; upgrade with `pip install -U pip-audit`): %w", err)
	}
	var findings []evidence.Evidence
	for _, d := range report.Dependencies {
		if len(d.Vulns) == 0 {
			continue
		}
		// pip-audit DOES carry aliases (decoded above), so this path needs
		// the alias merge just as much as /v1/query does — it is not a
		// batch-shaped, alias-less path. Collect the dependency's whole
		// vuln set first, then emit once.
		vulns := make([]osvVuln, 0, len(d.Vulns))
		for _, v := range d.Vulns {
			// Convert pip-audit's vuln record to the same osvVuln shape the
			// OSV.dev path uses, so both routes share one finding
			// constructor and cannot drift.
			osv := osvVuln{
				ID:      v.ID,
				Summary: v.Description,
				Aliases: v.Aliases,
			}
			// pip-audit returns fix_versions as a list; preserve the first.
			if len(v.FixVersions) > 0 {
				osv.Affected = []osvAffected{{
					Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: v.FixVersions[0]}}}},
				}}
			}
			vulns = append(vulns, osv)
		}
		findings = append(findings, buildFindings(
			pinnedPackage{name: d.Name, version: d.Version},
			vulns,
			manifestRelPath,
		)...)
	}
	return findings, nil
}

// findRequirementsManifests returns absolute paths to every
// `requirements.txt` under `root` up to `maxDepth` levels deep. Depth
// 0 is `root` itself; depth 1 includes its immediate children, etc.
// Directories named in `recurseSkipDirs` are pruned regardless of depth.
//
// Output is sorted by path for deterministic scan order.
func findRequirementsManifests(root string, maxDepth int) ([]string, error) {
	var manifests []string
	rootDepth := strings.Count(filepath.ToSlash(root), "/")

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Permission-denied on a subdir shouldn't sink the whole walk.
			return nil
		}
		if d.IsDir() {
			if path != root && recurseSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			// Depth check
			depth := strings.Count(filepath.ToSlash(path), "/") - rootDepth
			if depth > maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if isPythonManifest(d.Name()) {
			manifests = append(manifests, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(manifests)
	return manifests, nil
}

// isPythonManifest reports whether a filename is a Python dependency
// manifest the pip scanner knows how to parse. requirements.txt carries
// direct (==-pinned) deps; poetry.lock and Pipfile.lock carry the fully
// resolved transitive closure (90-day cut, item 3 — "locks ARE the
// transitive closure"). All three resolve to PyPI packages, so they share
// the downstream OSV batch/cache/offline machinery unchanged.
func isPythonManifest(name string) bool {
	switch name {
	case "requirements.txt", "poetry.lock", "Pipfile.lock":
		return true
	}
	return false
}

// parseManifest dispatches to the right parser by the manifest's base name.
// All parsers return the same pinnedPackage slice so the OSV query path is
// identical regardless of source format.
func parseManifest(path, content string) []pinnedPackage {
	switch filepath.Base(path) {
	case "poetry.lock":
		return parsePoetryLock(content)
	case "Pipfile.lock":
		return parsePipfileLock(content)
	default: // requirements.txt
		return parseRequirements(content)
	}
}

// pinnedPackage is one `==`-pinned line from requirements.txt.
type pinnedPackage struct {
	name    string
	version string
}

// pkgWithManifest carries the relative path of the manifest a package
// was discovered in. Sprint 02's batch path needs this stamp because
// the same package can appear in multiple manifests in a multi-service
// repo, and each finding must attribute ownership correctly via
// Finding.Endpoint.
type pkgWithManifest struct {
	pkg      pinnedPackage
	manifest string
}

// parseRequirements walks requirements.txt and yields only `==`-pinned
// entries. Comments (#), blank lines, and non-pinned specifiers are
// skipped — pip-audit refuses to scan unpinned deps for the same reason
// (the resolved version is environment-dependent).
//
// Hash specifiers (--hash=sha256:...) are stripped; extras
// (`package[extra]==1.0`) are stripped from the name; environment
// markers (`; python_version > "3.8"`) are stripped from the line.
func parseRequirements(content string) []pinnedPackage {
	var out []pinnedPackage
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip environment marker and trailing hash specifiers.
		if i := strings.Index(line, ";"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, " --hash="); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Drop continuation backslashes — pip allows wrapping a
		// hash-laden line but we already cut at the first --hash=.
		line = strings.TrimRight(line, "\\")
		line = strings.TrimSpace(line)

		// Only `==` pins are scannable. >=, ~=, > etc. are skipped.
		idx := strings.Index(line, "==")
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		// Strip extras: `package[extra1,extra2]` → `package`.
		if i := strings.Index(name, "["); i >= 0 {
			name = name[:i]
		}
		version := strings.TrimSpace(line[idx+2:])
		// A version may be followed by another specifier
		// (`==1.0,!=1.1` in legacy specs) — take the prefix until the
		// next comma.
		if i := strings.Index(version, ","); i >= 0 {
			version = strings.TrimSpace(version[:i])
		}
		if name == "" || version == "" {
			continue
		}
		out = append(out, pinnedPackage{name: strings.ToLower(name), version: version})
	}
	return out
}

// osvQueryRequest is the /v1/query payload shape per
// https://google.github.io/osv.dev/post-v1-query/.
type osvQueryRequest struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// osvQueryResponse is the subset of /v1/query response we care about.
type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Aliases  []string      `json:"aliases"`
	Affected []osvAffected `json:"affected"`
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	// Type is the OSV range type: "ECOSYSTEM", "SEMVER" or "GIT". Until
	// FIX-06 it was not decoded at all, which made the upgrade message a
	// liar: a GIT range's `fixed` event carries a COMMIT SHA, not a
	// version, so "Upgrade to pillow==8f1d2c3..." was reachable in
	// production (pillow==9.0.0's advisories carry ECOSYSTEM 50 /
	// SEMVER 11 / GIT 3 ranges today). Decoding the field lets
	// usableRange filter those out.
	//
	// An empty type is treated as ECOSYSTEM-equivalent: both the offline
	// snapshot adapter and the pip-audit adapter synthesise ranges, and
	// a cache entry written by an older binary has no type either.
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Fixed      string `json:"fixed,omitempty"`
	Introduced string `json:"introduced,omitempty"`
}

// queryOSV calls /v1/query for one (package, version) pair and returns
// the vulnerability list. Hits the local cache first; on miss, POSTs
// to OSV.dev and writes the response to cache.
func queryOSV(ctx context.Context, client *http.Client, cacheDir, pkg, version string) ([]osvVuln, error) {
	if cached, ok := readCache(cacheDir, pkg, version); ok {
		return cached, nil
	}

	body, _ := json.Marshal(osvQueryRequest{
		Package: osvPackage{Ecosystem: "PyPI", Name: pkg},
		Version: version,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", osvAPIBase+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain to allow connection reuse.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("osv.dev returned %d", resp.StatusCode)
	}
	var out osvQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	writeCache(cacheDir, pkg, version, out.Vulns)
	return out.Vulns, nil
}

// ── FIX-05: one finding per VULNERABILITY, not per advisory record ──────
//
// OSV's /v1/query returns the GHSA record AND each PYSEC record for the
// SAME underlying vulnerability as separate vulns[] entries. Verified
// against live OSV: cryptography==48.0.1 returns SIX records — 3 GHSA +
// 3 PYSEC — which are THREE real vulnerabilities. Emitting one finding
// per record triples the count and asks the user to fix the same CVE
// three times, which is precisely the kind of inflated number that makes
// a report untrustworthy.
//
// The fix is to partition each (package, version) result set into
// alias-connected components and emit one finding per component.

// aliasComponents partitions vulns into alias-connected components using
// union-find over the id universe {v.ID} ∪ v.Aliases.
//
// Determinism (Rule 8): union-find over a fixed edge set yields the same
// partition regardless of insertion order, nothing downstream reads a
// find() root, members are sorted by id and components are sorted by
// canonical id — so no map iteration order escapes this function.
//
// Bad-alias guard: alias data is contributed by many authorities and is
// not verified. Before merging, every pair in a multi-member component is
// checked with rangesProvablyDisjoint; if ANY pair is provably disjoint
// the WHOLE component splits back into singletons (today's behaviour) and
// the refusal is logged. Splitting the whole component rather than
// partially merging is what keeps the result independent of
// pair-evaluation order: with A~B~C where A∩B and B∩C overlap but A∩C is
// empty, "union unless disjoint" would give a different answer depending
// on which pair was visited first.
//
// Honest note on reachability: on every live path both records were
// returned BECAUSE OSV matched them against the same installed version,
// so their ranges necessarily overlap and this guard is close to
// unreachable. It is genuinely reachable only for a multi-ecosystem
// advisory whose per-ecosystem `affected` entries diverge. It is specified
// and tested; it is not claimed to fire often.
func aliasComponents(vulns []osvVuln) [][]osvVuln {
	if len(vulns) <= 1 {
		if len(vulns) == 0 {
			return nil
		}
		return [][]osvVuln{{vulns[0]}}
	}

	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		p, ok := parent[x]
		if !ok {
			parent[x] = x
			return x
		}
		if p != x {
			parent[x] = find(p)
		}
		return parent[x]
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		// Attach the lexicographically larger root under the smaller one,
		// so the forest SHAPE — not merely the partition it induces — is
		// a pure function of the input.
		if ra < rb {
			parent[rb] = ra
		} else {
			parent[ra] = rb
		}
	}

	// A record with no id gets a synthetic per-index key: an empty string
	// is not an identity, and letting several id-less records share one
	// would merge unrelated advisories. Its aliases still participate —
	// an alias identifies the vulnerability even when the id is missing.
	keys := make([]string, len(vulns))
	for i, v := range vulns {
		if v.ID != "" {
			keys[i] = v.ID
		} else {
			keys[i] = fmt.Sprintf("\x00anonymous-%d", i)
		}
		find(keys[i])
		for _, a := range v.Aliases {
			if a != "" {
				union(keys[i], a)
			}
		}
	}

	groups := map[string][]osvVuln{}
	roots := make([]string, 0, len(vulns))
	for i, v := range vulns {
		r := find(keys[i])
		if _, seen := groups[r]; !seen {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], v)
	}
	sort.Strings(roots) // stderr log order must be deterministic too

	comps := make([][]osvVuln, 0, len(roots))
	for _, r := range roots {
		members := groups[r]
		sort.SliceStable(members, func(i, j int) bool { return members[i].ID < members[j].ID })
		if len(members) > 1 && anyPairProvablyDisjoint(members) {
			fmt.Fprintf(os.Stderr,
				"[fendix] pip: refusing to merge alias-linked advisories with disjoint affected ranges: %v\n",
				vulnIDs(members))
			for _, m := range members {
				comps = append(comps, []osvVuln{m})
			}
			continue
		}
		comps = append(comps, members)
	}
	sort.SliceStable(comps, func(i, j int) bool {
		return canonicalID(componentIDs(comps[i])) < canonicalID(componentIDs(comps[j]))
	})
	return comps
}

// vulnIDs renders a component's top-level ids for the refusal log.
func vulnIDs(members []osvVuln) []string {
	out := make([]string, 0, len(members))
	for _, m := range members {
		out = append(out, m.ID)
	}
	return out
}

// anyPairProvablyDisjoint reports whether ANY pair in the component has
// provably non-overlapping affected ranges — the signal that the alias
// edge joining them is bad data rather than two names for one bug.
func anyPairProvablyDisjoint(members []osvVuln) bool {
	for i := 0; i < len(members); i++ {
		for j := i + 1; j < len(members); j++ {
			if rangesProvablyDisjoint(members[i], members[j]) {
				return true
			}
		}
	}
	return false
}

// versionInterval is one [introduced, fixed) affected window. An empty
// endpoint is unbounded on that side.
type versionInterval struct {
	introduced string
	fixed      string
}

// affectedIntervals flattens an advisory's non-GIT ranges into intervals.
// Per the OSV schema the events within a range are ordered, alternating
// `introduced` and `fixed`; a trailing `introduced` with no `fixed` means
// "still affected".
func affectedIntervals(v osvVuln) []versionInterval {
	var out []versionInterval
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			if !usableRange(r) {
				continue
			}
			var cur versionInterval
			open := false
			for _, ev := range r.Events {
				switch {
				case ev.Introduced != "":
					if open {
						out = append(out, cur)
					}
					cur = versionInterval{introduced: ev.Introduced}
					open = true
				case ev.Fixed != "":
					if !open {
						cur = versionInterval{}
					}
					cur.fixed = ev.Fixed
					out = append(out, cur)
					cur, open = versionInterval{}, false
				}
			}
			if open {
				out = append(out, cur)
			}
		}
	}
	return out
}

// intervalsOverlap reports whether two affected windows intersect, with an
// empty endpoint read as unbounded.
func intervalsOverlap(a, b versionInterval) bool {
	if b.fixed != "" && a.introduced != "" && offline.CompareVersions(a.introduced, b.fixed) >= 0 {
		return false
	}
	if a.fixed != "" && b.introduced != "" && offline.CompareVersions(b.introduced, a.fixed) >= 0 {
		return false
	}
	return true
}

// rangesProvablyDisjoint reports whether a and b can be PROVEN to affect
// non-overlapping version windows.
//
// Merge-unless-proven-disjoint, deliberately: a false "these are the same
// bug" costs a slightly over-merged reference list, while a false "these
// are different bugs" restores the duplicate-finding inflation FIX-05
// exists to remove. So an advisory with no usable (non-GIT) range — which
// carries no evidence either way — returns false and merges.
func rangesProvablyDisjoint(a, b osvVuln) bool {
	ia, ib := affectedIntervals(a), affectedIntervals(b)
	if len(ia) == 0 || len(ib) == 0 {
		return false
	}
	for _, x := range ia {
		for _, y := range ib {
			if intervalsOverlap(x, y) {
				return false
			}
		}
	}
	return true
}

// componentIDs returns every id a component is known by — member ids AND
// their aliases — deduped and sorted. This is the set the canonical picker
// ranges over and the set References preserves (Rule 3: nothing a record
// told us is dropped by the merge).
func componentIDs(members []osvVuln) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(members)*2)
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	for _, m := range members {
		add(m.ID)
		for _, a := range m.Aliases {
			add(a)
		}
	}
	sort.Strings(out)
	return out
}

// canonicalIDTier ranks an id by naming authority: CVE first, because it
// is the one identifier every downstream tracker, ticket system and
// scanner agrees on; then GHSA, then PYSEC, then everything else.
//
// Matching is exact-with-hyphen. BIT-* is a real OSV alias prefix
// (BIT-django-2026-15830 rides along with django's PYSEC record) and it
// belongs in "other" — anything looser would promote it past the PYSEC id
// that should win.
func canonicalIDTier(id string) int {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return 0
	case strings.HasPrefix(id, "GHSA-"):
		return 1
	case strings.HasPrefix(id, "PYSEC-"):
		return 2
	default:
		return 3
	}
}

// canonicalID picks the component's public identity: highest-priority
// tier, lexicographically smallest within a tier so the choice is a pure
// function of the id SET.
//
// It MUST range over aliases, not just top-level ids. In the verified
// cryptography==48.0.1 data the CVE ids appear ONLY as aliases and never
// as a record's `id`, so a picker that inspected v.ID alone would never
// select a CVE and the whole tier table would be dead.
func canonicalID(ids []string) string {
	best, bestTier := "", 0
	for _, id := range ids {
		if id == "" {
			continue
		}
		t := canonicalIDTier(id)
		if best == "" || t < bestTier || (t == bestTier && id < best) {
			best, bestTier = id, t
		}
	}
	return best
}

// buildFindings is the single emit point for a (package, version) result
// set: it partitions the records into alias-connected components and
// builds one finding per component. Every call site in this package goes
// through it, so there is one determinism story and one place to stamp
// per-finding context.
func buildFindings(pkg pinnedPackage, vulns []osvVuln, manifestName string) []evidence.Evidence {
	comps := aliasComponents(vulns)
	out := make([]evidence.Evidence, 0, len(comps))
	for _, members := range comps {
		out = append(out, buildMergedFinding(pkg, members, manifestName))
	}
	return out
}

// buildMergedFinding renders one alias-connected component as a single
// finding. It is the whole finding constructor for this package;
// buildFinding is the one-record special case.
//
// The description is taken from the member whose id IS the canonical id
// when one exists, and otherwise from the first member in sorted-id order
// with a non-empty value — never "whichever came first in the slice",
// which would make the rendered text depend on OSV's response ordering.
func buildMergedFinding(pkg pinnedPackage, members []osvVuln, manifestName string) evidence.Evidence {
	ids := componentIDs(members)
	canonical := canonicalID(ids)

	// Members arrive sorted by id from aliasComponents; sort defensively so
	// a direct caller cannot make the output order-dependent.
	sorted := make([]osvVuln, len(members))
	copy(sorted, members)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	pick := func(get func(osvVuln) string) string {
		for _, m := range sorted {
			if m.ID == canonical {
				if val := get(m); val != "" {
					return val
				}
				break
			}
		}
		for _, m := range sorted {
			if val := get(m); val != "" {
				return val
			}
		}
		return ""
	}

	summary := pick(func(v osvVuln) string { return v.Summary })
	if summary == "" {
		summary = canonical
	}
	desc := pick(func(v osvVuln) string { return v.Details })
	if desc == "" {
		desc = summary
	}
	if len(desc) > 200 {
		desc = desc[:200]
	}

	fix := mergedFixVersion(sorted, pkg.version)
	fixMsg := "Upgrade to a patched version (no fix listed in OSV)."
	if fix != "" {
		fixMsg = fmt.Sprintf("Upgrade to %s==%s or later.", pkg.name, fix)
	}

	// References: canonical first, then every other merged id in sorted
	// order. Nothing is dropped — a user who saved a baseline or an ignore
	// rule against a merged-away id can still find it here (Rule 3).
	//
	// Canonical-first is a SCANNER-PACKAGE contract, not a report contract:
	// engine.Deduplicate unconditionally re-sorts References, so by the time
	// a report renders they are alphabetical.
	refs := make([]string, 0, len(ids))
	refs = append(refs, canonical)
	for _, id := range ids {
		if id != canonical {
			refs = append(refs, id)
		}
	}

	idSlug := strings.ReplaceAll(canonical, "-", "_")
	line := manifestName
	return evidence.Evidence{
		ID:         "SEC-DEPS-" + idSlug,
		RuleID:     canonical,
		Title:      fmt.Sprintf("Vulnerable dependency: %s==%s (%s)", pkg.name, pkg.version, canonical),
		Severity:   models.SeverityHigh,
		Source:     models.SourceWhitebox,
		Category:   "deps",
		Endpoint:   manifestName,
		Evidence:   fmt.Sprintf("%s==%s: %s", pkg.name, pkg.version, desc),
		Fix:        fixMsg,
		References: refs,
		Confidence: models.ConfidenceHigh,
		Line:       &line,
		// The v2 fingerprint keys this finding on advisory + ecosystem +
		// package. Carried structurally so identity never has to be parsed
		// back out of the rendered Title.
		Dependency: &models.DependencyRef{
			Ecosystem: "PyPI",
			Package:   pkg.name,
			Version:   pkg.version,
			Manifest:  manifestName,
		},
		// INTERNAL handoff to scanner/deps/applicability (FIX-14), which
		// needs the ecosystem/package/version this finding is about in a
		// form it can look up without re-parsing the title. Metadata is
		// dropped by ToFinding, which is fine: applicability.Resolve runs
		// inside this package, before any projection, and nothing
		// downstream may reach for these keys.
		Metadata: map[string]string{
			"deps.ecosystem": "PyPI",
			"deps.package":   pkg.name,
			"deps.version":   pkg.version,
		},
	}
}

// buildFinding maps ONE OSV record to a finding — the single-record case
// of buildMergedFinding, kept so the one-record call sites and the
// package's shape tests have a direct target. Emit paths use buildFindings
// so alias-connected records collapse first.
func buildFinding(pkg pinnedPackage, v osvVuln, manifestName string) evidence.Evidence {
	return buildMergedFinding(pkg, []osvVuln{v}, manifestName)
}

// usableRange reports whether an OSV range's `fixed` events name real
// package versions. GIT ranges name commit SHAs, which are useless in an
// "Upgrade to X" message and meaningless to a version comparator. An
// empty type is accepted: the offline-snapshot and pip-audit adapters
// synthesise ECOSYSTEM-equivalent ranges without setting it.
func usableRange(r osvRange) bool { return r.Type != "GIT" }

// firstFixVersion walks OSV.affected[].ranges[].events[] and returns
// the first `fixed` version (per OSV schema, the canonical upgrade
// target), skipping GIT ranges whose `fixed` is a commit SHA.
//
// Kept as the installed-version-agnostic form. fixCandidate is what the
// finding constructor uses; this remains the honest answer to "does this
// advisory name a fix at all".
func firstFixVersion(v osvVuln) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			if !usableRange(r) {
				continue
			}
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

// fixedVersions collects every `fixed` event across an advisory's non-GIT
// ranges, in document order.
func fixedVersions(v osvVuln) []string {
	var out []string
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			if !usableRange(r) {
				continue
			}
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					out = append(out, ev.Fixed)
				}
			}
		}
	}
	return out
}

// lowerVersion / higherVersion pick between two version strings using the
// shared offline comparator, breaking a comparator TIE lexicographically.
// The tie-break is not cosmetic: offline.CompareVersions collapses
// "1.0.0-rc.1" and "1.0.0" to the same release core, so without it the
// winner would depend on iteration order and the output would stop being
// a pure function of the input set (Rule 8). "" means "no candidate yet".
func lowerVersion(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	switch c := offline.CompareVersions(a, b); {
	case c < 0:
		return a
	case c > 0:
		return b
	}
	if a < b {
		return a
	}
	return b
}

func higherVersion(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	switch c := offline.CompareVersions(a, b); {
	case c > 0:
		return a
	case c < 0:
		return b
	}
	if a > b {
		return a
	}
	return b
}

// fixCandidate returns the minimal in-branch upgrade target for ONE
// advisory: the LOWEST `fixed` version strictly greater than the installed
// pin, across every non-GIT range.
//
// Django's PYSEC-2026-3717 is why this is not simply "the first fixed
// event", and equally why it is not "the max": that single advisory lists
// fixed=5.2.17 (the 5.2.x branch) AND fixed=6.0.8 (the 6.0.x branch). For
// a user pinned at 5.2.16 the correct answer is 5.2.17 — the first-event
// rule would have picked whichever the JSON happened to list first, and a
// max would push a major-version jump at someone who asked for a patch.
//
// Fallback ladder — the point of which is to never invent a version and
// never claim "no fix" when OSV named one:
//
//  1. Some fixed event compares strictly greater than installed → the
//     lowest such (lexicographic tie-break, see lowerVersion).
//  2. Nothing compares greater — offline.CompareVersions cannot order a
//     PyPI pre/dev-release pin against a release, and a stale cache can
//     carry a fix already below the pin → the lowest listed fixed
//     version. The advisory DOES name a fix; we merely cannot rank it
//     against this pin, and printing "no fix listed" there would be a lie.
//  3. No usable fixed event at all (GIT-only, or none) → "". The caller
//     prints the honest "no fix listed in OSV" message.
func fixCandidate(v osvVuln, installed string) string {
	fixed := fixedVersions(v)
	if len(fixed) == 0 {
		return ""
	}
	var above, lowest string
	for _, f := range fixed {
		lowest = lowerVersion(lowest, f)
		if installed == "" || offline.CompareVersions(f, installed) > 0 {
			above = lowerVersion(above, f)
		}
	}
	if above != "" {
		return above
	}
	return lowest
}

// mergedFixVersion is level (b) of the two-level rule: across the
// alias-merged members of one component, take the MAX of the per-advisory
// candidates, so the printed version actually fixes every vulnerability
// the merged finding reports. A member with no usable fix contributes
// nothing; when EVERY member contributes nothing the caller falls back to
// the honest no-fix message.
//
// Level (a) is deliberately inside fixCandidate rather than folded in
// here: minimality is a property of one advisory's branch set, and
// maximality is a property of the component. Collapsing them into a
// single max over all fixed events would reintroduce the django
// 5.2.16 → 6.0.8 jump.
func mergedFixVersion(members []osvVuln, installed string) string {
	var best string
	for _, m := range members {
		best = higherVersion(best, fixCandidate(m, installed))
	}
	return best
}

// sortFindingsByID puts findings in deterministic order so the report
// is stable across runs of the same scan.
func sortFindingsByID(fs []evidence.Evidence) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].ID < fs[j].ID })
}

// --- cache ------------------------------------------------------------

// cacheDir returns ~/.fendix/cache/osv-pypi, creating it lazily. Empty
// string + nil error means "no usable cache dir" (HOME unset, perms
// denied, etc.) — Scan keeps working, just hits the network each call.
func cacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", err
	}
	d := filepath.Join(home, ".fendix", "cache", "osv-pypi")
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	return d, nil
}

func cachePath(dir, pkg, version string) string {
	// Package names can contain `/` in some ecosystems; PyPI doesn't,
	// but normalise anyway to keep this resilient.
	safe := strings.ReplaceAll(pkg, "/", "_") + "@" + strings.ReplaceAll(version, "/", "_")
	return filepath.Join(dir, safe+".json")
}

// cacheSchema is bumped whenever the SHAPE of a cached record changes —
// not merely its freshness. Before FIX-05 the cache held a bare []osvVuln
// array whose contents depended on WHICH path filled it: a batch-path
// write stored alias-less, Affected-less records that readCache then
// served to every path, including the serial one, for the full 24h TTL.
// So users would have upgraded, seen no change for a day, then seen a
// partial one.
//
// v2 records are alias- and affected-complete (post-hydration). A v1 bare
// array fails to decode into cacheEnvelope and is therefore treated as a
// MISS, so each entry is re-fetched once rather than silently lacking the
// aliases FIX-05 merges on and the ranges FIX-06 reads.
const cacheSchema = 2

type cacheEnvelope struct {
	Schema int       `json:"schema"`
	Vulns  []osvVuln `json:"vulns"`
}

func readCache(dir, pkg, version string) ([]osvVuln, bool) {
	if dir == "" {
		return nil, false
	}
	p := cachePath(dir, pkg, version)
	info, err := os.Stat(p)
	if err != nil {
		return nil, false
	}
	if time.Since(info.ModTime()) > cacheTTL {
		return nil, false
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var env cacheEnvelope
	if err := json.Unmarshal(data, &env); err != nil || env.Schema != cacheSchema {
		return nil, false
	}
	return env.Vulns, true
}

func writeCache(dir, pkg, version string, vulns []osvVuln) {
	if dir == "" {
		return
	}
	data, err := json.Marshal(cacheEnvelope{Schema: cacheSchema, Vulns: vulns})
	if err != nil {
		return
	}
	// Write to a tmpfile then rename so concurrent scans don't see a
	// half-written cache file.
	p := cachePath(dir, pkg, version)
	tmp, err := os.CreateTemp(dir, "osv-")
	if err != nil {
		return
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return
	}
	tmp.Close()
	_ = os.Rename(tmp.Name(), p)
}
