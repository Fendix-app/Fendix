package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/logagg"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

const (
	evilOrigin    = "https://evil.example.com"
	evilDomain    = "evil.example.com"
	attackerCom   = "attacker.com"
	nullOriginVal = "null"
)

// corsCheck implements the Check interface for the CORS misconfiguration
// scanner. Structural adapter — Run holds the unchanged body of the
// historical CheckCORS free function.
type corsCheck struct{}

func (corsCheck) Name() string                        { return "cors" }
func (corsCheck) Category() string                    { return "cors" }
func (corsCheck) Tier() Tier                          { return TierPassive }
func (corsCheck) Enabled(cfg *models.ScanConfig) bool { return true }

// CheckCORS sends a request with an evil Origin header and checks for
// CORS misconfigurations. Covers 4 scenarios:
//  1. Wildcard ACAO + credentials → CRITICAL
//  2. Wildcard ACAO without credentials → MEDIUM
//  3. Reflected arbitrary origin → HIGH
//  4. Non-standard methods allowed → LOW
func CheckCORS(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []ev.Evidence {
	return corsCheck{}.Run(ctx, NewCheckContext(cfg), endpoint)
}

// probeOrigins returns the set of attacker-controlled Origin values to test
// against an endpoint. Beyond the bare attacker origin (exact-match), it derives
// suffix/prefix/substring bypass candidates from the target host so the common
// permissive-regex misconfigs are caught (Phase 4a / 4.1). The literal "null"
// origin is included to flag servers that reflect sandboxed-iframe / data-URI
// origins (Phase 4a / 4.4). targetHost is parsed from endpoint.FullURL; when it
// is empty (unparseable URL) the host-derived probes are skipped.
func probeOrigins(fullURL string) []string {
	origins := []string{evilOrigin, nullOriginVal}

	targetHost := ""
	if u, err := url.Parse(fullURL); err == nil {
		targetHost = u.Hostname()
	}
	if targetHost != "" {
		origins = append(origins,
			// suffix bypass: target appears as a subdomain of the attacker domain
			fmt.Sprintf("https://%s.%s", targetHost, evilDomain),
			// prefix/substring: target as a subdomain of an attacker-owned domain
			fmt.Sprintf("https://%s.%s", targetHost, attackerCom),
			// substring of attacker host: target embedded in the attacker label
			fmt.Sprintf("https://attacker-%s", targetHost),
		)
	}
	return origins
}

// Run sends CORS probes for a handful of attacker-controlled origins, on both
// the OPTIONS preflight and the endpoint's real (simple-request) method, and
// reports reflected-origin / null-origin / wildcard misconfigurations. Findings
// are deduped by misconfig class so the same issue seen on both preflight and
// simple request is reported once. Client construction is identical to the
// historical free function (guardedClient).
func (corsCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []ev.Evidence {
	cfg := cc.Cfg
	client := guardedClient(cfg)
	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)

	// One probe per origin on the preflight (OPTIONS) and on the real method
	// (simple request). Some servers reflect Origin only on the actual request,
	// not the preflight (Phase 4a / 4.3).
	methods := []string{http.MethodOptions}
	simpleMethod := strings.ToUpper(strings.TrimSpace(endpoint.Method))
	if simpleMethod == "" {
		simpleMethod = http.MethodGet
	}
	if simpleMethod != http.MethodOptions {
		methods = append(methods, simpleMethod)
	}

	// Phase 1 — probe and record signals. We gather across all probes before
	// emitting, so the broader misconfig classes can subsume the narrower ones
	// (a server that reflects ANY origin trivially reflects "null" too; reporting
	// both would be redundant noise). Each signal also captures whether it was
	// observed with credentials, which escalates its severity.
	var (
		sawWildcard      bool // ACAO: *
		sawWildcardCreds bool // ACAO: * AND ACAC: true
		sawReflected     bool // ACAO == an attacker probe origin (exact)
		sawReflectedCred bool
		reflectedEvid    string
		sawNull          bool // ACAO: null (only when we sent Origin: null)
		sawNullCred      bool
		acamSeen         string // first non-empty Access-Control-Allow-Methods (for non-standard-token detection)
		sawWildcardMeth  bool   // ACAM: * (or '*' among tokens) on ANY probe
		// B4: track whether the CORS misconfig was observed on a 4xx
		// (auth-gated) response vs a non-4xx one. When EVERY positive signal
		// came from a 4xx, the finding is lower-confidence context.
		sig4xx    bool
		sigNon4xx bool
	)

	// The probe set is method-independent (derived from the URL only), so build
	// it once instead of re-parsing the URL on every method.
	origins := probeOrigins(endpoint.FullURL)

	for _, probeMethod := range methods {
		for _, origin := range origins {
			req, err := http.NewRequestWithContext(ctx, probeMethod, endpoint.FullURL, nil)
			if err != nil {
				logagg.Warn("cors", "CORS check: failed to create request", "url", endpoint.FullURL, "error", err)
				continue
			}
			req.Header.Set("Origin", origin)
			if probeMethod == http.MethodOptions {
				req.Header.Set("Access-Control-Request-Method", "GET")
			}
			cfg.Auth.ApplyToRequest(req)

			resp, err := client.Do(req)
			if err != nil {
				logagg.Warn("cors", "CORS check: request failed", "url", endpoint.FullURL, "error", err)
				continue
			}

			acao := resp.Header.Get("Access-Control-Allow-Origin")
			acac := resp.Header.Get("Access-Control-Allow-Credentials")
			acam := resp.Header.Get("Access-Control-Allow-Methods")
			status := resp.StatusCode
			resp.Body.Close()

			// Status-gate narrowing (Phase 4a / 4.5): only 404 and 5xx gate
			// evaluation out. A CORS misconfig on a 404 page is unreachable
			// (FP corpus pattern P2). But auth-gated 401/403/405 responses that
			// still emit reflecting CORS headers ARE real misconfigs — the
			// headers gate cross-origin traffic independently of the probe's
			// auth outcome, so keep evaluating them.
			if status == http.StatusNotFound || status >= 500 {
				slog.Debug("CORS check skipped (404/5xx response)",
					"endpoint", epLabel, "status", status, "method", probeMethod)
				continue
			}

			credentialed := strings.EqualFold(acac, "true")
			if acam != "" {
				if acamSeen == "" {
					acamSeen = acam
				}
				// A wildcard ACAM on ANY probe is a wildcard-methods misconfig.
				// Capturing only the first non-empty ACAM (acamSeen) would let
				// probe ordering hide a wildcard behind an earlier explicit list.
				if acamHasWildcard(acam) {
					sawWildcardMeth = true
				}
			}

			positiveSignal := false
			switch {
			case acao == "*":
				sawWildcard = true
				sawWildcardCreds = sawWildcardCreds || credentialed
				positiveSignal = true
			case origin == nullOriginVal && strings.EqualFold(acao, nullOriginVal):
				// null-origin acceptance (Phase 4a / 4.4). Sandboxed iframes
				// and data-URIs send Origin: null; reflecting it is exploitable.
				sawNull = true
				sawNullCred = sawNullCred || credentialed
				positiveSignal = true
			case origin != nullOriginVal && strings.EqualFold(acao, origin):
				// Reflected arbitrary origin (Phase 4a / 4.1, 4.2). Detection is
				// EXACT case-insensitive equality to the probe origin, never a
				// substring match — that avoids the false-positive class where a
				// legitimate allowlisted origin merely contains the attacker host.
				sawReflected = true
				sawReflectedCred = sawReflectedCred || credentialed
				if reflectedEvid == "" {
					reflectedEvid = acao
				}
				positiveSignal = true
			}
			// B4: record whether this misconfig-producing probe was a 4xx.
			if positiveSignal {
				if httpResponseContext(status) == "4xx" {
					sig4xx = true
				} else {
					sigNon4xx = true
				}
			}
		}
	}

	// Phase 2 — emit the SINGLE highest-severity ORIGIN finding.
	//
	// wildcard-no-creds, reflected-origin, and null-origin are DISTINCT
	// misconfigs that can co-occur across different probes/methods (e.g. ACAO: *
	// on the OPTIONS preflight but a reflected arbitrary origin on the GET simple
	// request). They are NOT a subsumption hierarchy by breadth — a plain
	// wildcard is LOWER severity than a reflected/null origin, so it must never
	// hide the higher-severity findings. We avoid the noise of N origin findings
	// by emitting only the single highest-severity candidate, never by letting a
	// lower-severity signal win. The one genuine subsumption is null ⊂ reflected:
	// a server that reflects ANY arbitrary origin trivially reflects "null" too,
	// same root cause, so a reflected signal absorbs the null signal.
	//
	// Severity ranking (highest first), credentialed > non-credentialed on ties:
	//   wildcard+creds (CRIT) ≈ reflected+creds (CRIT) > reflected (HIGH) ≈ null (HIGH) > wildcard (MEDIUM)
	// The five ORIGIN findings below are direct observations: ACAO and ACAC are
	// read literally, and reflection is EXACT case-insensitive equality to the
	// probe origin (never a substring match — see the switch above), so there
	// is no inference step. The two appendMethodFindings results deliberately
	// are not: an ACAM token list is read literally too, but those findings
	// grade EXPLOITABILITY rather than certainty, which is why both already
	// carry ConfidenceMedium. Same predicate as headers.go: DirectObservation
	// == the check asserts ConfidenceHigh from a literal read.
	var findings []ev.Evidence

	type originCandidate struct {
		rank    int // higher = emitted first
		finding ev.Evidence
	}
	var candidates []originCandidate

	// Wildcard + credentials is a CONFIGURATION-ONLY observation, and it is
	// graded as one. The pair is invalid rather than exploitable: the Fetch
	// standard forbids `Access-Control-Allow-Origin: *` when the request's
	// credentials mode is `include`, so a spec-compliant browser rejects the
	// response outright and NO authenticated cross-origin read occurs. Reading
	// two headers therefore proves a server misconfigured to intend permissive
	// credentialed sharing — it does not demonstrate that sharing works.
	//
	// It stays MEDIUM/non-blocking for that reason. The exploitable shape is
	// origin REFLECTION with credentials (rank 90 below), where the server
	// echoes a specific attacker origin and the browser does honour it; that
	// remains CRITICAL. Ranking wildcard+creds below every reflection finding
	// keeps a configuration observation from masking a demonstrated one.
	if sawWildcardCreds {
		candidates = append(candidates, originCandidate{
			// MEDIUM — above plain wildcard (30), below every reflected/null
			// signal, which grade demonstrated behaviour rather than intent.
			rank: 40,
			finding: ev.Evidence{
				RuleID:            "cors/wildcard-with-credentials",
				Title:             "CORS wildcard origin combined with credentials (invalid configuration)",
				Severity:          models.SeverityMedium,
				Source:            models.SourceBlackbox,
				Category:          "cors",
				Endpoint:          epLabel,
				Evidence:          "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true — an invalid combination that browsers reject; credentialed cross-origin access was NOT demonstrated",
				Fix:               "Never combine wildcard origin with credentials. Specify explicit allowed origins.",
				References:        []string{"CWE-942"},
				Confidence:        models.ConfidenceHigh,
				DirectObservation: true,
			},
		})
	}
	if sawReflected && sawReflectedCred {
		// Reflected arbitrary origin WITH credentials is account-takeover grade
		// (Phase 4a / 4.2) → CRITICAL, because an attacker page can read the
		// authenticated response.
		//
		// That impact is what CRITICAL is claiming, so it is graded against
		// what the response actually exposes. When a source of truth DECLARES
		// the operation anonymous (AuthExpectationPublic), the credentialed
		// read returns a body any unauthenticated client could already fetch:
		// the reflection is still a real misconfiguration to fix, but calling
		// it account-takeover overstates the evidence.
		//
		// Only the POSITIVE declaration de-escalates. AuthExpectationUnknown —
		// every crawled or brute-forced endpoint — stays CRITICAL, because an
		// absent declaration is not evidence that a response is harmless. That
		// asymmetry is deliberate and matches the rest of the decision layer:
		// unknown is never silently read as safe.
		severity, rank := models.SeverityCritical, 90
		exposure := "credentialed cross-origin read of an authenticated response"
		if endpoint.AuthExpectation == models.AuthExpectationPublic {
			// HIGH, still ranked above uncredentialed reflection (70): strictly
			// more evidence than that finding holds.
			severity, rank = models.SeverityHigh, 75
			exposure = "credentialed cross-origin read, but a source of truth declares this operation public, so the readable response is not authenticated data"
		}
		candidates = append(candidates, originCandidate{
			rank: rank,
			finding: ev.Evidence{
				RuleID:            "cors/reflects-origin-with-credentials",
				Title:             "CORS reflects arbitrary origin with credentials",
				Severity:          severity,
				Source:            models.SourceBlackbox,
				Category:          "cors",
				Endpoint:          epLabel,
				Evidence:          fmt.Sprintf("Access-Control-Allow-Origin reflects attacker origin: %s with Access-Control-Allow-Credentials: true — %s", reflectedEvid, exposure),
				Fix:               "Validate Origin against an explicit allowlist. Do not reflect the Origin header.",
				References:        []string{"CWE-942"},
				Confidence:        models.ConfidenceHigh,
				DirectObservation: true,
				AuthExpectation:   endpoint.AuthExpectation,
			},
		})
	}
	if sawReflected && !sawReflectedCred {
		candidates = append(candidates, originCandidate{
			rank: 70,
			finding: ev.Evidence{
				RuleID:            "cors/reflects-origin",
				Title:             "CORS reflects arbitrary origin",
				Severity:          models.SeverityHigh,
				Source:            models.SourceBlackbox,
				Category:          "cors",
				Endpoint:          epLabel,
				Evidence:          fmt.Sprintf("Access-Control-Allow-Origin reflects attacker origin: %s", reflectedEvid),
				Fix:               "Validate Origin against an explicit allowlist. Do not reflect the Origin header.",
				References:        []string{"CWE-942"},
				Confidence:        models.ConfidenceHigh,
				DirectObservation: true,
			},
		})
	}
	// null ⊂ reflected: only consider the null signal when reflection did NOT
	// fire — same arbitrary-origin root cause, don't double-report.
	if sawNull && !sawReflected {
		f := ev.Evidence{
			RuleID:            "cors/null-origin",
			Title:             "CORS accepts null origin",
			Severity:          models.SeverityHigh,
			Source:            models.SourceBlackbox,
			Category:          "cors",
			Endpoint:          epLabel,
			Evidence:          "Access-Control-Allow-Origin: null",
			Fix:               "Never allow the null origin. Validate Origin against an explicit allowlist.",
			References:        []string{"CWE-942"},
			Confidence:        models.ConfidenceHigh,
			DirectObservation: true,
		}
		rank := 60 // HIGH, slightly below reflected-HIGH on ties
		if sawNullCred {
			f.Severity = models.SeverityCritical
			f.Evidence = "Access-Control-Allow-Origin: null with Access-Control-Allow-Credentials: true"
			rank = 85 // CRITICAL, just below the credentialed-reflected CRITICAL
		}
		candidates = append(candidates, originCandidate{rank: rank, finding: f})
	}
	if sawWildcard {
		candidates = append(candidates, originCandidate{
			rank: 30, // MEDIUM — lowest; must never suppress a higher finding
			finding: ev.Evidence{
				RuleID:            "cors/wildcard-origin",
				Title:             "CORS allows any origin",
				Severity:          models.SeverityMedium,
				Source:            models.SourceBlackbox,
				Category:          "cors",
				Endpoint:          epLabel,
				Evidence:          "Access-Control-Allow-Origin: *",
				Fix:               "Restrict Access-Control-Allow-Origin to specific trusted origins.",
				References:        []string{"CWE-942"},
				Confidence:        models.ConfidenceHigh,
				DirectObservation: true,
			},
		})
	}

	if len(candidates) > 0 {
		best := candidates[0]
		for _, c := range candidates[1:] {
			if c.rank > best.rank {
				best = c
			}
		}
		findings = append(findings, best.finding)
	}

	// Method-policy findings are independent of the origin verdict: wildcard
	// methods (Phase 4a / 4.6) and genuinely non-standard tokens.
	findings = appendMethodFindings(findings, acamSeen, sawWildcardMeth, epLabel)

	// B4: de-escalate via the confidence scorer when the context makes the
	// misconfig lower-trust. Evidence preserved (Rule 3) — the finding stays,
	// only its confidence drops.
	//
	//   "4xx"          the misconfig was ONLY ever observed on an auth-gated
	//                  response, never on a 2xx. A signal that also fired on a
	//                  2xx is real and left untagged.
	//   "static-asset" the endpoint serves a static file. A permissive CORS
	//                  policy on a CDN-served asset is a real observation but a
	//                  weaker one than the same policy on an API route.
	//
	// 4xx wins when both apply, matching responseContextFor's precedence.
	switch {
	case sig4xx && !sigNon4xx:
		for i := range findings {
			findings[i].ResponseContext = "4xx"
		}
	case isStaticAssetPath(endpoint.Path):
		for i := range findings {
			findings[i].ResponseContext = "static-asset"
		}
	}

	slog.Debug("CORS check complete", "endpoint", epLabel, "findings", len(findings))
	return findings
}

// acamHasWildcard reports whether an Access-Control-Allow-Methods value is a
// wildcard — either the bare "*" or "*" among the comma-separated tokens.
func acamHasWildcard(acam string) bool {
	if strings.TrimSpace(acam) == "*" {
		return true
	}
	for _, method := range strings.Split(acam, ",") {
		if strings.TrimSpace(method) == "*" {
			return true
		}
	}
	return false
}

// appendMethodFindings evaluates the Access-Control-Allow-Methods header and
// appends at most one method-policy finding. A wildcard ("*", or "*" among the
// listed tokens) is its own finding class (Phase 4a / 4.6) and is detected
// across ALL probes (sawWildcardMeth), so probe ordering can't hide it behind an
// earlier explicit method list; the historical non-standard-token detection is
// preserved for genuinely odd methods. Called once per endpoint, so no
// cross-probe dedup is needed.
func appendMethodFindings(findings []ev.Evidence, acam string, sawWildcardMeth bool, epLabel string) []ev.Evidence {
	if sawWildcardMeth {
		evidence := "Access-Control-Allow-Methods: *"
		if acam != "" && strings.TrimSpace(acam) != "*" {
			evidence = fmt.Sprintf("Access-Control-Allow-Methods includes wildcard method: %s", acam)
		}
		return append(findings, ev.Evidence{
			RuleID:     "cors/wildcard-methods",
			Title:      "CORS allows all methods (wildcard)",
			Severity:   models.SeverityMedium,
			Source:     models.SourceBlackbox,
			Category:   "cors",
			Endpoint:   epLabel,
			Evidence:   evidence,
			Fix:        "List only the HTTP methods the endpoint requires instead of a wildcard.",
			References: []string{"CWE-942"},
			Confidence: models.ConfidenceMedium,
		})
	}

	if acam == "" {
		return findings
	}

	standardMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "PATCH": true,
		"DELETE": true, "HEAD": true, "OPTIONS": true,
	}

	for _, method := range strings.Split(acam, ",") {
		method = strings.TrimSpace(strings.ToUpper(method))
		if method != "" && !standardMethods[method] {
			return append(findings, ev.Evidence{
				RuleID:     "cors/nonstandard-method",
				Title:      "CORS allows non-standard HTTP method",
				Severity:   models.SeverityLow,
				Source:     models.SourceBlackbox,
				Category:   "cors",
				Endpoint:   epLabel,
				Evidence:   fmt.Sprintf("Access-Control-Allow-Methods includes non-standard method: %s", method),
				Fix:        "Remove non-standard methods from Access-Control-Allow-Methods.",
				References: []string{"CWE-942"},
				Confidence: models.ConfidenceMedium,
			})
		}
	}
	return findings
}
