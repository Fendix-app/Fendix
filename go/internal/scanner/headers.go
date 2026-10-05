package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/logagg"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// headerCheck defines what to look for in a single response header.
type headerCheck struct {
	Name     string
	Severity models.Severity
	Category string
	Check    func(value string) *ev.Evidence
	// DocumentOnly marks a header that only constrains a browser RENDERING a
	// document. On a response the browser parses as data — a JSON API payload —
	// the control has nothing to act on, so the finding is de-escalated to INFO
	// rather than reported at a weight that implies a missing protection.
	//
	// See classifyDocumentRendering: the de-escalation applies only when the
	// response type is POSITIVELY known not to be a document. An unrecognised
	// or absent Content-Type leaves the finding exactly as it was.
	DocumentOnly bool
}

// DIRECT OBSERVATION. Every check in this file that asserts
// models.ConfidenceHigh does so because it is reading a header LITERALLY —
// present, absent, or exactly this token — so the claim carries no inference
// between the bytes on the wire and the finding. Those all set
// Evidence.DirectObservation, which the confidence scorer turns into a +30
// delta; without it a single-engine DAST finding could never reach the HIGH
// band, because headers/cookie/cors are outside engine.categoryMap and so can
// never become SourceCorrelated.
//
// The one exception is "Weak Content-Security-Policy": analyzeCSP GRADES a
// policy rather than reading it, and a nonce/'strict-dynamic' policy that lists
// 'unsafe-inline' as a legacy fallback is not actually weak. It is already the
// only ConfidenceMedium result here, and it stays out. The predicate in this
// file is therefore exactly: DirectObservation == the check asserts
// ConfidenceHigh from a literal read.
//
// securityHeaders returns the list of header checks. Implemented headers:
// Strict-Transport-Security (presence + max-age depth), X-Content-Type-Options,
// X-Frame-Options, Content-Security-Policy (presence + directive depth),
// Server, X-Powered-By, and the modern set (Referrer-Policy,
// Permissions-Policy, Cross-Origin-{Opener,Embedder,Resource}-Policy).
func securityHeaders(endpoint string) []headerCheck {
	return []headerCheck{
		{
			Name:     "Strict-Transport-Security",
			Severity: models.SeverityMedium,
			Category: "headers",
			Check: func(value string) *ev.Evidence {
				return checkHSTS(endpoint, value)
			},
		},
		{
			Name:     "X-Content-Type-Options",
			Severity: models.SeverityLow,
			Category: "headers",
			Check: func(value string) *ev.Evidence {
				if strings.ToLower(value) != "nosniff" {
					return &ev.Evidence{
						Title:             "Missing or incorrect X-Content-Type-Options header",
						Severity:          models.SeverityLow,
						Source:            models.SourceBlackbox,
						Category:          "headers",
						Endpoint:          endpoint,
						Evidence:          fmt.Sprintf("X-Content-Type-Options: %q (expected 'nosniff')", value),
						Fix:               "Add header: X-Content-Type-Options: nosniff",
						References:        []string{"CWE-693"},
						Confidence:        models.ConfidenceHigh,
						DirectObservation: true,
					}
				}
				return nil
			},
		},
		{
			Name:         "X-Frame-Options",
			Severity:     models.SeverityLow,
			Category:     "headers",
			DocumentOnly: true,
			Check: func(value string) *ev.Evidence {
				v := strings.ToUpper(value)
				if v != "DENY" && v != "SAMEORIGIN" {
					return &ev.Evidence{
						Title:             "Missing or incorrect X-Frame-Options header",
						Severity:          models.SeverityLow,
						Source:            models.SourceBlackbox,
						Category:          "headers",
						Endpoint:          endpoint,
						Evidence:          fmt.Sprintf("X-Frame-Options: %q (expected 'DENY' or 'SAMEORIGIN')", value),
						Fix:               "Add header: X-Frame-Options: DENY",
						References:        []string{"CWE-1021"},
						Confidence:        models.ConfidenceHigh,
						DirectObservation: true,
					}
				}
				return nil
			},
		},
		{
			Name:         "Content-Security-Policy",
			Severity:     models.SeverityMedium,
			Category:     "headers",
			DocumentOnly: true,
			Check: func(value string) *ev.Evidence {
				return checkCSP(endpoint, value)
			},
		},
		{
			Name:     "Server",
			Severity: models.SeverityInfo,
			Category: "headers",
			Check: func(value string) *ev.Evidence {
				if value != "" && containsVersion(value) {
					return &ev.Evidence{
						Title:             "Server version disclosed in header",
						Severity:          models.SeverityInfo,
						Source:            models.SourceBlackbox,
						Category:          "headers",
						Endpoint:          endpoint,
						Evidence:          fmt.Sprintf("Server: %s", value),
						Fix:               "Remove version information from Server header or remove the header entirely",
						References:        []string{"CWE-200"},
						Confidence:        models.ConfidenceHigh,
						DirectObservation: true,
					}
				}
				return nil
			},
		},
		{
			Name:     "X-Powered-By",
			Severity: models.SeverityInfo,
			Category: "headers",
			Check: func(value string) *ev.Evidence {
				if value != "" {
					return &ev.Evidence{
						Title:             "X-Powered-By header discloses technology",
						Severity:          models.SeverityInfo,
						Source:            models.SourceBlackbox,
						Category:          "headers",
						Endpoint:          endpoint,
						Evidence:          fmt.Sprintf("X-Powered-By: %s", value),
						Fix:               "Remove the X-Powered-By header",
						References:        []string{"CWE-200"},
						Confidence:        models.ConfidenceHigh,
						DirectObservation: true,
					}
				}
				return nil
			},
		},
		// 4.10: modern security headers. Absent (or, for Referrer-Policy,
		// the dangerous "unsafe-url") is flagged LOW/Info — these harden a
		// site's privacy + cross-origin isolation posture.
		{
			Name:     "Referrer-Policy",
			Severity: models.SeverityLow,
			Category: "headers",
			Check: func(value string) *ev.Evidence {
				v := strings.ToLower(strings.TrimSpace(value))
				if v == "" || v == "unsafe-url" {
					sev := models.SeverityLow
					evidence := "Response does not include Referrer-Policy header"
					if v == "unsafe-url" {
						evidence = "Referrer-Policy: unsafe-url (leaks full URL cross-origin)"
					}
					return &ev.Evidence{
						Title:             "Missing Referrer-Policy header",
						Severity:          sev,
						Source:            models.SourceBlackbox,
						Category:          "headers",
						Endpoint:          endpoint,
						Evidence:          evidence,
						Fix:               "Add header: Referrer-Policy: no-referrer or strict-origin-when-cross-origin",
						References:        []string{"CWE-200"},
						Confidence:        models.ConfidenceHigh,
						DirectObservation: true,
					}
				}
				return nil
			},
		},
		{
			Name:         "Permissions-Policy",
			Severity:     models.SeverityInfo,
			Category:     "headers",
			DocumentOnly: true,
			Check: func(value string) *ev.Evidence {
				if value == "" {
					return &ev.Evidence{
						Title:             "Missing Permissions-Policy header",
						Severity:          models.SeverityInfo,
						Source:            models.SourceBlackbox,
						Category:          "headers",
						Endpoint:          endpoint,
						Evidence:          "Response does not include Permissions-Policy header",
						Fix:               "Add a Permissions-Policy header to restrict powerful browser features (geolocation, camera, etc.)",
						References:        []string{"CWE-693"},
						Confidence:        models.ConfidenceHigh,
						DirectObservation: true,
					}
				}
				return nil
			},
		},
		// COOP and COEP isolate a BROWSING CONTEXT — they have meaning only
		// where a document is rendered. CORP is deliberately NOT document-only:
		// it governs whether a resource may be embedded cross-origin at all,
		// which is exactly the protection a JSON endpoint wants.
		missingHeaderInfo(endpoint, "Cross-Origin-Opener-Policy",
			"Add header: Cross-Origin-Opener-Policy: same-origin", true),
		missingHeaderInfo(endpoint, "Cross-Origin-Embedder-Policy",
			"Add header: Cross-Origin-Embedder-Policy: require-corp", true),
		missingHeaderInfo(endpoint, "Cross-Origin-Resource-Policy",
			"Add header: Cross-Origin-Resource-Policy: same-origin", false),
	}
}

// missingHeaderInfo builds a headerCheck that emits an Info finding when
// the named header is entirely absent. Used for the Cross-Origin-*
// isolation headers (4.10).
func missingHeaderInfo(endpoint, name, fix string, documentOnly bool) headerCheck {
	return headerCheck{
		Name:         name,
		Severity:     models.SeverityInfo,
		Category:     "headers",
		DocumentOnly: documentOnly,
		Check: func(value string) *ev.Evidence {
			if value == "" {
				return &ev.Evidence{
					Title:             fmt.Sprintf("Missing %s header", name),
					Severity:          models.SeverityInfo,
					Source:            models.SourceBlackbox,
					Category:          "headers",
					Endpoint:          endpoint,
					Evidence:          fmt.Sprintf("Response does not include %s header", name),
					Fix:               fix,
					References:        []string{"CWE-693"},
					Confidence:        models.ConfidenceHigh,
					DirectObservation: true,
				}
			}
			return nil
		},
	}
}

// checkHSTS implements HSTS presence + max-age depth (4.9). Absent →
// "Missing" MEDIUM; max-age=0 or missing max-age directive →
// "HSTS disabled" MEDIUM; max-age < 180 days → "too short" LOW.
func checkHSTS(endpoint, value string) *ev.Evidence {
	if value == "" {
		return &ev.Evidence{
			RuleID:            "headers/Strict-Transport-Security/missing",
			Title:             "Missing Strict-Transport-Security header",
			Severity:          models.SeverityMedium,
			Source:            models.SourceBlackbox,
			Category:          "headers",
			Endpoint:          endpoint,
			Evidence:          "Response does not include Strict-Transport-Security header",
			Fix:               "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
			References:        []string{"CWE-319"},
			Confidence:        models.ConfidenceHigh,
			DirectObservation: true,
		}
	}

	const minMaxAge = 15552000 // 180 days
	maxAge, hasMaxAge := parseHSTSMaxAge(value)

	if !hasMaxAge || maxAge == 0 {
		return &ev.Evidence{
			RuleID:            "headers/Strict-Transport-Security/disabled",
			Title:             "HSTS disabled",
			Severity:          models.SeverityMedium,
			Source:            models.SourceBlackbox,
			Category:          "headers",
			Endpoint:          endpoint,
			Evidence:          fmt.Sprintf("Strict-Transport-Security: %q (max-age is 0 or absent — HSTS not enforced)", value),
			Fix:               "Set a non-zero max-age, e.g. Strict-Transport-Security: max-age=31536000; includeSubDomains",
			References:        []string{"CWE-319"},
			Confidence:        models.ConfidenceHigh,
			DirectObservation: true,
		}
	}
	if maxAge < minMaxAge {
		return &ev.Evidence{
			RuleID:            "headers/Strict-Transport-Security/max-age-too-short",
			Title:             "HSTS max-age too short",
			Severity:          models.SeverityLow,
			Source:            models.SourceBlackbox,
			Category:          "headers",
			Endpoint:          endpoint,
			Evidence:          fmt.Sprintf("Strict-Transport-Security: %q (max-age=%d < 180 days)", value, maxAge),
			Fix:               "Increase max-age to at least 15552000 (180 days); 31536000 (1 year) is recommended",
			References:        []string{"CWE-319"},
			Confidence:        models.ConfidenceHigh,
			DirectObservation: true,
		}
	}
	return nil
}

// parseHSTSMaxAge extracts the max-age directive value from an HSTS
// header. Returns (seconds, true) when a max-age directive is present,
// (0, false) when it is absent or unparseable.
func parseHSTSMaxAge(value string) (int64, bool) {
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(strings.ToLower(part), "max-age") {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		raw := strings.TrimSpace(part[eq+1:])
		raw = strings.Trim(raw, `"`)
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// checkCSP implements CSP presence + directive depth (4.8). Absent →
// "Missing" MEDIUM (unchanged). Present-but-weak → "Weak
// Content-Security-Policy": unsafe-inline/unsafe-eval or a wildcard
// source in script-src/default-src is MEDIUM; missing BOTH default-src
// AND script-src is LOW.
func checkCSP(endpoint, value string) *ev.Evidence {
	if value == "" {
		return &ev.Evidence{
			RuleID:            "headers/Content-Security-Policy/missing",
			Title:             "Missing Content-Security-Policy header",
			Severity:          models.SeverityMedium,
			Source:            models.SourceBlackbox,
			Category:          "headers",
			Endpoint:          endpoint,
			Evidence:          "Response does not include Content-Security-Policy header",
			Fix:               "Add a Content-Security-Policy header with appropriate directives",
			References:        []string{"CWE-693"},
			Confidence:        models.ConfidenceHigh,
			DirectObservation: true,
		}
	}

	weakness, severity := analyzeCSP(value)
	if weakness == "" {
		return nil
	}
	return &ev.Evidence{
		RuleID:     "headers/Content-Security-Policy/weak",
		Title:      "Weak Content-Security-Policy",
		Severity:   severity,
		Source:     models.SourceBlackbox,
		Category:   "headers",
		Endpoint:   endpoint,
		Evidence:   fmt.Sprintf("Content-Security-Policy: %s — %s", value, weakness),
		Fix:        "Remove 'unsafe-inline'/'unsafe-eval' and wildcard sources; define an explicit default-src/script-src allowlist",
		References: []string{"CWE-693"},
		Confidence: models.ConfidenceMedium,
	}
}

// analyzeCSP parses a CSP directive string and returns a human-readable
// weakness description plus its severity, or ("", "") if the policy is
// acceptable. Source-controlling directives examined: default-src,
// script-src.
func analyzeCSP(value string) (string, models.Severity) {
	directives := map[string]string{}
	for _, d := range strings.Split(value, ";") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		fields := strings.Fields(d)
		name := strings.ToLower(fields[0])
		rest := ""
		if len(fields) > 1 {
			rest = strings.ToLower(strings.Join(fields[1:], " "))
		}
		directives[name] = rest
	}

	scriptControlling := []string{"script-src", "default-src"}
	for _, name := range scriptControlling {
		src, ok := directives[name]
		if !ok {
			continue
		}
		if strings.Contains(src, "'unsafe-inline'") || strings.Contains(src, "'unsafe-eval'") {
			return fmt.Sprintf("%s allows 'unsafe-inline'/'unsafe-eval'", name), models.SeverityMedium
		}
		for _, tok := range strings.Fields(src) {
			if tok == "*" || tok == "http:" || tok == "https:" {
				return fmt.Sprintf("%s uses a wildcard source (%s)", name, tok), models.SeverityMedium
			}
		}
	}

	_, hasDefault := directives["default-src"]
	_, hasScript := directives["script-src"]
	if !hasDefault && !hasScript {
		return "no default-src or script-src directive defined", models.SeverityLow
	}
	return "", ""
}

// versionTokenRe matches a real version token anywhere in the FULL
// header value: a digit-group followed by a dot and another digit-group
// (e.g. "1.21", "2.4"), preceded by a separator (' ' or '/'), start of
// string, or an optional 'v' prefix. Requiring two dot-separated numeric
// groups avoids the old byte-scan's FPs on benign values that merely
// contained "N." or "/N" and lets the final byte be reached (the old
// loop bound len-1 could not).
//
// 4.7: compiled once at package scope. Linear, no backtracking.
var versionTokenRe = regexp.MustCompile(`(?:[ /]|^)v?\d+\.\d+`)

// containsVersion reports whether a header value discloses a real
// product/version token.
func containsVersion(value string) bool {
	return versionTokenRe.MatchString(value)
}

// headersCheck implements the Check interface for the security-header
// scanner. Structural adapter — Run holds the unchanged body of the
// historical CheckHeaders free function. (Distinct from the singular
// headerCheck struct above, which describes a single header rule.)
type headersCheck struct{}

func (headersCheck) Name() string                        { return "headers" }
func (headersCheck) Category() string                    { return "headers" }
func (headersCheck) Tier() Tier                          { return TierPassive }
func (headersCheck) Enabled(cfg *models.ScanConfig) bool { return true }

// CheckHeaders sends a GET request and checks for missing/misconfigured security headers.
func CheckHeaders(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []ev.Evidence {
	return headersCheck{}.Run(ctx, NewCheckContext(cfg), endpoint)
}

// Run holds the unchanged security-header detection body. Outbound
// requests go through the shared SSRF-guarded follow-redirect client
// (cc.Client); the per-job deadline comes from ctx (runCheck).
func (headersCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []ev.Evidence {
	cfg := cc.Cfg
	client := cc.Client

	method := endpoint.Method
	if method == "" {
		method = "GET"
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.FullURL, nil)
	if err != nil {
		logagg.Warn("headers", "headers check: failed to create request", "url", endpoint.FullURL, "error", err)
		return nil
	}

	cfg.Auth.ApplyToRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		logagg.Warn("headers", "headers check: request failed", "url", endpoint.FullURL, "error", err)
		return nil
	}
	defer resp.Body.Close()

	// 4.11: narrow the skip. Transport-level security headers
	// (HSTS/CSP/etc.) are app-wide regardless of auth, so 401/403
	// responses must still be evaluated — suppressing them was a FN.
	// We skip only "this resource isn't here" (404/410) and server
	// faults (5xx), where headers are framework-controlled noise.
	// (TASK-123 / FP corpus pattern P2: juice-shop /.env.local 404.)
	if resp.StatusCode == http.StatusNotFound ||
		resp.StatusCode == http.StatusGone ||
		resp.StatusCode >= 500 {
		slog.Debug("headers check skipped (404/410/5xx response)",
			"endpoint", fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path),
			"status", resp.StatusCode)
		return nil
	}

	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)
	checks := securityHeaders(epLabel)

	// Resolved once for the response, not per check: every DocumentOnly header
	// is answering the same question about the same body.
	isDocument, renderingKnown := classifyDocumentRendering(resp.Header.Get("Content-Type"))

	var findings []ev.Evidence
	for _, hc := range checks {
		value := resp.Header.Get(hc.Name)
		if finding := hc.Check(value); finding != nil {
			// A browser-document header on a response the browser parses as
			// DATA. The header really is absent — that observation is true and
			// is kept, at the same rule id and endpoint, with its evidence and
			// fix intact — but a JSON payload has no DOM to inject into, no
			// frame to be nested in and no browsing context to isolate, so
			// reporting it at a weight that implies a missing protection
			// describes a control that had nothing to control.
			//
			// Gated on renderingKnown, so this fires ONLY when the media type
			// positively says "data". An absent or unrecognised Content-Type
			// leaves the finding exactly as it was: not knowing what a response
			// is must never be spent as a reason to care less about it.
			if hc.DocumentOnly && renderingKnown && !isDocument {
				finding.Severity = models.SeverityInfo
				finding.Evidence += fmt.Sprintf(
					" Context: this response is %s, which a browser parses as data rather than "+
						"rendering as a document, so this header would not have applied to it. "+
						"Reported for completeness; it is not a missing protection for this endpoint.",
					resp.Header.Get("Content-Type"))
			}
			// B4: tag lower-confidence context so the scorer de-escalates —
			// evidence preserved, not suppressed. Two cases apply here:
			//   "4xx"          an auth-gated / client-error response (the
			//                  response an unauthenticated browser probe sees).
			//   "static-asset" a CDN/static-middleware-served file, where an
			//                  app-layer header expectation is a weak signal.
			// The header IS genuinely absent in both cases — that observation
			// is real, so the finding stays; only its confidence drops.
			if respContext := responseContextFor(resp.StatusCode, endpoint.Path); respContext != "" {
				finding.ResponseContext = respContext
			}
			// Identity for a blackbox finding is category + rule + endpoint.
			// With no rule, all eleven header checks at one endpoint collapse
			// into ONE record, so suppressing "missing CSP" silently
			// suppresses "missing HSTS" and every sibling with it. The header
			// this check is about is the rule.
			//
			// Only filled when empty: a check whose single header yields more
			// than one distinct claim (HSTS present-but-disabled versus
			// max-age-too-short) sets its own finer id, and that must win.
			if finding.RuleID == "" {
				finding.RuleID = "headers/" + hc.Name
			}
			findings = append(findings, *finding)
		}
	}

	slog.Debug("headers check complete", "endpoint", epLabel, "findings", len(findings))
	return findings
}

// httpResponseContext and the static-asset classifier now live together in
// responsecontext.go so every check resolves B4 context the same way.
