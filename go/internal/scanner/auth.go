package scanner

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/logagg"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// corroborationFloor is the minimum unauth/tampered-response body length
// (bytes) that lifts an auth-bypass finding from MEDIUM to HIGH confidence.
// A status code alone is a weak signal (a 200 with an empty body or a
// generic page can be a soft-fail); a non-trivial body on a 2xx response
// corroborates that the endpoint actually served protected content to the
// unauthenticated/tampered request. See fix 3.3.
const corroborationFloor = 16

// bodyPeekLimit bounds how many response-body bytes we read for the
// corroboration check so a hostile/huge response can't blow up memory.
const bodyPeekLimit = 4096

// The two titles checkUnauthenticated can emit for the SAME live observation
// (HTTP 2xx with no credentials). Which one applies is decided entirely by
// Endpoint.AuthExpectation — see checkUnauthenticated.
//
// Named constants rather than string literals because the JWT-probe dedup, the
// scanner tests and the integration tests all key off the title; before RC-2
// they each carried their own copy of it, so changing the claim meant hunting
// fourteen literals.
const (
	// authTitleObserved — a 2xx with no credentials where nothing established
	// that authentication was expected. An observation, not a confirmed bypass.
	authTitleObserved = "Unauthenticated endpoint observed"
	// authTitleBypassed — the same observation where a source of truth DID
	// declare a requirement, so the live result contradicts it.
	authTitleBypassed = "Authentication requirement bypassed"
)

// authCheck implements the Check interface for the authentication
// scanner. Structural adapter — Run holds the unchanged body of the
// historical CheckAuth free function.
type authCheck struct{}

func (authCheck) Name() string     { return "auth" }
func (authCheck) Category() string { return "auth_bypass" }
func (authCheck) Tier() Tier       { return TierAuth }
func (authCheck) Enabled(cfg *models.ScanConfig) bool {
	return cfg != nil && cfg.Auth != nil
}

// CheckAuth runs authentication checks on an endpoint.
// When auth is configured, it tests: unauthenticated access, malformed JWT,
// expired JWT, and alg:none JWT confusion.
func CheckAuth(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []ev.Evidence {
	return authCheck{}.Run(ctx, NewCheckContext(cfg), endpoint)
}

// Run holds the unchanged auth detection body. Outbound requests go
// through the shared SSRF-guarded no-follow client (cc.NoFollow), which
// returns the raw 3xx (CheckRedirect: ErrUseLastResponse) so a redirect
// to a login page reads as "auth enforced". The per-job deadline comes
// from ctx (runCheck).
func (authCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []ev.Evidence {
	cfg := cc.Cfg
	if cfg.Auth == nil {
		return nil
	}

	client := cc.NoFollow

	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)
	var findings []ev.Evidence

	missingAuth := checkUnauthenticated(ctx, client, cfg, endpoint, epLabel)
	if missingAuth != nil {
		findings = append(findings, *missingAuth)
	}

	// FP-dedup (Track 4 gap surfaced by TwiScope-backend /metrics scan).
	//
	// When the endpoint accepts a request with NO Authorization header
	// AND also accepts a request with a syntactically-invalid header
	// (e.g. "Bearer junk"), the auth handler isn't checking auth at
	// all — every JWT-bypass probe (malformed / expired / alg:none)
	// will also return 200, but those findings are downstream byproducts
	// of the same root cause. Emitting them produces 4 CRITICALs on
	// every public endpoint (Prometheus /metrics, health checks, etc.)
	// when only the first one ("Missing authentication") is actionable.
	//
	// Posture: only suppress JWT-bypass probes when BOTH probes (no
	// auth + garbage auth) succeed. If garbage-auth is rejected but
	// the original missing-auth succeeded, the endpoint does some
	// header-presence check — the JWT-bypass probes are still
	// meaningful (the endpoint distinguishes "no header" from "bad
	// signature", but may still accept the structurally-valid bad
	// tokens). Other endpoints in the scan are unaffected.
	suppressJWTProbes := false
	if missingAuth != nil && isJWTAuth(cfg.Auth) {
		if endpointAcceptsGarbageAuth(ctx, client, cfg, endpoint) {
			suppressJWTProbes = true
			slog.Debug("auth check: suppressing JWT-bypass probes (endpoint is fully unauthenticated — accepts no-auth AND garbage-auth)",
				"endpoint", epLabel)
		}
	}

	if isJWTAuth(cfg.Auth) && !suppressJWTProbes {
		// Negative gate (fix 3.7): the JWT-bypass probes only mean
		// something if we can first establish that the REAL token works.
		// If the endpoint returns non-2xx even WITH the operator's valid
		// token (e.g. a 404 route, a 405 on the wrong method, or a 500),
		// then "tampered token also not accepted" is not a bypass — and
		// "tampered token accepted" can't be distinguished from the route
		// simply not gating on this auth value at all. Skip the suite.
		if realTokenAccepted(ctx, client, cfg, endpoint) {
			findings = append(findings, checkJWTBypasses(ctx, client, cfg, endpoint, epLabel)...)
		} else {
			slog.Debug("auth check: skipping JWT-bypass probes (real valid token did not yield 2xx — can't establish a working-auth baseline)",
				"endpoint", epLabel)
		}
	}

	slog.Debug("auth check complete", "endpoint", epLabel, "findings", len(findings))
	return findings
}

// realTokenAccepted sends a request carrying the operator's real,
// unmodified credential and reports whether the endpoint returns 2xx.
// This is the baseline for the JWT-bypass negative gate (fix 3.7): a
// tampered-token "bypass" is only meaningful relative to a route where
// the valid token is actually accepted. Network errors and non-2xx
// responses both return false (conservative — no baseline, no probes).
func realTokenAccepted(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint) bool {
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.FullURL, bodyForMethod(endpoint.Method))
	if err != nil {
		return false
	}
	setJSONContentType(req, endpoint.Method)
	cfg.Auth.ApplyToRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, bodyPeekLimit))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// endpointAcceptsGarbageAuth returns true if a request with an
// obviously-invalid credential still gets a 2xx response. Used by the
// FP-dedup logic above: an endpoint that 200s on both no-auth and a
// junk credential isn't checking auth at all, so JWT-bypass findings on
// it are downstream noise from the missing-auth root cause.
//
// The junk credential is injected through a tampered AuthContext
// (fix 3.5) so the value travels the SAME channel the real auth uses —
// cookie, query-string apikey, or a custom header — instead of being
// hardcoded onto the "Authorization" header. For body-accepting methods
// a minimal JSON body is sent (fix 3.2) so a 4xx from body validation
// doesn't get misread as an auth rejection.
//
// Network errors return false (conservative — keep the probe in play).
func endpointAcceptsGarbageAuth(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint) bool {
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.FullURL, bodyForMethod(endpoint.Method))
	if err != nil {
		return false
	}
	setJSONContentType(req, endpoint.Method)
	// Deliberately bogus value: no dots, no base64, no jwt shape. Routed
	// through a tampered AuthContext so it honors the configured channel.
	tamperedAuthWithToken(cfg.Auth, "fendix-auth-probe-not-a-real-token").ApplyToRequest(req)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, bodyPeekLimit))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// checkUnauthenticated sends a request without auth credentials.
// If the server returns 200 instead of 401/403, it's a CRITICAL finding.
func checkUnauthenticated(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, epLabel string) *ev.Evidence {
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.FullURL, bodyForMethod(endpoint.Method))
	if err != nil {
		logagg.Warn("auth", "auth check: failed to create unauthenticated request", "url", endpoint.FullURL, "error", err)
		return nil
	}
	setJSONContentType(req, endpoint.Method)

	resp, err := client.Do(req)
	if err != nil {
		logagg.Warn("auth", "auth check: unauthenticated request failed", "url", endpoint.FullURL, "error", err)
		return nil
	}
	defer resp.Body.Close()

	twoXX, bodyLen := readOutcome(resp)
	if !twoXX {
		return nil
	}

	// RC-2. The observation is identical in all three cases — HTTP 2xx with no
	// credentials. What differs is whether Fendix ESTABLISHED that
	// authentication was expected, and that is what decides whether this is a
	// confirmed bypass or merely an unauthenticated endpoint.
	//
	// Before this, every 2xx was "Missing authentication on endpoint" at
	// CRITICAL, so docs pages, health checks and SPA routes each produced a
	// CRITICAL that the decision layer then blocked on. The premise the claim
	// needs — "authentication was expected here" — was never supplied by
	// anything, and a status code cannot supply it.
	//
	// Nothing here is path-based. A /status the spec declares protected still
	// reports a bypass; an /api/admin the spec declares public does not. That
	// is the difference between a semantic fix and an allowlist, and
	// TestClassificationIsSemanticNotPathBased pins it.
	title, severity := authTitleObserved, models.SeverityMedium
	fix := "If this endpoint is intended to be public, declare it so in the API specification " +
		"(an explicit `security: []` on the operation). If it is not, require authentication and " +
		"return 401 for unauthenticated requests."
	detail := "; no authentication requirement was established for this operation " +
		"(no specification security requirement and no static route evidence), so this is an " +
		"observation, not a confirmed bypass"

	source := ""
	switch endpoint.AuthExpectation {
	case models.AuthExpectationRequired:
		title, severity = authTitleBypassed, models.SeverityCritical
		fix = "Require authentication. Return 401 for unauthenticated requests."
		detail = "; the API specification declares an authentication requirement for this " +
			"operation, and it was not enforced"
		source = "openapi"
	case models.AuthExpectationPublic:
		severity = models.SeverityInfo
		fix = "No action needed: the API specification declares this operation public."
		detail = "; the API specification declares this operation public, so anonymous access " +
			"is intentional"
		source = "openapi"
	}

	return &ev.Evidence{
		// ONE rule for both titles. "Unauthenticated endpoint observed" and
		// "Authentication requirement bypassed" are the same observation about
		// the same endpoint; what differs is whether a source of truth
		// established that authentication was expected. Learning that is
		// evidence ENRICHMENT, so the finding must keep the record it already
		// had rather than being filed as a new vulnerability — the same
		// invariant that lets "Potential SSRF" become "SSRF".
		RuleID:     "auth/unauthenticated-access",
		Title:      title,
		Severity:   severity,
		Source:     models.SourceBlackbox,
		Category:   "auth_bypass",
		Endpoint:   epLabel,
		Evidence:   fmt.Sprintf("HTTP %d returned without Authorization header%s", resp.StatusCode, detail),
		Fix:        fix,
		References: []string{"CWE-306", "OWASP-A01"},
		Confidence: confidenceFor(bodyLen),
		// Carried onto the evidence so the decision layer can count a
		// CONTRADICTED requirement as independent corroboration, and so the
		// exported result can show which of the three states applied.
		AuthExpectation:       endpoint.AuthExpectation,
		AuthExpectationSource: source,
	}
}

// isJWTAuth returns true only if the auth value carries a real JWT: after
// stripping an optional "Bearer " scheme prefix the value must split into
// exactly three dot-separated parts AND the first part must base64url-decode
// to a JSON object containing an "alg" key (the defining trait of a JOSE
// header). This rejects the prior 3-dot heuristic's false positives on
// non-JWT "a.b.c" values whose first segment isn't a JWT header, and on
// values whose first segment isn't even valid base64url/JSON (fix 3.6).
//
// 5-part values are JWE (encrypted JWTs); we can't tamper their claims
// black-box, so they're skipped with a debug log rather than treated as JWS.
func isJWTAuth(auth *models.AuthContext) bool {
	if auth == nil {
		return false
	}
	token := extractJWT(auth)
	parts := strings.Split(token, ".")

	if len(parts) == 5 {
		slog.Debug("auth check: credential looks like a JWE (5 parts) — skipping JWT-bypass probes (encrypted claims can't be tampered black-box)")
		return false
	}
	if len(parts) != 3 {
		return false
	}

	headerBytes, err := base64URLDecodeJWT(parts[0])
	if err != nil {
		return false
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}
	_, hasAlg := header["alg"]
	return hasAlg
}

// extractJWT pulls the raw JWT string out of an auth value, stripping a
// leading "Bearer " scheme prefix when present. For cookie-style values
// (`name=<jwt>`) it returns the value after the last `=` so the JWT itself
// is examined. Returns the trimmed value unchanged otherwise.
func extractJWT(auth *models.AuthContext) string {
	val := strings.TrimSpace(auth.Value)
	if strings.HasPrefix(strings.ToLower(val), "bearer ") {
		return strings.TrimSpace(val[7:])
	}
	// Cookie transport: value is `name=<token>` (or `a=x; b=<token>`); the
	// JWT, if any, is the value of the last name=value pair.
	if auth.Type == models.AuthTypeCookie || (strings.Contains(val, "=") && !strings.Contains(val, " ")) {
		if idx := strings.LastIndex(val, "="); idx >= 0 {
			return strings.TrimSpace(val[idx+1:])
		}
	}
	return val
}

// tamperedAuthWithToken returns a copy of orig that carries rawToken through
// the SAME transport channel as the real credential (fix 3.1 / 3.5). It
// never hardcodes a scheme prefix: the tampered value is built by replacing
// the JWT substring inside the real value (preserving any `Bearer ` /
// `name=` wrapping). When the real value has no embedded JWT (e.g. a plain
// API key), the token is wrapped to match the scheme — "Bearer <token>" for
// bearer, "<header>=<token>" for cookie, and the bare token for apikey /
// apikey-query / basic. The result is fed to ApplyToRequest by the caller,
// so cookie / query-string / custom-header schemes are all honored.
func tamperedAuthWithToken(orig *models.AuthContext, rawToken string) *models.AuthContext {
	tampered := *orig // shallow copy preserves Type + Header

	realJWT := extractJWT(orig)
	if isThreeOrFiveDot(realJWT) && strings.Contains(orig.Value, realJWT) {
		// Swap the real JWT in place, preserving whatever wrapping the
		// operator's value carried (Bearer prefix, cookie name=, etc.).
		tampered.Value = strings.Replace(orig.Value, realJWT, rawToken, 1)
		return &tampered
	}

	// No embedded JWT to swap — wrap rawToken to match the scheme.
	switch orig.Type {
	case models.AuthTypeCookie:
		name := "session"
		if v := strings.TrimSpace(orig.Value); v != "" {
			if idx := strings.Index(v, "="); idx > 0 {
				name = v[:idx]
			}
		}
		tampered.Value = name + "=" + rawToken
	case models.AuthTypeBearer:
		tampered.Value = "Bearer " + rawToken
	default:
		// apikey, apikey-query, basic: raw value, no prefix.
		tampered.Value = rawToken
	}
	return &tampered
}

func isThreeOrFiveDot(s string) bool {
	n := strings.Count(s, ".")
	return n == 2 || n == 4
}

// checkJWTBypasses tests three JWT-specific bypass scenarios:
// 1. Malformed JWT → server should reject with 401
// 2. Expired JWT → server should reject with 401
// 3. alg:none JWT confusion → server should reject with 401
func checkJWTBypasses(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, epLabel string) []ev.Evidence {
	var findings []ev.Evidence

	if f := checkMalformedJWT(ctx, client, cfg, endpoint, epLabel); f != nil {
		findings = append(findings, *f)
	}
	if f := checkExpiredJWT(ctx, client, cfg, endpoint, epLabel); f != nil {
		findings = append(findings, *f)
	}
	if f := checkAlgNoneJWT(ctx, client, cfg, endpoint, epLabel); f != nil {
		findings = append(findings, *f)
	}

	return findings
}

// sendTamperedJWT injects a tampered token through the real auth's channel
// (fix 3.1 / 3.5) and returns (is2xx, bodyLen) so callers can both decide
// whether the bypass succeeded and pick a corroborated confidence (fix 3.3).
// Returns (false, 0) on request-build or network error.
func sendTamperedJWT(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, token string) (bool, int) {
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.FullURL, bodyForMethod(endpoint.Method))
	if err != nil {
		return false, 0
	}
	setJSONContentType(req, endpoint.Method)
	tamperedAuthWithToken(cfg.Auth, token).ApplyToRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	return readOutcome(resp)
}

// checkMalformedJWT sends a request with a structurally-invalid JWT token.
func checkMalformedJWT(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, epLabel string) *ev.Evidence {
	twoXX, bodyLen := sendTamperedJWT(ctx, client, cfg, endpoint, "invalid.jwt.token")
	if twoXX {
		return &ev.Evidence{
			RuleID:     "auth/jwt-not-validated",
			Title:      "JWT not validated",
			Severity:   models.SeverityCritical,
			Source:     models.SourceBlackbox,
			Category:   "auth_bypass",
			Endpoint:   epLabel,
			Evidence:   "HTTP 2xx returned with malformed JWT 'invalid.jwt.token'",
			Fix:        "Validate JWT signature and structure on every request. Reject malformed tokens with 401.",
			References: []string{"CWE-287", "OWASP-A07"},
			Confidence: confidenceFor(bodyLen),
		}
	}
	return nil
}

// checkExpiredJWT generates a JWT with exp in the past and tests acceptance.
func checkExpiredJWT(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, epLabel string) *ev.Evidence {
	expiredToken := buildExpiredJWT(extractJWT(cfg.Auth))
	twoXX, bodyLen := sendTamperedJWT(ctx, client, cfg, endpoint, expiredToken)
	if twoXX {
		return &ev.Evidence{
			RuleID:     "auth/expired-jwt-accepted",
			Title:      "Expired JWT accepted",
			Severity:   models.SeverityCritical,
			Source:     models.SourceBlackbox,
			Category:   "auth_bypass",
			Endpoint:   epLabel,
			Evidence:   "HTTP 2xx returned with expired JWT (exp set to past)",
			Fix:        "Validate the 'exp' claim in JWT tokens. Reject expired tokens with 401.",
			References: []string{"CWE-613", "OWASP-A07"},
			Confidence: confidenceFor(bodyLen),
		}
	}
	return nil
}

// checkAlgNoneJWT sends a JWT with alg:none (no signature) to test for algorithm confusion.
func checkAlgNoneJWT(ctx context.Context, client *http.Client, cfg *models.ScanConfig, endpoint Endpoint, epLabel string) *ev.Evidence {
	algNoneToken := buildAlgNoneJWT(extractJWT(cfg.Auth))
	twoXX, bodyLen := sendTamperedJWT(ctx, client, cfg, endpoint, algNoneToken)
	if twoXX {
		return &ev.Evidence{
			RuleID:     "auth/jwt-alg-none",
			Title:      "JWT algorithm confusion (alg:none accepted)",
			Severity:   models.SeverityCritical,
			Source:     models.SourceBlackbox,
			Category:   "auth_bypass",
			Endpoint:   epLabel,
			Evidence:   "HTTP 2xx returned with alg:none JWT (unsigned token)",
			Fix:        "Explicitly whitelist allowed JWT algorithms. Never accept alg:none.",
			References: []string{"CWE-327", "OWASP-A02"},
			Confidence: confidenceFor(bodyLen),
		}
	}
	return nil
}

// readOutcome reads a bounded prefix of the response body and returns
// whether the status is 2xx along with the number of body bytes observed
// (capped at bodyPeekLimit). The body length feeds the confidence
// corroboration in confidenceFor (fix 3.3).
func readOutcome(resp *http.Response) (twoXX bool, bodyLen int) {
	twoXX = resp.StatusCode >= 200 && resp.StatusCode < 300
	if !twoXX {
		// Still drain (bounded) so the connection can be reused.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, bodyPeekLimit))
		return false, 0
	}
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, bodyPeekLimit))
	return true, int(n)
}

// confidenceFor maps an observed 2xx body length to a finding confidence
// (fix 3.3). A status code alone (empty/trivial body) is a weak corroborator
// → MEDIUM; a non-trivial body (>= corroborationFloor bytes) shows the
// endpoint actually served content to the unauthorized request → HIGH.
func confidenceFor(bodyLen int) models.Confidence {
	if bodyLen >= corroborationFloor {
		return models.ConfidenceHigh
	}
	return models.ConfidenceMedium
}

// bodyForMethod returns a minimal JSON request body for body-accepting
// methods (POST/PUT/PATCH) and nil otherwise (fix 3.2). POST/PUT endpoints
// that require a body 4xx on an empty one — without a body the auth decision
// is confounded by body validation, breaking the garbage-auth dedup and the
// bypass probes. The body is intentionally generic.
func bodyForMethod(method string) io.Reader {
	if methodAcceptsBody(method) {
		return strings.NewReader(`{"fendix":"fendix"}`)
	}
	return nil
}

// setJSONContentType stamps Content-Type: application/json on body-accepting
// methods so servers that branch on it parse the probe body we send.
// (methodAcceptsBody is defined in injection.go, same package.)
func setJSONContentType(req *http.Request, method string) {
	if methodAcceptsBody(method) {
		req.Header.Set("Content-Type", "application/json")
	}
}

// buildExpiredJWT returns a JWT whose exp claim is in the past.
//
// Best-effort black-box realism (fix 3.4): when realToken is itself a
// 3-part JWS, the payload is decoded, its exp is rewound one hour, and the
// payload is re-encoded while KEEPING the original header and signature.
// This specifically exercises the naive-validator bug where exp is checked
// WITHOUT re-verifying the signature over the (now-mutated) payload — a real
// class of vulnerability. When no real JWT is available, it falls back to a
// fully-synthetic HS256-signed token with a past exp (which only exercises
// servers that don't verify the signature at all, but is still a valid
// expired-token probe).
func buildExpiredJWT(realToken string) string {
	if h, p, _, ok := splitJWS(realToken); ok {
		if payload, ok := decodeClaims(p); ok {
			payload["exp"] = time.Now().Add(-1 * time.Hour).Unix()
			payload["iat"] = time.Now().Add(-2 * time.Hour).Unix()
			newPayload := base64URLEncode(mustJSON(payload))
			// Keep header + ORIGINAL signature: tests exp-without-resig.
			_, _, sig, _ := splitJWS(realToken)
			return h + "." + newPayload + "." + sig
		}
	}
	return buildSyntheticExpiredJWT()
}

// buildSyntheticExpiredJWT creates a HS256-signed JWT with exp 1 hour in the
// past. Fallback for buildExpiredJWT when no real JWT is available.
func buildSyntheticExpiredJWT() string {
	header := base64URLEncode(mustJSON(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}))

	payload := base64URLEncode(mustJSON(map[string]interface{}{
		"sub":  "fendix-test",
		"iat":  time.Now().Add(-2 * time.Hour).Unix(),
		"exp":  time.Now().Add(-1 * time.Hour).Unix(),
		"role": "user",
	}))

	signingInput := header + "." + payload
	sig := hmacSHA256([]byte(signingInput), []byte("secret"))

	return signingInput + "." + base64URLEncode(sig)
}

// buildAlgNoneJWT returns an unsigned JWT with alg:none.
//
// Best-effort black-box realism (fix 3.4): when realToken is a 3-part JWS,
// the alg:none token reuses the real header (with alg forced to "none") and
// the real payload, dropping the signature. Reusing the real claims makes
// the probe travel with a plausible subject/role/exp so a server that strips
// the alg check but otherwise trusts the claims is exercised faithfully.
// Falls back to a fully-synthetic alg:none token otherwise.
func buildAlgNoneJWT(realToken string) string {
	if h, p, _, ok := splitJWS(realToken); ok {
		if header, ok := decodeClaims(h); ok {
			header["alg"] = "none"
			newHeader := base64URLEncode(mustJSON(header))
			// Reuse the real payload verbatim; drop the signature.
			return newHeader + "." + p + "."
		}
	}
	return buildSyntheticAlgNoneJWT()
}

// buildSyntheticAlgNoneJWT creates an unsigned JWT with alg:none. Fallback
// for buildAlgNoneJWT when no real JWT is available.
func buildSyntheticAlgNoneJWT() string {
	header := base64URLEncode(mustJSON(map[string]string{
		"alg": "none",
		"typ": "JWT",
	}))

	payload := base64URLEncode(mustJSON(map[string]interface{}{
		"sub":  "fendix-test",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(1 * time.Hour).Unix(),
		"role": "admin",
	}))

	return header + "." + payload + "."
}

// splitJWS splits a compact JWS into (header, payload, signature, ok). ok is
// false unless the token has exactly 3 dot-separated parts with non-empty
// header and payload segments (the signature MAY be empty, e.g. alg:none).
func splitJWS(token string) (header, payload, sig string, ok bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// decodeClaims base64url-decodes a JWS segment and unmarshals it into a
// claims map. ok is false on decode/parse failure.
func decodeClaims(segment string) (map[string]interface{}, bool) {
	raw, err := base64URLDecodeJWT(segment)
	if err != nil {
		return nil, false
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, false
	}
	return claims, true
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// base64URLDecodeJWT decodes a (possibly unpadded) base64url JWT segment.
func base64URLDecodeJWT(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

// mustJSON marshals a value that is *statically* guaranteed to be
// json.Marshal-safe: every call site in this file passes a
// map[string]string or map[string]interface{} where the values are
// strings, int64 (from time.Unix), or other primitives. None of
// these shapes can fail json.Marshal in any Go release.
//
// We previously panicked here. That was correct in the sense that
// the error truly cannot happen, but a panic in a scanner that runs
// in CI as a non-root process surfaces as an exit-code-2 + stack
// trace, which is a worse end-user experience than emitting an
// empty payload and letting the JWT bypass probe still go out
// (where the receiving auth handler will reject it on its own
// merits). If json.Marshal ever does fail here, we log at error
// level and return an empty byte slice; the resulting probe is
// still a valid security-relevant request (a malformed JWT).
func mustJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// Defensive — see GoDoc above. Not reachable from any
		// current call site, but if a future call passes a
		// non-marshalable value (e.g. a channel) this keeps the
		// scanner alive instead of crash-exiting the whole process.
		slog.Error("auth: json.Marshal on a value that should be statically safe",
			"err", err,
			"hint", "review callers of mustJSON in scanner/auth.go")
		return []byte("{}")
	}
	return b
}

func hmacSHA256(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
