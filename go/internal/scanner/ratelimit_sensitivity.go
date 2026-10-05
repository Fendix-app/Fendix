package scanner

import (
	"net/http"
	"strings"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// abuseSensitivity grades how much an UNLIMITED operation is worth abusing.
//
// It exists because "no rate limiting observed" is one observation with wildly
// different consequences. On a login endpoint it is the precondition for
// credential stuffing; on an authenticated list endpoint it is a capacity note.
// Emitting both at the same severity — which is what a flat MEDIUM did — makes
// a 700-endpoint scan produce one enormous WARN that implies equal urgency
// everywhere, and a reader who cannot see which of those endpoints matters
// treats the whole group as noise.
//
// This grades the CONSEQUENCE. It never changes the observation, the bounded
// "within N requests" claim, or the scope disclaimers: the probe result is
// identical either way, and nothing is dropped. Only the effective risk moves.
type abuseSensitivity int

const (
	// abuseOrdinary — a normal operation. Abuse costs the attacker as much as
	// the target. INFO.
	abuseOrdinary abuseSensitivity = iota
	// abuseElevated — abuse has a real cost: it sends mail, burns quota,
	// renders documents, or runs an expensive query.
	abuseElevated
	// abuseCredential — an authentication or identity gateway. Unlimited
	// attempts here mean credential stuffing, OTP brute force, enumeration or
	// invitation spam. The canonical rate-limiting defect.
	abuseCredential
)

// severity maps a sensitivity class to the finding's severity.
//
// MEDIUM keeps a finding actionable-but-non-blocking under the default
// --fail-on HIGH, which is the right weight for a bounded-burst observation:
// it never proves a slower limiter is missing, so it should never gate a build
// on its own. INFO is for operations where the absence is a capacity fact
// rather than a security one.
func (a abuseSensitivity) severity() models.Severity {
	if a == abuseOrdinary {
		return models.SeverityInfo
	}
	return models.SeverityMedium
}

// credentialParamTokens are parameter names that identify an authentication or
// identity operation REGARDLESS of what the route is called.
//
// This is the semantic signal and it is checked first, because it survives
// naming conventions a route-token list cannot anticipate: an endpoint that
// accepts `password` is an authentication endpoint whether it is spelled
// /login, /sessions, /v2/auth/pw or /gateway/entrar.
//
// Every entry is a COMPOUND or an unambiguous credential noun. Bare "token" and
// bare "code" are deliberately absent — pagination tokens and country codes are
// everywhere, and matching them would reclassify half of an ordinary API as an
// authentication surface, which is the same noise problem in a new place.
var credentialParamTokens = []string{
	"password", "passwd", "passphrase",
	"new_password", "current_password", "old_password", "password_confirmation",
	"otp", "totp", "mfa", "2fa", "mfa_code", "otp_code",
	"verification_code", "confirmation_code", "activation_code",
	"recovery_code", "backup_code",
	"reset_token", "recovery_token", "invite_token", "invitation_token",
	"confirmation_token", "activation_token", "magic_link", "magiclink",
	"refresh_token", "client_secret", "api_secret",
}

// credentialPathTokens are path SEGMENTS that name an authentication or
// identity operation. Scoped fallback for when parameters were never
// discovered — a crawled endpoint often has no known parameter list at all.
//
// Matched against whole, separator-split segments, never as substrings: a
// substring match would classify /api/authors as authentication (it contains
// "auth") and /resetting-expectations as a password reset.
var credentialPathTokens = []string{
	"login", "signin", "logon", "authenticate", "authentication", "auth",
	"session", "sessions", "token", "tokens", "oauth", "oauth2", "sso", "saml",
	"otp", "totp", "mfa", "2fa", "challenge",
	"register", "registration", "signup", "onboard",
	"password", "passwords", "forgot", "reset", "recover", "recovery",
	"verify", "verification", "confirm", "confirmation", "activate", "activation",
	"resend", "invite", "invites", "invitation", "invitations",
	"magiclink", "credentials",
}

// readAbusableCredentialTokens is the subset of credentialPathTokens that stays
// abuse-sensitive under a READ.
//
// The distinction matters. `POST /sessions` is a login; `GET /sessions` lists
// the sessions a user already has, which is an ordinary read. But
// `GET /verify-email?token=…` and `GET /invitations/accept` really are
// identity operations driven by a link in an email, and an unlimited one is
// brute-forceable. Only those stay credential-grade on a read.
var readAbusableCredentialTokens = []string{
	"verify", "verification", "confirm", "confirmation", "activate", "activation",
	"resend", "otp", "totp", "mfa", "2fa",
	"reset", "recover", "recovery", "invite", "invites", "invitation",
	"invitations", "magiclink",
}

// expensiveTokens name operations whose abuse costs the TARGET real money or
// capacity — mail and SMS delivery, document rendering, bulk export, search.
// Unlimited access to these is a billing and availability problem even when no
// credential is involved.
var expensiveTokens = []string{
	"export", "exports", "report", "reports", "download", "downloads",
	"search", "query", "upload", "uploads", "import", "imports",
	"bulk", "batch", "generate", "render", "pdf", "csv", "xlsx",
	"email", "emails", "mail", "sms", "notify", "notification", "notifications",
	"message", "messages", "invoice", "invoices", "webhook", "webhooks",
	"subscribe", "contact", "feedback", "share", "invitecode",
}

// classifyAbuseSensitivity grades one operation and returns the class together
// with the SIGNAL that produced it.
//
// The reason string is returned rather than derived later so the finding can
// state, in its own evidence text, why it was graded the way it was. A grading
// a reader cannot audit is exactly the kind of opaque scoring this engine's
// decision layer exists to avoid.
//
// probeMethod (not endpoint.Method) is the verb the check ACTUALLY sent, so the
// read/write distinction below describes the request that produced the
// observation rather than one that was never issued.
func classifyAbuseSensitivity(endpoint Endpoint, probeMethod string) (abuseSensitivity, string) {
	segments := pathSegments(endpoint.Path)
	write := isWriteMethod(probeMethod)

	// 1. Parameter semantics — strongest and naming-independent.
	if name, ok := matchesAnyToken(endpointParamNames(endpoint), credentialParamTokens); ok {
		return abuseCredential, "handles the credential parameter " + name
	}

	// 2. Route semantics — scoped fallback, whole segments only.
	if seg, ok := matchesAnyToken(segments, credentialPathTokens); ok {
		if write {
			return abuseCredential, "authentication/identity operation (path segment " + seg + ", write method)"
		}
		if _, readAbusable := matchesAnyToken([]string{seg}, readAbusableCredentialTokens); readAbusable {
			return abuseCredential, "link-driven identity operation (path segment " + seg + ")"
		}
		// A read against an identity NOUN (GET /sessions, GET /tokens) is an
		// ordinary listing. Fall through rather than claim otherwise.
	}

	// 3. Operation cost, modulated by authentication context.
	if seg, ok := matchesAnyToken(segments, expensiveTokens); ok {
		// Only a POSITIVE declaration de-escalates. AuthExpectationRequired
		// comes from a source of truth saying the operation is gated, which
		// genuinely raises the cost of abusing it. AuthExpectationUnknown —
		// what every crawled endpoint carries — must NOT be read as "probably
		// authenticated"; absence of a declaration is not evidence of a
		// control, and treating it as one is how a scanner talks itself out of
		// real findings.
		if endpoint.AuthExpectation == models.AuthExpectationRequired {
			return abuseOrdinary, "expensive operation (" + seg + ") behind a declared authentication requirement"
		}
		return abuseElevated, "expensive operation (" + seg + ") without a declared authentication requirement"
	}

	return abuseOrdinary, "ordinary operation with no abuse-sensitive parameters or route semantics"
}

// isWriteMethod reports whether the verb changes state. OPTIONS/HEAD/GET are
// reads per RFC 9110 §9.2.1; anything else is treated as a write, which is the
// conservative direction for a sensitivity grade.
func isWriteMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, "":
		return false
	default:
		return true
	}
}

// pathSegments turns a URL path into lowercase comparison tokens.
//
// Each '/'-delimited segment yields BOTH forms, because either can be the
// meaningful one:
//
//	"sign-in"        → "signin" (joined) + "sign", "in" (parts)
//	"reset-password" → "resetpassword"   + "reset", "password"
//
// The joined form is what matches a token spelled as one word ("signin"); the
// parts are what match a compound built from ordinary words ("password").
// Emitting only one of the two would miss whichever convention the target
// happens to use, and separator style is not something a scanner gets to
// assume.
//
// Path PARAMETERS ({id}, :id) are dropped — placeholders, not semantics.
func pathSegments(path string) []string {
	var out []string
	for _, raw := range strings.Split(path, "/") {
		seg := strings.ToLower(strings.TrimSpace(raw))
		if seg == "" || strings.HasPrefix(seg, "{") || strings.HasPrefix(seg, ":") {
			continue
		}
		parts := strings.FieldsFunc(seg, func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		})
		// Joined form first, so a whole-word token wins the reason string over
		// one of its fragments.
		if len(parts) > 1 {
			out = append(out, strings.Join(parts, ""))
		}
		out = append(out, parts...)
	}
	return out
}

// endpointParamNames collects every parameter name known for an operation:
// query, header and body. Discovery sources that never learned an operation's
// parameters return an empty list, which correctly contributes no signal.
func endpointParamNames(endpoint Endpoint) []string {
	names := make([]string, 0, len(endpoint.Params)+len(endpoint.BodyParams))
	for _, p := range endpoint.Params {
		names = append(names, normalizeParamName(p))
	}
	for _, p := range endpoint.BodyParams {
		names = append(names, normalizeParamName(p))
	}
	return names
}

// normalizeParamName lowercases a parameter and strips the separators that
// distinguish new_password from newPassword from new-password, so one token
// list covers every casing convention a real API might use.
func normalizeParamName(p string) string {
	return strings.NewReplacer("-", "_", ".", "_", " ", "_").Replace(strings.ToLower(strings.TrimSpace(p)))
}

// matchesAnyToken reports the first (candidate, token) pair that matches, using
// EXACT equality after normalization — plus an underscore-insensitive compare so
// "newpassword" matches the "new_password" token.
//
// Exact matching is the whole point: substring matching is what turns /api/
// authors into an authentication endpoint, and a sensitivity grade that fires
// on coincidental spelling is worse than no grade at all.
func matchesAnyToken(candidates, tokens []string) (string, bool) {
	for _, c := range candidates {
		if c == "" {
			continue
		}
		squashed := strings.ReplaceAll(c, "_", "")
		for _, t := range tokens {
			if c == t || squashed == strings.ReplaceAll(t, "_", "") {
				return c, true
			}
		}
	}
	return "", false
}
