package scanner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/logagg"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

const maxEvidenceLen = 200

// exposurePattern defines a regex pattern to scan response bodies for
// sensitive data. When Guard is non-nil it receives the matched bytes
// plus the full response body and may veto the match (return false → not
// a finding); used to drop masked/placeholder values and i18n label
// tables that would otherwise FP.
type exposurePattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity models.Severity
	Title    string
	Fix      string
	CWE      string
	Guard    func(match, body []byte) bool
}

// 4.14: a real stack frame requires a dotted package/identifier path
// followed by a (file.ext:line) location. The file extension + ":digit"
// anchor is what separates a true frame from prose like "at home
// (tomorrow)". The Python/Go/Java framing markers stay as literals.
var stackFrameLocRe = `\([^)]*\.(?:java|kt|js|jsx|ts|tsx|scala|py|go|rb|php|cs|cpp|c|swift|rs):\d+`

var exposurePatterns = []exposurePattern{
	{
		Name:     "password_field",
		Pattern:  regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]+)"`),
		Severity: models.SeverityCritical,
		Title:    "Password exposed in API response",
		Fix:      "Never return password fields in API responses. Remove from serialization or use a DTO.",
		CWE:      "CWE-200",
		Guard:    passwordNotMasked,
	},
	{
		Name:     "secret_field",
		Pattern:  regexp.MustCompile(`(?i)"(?:secret|api_key|apikey|api_secret|client_secret|private_key)"\s*:\s*"[^"]{8,}"`),
		Severity: models.SeverityCritical,
		Title:    "Secret or API key exposed in API response",
		Fix:      "Remove secret fields from API responses. Use server-side references instead.",
		CWE:      "CWE-200",
	},
	{
		Name:     "token_field",
		Pattern:  regexp.MustCompile(`(?i)"(?:token|access_token|refresh_token)"\s*:\s*"[a-zA-Z0-9\-_.]{20,}"`),
		Severity: models.SeverityHigh,
		Title:    "Token exposed in API response",
		Fix:      "Avoid returning long-lived tokens in response bodies. Use secure HTTP-only cookies.",
		CWE:      "CWE-200",
	},
	// 4.13: value-shape secrets, independent of any JSON key name.
	{
		Name:     "jwt_value",
		Pattern:  regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
		Severity: models.SeverityHigh,
		Title:    "JWT exposed in API response",
		Fix:      "Do not return JWTs in response bodies where they aren't expected; treat as a credential leak and rotate signing keys if compromised.",
		CWE:      "CWE-200",
	},
	{
		Name:     "aws_access_key",
		Pattern:  regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`),
		Severity: models.SeverityCritical,
		Title:    "AWS access key exposed in API response",
		Fix:      "Rotate the exposed AWS access key immediately and remove it from the response.",
		CWE:      "CWE-200",
	},
	{
		Name:     "pem_private_key",
		Pattern:  regexp.MustCompile(`-----BEGIN[ A-Z]*PRIVATE KEY-----`),
		Severity: models.SeverityCritical,
		Title:    "Private key exposed in API response",
		Fix:      "Remove the private key from the response and rotate it immediately.",
		CWE:      "CWE-200",
	},
	{
		Name: "stack_trace",
		// 4.14: real stack frame (dotted path + file.ext:line) OR a known
		// framing marker. Tightened from the old "at IDENT(...)" which FP'd
		// on prose like "at home (today)".
		Pattern:  regexp.MustCompile(`(?:Traceback \(most recent call last\)|at [a-zA-Z0-9$_.<>]+\s*` + stackFrameLocRe + `|panic:|goroutine \d+|Exception in thread)`),
		Severity: models.SeverityMedium,
		Title:    "Stack trace in error response",
		Fix:      "Disable debug mode in production. Return generic error messages to clients.",
		CWE:      "CWE-209",
	},
	{
		Name: "internal_ip",
		// 4.14: \b-anchored with each octet constrained to 0-255 so it no
		// longer FPs on version strings ("10.20.30") or prices ("$192.168").
		Pattern:  regexp.MustCompile(`\b(?:10\.` + ipOctet + `\.` + ipOctet + `\.` + ipOctet + `|172\.(?:1[6-9]|2\d|3[01])\.` + ipOctet + `\.` + ipOctet + `|192\.168\.` + ipOctet + `\.` + ipOctet + `)\b`),
		Severity: models.SeverityLow,
		Title:    "Internal IP address disclosed in response",
		Fix:      "Remove internal IP addresses from API responses and error messages.",
		CWE:      "CWE-200",
	},
	{
		Name:     "version_string",
		Pattern:  regexp.MustCompile(`(?i)(?:version|ver)["\s]*[:=]\s*["']?\d+\.\d+\.\d+`),
		Severity: models.SeverityInfo,
		Title:    "Software version string in response",
		Fix:      "Consider removing version information from API responses.",
		CWE:      "CWE-200",
	},
}

// ipOctet matches a single dotted-quad octet constrained to 0-255.
const ipOctet = `(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`

// maskCharsRe matches a value that is composed entirely of a single
// masking character class (*, x/X, bullet, #), used by passwordNotMasked.
var maskCharsRe = regexp.MustCompile(`^(?:\*+|[xX]+|\x{2022}+|#+)$`)

// placeholderValues are well-known non-secret stand-ins.
var placeholderValues = map[string]struct{}{
	"redacted": {}, "hidden": {}, "null": {}, "not-set": {},
	"notset": {}, "changeme": {}, "***": {}, "n/a": {}, "none": {},
}

// passwordNotMasked vets the password_field match: returns false (drop the
// finding) only when EVERY `"password"` value in the body is a non-credential
// — empty, an all-mask string, a known placeholder, or an i18n/UI label inside
// a label dictionary. It returns true as soon as it finds one real credential,
// so a genuine leak is never suppressed on key-count alone, nor hidden behind a
// leading i18n label or a masked sibling (regexp.Find only ever hands the guard
// the *first* match, so the guard re-scans the body itself). 4.12, 4.15.
func passwordNotMasked(_, body []byte) bool {
	// i18n / UI-label dictionaries surface the *word* "password" (in many
	// languages) as translation strings — e.g. `"password":"Password"` or
	// `"password":"كلمة المرور"` — not a stored credential. A body carrying
	// several distinct "password"-family keys (passwordHint, forgotPassword,
	// …) is such a label table; a *label-shaped* value in it is a translation.
	// We require the value itself to look like a label before suppressing, so a
	// real credential sitting next to password-metadata columns
	// (password_changed_at, …) — or in a different object in the same body — is
	// never dropped just because the body has many password-named keys.
	inLabelDict := distinctPasswordKeys(body) >= labelDictMinKeys

	subs := passwordValueRe.FindAllSubmatch(body, -1)
	if len(subs) == 0 {
		return true // shouldn't happen (pattern already matched); fail open
	}
	for _, sub := range subs {
		val := strings.TrimSpace(string(sub[1]))
		if val == "" {
			continue
		}
		if maskCharsRe.MatchString(val) {
			continue
		}
		if _, ok := placeholderValues[strings.ToLower(val)]; ok {
			continue
		}
		if inLabelDict && labelLikeValue(val) {
			continue
		}
		return true // a real credential value — keep the finding
	}
	return false // every "password" value was masked / placeholder / label
}

// labelDictMinKeys is the number of distinct "password"-family keys at or above
// which the body is treated as an i18n/label table — so a *label-shaped*
// password value in it reads as a translation, not a credential. Two is enough:
// a genuine record rarely pairs the bare "password" key with a second
// password-family key whose value is *also* label-shaped, whereas a translation
// table always carries several. The value-shape gate (labelLikeValue) is what
// actually protects real leaks; this count only decides whether label-shaped
// values are eligible to be treated as translations at all — so a lone
// `{"password":"password"}` (no siblings) still flags as a weak-credential leak.
const labelDictMinKeys = 2

// passwordKeyRe matches a JSON key in the "password" family — plain
// "password" plus relatives like "passwordHint", "newPassword",
// "confirm_password", "forgot-password". The `_-` in the class catches both
// snake_case and kebab-case i18n keys, which label tables carry many of.
var passwordKeyRe = regexp.MustCompile(`(?i)"([a-z0-9_-]*password[a-z0-9_-]*)"\s*:`)

// distinctPasswordKeys counts the distinct (case-insensitive) password-
// family JSON keys present in body.
func distinctPasswordKeys(body []byte) int {
	matches := passwordKeyRe.FindAllSubmatch(body, -1)
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		seen[strings.ToLower(string(m[1]))] = struct{}{}
	}
	return len(seen)
}

// labelLikeValue reports whether a password value reads as a UI label /
// translation rather than a credential: the field's own English label
// ("Password"), or descriptive text containing whitespace ("Forgot password?",
// "كلمة المرور", "mot de passe"). It deliberately does NOT treat a single
// whitespace-free token as a label just because it is non-Latin — a one-word
// non-ASCII value is at least as likely to be a real password (e.g. a Cyrillic
// or Arabic credential) as a translation, and missing a real leak is the worse
// error.
func labelLikeValue(val string) bool {
	v := strings.TrimSpace(val)
	if v == "" {
		return false
	}
	if strings.EqualFold(v, "password") {
		return true
	}
	for _, r := range v {
		if unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

// passwordValueRe extracts every `"password":"<value>"` value from a body so
// the guard can inspect each one (regexp.Find hands it only the first match).
var passwordValueRe = regexp.MustCompile(`(?i)"password"\s*:\s*"([^"]*)"`)

// exposureCheck implements the Check interface for the response-body
// sensitive-data scanner. Structural adapter — Run holds the unchanged
// body of the historical CheckExposure free function.
type exposureCheck struct{}

func (exposureCheck) Name() string                        { return "exposure" }
func (exposureCheck) Category() string                    { return "data_exposure" }
func (exposureCheck) Tier() Tier                          { return TierPassive }
func (exposureCheck) Enabled(cfg *models.ScanConfig) bool { return true }

// CheckExposure scans response bodies for sensitive data patterns.
func CheckExposure(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []ev.Evidence {
	return exposureCheck{}.Run(ctx, NewCheckContext(cfg), endpoint)
}

// Run holds the unchanged data-exposure detection body. Outbound
// requests go through the shared SSRF-guarded follow-redirect client
// (cc.Client); the per-job deadline comes from ctx (runCheck).
func (exposureCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []ev.Evidence {
	cfg := cc.Cfg
	client := cc.Client

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.FullURL, nil)
	if err != nil {
		logagg.Warn("exposure", "exposure check: failed to create request", "url", endpoint.FullURL, "error", err)
		return nil
	}

	cfg.Auth.ApplyToRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		logagg.Warn("exposure", "exposure check: request failed", "url", endpoint.FullURL, "error", err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		logagg.Warn("exposure", "exposure check: failed to read body", "url", endpoint.FullURL, "error", err)
		return nil
	}

	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)
	var findings []ev.Evidence

	for _, pat := range exposurePatterns {
		match := pat.Pattern.Find(body)
		if match != nil {
			// 4.12: optional guard can veto a match (e.g. masked password,
			// i18n label table). It sees the full body for context.
			if pat.Guard != nil && !pat.Guard(match, body) {
				continue
			}
			evidence := string(match)
			if len(evidence) > maxEvidenceLen {
				evidence = evidence[:maxEvidenceLen] + "..."
			}

			findings = append(findings, ev.Evidence{
				// The pattern's own name is the rule. Without it every
				// exposure pattern firing at one endpoint shares a single
				// identity — a password disclosure and a stack trace become
				// one record, and suppressing either hides both.
				RuleID:     "exposure/" + pat.Name,
				Title:      pat.Title,
				Severity:   pat.Severity,
				Source:     models.SourceBlackbox,
				Category:   "data_exposure",
				Endpoint:   epLabel,
				Evidence:   evidence,
				Fix:        pat.Fix,
				References: []string{pat.CWE},
				Confidence: models.ConfidenceHigh,
			})
		}
	}

	slog.Debug("exposure check complete", "endpoint", epLabel, "findings", len(findings))
	return findings
}
