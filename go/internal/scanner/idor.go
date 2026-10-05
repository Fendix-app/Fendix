package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

const idorMaxBodySize = 64 * 1024 // 64KB for response comparison

// idorLengthTolerance is the fractional body-length window within which
// two non-JSON same-status responses are treated as structurally
// identical for the same-URL fallback. Conservative (5%) to avoid FPs on
// pages that merely happen to be similar-sized.
const idorLengthTolerance = 0.05

// idorVolatileKeys are common dynamic JSON field names whose VALUES
// legitimately differ between two identical-object requests (timestamps,
// per-request correlation ids, CSRF/nonce echoes). They are stripped
// before comparing the same-URL fallback's stable field values so that a
// real shared-object IDOR (same object, different volatile metadata) is
// not masked, while genuinely different objects (differing id/name/etc.)
// still read as distinct. Conservative list — adding a real data field
// here would risk FPs, so only request-scoped metadata is included.
var idorVolatileKeys = map[string]struct{}{
	"request_id": {}, "requestid": {}, "request-id": {},
	"trace_id": {}, "traceid": {}, "trace-id": {},
	"correlation_id": {}, "correlationid": {},
	"ts": {}, "timestamp": {}, "time": {}, "datetime": {},
	"created_at": {}, "updated_at": {}, "now": {},
	"nonce": {}, "csrf": {}, "csrf_token": {}, "csrftoken": {},
	"etag": {}, "last_modified": {},
}

// idObjectSegmentRe matches a path segment that looks like an object
// identifier: a pure numeric id, or a UUID. Its presence means the
// endpoint URL is bound to a specific object, so issuing user2's
// credentials against user1's identifier is a cross-tenant access probe
// rather than a shared/global-resource check.
var idObjectSegmentRe = regexp.MustCompile(
	`(?i)/(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)`,
)

// idValueRe matches a query-param value that looks like an object id
// (numeric or UUID) — e.g. ?id=1001 or ?uuid=<...>.
var idValueRe = regexp.MustCompile(
	`(?i)^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`,
)

// idorCheck implements the Check interface for the cross-user IDOR
// scanner. Structural adapter — Run holds the unchanged body of the
// historical CheckIDOR free function.
type idorCheck struct{}

func (idorCheck) Name() string     { return "idor" }
func (idorCheck) Category() string { return "idor" }
func (idorCheck) Tier() Tier       { return TierMultiuser }
func (idorCheck) Enabled(cfg *models.ScanConfig) bool {
	return cfg != nil && cfg.Auth != nil && cfg.AuthUser2 != nil
}

// CheckIDOR performs Insecure Direct Object Reference detection using two
// authenticated accounts. It sends the endpoint request with user1 and
// user2 credentials and flags broken object-level authorization.
//
// Two detection modes:
//   - id-mutation (cross-tenant): when the endpoint carries an object
//     identifier (numeric/UUID path segment or id-shaped query value),
//     user2 hitting user1's identifier and getting 2xx is a direct
//     access-control bypass → HIGH confidence (body emptiness is not the
//     signal; access is).
//   - same-URL fallback: when no identifier is detectable, two identical
//     /structurally-equivalent 2xx responses suggest a shared/global
//     resource or missing authz → MEDIUM confidence (heuristic).
//
// Requires cfg.AuthUser2 to be set (--auth-user2 flag).
func CheckIDOR(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []ev.Evidence {
	return idorCheck{}.Run(ctx, NewCheckContext(cfg), endpoint)
}

// Run holds the IDOR detection body. Outbound requests go through the
// shared SSRF-guarded no-follow client (cc.NoFollow), which returns the
// raw 3xx (CheckRedirect: ErrUseLastResponse) so a redirect is compared
// as-is rather than followed. The per-job deadline comes from ctx
// (runCheck).
func (idorCheck) Run(ctx context.Context, cc *CheckContext, endpoint Endpoint) []ev.Evidence {
	cfg := cc.Cfg
	if cfg.Auth == nil || cfg.AuthUser2 == nil {
		return nil
	}

	client := cc.NoFollow

	epLabel := fmt.Sprintf("%s %s", endpoint.Method, endpoint.Path)

	resp1Body, resp1Status, err := doAuthRequest(ctx, client, endpoint, cfg.Auth)
	if err != nil || resp1Status < 200 || resp1Status >= 300 {
		return nil
	}

	resp2Body, resp2Status, err := doAuthRequest(ctx, client, endpoint, cfg.AuthUser2)
	if err != nil {
		return nil
	}

	// 5.2 — cross-tenant id-mutation. When the endpoint is bound to a
	// concrete object identifier, user1's request established that the id
	// resolves to a real resource (resp1 was 2xx). If user2 — a different
	// account that should NOT own user1's id — also gets 2xx, that is a
	// direct broken-object-level-authorization bypass. We gate purely on
	// access-control semantics: 5.3 — a 200/204 with an empty body is
	// still a bypass (the access is the signal, not the body bytes).
	if endpointHasObjectID(endpoint) {
		if resp2Status >= 200 && resp2Status < 300 {
			evidence := fmt.Sprintf(
				"Endpoint is bound to an object identifier; user2 (a different account) accessed user1's resource: "+
					"user1 HTTP %d (%d bytes), user2 HTTP %d (%d bytes). user2 should not be authorized for this id.",
				resp1Status, len(resp1Body), resp2Status, len(resp2Body))
			return []ev.Evidence{
				{
					RuleID:     "idor/cross-tenant-access",
					Title:      "IDOR — cross-tenant object access (id mutation)",
					Severity:   models.SeverityHigh,
					Source:     models.SourceBlackbox,
					Category:   "idor",
					Endpoint:   epLabel,
					Evidence:   truncateEvidence(evidence, 500),
					Fix:        "Enforce object-level authorization: verify the authenticated principal owns or may access the requested object id before returning it.",
					References: []string{"CWE-639", "OWASP-A01"},
					Confidence: models.ConfidenceHigh,
					// A two-account controlled differential — the strongest
					// confirmation this scanner can produce. Both halves are
					// required: user2 receiving a 2xx is unremarkable on its
					// own; it is a bypass only relative to the object being
					// user1's. Preserving the comparison is what justifies the
					// claim.
					Payload: "user2 credentials replayed against user1's object id",
					Response: ProbeExcerpt(fmt.Sprintf(
						"user1 HTTP %d (%d bytes); user2 HTTP %d (%d bytes) — user2 authorized for user1's id",
						resp1Status, len(resp1Body), resp2Status, len(resp2Body))),
				},
			}
		}
		// user2 was denied (e.g. 403) — authz is enforced for this id.
		slog.Debug("IDOR id-mutation: user2 denied", "endpoint", epLabel, "user2_status", resp2Status)
		return nil
	}

	// 5.1 — same-URL fallback (no detectable identifier). This detects
	// shared/global resources or blanket-missing authz, not cross-tenant
	// access. Require the SAME status AND high structural similarity
	// (conservative — same JSON shape or near-equal length), so dynamic
	// fields (timestamps, request ids) don't hide a real match and
	// genuinely-different objects don't over-trigger.
	if resp1Status != resp2Status {
		slog.Debug("IDOR same-URL: status differs", "endpoint", epLabel)
		return nil
	}
	if !structurallyIdentical(resp1Body, resp2Body) {
		slog.Debug("IDOR same-URL: bodies not structurally identical", "endpoint", epLabel)
		return nil
	}

	evidence := fmt.Sprintf("Both users received structurally identical HTTP %d responses (user1 %d bytes, user2 %d bytes)",
		resp1Status, len(resp1Body), len(resp2Body))
	if len(resp1Body) > 200 {
		evidence += fmt.Sprintf("; body preview: %s...", resp1Body[:200])
	}

	return []ev.Evidence{
		{
			RuleID:     "idor/identical-responses",
			Title:      "Potential IDOR — identical responses for different users",
			Severity:   models.SeverityHigh,
			Source:     models.SourceBlackbox,
			Category:   "idor",
			Endpoint:   epLabel,
			Evidence:   truncateEvidence(evidence, 500),
			Fix:        "Implement object-level authorization. Ensure each user can only access their own resources.",
			References: []string{"CWE-639", "OWASP-A01"},
			Confidence: models.ConfidenceMedium,
			// The same two-account differential, but the INFERENCE is weaker:
			// with no detectable object id this shape also matches a genuinely
			// shared/global resource. The observation is real evidence and is
			// recorded as such; the weakness lives in Confidence=MEDIUM, which
			// is where the decision layer already accounts for it — not in
			// withholding the comparison.
			Payload: "same URL requested with two different accounts' credentials",
			Response: ProbeExcerpt(fmt.Sprintf(
				"user1 HTTP %d (%d bytes); user2 HTTP %d (%d bytes) — structurally identical",
				resp1Status, len(resp1Body), resp1Status, len(resp2Body))),
		},
	}
}

// endpointHasObjectID reports whether the endpoint URL is bound to a
// concrete object identifier — a numeric/UUID path segment, or a query
// param whose value is id-shaped. Best-effort: when nothing is
// detectable it returns false and Run falls back to the same-URL check.
func endpointHasObjectID(endpoint Endpoint) bool {
	if idObjectSegmentRe.MatchString(endpoint.Path) {
		return true
	}
	// Inspect the live URL's query for an id-shaped value. The crawler
	// bakes concrete values into FullURL (e.g. ?id=1001), so this catches
	// query-id endpoints even though endpoint.Params only carries names.
	if u, err := url.Parse(endpoint.FullURL); err == nil {
		for _, vals := range u.Query() {
			for _, v := range vals {
				if idValueRe.MatchString(v) {
					return true
				}
			}
		}
	}
	return false
}

// structurallyIdentical reports whether two response bodies look like the
// SAME underlying object for the same-URL fallback. Conservative — it
// must fire on identical-object-with-volatile-noise but NOT on per-user
// scoped data (e.g. /me returning each caller's own record):
//   - Both empty → not a usable signal (returns false; avoids FPs on a
//     shared always-empty endpoint that isn't access-control evidence).
//   - Both JSON objects → equal only if their TOP-LEVEL key sets match
//     AND every non-volatile field VALUE matches. Stripping known
//     volatile keys (timestamps, request ids) lets a real shared-object
//     match survive dynamic noise, while differing stable values (a
//     different id/name) read as distinct objects → no FP.
//   - Otherwise (arrays / scalars / non-JSON) → equal if byte-identical
//     OR lengths are within idorLengthTolerance of each other.
func structurallyIdentical(a, b string) bool {
	if a == "" || b == "" {
		return false
	}

	objA, okA := jsonObject(a)
	objB, okB := jsonObject(b)
	if okA && okB {
		return sameStableObject(objA, objB)
	}
	if okA != okB {
		// One is a JSON object, the other isn't → different shape.
		return false
	}

	if a == b {
		return true
	}
	la, lb := float64(len(a)), float64(len(b))
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	longer := la
	if lb > longer {
		longer = lb
	}
	if longer == 0 {
		return false
	}
	return diff/longer <= idorLengthTolerance
}

// jsonObject decodes a JSON object body. ok is false when the body is not
// a JSON object (array, scalar, or invalid JSON), signalling the caller
// to use length-based comparison.
func jsonObject(body string) (map[string]json.RawMessage, bool) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || trimmed[0] != '{' {
		return nil, false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return nil, false
	}
	return obj, true
}

// sameStableObject reports whether two JSON objects share the same
// top-level key set AND the same value for every non-volatile field. A
// match means "the same object with possibly different volatile
// metadata" — the shared-resource IDOR signal. Differing stable values
// mean each user saw their own distinct record — secure, no match.
func sameStableObject(a, b map[string]json.RawMessage) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			return false // key set differs
		}
		if _, volatile := idorVolatileKeys[strings.ToLower(k)]; volatile {
			continue // dynamic field — value mismatch expected, ignore
		}
		if string(va) != string(vb) {
			return false // stable field value differs → different object
		}
	}
	return true
}

func doAuthRequest(ctx context.Context, client *http.Client, endpoint Endpoint, auth *models.AuthContext) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, endpoint.FullURL, nil)
	if err != nil {
		return "", 0, fmt.Errorf("creating request: %w", err)
	}

	auth.ApplyToRequest(req)

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, idorMaxBodySize))
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("reading body: %w", err)
	}

	return string(body), resp.StatusCode, nil
}

func truncateEvidence(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
