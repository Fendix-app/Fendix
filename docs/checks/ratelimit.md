# Rate Limiting Check

**Engine:** Go (black-box)
**Category:** `rate_limiting`
**Emitted severity:** MEDIUM for sensitive unthrottled operations; INFO for ordinary or explicitly untested operations
**Tier:** passive, with write-method bursts gated by `--enable-active`

## What It Detects

Endpoints that lack rate limiting, making them vulnerable to brute-force attacks, credential stuffing, and denial-of-service.

## How It Works

1. Chooses the operation's own method. GET, HEAD, and OPTIONS can be burst
   tested in a passive scan; POST, PUT, and PATCH require `--enable-active`;
   DELETE is never burst tested.
2. Sends up to 20 rapid requests with that method (no delay between them).
3. Checks for rate-limiting indicators:
   - HTTP 429 (Too Many Requests) response
   - `X-RateLimit-*` headers
   - `Retry-After` header
   - `X-Rate-Limit-*` headers
4. If at least 10 requests complete without any throttling response, reports
   the bounded observation. An ineligible write operation gets an INFO
   `ratelimit.not-tested` coverage finding instead.

The title and evidence deliberately scope the claim to the burst size: a bounded
burst can only show the ABSENCE of limiting within N requests, never prove that
a per-minute or per-hour limiter is missing. Confidence stays MEDIUM for the
same reason.

## Example Finding

```json
{
  "title": "No rate limiting observed within 20 requests",
  "severity": "MEDIUM",
  "category": "rate_limiting",
  "endpoint": "POST /api/login",
  "evidence": "Sent 20 rapid requests with no 429 response and no rate-limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset). Scope note: this bounded burst cannot prove the absence of slower per-minute/per-hour limiters — it only shows no limiting within 20 requests.",
  "fix": "Implement rate limiting. Return 429 with Retry-After header when threshold exceeded."
}
```

That POST example requires `--enable-active`; without it, Fendix records that
the write operation was not burst tested.

## Skipped endpoints

This check is **skipped entirely** on static-asset paths (`.js`, `.css`, images,
fonts, `.map`, `favicon.ico`, `robots.txt`, `sitemap.xml`, `.DS_Store` — see
`isStaticAssetPath` in `go/internal/scanner/responsecontext.go`).

This is a skip, not a de-escalation, and the distinction is deliberate. Fendix's
posture is to preserve evidence and lower its confidence when context makes a
finding less trustworthy (that is what the header and CORS checks do for the
same paths). Here there is nothing to preserve: rate limiting on a file served
by a CDN or static-file middleware is not an app-layer control, so "no 429
within 20 requests on `/favicon.ico`" was never a security observation. Skipping
also avoids spending 20 requests of the scan budget per static endpoint.

The check also returns nothing when fewer than 10 probes actually completed
(budget exhaustion or transport errors) — too few requests reached the target to
distinguish "unprotected" from "never really tested".

## References

- [CWE-770: Allocation of Resources Without Limits](https://cwe.mitre.org/data/definitions/770.html)
- [OWASP Rate Limiting](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
