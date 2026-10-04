# Authentication Check

**Engine:** Go (black-box)
**Registry ID:** `auth`
**Category:** `auth_bypass`
**Tier:** authentication (`--auth` required)
**Emitted severity:** CRITICAL, MEDIUM, or INFO
**Active payload flag:** not required; this check still sends live
credential-differential requests

## What It Detects

Authentication failures on live API endpoints, including missing
authentication and JWT validation bypasses. IDOR is a separate `idor` registry
check in the multiuser tier and requires both `--auth` and `--auth-user2`.

## Checks Performed

| Check | Description | Severity |
|---|---|---|
| **Unauthenticated access** | Endpoint returns 2xx without credentials | CRITICAL when the OpenAPI operation requires authentication; MEDIUM when the requirement is unknown; INFO when OpenAPI declares it public |
| **Malformed JWT accepted** | Server accepts `Authorization: Bearer invalid.jwt.token` | CRITICAL |
| **Expired JWT accepted** | Server accepts a JWT with `exp` in the past | CRITICAL |
| **alg:none bypass** | Server accepts a JWT with `"alg": "none"` (no signature) | CRITICAL |

JWT probes run only when the supplied credential is a parseable JWT and the
endpoint first accepts that real token.

## How It Works

### Unauthenticated access
1. Sends a request without the configured credential (header, cookie, query,
   Basic, or bearer auth)
2. If response is 200 OK, the endpoint lacks authentication

### JWT bypass
1. Generates a malformed/expired/alg:none JWT using go-jwt
2. Sends the crafted token to the endpoint
3. If the server responds with 200, JWT validation is broken

### Separate IDOR check

The `idor` check compares two authenticated accounts. It is a distinct
`TierMultiuser` registry entry, emits HIGH findings, and uses CWE-639.

## Example Finding

```json
{
  "title": "Expired JWT accepted",
  "severity": "CRITICAL",
  "category": "auth_bypass",
  "endpoint": "GET /api/users/me",
  "evidence": "Server returned 200 with expired JWT (exp: 2020-01-01T00:00:00Z)",
  "fix": "Validate JWT expiration. Reject tokens where exp < current time."
}
```

## References

- [CWE-306: Missing Authentication](https://cwe.mitre.org/data/definitions/306.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [OWASP A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
