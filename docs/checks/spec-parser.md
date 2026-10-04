# OpenAPI Spec Parser Check

**Engine:** Python (white-box)
**Category:** `auth`
**Emitted severity:** HIGH or MEDIUM
**Active probing:** No (static analysis)

## What It Detects

Security misconfigurations in OpenAPI 2.0 (Swagger) and OpenAPI 3.x specifications, focusing on authentication and transport security issues.

## Checks Performed

| Check | Description | Severity |
|---|---|---|
| `SEC-SPEC-PARSE` | Spec cannot be parsed or exceeds the size/recursion limits | MEDIUM |
| `SEC-SPEC-NO-GLOBAL-AUTH` | Security schemes exist but top-level security is absent or permits anonymous access | MEDIUM |
| `SEC-SPEC-HTTP-SCHEME` / `SEC-SPEC-HTTP-SERVER` | Spec allows an unencrypted HTTP transport/server | HIGH |
| `SEC-SPEC-NO-AUTH` | Operation inherits no authentication requirement because none exists globally | HIGH |
| `SEC-SPEC-OPEN-ENDPOINT` | Operation explicitly permits anonymous access | MEDIUM with global auth, otherwise HIGH |
| `SEC-SPEC-BASIC-AUTH` | Spec uses HTTP Basic authentication | MEDIUM |
| `SEC-SPEC-APIKEY-QUERY` | API key is carried in the query string | MEDIUM |

## Supported Formats

- OpenAPI 2.0 (Swagger) — YAML and JSON
- OpenAPI 3.0.x — YAML and JSON
- OpenAPI 3.1.x — YAML and JSON

The Python analyzer accepts local files and HTTPS URLs. In the current CLI,
`--spec` by itself runs Go discovery but does not auto-enable this Python
analyzer; pass `--python-engine`, or supply `--code` (which auto-enables the
Python phase unless explicitly disabled). Prefer a local spec file: the known
remote-spec defect means Python rejects HTTP and refetches HTTPS without the
Go fetcher's equivalent private-IP guard.

## How It Works

1. Parses the spec file (YAML or JSON)
2. Detects OpenAPI version (2.0 vs 3.x)
3. Checks for global security definitions
4. Iterates all paths/operations and checks for per-endpoint security
5. Inspects server URLs for HTTP vs HTTPS
6. Reports findings with the spec file path and operation as the endpoint

## Example Finding

```json
{
  "title": "Endpoint has no authentication requirement",
  "severity": "HIGH",
  "source": "whitebox",
  "category": "auth",
  "endpoint": "GET /api/admin/users",
  "evidence": "No security requirement defined for GET /api/admin/users and no global security fallback",
  "fix": "Add a security requirement to this endpoint or define a global security scheme.",
  "references": ["CWE-306"],
  "line": "openapi.yaml"
}
```

## References

- [CWE-306: Missing Authentication](https://cwe.mitre.org/data/definitions/306.html)
- [OpenAPI Specification](https://spec.openapis.org/oas/latest.html)
