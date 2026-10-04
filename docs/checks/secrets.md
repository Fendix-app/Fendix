# Secrets Detection Check

**Engine:** Go (white-box) — `go/internal/scanner/secrets/`, native since TASK-115
**Category:** `secrets`
**Emitted severity:** CRITICAL or HIGH
**Active probing:** No (static analysis)

## What It Detects

Hardcoded secrets, credentials, and API keys embedded directly in source code.

## Pattern Types

| Pattern | Example Match | Severity |
|---|---|---|
| **AWS Access Key ID** | `AKIAIOSFODNN7EXAMPLE` | CRITICAL |
| **AWS Secret Key** | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | CRITICAL |
| **Private Key (PEM)** | `-----BEGIN RSA PRIVATE KEY-----` | CRITICAL |
| **Generic API Key** | `api_key = "sk-live-abc123def456"` | HIGH |
| **Hardcoded Password** | `password = "mysecretpassword"` | HIGH |
| **JWT Secret** | `jwt_secret = "my-signing-key"` | HIGH |
| **Database Connection String** | `postgres://user:pass@host/db` | HIGH |

## How It Works

1. Recursively walks all files in `--code` directory
2. Skips binary files, `.git/`, `node_modules/`, `vendor/` directories
3. Applies regex patterns line-by-line against file contents
4. **Redacts credential material at capture time** (see below), then frames the
   redacted line as evidence
5. Classifies the captured value as real-or-fixture and records the verdict on
   the evidence, which the confidence scorer turns into a named delta
6. Reports file path and line number for each finding

## Evidence redaction (v2.0)

Before v2.0 the scanner kept a 20-character raw prefix of every matched value
and framed it in a 120-character window over the source line. `evidence` is not
an internal field — the JSON, SARIF, HTML and PDF reporters print it, the GitHub
App posts it into PR comments, and the Jira integration pastes it into a ticket
body. Half of a 40-character token, distributed to all of those, is a leak.

Credential material is now replaced at capture time with a deterministic marker:

```
[REDACTED len=40 sha256:a3f19c02...]
```

- **Deterministic and unsalted**, so identical values render identically —
  evidence bytes stay reproducible and the dedup tiebreak stays stable, and you
  can correlate two occurrences of the same credential without carrying it.
- **A fingerprint, not a security boundary.** A low-entropy value is still
  recoverable from an 8-hex-char digest by dictionary.
- **Covers the union of every pattern's value spans on the line**, not just the
  emitting pattern's own match. Two credentials on one line used to ship each
  other in the clear inside the neighbour's window, and a one-line PEM (the
  shape of a Google service-account JSON) shipped the whole key body, because
  `PRIVATE_KEY` matches only the armour header.
- **Retained signal is deliberate and tested:** the PEM header, a connection
  string's scheme / user / host, the `"type": "service_account"` signature, and
  the assignment's variable name all survive.

> **Evidence text changed for every secrets finding.** A snapshot or golden file
> that pinned it needs regenerating. Fingerprints do not move: current builds
> emit the `fendix/v2` semantic fingerprint, which keys a secret on its rule,
> repository-relative file, and safe identifier. Evidence, credential material,
> line/column coordinates, severity, and decision fields are excluded, so
> capture-time redaction does not re-key `.fendix-ignore` rules or baseline
> entries.

## Fixture-shaped values (v2.0)

`FAKE_API_KEY = "08bf2e526…"`, `ghp_` followed by 36 `A`s and AWS's own
documented `AKIAIOSFODNN7EXAMPLE` used to score at exactly the confidence of a
live production credential, because nothing downstream of the regex looked at
the value or the name it was bound to.

Each captured value is now classified against four deterministic rules:

1. A `FAKE_` / `TEST_` / `DUMMY_` / `MOCK_` / `EXAMPLE_` / `PLACEHOLDER_` /
   `SAMPLE_` assignment key (snake, kebab or camelCase)
2. A placeholder word inside the value
3. A long identical run, or a single dominant byte
4. A value too short to be a credential

A classified value earns a named **−20** delta *and* forfeits the **+30**
`deterministic detection` bonus, so a fixture-shaped secret lands in the LOW
band where a real one lands HIGH.

This is de-escalation, never suppression: the finding is still emitted, at the
same id, severity, endpoint and evidence. It is deliberately **not** folded into
the existing placeholder suppression, which *drops* matches — "EXAMPLE" appears
inside real leaked keys too.

The classifier is pure and rule-based: no model, no randomness, and every point
it costs is a reason line in `confidence_reasons` that reconciles with
`confidence_score`. Boundary cases are pinned — `latest_token`, `testament`,
`testing_key` and `TESTING_KEY` do **not** classify as fixtures, and neither do
Stripe's documentation key, a 48-character OpenAI key, or a database password.

> **`confidence_score` and `confidence_band` moved for affected findings**, and
> both are serialized into JSON and SARIF. Severity, `status`'s severity input
> and the `confidence` enum are untouched. Because a `LOW` band never blocks,
> this can change an exit code — see
> [`--enforce-confidence`](../../README.md#common-scan-flags).

## Example Finding

```json
{
  "title": "AWS Access Key ID hardcoded",
  "severity": "CRITICAL",
  "source": "whitebox",
  "category": "secrets",
  "endpoint": "src/config.py:14",
  "evidence": "AWS_ACCESS_KEY_ID = \"[REDACTED len=20 sha256:7c1e9b40...]\"",
  "fix": "Remove hardcoded key. Use environment variables or a secrets manager. Rotate the exposed key immediately.",
  "references": ["CWE-798"],
  "confidence": "HIGH",
  "line": "src/config.py:14"
}
```

The variable name survives redaction on purpose — it is what tells a reviewer
which credential to rotate. The same finding with the value bound to
`FAKE_AWS_ACCESS_KEY_ID` keeps its CRITICAL severity but lands in the LOW
confidence band, and so does not block a build.

## References

- [CWE-798: Hardcoded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-321: Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
