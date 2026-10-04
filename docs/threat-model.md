# Active scanner — threat model

> Companion doc to [`SECURITY.md`](../SECURITY.md). This file is the
> reference for **how Fendix is designed to be safe** when it sends real
> payloads to a target system, and what an operator should still do
> themselves to operate it safely.

The passive scanner (default mode) does not send anything that a
browser wouldn't send when fetching the target. The threat model below
is about the **active scanner** — the SQLi / CMDi / CRLF probes that
only run with `--enable-active`.

---

## TL;DR

- Active probing is **off by default** and gated on an explicit flag
  (`--enable-active`) plus a stderr disclaimer.
- All payloads are **non-destructive by design**: time-based blind
  SQLi (no data extraction), echo-canary CMDi (no destructive shell),
  Set-Cookie CRLF (no cache poisoning).
- A **per-endpoint probe cap** (`--max-probes-per-endpoint`, default
  20) and a **global request budget** (`--max-requests`,
  `--max-duration`) bound the load Fendix can put on a target.
- Every probe is recorded in an in-memory **audit log**; the
  `--debug` flag (planned, TASK-102) will emit it as part of a
  diagnostic bundle.
- Operators are still required to have **written authorisation** to
  scan the target (see [`SECURITY.md`](../SECURITY.md) §"Policy for
  active-scanner misuse").

---

## Scope

This document covers:

- The **threats** the active scanner could pose to a target system.
- The **mitigations** built into Fendix to bound those threats.
- The **residual risks** that an operator must own.

It does **not** cover threats from a malicious target *to* Fendix
(parser fuzz, malformed responses, cert pinning bypass) — those are
covered by Phase 9 hardening (TASK-073, TASK-074, TASK-076) and live
in the test suite, not here.

---

## Threats and mitigations

### T1: Destructive injection payload reaches a vulnerable endpoint

**Scenario.** An operator points Fendix at an endpoint with a SQL
injection vulnerability. The payload Fendix sends contains a
destructive clause (`DROP TABLE`, `DELETE FROM`, etc.) and the target
executes it.

**Mitigations.**

- **No destructive payloads in the codebase.** SQLi probes only use
  time-based blind techniques (`SLEEP(5)`, `pg_sleep(5)`,
  `WAITFOR DELAY`, SQLite `randomblob`, Oracle
  `DBMS_PIPE.RECEIVE_MESSAGE`) and detection-only error/boolean
  patterns (`' OR '1'='1`, `' AND '1'='2`). Boolean-based detection
  reads the response length / status, not the response body.
- **No data extraction.** No `UNION SELECT`, no error-channel
  exfiltration, no out-of-band DNS callbacks. The probes confirm a
  vulnerability exists; they do not pull data through it.
- **No mutating verbs by default.** Active probes target the verbs the
  spec or HTML crawl expose — but the payloads themselves do not
  contain mutating SQL.
- **Code review gate.** Any new injection probe class must land via a
  PR that documents its threat model in this doc. Reviewers must
  confirm the payload cannot have side effects on the target beyond
  the timing or boolean signal it relies on.

**Residual risk.** A poorly-written application that constructs SQL
from the boolean payload itself could in principle behave
unexpectedly. Operators who scan production must own this risk by
running on a staging clone first, or by accepting that staging-style
testing may briefly show timing anomalies on production graphs.

### T2: Resource exhaustion (DoS) on the target

**Scenario.** Fendix sends so many probes per endpoint, or so many
requests overall, that the target's request queue, connection pool,
or downstream database becomes saturated.

**Mitigations.**

- **Per-endpoint probe cap.** `--max-probes-per-endpoint` (default
  20) hard-caps the total number of injection probes per endpoint.
  Enforced via the audit log: every `probe()` call checks
  `len(audit) - audit_at_endpoint_entry < max` before sending.
- **Global request budget.** `--max-requests N` (Phase 12 / TASK-095)
  is a soft-stop counter on every outbound HTTP request. Cap-hit
  fires a one-shot `context.CancelFunc` so the worker pool stops
  scheduling new jobs. In-flight requests finish; no new ones start.
- **Wall-clock budget.** `--max-duration 5m` wraps the scan context
  in `context.WithTimeout`. Bounds total scan time including
  discovery — so a stuck server can't block the operator forever.
- **Concurrency cap.** `--workers N` (default 10) bounds the
  parallelism. With default workers and the default per-endpoint
  cap, the worst-case load is ~10 simultaneous probes.
- **Request delay.** `--delay Nms` (default 100 ms) sleeps between
  requests on each worker — explicitly designed to be a polite
  scanner, not a stress test.
- **Time-based payload cost.** Time-based blind SQLi waits up to 5
  seconds per probe. This is a per-probe cost, not a per-target
  cost — the slow-by-design behaviour does not amplify load, only
  scan duration.

**Residual risk.** A target with very low capacity (a Raspberry Pi,
a free-tier serverless function with cold starts) can still be
saturated by even a polite scanner. Operators are expected to know
the capacity of what they're scanning.

### T3: Authentication bypass / credential leakage

**Scenario.** Fendix sends auth credentials (Bearer token, API key,
basic-auth password) to a target, and either (a) the credentials
end up somewhere the operator didn't expect (logs, third-party
reports), or (b) Fendix's JWT-bypass probes accidentally elevate
privileges on the target.

**Mitigations.**

- **Credential masking in reports.** All auth values are replaced
  with `[REDACTED]` in JSON, HTML, SARIF, and PDF output. The
  `--verbose` flag never logs credentials in plaintext.
- **No credential storage.** The auth context lives in memory for
  the duration of the scan; nothing persists to disk except the
  documented profile path (`~/.fendix/profiles/`) which the user
  explicitly opted into.
- **JWT bypass probes are read-only.** `alg:none` and expired-token
  probes only test whether the target *accepts* the bypass — they
  send `GET` requests, not state-mutating verbs, and they don't
  follow up with an authenticated action.
- **Per-request scope.** Auth is applied per-request; there is no
  long-lived session that could end up with elevated privileges and
  be re-used across endpoints in unexpected ways.

**Residual risk.** Active probes against an authenticated endpoint
will, by design, send the operator's auth value. If the operator
provides a high-privilege production token to scan a production
target, Fendix is sending that token on every probe. Operators
should use a scoped, low-privilege test account whenever possible.

### T4: Side effects from "safe" payloads

**Scenario.** A payload Fendix considers safe triggers an
unexpected side effect — the target's WAF logs it as an attack and
pages oncall, an audit log fills up, a fraud detection model
mis-classifies the operator's IP.

**Mitigations.**

- **Stderr disclaimer.** When `--enable-active` is used, Fendix
  prints a disclaimer to stderr before any probes are sent,
  reminding the operator that probes will hit the target.
- **Audit log.** Every probe is recorded with endpoint, payload,
  timestamp, response status, and timing. The audit log is the
  source of truth for "what did Fendix actually send"; planned
  TASK-102 will package it into a redacted `--debug` bundle.
- **Probe identification.** SQLi payloads are clearly synthetic
  (e.g. `' OR '1'='1` — not stealthy). CMDi canaries echo a fixed
  string `fendix_canary_<hex>` so operators searching their logs
  can attribute the probes back to a Fendix run.
- **No probe persistence.** Fendix does not write to the target.
  The only writes that touch state are reads — even CMDi canary
  detection reads its own canary back out of the response body.

**Residual risk.** WAFs and fraud detection systems are
deliberately conservative; some will flag any active scanner.
Operators should coordinate with their security team before running
active scans against shared production infrastructure.

### T5: Cross-target contamination

**Scenario.** The operator runs Fendix against host A, then against
host B without restarting. Cookies, JWTs, or auth state from A leak
into the request stream for B.

**Mitigations.**

- **Per-scan auth context.** Each invocation of `fendix scan`
  initialises a fresh `AuthContext`; nothing persists across
  process invocations.
- **No global cookie jar.** Each scanner check uses its own
  `http.Client{}` with its own (or no) cookie state. Cookies
  observed on a target are not propagated back to the operator's
  CLI session or to other targets.
- **Worker pool reset.** `WorkerPool` is constructed per-scan;
  cancellation propagates cleanly via `context.CancelFunc`
  (verified by TASK-097 fuzz testing).

**Residual risk.** If the operator deliberately shares a
`~/.fendix/profiles/` profile across targets, that's by design.
The profile system is opt-in.

### T6: Supply chain compromise of Fendix itself

**Scenario.** An attacker compromises the Fendix release pipeline
or a dependency, ships a backdoored binary, and operators install
it.

**Mitigations.**

- **Cosign keyless signing.** Every binary and the Docker image
  are (optionally — see [`SECURITY.md`](../SECURITY.md)) signed
  with cosign in keyless mode. Signatures are bound to the GitHub
  Actions identity that produced them; there is no long-lived key
  for an attacker to exfiltrate.
- **Reproducible release matrix.** The release workflow runs in a
  declared, audited CI environment with **commit-SHA-pinned third-party
  actions** (every `uses:` line carries a 40-char SHA followed by a
  human-readable major-tag comment, e.g.
  `actions/checkout@34e114...d5 # v4`). A `dependabot` config can
  bump these by opening a PR rather than silently moving the tag. The
  build ldflags (`-s -w -X main.Version=...`) and Go version (1.22)
  are recorded in `release.yml`.
- **Dependency hygiene.** `go.sum` is committed and verified by
  `go mod download` on every CI run. `python/requirements.txt`
  pins exact versions. `dependabot` is enabled for both Go and
  Python ecosystems.
- **No third-party CI actions in critical path.** The release
  workflow uses only GitHub-published or Sigstore-published
  actions; no random `marketplace.action@latest` pins.

**Residual risk.** Operators who install via `go install ...@latest`
or `curl ... | sh` get the artifact GitHub serves at request time;
a momentary repo compromise could distribute a malicious build.
Using cosign-verified binaries (after TASK-099 ships) closes this
window. We recommend pinning to a specific tag in CI, not `@latest`.

**Container base-image CVE posture.** Both Dockerfiles
([Dockerfile](../Dockerfile), [Dockerfile.app](../Dockerfile.app))
pin their `FROM` lines to image digests (sha256-addressed), so the
exact byte content of a release-pipeline image build is reproducible.
At pin time the IDE's container scanner reports:

| Image | Stage | CVE count (reported at pin time) |
| --- | --- | --- |
| `golang:1.22-alpine@sha256:1699c10...` | builder (multi-stage; discarded) | 3 critical + 27 high |
| `python:3.11-slim@sha256:9a7765b3...` | runtime | 1 high |

The Go builder-stage CVEs **do not ship** — multi-stage copies only
the compiled binary into the runtime image, so a `golang:` CVE
affects the build environment but not anyone who pulls the
published image. The `python:3.11-slim` CVEs **do ship** and bound
the runtime attack surface. Dependabot's docker ecosystem
([.github/dependabot.yml](../.github/dependabot.yml)) tracks both
digests weekly so a patched upstream image lands in a reviewable PR
rather than silently. Until a customer's procurement gates require
zero-CVE base images, the policy is: review dependabot bumps
within the week they arrive, prioritise the runtime image, and
accept that builder-stage CVEs are an internal-CI concern.

**Transitive telemetry import (disclosed).** Verifiable via
`go list -deps ./go/cmd/fendix | grep telemetry`, the binary links
`golang.org/x/telemetry/counter` transitively through
`golang.org/x/vuln/internal/scan`. The package writes local-only
counters under `~/.config/go/telemetry/local/` and uploads **nothing**
unless the host user has explicitly enabled Go telemetry with
`go telemetry on`. Fendix itself does not call `counter.Open` or
otherwise initialise the counter system in its own code. Operators
who require zero local-counter writes can audit with `strace`/`dtrace`
on a scan run, or set `GOTELEMETRY=off` in the binary's environment
(the upstream toggle). This entry exists because "Fendix does not
phone home" is part of the operator-facing promise and the
transitive import deserves an explicit disclosure.

### T7: Output report contains exploitable content

**Scenario.** Fendix's HTML report renders attacker-controlled text
(e.g. a reflected XSS payload from the target's response) without
escaping. An operator opens the report in a browser and the
payload fires.

**Mitigations.**

- **All evidence is HTML-escaped.** The HTML reporter passes every
  finding's `Evidence`, `Title`, `Endpoint`, and `Fix` field
  through `html.EscapeString` before writing to the template. A
  test fixture covers `<script>`, `javascript:`, and `<img onerror>`
  payloads.
- **No remote loads in the HTML report.** The HTML report is a
  self-contained single file: no remote scripts, no remote
  stylesheets, no external fonts. An operator can open the report
  on an air-gapped machine and nothing fetches.
- **CSP header in HTML report.** The HTML report's `<head>`
  includes a `<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; style-src 'unsafe-inline'; script-src
  'unsafe-inline';">` block. The inline script is the report's own
  sort/expand JS; no remote script can run.

**Residual risk.** Operators who pipe the JSON report through a
custom rendering pipeline are responsible for escaping there.
SARIF output is consumed by GitHub Code Scanning, which performs
its own sanitisation.

---

## Active scanner safety envelope

The "safety envelope" is the set of properties Fendix's active
scanner promises to maintain. A break of any of these is a
**security vulnerability in Fendix** and should be reported via
the channels in [`SECURITY.md`](../SECURITY.md).

The envelope:

1. **No write verbs without operator opt-in.** Active probes use
   the verbs the spec or crawl expose. They do not upgrade `GET`
   to `POST`/`PUT`/`PATCH`/`DELETE` to find more vulns.
2. **No payload mutates target state.** Time-based SQLi waits;
   error-based SQLi reads error strings; boolean-based SQLi reads
   length/status; CMDi echoes a canary; CRLF injects a
   `Set-Cookie`. None of these alter the target's persistent state
   when applied to a normally-coded application.
3. **No out-of-band callback.** Probes never include a URL, DNS
   name, or IP that an attacker could observe to confirm the
   probe ran. (This is a deliberate design choice: it means
   Fendix can produce false negatives where an OOB-only vuln
   exists, but it also means Fendix cannot be hijacked into being
   a scan-launcher for an attacker who controls the spec or
   wordlist.)
4. **No automatic crawl beyond same-host.** HTML crawling
   (TASK-089) is hard-bounded to the original host. `--wordlist`
   probes are hard-bounded to the base URL. Fendix does not
   "discover" external hosts and start scanning them.
5. **All probes are auditable.** Every active probe is recorded
   in the in-memory audit log with payload, endpoint, and
   timestamp. The `--debug` bundle (planned, TASK-102) ships the
   audit log so operators can prove what was sent.

---

## What the operator still owns

The threat model assumes the operator:

- Has **authorisation** to test the target.
- Knows the **capacity** of the target and chooses appropriate
  `--workers`, `--delay`, `--max-requests`, `--max-duration`.
- Uses a **scoped** auth credential (test account, low-privilege
  service account) when possible.
- **Reviews findings** before acting on them — Fendix's confidence
  scoring is a heuristic, not a guarantee.
- **Pins** the Fendix version they install in CI (do not use
  `@latest` for production gates).
- Coordinates with their security team if scanning shared
  production infrastructure (WAF logs, fraud detection, etc.).

Fendix can do all the engineering above and still hurt a target if
the operator runs `--enable-active` against a system they don't own
or a system that can't take the load. The opt-in flag is the
contract: the operator declares "I have authorisation and I
understand the load," and Fendix takes them at their word.

---

## Change log

- **2026-04-30**: Initial threat model committed under TASK-103
  (Phase 13 — external release readiness). Covers v0.5.0 active
  scanner surface.
