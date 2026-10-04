# 5-Minute Walkthrough — OWASP Juice Shop

This guide takes you from zero to a working Fendix scan against
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop), the canonical
deliberately-vulnerable web app. You'll run a hybrid scan (live HTTP + source
code static analysis), open the HTML report, and learn how to interpret the
output.

**Estimated time:** 5 minutes (most of which is the Juice Shop container
pulling).

**You will need:**

- `docker` (for Juice Shop)
- `fendix` ≥ 0.5 ([install guide](../README.md#installation))
- `git` (to clone Juice Shop's source for the white-box scan)
- A POSIX shell (`bash` / `zsh`)

---

## 1. Stand up Juice Shop

```bash
# Start Juice Shop on http://localhost:3000
docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop:latest

# Wait until it's healthy (about 10 seconds)
until curl -fsSL http://localhost:3000 > /dev/null; do sleep 1; done
echo "Juice Shop ready."
```

Visit `http://localhost:3000` — you should see the storefront.

> **Why Juice Shop?** It ships with deliberately-broken auth, SQL injection,
> XSS, sensitive data exposure, and IDOR. Every reputable security scanner
> uses it as a smoke test. If a scanner can't find anything in Juice Shop,
> it can't find anything anywhere.

## 2. Clone the source for the white-box pass

```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop.git /tmp/juice-shop-src
```

The shallow clone is enough — Fendix's white-box engine reads the working
tree, not history.

## 3. Run a hybrid scan

```bash
fendix scan \
  --url http://localhost:3000 \
  --code /tmp/juice-shop-src \
  --format html \
  --output juice-shop-report.html \
  --crawl-depth 2 \
  --max-requests 1000 \
  --max-duration 3m
```

What each flag does:

| Flag | Why |
|------|-----|
| `--url` | Target the running Juice Shop. The Go scanner crawls and probes it live. |
| `--code` | Point the Python engine at the cloned source. White-box findings (secrets, missing-auth patterns, weak crypto) are produced here. |
| `--format html --output ...` | Self-contained HTML report (one file, no assets). |
| `--crawl-depth 2` | Follow `<a>` and `<form>` links two levels from the entry. Juice Shop's SPA structure rewards this. |
| `--max-requests 1000` | Soft-cap for the scan budget. Prevents runaway crawl. |
| `--max-duration 3m` | Wall-clock deadline. Scan finishes regardless. |

The scan completes in roughly 30–90 seconds depending on your machine. You
should see a budget summary line near the end:

```
INFO budget summary requests_sent=487 requests_rejected=0 max_requests=1000 max_duration=3m0s
```

## 4. Open the report

```bash
open juice-shop-report.html      # macOS
xdg-open juice-shop-report.html  # Linux
```

You'll see (counts vary slightly by Juice Shop version):

- **CRITICAL** — exposed secrets in source (test fixtures with hardcoded
  tokens), unauth admin endpoints
- **HIGH** — missing security headers, `Access-Control-Allow-Origin: *`,
  weak password hashing patterns
- **MEDIUM** — open-redirect candidates, missing rate limiting
- **INFO** — `X-Powered-By` disclosure

Click any finding to expand its evidence, fix guidance, and CWE reference.
Findings flagged `correlated` are the highest-confidence ones — both
engines agreed on the same endpoint.

Since v2.0 severity and confidence are separate axes here. A hardcoded token
whose value or variable name is fixture-shaped (`FAKE_`/`TEST_`-prefixed key, a
placeholder word in the value, a long identical run) keeps its CRITICAL severity
but drops into the `LOW` confidence band, and so reports as `WARN` rather than
blocking a build. Nothing is hidden — check `confidence_band` and
`confidence_reasons` on a finding to see which of the two it is.

## 5. Interpret the output (90 seconds)

Open the HTML report's "Summary" panel:

- **By severity** — sort the table column. Triage CRITICAL → HIGH first.
- **By status** — since v2.0 every finding carries a decision verdict.
  `BLOCK` is what would fail a CI build (it met `--fail-on` *and* its
  deterministic confidence band supported the claim); `WARN` is real output
  that did not clear the evidence bar, with `confidence_reasons` naming the
  missing signal. If you're wondering "where do I start?", start with `BLOCK`.
- **By source** — `correlated` means separate analyzers supplied evidence for
  the same issue. The confidence reasons show how that support affected the
  decision; no repository benchmark currently isolates correlation's
  false-positive rate.
- **Affected endpoints (N)** — when one finding type covers many endpoints
  (e.g. "Missing CSP" across 21 endpoints), Fendix collapses them into one
  finding with an `affected_endpoints` list. Fix the underlying control once,
  not per-endpoint.

For each finding the report shows:

- **Title + severity badge** — what was detected.
- **Endpoint** — URL or `file:line`.
- **Evidence** — the response snippet or source line that triggered the
  detection. Credentials you passed via `--auth` are masked as `[REDACTED]`;
  credential material the secrets scanner *found* is redacted at capture time
  as `[REDACTED len=N sha256:xxxxxxxx...]`, so no part of it reaches the report.
- **Fix** — concrete remediation guidance.
- **References** — CWE, OWASP, RFC IDs.

When you're done triaging, save a baseline so the next scan reports only
new findings:

```bash
fendix scan --url http://localhost:3000 --code /tmp/juice-shop-src \
  --format json --output findings.json --save-baseline .fendix/baseline.json
```

Re-run with `--baseline .fendix/baseline.json` and the report will show the
diff against this snapshot — see the
[CI/CD integration guide](./ci-cd-integration.md) for the full pattern.

## 6. Tear down

```bash
docker stop juice-shop
rm -rf /tmp/juice-shop-src juice-shop-report.html .fendix/baseline.json
```

---

## Where to next?

- **CI integration** — drop a workflow into your repo:
  [`docs/ci-cd-integration.md`](./ci-cd-integration.md).
- **Triaging at scale** — when the report is bigger than 5 findings:
  [`docs/triage-workflow.md`](./triage-workflow.md).
- **Custom Semgrep rules** — extend the white-box engine with project-
  specific patterns: [`docs/semgrep-rules.md`](./semgrep-rules.md).
- **JSON schema** — building tooling on top of the report?
  [`docs/schema.md`](./schema.md).

## Troubleshooting

**Scan finishes too fast with zero findings.** Check that `--url` resolves
from your shell (`curl http://localhost:3000`). Inside Docker-Desktop on
macOS, `localhost` works; in CI runners with networked containers you may
need the container IP.

**Python engine warnings about `semgrep not installed`.** Install it for
deeper static-analysis coverage: `pip install semgrep`. Without it, only
the AST analyzer + secrets scanner run on the white-box side.

**`--crawl-depth 2` exceeded the 3-minute deadline.** Bump
`--max-duration 5m` or lower depth to 1. Juice Shop's SPA can produce a
large frontier on depth ≥ 3; depth 2 is the sweet spot.
