# Fendix — GitHub Marketplace Listing Copy

> This document contains the copy for the GitHub Marketplace listing submission.
> Once the App is registered and deployed, submit this at:
> https://github.com/marketplace/manage

---

## App name

Fendix

## Short description (80 chars max)

DAST + SAST as one PR check. Correlated findings get elevated severity.

## Detailed description

Fendix scans every pull request with two engines working together:

**Black-box (DAST):** Probes your running API for real vulnerabilities — SQL injection, auth bypass, CORS misconfiguration, missing security headers, exposed config files (.env / .git / .htaccess / .htpasswd at known paths).

**White-box (SAST):** Analyzes your source code for hardcoded secrets, dependency CVEs (real call-graph reachability for Go via `golang.org/x/vuln`, OSV.dev for PyPI and npm), and taint chains across 7 sink classes — SQL injection, SSRF, open redirect, XSS, command injection, path traversal, and insecure deserialization.

**The key insight:** When both engines agree on the same vulnerability, Fendix escalates severity and confidence — correlated findings rise above the noise. When taint analysis also proves data flows from a request source to a dangerous sink, severity escalates a second time (e.g., MEDIUM → CRITICAL). You control the `fail_on` threshold, so you can choose to only block merges on high-confidence correlated findings.

**Measured accuracy (current binary, 2026-06-30):** F1 = 1.000 on the labeled synthetic corpus (38 TPs / 0 FPs / 0 FNs across 7 detection categories — reproduced and CI-gated; v0.26 disclosed one multi-hop SSRF false negative, fixed in v0.27); P/R/F1 = 1.000 on the 40-case Python taint-engine corpus (CI-gated). Real-world: DVWA 13/13 and OWASP Juice Shop 12 findings (regression coverage of the unauthenticated surface; 5 raw FPs — no FP-*rate* claimed without a negative corpus). Full methodology + caveats + reproduce commands in [BENCHMARKS.md](https://github.com/Fendix-app/Fendix/blob/main/BENCHMARKS.md).

### What happens on every PR

1. Fendix clones the PR head commit
2. Runs a hybrid scan (SAST over source + DAST if a preview URL is available)
3. Posts a single PR comment summarizing findings by severity
4. Uploads SARIF to the Code Scanning tab (inline annotations on changed lines)
5. Blocks merge based on your configured `fail_on` threshold (default: HIGH)

### Features

- Zero configuration — install and it works on the next PR
- Correlated findings with severity escalation (DAST + SAST + reachability proof)
- 7 reachable taint-chain sink classes (SQLi / SSRF / open-redirect / XSS / cmd-injection / path-traversal / insecure-deserialization)
- 15 native-Go secret patterns + 32 exposed-config-file detections (CWE-538)
- SARIF integration with GitHub Code Scanning
- Plugin system for custom checks — `fendix plugins install <git-url>` for any-language plugin (NDJSON contract)
- Suppression tooling — `fendix ignore list / validate / prune` for .fendix-ignore lifecycle
- Supports `.fendix.yaml` policy files for per-repo customization
- MIT licensed, fully open source

### What Fendix does NOT do

- No telemetry, no phone-home, no data collection
- No cloud service dependency — the App runs on YOUR infrastructure
- No vendor lock-in — self-host or use the GitHub Actions workflow instead

## Category

Security

## Pricing

Free

## Support URL

https://github.com/Fendix-app/Fendix/issues

## Documentation URL

https://github.com/Fendix-app/Fendix/blob/main/docs/github-app.md

## Screenshot descriptions

1. **PR comment** — Shows the findings summary comment Fendix posts on a pull request (severity table + source breakdown)
2. **HTML report** — The self-contained HTML report with expandable finding details
3. **Code Scanning** — SARIF annotations inline on the PR's changed files

## Installation instructions (shown post-install)

Fendix is now active on your selected repositories. Every new pull request
will trigger a security scan automatically.

**First scan:** Open a PR (or push to an existing one) and wait ~60 seconds.
You'll see a Fendix comment with the scan results.

**Configuration (optional):** Add a `.fendix.yaml` to your repo root to
customize severity thresholds, ignored rules, or authentication profiles.
Run `fendix init` locally to generate a starter config.

**Troubleshooting:** If no comment appears after 2 minutes, check the
webhook delivery log in your App settings (Settings → Developer settings →
GitHub Apps → Fendix → Advanced → Recent Deliveries).
