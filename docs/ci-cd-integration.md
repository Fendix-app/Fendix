# CI/CD Integration

Fendix produces SARIF 2.1.0 output for GitHub code scanning: PR annotations and the Security tab. Code scanning on a private repository needs GitHub Code Security.

## Quick start

The recommended GitHub integration is the Fendix Action
([Fendix Security Scan on GitHub Marketplace](https://github.com/marketplace/actions/fendix-security-scan)),
`uses: Fendix-app/Fendix@v1` with an explicit `version: v3.6.2`, or pinned to
the full commit of the validated release for high-assurance pipelines,
`Fendix-app/Fendix@90adf6a5082be0661b4156566a3a99609ed4792d # v3.7.0` with
`version: v3.7.0`. `@v1` still resolves to the v3.6.2 Action code until it is
moved, so v3.7.0's fail-closed required analyzers need the v3.7.0 commit until
then; see
[INTEGRATION_GUIDE §3.1](INTEGRATION_GUIDE.md#31-recommended--the-composite-github-action).
Never reference `@main`.

### Alternative — copy the reference workflow

For the container-based path, a complete, digest-pinned v3.7.0 container
workflow lives at
[`examples/github-actions/fendix-scan.yml`](https://github.com/Fendix-app/Fendix/blob/5ddfd88bde0e24d67d23be7f0d0302cfb29789f5/examples/github-actions/fendix-scan.yml).
Install it from that tested commit, not from `main`, as shown in
[INTEGRATION_GUIDE §3.2](INTEGRATION_GUIDE.md#32-alternative--the-digest-pinned-reference-workflow).
Dropped into `.github/workflows/fendix-scan.yml` of your project, it will:

- Scan on every PR and on push to `main`.
- Upload SARIF to GitHub Code Scanning (inline annotations on the PR). A
  private repository needs GitHub Code Security for this, so the upload is
  skipped there unless the repository variable `FENDIX_UPLOAD_SARIF` is
  `true`; the scan, comment and gate still run.
- Persist the previous run's findings as a baseline (cached via
  `actions/cache`) so a PR comment shows only the diff.
- Post a summary comment on each PR with finding counts and the top 5
  findings.
- Fail the build on a HIGH or CRITICAL finding that survives baseline
  filtering **and** whose confidence band supports the claim (`--fail-on HIGH`),
  and on a scan error. A missing exit code fails closed.

The sections below show the individual building blocks if you'd rather
assemble your own workflow.

Commands shown with a bare `fendix` binary assume a version-matched Python
engine tree is configured when `--code` coverage is expected. Official v3.7.0
standalone binaries do not include that tree; without it, the native analyzers
continue and `python-engine` is recorded `skipped/dependency_missing`. The
reference workflow avoids that degradation by using the official container.

## GitHub Actions — SARIF Upload

This workflow runs Fendix on every pull request, uploads SARIF results to GitHub Code Scanning, and fails the build on a HIGH or CRITICAL finding that reaches status `BLOCK`.

```yaml
name: Fendix Security Scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    env:
      FENDIX_IMAGE: docker.io/fendixapp/fendix@sha256:0f0a04e520cbb7eda9dd0850f1807e09c3952111bb79bb72f57c3955eb622015
    permissions:
      actions: read           # Required for SARIF upload on a private repository
      security-events: write  # Required for SARIF upload
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Pull pinned Fendix image
        run: |
          docker pull "$FENDIX_IMAGE"
          docker run --rm "$FENDIX_IMAGE" version

      - name: Run security scan
        run: |
          docker run --rm \
            --user "$(id -u):$(id -g)" \
            --env HOME=/tmp \
            --volume "$PWD:/work" \
            --workdir /work \
            "$FENDIX_IMAGE" scan \
            --spec openapi.yaml \
            --code ./src \
            --format sarif \
            --output results.sarif \
            --fail-on HIGH
        continue-on-error: true  # Upload SARIF even if findings exist

      # A private repository needs GitHub Code Security for this upload.
      - name: Upload SARIF to GitHub
        if: hashFiles('results.sarif') != ''
        uses: github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
        with:
          sarif_file: results.sarif
          category: fendix

      - name: Fail on findings
        run: |
          docker run --rm \
            --user "$(id -u):$(id -g)" \
            --env HOME=/tmp \
            --volume "$PWD:/work" \
            --workdir /work \
            "$FENDIX_IMAGE" scan \
            --spec openapi.yaml \
            --code ./src \
            --format json \
            --fail-on HIGH
```

## GitHub Actions — Baseline Diff

Only report new findings by comparing against a saved baseline. This prevents alert fatigue from pre-existing issues.

```yaml
      - name: Download baseline
        uses: actions/download-artifact@v4
        with:
          name: fendix-baseline
          path: .fendix/
        continue-on-error: true  # First run has no baseline

      - name: Run scan with baseline
        run: |
          fendix scan \
            --spec openapi.yaml \
            --code ./src \
            --format json \
            --output findings.json \
            --baseline .fendix/baseline.json \
            --save-baseline .fendix/baseline.json \
            --fail-on HIGH

      - name: Upload baseline
        if: github.ref == 'refs/heads/main'
        uses: actions/upload-artifact@v4
        with:
          name: fendix-baseline
          path: .fendix/baseline.json
```

## GitHub Actions — Live API Scan

For scanning a deployed staging environment before promoting to production:

```yaml
      - name: Scan staging API
        run: |
          fendix scan \
            --url https://staging-api.example.com \
            --auth "Bearer ${{ secrets.STAGING_API_TOKEN }}" \
            --format sarif \
            --output results.sarif \
            --fail-on CRITICAL
```

## GitHub Actions — Active Probing (with consent)

Enable injection detection for pre-production environments:

```yaml
      - name: Active security scan
        run: |
          fendix scan \
            --url https://staging-api.example.com \
            --auth "Bearer ${{ secrets.STAGING_API_TOKEN }}" \
            --enable-active \
            --format sarif \
            --output results.sarif \
            --fail-on HIGH
```

## Re-rendering Reports

Re-render a saved JSON findings file as JSON, HTML, SARIF, or PDF. Common human
and CI conversions are:

```bash
# JSON -> HTML
fendix report --input findings.json --format html --output report.html

# JSON -> SARIF
fendix report --input findings.json --format sarif --output results.sarif

# JSON -> PDF
fendix report --input findings.json --format pdf --output report.pdf
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan complete, nothing reached status `BLOCK` |
| 1 | Scan complete, at least one finding reached status `BLOCK` |
| 2 | Scan error (network failure, invalid config, etc.) |

Use `--fail-on` to set the severity floor for the gate:
- `--fail-on CRITICAL` — only critical findings can block
- `--fail-on HIGH` — high or critical
- `--fail-on MEDIUM` — medium, high, or critical
- `--fail-on LOW` — low, medium, high, or critical can be considered; the
  evidence policy still prevents LOW-confidence findings from blocking

### Meeting the threshold is necessary, not sufficient (v2.0)

Since **v2.0**, `--fail-on` consults the deterministic confidence band as well
as severity. A finding at or above the threshold reaches `BLOCK` only when the
band supports the claim:

| Confidence band | Required evidence | Status |
|---|---|---|
| `HIGH` | independent or self-evident signal | **BLOCK** |
| `HIGH` | no signal | WARN |
| `MEDIUM` | at least one independent signal | **BLOCK** |
| `MEDIUM` | no independent signal | WARN |
| `LOW` | any evidence | WARN |
| any | marked unconfirmed-by-live-scan without an independent signal | WARN |

Independent signals include cross-engine agreement, a confirmed route,
reachable/proven taint path, a payload-validated probe, cross-tool agreement,
or a contradicted declared authentication requirement. Self-evident signals
include a deterministic response read, deterministic detection in production
source, or an imported high-precision rule. A provider-shaped token is not a
live credential validation. Every demotion is named in
`confidence_reasons`, so a WARN that used to be a BLOCK is attributable from
the report alone.

> **This changes the exit code of an existing pipeline.** A job that gated on
> `--fail-on` can now exit 0 where it exited 1 — most often on shape-match SAST
> findings (including the semgrep-shim tier) that carry no corroborating signal.
> A real hardcoded credential in production code still bands `HIGH` and still
> exits 1. Pass `--enforce-confidence=false` (or set
> `scan.enforce_confidence: false` in `.fendix.yaml`) to restore the pre-2.0
> severity-only mapping byte-for-byte.

A second, independent rule: `--deescalate-tests` (on by default) holds an
unsupported finding in test/fixture code at `WARN` even when it meets
`--fail-on`. Independent corroboration can still support a block.
`--deescalate-tests=false` turns that rule off; neither flag implies
the other.

## Suppressing Known Issues

Create a `.fendix-ignore` file to suppress known or accepted findings:

```yaml
ignore:
  - id: SEC-014
    reason: "Rate limiting handled at API gateway"
    until: 2026-12-01

  - endpoint: GET /health
    reason: "Public health check by design"

  - endpoint: GET /api/public/*
    category: auth
    reason: "Public endpoints intentionally unauthenticated"
```

For the full suppression model and guidance on when to suppress vs. fix,
see the [triage workflow](./triage-workflow.md).

## See also

- [JSON schema reference](./schema.md) — fields you can read in PR
  comment templates and dashboards.
- [Triage workflow](./triage-workflow.md) — what to do once findings
  start landing in PRs.
- [5-minute Juice Shop walkthrough](./walkthrough-juice-shop.md) — try
  the full pipeline locally before wiring it into CI.
