# ADR-006: Report Output Formats

## Status

Accepted; amended for PDF and decision-aware SARIF.

## Current implementation addendum

The engine supports four formats: JSON, HTML, SARIF 2.1.0 and PDF. PDF is a
first-class renderer with an optional classification banner, rather than a
browser-print instruction.

SARIF rule metadata still maps intrinsic severity to
`defaultConfiguration.level` and `security-severity`. Each result's `level`
maps the finding decision (`BLOCK` → `error`, `WARN` → `warning`, `INFO` →
`note`), falling back to intrinsic severity only for archived/unstamped input.
Its partial-fingerprint key is the report's declared algorithm (`fendix/v2`
for current output), and `automationDetails.id` is mode-qualified.

## Context

Different users consume scan results in different ways:
- **Developers** want human-readable reports they can open in a browser
- **CI/CD systems** need machine-readable output for pipeline gating
- **Security platforms** (GitHub Code Scanning, Azure DevOps) use SARIF format
- **Scripts** need parseable JSON for automation

## Decision

Support three output formats, selectable via `--format`:

### JSON (default)
- Machine-readable findings with scan metadata
- Includes severity breakdown, source counts, scan duration
- Used as the baseline format for `--save-baseline` / `--baseline` diff

### HTML (self-contained)
- Single-file HTML report with no external dependencies (CSS/JS inline)
- Executive summary with severity breakdown cards
- Sortable findings table (severity, endpoint, source)
- Expandable rows with evidence and remediation
- Print-friendly CSS for PDF export

### SARIF 2.1.0
- Industry standard for static analysis results
- Compatible with GitHub Code Scanning `upload-sarif` action
- Maps Fendix severity to SARIF levels (CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note)
- Physical locations for whitebox findings (file + line), logical locations for blackbox (endpoint)
- CWE references mapped to MITRE URLs

## Consequences

**Positive:**
- Covers all major use cases (human, CI/CD, security platforms)
- HTML report is zero-dependency — can be shared as email attachment
- SARIF enables native integration with GitHub, Azure DevOps, etc.
- JSON serves as both output format and baseline storage format

**Negative:**
- Three renderers to maintain
- SARIF spec is complex — must validate against schema

**Mitigations:**
- `fendix report --input --format` re-renders without re-scanning
- SARIF output validated by comprehensive structural tests
- HTML template uses Go's html/template for safe rendering
