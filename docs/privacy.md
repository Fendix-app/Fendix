# Fendix Privacy & Data Handling

What the Fendix CLI reads, sends, and stores. The engine runs on your machine
or CI, requires no hosted account or backend, and has **no telemetry**. Fendix
also offers a separate optional hosted product; see the final section.

Last reviewed: 2026-10-03 (stable v3.4.1 contract).

## TL;DR

- **No telemetry.** Fendix never phones home about your usage, code, or findings.
- Built-in non-target network traffic comes from dependency-CVE tools during a
  `--code` scan (`api.osv.dev`, `vuln.go.dev`, or their tool wrappers).
- `--offline` controls native dependency analyzers. A current product defect
  leaves the auto-enabled Python deps check outside that flag; use the
  hermetic commands below until it is fixed.
- Findings, reports, and metrics stay **on your disk**. You choose where they go.

## What Fendix reads

| Input | Read when | Leaves your machine? |
|-------|-----------|----------------------|
| Source files under `--code` | white-box scan | No (analyzed locally) |
| The target URL under `--url` | black-box scan | Only requests to that target you specified |
| OpenAPI/Swagger under `--spec` | spec scan | A local file is parsed locally; an `http://` or `https://` spec URL is fetched from the address you supplied. |
| Dependency manifests (`requirements.txt`, `package-lock.json`, `go.mod`, …) | dep-CVE scan | Dependency tools and advisory services may receive manifest-derived data. `--offline` stops native lookups; the current Python limitation is described below. |

## Network egress contract

This mirrors the README "What Fendix sends to the network" section for the
built-in engine. External dependency tools and out-of-tree plugins have their
own behavior; review them before use.

| Scenario | Outbound traffic |
|----------|------------------|
| `fendix scan --url …` | Built-in DAST requests to the target you named. An enabled out-of-tree plugin may add its own traffic. |
| `fendix scan --spec …` | A remote spec URL is fetched; a local spec file is parsed locally. An enabled out-of-tree plugin may add its own traffic. |
| `fendix scan --code …` (default) | Native dependency-CVE lookups use `api.osv.dev` (PyPI/npm) and `vuln.go.dev` (Go, via govulncheck). Python dependency tools and out-of-tree plugins may add their own traffic. Other built-in code analyzers are local. |
| `fendix scan --code … --offline` | Native pip/npm use the snapshot and native govulncheck is skipped. The Python deps check may still call networked tools; see below. |
| `fendix scan --code … --no-native-deps` | Skips native dependency analyzers. The Python deps check remains enabled unless separately excluded. |
| `fendix scan` (no target) | Errors out. Zero outbound. |

The native OSV request path sends dependency coordinates. External tools such
as `npm audit`, `pip-audit`, and `govulncheck` are separate executables whose
request payloads are not constrained by the Fendix process. Consult the tool
version and configuration you install when that distinction matters.

Remote specs currently have two fetch paths when Python analysis runs. The Go
crawler uses its guarded client, while the Python spec parser refetches HTTPS
with `urllib` and does not inherit the Go private-IP policy; Python also rejects
plaintext HTTP that Go accepts. This is a product defect. Download a remote
spec through your own reviewed path and scan the local file when the network
boundary matters.

### Air-gapped mode

For native dependency analyzers, `--offline` is hermetic:

- pip / npm advisories are read from a local snapshot
  (`--offline-db`, default `~/.fendix/offline-db.json`, built with
  `fendix db update`).
- govulncheck needs `vuln.go.dev`, so in offline mode it is recorded
  **SKIPPED** rather than silently reaching the network.
- The native offline code path (`pip.ScanOffline` / `npm.ScanOffline`) takes no HTTP
  client at all — it is *structurally* incapable of a network call.

The `ScanRequest` sent to the Python engine has no offline field. Consequently,
the Python deps check auto-enabled by `--code` may invoke `pip-audit`,
`npm audit`, or `govulncheck` despite the top-level flag. This is a **product
defect**, not an accepted offline guarantee. For a built-in hermetic code scan:

```bash
# Keep Python auth/injection analysis, omit its deps check.
fendix scan --code . --offline --checks auth,injection --no-plugins

# Or run only the native analyzers.
fendix scan --code . --offline --python-engine=false --no-plugins
```

`--no-plugins` matters because out-of-tree plugins are executable code and can
implement their own network behavior. Verify the selected command with
`sudo tcpdump -n host not <target>`.

## What Fendix stores

| Artifact | Location | Notes |
|----------|----------|-------|
| Scan reports (JSON/HTML/SARIF/PDF) | wherever you point `--output` | You control retention |
| Config-leak findings | in the report | The served-file **body is never captured** — only the HTTP status + path, so a leaked secret isn't re-persisted into your report |
| Debug bundle (`--debug-bundle`) | the path you give | Redacted; opt-in, for bug reports |

### Product metrics

v0.20 added an **opt-in, local-only** metrics log:

- Off by default. Enabled only when `FENDIX_METRICS=true`.
- Written to `metrics/events.jsonl` (override with `FENDIX_METRICS_PATH`); the
  default is `.gitignore`d.
- **Structural data only** — version, scan phase, duration, finding *count*,
  memory. v0.25 adds per-invocation events (phase `cli`) recording the
  **subcommand name** (`scan`, `version`, … — never its arguments), the exit
  code, a success flag, and a coarse **error *class*** (`usage`, `scan-error`,
  … — never the error text). These power the local `CLI success rate` line in
  `fendix metrics show`. By construction the event record still has no field for
  source code, file paths, hostnames, secrets, arguments, or finding content.
- **Never transmitted.** `fendix metrics show/export/clear` operate purely on
  the local file. There is no analytics endpoint.

## Hosted / SaaS

The Fendix web application (dashboard, org workspaces) is a separate, optional
product with its own data handling and its own DPA. This document covers the
**CLI / engine**, which needs no account and no backend. If you only run the
CLI, none of the hosted-product data handling applies to you.

## Questions or a discrepancy?

If anything here doesn't match observed behavior, treat it as a security issue
and report it per [SECURITY.md](../SECURITY.md). See the [Trust Center](trust-center.md)
for the full picture.
