# Dependency CVE Check

**Engine:** Go (white-box) — `go/internal/scanner/deps/{govulncheck,npm,pip}`, native since TASK-119 (orchestrator step 3.5, disable with `--no-native-deps`). The Python `analyzers/deps.py` path also runs when the Python phase is enabled; `--code` auto-enables that phase unless `--python-engine=false` is explicit. Its findings collapse into native output through dedup.
**Category:** `deps`
**Severity as emitted:** vulnerability advisories are HIGH; coverage/config
observations such as native npm lockfile-missing and Python unpinned-range
findings are INFO. Correlation and consistency policy may adjust later.
**Active probing:** No (static analysis)

## What It Detects

Known vulnerabilities in project dependencies, by reading the manifests that
record exactly which versions are installed.

## Supported Manifest Files

| File | Ecosystem | Discovery |
|---|---|---|
| `requirements.txt` | PyPI | Recursive, up to 3 levels below `--code` (a monorepo's `service/requirements.txt` is found) |
| `poetry.lock` | PyPI | Same walk |
| `Pipfile.lock` | PyPI | Same walk |
| `package-lock.json` | npm | Repo root. A `package.json` with no lockfile emits one INFO finding (`SEC-NPM_LOCKFILE_MISSING`) rather than a silent skip — ranges (`"^4.17.1"`) don't say what is installed |
| `go.mod` | Go modules | Repo root, via `govulncheck` (real call-graph reachability) |

## How It Works

1. **Default path — OSV.dev.** The pip and npm scanners batch every pinned
   `(package, version)` into `api.osv.dev/v1/querybatch`. `/v1/querybatch`
   answers with bare vuln ids — no summary, no aliases, no affected ranges — so
   any package it reports as vulnerable is re-fetched through the per-package
   `/v1/query` before findings are built. The cost is one extra request per
   **vulnerable** package, not per record. If hydration fails the degraded
   record is still reported, with a stderr warning.
2. **Go modules** go through `govulncheck` against `vuln.go.dev`, which resolves
   real call-graph reachability rather than manifest presence.
3. **Alias merge.** Each `(package, version)` result set is partitioned into
   alias-connected components — union-find over `{id} ∪ aliases` — and one
   finding is emitted per component. See [Finding identity](#finding-identity).
4. **Applicability.** An advisory scoped to an importable sub-component is
   checked against the scanned tree; if nothing imports it, the finding loses
   confidence but is never dropped. See
   [Applicability](#applicability-de-escalation).
5. **Caching.** Responses are cached per `(package, version)` under
   `~/.fendix/cache/osv-{pypi,npm}/` for **24 hours**. There is no cache-bust
   flag — delete the directory to force a refresh. An advisory published in the
   last day is not seen until the entry expires, and one withdrawn in the last
   day keeps being reported.

### Alternative paths

| Flag | Behaviour |
|---|---|
| `--use-pip-audit` | Shells out to `pip-audit --format json` instead of querying OSV directly. If `pip-audit` is not on `PATH`, a warning is emitted and the OSV path is used — never a silent fail-closed. |
| `--offline` | Native pip/npm read the local snapshot at `--offline-db` (default `~/.fendix/offline-db.json`, built with `fendix db update`), and native govulncheck is recorded `SKIPPED`. A current product defect leaves the auto-enabled Python deps check outside this flag, so `--offline` alone does not guarantee zero outbound calls. Use `--offline --checks auth,injection --no-plugins` or `--offline --python-engine=false --no-plugins` for the documented hermetic built-in paths. |
| `--no-native-deps` | Disables the in-process Go SCA entirely. |

## Finding identity

**As of v2.0 a dependency finding is one per vulnerability, not one per OSV
record.** OSV's `/v1/query` returns the GHSA record and each PYSEC record for
the same underlying bug as separate `vulns[]` entries; before v2.0 each became
its own finding. Verified against live OSV.dev, `cryptography==48.0.1` returns
**six** records that are **three** real vulnerabilities.

The finding is named after the **canonical** id of its alias set — `CVE-*`
first, then `GHSA-*`, then `PYSEC-*`, then everything else, lexicographically
smallest within a tier. The picker ranges over aliases as well as top-level
ids, because OSV routinely carries the CVE only as an alias. So
`SEC-DEPS-PYSEC_2026_3552` is now `SEC-DEPS-CVE_2026_69247`.

Nothing is dropped: every merged id is preserved in `references`. Two
alias-linked records whose affected version ranges are provably disjoint are
**not** merged — alias data is not verified upstream — and the refusal is logged
to stderr.

> **Historical v2 migration:** under the then-current `fendix/v1` identity,
> this title change invalidated dependency baselines and fingerprint rules.
> Current v3+ builds use the semantic `fendix/v2` algorithm, which excludes
> title and package version. Any artifact created before v3.0.0 must still be
> regenerated once because the algorithm itself changed; see
> [`schema.md`](../schema.md). `fendix
> verify` matches the preserved id set, so a finding recorded under the old id
> resolves to its renamed twin instead of being reported as fixed.

`govulncheck` is deliberately untouched: `vuln.go.dev` emits one `GO-*` record
per vulnerability with aliases pointing outward, so the duplicate-record problem
does not arise there.

## Upgrade advice

The `fix` string names a version you can actually move to. Two rules, both v2.0:

- **GIT ranges are ignored.** An OSV `GIT` range's `fixed` event carries a commit
  SHA, not a release. Before v2.0 whichever range the advisory listed first won,
  so a finding could tell you to "upgrade to" a SHA. An absent `type` is still
  treated as `ECOSYSTEM` (the offline-snapshot and pip-audit adapters synthesise
  ranges without one).
- **The version is chosen relative to your pin.** Within one advisory: the
  lowest `fixed` version strictly greater than the installed version — the
  minimal in-branch upgrade. Across the alias-merged members of one finding: the
  maximum of those candidates, so the printed version fixes every vulnerability
  the finding reports. An advisory that patches several release branches lists
  one `fixed` per branch, so a user pinned at `5.2.16` is told `5.2.17`, not
  `6.0.8`.

A version is never invented. An advisory with no usable `fixed` event prints the
honest sentinel: *"Upgrade to a patched version (no fix listed in OSV)."*

## Applicability de-escalation

A Django advisory that only touches `django.contrib.gis` is real — the
vulnerable code is installed — but a project that never imports GeoDjango cannot
reach it. Since v2.0, `internal/scanner/deps/applicability` consults a small
curated catalog and, when an advisory maps to an importable component, greps the
scanned tree for it. If nothing imports it, the finding gains one sentence of
evidence saying so and a named **−10** confidence delta, which typically moves it
from the HIGH band to MEDIUM.

This is de-escalation and nothing else: the finding keeps its id, severity,
endpoint, upgrade advice and original evidence text verbatim. Nothing is
suppressed.

It is deterministic and cheap: the catalog is Go literals, the package tier only
fires when the advisory's own summary names the component, the grep is one walk
for all advisories at once, a scan whose advisories are not in the catalog
touches the filesystem zero times, and it **fails open** at full confidence if
the tree exceeds the file budget or the walk cannot complete. The matchers
deliberately over-match — a false "imported" costs nothing, a false "not
imported" quietly discounts a real risk. Fully dynamic imports
(`importlib.import_module(name)`) are a known blind spot, which is why the
penalty is a modest −10 rather than something that could move a band alone.

Because a MEDIUM band blocks only with an independent signal, this delta can
change an exit code — see [`--enforce-confidence`](../../README.md#common-scan-flags).

## Example Finding

```json
{
  "id": "SEC-DEPS-CVE_2026_69247",
  "title": "Vulnerable dependency: cryptography==48.0.1 (CVE-2026-69247)",
  "severity": "HIGH",
  "source": "whitebox",
  "category": "deps",
  "endpoint": "requirements.txt",
  "evidence": "cryptography==48.0.1: <advisory summary, truncated to 200 chars>",
  "fix": "Upgrade to cryptography==50.0.0 or later.",
  "references": ["CVE-2026-69247", "GHSA-xxxx-xxxx-xxxx", "PYSEC-2026-3552"],
  "confidence": "HIGH",
  "line": "requirements.txt"
}
```

`references` carries every id merged into this finding. The scanner emits the
canonical id first; `engine.Deduplicate` re-sorts the list, so by the time a
report renders they are alphabetical.

## References

- [CWE-1035: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)
- [OWASP A06: Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
