# `.fendix.yaml` — repo-committed policy

> **Status:** shipped in v0.6.2 (TASK-109).

A `.fendix.yaml` at the repo root pins your team's scan policy in
source control. CLI flags still work — they override the policy
file when present — so the file is a *default*, not a lock.

## Why a policy file

CLI-flags-only fendix worked for one-off scans, but doesn't scale:

- A six-flag invocation in your CI workflow drifts from the same
  six flags in your developer-runs-it-locally docs.
- Adding a new check (or a new severity threshold) means editing
  every workflow that invokes fendix.
- Reviewers can't see your scan posture in code review.

Committing `.fendix.yaml` fixes all three. The team's scan posture
is one diff away from your changelog.

## Precedence

Lowest to highest:

1. **Cobra defaults** baked into `fendix scan` — e.g. `workers: 10`.
2. **Policy file** values from `.fendix.yaml` (or `--config <path>`).
3. **Explicit CLI flags** the user passed on the command line.

CLI flags ALWAYS win when explicitly passed. This is the same
precedence model `git config` uses (system → global → local) and
matches what AppSec engineers expect from CI tools.

## How fendix finds the policy file

| Scenario | Policy resolved from |
|---|---|
| `--config <path>` | The exact path. Missing file is a hard error. |
| no `--config`, `.fendix.yaml` exists in cwd | `.fendix.yaml` (silent pickup) |
| no `--config`, no `.fendix.yaml` in cwd | flag-only (no policy applied) |

The "silent pickup" behavior is a deliberate design choice — running
`fendix scan` in a repo with policy committed should *just work*
without ceremony.

## Schema

```yaml
# .fendix.yaml — Fendix policy file

# Required. The policy schema version. Currently only `1` is valid.
# Older fendix builds reject newer version numbers rather than
# silently accepting a schema they do not understand.
version: 1

# Severity threshold for the scan to fail. Matches the --fail-on flag.
# Values: CRITICAL, HIGH, MEDIUM, LOW. Empty/missing disables the
# gate (warn-only mode).
fail_on: HIGH

# Path to the suppressions file (matches --ignore). Relative to the
# directory `fendix scan` is invoked from.
ignore_path: .fendix-ignore

# Scan-runtime knobs. Each field maps 1:1 to a CLI flag; the policy
# value is applied only when the corresponding CLI flag is NOT
# explicitly passed.
scan:
  enable_active: false   # --enable-active
  workers: 10            # --workers
  timeout: 10            # --timeout (seconds)
  delay_ms: 100          # --delay (ms)
  format: json           # --format (json | html | sarif | pdf)
  deescalate_tests: true # --deescalate-tests (findings in test/fixture code
                         #   report as INFO instead of WARN, and one at or
                         #   above `fail_on` is held at WARN unless a
                         #   corroborating signal backs it; the evidence is
                         #   always preserved)
  enforce_confidence: true # --enforce-confidence (a finding at or above
                         #   `fail_on` blocks only when its deterministic
                         #   confidence band and evidence support the claim:
                         #   HIGH needs an independent or self-evident signal,
                         #   MEDIUM needs an independent signal, LOW never
                         #   blocks. Set false to restore the legacy
                         #   severity-only gate.)

# Crawler discovery knobs.
crawler:
  crawl_depth: 1         # --crawl-depth (0 disables HTML link follow)
  max_endpoints: 500     # --max-endpoints (0 = no cap)
  wordlist_path: ""      # --wordlist (empty = built-in CommonPaths)
  respect_robots: false  # --respect-robots

# Soft-cap budgets that constrain CI cost. 0 = no cap.
budgets:
  max_requests: 0        # --max-requests
  max_duration: 0s       # --max-duration (e.g. 5m, 30s)

# Auth profile reference. Points at ~/.fendix/profiles/<name>.yaml,
# which is where the actual credentials live (and stay out of source
# control). Matches --profile.
auth:
  profile: ""
```

## What's intentionally NOT in the schema

These are per-invocation runtime concerns, not committable policy. The list is
exhaustive for the stable v3.6.0 `scan` surface:

- Targets, history and output: `--url`, `--spec`, `--code`, `--import`,
  `--diff`, `--staged`, `--fast`, `--baseline`, `--save-baseline`, `--output`,
  `--lang`, `--verbose`, `--debug-bundle`, and `--config` (the policy-file
  locator itself).
- Credentials: `--auth`, `--auth-type`, `--auth-header`, and `--auth-user2`.
  Use `auth.profile` for a committable reference and keep the credential in
  `~/.fendix/profiles/`.
- Probe and network safety: `--max-probes-per-endpoint` and
  `--allow-private-targets`.
- Analyzer selection and dependencies: `--python-engine`, `--checks`,
  `--no-native-deps`, `--use-pip-audit`, `--offline`, `--offline-db`,
  `--no-plugins`, and `--allow-repo-local-plugins`.
- Strict coverage and dependency policy: `--fail-on-scanner-error`,
  `--fail-on-coverage-gap`, `--require-analyzers`, and
  `--block-on-inapplicable`.

Since v3.5.0, releases also ship managed-CI producer flags as a preview (ADR-010). They are
not part of the stable CLI or the `.fendix.yaml` schema.

## Worked example

A typical Phase 14 setup:

`.fendix.yaml`:

```yaml
version: 1
fail_on: HIGH
ignore_path: .fendix-ignore
scan:
  enable_active: false  # active probing only on staging, never on prod
  workers: 16
  timeout: 15
crawler:
  respect_robots: true
budgets:
  max_requests: 5000
  max_duration: 5m
auth:
  profile: ci
```

`.fendix-ignore`:

```yaml
ignore:
  - id: SEC-014
    reason: "Rate limiting handled at API gateway"
    until: 2026-12-01
```

`~/.fendix/profiles/ci.yaml` (NOT committed; user-local):

```yaml
auth:
  type: bearer
  value: ${FENDIX_CI_TOKEN}  # resolved at scan time from env
```

The credential **must** be nested under `auth:`. A flat `type:` / `value:` at
the top level is not the profile schema; Fendix detects that specific mistake
and fails with the correction rather than silently scanning unauthenticated.

CI workflow:

```yaml
- run: fendix scan --url ${{ env.STAGING_URL }} --code ./
```

No flags besides the target. Policy lives in source control; the
secret stays in CI's secret store.

## Validation

`fendix scan --config .fendix.yaml ...` parses the file with strict
field checking enabled (`yaml.KnownFields(true)`) — so typos like
`fial_on:` produce a clear error rather than silently doing nothing.
The `version` field is mandatory and validated against the build's
supported version range.

## Versioning

This build supports exactly **`version: 1`**. It rejects a file declaring a
newer version with a clear error (`policy file declares version 2 but this
fendix build supports up to version 1`). Compatibility behavior for a future
schema version is not part of the current executable contract.

This is the opposite of YAML's default "ignore unknown fields"
behavior — we want surprises to be loud.

## Migrating from CLI-only

Find your team's most common `fendix scan` invocation in CI. Each
flag in that invocation is a candidate for `.fendix.yaml`:

| CLI flag | Policy field |
|---|---|
| `--fail-on HIGH` | `fail_on: HIGH` |
| `--enable-active` | `scan.enable_active: true` |
| `--workers 16` | `scan.workers: 16` |
| `--timeout 15` | `scan.timeout: 15` |
| `--delay 50` | `scan.delay_ms: 50` |
| `--format sarif` | `scan.format: sarif` |
| `--deescalate-tests=false` | `scan.deescalate_tests: false` |
| `--enforce-confidence=false` | `scan.enforce_confidence: false` |
| `--crawl-depth 2` | `crawler.crawl_depth: 2` |
| `--max-endpoints 1000` | `crawler.max_endpoints: 1000` |
| `--wordlist ./words.txt` | `crawler.wordlist_path: ./words.txt` |
| `--respect-robots` | `crawler.respect_robots: true` |
| `--max-requests 5000` | `budgets.max_requests: 5000` |
| `--max-duration 5m` | `budgets.max_duration: 5m` |
| `--ignore .fendix-ignore` | `ignore_path: .fendix-ignore` |
| `--profile ci` | `auth.profile: ci` |

After committing the policy, your CI workflow shrinks to one line:

```yaml
- run: fendix scan --url ${{ env.STAGING_URL }} --code ./
```

`fendix init` (TASK-105 + TASK-109) writes a starter `.fendix.yaml`
into your repo automatically — including the comments above so
future contributors know what each knob does.
