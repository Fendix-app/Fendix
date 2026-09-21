# Fendix Trust Center

> Fendix is a security tool. The bar for trusting it must be higher than for
> ordinary software. This page is the single index of how we earn that trust —
> every claim links to something you can read, run, or reproduce.

Last reviewed: 2026-06-28 (v0.21 — Earn Trust).

---

## 1. Security of the tool itself

| Topic | Where |
|-------|-------|
| Threat model (assets, trust boundaries, attacker model) | [docs/threat-model.md](threat-model.md) |
| Reporting a vulnerability + coordinated-disclosure timeline | [SECURITY.md](../SECURITY.md) — `security@fendix.dev`, PGP on request |
| Supported versions / patch policy | [SECURITY.md](../SECURITY.md) |

### HIGH-severity findings — status

Tracked against the independent enterprise review (`ENTERPRISE_REVIEW_2026-06-07.md`).
Verified 2026-06-28:

| Finding | Status |
|---------|--------|
| F-H1 SSRF egress guard (metadata IP / RFC1918 / DNS-rebind, all scanner clients) | ✅ Fixed — `internal/netguard`, locked by `TestIsBlockedAddr` |
| F-H2 Plugin sandboxing (repo-local opt-in OFF by default; symlink/ownership/env-allowlist pre-exec checks) | ✅ Fixed — `internal/plugin`, locked by `TestDefaultRoots_OmitsRepoLocalByDefault` |
| F-H3 GitHub-App token (per-invocation `http.extraheader`, never `.git/config`; scrubbed from child env) | ✅ Fixed — `internal/ghapp`, locked by `TestFendixScanner_Run_Success` + `TestScrubTokenFromEnv` |
| F-H5a Webhook handler async + bounded (worker pool + dedup) | ✅ Fixed — `internal/ghapp/worker.go` |
| F-H5b AST taint recursion bomb (depth + cycle caps) | ✅ Fixed — `_MAX_TAINT_HOPS` in `python/analyzers/ast_analyzer.py` |
| Config-file-exposure false positives on SPA catch-all servers | ✅ Fixed (v0.21) — body/Content-Type check in `internal/scanner/configleak.go` |

We do **not** currently hold SOC 2 / ISO certifications, and we don't claim to.
What we offer instead is reproducibility: the code, the tests, and the
benchmark are all public and you can verify each item above yourself.

## 2. What Fendix does with your data

| Topic | Where |
|-------|-------|
| Network egress contract (what leaves your machine, when) | [Privacy](privacy.md) · README "What Fendix sends to the network" |
| Air-gapped / hermetic scanning (`--offline`) | [Privacy](privacy.md#air-gapped-mode) |
| Opt-in local product metrics (`FENDIX_METRICS`, never transmitted) | [Privacy](privacy.md#product-metrics) |

Short version: Fendix has **no telemetry**. The only non-target traffic is
dependency-CVE lookups during a `--code`/`--spec` scan, and `--offline` turns
those off. See [Privacy](privacy.md) for the full contract.

## 3. Integrity of what you install

| Topic | Where |
|-------|-------|
| Releases are cosign-keyless signed (Sigstore Fulcio) | README "Verifying signed releases" · `.github/workflows/release.yml` |
| Install script verifies (fail-closed) before installing | [scripts/install.sh](../scripts/install.sh) — SHA-256 required (bypass only via explicit `FENDIX_ALLOW_UNVERIFIED=1`); optional cosign verification when `cosign` is present |
| Workflow actions are SHA-pinned; enforced in CI | `.github/workflows/ci.yml` (actionlint + pin guard) |

## 4. Accuracy you can reproduce

| Topic | Where |
|-------|-------|
| "Benchmark before marketing" — methodology | [docs/benchmarks.md](benchmarks.md), [docs/accuracy.md](accuracy.md) |
| Committed baseline (regression-gated) | `benchmarks/baselines/baseline.json` + `fendix benchmark compare` |
| Honest limitations (e.g. no Java until v0.27; DAST precision caveats) | [docs/accuracy.md](accuracy.md), `TASK_MANIFEST.md` |

We publish weaknesses, not just wins. The v0.20 benchmark triage, for example,
found and disclosed a false-positive class in our own scanner before fixing it.

## 5. How to verify any of this yourself

```bash
# No telemetry — watch the wire during a scan:
sudo tcpdump -n host not <your-target> &   # then run a --code scan

# Hermetic scan — zero outbound:
fendix scan --code . --offline

# Reproduce the benchmark baseline:
fendix benchmark run --target all

# Verify the current public container at its immutable v3.4.1 digest:
REF='docker.io/fendixapp/fendix@sha256:88783a1a032f925630bdb0977b37821add5e3381d347f91ec101401f4e98e02a'
IDENTITY='^https://github.com/Fendix-app/Fendix/.github/workflows/release.yml@refs/heads/main$'
ISSUER='https://token.actions.githubusercontent.com'

cosign verify \
  --certificate-identity-regexp "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  "$REF"
```

See [install.md](install.md#verifying-release-artifacts-cosign) for binary verification,
including the clearly scoped historical identity required by releases through
v3.4.1.

Found a gap between a claim here and reality? That's a security report —
see [SECURITY.md](../SECURITY.md).
