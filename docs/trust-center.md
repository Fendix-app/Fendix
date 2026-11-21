# Fendix Trust Center

> Fendix is a security tool. The bar for trusting it must be higher than for
> ordinary software. This page is the single index of how we earn that trust —
> every claim links to something you can read, run, or reproduce.

Release-integrity references reviewed: **2026-11-21, v3.8.1**. The historical enterprise-review findings below retain their original evidence dates.

---

## 1. Security of the tool itself

| Topic | Where |
|-------|-------|
| Threat model (assets, trust boundaries, attacker model) | [docs/threat-model.md](threat-model.md) |
| Reporting a vulnerability + coordinated-disclosure timeline | [SECURITY.md](../SECURITY.md) — GitHub private vulnerability reporting |
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
| Native offline scanning and the current Python-deps limitation | [Privacy](privacy.md#air-gapped-mode) |
| Opt-in local product metrics (`FENDIX_METRICS`, never transmitted) | [Privacy](privacy.md#product-metrics) |

Short version: the CLI has **no telemetry**. Built-in non-target traffic comes
from dependency-CVE tools during a `--code` scan. `--offline` stops the native
lookups, but a current product defect leaves the auto-enabled Python deps check
outside that flag. See [Privacy](privacy.md) for the exact hermetic commands.

## 3. Integrity of what you install

The current stable release is [v3.8.1](https://github.com/Fendix-app/Fendix/releases/tag/v3.8.1), built from commit `e3e3eadaaecb8670973f7acbc7b0cc4d3fca34c0` with Go 1.27.4. It is a security rebuild of v3.8.0 with unchanged scanner behaviour, report schema and finding identity. Verification binds the bytes or image digest to that exact release signer; it does not certify that every bundled dependency has no advisory.

| Topic | Where |
|-------|-------|
| Releases are cosign-keyless signed (Sigstore Fulcio) | README "Verifying signed releases" · `.github/workflows/release.yml` |
| Install script verifies (fail-closed) before installing | [scripts/install.sh](../scripts/install.sh) — SHA-256 required (bypass only via explicit `FENDIX_ALLOW_UNVERIFIED=1`); optional cosign verification when `cosign` is present |
| Binary digests and source commit are bound by a signed release record | [SECURITY.md](../SECURITY.md#verifying-binary-release-binding) · [build-record contract](managed-ci/signed-build-record.md) |
| Workflow actions are SHA-pinned; enforced in CI | `.github/workflows/ci.yml` (actionlint + pin guard) |

## 4. Accuracy you can reproduce

| Topic | Where |
|-------|-------|
| "Benchmark before marketing" — methodology | [docs/benchmarks.md](benchmarks.md), [docs/accuracy.md](accuracy.md) |
| Committed baseline (regression-gated) | `benchmarks/baselines/baseline.json` + `fendix benchmark compare` |
| Honest limitations (framework-specific evidence and DAST precision caveats) | [docs/accuracy.md](accuracy.md), `TASK_MANIFEST.md` |

We publish weaknesses, not just wins. The v0.20 benchmark triage, for example,
found and disclosed a false-positive class in our own scanner before fixing it.

## 5. How to verify any of this yourself

```bash
# No telemetry — watch the wire during a scan:
sudo tcpdump -n host not <your-target> &   # then run a --code scan

# Native-only hermetic scan; disable out-of-tree executable plugins too:
fendix scan --code . --offline --python-engine=false --no-plugins

# Reproduce the benchmark baseline:
fendix benchmark run --target all

# Verify the current public container at its immutable v3.8.1 digest:
REF='docker.io/fendixapp/fendix@sha256:2752d6114b209b2c3b986b49950c0238b7e72d98c988eb9c5ee623fcd7c9ff1a'
IDENTITY='https://github.com/Fendix-app/Fendix/.github/workflows/release.yml@refs/tags/v3.8.1'
ISSUER='https://token.actions.githubusercontent.com'

cosign verify \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  "$REF"

# Verify the image SBOM and build provenance under the same release identity:
cosign verify-attestation --type cyclonedx \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$REF"
cosign verify-attestation --type slsaprovenance1 \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$REF"
```

See [install.md](install.md#verifying-release-artifacts-cosign) for binary verification,
including the clearly scoped historical identity required by releases through
v3.4.1.

Found a gap between a claim here and reality? That's a security report —
see [SECURITY.md](../SECURITY.md).
