# Security Policy

Thanks for taking the time to make Fendix safer to ship and to use.

This document covers two things:

1. How to report a vulnerability **in Fendix itself** (the scanner — the
   binary, the Python engine, the release pipeline). For a higher-level
   discussion of how Fendix is *designed* to be safe when scanning targets
   that are not your own, see [`docs/threat-model.md`](docs/threat-model.md).
2. The release artifacts you should trust, and how to verify them.

---

## Supported versions

Current release: **v1.1.0** (2026-07-08 — see [`CHANGELOG.md`](CHANGELOG.md)).

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | ✅ active           |
| 1.0.x   | ✅ critical only    |
| < 1.0   | ❌ end of life      |

The post-1.0 policy announced pre-1.0 is now in force: **the latest two minor
versions are supported — full security fixes on the current minor, critical
fixes only on the previous one.** Everything below `1.0.0` (the whole `0.x`
line) is end of life and will not receive backports; upgrade to `1.1.x`.

A patch release on the supported branch is the delivery vehicle for a fix
(e.g. `1.1.1` for a `1.1.x` issue).

## Reporting a vulnerability

**Please do not open a public GitHub issue.**

Use one of the following private channels:

- **GitHub private vulnerability report** (preferred):
  <https://github.com/Fendix-app/Fendix/security/advisories/new>
- **Email**: `security@fendix.dev` (PGP key on request)

Include in your report:

- A clear description of the vulnerability and the affected component
  (Go binary, Python engine, release pipeline, embedded dependency, etc.).
- Steps to reproduce, or a minimal proof of concept.
- Fendix version (`fendix version`).
- Impact assessment if you have one — what an attacker can do, what
  privileges they need, what they can read/modify/destroy.
- Whether you intend to publish a write-up, and on what timeline. We
  prefer coordinated disclosure but will not block legitimate research.

You will receive an acknowledgement within **72 hours**, and a full
triage response within **7 days**. If we accept the report we'll work
with you on a fix and a release timeline; if we decline, you'll get a
written reason. If you don't hear back in 7 days, please escalate by
emailing the maintainer directly.

## Scope

In scope for this policy:

- The `fendix` binary built from this repo (`go/cmd/fendix`).
- The Python engine and its analyzers (`python/`).
- Vulnerabilities in dependencies that are reachable from a default
  scan (i.e. not just present in `go.sum` but actually called).
- The release pipeline (`.github/workflows/release.yml`) and its
  outputs — signed binaries, Docker image, Homebrew tap.
- Misuse of the active scanner that goes beyond the documented
  safety envelope (see [`docs/threat-model.md`](docs/threat-model.md)
  §"Active scanner safety envelope").

Out of scope:

- Findings produced by Fendix against a third-party target — those
  belong to the target's vendor.
- Theoretical issues that require an attacker to already control the
  machine running Fendix (e.g. "if I write a malicious `.fendix-ignore`
  file I can suppress findings"). The threat model assumes the host
  user is trusted.
- Self-DoS via input parameters — Fendix is a CLI scanner, not a
  service. If you can crash Fendix by feeding it a 50 MB malformed
  spec, that's a bug, but it's not a security issue.

## What's in the binary (transitive imports worth knowing about)

Fendix's "no telemetry" stance applies to code we control. One
transitive import is worth calling out explicitly so the marketing
claim matches the artifact:

- `golang.org/x/telemetry/counter` is pulled in via
  `golang.org/x/vuln/internal/scan`. It writes **local-only** counters
  to `~/.config/go/telemetry/local/` and uploads NOTHING unless the
  host user has separately run `go telemetry on`. Fendix code does
  not call `counter.Open` or otherwise activate uploads. Audit with
  `go list -deps ./go/cmd/fendix | grep telemetry`. See
  [`docs/threat-model.md`](docs/threat-model.md) §T6 for the full
  disclosure.

## Verifying release artifacts

Starting with the first cosign-enabled release after v0.5.0, every
release binary and the Docker image are signed with **cosign in
keyless mode** — Sigstore Fulcio + GitHub Actions OIDC. There is no
shared key to leak; signatures are bound to the GitHub Actions
identity that produced them.

### Verifying a binary

```sh
# After downloading both fendix-vX.Y.Z-linux-amd64 and the .sig + .crt
# sidecars from the GitHub release page:
cosign verify-blob \
  --certificate fendix-vX.Y.Z-linux-amd64.crt \
  --signature   fendix-vX.Y.Z-linux-amd64.sig \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  fendix-vX.Y.Z-linux-amd64
```

A successful verification prints `Verified OK`. Any mismatch — wrong
identity, wrong signing time, tampered binary — exits non-zero.

### Verifying the Docker image

```sh
cosign verify ghcr.io/abdel-rahmansaied/fendix:vX.Y.Z \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

### Verifying SLSA build provenance

Each release binary and the Docker image carry a SLSA v1.0 build
provenance attestation signed via cosign keyless (Sigstore Fulcio +
GitHub Actions OIDC). The predicate records the workflow file path,
the source commit SHA, the runner identity, and the build inputs.

```sh
# Per-binary SLSA provenance (the .intoto.jsonl sidecar):
cosign verify-blob-attestation \
  --signature fendix-vX.Y.Z-linux-amd64.intoto.jsonl \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --type slsaprovenance1 \
  fendix-vX.Y.Z-linux-amd64

# Docker image SLSA provenance (via Rekor):
cosign verify-attestation \
  --type slsaprovenance1 \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/abdel-rahmansaied/fendix:vX.Y.Z
```

SLSA level claim: **L2** (hosted, non-forgeable OIDC, automated,
source-versioned). The build also happens to satisfy L3 properties
(ephemeral runner, parameterless, the build script is pinned by the
commit SHA the attestation records), but L3 requires a third-party
attestor that we don't currently use. Operators with strict SLSA
gates can self-verify the L3 properties from the predicate JSON.

### Verifying the SBOM

Each release ships a CycloneDX SBOM (`*.cdx.json`) and an SPDX SBOM
(`*.spdx.json`) per binary, both cosign-signed. The Docker image
carries an in-toto attestation uploaded to Rekor.

```sh
# Per-binary SBOM signature (same flow as the binary itself):
cosign verify-blob \
  --certificate fendix-vX.Y.Z-linux-amd64.cdx.json.crt \
  --signature   fendix-vX.Y.Z-linux-amd64.cdx.json.sig \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  fendix-vX.Y.Z-linux-amd64.cdx.json

# Docker image SBOM attestation (verifies against the Rekor log):
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "^https://github.com/Abdel-RahmanSaied/Fendix/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/abdel-rahmansaied/fendix:vX.Y.Z
```

Pipe the verified CycloneDX into your usual SBOM-consuming tooling
(e.g. `grype` for CVE scanning, the Dependency-Track upload API for
procurement records).

### Until cosign is enabled

Pre-cosign releases (v0.5.0 and earlier) ship with `.sha256` sidecars
only. Verify the SHA matches what GitHub publishes on the release page
and that the URL is the canonical one
(`https://github.com/Fendix-app/Fendix/releases/download/...`).
We recommend pinning to a specific tag rather than `:latest` until
you've cut a cosign-verified upgrade path into your installer.

Note: the `enforce-signing` job in `.github/workflows/release.yml`
refuses to release a `v*` tag unless cosign signing is on (or
explicitly set to `allow-unsigned` for debugging), so any v0.6.0+
release that lands on the GitHub releases page MUST carry the
sidecars described above.

## Disclosure timeline

Once a fix is ready, we publish it via **all** of:

- A GitHub Security Advisory, with CVE assignment (we are a CNA-eligible
  open-source project under GitHub's CNA umbrella).
- A patched release on the supported branch (e.g. `1.1.1` for a `1.1.x`
  fix), with the security advisory linked from the release notes.
- A `### Security` block in `CHANGELOG.md` summarising the issue and the
  fix.
- Credit to the reporter (unless they request anonymity).

We aim to publish within **14 days** of the fix landing. Reporters can
request a longer embargo if downstream coordination is needed.

## Policy for active-scanner misuse

Fendix's active scanner sends real payloads (SQLi, CMDi, CRLF) to a
target host. This is *only* legitimate when:

- The target is owned by the operator (`localhost`, staging, the org's
  own production), **or**
- The operator has written authorisation to test it (a pentest scope of
  work, a CTF, a bug-bounty program with explicit authorisation for
  active probing).

Reports of the form "Fendix can be used as an attack tool" without
evidence that the safety envelope is broken (see threat-model doc) are
not in scope. Reports that the safety envelope itself can be bypassed
**are** in scope and should be filed via the channels above.

## Recognition

A `SECURITY.md` Hall of Fame section will be added as soon as we
receive our first valid report. If you'd rather not be listed, just
say so in your report.
