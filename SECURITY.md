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

Current stable release: **v3.8.1** (2026-11-20 — see
[`CHANGELOG.md`](CHANGELOG.md)).

| Version | Supported          |
| ------- | ------------------ |
| 3.8.x   | ✅ active           |
| 3.7.x   | ✅ critical only    |
| < 3.7   | ❌ end of life      |

The post-1.0 policy announced pre-1.0 is now in force: **the latest two minor
versions are supported — full security fixes on the current minor, critical
fixes only on the previous one.** Everything below `3.7.0` is end of life and
will not receive backports; upgrade to `3.8.x`.

A patch release on the supported branch is the delivery vehicle for a fix
(e.g. `3.8.1` for a `3.8.x` issue).

## Reporting a vulnerability

**Please do not open a public GitHub issue.**

Report it privately through GitHub private vulnerability reporting:
<https://github.com/Fendix-app/Fendix/security/advisories/new>

This is the only reporting channel at present. There is no security email
address yet; this policy will list one once it is set up and tested.

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
adding a comment to your private report.

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

### Verifying current binaries

```sh
# Download the binary and its .sig + .crt sidecars from this release:
VERSION=v3.8.1
ASSET="fendix-${VERSION}-linux-amd64"
IDENTITY="https://github.com/Fendix-app/Fendix/.github/workflows/release.yml@refs/tags/${VERSION}"
cosign verify-blob \
  --certificate "${ASSET}.crt" \
  --signature "${ASSET}.sig" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$ASSET"
```

A successful verification prints `Verified OK`. Any mismatch — wrong
identity, wrong signing time, tampered binary — exits non-zero.

### Verifying the Docker image

The v3.8.1 multi-architecture manifest is pinned below. Its signature, CycloneDX SBOM and SLSA provenance use the same exact release workflow identity. Binaries and the image toolchain use Go 1.27.4; this fixes CVE-2026-97054 (GO-2026-6859). The remaining image advisories require their own reachability review; a valid signature is not a vulnerability-free claim.

```sh
REF='docker.io/fendixapp/fendix@sha256:2752d6114b209b2c3b986b49950c0238b7e72d98c988eb9c5ee623fcd7c9ff1a'
IDENTITY='https://github.com/Fendix-app/Fendix/.github/workflows/release.yml@refs/tags/v3.8.1'
ISSUER='https://token.actions.githubusercontent.com'

cosign verify \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  "$REF"
```

### Verifying binary release binding

The v3.8.1 release publishes a signed `build-record.json` that binds each
executable digest to its release tag, source commit and workflow. Verify the
record's signature, then compare the downloaded binary with its entry:

```sh
VERSION=v3.8.1
ASSET="fendix-${VERSION}-linux-amd64"
BASE="https://github.com/Fendix-app/Fendix/releases/download/${VERSION}"
for FILE in build-record.json build-record.json.crt build-record.json.sig; do
  curl -fsSL -o "$FILE" "$BASE/$FILE"
done

cosign verify-blob \
  --certificate build-record.json.crt \
  --signature build-record.json.sig \
  --certificate-identity "https://github.com/Fendix-app/Fendix/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  build-record.json && python3 - "$ASSET" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

record = json.loads(Path("build-record.json").read_text())
asset = Path(sys.argv[1])
expected_source = {
    "repository": "Fendix-app/Fendix",
    "tag": "v3.8.1",
    "commit": "e3e3eadaaecb8670973f7acbc7b0cc4d3fca34c0",
}
if record["engine_version"] != "v3.8.1" or record["source"] != expected_source:
    raise SystemExit("unexpected release or source in build record")
entries = [a for a in record["artifacts"] if a["download_name"] == asset.name]
digest = "sha256:" + hashlib.sha256(asset.read_bytes()).hexdigest()
if len(entries) != 1 or entries[0]["executable_sha256"] != digest:
    raise SystemExit("binary does not match the signed build record")
print("Binary matches the signed v3.8.1 release record")
PY
```

### Verifying per-binary SLSA provenance

From the first release after v3.8.1, each binary ships a Sigstore bundle,
`fendix-vX.Y.Z-<os>-<arch>.sigstore.json`. The bundle holds the DSSE-signed
SLSA v1.0 provenance, the Fulcio certificate and the Rekor inclusion proof, so
it verifies on its own:

```sh
VERSION=vX.Y.Z   # a release after v3.8.1
ASSET="fendix-${VERSION}-linux-amd64"
BASE="https://github.com/Fendix-app/Fendix/releases/download/${VERSION}"
for FILE in "$ASSET" "$ASSET.sigstore.json"; do
  curl -fsSL -o "$FILE" "$BASE/$FILE"
done

cosign verify-blob-attestation \
  --bundle "${ASSET}.sigstore.json" \
  --new-bundle-format \
  --type slsaprovenance1 \
  --certificate-identity "https://github.com/Fendix-app/Fendix/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${ASSET}"
```

The release workflow runs this same command on every binary before it
publishes, so a release whose recipe would fail is never published.

The `.predicate.json` and `.intoto.jsonl` files beside each binary are the
plain predicate and in-toto statement. They carry no signature; do not pass
them to cosign as a signature.

**Releases up to and including v3.8.1 have no per-binary bundle.** Their
`.intoto.jsonl` is an unsigned statement and cannot be verified on its own
(issue #90); they will not be re-signed. For those releases, the binary
signature and the signed build record above are the verifiable release
bindings. See [the build-record contract](docs/managed-ci/signed-build-record.md).

<a name="verifying-slsa-build-provenance"></a>

### Verifying container SLSA build provenance

The Docker image carries a verifiable SLSA v1.0 provenance attestation signed
via cosign keyless (Sigstore Fulcio + GitHub Actions OIDC). It records the
workflow, source commit, runner and build inputs:

```sh
REF='docker.io/fendixapp/fendix@sha256:2752d6114b209b2c3b986b49950c0238b7e72d98c988eb9c5ee623fcd7c9ff1a'
IDENTITY='https://github.com/Fendix-app/Fendix/.github/workflows/release.yml@refs/tags/v3.8.1'
ISSUER='https://token.actions.githubusercontent.com'

cosign verify-attestation \
  --type slsaprovenance1 \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  "$REF"
```

The project's SLSA **L2** claim applies to this container provenance: hosted
builds, workflow-bound OIDC identity, automation and versioned sources. No
independent L3 certification is claimed. The binary build record above is a
release binding, not a standalone SLSA-level claim.

### Verifying the SBOM

Each release ships a CycloneDX SBOM (`*.cdx.json`) and an SPDX SBOM
(`*.spdx.json`) per binary, both cosign-signed. The Docker image
carries an in-toto attestation uploaded to Rekor.

```sh
# Per-binary SBOM signature (same flow as the binary itself):
cosign verify-blob \
  --certificate fendix-v3.8.1-linux-amd64.cdx.json.crt \
  --signature   fendix-v3.8.1-linux-amd64.cdx.json.sig \
  --certificate-identity "https://github.com/Fendix-app/Fendix/.github/workflows/release.yml@refs/tags/v3.8.1" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  fendix-v3.8.1-linux-amd64.cdx.json

# Docker image SBOM attestation (verifies against the Rekor log):
REF='docker.io/fendixapp/fendix@sha256:2752d6114b209b2c3b986b49950c0238b7e72d98c988eb9c5ee623fcd7c9ff1a'
IDENTITY='https://github.com/Fendix-app/Fendix/.github/workflows/release.yml@refs/tags/v3.8.1'
ISSUER='https://token.actions.githubusercontent.com'

cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" \
  "$REF"
```

Pipe the verified CycloneDX into your usual SBOM-consuming tooling
(e.g. `grype` for CVE scanning, the Dependency-Track upload API for
procurement records).

### Historical binary verification through v3.4.1

Binaries and packages published through v3.4.1 were signed before the
repository moved to `Fendix-app`, and their immutable certificates keep that
earlier workflow identity. Verify them with
[`docs/historical-release-verification.md`](docs/historical-release-verification.md).
Never use that identity for current releases or the official Docker Hub image.

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
