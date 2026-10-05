# Verifying releases through v3.4.1

Current releases are signed by the release workflow of
`Fendix-app/Fendix`; verify them with the commands in
[`SECURITY.md`](../SECURITY.md#verifying-release-artifacts) and
[`docs/install.md`](install.md#verifying-release-artifacts-cosign).

This page exists only for artifacts published **through v3.4.1**. Those
releases were signed before the repository moved to the `Fendix-app`
organization. A Sigstore certificate records the workflow that signed it and
can never be reissued, so their certificates name the workflow at the
repository's previous location, and verifying them against the current
identity fails:

```text
none of the expected identities matched what was in the certificate
```

The previous identity below is retained solely to verify those already
published artifacts. It is not a download location, and no release after
v3.4.1 is signed with it.

## Binaries and `.deb` / `.rpm` packages

```sh
VERSION=v3.4.1
ASSET=fendix-${VERSION}-linux-amd64   # or …-linux-amd64.deb / .rpm, or another platform
BASE="https://github.com/Fendix-app/Fendix/releases/download/${VERSION}"
# Signing workflow before the repository transfer. Historical artifacts only.
HISTORICAL_SIGNER="https://github.com/Abdel-RahmanSaied/Fendix/.github/workflows/release.yml"

curl -fsSL -o "$ASSET"     "$BASE/$ASSET"
curl -fsSL -o "$ASSET.crt" "$BASE/$ASSET.crt"
curl -fsSL -o "$ASSET.sig" "$BASE/$ASSET.sig"

cosign verify-blob \
  --certificate "$ASSET.crt" \
  --signature   "$ASSET.sig" \
  --certificate-identity "${HISTORICAL_SIGNER}@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$ASSET"
# → Verified OK
```

The official installer applies the same rule automatically: `install.sh`
expects the historical signer for v3.4.1 and earlier and the
`Fendix-app/Fendix` workflow for every later release.

## What this does not cover

- **The Docker Hub image** (`docker.io/fendixapp/fendix`) is verified with the
  current identity; see [`SECURITY.md`](../SECURITY.md).
- **New releases** never use the historical signer. A current-release
  certificate that names it is a verification failure, not a compatibility
  case.
