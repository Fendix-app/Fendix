# GitHub App container publication

Status as of 2026-09-21: **published, independently verified, and pinned for deployment**.

The `fendix-app` service is built by [`Dockerfile.app`](../Dockerfile.app). It
packages the GitHub webhook service, Fendix CLI, Python engine, Git, and runtime
dependencies. It is a different product surface from the CLI/engine image at
`docker.io/fendixapp/fendix`; the two images are never substituted for one
another.

## Version decision

The application source and `Dockerfile.app` are both present in signed source
release `v3.4.1`, whose commit is
`1bc69125c1af330d303f0ddd58e4db10fc6f2d3c`. No independent application
release existed before this migration. The first official application image
therefore uses immutable image tag `3.4.1`, built from that exact source
revision. Separate `fendix-app-v3.4.1-rN` Git tags identify immutable reviewed
publication-workflow revisions; they do not change or recreate source release
`v3.4.1`. Revision `r1` failed safely during candidate verification before any
Docker Hub tag was published. The contract advances to `r2` for the corrected
workflow and retains `r1` as audit history.

The machine-readable contract is
[`deploy/fendix-app-release.json`](../deploy/fendix-app-release.json). The
workflow checks that the source tag resolves to the recorded commit before any
build can publish.

## Publication automation

[`.github/workflows/fendix-app-image.yml`](../.github/workflows/fendix-app-image.yml)
builds `Dockerfile.app` from the exact contract revision. Pull requests build
and run both declared platforms without registry credentials. A
`fendix-app-vX.Y.Z-rN` tag can publish only when it exactly matches the
contract's publication revision.
The workflow then:

1. validates the stable source release, public Docker Hub repository, and
   scoped publisher authorization;
2. builds an isolated `linux/amd64` and `linux/arm64` candidate with BuildKit
   SBOM and provenance enabled;
3. starts both candidate images with generated test credentials and verifies
   `/healthz` and the compiled version;
4. scans build output, image configuration, history, layers, and logs for
   generated or publishing credential material;
5. refuses to replace an existing immutable version with different bytes;
6. copies the verified candidate to `docker.io/fendixapp/fendix-app:X.Y.Z`;
7. anonymously pulls and re-runs both platform smoke tests by manifest digest;
8. signs that digest with keyless Cosign, attaches a CycloneDX SBOM and SLSA
   provenance, and verifies all three against the exact official workflow
   identity; and
9. moves `X.Y`, `X`, and `latest` only after every immutable gate succeeds.

GitHub Actions secrets provide Docker Hub credentials. They are never copied
into source, workflow output, build arguments, or the image.

## Published result

[Workflow run 35589325882](https://github.com/Fendix-app/Fendix/actions/runs/35589325882)
published immutable tag `3.4.1` and moved `3.4`, `3`, and `latest` only after
all publication gates passed. Every tag resolves to this manifest digest:

```text
sha256:cdd0fabae6e80abbc3724628e876680f630f2005d378fd47b19265c86fd24d46
```

The verified platform manifests are:

```text
linux/amd64  sha256:45333aba57779d7a5d0b4d16b443b8585401c73880dd16642c82706cfed27e63
linux/arm64  sha256:b7303fb1ccca2a2be2c1fa605a7da31c68a7593edf29c12072e865fb9879a3aa
```

The GitHub Actions and independent follow-up checks passed anonymous pulls,
startup and `/healthz`, image configuration/history/layer/log credential
scans, the Cosign signature, the CycloneDX SBOM attestation, and the SLSA
provenance attestation. The verified certificate identity is:

```text
https://github.com/Fendix-app/Fendix/.github/workflows/fendix-app-image.yml@refs/tags/fendix-app-v3.4.1-r2
```

The Kubernetes reference deployment is pinned to the manifest digest above.
`scripts/check-public-claims.py` rejects a personal namespace, mutable tag,
different digest, additional application image, or private pull configuration.
`deploy/k8s/kustomization.yaml` supplies the rendered manifest checked by
Kubeconform.

## Independent verification

```bash
REF='docker.io/fendixapp/fendix-app@sha256:cdd0fabae6e80abbc3724628e876680f630f2005d378fd47b19265c86fd24d46'
IDENTITY='https://github.com/Fendix-app/Fendix/.github/workflows/fendix-app-image.yml@refs/tags/fendix-app-v3.4.1-r2'
ISSUER='https://token.actions.githubusercontent.com'

docker buildx imagetools inspect "$REF"
DOCKER_CONFIG="$(mktemp -d)" docker pull "$REF"
cosign verify --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$REF"
cosign verify-attestation --type cyclonedx --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$REF"
cosign verify-attestation --type slsaprovenance1 --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$REF"
```
