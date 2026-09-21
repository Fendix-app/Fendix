# GitHub App container publication

Status as of 2026-09-21: **publication candidate under review; deployment remains gated**.

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
revision. The separate `fendix-app-v3.4.1` Git tag identifies the reviewed
publication workflow revision; it does not change or recreate source release
`v3.4.1`.

The machine-readable contract is
[`deploy/fendix-app-release.json`](../deploy/fendix-app-release.json). The
workflow checks that the source tag resolves to the recorded commit before any
build can publish.

## Publication automation

[`.github/workflows/fendix-app-image.yml`](../.github/workflows/fendix-app-image.yml)
builds `Dockerfile.app` from the exact contract revision. Pull requests build
and run both declared platforms without registry credentials. A
`fendix-app-vX.Y.Z` tag can publish only when it matches the contract version.
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

## Deployment gate

The Kubernetes manifest intentionally retains its compatibility image until a
workflow run has published and independently verified the official digest.
After that run succeeds, the same focused change must:

- pin `deploy/k8s/fendix-app.yaml` to
  `docker.io/fendixapp/fendix-app@sha256:...`;
- record the human-readable `3.4.1` tag beside the digest;
- remove the narrow compatibility allowlist entry;
- add a regression assertion for the exact official repository and digest;
- pass rendered-manifest and Kubeconform checks; and
- preserve the old reference only in the historical migration record.

Until those steps are complete, the application image must not be announced as
the supported Kubernetes deployment image.
