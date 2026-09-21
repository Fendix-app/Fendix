# GitHub App container status

The `fendix-app` service remains supported in source. It is built by
[`Dockerfile.app`](../Dockerfile.app), which compiles `go/cmd/fendix-app` and
packages the webhook service, the Fendix CLI, the embedded Python engine, and
the runtime dependencies used during scans.

The repository does not currently publish an official `fendix-app` container:

- none of the workflows in `.github/workflows/` builds or publishes
  `Dockerfile.app`;
- no brand-owned package has been established or verified;
- no immutable application-image version or digest is documented;
- public versus authenticated pull behavior has not been selected;
- supported container architectures have not been declared or tested; and
- no application-image signature, SBOM, or provenance has been verified.

The image reference in
[`deploy/k8s/fendix-app.yaml`](../deploy/k8s/fendix-app.yaml) is retained only as
a compatibility reference. It is not evidence of an official, pullable, or
production-ready image. The manifest itself is a reference template rather
than a paved-road deployment path. Do not substitute the Fendix engine image:
the two containers have different entry points and responsibilities.

## Publication gate

An owner must choose whether the application image is public or private and
add an official workflow that builds `Dockerfile.app` from this repository.
Before the Kubernetes reference may point to a brand-owned image, that image
must pass all of these gates:

1. Publish an immutable version tag from the official repository.
2. Declare and verify each supported architecture (preferably `linux/amd64`
   and `linux/arm64`).
3. Pull the exact digest using the documented deployment model. Public images
   require an unauthenticated clean pull; private images require documented
   `imagePullSecrets` without embedded credentials.
4. Start the container and verify `/healthz` with non-secret test settings.
5. Inspect configuration and image history for secret leakage.
6. Verify the cosign identity, CycloneDX SBOM, and SLSA provenance required by
   the release policy.
7. Replace the compatibility reference in the Kubernetes template with the
   verified brand-owned digest and re-run Kubernetes validation.

Until those gates pass, the GitHub App can be built locally or deployed as a
native binary as described in [github-app.md](github-app.md), while the public
Kubernetes publication gate remains blocked.
