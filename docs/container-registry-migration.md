# Official repository and container registry migration

Status as of 2026-09-20: **publication blocked only by Docker Hub repository metadata; release automation and image push authorization verified**.

## Canonical destinations

- Source: <https://github.com/Fendix-app/Fendix>
- Container image: `docker.io/fendixapp/fendix`
- Product documentation: <https://www.fendix.dev/docs/getting-started>

The GitHub repository transfer is complete and the default branch is `main`. Repository metadata now points to `https://fendix.dev`.

## Existing release source

The current stable GitHub release is `v3.4.1`. The existing compatibility image remains public at `ghcr.io/abdel-rahmansaied/fendix:v3.4.1` with manifest digest:

```text
sha256:07e4b0590923ba4651322c4a1fff6931a522289fa98403bed7c1e713c71fd9d2
```

It contains `linux/amd64` and `linux/arm64` images plus BuildKit attestation manifests. Existing release tags found in the legacy registry are:

```text
0.4.1, 0.4.2, 0.5.0, 0.6.0-rc1,
v0.6.0-rc2, v0.6.0, v0.6.1, v0.7.0, v0.8.0, v0.9.0, v0.9.1,
v0.10.0, v0.11.0, v0.14.0, v0.14.1, v0.15.0, v0.16.1,
v0.16.2, v0.16.3, v0.16.4, v0.17.0, v0.18.0, v0.18.1,
v0.19.0, v1.0.0-rc1, v1.0.0, v1.1.0, v1.2.0-rc1, v1.2.0,
v1.2.1, v2.0.0, v2.0.1, v2.1.0, v2.1.1, v3.0.0, v3.0.1,
v3.0.2, v3.1.0, v3.2.0, v3.3.0, v3.4.0, v3.4.1, latest
```

Do not delete or retag this compatibility image. Existing installations can continue to pull it while consumers migrate.

## Release automation

`.github/workflows/release.yml` now prepares Docker Hub as the canonical registry and retains a brand-owned GHCR mirror. It:

1. resolves an exact stable tag and commit;
2. requires the Docker Hub repository, public visibility and brand metadata;
3. requires `DOCKERHUB_USERNAME=fendixapp`, a non-empty `DOCKERHUB_TOKEN`, and keyless signing;
4. builds `linux/amd64` and `linux/arm64` with QEMU and Buildx;
5. emits BuildKit SBOM and provenance attestations;
6. smoke-tests the candidate by digest with the offline coverage fixture;
7. refuses to replace an existing immutable Docker Hub version with different bytes;
8. publishes the immutable version, verifies its manifest, clean-pulls it and repeats the fixture test;
9. signs and attests both Docker Hub and brand-owned GHCR digest references;
10. verifies the signature, CycloneDX SBOM and SLSA provenance against the official workflow identity;
11. only then publishes the major, minor and `latest` convenience tags; and
12. logs out and proves that the immutable Docker Hub tag can be pulled without authentication.

A tag push runs the normal release. The manual `workflow_dispatch` path is container-only and permits migration/backfill of an already published stable GitHub release such as `v3.4.1`.

Prerelease tags such as `v3.5.0-rc.1` publish only their immutable Docker Hub version and GHCR tag. They do not move Docker Hub major, minor, or `latest` tags and do not update the stable Homebrew mirror.

## Required infrastructure before publication

The public Docker Hub repository `fendixapp/fendix` now exists. Release run
[`35510206549`](https://github.com/Fendix-app/Fendix/actions/runs/35510206549)
verified all of the following without printing or inspecting the configured secret:

- `DOCKERHUB_USERNAME` is `fendixapp`;
- Docker Hub authentication succeeds;
- the token can request both `pull` and `push` authorization for `fendixapp/fendix`;
- the repository is public; and
- `COSIGN_ENABLED=true`.

The run then stopped before building or publishing because the repository's
public metadata does not contain the required brand links. The repository has
no tags. Its short description is present and its full description is empty.

Complete this single owner action in Docker Hub:

1. Open **My Hub → Repositories → fendixapp/fendix → General**.
2. Edit the repository overview so it includes both `https://fendix.dev` and `https://github.com/Fendix-app/Fendix`.
3. Dispatch **Release** with `release_tag=v3.4.1`.

The existing CI token has the least-privilege image pull/push scope but not the
separate `scope-repository-edit` metadata permission, so release automation
deliberately validates the public metadata instead of silently changing it.

Never paste the token into chat, source, build arguments, artifacts or reports.

## Verification after the first successful run

Record the digest reported in the Actions job summary, then independently run:

```bash
docker buildx imagetools inspect fendixapp/fendix:3.4.1
docker pull fendixapp/fendix:3.4.1
docker run --rm fendixapp/fendix:3.4.1 version
docker run --rm fendixapp/fendix:3.4.1 --help

cosign verify \
  --certificate-identity-regexp '^https://github.com/Fendix-app/Fendix/.github/workflows/release.yml@refs/tags/v3\.4\.1$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  fendixapp/fendix@sha256:REPLACE_WITH_VERIFIED_DIGEST

cosign verify-attestation --type cyclonedx \
  --certificate-identity-regexp '^https://github.com/Fendix-app/Fendix/.github/workflows/release.yml@refs/tags/v3\.4\.1$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  fendixapp/fendix@sha256:REPLACE_WITH_VERIFIED_DIGEST

cosign verify-attestation --type slsaprovenance1 \
  --certificate-identity-regexp '^https://github.com/Fendix-app/Fendix/.github/workflows/release.yml@refs/tags/v3\.4\.1$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  fendixapp/fendix@sha256:REPLACE_WITH_VERIFIED_DIGEST
```

Only after these checks succeed may public Docker instructions switch from the compatibility GHCR image to `fendixapp/fendix`.

## Intentional legacy identifiers

- The Go module path and Go imports remain `github.com/Abdel-RahmanSaied/Fendix`. Changing them would break import compatibility and requires a separate major-version migration.
- `Abdel-RahmanSaied/homebrew-fendix` remains the binary/Homebrew distribution mirror until a brand-owned tap and mirror are provisioned.
- Historical changelog, audit and authorship records are retained where changing them would misrepresent history.
- The previous GHCR package remains pullable for existing users. No shutdown date is set.

## `get.fendix.dev`

The host currently resolves by CNAME to `abdel-rahmansaied.github.io` and GitHub Pages returns `200`; GitHub Pages cannot issue a server-side `301` or `308`. The release-managed page template now contains only a canonical client redirect to `https://www.fendix.dev/docs/getting-started`, so the obsolete multi-engine-only claim cannot return on a future mirror sync.

For the required permanent redirect, change the `get.fendix.dev` DNS record from the GitHub Pages CNAME to a redirect-capable host (for example, the same provider serving `www.fendix.dev`) and configure a path-specific rule:

```text
GET / and /index.html -> 308 https://www.fendix.dev/docs/getting-started
```

Keep `/install.sh` serving the verified installer until a brand-owned replacement exists; then redirect it separately to that exact script, never to an HTML documentation page. Preserve other request paths only when the canonical site defines equivalent routes. Remove the GitHub Pages custom domain after DNS cutover. This infrastructure change has not been deployed from this repository.
