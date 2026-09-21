# Installing Fendix

This page covers every supported install path. The README's
[Quick Start](../README.md#installation) section points at the most common
ones; this document is the canonical reference for ops shops that need to
choose between them or want signature-verification details.

> Engine source and release assets live in the official
> [`Fendix-app/Fendix`](https://github.com/Fendix-app/Fendix) repository. The
> [`Fendix-app/homebrew-fendix`](https://github.com/Fendix-app/homebrew-fendix)
> repository provides the Homebrew tap and `get.fendix.dev` compatibility host.

---

## Choose a path

| You want… | Use |
|---|---|
| One command on a developer laptop (macOS or Linux) | [Homebrew](#homebrew-macos--linux) |
| One command on a CI runner (POSIX) | [`install.sh` via `get.fendix.dev`](#install-script-curl--sh) |
| `apt install` / `apt upgrade` integration on Debian/Ubuntu | [.deb package](#debian--ubuntu-deb) |
| `dnf install` / `yum install` integration on RHEL/Fedora | [.rpm package](#rhel--fedora--centos-rpm) |
| Containers, no host install | [Docker](#docker) |
| Pinned, signature-verified, reproducible install | [Manual binary download](#manual-binary-download) + [cosign verification](#verifying-release-artifacts-cosign) |
| Building from source | [Build from source](#build-from-source) |

---

## Homebrew (macOS / Linux)

```bash
brew tap Fendix-app/fendix
brew install fendix
```

The formula auto-selects the right binary for your arch (Apple Silicon vs
Intel; arm64 Linux vs amd64 Linux). Updates land via `brew upgrade fendix`
once the next release tag mirrors.

## Install script (curl | sh)

```bash
curl -fsSL https://get.fendix.dev/install.sh | sh
```

Downloads the latest release binary, verifies its sha256 checksum, and
installs to `/usr/local/bin/fendix`. Override:

- `FENDIX_DIR=$HOME/.local/bin` — install to a user-writable directory.
- `FENDIX_VERSION=v3.4.1` — pin a specific version.
- `FENDIX_REPO=...` — pull from a fork or private mirror.

Sudo is requested only if `FENDIX_DIR` isn't writable.

`get.fendix.dev` is a CNAME to GitHub Pages for the official
[`homebrew-fendix`](https://github.com/Fendix-app/homebrew-fendix) repository.
It is the preferred URL because it is stable across repository changes. If
`get.fendix.dev` is ever unreachable, the repository is also directly
fetchable:

```bash
# Documented fallback — same script, served straight from the mirror branch.
curl -fsSL https://raw.githubusercontent.com/Fendix-app/homebrew-fendix/main/install.sh | sh
```

To inspect the script before piping to a shell:

```bash
curl -fsSL https://get.fendix.dev/install.sh | less
```

## Debian / Ubuntu (.deb)

```bash
# Pick the right architecture for your host
ARCH=$(dpkg --print-architecture)         # amd64 or arm64
VERSION=v3.4.1                            # current release at time of writing
URL="https://github.com/Fendix-app/Fendix/releases/download/${VERSION}/fendix-${VERSION}-linux-${ARCH}.deb"

# Download + verify + install
curl -fsSL -o fendix.deb "${URL}"
curl -fsSL -o fendix.deb.sha256 "${URL}.sha256"
sha256sum -c fendix.deb.sha256
sudo dpkg -i fendix.deb
sudo apt-get install -f       # pull in python3 if it isn't already there
```

The package depends on `python3` and recommends `semgrep` (for deeper
white-box coverage). All Fendix files land under `/usr/bin/fendix` plus
docs in `/usr/share/doc/fendix/`.

Uninstall with `sudo apt-get remove fendix` (or `dpkg -r`).

## RHEL / Fedora / CentOS (.rpm)

```bash
ARCH=$(uname -m)                          # x86_64 or aarch64
case "$ARCH" in
  x86_64)  PKG_ARCH=amd64 ;;
  aarch64) PKG_ARCH=arm64 ;;
esac
VERSION=v3.4.1
URL="https://github.com/Fendix-app/Fendix/releases/download/${VERSION}/fendix-${VERSION}-linux-${PKG_ARCH}.rpm"

curl -fsSL -o fendix.rpm "${URL}"
curl -fsSL -o fendix.rpm.sha256 "${URL}.sha256"
sha256sum -c fendix.rpm.sha256
sudo dnf install ./fendix.rpm   # or: sudo rpm -i ./fendix.rpm
```

Note: nfpm builds Fendix `.rpm` files using the canonical Go-style arch in
the *filename* (`amd64`/`arm64`) but the rpm metadata reports the rpm-side
canonical arch (`x86_64`/`aarch64`) — `dnf install` matches on the
metadata side, so a `*-amd64.rpm` will install fine on `x86_64` hosts.

Uninstall with `sudo dnf remove fendix`.

## Docker

```bash
docker pull fendixapp/fendix:3.4.1
docker run --rm fendixapp/fendix:3.4.1 scan --url https://api.example.com
```

The image is multi-arch (linux/amd64 + linux/arm64); `docker pull` picks
the right one. Python and the white-box analyzer are baked in, so hybrid
mode works out of the box.

> **Images published before v2.0.1 answer `fendix version docker`.** The image
> build hardcoded that placeholder with no way to override it, so a report
> produced by one of those cannot say which engine version wrote it — including
> SARIF `driver.version`. From v2.0.1 the build takes the git tag, matching how
> the platform binaries have always been stamped. Pin a tag
> (`fendixapp/fendix:3.4.1`) or a digest rather than `:latest`
> if you need that to be reproducible. A locally built image still reports
> `docker`, deliberately: a plain `docker build .` has no tag to claim.

## Manual binary download

Pick a binary for your platform from the
[latest release](https://github.com/Fendix-app/Fendix/releases/latest)
(linux/amd64, linux/arm64, darwin/amd64, darwin/arm64), verify the
matching `.sha256` file, and place it on your PATH:

```bash
VERSION=v3.4.1
URL="https://github.com/Fendix-app/Fendix/releases/download/${VERSION}/fendix-${VERSION}-darwin-arm64"

curl -fsSL -o fendix "${URL}"
curl -fsSL -o fendix.sha256 "${URL}.sha256"
shasum -a 256 -c fendix.sha256

chmod +x fendix
sudo mv fendix /usr/local/bin/fendix
fendix version
```

## Build from source

Requires Go 1.21+ and Python 3.9+.

```bash
git clone https://github.com/Fendix-app/Fendix.git
cd Fendix
make build
./bin/fendix version
```

The white-box engine needs Python at runtime:

```bash
pip install -r python/requirements.txt
```

---

## Verifying release artifacts (cosign)

When `COSIGN_ENABLED=true` is set on the engine repo, every release
ships `.sig` + `.crt` sidecar files alongside each binary, `.deb`, `.rpm`,
and Docker image. Verification is keyless via Sigstore Fulcio — no static
public key to distribute.

Verify a binary:

The v3.4.1 certificate retains the immutable pre-transfer workflow identity
shown below. Releases after v3.4.1 use `Fendix-app/Fendix` in the identity.

```bash
cosign verify-blob \
  --certificate fendix-v3.4.1-linux-amd64.crt \
  --signature   fendix-v3.4.1-linux-amd64.sig \
  --certificate-identity "https://github.com/Abdel-RahmanSaied/Fendix/.github/workflows/release.yml@refs/tags/v3.4.1" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  fendix-v3.4.1-linux-amd64
```

Verify a `.deb` or `.rpm` package (same pattern, swap the asset name):

```bash
cosign verify-blob \
  --certificate fendix-v3.4.1-linux-amd64.deb.crt \
  --signature   fendix-v3.4.1-linux-amd64.deb.sig \
  --certificate-identity "https://github.com/Abdel-RahmanSaied/Fendix/.github/workflows/release.yml@refs/tags/v3.4.1" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  fendix-v3.4.1-linux-amd64.deb
```

Verify the Docker image (signs the multi-arch manifest digest):

```bash
cosign verify fendixapp/fendix@sha256:88783a1a032f925630bdb0977b37821add5e3381d347f91ec101401f4e98e02a \
  --certificate-identity-regexp "^https://github.com/Fendix-app/Fendix/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Releases cut **before** `COSIGN_ENABLED=true` rolled out won't have these
sidecars — fall back to the `.sha256` file for those. See
[`SECURITY.md`](../SECURITY.md) for the broader artifact-trust policy.

---

## `get.fendix.dev` — how it's wired

`https://get.fendix.dev/install.sh` is live as of 2026-04-30. It's a
CNAME on the operator's `fendix.dev` zone pointing at
`abdel-rahmansaied.github.io`, served via GitHub Pages from `main:/` in the
official [`homebrew-fendix`](https://github.com/Fendix-app/homebrew-fendix)
repository with an auto-provisioned Let's Encrypt certificate. The personal
GitHub Pages hostname is the DNS target only; current source and ownership are
organization-controlled.

The root page is a scoped client-side compatibility redirect to
`https://www.fendix.dev/docs/getting-started`; `/install.sh` remains directly
served. GitHub Pages responds to `/` with HTTP 200, so the page declares the
canonical URL, `noindex,follow`, an immediate redirect, and a visible fallback
link. It must not be described as an HTTP 301 or 308. A future edge-host
migration can provide a route-specific permanent redirect for `/` while
continuing to serve `/install.sh` unchanged.

### What's in the mirror, and why

The four files that make up the Pages site are auto-synced from the
engine repo into the mirror on every `v*` tag by
[`.github/workflows/release.yml`](../.github/workflows/release.yml)
(the `mirror` job, alongside the existing Formula update). The
canonical sources live in this repo:

| Mirror path     | Source in engine repo                                              | Purpose                                     |
|-----------------|--------------------------------------------------------------------|---------------------------------------------|
| `/install.sh`   | [`scripts/install.sh`](../scripts/install.sh)                      | The installer that `curl … \| sh` runs.     |
| `/CNAME`        | [`scripts/release/mirror-pages-bootstrap/CNAME`](../scripts/release/mirror-pages-bootstrap/CNAME) | Tells Pages to bind `get.fendix.dev`.       |
| `/.nojekyll`    | [`scripts/release/mirror-pages-bootstrap/.nojekyll`](../scripts/release/mirror-pages-bootstrap/.nojekyll) | Skips Jekyll processing on Pages.           |
| `/index.html`   | [`scripts/release/mirror-pages-bootstrap/index.html`](../scripts/release/mirror-pages-bootstrap/index.html) | Scoped client redirect and accessible fallback at `https://get.fendix.dev/`. |

The mirror is generated, not hand-edited — every `v*` tag overwrites
these four files. To change anything served at `get.fendix.dev`, edit
the engine-repo source and cut a release.

### Verifying the chain

```bash
# DNS resolves to GitHub Pages
dig +short get.fendix.dev
# Expected: abdel-rahmansaied.github.io. + 4 GitHub Pages IPs

# HTTPS works, install.sh has the right content-type
curl -I https://get.fendix.dev/install.sh
# Expected: HTTP/2 200, content-type: application/x-sh, server: GitHub.com

# End-to-end install (do this in a throwaway VM, not your laptop)
curl -fsSL https://get.fendix.dev/install.sh | sh
fendix version
```

---

## Troubleshooting

**`fendix: command not found` after install.sh.**
Add `/usr/local/bin` to your `PATH`, or set `FENDIX_DIR=$HOME/.local/bin`
and re-run the installer.

**`Couldn't resolve host 'github.com'` from `apt`/`dnf`.**
The `.deb` / `.rpm` paths above download from GitHub Releases; corporate
networks may need a proxy. Use the `Manual binary download` path with
`curl --proxy …` instead.

**Hybrid scans skip white-box findings with `python3 not found`.**
Install Python 3.9+. The `.deb` and `.rpm` packages declare `python3` as
a dependency, so `apt-get install -f` (or `dnf install --setopt=install_weak_deps=False`)
should pull it in. Manual installs need it too.

**Cosign verify fails with "no matching signatures".**
Either the release predates `COSIGN_ENABLED=true` rolling out, or the
`.crt`/`.sig` filenames don't match the asset filename. Check that the
release page shows the sidecar files; if it doesn't, verify by sha256
instead.
