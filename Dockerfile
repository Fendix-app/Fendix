# Fendix — Multi-stage Docker build
# Produces a minimal image with the Go binary + Python engine.
#
# Build:  docker build -t fendix .
# Run:    docker run --rm fendix scan --url https://api.example.com

# ---- Stage 1: Build the Go binary ----
FROM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS go-builder
# ↑ Base image pinned to digest. Bumps come through dependabot
# (docker ecosystem in .github/dependabot.yml); never silently shift
# under us. The `1.27-alpine` tag stays in the line so a human reader
# knows what minor version we're on.

RUN apk add --no-cache git make

WORKDIR /build

# Copy Go module files first for layer caching
COPY go/go.mod go/go.sum ./go/
RUN cd go && go mod download

# Copy Python engine files for embedding
COPY python/ ./python/

# Copy Go source
COPY go/ ./go/
COPY Makefile ./

# Version stamped into the binary as `main.Version`, surfaced by
# `fendix version` and — since the backend forwards it — as SARIF
# `driver.version` and the persisted `engine_version` on every scan.
#
# release.yml passes the git tag (`VERSION=v2.0.1`). The default is
# deliberately the literal "docker" rather than a version number: a plain
# `docker build .` has no tag to claim, and a local build asserting it is a
# release would be worse than one that says it is an unversioned image.
#
# It used to be hardcoded to "docker" with no way to override, so every
# published image reported `fendix version docker`. That was invisible until
# the backend began persisting the value, at which point production scans
# started recording their engine as "docker" — replacing one uninformative
# placeholder with another.
ARG VERSION=docker
# REVISION is the commit being built. The build context has no .git, so Go
# cannot stamp it; release.yml passes it so `fendix init` inside the image can
# pin the installer to that commit. Empty leaves it unknown (init then writes
# a placeholder the generated CI rejects).
ARG REVISION=

# Bundle Python engine into Go embed directory and build.
# -trimpath + CGO_ENABLED=0 match release.yml so a docker-built fendix
# and a release-pipeline fendix have comparable build provenance.
RUN make embed-engine && \
    cd go && CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w -X main.Version=${VERSION} -X main.Revision=${REVISION}" \
    -o /fendix ./cmd/fendix/

# ---- Stage 2: Runtime image ----
FROM python:3.14-slim@sha256:7a500125bc50693f2214e842a621440a1b1b9cbb2188f74ab045d29ed2ea5856

# Debian security refresh. The base is pinned by digest, so its packages are
# as old as that digest; this applies the trixie security updates published
# since, so a rebuild carries current OS fixes (perl-base, openssl,
# util-linux, ...) without moving the Python interpreter or the pip the base
# ships. apt-get upgrade installs no new package. Until v3.6.4 the transient
# build-essential install upgraded some of these (perl-base, libc6) as a side
# effect; installing from wheels only removed that, so the refresh is explicit.
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies for whitebox analysis from
# python/requirements.lock, the hash-locked set the composite Action
# installs, so the image and the Action run the same Semgrep, MCP and
# Pydantic versions. --require-hashes checks every file against the lock;
# --only-binary=:all: refuses source builds, so the layer needs no compiler
# (every pinned version ships a cp314 wheel for linux/amd64 and
# linux/arm64). pip check fails the build if the lock, resolved for the
# Action's CPython 3.11, leaves a dependency of this CPython unmet.
COPY python/requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
        -r /tmp/requirements.lock && \
    pip check && \
    rm /tmp/requirements.lock

# Copy the Go binary
COPY --from=go-builder /fendix /usr/local/bin/fendix

# ---- Go toolchain, so govulncheck can run inside the image ----
# govulncheck (golang.org/x/vuln) loads the target module through the `go`
# command. Without a toolchain it recorded `failed/execution_error` on every
# Go repository the image scanned — a permanent, Fendix-owned coverage gap
# that release policy 2.0.0 turns into INCOMPLETE (coverage spec §11, risk
# 13). The builder's toolchain is statically linked, so it runs on this
# glibc runtime as is (~300 MB of image). Dockerfile and Dockerfile.app carry
# the same block; keep the two in step.
#
# What a scan does with it, and the knobs that bound it:
#   - Module resolution reaches Go's default proxy and checksum database
#     (proxy.golang.org, sum.golang.org) for any dependency the target does
#     not vendor, so the dependency graph of a scanned repository leaves the
#     scan host. Operators with private modules set GOPRIVATE (and GOPROXY /
#     GONOSUMDB as their proxy requires) on the container; an unresolvable
#     dependency records govulncheck failed/execution_error, never a silent ok.
#   - GOTOOLCHAIN=local: a module whose go.mod asks for a newer Go than this
#     image carries records execution_error instead of downloading a
#     toolchain mid-scan; the fix is a builder bump, which dependabot proposes.
#   - GOFLAGS=-mod=readonly and GOENV=off: a scan never rewrites the target's
#     go.mod/go.sum (checkouts are mounted read-only) and never reads a
#     per-user go env file, whatever a future Go version's defaults become.
#   - CGO_ENABLED=0: the runtime ships no C compiler, so cgo packages cannot
#     be loaded; saying so keeps that failure deterministic.
#   - Caches live under /tmp so any UID the container runs as can write them.
COPY --from=go-builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}" \
    GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    GOFLAGS=-mod=readonly \
    GOENV=off \
    GOPATH=/tmp/go \
    GOCACHE=/tmp/go-build \
    GOMODCACHE=/tmp/go/pkg/mod

# Copy the Python engine (for direct use, not just embedded)
COPY python/ /opt/fendix/python/
# Source worktrees may have owner-only directory modes. COPY preserves those
# modes, which would make the engine modules invisible after USER fendix.
# Normalize read/traverse permissions without granting write access.
RUN chmod -R a+rX /opt/fendix/python
# EnsureEngine (go/internal/engine/extract.go) resolves the taint engine via
# the FENDIX_ENGINE env var — this MUST match that name. A prior typo set
# FENDIX_PYTHON_ENGINE, which the Go side never reads, so resolution fell
# through to the embedded placeholder and then the CWD-relative ./python
# fallback (WORKDIR /workspace → /workspace/python, absent), silently
# disabling whitebox taint analysis in every container. FENDIX_PYTHON_ENGINE
# is kept as a human-facing alias only.
ENV FENDIX_ENGINE=/opt/fendix/python/
ENV FENDIX_PYTHON_ENGINE=/opt/fendix/python/

# Non-root user for security
RUN useradd -m -s /bin/sh fendix
USER fendix
WORKDIR /workspace

ENTRYPOINT ["fendix"]
CMD ["version"]
