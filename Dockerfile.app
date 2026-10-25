# Fendix GitHub App — multi-stage Docker build
#
# Produces a minimal image that runs `fendix-app` (the webhook server)
# alongside a working `fendix` CLI + embedded Python engine on PATH.
# The webhook handler shells out to `git` (to clone the PR head) and
# `fendix` (to run the actual scan + render SARIF) — both must be in
# the runtime image.
#
# Build:  docker build -f Dockerfile.app -t fendix-app .
# Run:    docker run --rm -p 8080:8080 \
#           -e FENDIX_APP_ID=<id> \
#           -e FENDIX_APP_PRIVATE_KEY="$(cat private-key.pem)" \
#           -e FENDIX_WEBHOOK_SECRET=<secret> \
#           fendix-app

# ---- Stage 1: Build the Go binaries ----
FROM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS go-builder
# Base image pinned to digest — see Dockerfile for rationale.

RUN apk add --no-cache git make

WORKDIR /build

COPY go/go.mod go/go.sum ./go/
RUN cd go && go mod download

COPY python/ ./python/
COPY go/ ./go/
COPY Makefile ./

# Bundle Python engine into the embed dir, then build both binaries.
# -trimpath + CGO_ENABLED=0 mirror release.yml so docker-built and
# release-built binaries share build provenance.
ARG VERSION=docker
RUN make embed-engine && \
    cd go && export CGO_ENABLED=0 && \
    go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /fendix      ./cmd/fendix/ && \
    go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /fendix-app  ./cmd/fendix-app/

# ---- Stage 2: Runtime image ----
FROM python:3.14-slim@sha256:7a500125bc50693f2214e842a621440a1b1b9cbb2188f74ab045d29ed2ea5856

# git is required for the clone step in the App's pull_request handler.
# ca-certificates so HTTPS to api.github.com + github.com works.
# tini for clean signal forwarding under non-PID-1 init.
# apt-get upgrade is the same Debian security refresh as Dockerfile's.
RUN apt-get update && apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Python deps for the embedded white-box engine. Same shape as Dockerfile:
# the hash-locked python/requirements.lock, wheels only, then pip check.
COPY python/requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
        -r /tmp/requirements.lock && \
    pip check && \
    rm /tmp/requirements.lock

COPY --from=go-builder /fendix     /usr/local/bin/fendix
COPY --from=go-builder /fendix-app /usr/local/bin/fendix-app

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

COPY python/ /opt/fendix/python/
RUN chmod -R a+rX /opt/fendix/python
ENV FENDIX_ENGINE=/opt/fendix/python/
ENV FENDIX_PYTHON_ENGINE=/opt/fendix/python/

# Non-root runtime user. The clone target lives under /tmp which the
# scanner creates per-scan; no persistent state on disk.
RUN useradd -m -s /bin/sh fendix
USER fendix
WORKDIR /home/fendix

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/fendix-app"]
