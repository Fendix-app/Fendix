#!/bin/sh
# Fendix installer — downloads the latest release binary for your platform.
#
# This script is mirrored to the public install repo on every release by
# .github/workflows/release.yml. The canonical user-facing URL is:
#   curl -fsSL https://get.fendix.dev/install.sh | sh
#
# Direct-from-mirror fallback (works even if get.fendix.dev DNS is down):
#   curl -fsSL https://raw.githubusercontent.com/Fendix-app/homebrew-fendix/main/install.sh | sh
#
# Options (environment variables):
#   FENDIX_VERSION  — specific version to install (default: latest)
#   FENDIX_DIR      — install directory (default: /usr/local/bin)
#   FENDIX_REPO     — override source repo (default: Fendix-app/Fendix)
#   FENDIX_SIGN_REPO — override the expected GitHub Actions signer repository

set -eu
umask 077

REPO="${FENDIX_REPO:-Fendix-app/Fendix}"
# SIGN_REPO is the repo whose GitHub Actions OIDC identity cosign-signed the
# release. It is the MAIN engine repo (not the homebrew tap that may host the
# download), so it must NOT default to $REPO. Matches the verify command in
# README "Verifying signed releases". Overridable for forks.
INSTALL_DIR="${FENDIX_DIR:-/usr/local/bin}"

# Colors (if terminal supports them)
if [ -t 1 ]; then
    BOLD='\033[1m'
    GREEN='\033[32m'
    RED='\033[31m'
    YELLOW='\033[33m'
    RESET='\033[0m'
else
    BOLD='' GREEN='' RED='' YELLOW='' RESET=''
fi

info()  { printf "${GREEN}→${RESET} %s\n" "$1"; }
warn()  { printf "${YELLOW}!${RESET} %s\n" "$1"; }
error() { printf "${RED}✗${RESET} %s\n" "$1" >&2; exit 1; }

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux)  OS="linux" ;;
        darwin) OS="darwin" ;;
        *)      error "Unsupported OS: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64" ;;
        arm64|aarch64)  ARCH="arm64" ;;
        *)              error "Unsupported architecture: $ARCH" ;;
    esac
}

# Get the latest release version from GitHub
get_version() {
    if [ -n "${FENDIX_VERSION:-}" ]; then
        VERSION="$FENDIX_VERSION"
    else
        info "Fetching latest version..."
        VERSION=$(curl --proto '=https' --tlsv1.2 -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' \
            | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    fi

    if [ -z "$VERSION" ]; then
        error "Could not determine latest version. Set FENDIX_VERSION manually."
    fi

    case "$VERSION" in
        v[0-9]* ) ;;
        * ) error "Invalid version: $VERSION" ;;
    esac
    case "$VERSION" in
        *[!A-Za-z0-9._+-]* ) error "Invalid version: $VERSION" ;;
    esac
}

signing_repo() {
    if [ -n "${FENDIX_SIGN_REPO:-}" ]; then
        printf '%s\n' "$FENDIX_SIGN_REPO"
        return
    fi

    # Certificates through v3.4.1 are immutable and retain the repository's
    # pre-transfer workflow identity. Later releases use the organization.
    case "$VERSION" in
        v0.*|v1.*|v2.*|v3.0.*|v3.1.*|v3.2.*|v3.3.*|v3.4.0|v3.4.1)
            printf '%s\n' "Abdel-RahmanSaied/Fendix"
            ;;
        *)
            printf '%s\n' "Fendix-app/Fendix"
            ;;
    esac
}

# Download and install
install() {
    BINARY="fendix-${VERSION}-${OS}-${ARCH}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${BINARY}"

    info "Downloading fendix ${VERSION} for ${OS}/${ARCH}..."

    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    if ! curl --proto '=https' --tlsv1.2 -fsSL -o "${TMP_DIR}/fendix" "$URL"; then
        error "Download failed. Check that version ${VERSION} exists for ${OS}/${ARCH}."
    fi

    # --- Verify the download (FAIL-CLOSED) -----------------------------------
    # An install ABORTS unless the binary's SHA-256 matches the published
    # checksum. Set FENDIX_ALLOW_UNVERIFIED=1 to bypass (NOT recommended —
    # e.g. an air-gapped mirror without the .sha256 sidecar). Previously a
    # missing hashing tool or a failed checksum download silently skipped
    # verification (fail-open); that is the F-M2 trust gap this closes.
    CHECKSUM_URL="${URL}.sha256"
    if curl --proto '=https' --tlsv1.2 -fsSL -o "${TMP_DIR}/fendix.sha256" "$CHECKSUM_URL" 2>/dev/null; then
        info "Verifying checksum..."
        EXPECTED=$(awk '{print $1}' "${TMP_DIR}/fendix.sha256")
        case "$EXPECTED" in
            [0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]* ) ;;
            * ) error "Published checksum is malformed. Refusing to install." ;;
        esac
        if [ "${#EXPECTED}" -ne 64 ]; then
            error "Published checksum is malformed. Refusing to install."
        fi
        if command -v sha256sum >/dev/null 2>&1; then
            ACTUAL=$(sha256sum "${TMP_DIR}/fendix" | awk '{print $1}')
        elif command -v shasum >/dev/null 2>&1; then
            ACTUAL=$(shasum -a 256 "${TMP_DIR}/fendix" | awk '{print $1}')
        elif [ "${FENDIX_ALLOW_UNVERIFIED:-}" = "1" ]; then
            warn "No sha256sum/shasum found and FENDIX_ALLOW_UNVERIFIED=1 — installing UNVERIFIED."
            ACTUAL=""
        else
            error "No sha256sum or shasum available to verify the download. Install one, or re-run with FENDIX_ALLOW_UNVERIFIED=1 to bypass (not recommended)."
        fi
        if [ -n "$ACTUAL" ] && [ "$EXPECTED" != "$ACTUAL" ]; then
            error "Checksum mismatch! Expected ${EXPECTED}, got ${ACTUAL}. Refusing to install — the download may be corrupt or tampered."
        fi
    elif [ "${FENDIX_ALLOW_UNVERIFIED:-}" = "1" ]; then
        warn "Checksum file unavailable and FENDIX_ALLOW_UNVERIFIED=1 — installing UNVERIFIED."
    else
        error "Could not fetch the published checksum (${CHECKSUM_URL}). Refusing to install an unverified binary. Re-run with FENDIX_ALLOW_UNVERIFIED=1 to bypass (not recommended)."
    fi

    # --- Optional cosign keyless signature verification (defense in depth) ----
    # Releases >= v0.6.0-rc2 ship .sig/.crt sidecars (Sigstore Fulcio, bound to
    # the GitHub Actions OIDC identity that built the release). If cosign is
    # installed AND the sidecars exist, verify them and ABORT on failure. cosign
    # is not required (the checksum already gates the install); its absence, or
    # missing sidecars on older tags, is informational. Identity/issuer match
    # README "Verifying signed releases" and release.yml.
    if command -v cosign >/dev/null 2>&1; then
        if curl --proto '=https' --tlsv1.2 -fsSL -o "${TMP_DIR}/fendix.sig" "${URL}.sig" 2>/dev/null \
            && curl --proto '=https' --tlsv1.2 -fsSL -o "${TMP_DIR}/fendix.crt" "${URL}.crt" 2>/dev/null; then
            info "Verifying cosign signature..."
            SIGN_REPO=$(signing_repo)
            if cosign verify-blob \
                --certificate "${TMP_DIR}/fendix.crt" \
                --signature "${TMP_DIR}/fendix.sig" \
                --certificate-identity "https://github.com/${SIGN_REPO}/.github/workflows/release.yml@refs/tags/${VERSION}" \
                --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
                "${TMP_DIR}/fendix" >/dev/null 2>&1; then
                info "cosign signature verified."
            else
                error "cosign signature verification FAILED. Refusing to install."
            fi
        else
            info "cosign present but no .sig/.crt for this release (pre-v0.6.0-rc2?) — relying on the verified checksum."
        fi
    else
        info "cosign not installed — skipping signature check (checksum verified). See README 'Verifying signed releases' to verify manually."
    fi

    chmod +x "${TMP_DIR}/fendix"

    # Ensure install dir exists. mv would fail "No such file or directory"
    # if e.g. FENDIX_DIR=$HOME/.local/bin on a fresh runner where the
    # target dir doesn't exist yet. Try mkdir -p without sudo first; only
    # escalate if a parent up the chain isn't writable.
    if [ ! -d "$INSTALL_DIR" ]; then
        if ! mkdir -p "$INSTALL_DIR" 2>/dev/null; then
            info "Creating ${INSTALL_DIR} (requires sudo)..."
            sudo mkdir -p "$INSTALL_DIR"
        fi
    fi

    # Install to target directory
    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMP_DIR}/fendix" "${INSTALL_DIR}/fendix"
    else
        info "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo mv "${TMP_DIR}/fendix" "${INSTALL_DIR}/fendix"
    fi

    info "Installed fendix ${VERSION} to ${INSTALL_DIR}/fendix"
}

# Verify installation
verify() {
    if command -v fendix >/dev/null 2>&1; then
        printf '\n%s%s✓ fendix installed successfully!%s\n\n' "$BOLD" "$GREEN" "$RESET"
        fendix version
        printf "\nGet started:\n"
        printf '  %sfendix scan --url https://api.example.com%s\n' "$BOLD" "$RESET"
        printf '  %sfendix scan --code ./src --spec openapi.yaml%s\n\n' "$BOLD" "$RESET"
    else
        warn "fendix installed but not in PATH. Add ${INSTALL_DIR} to your PATH,"
        warn "or re-run with FENDIX_DIR pointing at a directory already on PATH:"
        warn "  curl -fsSL https://get.fendix.dev/install.sh | FENDIX_DIR=\$HOME/.local/bin sh"
    fi
}

# Main
detect_platform
get_version
install
verify
